//! relay-reads.json end to end (PORTING.md, steps 4 and 5): its `lists` and `onEveryRelay` cases,
//! each relay's read made by a local relay and told apart by the relay pool itself, through
//! `read_leases`, the client's read of the leases of deposit addresses: a complete read (step 3 of
//! "Leasing an address"), and on every relay (a lease's confirmation). onchain_vectors.rs runs the
//! same cases through `complete_read_of` and `CompleteRead::outcome`, the functions the pool
//! decides them with. As checkout-node's test/relay-reads.test.ts.
//!
//! What each relay of a case does, by its state:
//! - complete: holds a few events at the lease's address (one page, not full); or 250, at distinct
//!   seconds (it pages: 100, 100, then 50); or caps its answers at 40 events (a page that is not
//!   full: complete, whatever it leaves out, SPEC.md §13 relies on relays that honor the limit);
//! - incomplete: holds 150 events of one second (a full page, then the same page again: no event
//!   it had not sent); or 2 100 at distinct seconds (a 20th page that is full); or never answers
//!   its second page (that page runs out of time);
//! - failed: refuses connections (nothing listens); or accepts them and never answers (mute: its
//!   first page runs out of time);
//! - reading: a relay still reading when the read goes on: one that holds 2 100 events at distinct
//!   seconds and answers each page a quarter of the timeout late (its read would last five
//!   timeouts); or a mute one, when the read goes on before its first page runs out of time.
//!
//! Time is tokio's, paused: the durations below are exact.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use super::support::relay::{LocalRelay, RelayBehaviour, RelayNet, pool};
use super::support::vectors::{Field, spec};
use crate::derive::lease_address;
use crate::json::Json;
use crate::nostr::relay::majority;
use crate::onchain::lease::read_leases;
use crate::protocol::{MAX_PAGES, RECORD_KIND};
use crate::runtime::OsRandom;
use crate::secret::Secret;

/// relayTimeoutMs of these reads: each page, the connection included.
const TIMEOUT_MS: u64 = 1500;
/// How late a relay that is still reading answers each of its pages.
const SLOW_PAGE_MS: u64 = TIMEOUT_MS / 4;
/// How late the relays that read completely answer each page, when the read goes on as soon as a
/// majority read completely and every other relay's read must have ended (or failed) by then.
const LATE_COMPLETE_MS: u64 = 400;

const NOW: i64 = 1_791_378_000;
const ADDRESS: &str = "bc1px22v5j99gdwhxqyelg2p6tdcfajjd3njhzn22c2gura2dvxg2xlqw2wte4";

fn registry_key() -> Secret {
    Secret::new([9; 32])
}

/// The ways a local relay reads as a state does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Maker {
    Few,
    Pages,
    Caps,
    OneSecond,
    TwentyPages,
    StallsAtPage2,
    RefusesConnections,
    Mute,
    SlowPager,
}

const MAKERS: [Maker; 9] = [
    Maker::Few,
    Maker::Pages,
    Maker::Caps,
    Maker::OneSecond,
    Maker::TwentyPages,
    Maker::StallsAtPage2,
    Maker::RefusesConnections,
    Maker::Mute,
    Maker::SlowPager,
];

/// Each choice of makers takes turns, so that the relays of one state vary from case to case;
/// every maker the cases used.
#[derive(Default)]
struct Turns {
    turns: HashMap<Vec<Maker>, usize>,
    used: BTreeSet<Maker>,
}

impl Turns {
    fn next(&mut self, makers: &[Maker]) -> Maker {
        let turn = self.turns.entry(makers.to_vec()).or_default();
        let maker = makers[*turn % makers.len()];
        *turn += 1;
        self.used.insert(maker);
        maker
    }
}

/// `count` events at the lease's address, anybody's (none opens as a lease: a read pages through
/// them all the same), the newest at NOW; of one second each, or all of NOW. `serial` numbers
/// their ids.
fn events(count: usize, one_second: bool, serial: &mut u64) -> Vec<Json> {
    let d = lease_address(&registry_key(), ADDRESS);
    (0..count)
        .map(|index| {
            *serial += 1;
            Json::object([
                ("id", Json::from(format!("{:064x}", *serial))),
                ("pubkey", Json::from("ab".repeat(32))),
                ("created_at", Json::integer(if one_second { NOW } else { NOW - index as i64 })),
                ("kind", Json::Number(RECORD_KIND)),
                ("tags", Json::array(vec![Json::array(vec![Json::from("d"), Json::from(d.as_str())])])),
                ("content", Json::from("")),
                ("sig", Json::from("00".repeat(64))),
            ])
        })
        .collect()
}

/// The local relay `maker` makes at `url` (`None`: nothing listens there), a relay that reads
/// completely answering each page `delay_ms` late.
fn make(
    net: &RelayNet,
    url: &str,
    maker: Maker,
    delay_ms: Option<u64>,
    serial: &mut u64,
) -> Option<LocalRelay> {
    let late = RelayBehaviour { query_delay_ms: delay_ms, ..RelayBehaviour::default() };
    let (held, behaviour) = match maker {
        Maker::Few => (events(3, false, serial), late),
        Maker::Pages => (events(250, false, serial), late),
        Maker::Caps => (events(250, false, serial), RelayBehaviour { cap: Some(40), ..late }),
        Maker::OneSecond => (events(150, true, serial), RelayBehaviour::default()),
        Maker::TwentyPages => (events(2100, false, serial), RelayBehaviour::default()),
        Maker::StallsAtPage2 => (
            events(250, false, serial),
            RelayBehaviour {
                mute_query: Some(Arc::new(|filter: &Json| filter.has("until"))),
                ..RelayBehaviour::default()
            },
        ),
        Maker::RefusesConnections => return None,
        Maker::Mute => (Vec::new(), RelayBehaviour::mute()),
        Maker::SlowPager => (events(2100, false, serial), RelayBehaviour::delayed(SLOW_PAGE_MS)),
    };
    let relay = net.add(url, behaviour);
    for event in held {
        relay.store(event);
    }
    Some(relay)
}

/// What a read of the leases of ADDRESS gave on relays made by `makers` (on every relay or not),
/// how long it took, and the relays made (by URL).
struct Outcome {
    answered: bool,
    complete: bool,
    elapsed: Duration,
    relays: Vec<(String, Option<LocalRelay>)>,
}

async fn read(makers: &[(Maker, Option<u64>)], every_relay: bool) -> Outcome {
    let net = RelayNet::default();
    let mut serial = 0;
    let relays: Vec<(String, Option<LocalRelay>)> = makers
        .iter()
        .enumerate()
        .map(|(index, &(maker, delay_ms))| {
            let url = format!("wss://{}-{index}.test", format!("{maker:?}").to_ascii_lowercase());
            let relay = make(&net, &url, maker, delay_ms, &mut serial);
            (url, relay)
        })
        .collect();
    let urls: Vec<String> = relays.iter().map(|(url, _)| url.clone()).collect();
    let pool = pool(&net, TIMEOUT_MS);
    let started = tokio::time::Instant::now();
    let leases =
        read_leases(&pool, &registry_key(), &[ADDRESS.to_owned()], &urls, NOW, &OsRandom, every_relay).await;
    Outcome { answered: leases.answered, complete: leases.complete, elapsed: started.elapsed(), relays }
}

/// When the pool goes on with a complete read on every relay while these are its relays' states
/// (SPEC.md §13): once no relay is still reading ("settled"); or, with some still reading, a
/// timeout after a majority read completely ("grace"), or as soon as a majority can no longer read
/// completely ("at once"). Otherwise (`None`) it never does: it waits for the relays still reading,
/// until each ends or fails.
fn goes_on_with(states: &[String]) -> Option<&'static str> {
    let count = |state: &str| states.iter().filter(|other| *other == state).count();
    let needed = majority(states.len());
    if count("reading") == 0 {
        Some("settled")
    } else if count("complete") >= needed {
        Some("grace")
    } else if count("complete") + count("reading") < needed {
        Some("at once")
    } else {
        None
    }
}

#[tokio::test(start_paused = true)]
async fn relay_reads_json_end_to_end() {
    let vectors = spec("vectors/relay-reads.json");
    let mut turns = Turns::default();
    let mut failures = Vec::new();

    // lists: a complete read of a list. Complete: the read goes on as soon as a majority read
    // completely, the others dropped; so that each of those has ended as the case says by then,
    // they end at once and the relays that read completely answer late. Not complete: the read
    // waits for every relay.
    let lists = vectors.list("lists");
    assert!(!lists.is_empty());
    for case in lists {
        let expected = case.field("expected").as_bool().unwrap();
        let makers: Vec<(Maker, Option<u64>)> = case
            .texts("relays")
            .iter()
            .map(|state| match state.as_str() {
                "complete" => {
                    let maker = turns.next(&[Maker::Few, Maker::Pages, Maker::Caps]);
                    (maker, expected.then_some(LATE_COMPLETE_MS))
                }
                "incomplete" if expected => (turns.next(&[Maker::OneSecond]), None),
                "incomplete" => {
                    (turns.next(&[Maker::OneSecond, Maker::StallsAtPage2, Maker::TwentyPages]), None)
                }
                "failed" if expected => (turns.next(&[Maker::RefusesConnections]), None),
                "failed" => (turns.next(&[Maker::Mute, Maker::RefusesConnections]), None),
                other => panic!("no state {other} in lists"),
            })
            .collect();
        let outcome = read(&makers, false).await;
        if outcome.complete != expected {
            failures.push(format!("lists, {}: complete {}", case.text("name"), outcome.complete));
        }
    }

    // onEveryRelay: a read of a lease's confirmation. The cases the pool goes on with, made by
    // local relays whose state is the case's when it goes on.
    let every = vectors.list("onEveryRelay");
    let kinds: BTreeSet<&str> = every.iter().filter_map(|case| goes_on_with(&case.texts("relays"))).collect();
    assert_eq!(kinds, ["at once", "grace", "settled"].into_iter().collect());
    let timeout = Duration::from_millis(TIMEOUT_MS);
    for case in every {
        let states = case.texts("relays");
        let expected = case.field("expected");
        let expected =
            (expected.field("answered").as_bool().unwrap(), expected.field("complete").as_bool().unwrap());
        let when = goes_on_with(&states);
        let makers: Vec<(Maker, Option<u64>)> = states
            .iter()
            .map(|state| {
                let maker = match (state.as_str(), when) {
                    ("complete", _) => turns.next(&[Maker::Few, Maker::Pages, Maker::Caps]),
                    ("incomplete", Some("settled")) => {
                        turns.next(&[Maker::OneSecond, Maker::StallsAtPage2, Maker::TwentyPages])
                    }
                    ("incomplete", _) => turns.next(&[Maker::OneSecond, Maker::TwentyPages]),
                    ("failed", Some("settled")) => turns.next(&[Maker::RefusesConnections, Maker::Mute]),
                    ("failed", _) => turns.next(&[Maker::RefusesConnections]),
                    // A relay still reading when the read goes on: a slow one past a majority's
                    // grace; else a mute one, before its first page runs out of time. Where the
                    // pool never goes on with one still reading, a mute one, failed once its
                    // first page ran out of time: it answered no more than one that failed.
                    ("reading", Some("grace")) => turns.next(&[Maker::SlowPager]),
                    ("reading", _) => turns.next(&[Maker::Mute]),
                    (other, _) => panic!("no state {other} in onEveryRelay"),
                };
                (maker, None)
            })
            .collect();
        let outcome = read(&makers, true).await;
        let name = case.text("name");
        if (outcome.answered, outcome.complete) != expected {
            failures.push(format!(
                "onEveryRelay, {name}: answered {}, complete {}",
                outcome.answered, outcome.complete
            ));
        }
        match when {
            // The relays still reading were waited for a timeout after the majority, not until
            // they end.
            Some("grace") => {
                if outcome.elapsed < timeout {
                    failures.push(format!("onEveryRelay, {name}: went on after {:?}", outcome.elapsed));
                }
                for (index, (_, relay)) in outcome.relays.iter().enumerate() {
                    let queries = relay.as_ref().map_or(0, |relay| relay.queries().len());
                    if states[index] == "reading" && queries >= MAX_PAGES {
                        failures.push(format!(
                            "onEveryRelay, {name}: a relay still reading read {queries} pages"
                        ));
                    }
                }
            }
            // Before a mute relay's first page could run out of time: it was still reading.
            Some("at once") if outcome.elapsed >= timeout => {
                failures.push(format!("onEveryRelay, {name}: went on after {:?}", outcome.elapsed));
            }
            // Waited for until the relays still reading failed.
            None if outcome.elapsed < timeout => {
                failures.push(format!("onEveryRelay, {name}: went on after {:?}", outcome.elapsed));
            }
            _ => {}
        }
    }
    assert!(failures.is_empty(), "relay-reads.json end to end:\n{}", failures.join("\n"));
    // Each state was made more than one way, and every way used.
    assert_eq!(turns.used, MAKERS.into_iter().collect());
}
