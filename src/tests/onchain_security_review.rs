//! More attacks on on-chain payments (F1, F2, G3, G4, H1, H2, I1, L1 to L3, R6, R7, and S6 for
//! witnesses), end to end against local relays and fakes of the explorers. Each test states what
//! must hold (onchain_security.rs holds S1 to S6).

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use super::support::chain::{deposit_address, payment, txid};
use super::support::merchant::TestMerchant;
use super::support::random::TestClock;
use super::support::relay::{LocalRelay, RelayBehaviour, SlowWrites};
use crate::client::Client;
use crate::declaration::{DeclaredPrice, registry_of};
use crate::derive::{Sale, lease_address, sale_of, sha256};
use crate::error::{Error, ErrorCode};
use crate::json::Json;
use crate::model::{Invoice, PaymentStatus};
use crate::nostr::event::{Event, EventTemplate, sign_event, valid_event};
use crate::nostr::record::{Seal, seal_record};
use crate::nostr::relay::{PageEnd, after_complete_page, entry_in_answer};
use crate::onchain::lease::{LeaseHold, LeaseTerms, lease_event, open_lease_record, withdrawal_event};
use crate::onchain::witness::{address_tag, order_tag, seen_of, witness_address};
use crate::order::Order;
use crate::runtime::{Clock, OsRandom, Random};
use crate::secret::Secret;
use crate::text::to_hex;

fn lot() -> Vec<String> {
    (1..=3).map(deposit_address).collect()
}

fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    merchant.publish_channel(&merchant.channel_value(100, Json::object([("relays", relays)])), 100);
    merchant
}

fn client(merchant: &TestMerchant) -> Client {
    merchant.client().build().unwrap()
}

fn sale_of_ref(merchant: &TestMerchant, reference: &str) -> Sale {
    sale_of(
        &merchant.integration_key,
        &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
        reference,
    )
}

fn terms(
    address: &str,
    sats: u64,
    created_at: i64,
    seconds: i64,
    note: &str,
    confirmed: Option<bool>,
) -> LeaseTerms {
    LeaseTerms {
        address: address.to_owned(),
        sats,
        invoice: None,
        verify_url: None,
        created_at,
        expires_at: created_at + seconds,
        price: DeclaredPrice { minor: sats, digits: 0, currency: "SAT".to_owned() },
        note: note.to_owned(),
        tolerance: 0,
        confirmed,
    }
}

/// The lease of `address` by the sale of `reference`, from `created_at` for `seconds`.
fn lease_by(merchant: &TestMerchant, reference: &str, address: &str, created_at: i64, seconds: i64) -> Event {
    lease_event(
        &sale_of_ref(merchant, reference),
        &terms(address, 1000, created_at, seconds, reference, None),
        created_at,
        &OsRandom,
    )
    .unwrap()
}

/// Zeros: the auxiliary data of a throwaway signature.
struct Zeros;

impl Random for Zeros {
    fn fill(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

/// A record anybody writes at a registry address (it is public): a throwaway key signs it.
fn junk(d: &str, created_at: i64, seed: usize) -> Event {
    let secret = Secret::new(sha256(format!("throwaway {seed}").as_bytes()));
    sign_event(
        EventTemplate {
            kind: 30078.0,
            created_at,
            tags: vec![vec!["d".to_owned(), d.to_owned()]],
            content: "x".to_owned(),
        },
        &secret,
        &Zeros,
    )
}

fn relays(merchant: &TestMerchant) -> Vec<LocalRelay> {
    merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect()
}

/// Every relay of the key takes `event`.
fn everywhere(relays: &[LocalRelay], event: &Event) {
    for relay in relays {
        relay.take(event);
    }
}

fn has_d(event: &Event, d: &str) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.first().map(String::as_str) == Some("d") && tag.get(1).map(String::as_str) == Some(d))
}

/// The kinds of the records of `author` at `d` a relay holds: "lease" or "withdrawn".
fn lease_kinds(merchant: &TestMerchant, relay: &LocalRelay, d: &str, author: &str) -> Vec<&'static str> {
    relay
        .events()
        .iter()
        .filter_map(|value| {
            let event = valid_event(value)?;
            (event.pubkey == author && has_d(&event, d)).then(|| {
                match open_lease_record(value, &merchant.registry_key, d).map(|record| record.outside) {
                    Some(LeaseHold::Lease { .. }) => "lease",
                    Some(LeaseHold::Withdrawn) => "withdrawn",
                    Some(LeaseHold::Newer) => "newer",
                    None => "unopened",
                }
            })
        })
        .collect()
}

fn address_of(result: &Result<Invoice, Error>) -> Option<String> {
    result.as_ref().ok().and_then(|invoice| invoice.onchain_address.clone())
}

fn code<T: std::fmt::Debug>(result: &Result<T, Error>) -> Option<ErrorCode> {
    result.as_ref().err().map(Error::code)
}

mod f1_f2_leases_withdrawn_or_confirmed {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn f1_a_withdrawal_on_one_relay_only_frees_the_address_there_for_another_order() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let relays = relays(&merchant);
        let start = merchant.now();
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let author = sale_of_ref(&merchant, "F1-R").author;
        // Another server's short lease of the address reaches every relay right after R's: R's
        // lease is not confirmed. R's withdrawal of it reaches r1 only.
        let raced = Arc::new(AtomicBool::new(false));
        let competing = lease_by(&merchant, "F1-C", &lot[0], start, 60);
        for (index, relay) in relays.iter().enumerate() {
            let (raced, author, competing, all, d) =
                (raced.clone(), author.clone(), competing.clone(), relays.clone(), d.clone());
            let taken = Arc::new(AtomicUsize::new(0));
            let mine = author.clone();
            relay.set_behaviour(RelayBehaviour {
                on_event: Some(Arc::new(move |event: &Event, _| {
                    if raced.load(Ordering::SeqCst) || event.pubkey != author {
                        return;
                    }
                    raced.store(true, Ordering::SeqCst);
                    everywhere(&all, &competing);
                })),
                refuse_event: Some(Arc::new(move |event: &Event| {
                    (index != 0
                        && event.pubkey == mine
                        && has_d(event, &d)
                        && taken.fetch_add(1, Ordering::SeqCst) > 0)
                        .then(|| "blocked: rate-limited".to_owned())
                })),
                ..RelayBehaviour::default()
            });
        }
        let result = client(&merchant).create_invoice(&Order::sats("F1-R", 49_000)).await;
        assert_eq!(code(&result), Some(ErrorCode::OnchainUnavailable));
        for relay in &relays {
            relay.set_behaviour(RelayBehaviour::default());
        }
        assert_eq!(lease_kinds(&merchant, &relays[0], &d, &author), vec!["withdrawn"]);
        assert_eq!(lease_kinds(&merchant, &relays[1], &d, &author), vec!["lease"]);
        assert_eq!(lease_kinds(&merchant, &relays[2], &d, &author), vec!["lease"]);
        // The other lease over; R's still running on r2 and r3.
        merchant.set_now(start + 600);
        relays[0].set_behaviour(RelayBehaviour::delayed(500));
        let again = client(&merchant).create_invoice(&Order::sats("F1-R", 49_000)).await;
        // R's lease was never confirmed: it gives R no address, and still holds it where it is.
        assert_eq!(code(&again), Some(ErrorCode::OnchainUnavailable));
        relays[0].set_behaviour(RelayBehaviour::default());
        relays[1].set_behaviour(RelayBehaviour::delayed(500));
        let other = client(&merchant).create_invoice(&Order::sats("F1-D", 49_000)).await;
        // Read on r1 and r3, R's withdrawal is its newest record: the address is free for D.
        assert_eq!(address_of(&other).as_deref(), Some(lot[0].as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn f2_an_invoice_shown_and_paid_keeps_its_address_when_the_order_asks_again() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..2], 91);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let relays = relays(&merchant);
        let client = client(&merchant);
        let a = client.create_invoice(&Order::sats("F2-A", 49_000).duration_seconds(900)).await.unwrap();
        let x = a.onchain_address.clone().unwrap();
        merchant.chain.add(&x, payment(&txid("F2 pays"), &x, 49_000));
        let status = client.get_status(&a).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: 49_000, .. }), "{status:?}");
        // Another server's lease of x, its withdrawal on r1 only (a blip).
        let b = sale_of_ref(&merchant, "F2-B");
        everywhere(&relays, &lease_by(&merchant, "F2-B", &x, merchant.now() + 1, 900));
        relays[0].take(&withdrawal_event(&b, &x, merchant.now() + 2, &OsRandom));
        merchant.advance(30);
        relays[0].set_behaviour(RelayBehaviour::delayed(500));
        let again =
            client.create_invoice(&Order::sats("F2-A", 49_000).duration_seconds(900)).await.unwrap_err();
        assert_eq!(again.code(), ErrorCode::InvoicePending);
        assert_eq!(again.invoice().unwrap().onchain_address.as_deref(), Some(x.as_str()));
    }
}

#[tokio::test(start_paused = true)]
async fn g3_the_lease_a_flood_kept_from_being_confirmed_is_withdrawn() {
    let merchant = merchant();
    let lot = lot();
    merchant.publish_lot(&lot[..1], 91);
    // On-chain only: no address, no invoice.
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let d = lease_address(&merchant.registry_key, &lot[0]);
    let author = sale_of_ref(&merchant, "G3-1").author;
    let relays = relays(&merchant);
    // Whoever watches the relays sees the new lease, and fills its d tag at once: 101 records of
    // one second, so that no read of it is complete.
    let flooded = Arc::new(AtomicBool::new(false));
    for relay in &relays {
        let (flooded, author, all, d, clock) =
            (flooded.clone(), author.clone(), relays.clone(), d.clone(), merchant.clock.clone());
        relay.set_behaviour(RelayBehaviour {
            on_event: Some(Arc::new(move |event: &Event, _| {
                if flooded.load(Ordering::SeqCst) || event.pubkey != author {
                    return;
                }
                flooded.store(true, Ordering::SeqCst);
                for i in 0..101 {
                    everywhere(&all, &junk(&d, clock.now(), i));
                }
            })),
            ..RelayBehaviour::default()
        });
    }
    let result = client(&merchant).create_invoice(&Order::sats("G3-1", 49_000)).await;
    assert_eq!(code(&result), Some(ErrorCode::OnchainUnavailable));
    assert!(flooded.load(Ordering::SeqCst));
    for relay in &relays {
        assert_eq!(lease_kinds(&merchant, relay, &d, &author), vec!["withdrawn"]);
    }
    // The flood over (its records gone): the address is free at once, not at the lease's end.
    let junk_authors: HashSet<String> = relays[0]
        .events()
        .iter()
        .filter_map(valid_event)
        .filter(|event| has_d(event, &d) && event.pubkey != author)
        .map(|event| event.pubkey)
        .collect();
    let junk_authors = Arc::new(junk_authors);
    for relay in &relays {
        let junk_authors = junk_authors.clone();
        relay.set_behaviour(RelayBehaviour {
            hide: Some(Arc::new(move |value: &Json| {
                value.get("pubkey").and_then(Json::as_str).is_some_and(|pubkey| junk_authors.contains(pubkey))
            })),
            ..RelayBehaviour::default()
        });
    }
    let next = client(&merchant).create_invoice(&Order::sats("G3-2", 49_000)).await.unwrap();
    assert_eq!(next.onchain_address.as_deref(), Some(lot[0].as_str()));
}

#[tokio::test(start_paused = true)]
async fn g4_of_two_invoices_that_may_still_be_paid_the_one_shown_and_paid_wins() {
    let merchant = merchant();
    let lot = lot();
    merchant.publish_lot(&lot[..2], 91);
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let relays = relays(&merchant);
    let author = sale_of_ref(&merchant, "G4-R").author;
    // The lease's mark (its second record) reaches r1 only: network, nothing shown.
    let first: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    for relay in &relays[1..] {
        let (first, author) = (first.clone(), author.clone());
        let taken = Arc::new(AtomicUsize::new(0));
        relay.set_behaviour(RelayBehaviour {
            refuse_event: Some(Arc::new(move |event: &Event| {
                if event.pubkey != author {
                    return None;
                }
                let d = event.tag("d").unwrap_or("").to_owned();
                let first = first.lock().unwrap().get_or_insert(d.clone()).clone();
                (d == first && taken.fetch_add(1, Ordering::SeqCst) > 0)
                    .then(|| "blocked: rate-limited".to_owned())
            })),
            ..RelayBehaviour::default()
        });
    }
    let client = client(&merchant);
    assert_eq!(code(&client.create_invoice(&Order::sats("G4-R", 49_000)).await), Some(ErrorCode::Network));
    // Asked again while r1 is slow: its lease reads as not confirmed, so another invoice is made,
    // shown and paid.
    relays[1].set_behaviour(RelayBehaviour::default());
    relays[2].set_behaviour(RelayBehaviour::default());
    relays[0].set_behaviour(RelayBehaviour::delayed(500));
    let shown = client.create_invoice(&Order::sats("G4-R", 49_000)).await.unwrap();
    let address = shown.onchain_address.clone().expect("an address");
    relays[0].set_behaviour(RelayBehaviour::default());
    let t = payment(&txid("G4 shown"), &address, 49_000);
    merchant.chain.add(&address, t.clone());
    assert_eq!(client.get_status(&shown).await.unwrap().state(), "unconfirmed");
    merchant.chain.confirm(&address, &t.txid, merchant.chain.height() - 5);
    // Asked again, every relay answering: the first invoice is confirmed on r1, older, and may
    // still be paid; the order was paid with the one shown.
    let again = client.create_invoice(&Order::sats("G4-R", 49_000)).await.unwrap_err();
    assert_eq!(again.code(), ErrorCode::OrderPaid);
    assert_eq!(again.invoice().unwrap().onchain_address.as_deref(), Some(address.as_str()));
}

#[tokio::test(start_paused = true)]
async fn h1_the_call_of_one_order_that_loses_never_ends_the_lease_of_the_one_that_won() {
    let merchant = merchant();
    let lot = lot();
    merchant.publish_lot(&lot[..1], 91);
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let relays = relays(&merchant);
    let d = lease_address(&merchant.registry_key, &lot[0]);
    let author = sale_of_ref(&merchant, "H1-R").author;
    let c = merchant.now();
    // Once the winner's mark (created_at c + 1) is kept, two seconds pass.
    for relay in &relays {
        let (d, author, clock) = (d.clone(), author.clone(), merchant.clock.clone());
        relay.set_behaviour(RelayBehaviour {
            on_event: Some(Arc::new(move |event: &Event, _| {
                if event.pubkey == author && event.created_at == c + 1 && has_d(event, &d) {
                    clock.set(c + 2);
                }
            })),
            ..RelayBehaviour::default()
        });
    }
    // The loser's writes reach the relays 300 ms late (two servers: the order's lock failed).
    let slow = merchant
        .client()
        .websocket_client(SlowWrites { net: merchant.net.clone(), delay: Duration::from_millis(300) })
        .build()
        .unwrap();
    let fast = client(&merchant);
    let order = Order::sats("H1-R", 49_000);
    let (loser, winner) = tokio::join!(slow.create_invoice(&order), fast.create_invoice(&order));
    for relay in &relays {
        relay.set_behaviour(RelayBehaviour::default());
    }
    assert_eq!(code(&loser), Some(ErrorCode::OnchainUnavailable), "{loser:?}");
    assert_eq!(address_of(&winner).as_deref(), Some(lot[0].as_str()), "{winner:?}");
    // The winner's mark stays the order's newest record there, on every relay.
    for relay in &relays {
        assert_eq!(lease_kinds(&merchant, relay, &d, &author), vec!["lease"]);
    }
    merchant.set_now(c + 30);
    // Another order gets no address; the order's invoice is still the one handed out.
    assert_eq!(
        code(&client(&merchant).create_invoice(&Order::sats("H1-D", 49_000)).await),
        Some(ErrorCode::OnchainUnavailable)
    );
    let again = client(&merchant).create_invoice(&Order::sats("H1-R", 49_000)).await.unwrap_err();
    assert_eq!(again.code(), ErrorCode::InvoicePending);
    assert_eq!(again.invoice().unwrap().onchain_address.as_deref(), Some(lot[0].as_str()));
}

/// The test's clock, `skew` seconds ahead: another server's.
struct Skewed(TestClock, i64);

impl Clock for Skewed {
    fn now_ms(&self) -> i64 {
        (self.0.now() + self.1) * 1000
    }
}

mod h2_of_two_invoices_that_may_still_be_paid_the_one_shown_is_handed_out {
    use super::*;

    /// Call 1 (its server's clock `skew` s ahead): its mark reaches r1 only, network. Call 2 (r1
    /// slow) makes and shows another invoice. Call 3 (r2 slow) reads both.
    async fn two_pending(skew: i64) {
        let merchant = merchant();
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let lot = lot();
        let (x, y) = (lot[0].clone(), lot[1].clone());
        merchant.publish_lot(std::slice::from_ref(&x), 91);
        let relays = relays(&merchant);
        let author = sale_of_ref(&merchant, "H2-R").author;
        let c1 = merchant.now() + skew;
        for relay in &relays[1..] {
            let author = author.clone();
            relay.set_behaviour(RelayBehaviour {
                refuse_event: Some(Arc::new(move |event: &Event| {
                    (event.pubkey == author && event.created_at > c1).then(|| "error: down".to_owned())
                })),
                ..RelayBehaviour::default()
            });
        }
        let ahead = merchant.client().clock(Skewed(merchant.clock.clone(), skew)).build().unwrap();
        assert_eq!(code(&ahead.create_invoice(&Order::sats("H2-R", 49_000)).await), Some(ErrorCode::Network));
        merchant.publish_lot(&[x.clone(), y.clone()], 92);
        relays[1].set_behaviour(RelayBehaviour::default());
        relays[2].set_behaviour(RelayBehaviour::default());
        relays[0].set_behaviour(RelayBehaviour::delayed(500));
        let shown = client(&merchant).create_invoice(&Order::sats("H2-R", 49_000)).await.unwrap();
        assert_eq!(shown.onchain_address.as_deref(), Some(y.as_str()));
        relays[0].set_behaviour(RelayBehaviour::default());
        relays[1].set_behaviour(RelayBehaviour::delayed(500));
        let again = client(&merchant).create_invoice(&Order::sats("H2-R", 49_000)).await.unwrap_err();
        assert_eq!(again.code(), ErrorCode::InvoicePending);
        assert_eq!(again.invoice().unwrap().onchain_address, shown.onchain_address);
    }

    #[tokio::test(start_paused = true)]
    async fn the_failed_call_server_clock_3_s_ahead() {
        two_pending(3).await;
    }

    #[tokio::test(start_paused = true)]
    async fn both_of_one_second_the_one_never_shown_sorting_last() {
        two_pending(0).await;
    }
}

#[tokio::test(start_paused = true)]
async fn i1_an_object_that_only_carries_the_id_of_the_mark_never_shown_counts_for_nothing() {
    let merchant = merchant();
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let lot = lot();
    let (x, y) = (lot[0].clone(), lot[1].clone());
    merchant.publish_lot(std::slice::from_ref(&x), 91);
    let relays = relays(&merchant);
    let author = sale_of_ref(&merchant, "I1-R").author;
    let c = merchant.now();
    // Call 1: its mark reaches r1 only, network.
    for relay in &relays[1..] {
        let author = author.clone();
        relay.set_behaviour(RelayBehaviour {
            refuse_event: Some(Arc::new(move |event: &Event| {
                (event.pubkey == author && event.created_at > c).then(|| "error: down".to_owned())
            })),
            ..RelayBehaviour::default()
        });
    }
    assert_eq!(
        code(&client(&merchant).create_invoice(&Order::sats("I1-R", 49_000)).await),
        Some(ErrorCode::Network)
    );
    // Call 2: r1 slow and refusing the order's records; its invoice, on y, is shown.
    merchant.publish_lot(&[x.clone(), y.clone()], 92);
    merchant.set_now(c + 30);
    relays[1].set_behaviour(RelayBehaviour::default());
    relays[2].set_behaviour(RelayBehaviour::default());
    {
        let author = author.clone();
        relays[0].set_behaviour(RelayBehaviour {
            query_delay_ms: Some(500),
            refuse_event: Some(Arc::new(move |event: &Event| {
                (event.pubkey == author).then(|| "error: down".to_owned())
            })),
            ..RelayBehaviour::default()
        });
    }
    let shown = client(&merchant).create_invoice(&Order::sats("I1-R", 49_000)).await.unwrap();
    assert_eq!(shown.onchain_address.as_deref(), Some(y.as_str()));
    let at = |relay: &LocalRelay, address: &str| {
        let d = lease_address(&merchant.registry_key, address);
        relay
            .events()
            .iter()
            .filter_map(valid_event)
            .find(|event| event.pubkey == author && has_d(event, &d))
            .unwrap()
    };
    let mark_x = at(&relays[0], &x);
    let mark_y = at(&relays[1], &y);
    // Call 3: r3 hides y's mark, and sends an object that only carries x's mark's id.
    relays[0].set_behaviour(RelayBehaviour::default());
    let hidden = mark_y.id.clone();
    relays[2].set_behaviour(RelayBehaviour {
        hide: Some(Arc::new(move |value: &Json| {
            value.get("id").and_then(Json::as_str) == Some(hidden.as_str())
        })),
        ..RelayBehaviour::default()
    });
    let mut carrier = mark_x.clone();
    carrier.content = "not the event".to_owned();
    carrier.sig = "00".repeat(64);
    relays[2].store_event(&carrier);
    merchant.set_now(c + 60);
    let again = client(&merchant).create_invoice(&Order::sats("I1-R", 49_000)).await.unwrap_err();
    assert_eq!(again.code(), ErrorCode::InvoicePending);
    assert_eq!(again.invoice().unwrap().onchain_address.as_deref(), Some(y.as_str()));
}

#[tokio::test(start_paused = true)]
async fn s6_witnesses_read_again_on_every_relay_still_show_the_one_a_relay_hides() {
    let merchant = merchant();
    merchant.publish_lot(&lot()[..1], 91);
    let client = merchant.client().relay_timeout_ms(4000).build().unwrap();
    let p = client.create_invoice(&Order::sats("W6-P", 49_000)).await.unwrap();
    let x = p.onchain_address.clone().unwrap();
    let t = payment(&txid("W6 paid once"), &x, 49_000);
    // Another order's witness of t, in time for it: on r1 (which hides it) and r2 (late), not r3.
    let seen = seen_of(&merchant.integration_key);
    let other = sale_of_ref(&merchant, "W6-N").author;
    let value = Json::object([
        ("version", Json::unsigned(1)),
        ("address", Json::from(x.as_str())),
        ("txid", Json::from(t.txid.as_str())),
        ("sale", Json::from(other.as_str())),
        ("sats", Json::unsigned(49_000)),
        ("inputs", Json::array(t.coins().iter().map(|coin| Json::from(coin.as_str())).collect())),
        ("replacement", Json::Bool(false)),
        ("expiresAt", Json::integer(p.expires_at)),
    ]);
    let witness = seal_record(
        Seal {
            record_type: "integration-onchain-seen",
            value,
            signer: &seen.secret_key,
            encryption_key: &seen.encryption_key,
            address: &witness_address(&seen.address_key, &x, &t.txid, Some(&other)),
            created_at: merchant.now(),
            tags: vec![
                vec!["o".to_owned(), order_tag(&seen.address_key, &x, Some(&other))],
                vec!["o".to_owned(), address_tag(&seen.address_key, &x)],
            ],
        },
        &OsRandom,
    )
    .unwrap();
    let relays = relays(&merchant);
    relays[0].take(&witness);
    relays[1].take(&witness);
    let hidden = witness.id.clone();
    relays[0].set_behaviour(RelayBehaviour {
        hide: Some(Arc::new(move |value: &Json| {
            value.get("id").and_then(Json::as_str) == Some(hidden.as_str())
        })),
        ..RelayBehaviour::default()
    });
    relays[1].set_behaviour(RelayBehaviour::delayed(1500));
    merchant.chain.add(&x, t);
    // The first read (r1 and r3) misses it, so this check publishes its own witness; read again on
    // every relay, r2 shows the other's: t is another invoice's, and counts for nothing here.
    let status = client.get_status(&p).await.unwrap();
    assert!(matches!(status, PaymentStatus::Open { received: 0, .. }), "{status:?}");
}

#[tokio::test(start_paused = true)]
async fn r6_a_relay_that_failed_is_waited_for_once_per_call() {
    let merchant = merchant();
    let lot = lot();
    merchant.publish_lot(&lot[..2], 91);
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let relays = relays(&merchant);
    let author = sale_of_ref(&merchant, "R6-R").author;
    // Each lease of the order meets another server's lease of its address at once: not confirmed.
    let competing: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let others: Vec<(String, Event)> = lot[..2]
        .iter()
        .map(|address| {
            (
                lease_address(&merchant.registry_key, address),
                lease_by(&merchant, &format!("R6-OTHER-{address}"), address, merchant.now(), 900),
            )
        })
        .collect();
    let others = Arc::new(others);
    for relay in &relays[..2] {
        let (competing, author, others, pair) =
            (competing.clone(), author.clone(), others.clone(), vec![relays[0].clone(), relays[1].clone()]);
        relay.set_behaviour(RelayBehaviour {
            on_event: Some(Arc::new(move |event: &Event, _| {
                let Some(d) = event.tag("d").map(str::to_owned) else { return };
                if event.pubkey != author || !competing.lock().unwrap().insert(d.clone()) {
                    return;
                }
                let Some((_, other)) = others.iter().find(|(known, _)| *known == d) else { return };
                for relay in &pair {
                    relay.take(other);
                }
            })),
            ..RelayBehaviour::default()
        });
    }
    relays[2].set_behaviour(RelayBehaviour::mute());
    let started = Instant::now();
    let result = merchant
        .client()
        .relay_timeout_ms(1000)
        .build()
        .unwrap()
        .create_invoice(&Order::sats("R6-R", 49_000))
        .await;
    let elapsed = started.elapsed();
    assert_eq!(code(&result), Some(ErrorCode::OnchainUnavailable));
    assert_eq!(competing.lock().unwrap().len(), 2);
    // The first confirmation waits for r3 until its timeout; the second counts it failed at once.
    assert!(elapsed < Duration::from_millis(1700), "{elapsed:?}");
}

#[tokio::test(start_paused = true)]
async fn r7_a_relay_that_holds_the_lease_still_paging_at_the_cut_still_shows_it() {
    let merchant = merchant();
    let lot = lot();
    merchant.publish_lot(&lot[..1], 91);
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let d = lease_address(&merchant.registry_key, &lot[0]);
    let relays = relays(&merchant);
    // Anybody's records at the address's d tag, older than the lease: 20 pages to read.
    for i in 0..1950 {
        everywhere(&relays, &junk(&d, merchant.now() - 10 - i as i64, i));
    }
    let lease = lease_by(&merchant, "R7-A", &lot[0], merchant.now(), 900);
    // r1 missed the lease; h hides it; r2 answers each page in 150 ms, its 20 pages outlasting the
    // one timeout the read waits after a majority.
    relays[1].take(&lease);
    relays[2].take(&lease);
    let hidden = lease.id.clone();
    relays[1].set_behaviour(RelayBehaviour {
        hide: Some(Arc::new(move |value: &Json| {
            value.get("id").and_then(Json::as_str) == Some(hidden.as_str())
        })),
        ..RelayBehaviour::default()
    });
    relays[2].set_behaviour(RelayBehaviour::delayed(150));
    let result = merchant
        .client()
        .relay_timeout_ms(1000)
        .build()
        .unwrap()
        .create_invoice(&Order::sats("R7-D", 49_000))
        .await;
    assert_eq!(code(&result), Some(ErrorCode::OnchainUnavailable));
}

/// What a relay does once it took a lease.
type OnLease = Arc<dyn Fn(&LocalRelay, &Event) + Send + Sync>;

#[tokio::test(start_paused = true)]
async fn r8_a_relay_still_reading_when_the_confirmation_goes_on_is_no_answer_network() {
    let merchant = merchant();
    let lot = lot();
    merchant.publish_lot(&lot[..1], 91);
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
    let d = lease_address(&merchant.registry_key, &lot[0]);
    let author = sale_of_ref(&merchant, "R8-R").author;
    let relays = relays(&merchant);
    // Once each took the lease: r1 holds more than a page of anybody's records of its second (its
    // read ends incomplete at once), r2 answers nothing more (it fails at its timeout), r3 sends its
    // first page late and never its second (still reading when r2 fails: a majority can no longer
    // read completely, the read goes on).
    let on_lease = |change: OnLease| {
        let (author, d, done) = (author.clone(), d.clone(), Arc::new(AtomicBool::new(false)));
        RelayBehaviour {
            on_event: Some(Arc::new(move |event: &Event, relay: &LocalRelay| {
                if event.pubkey == author && has_d(event, &d) && !done.swap(true, Ordering::SeqCst) {
                    change(relay, event);
                }
            })),
            ..RelayBehaviour::default()
        }
    };
    let junk_d = d.clone();
    relays[0].set_behaviour(on_lease(Arc::new(move |relay, lease| {
        for seed in 0..150 {
            relay.take(&junk(&junk_d, lease.created_at, seed));
        }
    })));
    relays[1].set_behaviour(on_lease(Arc::new(|relay, _| relay.update(|behaviour| behaviour.mute = true))));
    let junk_d = d.clone();
    relays[2].set_behaviour(on_lease(Arc::new(move |relay, lease| {
        for seed in 0..150 {
            relay.take(&junk(&junk_d, lease.created_at - 1 - seed as i64, 1000 + seed));
        }
        relay.update(|behaviour| {
            behaviour.query_delay_ms = Some(500);
            behaviour.mute_query = Some(Arc::new(|filter: &Json| filter.has("until")));
        });
    })));
    let result = merchant
        .client()
        .relay_timeout_ms(1000)
        .build()
        .unwrap()
        .create_invoice(&Order::sats("R8-R", 49_000))
        .await;
    // r3's page counts as records, never as an answer: fewer than a majority answered.
    assert_eq!(code(&result), Some(ErrorCode::Network));
    // Not confirmed: withdrawn.
    assert_eq!(lease_kinds(&merchant, &relays[0], &d, &author), vec!["withdrawn"]);
}

mod l1_l2_a_lease_not_confirmed_beside_another_call_mark {
    use super::*;

    /// The mark of another call of the order `reference`: its lease of `address` at `c`,
    /// confirmed at c + 1.
    fn mark_of(merchant: &TestMerchant, reference: &str, address: &str, c: i64) -> Event {
        lease_event(
            &sale_of_ref(merchant, reference),
            &terms(address, 49_000, c, 900, reference, Some(true)),
            c + 1,
            &OsRandom,
        )
        .unwrap()
    }

    /// The withdrawals of `author` at `d` the relays received.
    fn withdrawals(merchant: &TestMerchant, d: &str, author: &str) -> Vec<Event> {
        relays(merchant)
            .iter()
            .flat_map(LocalRelay::received)
            .filter(|event| {
                event.pubkey == author
                    && open_lease_record(&event.to_json(), &merchant.registry_key, d)
                        .is_some_and(|record| record.outside == LeaseHold::Withdrawn)
            })
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn l1_fewer_than_a_majority_answer_the_confirmation_the_minority_showing_the_mark_not_withdrawn() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let author = sale_of_ref(&merchant, "L1-R").author;
        let mark = mark_of(&merchant, "L1-R", &lot[0], merchant.now());
        let relays = relays(&merchant);
        // Once this call's lease is taken, the other call's mark is everywhere, and r2 and r3
        // answer reads too late (their writes at once).
        let marked = Arc::new(AtomicBool::new(false));
        for relay in &relays {
            let (marked, author, mark, all) = (marked.clone(), author.clone(), mark.clone(), relays.clone());
            relay.set_behaviour(RelayBehaviour {
                on_event: Some(Arc::new(move |event: &Event, _| {
                    if marked.load(Ordering::SeqCst) || event.pubkey != author {
                        return;
                    }
                    marked.store(true, Ordering::SeqCst);
                    everywhere(&all, &mark);
                    all[1].set_behaviour(RelayBehaviour::delayed(5000));
                    all[2].set_behaviour(RelayBehaviour::delayed(5000));
                })),
                ..RelayBehaviour::default()
            });
        }
        assert_eq!(
            code(&client(&merchant).create_invoice(&Order::sats("L1-R", 49_000)).await),
            Some(ErrorCode::Network)
        );
        for relay in &relays {
            relay.set_behaviour(RelayBehaviour::default());
        }
        // r1 showed the mark: no withdrawal, which could have replaced it (same second, a lower id).
        assert!(withdrawals(&merchant, &d, &author).is_empty());
        for relay in &relays {
            assert_eq!(lease_kinds(&merchant, relay, &d, &author), vec!["lease"]);
        }
        merchant.advance(30);
        assert_eq!(
            code(&client(&merchant).create_invoice(&Order::sats("L1-D", 49_000)).await),
            Some(ErrorCode::OnchainUnavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn l2_a_copy_of_the_mark_with_a_damaged_signature_sent_first_hides_no_valid_copy() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let author = sale_of_ref(&merchant, "L2-R").author;
        let mark = mark_of(&merchant, "L2-R", &lot[0], merchant.now());
        let mut damaged = mark.clone();
        damaged.sig = format!("{}{}", if mark.sig.starts_with('0') { "1" } else { "0" }, &mark.sig[1..]);
        let relays = relays(&merchant);
        // r1 sends the damaged copy alone, first; r2 and r3 the valid one, 100 ms later.
        let marked = Arc::new(AtomicBool::new(false));
        for relay in &relays {
            let (marked, author, mark, damaged, all) =
                (marked.clone(), author.clone(), mark.clone(), damaged.clone(), relays.clone());
            relay.set_behaviour(RelayBehaviour {
                on_event: Some(Arc::new(move |event: &Event, _| {
                    if marked.load(Ordering::SeqCst) || event.pubkey != author {
                        return;
                    }
                    marked.store(true, Ordering::SeqCst);
                    everywhere(&all, &mark);
                    all[0].store_event(&damaged);
                    let (id, sig) = (mark.id.clone(), mark.sig.clone());
                    all[0].set_behaviour(RelayBehaviour {
                        hide: Some(Arc::new(move |value: &Json| {
                            value.get("id").and_then(Json::as_str) == Some(id.as_str())
                                && value.get("sig").and_then(Json::as_str) == Some(sig.as_str())
                        })),
                        ..RelayBehaviour::default()
                    });
                    all[1].set_behaviour(RelayBehaviour::delayed(100));
                    all[2].set_behaviour(RelayBehaviour::delayed(100));
                })),
                ..RelayBehaviour::default()
            });
        }
        assert_eq!(
            code(&client(&merchant).create_invoice(&Order::sats("L2-R", 49_000)).await),
            Some(ErrorCode::OnchainUnavailable)
        );
        for relay in &relays {
            relay.set_behaviour(RelayBehaviour::default());
        }
        assert!(withdrawals(&merchant, &d, &author).is_empty());
        for relay in &relays[1..] {
            assert_eq!(lease_kinds(&merchant, relay, &d, &author), vec!["lease"]);
        }
    }
}

#[test]
fn l3_a_full_page_whose_only_new_event_has_no_usable_date_is_asked_again_once_then_the_read_stops_incomplete()
{
    let mut seen = HashSet::new();
    let mut kept: Vec<Json> = Vec::new();
    // Each page the answer of one query, read as the pool reads it.
    let page = |events: &[(String, f64)]| {
        let mut read = HashSet::new();
        events
            .iter()
            .map(|(id, created_at)| {
                let value = Json::object([
                    ("id", Json::from(id.as_str())),
                    ("created_at", Json::Number(*created_at)),
                ]);
                entry_in_answer(&value, &|value: &Json| Some(value.clone()), &mut read)
            })
            .collect::<Vec<_>>()
    };
    let first: Vec<(String, f64)> = (0..100).map(|i| (format!("a{i}"), 1000.0)).collect();
    assert_eq!(after_complete_page(page(&first), &mut seen, &mut kept, 1), PageEnd::Until(1000));
    let mut second: Vec<(String, f64)> = first[..99].to_vec();
    second.push(("new".to_owned(), 2f64.powi(60)));
    // SPEC.md §13: a new event, undated, lets the read go on from the dated ones.
    assert_eq!(after_complete_page(page(&second), &mut seen, &mut kept, 2), PageEnd::Until(1000));
    // The same page again brings nothing new: incomplete, never a loop.
    assert_eq!(after_complete_page(page(&second), &mut seen, &mut kept, 3), PageEnd::Complete(false));
    // Kept all the same, once.
    assert_eq!(kept.len(), 101);
}
