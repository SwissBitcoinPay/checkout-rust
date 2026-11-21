//! What the blockchain shows (SPEC.md §31, Explorers): one explorer of the Esplora API, **the
//! explorer**, asked over HTTP: mempool.space, or the merchant's Bitcoin node when the channel
//! names one (node.rs), mempool.space answering in its place when the node fails and its
//! `fallback` is `"mempool"`; and BlockCypher, for when a transaction was received, asked only
//! about a transaction no check saw while its lease ran. Third parties: they see the server's IP
//! address and what it asks about, never a key. Their answers are checked as strictly as a
//! relay's: anything else is a failure (`network`). A payment counts as made on what the explorer
//! read alone shows.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::error::{Error, ErrorCode};
use crate::http::{Http, Reach, host_of};
use crate::json::Json;
use crate::onchain::node::{BitcoinNode, NodeFallback, parse_node_url};
use crate::protocol::{
    BLOCKCYPHER_URL, MAX_SATS, MEMPOOL_URL, MEMPOOL_WEBSOCKET_URL, NODE_FAILED_RECENTLY_MS,
};
use crate::runtime::Clock;
use crate::text::is_hex32;

/// A transaction, as an explorer gives it, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExplorerTx {
    pub(crate) txid: String,
    /// The coins it spends (`<txid>:<vout>`), coinbase inputs left out, in their order.
    pub(crate) coins: Vec<String>,
    pub(crate) outputs: Vec<(u64, Option<String>)>,
    /// The height of its block; `None` while it is not confirmed.
    pub(crate) block_height: Option<u64>,
}

const MAX_VOUT: u64 = 4_294_967_295;

/// A non-negative safe integer.
fn safe_natural(value: Option<&Json>) -> Option<u64> {
    value?.as_safe_integer().and_then(|value| u64::try_from(value).ok())
}

/// An Esplora transaction, checked; `None` when it is not one. Its outputs together hold at most
/// every bitcoin there will ever be (2 100 000 000 000 000 sats): a transaction that pays more is
/// none (SPEC.md §31, Explorers), and so a sum of what an answer pays fits a u64.
pub(crate) fn parse_transaction(value: &Json) -> Option<ExplorerTx> {
    let txid = value.get("txid")?.as_str().filter(|txid| is_hex32(txid))?;
    let vin = value.get("vin")?.as_array()?;
    let vout = value.get("vout")?.as_array()?;
    let status = value.get("status").filter(|status| status.is_object())?;
    let mut coins = Vec::new();
    for input in vin {
        if !input.is_object() {
            return None;
        }
        if input.get("is_coinbase") == Some(&Json::Bool(true)) {
            continue;
        }
        let spent = input.get("txid")?.as_str().filter(|txid| is_hex32(txid))?;
        let index = safe_natural(input.get("vout")).filter(|&index| index <= MAX_VOUT)?;
        coins.push(format!("{spent}:{index}"));
    }
    let mut outputs = Vec::with_capacity(vout.len());
    for output in vout {
        if !output.is_object() {
            return None;
        }
        let sats = safe_natural(output.get("value"))?;
        let address = match output.get("scriptpubkey_address") {
            None => None,
            Some(address) => Some(address.as_str()?.to_owned()),
        };
        outputs.push((sats, address));
    }
    // More than every bitcoin there will ever be: no transaction, whatever an explorer says (each
    // output a safe integer, the sum of a few fits a u64).
    if outputs.iter().map(|(sats, _)| u128::from(*sats)).sum::<u128>() > u128::from(MAX_SATS) {
        return None;
    }
    let block_height = match status.get("confirmed")?.as_bool()? {
        true => Some(safe_natural(status.get("block_height"))?),
        false => None,
    };
    Some(ExplorerTx { txid: txid.to_owned(), coins, outputs, block_height })
}

/// What `tx` pays `address`: the sum of its outputs to it, every bitcoin at most.
pub(crate) fn pays_to(tx: &ExplorerTx, address: &str) -> u64 {
    tx.outputs
        .iter()
        .filter(|(_, to)| to.as_deref() == Some(address))
        .fold(0u64, |sum, (sats, _)| sum.saturating_add(*sats))
}

/// Its confirmations at the chain's `height`: 0 unconfirmed, else height − its block's + 1, 1 at
/// least.
pub(crate) fn confirmations_of(tx: &ExplorerTx, height: u64) -> u64 {
    match tx.block_height {
        None => 0,
        Some(block) => (height as i128 - block as i128 + 1).max(1) as u64,
    }
}

/// The transactions of `address` on the explorer `at`: its first answer (a deposit address is
/// paid a few times at most), in the explorer's order.
pub(crate) async fn address_transactions(
    at: &ExplorerSource,
    address: &str,
    http: &Http,
) -> Result<Vec<ExplorerTx>, Error> {
    let url = format!("{}/address/{address}/txs", at.rest);
    let answer = http.get_json_at(&url, &[], at.reach()).await?;
    if !answer.ok() {
        return Err(Error::network(format!("{} answered HTTP {}", host_of(&url), answer.status)));
    }
    let body =
        answer.body.ok_or_else(|| Error::network(format!("{} gave no transactions", host_of(&url))))?;
    let items =
        body.as_array().ok_or_else(|| Error::network(format!("{} gave no transactions", host_of(&url))))?;
    items
        .iter()
        .map(|value| {
            parse_transaction(value).ok_or_else(|| {
                Error::network(format!("{} gave a transaction that is not one", host_of(&url)))
            })
        })
        .collect()
}

/// The chain's height on the explorer `at`: a body of 1 to 9 digits (plain text, not JSON).
pub(crate) async fn chain_height(at: &ExplorerSource, http: &Http) -> Result<u64, Error> {
    let url = format!("{}/blocks/tip/height", at.rest);
    let answer = http.get_text(&url, at.reach()).await?;
    if !answer.ok() {
        return Err(Error::network(format!("{} answered HTTP {}", host_of(&url), answer.status)));
    }
    answer
        .body
        .filter(|text| (1..=9).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| Error::network(format!("{} gave no height", host_of(&url))))
}

/// Whether `year` is a leap year of the proleptic Gregorian calendar.
fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days from 1970-01-01 to `year`-`month`-`day` (proleptic Gregorian).
fn days_from_epoch(year: i64, month: i64, day: i64) -> i64 {
    // Howard Hinnant's days_from_civil.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Unix milliseconds of a time as BlockCypher writes it (SPEC.md §31, Explorers): UTC,
/// `YYYY-MM-DDTHH:MM:SS`, a fraction of 1 to 9 digits or none, `Z`; a real date and time (a month
/// of 01 to 12, a day of that month, hours 00 to 23, minutes and seconds 00 to 59: no leap
/// second), the fraction past milliseconds dropped, never rounded. `None` when it is not one.
pub(crate) fn blockcypher_milliseconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.ends_with('Z') {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        if part.bytes().all(|byte| byte.is_ascii_digit()) { part.parse().ok() } else { None }
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    let rest = &text[19..text.len() - 1];
    let millis = if rest.is_empty() {
        0
    } else {
        let fraction = rest.strip_prefix('.')?;
        if !(1..=9).contains(&fraction.len()) || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        format!("{:0<3}", &fraction[..fraction.len().min(3)]).parse::<i64>().ok()?
    };
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    };
    if day < 1 || day > days_in_month {
        return None;
    }
    let seconds = days_from_epoch(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(seconds * 1000 + millis)
}

/// When BlockCypher first received `txid`, in Unix milliseconds (it never changes); `None` when it
/// does not know it yet (HTTP 404: it receives it later). Without a token, BlockCypher takes 100
/// requests an hour from an IP address: it is asked only about a transaction no check saw in time.
pub(crate) async fn received_at(txid: &str, http: &Http) -> Result<Option<i64>, Error> {
    let url = format!("{BLOCKCYPHER_URL}/txs/{txid}?limit=1&includeHex=false");
    let answer = http.get_json(&url, &[]).await?;
    if answer.status == 404 {
        return Ok(None);
    }
    if !answer.ok() {
        return Err(Error::network(format!("{} answered HTTP {}", host_of(&url), answer.status)));
    }
    let no_time = || Error::network(format!("{} gave no time for the transaction", host_of(&url)));
    let body = answer.body.filter(Json::is_object).ok_or_else(no_time)?;
    if body.get("hash").and_then(Json::as_str) != Some(txid) {
        return Err(no_time());
    }
    let received = body.get("received").and_then(Json::as_str).ok_or_else(no_time)?;
    match blockcypher_milliseconds(received) {
        Some(time) if time > 0 => Ok(Some(time)),
        _ => Err(no_time()),
    }
}

/// An explorer a read may ask: the merchant's Bitcoin node, or mempool.space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExplorerName {
    Node,
    Mempool,
}

/// An explorer asked: its name, its REST URL (`<explorer>`) and its WebSocket's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExplorerSource {
    pub(crate) name: ExplorerName,
    pub(crate) rest: String,
    pub(crate) websocket: String,
}

impl ExplorerSource {
    /// mempool.space.
    pub(crate) fn mempool() -> Self {
        Self {
            name: ExplorerName::Mempool,
            rest: MEMPOOL_URL.to_owned(),
            websocket: MEMPOOL_WEBSOCKET_URL.to_owned(),
        }
    }

    /// The rule of its URLs: a node's own (SPEC.md §31, `http` to a local host and an IPv4 address
    /// allowed), else an https URL's.
    pub(crate) fn reach(&self) -> Reach {
        match self.name {
            ExplorerName::Node => Reach::Node,
            ExplorerName::Mempool => Reach::Https,
        }
    }
}

/// The explorers one read asks, in order (SPEC.md §31, `fallback`): without a node, mempool.space;
/// with `"none"`, the node alone; with `"mempool"`, the node then mempool.space, or mempool.space
/// first when the node failed a read less than 60 s ago in the same call (`failed_recently`). The
/// next one is asked only when the one before failed: a read gives the answer of the first that
/// answers, and fails (`network`) when every one asked failed.
pub(crate) fn explorers_to_ask(node: Option<(NodeFallback, bool)>) -> Vec<ExplorerName> {
    match node {
        None => vec![ExplorerName::Mempool],
        Some((NodeFallback::None, _)) => vec![ExplorerName::Node],
        Some((NodeFallback::Mempool, false)) => vec![ExplorerName::Node, ExplorerName::Mempool],
        Some((NodeFallback::Mempool, true)) => vec![ExplorerName::Mempool, ExplorerName::Node],
    }
}

/// When the nodes a call read failed a read, by node URL (Unix milliseconds): of one call alone
/// (`create_invoice`, `get_status`, one `wait_for_payment`), never kept between calls.
pub(crate) type NodeFailures = Arc<Mutex<HashMap<String, i64>>>;

/// The node of an explorer: where it is read, its URL and its fallback.
#[derive(Clone, Debug)]
struct Node {
    source: ExplorerSource,
    url: String,
    fallback: NodeFallback,
}

/// The explorer of a call (SPEC.md §31): mempool.space, or the channel's node with its fallback.
/// Each read follows the fallback on its own; a node that fails is remembered in the call's
/// failures, which its reads (and its WebSocket) share, so that for 60 s it is asked after
/// mempool.space.
#[derive(Clone)]
pub(crate) struct Explorer {
    node: Option<Node>,
    failures: NodeFailures,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Explorer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Explorer").field("node", &self.node).finish_non_exhaustive()
    }
}

impl Explorer {
    /// The explorer of a call whose channel names `node` (`None`: mempool.space), its node's
    /// failures in `failures` (the call's), the time from `clock`.
    pub(crate) fn new(node: Option<&BitcoinNode>, failures: NodeFailures, clock: Arc<dyn Clock>) -> Self {
        let node = node.and_then(|node| {
            let at = parse_node_url(&node.url)?;
            Some(Node {
                source: ExplorerSource { name: ExplorerName::Node, rest: at.rest, websocket: at.websocket },
                url: at.url,
                fallback: node.fallback,
            })
        });
        Self { node, failures, clock }
    }

    /// The explorers the next read asks, in order ([`explorers_to_ask`]).
    pub(crate) fn sources(&self) -> Vec<ExplorerSource> {
        let Some(node) = &self.node else {
            return vec![ExplorerSource::mempool()];
        };
        let failed_at =
            self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&node.url).copied();
        let failed_recently =
            failed_at.is_some_and(|at| self.clock.now_ms().saturating_sub(at) < NODE_FAILED_RECENTLY_MS);
        explorers_to_ask(Some((node.fallback, failed_recently)))
            .into_iter()
            .map(|name| match name {
                ExplorerName::Node => node.source.clone(),
                ExplorerName::Mempool => ExplorerSource::mempool(),
            })
            .collect()
    }

    /// The node failed a read (or its WebSocket a connection): remembered for the call.
    pub(crate) fn node_failed(&self) {
        if let Some(node) = &self.node {
            let now = self.clock.now_ms();
            self.failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(node.url.clone(), now);
        }
    }

    /// One read of the explorer: `run` with each explorer of [`Explorer::sources`], in order,
    /// until one answers. What `run` asks of one explorer at once (the chain's height with the
    /// address's transactions) ends when either fails, and the whole read is asked again of the
    /// next one, never part of it. `network` when every one failed; an error of another code goes
    /// through as it is.
    pub(crate) async fn read<T, F, Fut>(&self, mut run: F) -> Result<T, Error>
    where
        F: FnMut(ExplorerSource) -> Fut,
        Fut: Future<Output = Result<T, Error>>,
    {
        let mut failures: Vec<Error> = Vec::new();
        for source in self.sources() {
            let name = source.name;
            match run(source).await {
                Ok(answer) => return Ok(answer),
                Err(error) if error.code() == ErrorCode::Network => {
                    if name == ExplorerName::Node {
                        self.node_failed();
                    }
                    failures.push(error);
                }
                Err(error) => return Err(error),
            }
        }
        let last = failures.pop().expect("a read asks one explorer at least");
        if failures.is_empty() {
            return Err(last);
        }
        let messages: Vec<&str> = failures.iter().chain([&last]).map(Error::message).collect();
        Err(Error::network(format!(
            "Neither the merchant's Bitcoin node nor mempool.space answered ({})",
            messages.join("; ")
        ))
        .with_source(Box::new(last) as crate::error::Cause))
    }
}
