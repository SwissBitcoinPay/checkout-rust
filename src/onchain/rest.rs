//! The rest of an on-chain underpayment (SPEC.md §31, The rest of an underpayment): when less than
//! the amount came on-chain in time, a payment check asks the merchant's Lightning address for an
//! invoice of the rest, declares it for the order's sale with `rest` (the address and the end), and
//! publishes a rest record, which the pages of the order's checkout links read (they cannot read
//! the registry). From 1 000 sats, the rest is payable on-chain to the same address too; below, in
//! Lightning only.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::declaration::{OpenedDeclaration, d_tag};
use crate::derive::{RestKeys, acceptance_record_address, rest_record_address};
use crate::error::Error;
use crate::json::Json;
use crate::lightning::bolt11;
use crate::model::Rest;
use crate::nostr::event::Event;
use crate::nostr::record::{
    Expected, Newer, Opened, Parsed, Seal, open_event, records_that_open, seal_record,
};
use crate::nostr::relay::{Filter, ReadOf, RelayPool, majority, read_key};
use crate::onchain::address::payment_uri;
use crate::protocol::{
    CHECKOUT_LIFE_SECONDS, CLOCK_TOLERANCE_SECONDS, MIN_REST_SECONDS, ONCHAIN_FLOOR_SATS, RECORD_KIND,
    REST_RECORD_TYPE, REST_VERSION,
};
use crate::runtime::Random;
use crate::secret::Secret;
use crate::urls::parse_https_url;

/// A rest invoice: a declaration of the sale with `rest`, its invoice decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestInvoice {
    pub(crate) bolt11: String,
    pub(crate) payment_hash: String,
    pub(crate) verify_url: String,
    pub(crate) sats: u64,
    /// Its BOLT11 timestamp, and that plus its expiry (Unix seconds).
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}

/// The rest invoice of a declaration with `rest`.
pub(crate) fn rest_invoice_of(declaration: &OpenedDeclaration) -> RestInvoice {
    RestInvoice {
        bolt11: declaration.invoice.clone(),
        payment_hash: declaration.decoded.payment_hash.clone(),
        verify_url: declaration.verify_url.clone(),
        sats: declaration.sats,
        created_at: declaration.decoded.timestamp,
        expires_at: declaration.decoded.expires_at(),
    }
}

/// The order of the rest invoices: by date, then payment hash.
pub(crate) fn by_rest_order(a: &RestInvoice, b: &RestInvoice) -> Ordering {
    a.created_at.cmp(&b.created_at).then_with(|| a.payment_hash.cmp(&b.payment_hash))
}

/// The `rest` of an open status (SPEC.md §31, The status's `rest`): `None` unless `received` is
/// above 0 (and below `sats`) before the invoice's end; else what is left, the latest rest invoice
/// of exactly that amount neither paid (`paid`: the payment hashes paid) nor ended, and its QR
/// code: on-chain to `address` too from 1 000 sats, in Lightning only below.
pub(crate) fn rest_of(
    sats: u64,
    expires_at: i64,
    address: &str,
    received: u64,
    now: i64,
    rests: &[&RestInvoice],
    paid: &HashSet<String>,
) -> Option<Rest> {
    if received == 0 || received >= sats || now >= expires_at {
        return None;
    }
    let rest = sats - received;
    let mut sorted: Vec<&RestInvoice> = rests.to_vec();
    sorted.sort_by(|a, b| by_rest_order(a, b));
    let invoice = sorted.iter().rev().find(|candidate| {
        candidate.sats == rest && !paid.contains(&candidate.payment_hash) && now < candidate.expires_at
    });
    let bolt11 = invoice.map(|invoice| invoice.bolt11.clone());
    let payment_uri = if rest >= ONCHAIN_FLOOR_SATS {
        Some(payment_uri(Some(address), rest, bolt11.as_deref()))
    } else {
        bolt11.as_ref().map(|bolt11| format!("lightning:{bolt11}"))
    };
    Some(Rest { sats: rest, bolt11, payment_uri })
}

/// What a check asks for: an invoice of `sats`, lasting `expiry_seconds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RestAsk {
    pub(crate) sats: u64,
    pub(crate) expiry_seconds: i64,
}

/// Whether a check whose status gave `rest` asks for an invoice of it (SPEC.md §31, Asking for a
/// rest invoice), and which: none when it has one, with less than 60 s left, or when the sale's
/// lease of the address (`lease`: its sats and end) is not the invoice's. The Lightning address's
/// sendable sats are checked after: its pay request is asked only then.
pub(crate) fn rest_to_ask(
    rest: Option<&Rest>,
    sats: u64,
    expires_at: i64,
    now: i64,
    lease: Option<(u64, i64)>,
) -> Option<RestAsk> {
    let rest = rest?;
    if rest.bolt11.is_some() || now + MIN_REST_SECONDS > expires_at {
        return None;
    }
    if lease != Some((sats, expires_at)) {
        return None;
    }
    Some(RestAsk { sats: rest.sats, expiry_seconds: expires_at - now })
}

/// Whether `sats` is within the Lightning address's sendable sats.
pub(crate) fn sendable(sats: u64, bounds: (u64, u64)) -> bool {
    sats >= bounds.0 && sats <= bounds.1
}

/// The rest record of `invoice` (SPEC.md §31, Rest records): its invoice and verify URL, sealed
/// with the rest encryption key at the rest record address of its payment hash, signed by the rest
/// secret at `created_at`, dropped by the relays a week after the end of the order's invoice
/// (`expires_at`), as its checkout links.
pub(crate) fn rest_record_event(
    keys: &RestKeys,
    invoice: &RestInvoice,
    expires_at: i64,
    created_at: i64,
    random: &dyn Random,
) -> Option<Event> {
    seal_record(
        Seal {
            record_type: REST_RECORD_TYPE,
            value: Json::object([
                ("version", Json::Number(REST_VERSION)),
                ("invoice", Json::from(invoice.bolt11.as_str())),
                ("verifyUrl", Json::from(invoice.verify_url.as_str())),
            ]),
            signer: &keys.secret_key,
            encryption_key: &keys.encryption_key,
            address: &rest_record_address(&keys.key, &invoice.payment_hash),
            created_at,
            tags: vec![vec!["expiration".to_owned(), (expires_at + CHECKOUT_LIFE_SECONDS).to_string()]],
        },
        random,
    )
}

/// What a checkout link's page reads rest records and acceptance records with: the rest key, the
/// rest author, and the rest encryption key the key derives.
#[derive(Clone, Debug)]
pub(crate) struct RestReaderKeys {
    pub(crate) key: Secret,
    pub(crate) author: String,
    pub(crate) encryption_key: Secret,
}

impl RestReaderKeys {
    /// The keys a link's record carries (its rest key and author), as the page reads them.
    #[cfg(test)]
    pub(crate) fn new(key: Secret, author: String) -> Self {
        let encryption_key = crate::derive::derive_key(
            key.expose(),
            crate::protocol::CHECKOUT_SALT,
            crate::protocol::REST_ENCRYPTION_INFO,
        );
        Self { key, author, encryption_key }
    }

    pub(crate) fn of(keys: &RestKeys) -> Self {
        Self {
            key: keys.key.clone(),
            author: keys.author.clone(),
            encryption_key: keys.encryption_key.clone(),
        }
    }
}

/// The invoice of the order a rest record belongs to: its amount and dates, as its link holds
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RestLinkTerms {
    pub(crate) sats: u64,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}

/// The value of a rest record (SPEC.md §31, Reading a rest record), at `d`.
fn parse_rest(value: &Json, d: &str, keys: &RestReaderKeys, terms: &RestLinkTerms) -> Parsed<RestInvoice> {
    if !value.is_object() {
        return Ok(None);
    }
    if value.get("version").and_then(Json::as_f64).is_some_and(|version| version > REST_VERSION) {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(REST_VERSION)) {
        return Ok(None);
    }
    let Some(invoice) = value.get("invoice").and_then(Json::as_str) else { return Ok(None) };
    let Some(verify_url) =
        value.get("verifyUrl").and_then(Json::as_str).filter(|url| parse_https_url(url).is_some())
    else {
        return Ok(None);
    };
    let Some((decoded, sats)) = bolt11::decode_mainnet(invoice) else { return Ok(None) };
    let end = decoded.expires_at();
    if sats >= terms.sats
        || decoded.timestamp < terms.created_at.saturating_sub(CLOCK_TOLERANCE_SECONDS)
        || end > terms.expires_at + CLOCK_TOLERANCE_SECONDS
    {
        return Ok(None);
    }
    if d != rest_record_address(&keys.key, &decoded.payment_hash) {
        return Ok(None);
    }
    Ok(Some(RestInvoice {
        bolt11: invoice.to_owned(),
        payment_hash: decoded.payment_hash,
        verify_url: verify_url.to_owned(),
        sats,
        created_at: decoded.timestamp,
        expires_at: end,
    }))
}

/// An event that checked out, if it is a rest record of the rest author and rest key of a checkout
/// link of an invoice `terms` describes: `Some(Err(Newer))` for one of a newer format, which the
/// page leaves aside. An event at the link's acceptance record address is no rest record.
pub(crate) fn open_rest_event(
    event: &Event,
    keys: &RestReaderKeys,
    terms: &RestLinkTerms,
) -> Option<Result<RestInvoice, Newer>> {
    let d = d_tag(event)?;
    if d == acceptance_record_address(&keys.key) {
        return None;
    }
    let expected = Expected {
        record_type: REST_RECORD_TYPE,
        encryption_key: &keys.encryption_key,
        address: d,
        author: &keys.author,
    };
    match open_event(event, &expected, |value, _| parse_rest(value, d, keys, terms))? {
        Opened::Newer { .. } => Some(Err(Newer)),
        Opened::Valid { value, .. } => Some(Ok(value)),
    }
}

/// What a relay sent, opened as a rest record (as `open_rest_event`), from its raw value: as the
/// pages of checkout links read it.
#[cfg(test)]
pub(crate) fn open_rest_record(
    value: &Json,
    keys: &RestReaderKeys,
    terms: &RestLinkTerms,
) -> Option<Result<RestInvoice, Newer>> {
    let d = crate::nostr::record::d_tag_of(value)?;
    if d == acceptance_record_address(&keys.key) {
        return None;
    }
    let expected = Expected {
        record_type: REST_RECORD_TYPE,
        encryption_key: &keys.encryption_key,
        address: d,
        author: &keys.author,
    };
    match crate::nostr::record::open_record(value, &expected, |value, _| parse_rest(value, d, keys, terms))? {
        Opened::Newer { .. } => Some(Err(Newer)),
        Opened::Valid { value, .. } => Some(Ok(value)),
    }
}

/// What the merchant's relays hold of the rest records of an invoice, by record address.
#[derive(Debug, Default)]
pub(crate) struct RestRecords {
    /// How many relays sent a record at each record address (its `d` tag): a rest record as the
    /// page reads it, or one of a newer format, which holds the address.
    pub(crate) sent_by: HashMap<String, usize>,
    /// The record addresses where a relay sent a record of a newer format (its event checked
    /// out): never written over (SPEC.md §12).
    pub(crate) newer: HashSet<String>,
}

impl RestRecords {
    /// Whether `count` relays at least sent a record at `address`.
    pub(crate) fn held_by(&self, address: &str, count: usize) -> bool {
        self.sent_by.get(address).is_some_and(|sent| *sent >= count)
    }
}

/// The rest records of `keys` on the merchant's `relays`; `None` when fewer than a majority
/// answered. Read with a key of this read alone, not paged.
pub(crate) async fn read_rest_records(
    pool: &RelayPool,
    keys: &RestReaderKeys,
    terms: &RestLinkTerms,
    relays: &[String],
    random: &dyn Random,
) -> Option<RestRecords> {
    let author = keys.author.clone();
    let encryption_key = keys.encryption_key.clone();
    let keep =
        records_that_open(Arc::new(move |_, pubkey| (pubkey == author).then(|| encryption_key.clone())));
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![keys.author.clone()]),
        ..Filter::default()
    };
    let read = pool.query_relays(relays, &filter, &read_key(random), &keep, ReadOf::query(relays)).await;
    if !read.majority_answered(relays.len()) {
        return None;
    }
    let mut records = RestRecords::default();
    for (_, events) in &read.answers {
        // The addresses this relay sent a record at: a valid one's is its payment hash's.
        let mut addresses: HashSet<&str> = HashSet::new();
        for event in events {
            let Some(opened) = open_rest_event(event, keys, terms) else { continue };
            let d = d_tag(event).expect("a record that opens has its d tag");
            if opened.is_err() {
                records.newer.insert(d.to_owned());
            }
            addresses.insert(d);
        }
        for address in addresses {
            *records.sent_by.entry(address.to_owned()).or_default() += 1;
        }
    }
    Some(records)
}

/// Publishes a rest record on the merchant's `relays`, signed and authenticated with the rest
/// secret: once a majority took it, else `network`.
pub(crate) async fn publish_rest_record(
    pool: &RelayPool,
    event: &Event,
    keys: &RestKeys,
    relays: &[String],
) -> Result<(), Error> {
    pool.publish_to_quorum(relays, event, &keys.secret_key, majority(relays.len())).await.map_err(|_| {
        Error::network(
            "Fewer than a majority of the merchant's relays took the record of an invoice of the rest",
        )
    })
}
