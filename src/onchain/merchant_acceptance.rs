//! The merchant's acceptance (SPEC.md §31, The merchant's acceptance): the merchant may accept by
//! hand, in its app, what an order underpaid on-chain received as paying it in full. The app
//! publishes a record of the team (the integration key opens it but cannot make one) holding what
//! the order had received then; a check judges the payment against that amount when it is less
//! than the least the order's tolerance accepts (`due_onchain`). The majority of the merchant's
//! relays holds the truth: a check reads it on every relay and counts a record only when a
//! majority of the relays sent it. A check never publishes one, nor publishes one again: the pages
//! of the order's checkout links learn of it only through an acceptance record (acceptance.rs).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::derive::{channel_keys, merchant_acceptance_address};
use crate::error::Error;
use crate::json::Json;
use crate::nostr::event::Event;
use crate::nostr::record::{Expected, Newer, Opened, Parsed, open_event, records_that_open, replaces};
use crate::nostr::relay::{Answers, Filter, Keep, ReadOf, RelayPool, majority, read_key};
use crate::protocol::{
    GRACE_SECONDS, MERCHANT_ACCEPTANCE_RECORD_TYPE, MERCHANT_ACCEPTANCE_VERSION, RECORD_KIND,
};
use crate::runtime::Random;
use crate::secret::Secret;

/// What a check opens the merchant's acceptance of an invoice with.
#[derive(Clone)]
pub(crate) struct MerchantAcceptanceKeys {
    /// The team's public key (hex): its only author.
    pub(crate) team: String,
    /// The channel's encryption key: its NIP-44 conversation key.
    pub(crate) encryption_key: Secret,
    /// Its `d` tag ([`merchant_acceptance_address`]).
    pub(crate) address: String,
}

impl MerchantAcceptanceKeys {
    /// The keys of the merchant's acceptance of the invoice of the sale `sale_author` with the
    /// deposit address `address` and the end `expires_at`, for the integration `integration_key`
    /// of `team`.
    pub(crate) fn of(
        integration_key: &Secret,
        team: &str,
        sale_author: &str,
        address: &str,
        expires_at: i64,
    ) -> Self {
        Self {
            team: team.to_owned(),
            encryption_key: channel_keys(integration_key).encryption_key,
            address: merchant_acceptance_address(integration_key, sale_author, address, expires_at),
        }
    }
}

/// The invoice a merchant's acceptance is read for: its amount and its end.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AcceptedInvoice {
    pub(crate) sats: u64,
    pub(crate) expires_at: i64,
}

/// A merchant's acceptance a relay sent, opened.
#[derive(Clone, Debug)]
pub(crate) enum OpenedMerchantAcceptance {
    /// Valid: what the order had received when the merchant accepted it.
    Valid { event: Event, received: u64 },
    /// Of a newer format: logged; the newest a majority sent, it leaves the order without one.
    Newer { event: Event },
    /// Of a newer format, dated after the lease's end: set aside as any record dated so, logged.
    NewerSetAside { event: Event },
}

/// Its value: an object whose `version` is 1 and whose `received` is a safe integer from 1, below
/// `sats` (more fields ignored); a `version` above 1 is a newer format.
fn parse_merchant_acceptance(value: &Json, sats: u64) -> Parsed<u64> {
    if !value.is_object() {
        return Ok(None);
    }
    if value
        .get("version")
        .and_then(Json::as_f64)
        .is_some_and(|version| version > MERCHANT_ACCEPTANCE_VERSION)
    {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(MERCHANT_ACCEPTANCE_VERSION)) {
        return Ok(None);
    }
    let received = value
        .get("received")
        .and_then(Json::as_safe_integer)
        .and_then(|received| u64::try_from(received).ok());
    Ok(received.filter(|&received| received >= 1 && received < sats))
}

fn expected(keys: &MerchantAcceptanceKeys) -> Expected<'_> {
    Expected {
        record_type: MERCHANT_ACCEPTANCE_RECORD_TYPE,
        encryption_key: &keys.encryption_key,
        address: &keys.address,
        author: &keys.team,
    }
}

/// A record that opened, by its date: one dated after the lease's end (`expires_at` + 120) is set
/// aside whatever its format, one of a newer format still told, for the warning.
fn by_date(opened: Opened<u64>, invoice: AcceptedInvoice) -> Option<OpenedMerchantAcceptance> {
    let late = |event: &Event| event.created_at > invoice.expires_at + GRACE_SECONDS;
    match opened {
        Opened::Newer { event } if late(&event) => Some(OpenedMerchantAcceptance::NewerSetAside { event }),
        Opened::Newer { event } => Some(OpenedMerchantAcceptance::Newer { event }),
        Opened::Valid { event, .. } if late(&event) => None,
        Opened::Valid { event, value } => Some(OpenedMerchantAcceptance::Valid { event, received: value }),
    }
}

/// An event that checked out (its id, its signature), read as the merchant's acceptance of
/// `invoice` (SPEC.md §31, Reading it): a record of type `integration-onchain-accepted`, author the
/// team, sealed with the channel's key, at the address of `keys`; valid when its value is an object
/// whose `version` is 1 and whose `received` is a safe integer from 1, below the invoice's `sats`
/// (more fields ignored), of a newer format when its `version` is above 1 or its content of a newer
/// NIP-44 version. `None` for anything else, and for a valid record dated after the lease's end
/// (`expires_at` + 120); one of a newer format dated so is still told, set aside, for the warning.
/// Its `created_at` is never compared with now.
pub(crate) fn open_merchant_acceptance_event(
    event: &Event,
    keys: &MerchantAcceptanceKeys,
    invoice: AcceptedInvoice,
) -> Option<OpenedMerchantAcceptance> {
    let opened =
        open_event(event, &expected(keys), |value, _| parse_merchant_acceptance(value, invoice.sats))?;
    by_date(opened, invoice)
}

/// What a relay sent, opened as the merchant's acceptance of `invoice` (as
/// `open_merchant_acceptance_event`), from its raw value: its event checked too.
#[cfg(test)]
pub(crate) fn open_merchant_acceptance(
    value: &Json,
    keys: &MerchantAcceptanceKeys,
    invoice: AcceptedInvoice,
) -> Option<OpenedMerchantAcceptance> {
    let opened = crate::nostr::record::open_record(value, &expected(keys), |value, _| {
        parse_merchant_acceptance(value, invoice.sats)
    })?;
    by_date(opened, invoice)
}

/// What the read of the merchant's acceptance keeps of each event a relay sends: an event of the
/// team at its address that opens with the channel's key and checks out (`records_that_open`).
pub(crate) fn merchant_acceptance_keep(keys: &MerchantAcceptanceKeys) -> Keep<Event> {
    let (team, address, encryption_key) =
        (keys.team.clone(), keys.address.clone(), keys.encryption_key.clone());
    records_that_open(Arc::new(move |d, pubkey| {
        (pubkey == team && d == Some(address.as_str())).then(|| encryption_key.clone())
    }))
}

/// The merchant's acceptance of an invoice, as a check counts it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MerchantAcceptance {
    /// The `received` of the merchant's acceptance that counts; `None` without one.
    pub(crate) received: Option<u64>,
    /// Whether a relay sent one of a newer format, whatever its date and however many relays sent
    /// it: logged.
    pub(crate) newer: bool,
}

/// The merchant's acceptance of `invoice` (SPEC.md §31, Counting it), from what each relay of the
/// merchant's list (`relays` relays) sent to its read on every relay (`answers`: the events that
/// checked out, by relay): each copy opened once per id and signature
/// ([`open_merchant_acceptance_event`]); a relay sent a record when it sent a copy of it that
/// opens, and counts once for it whatever copies it sent. Of the records valid or of a newer
/// format that a majority of the list sent, the newest (the highest `created_at`, then the lowest
/// id, as relays keep them) decides: a valid one is the merchant's acceptance, one of a newer
/// format leaves the order without one. One that fewer than a majority sent never counts,
/// whichever relays sent it.
pub(crate) fn merchant_acceptance_of(
    answers: &Answers<Event>,
    keys: &MerchantAcceptanceKeys,
    invoice: AcceptedInvoice,
    relays: usize,
) -> MerchantAcceptance {
    // Each copy opened once, by id and signature, whatever relays send it.
    let mut copies: HashMap<(String, String), Option<OpenedMerchantAcceptance>> = HashMap::new();
    // The records that count if enough relays sent them, by id, in the order first sent, and how
    // many relays sent each.
    let mut records: Vec<(OpenedMerchantAcceptance, usize)> = Vec::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();
    let mut accepted = MerchantAcceptance::default();
    for (_, events) in answers {
        let mut sent: HashSet<&str> = HashSet::new();
        for event in events {
            let Some(opened) = copies
                .entry((event.id.clone(), event.sig.clone()))
                .or_insert_with(|| open_merchant_acceptance_event(event, keys, invoice))
            else {
                continue;
            };
            match opened {
                OpenedMerchantAcceptance::Valid { .. } => {}
                OpenedMerchantAcceptance::Newer { .. } => accepted.newer = true,
                OpenedMerchantAcceptance::NewerSetAside { .. } => {
                    accepted.newer = true;
                    continue;
                }
            }
            // One relay counts once for a record, whatever copies of it it sent.
            if !sent.insert(event.id.as_str()) {
                continue;
            }
            match by_id.get(&event.id) {
                Some(&index) => records[index].1 += 1,
                None => {
                    by_id.insert(event.id.clone(), records.len());
                    records.push((opened.clone(), 1));
                }
            }
        }
    }
    let needed = majority(relays);
    let mut newest: Option<&OpenedMerchantAcceptance> = None;
    for (opened, sent_by) in &records {
        if *sent_by < needed {
            continue;
        }
        if newest.is_none_or(|newest| replaces(event_of(opened), event_of(newest))) {
            newest = Some(opened);
        }
    }
    if let Some(OpenedMerchantAcceptance::Valid { received, .. }) = newest {
        accepted.received = Some(*received);
    }
    accepted
}

fn event_of(opened: &OpenedMerchantAcceptance) -> &Event {
    match opened {
        OpenedMerchantAcceptance::Valid { event, .. }
        | OpenedMerchantAcceptance::Newer { event }
        | OpenedMerchantAcceptance::NewerSetAside { event } => event,
    }
}

/// The merchant's acceptance of `invoice` ([`merchant_acceptance_of`]), read on every relay of the
/// merchant's `relays` (SPEC.md §13: once every relay answered or failed, or one timeout after a
/// majority answered), not paged, by its address and the team, with a key of this read alone.
/// `network` when fewer than a majority answered. Publishes nothing.
pub(crate) async fn read_merchant_acceptance(
    pool: &RelayPool,
    keys: &MerchantAcceptanceKeys,
    invoice: AcceptedInvoice,
    relays: &[String],
    random: &dyn Random,
) -> Result<MerchantAcceptance, Error> {
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![keys.team.clone()]),
        d: Some(vec![keys.address.clone()]),
        ..Filter::default()
    };
    let read = ReadOf { needed: majority(relays.len()), paged: false, every_relay: true };
    let read =
        pool.query_relays(relays, &filter, &read_key(random), &merchant_acceptance_keep(keys), read).await;
    if !read.majority_answered(relays.len()) {
        return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
    }
    // Not paged: a relay still reading when the read went on sent nothing (`read.pages` is empty).
    Ok(merchant_acceptance_of(&read.answers, keys, invoice, relays.len()))
}
