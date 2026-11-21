//! Acceptance records (SPEC.md §31, Acceptance records): the page of a checkout link cannot know
//! the merchant's tolerance nor read the merchant's acceptance (merchant_acceptance.rs), so an
//! order either accepted would read underpaid there, its customer asked for the rest and never
//! sent back to the shop. A check whose status is paid (or being confirmed) with less than the
//! amount publishes what it received then, signed by the rest secret, for the pages of the
//! order's checkout links: they count the payment as enough from that on. Never the tolerance
//! itself.

use std::sync::Arc;

use crate::derive::{RestKeys, acceptance_record_address};
use crate::error::Error;
use crate::json::Json;
use crate::model::{Payment, PaymentStatus};
use crate::nostr::event::Event;
use crate::nostr::record::{
    Expected, Newer, Opened, Parsed, Seal, newest_record, open_event, records_that_open, seal_record,
};
use crate::nostr::relay::{Filter, ReadOf, RelayPool, majority, read_key};
use crate::onchain::rest::RestReaderKeys;
use crate::protocol::{ACCEPTANCE_RECORD_TYPE, ACCEPTANCE_VERSION, CHECKOUT_LIFE_SECONDS, RECORD_KIND};
use crate::runtime::{Logger, Random};

/// What a check whose status is `status` must have the pages of the order's checkout links know
/// (SPEC.md §31, Publishing it): the status's `received`, when the order's tolerance or the
/// merchant's acceptance accepted less than its amount (`unconfirmed`, or `paid` with
/// transactions) before the links' life ends; `None` otherwise.
pub(crate) fn acceptance_to_publish(
    status: &PaymentStatus,
    sats: u64,
    expires_at: i64,
    now: i64,
) -> Option<u64> {
    if now >= expires_at + CHECKOUT_LIFE_SECONDS {
        return None;
    }
    let received = match status {
        PaymentStatus::Unconfirmed { received, .. } => *received,
        PaymentStatus::Paid(
            Payment::Onchain { received, txids } | Payment::Mixed { received, txids, .. },
        ) if !txids.is_empty() => *received,
        _ => return None,
    };
    (received < sats).then_some(received)
}

/// The acceptance record of the invoice of `keys` (its rest keys): `received`, sealed with the
/// rest encryption key at its acceptance record address, signed by the rest secret at
/// `created_at`, dropped by the relays a week after the invoice's end, as its checkout links.
pub(crate) fn acceptance_record_event(
    keys: &RestKeys,
    received: u64,
    expires_at: i64,
    created_at: i64,
    random: &dyn Random,
) -> Event {
    seal_record(
        Seal {
            record_type: ACCEPTANCE_RECORD_TYPE,
            value: Json::object([
                ("version", Json::Number(ACCEPTANCE_VERSION)),
                ("received", Json::unsigned(received)),
            ]),
            signer: &keys.secret_key,
            encryption_key: &keys.encryption_key,
            address: &acceptance_record_address(&keys.key),
            created_at,
            tags: vec![vec!["expiration".to_owned(), (expires_at + CHECKOUT_LIFE_SECONDS).to_string()]],
        },
        random,
    )
    .expect("an acceptance record fits NIP-44")
}

fn parse_acceptance(value: &Json, sats: u64) -> Parsed<u64> {
    if !value.is_object() {
        return Ok(None);
    }
    if value.get("version").and_then(Json::as_f64).is_some_and(|version| version > ACCEPTANCE_VERSION) {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(ACCEPTANCE_VERSION)) {
        return Ok(None);
    }
    let received = value
        .get("received")
        .and_then(Json::as_safe_integer)
        .and_then(|received| u64::try_from(received).ok());
    Ok(received.filter(|&received| received >= 1 && received < sats))
}

/// An event that checked out, opened as an acceptance record of `keys` for an invoice of `sats`
/// (SPEC.md §31, Reading an acceptance record): its `received`, from 1, below `sats`.
pub(crate) fn open_acceptance_event(event: &Event, keys: &RestReaderKeys, sats: u64) -> Option<Opened<u64>> {
    let address = acceptance_record_address(&keys.key);
    if crate::declaration::d_tag(event) != Some(address.as_str()) {
        return None;
    }
    let expected = Expected {
        record_type: ACCEPTANCE_RECORD_TYPE,
        encryption_key: &keys.encryption_key,
        address: &address,
        author: &keys.author,
    };
    open_event(event, &expected, |value, _| parse_acceptance(value, sats))
}

/// What a relay sent, opened as an acceptance record (as `open_acceptance_event`), from its raw
/// value: as the pages of checkout links read it.
#[cfg(test)]
pub(crate) fn open_acceptance_record(value: &Json, keys: &RestReaderKeys, sats: u64) -> Option<Opened<u64>> {
    let address = acceptance_record_address(&keys.key);
    if crate::nostr::record::d_tag_of(value) != Some(address.as_str()) {
        return None;
    }
    let expected = Expected {
        record_type: ACCEPTANCE_RECORD_TYPE,
        encryption_key: &keys.encryption_key,
        address: &address,
        author: &keys.author,
    };
    crate::nostr::record::open_record(value, &expected, |value, _| parse_acceptance(value, sats))
}

/// What the relays hold of the invoice's acceptance records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Acceptance {
    /// A majority of the merchant's relays each sent a valid record whose `received` (the newest
    /// each sent) is at most the status's: nothing to publish.
    Known,
    /// A relay sent one of a newer format (its event checked out): never written over, nothing to
    /// publish; a warning to log (SPEC.md §12).
    Newer,
    /// It must be published.
    Unknown,
    /// Fewer than a majority answered the read: such a read decides nothing (SPEC.md §13), and
    /// what the others hold, of a newer format perhaps, is never written over unseen. Nothing is
    /// published, the failure logged: the next check reads and publishes again.
    Unread,
}

/// Whether the pages already know `received` (SPEC.md §31, Publishing it). Read with a key of
/// this read alone, not paged (one record per invoice). A relay that answered with a record of a
/// newer format stops the publication whatever the others answered; else fewer than a majority
/// answering is no answer (`Unread`), never an absence.
pub(crate) async fn acceptance_known(
    pool: &RelayPool,
    keys: &RestReaderKeys,
    sats: u64,
    received: u64,
    relays: &[String],
    random: &dyn Random,
) -> Acceptance {
    let needed = majority(relays.len());
    let author = keys.author.clone();
    let encryption_key = keys.encryption_key.clone();
    let keep =
        records_that_open(Arc::new(move |_, pubkey| (pubkey == author).then(|| encryption_key.clone())));
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![keys.author.clone()]),
        d: Some(vec![acceptance_record_address(&keys.key)]),
        ..Filter::default()
    };
    let read = pool.query_relays(relays, &filter, &read_key(random), &keep, ReadOf::query(relays)).await;
    let mut holders = 0;
    for (relay, events) in &read.answers {
        let one = vec![(relay.clone(), events.clone())];
        let newest = newest_record(&one, |event| open_acceptance_event(event, keys, sats));
        if newest.newest_unreadable.is_some() {
            return Acceptance::Newer;
        }
        if newest.newest.is_some_and(|(_, accepted)| accepted <= received) {
            holders += 1;
        }
    }
    if holders >= needed {
        Acceptance::Known
    } else if !read.majority_answered(relays.len()) {
        Acceptance::Unread
    } else {
        Acceptance::Unknown
    }
}

/// Publishes an acceptance record on the merchant's `relays`, signed and authenticated with the
/// rest secret: once a majority took it, else `network`.
pub(crate) async fn publish_acceptance_record(
    pool: &RelayPool,
    event: &Event,
    keys: &RestKeys,
    relays: &[String],
) -> Result<(), Error> {
    pool.publish_to_quorum(relays, event, &keys.secret_key, majority(relays.len())).await.map_err(|_| {
        Error::network(
            "Fewer than a majority of the merchant's relays took the acceptance record of a payment",
        )
    })
}

/// The invoice whose acceptance record a check publishes: its amount, its end and its rest keys.
pub(crate) struct AcceptanceOf<'a> {
    pub(crate) sats: u64,
    pub(crate) expires_at: i64,
    pub(crate) keys: &'a RestKeys,
}

/// What a check whose status is `status` publishes of an acceptance record of `invoice`, at `now` (SPEC.md §31, Acceptance records):
/// when the order's tolerance or the merchant's acceptance accepted less than its amount, the
/// status's `received`, unless a majority of the merchant's `relays` hold a record of it or less;
/// nothing after a read fewer than a majority answered, nor over a record of a newer format. A
/// failure is logged, never the check's: the next check reads and publishes it again. Never the
/// tolerance itself. What a majority took, `None` when nothing was.
pub(crate) async fn publish_acceptance(
    pool: &RelayPool,
    status: &PaymentStatus,
    invoice: AcceptanceOf<'_>,
    relays: &[String],
    now: i64,
    random: &dyn Random,
    logger: &dyn Logger,
) -> Option<u64> {
    let AcceptanceOf { sats, expires_at, keys } = invoice;
    let received = acceptance_to_publish(status, sats, expires_at, now)?;
    let readers = RestReaderKeys::of(keys);
    match acceptance_known(pool, &readers, sats, received, relays, random).await {
        Acceptance::Known => return None,
        Acceptance::Newer => {
            logger.warn(
                "sattleme-checkout: the acceptance record of a payment has a newer format than this version reads; update the crate",
            );
            return None;
        }
        Acceptance::Unknown => {}
        // Such a read decides nothing: what the relays that did not answer hold is never written
        // over unseen (SPEC.md §13, §12).
        Acceptance::Unread => {
            logger.warn(
                "sattleme-checkout: the acceptance record of a payment was not published (fewer than a majority of the merchant's relays answered its read); published again at the next check",
            );
            return None;
        }
    }
    let event = acceptance_record_event(keys, received, expires_at, now, random);
    match publish_acceptance_record(pool, &event, keys, relays).await {
        Ok(()) => Some(received),
        Err(error) => {
            logger.warn(&format!(
                "sattleme-checkout: the acceptance record of a payment was not published ({}); published again at the next check",
                error.message()
            ));
            None
        }
    }
}
