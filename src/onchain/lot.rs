//! The integration's lot (SPEC.md §31, The lot): deposit addresses of the merchant's wallet, which
//! the merchant's app gives the integration and fills again whenever the merchant opens it. One
//! record signed by the team, sealed with the channel's key, at an address the integration key
//! derives. The crate only reads it: it never makes an address, and never writes the lot.

use std::sync::Arc;

use crate::derive::{channel_keys, lot_address};
use crate::error::Error;
use crate::json::Json;
use crate::key::IntegrationKey;
use crate::nostr::event::Event;
use crate::nostr::record::{Expected, Newer, Opened, Parsed, newest_record, open_event, records_that_open};
use crate::nostr::relay::{Filter, ReadOf, RelayPool, read_key};
use crate::onchain::address::is_deposit_address;
use crate::protocol::{LOT_RECORD_TYPE, LOT_VERSION, MAX_LOT_ADDRESSES, RECORD_KIND};
use crate::runtime::{Logger, Random};

/// A lot's value: version 1, `updatedAt` its event's `created_at`, 0 to 100 deposit addresses,
/// none twice.
pub(crate) fn parse_lot(value: &Json, created_at: i64) -> Parsed<Vec<String>> {
    if !value.is_object() {
        return Ok(None);
    }
    if value.get("version").and_then(Json::as_f64).is_some_and(|version| version > LOT_VERSION) {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(LOT_VERSION))
        || !value.get("updatedAt").is_some_and(|updated| updated.is_number(created_at as f64))
    {
        return Ok(None);
    }
    let Some(addresses) = value.get("addresses").and_then(Json::as_array) else {
        return Ok(None);
    };
    if addresses.len() > MAX_LOT_ADDRESSES {
        return Ok(None);
    }
    let mut lot: Vec<String> = Vec::with_capacity(addresses.len());
    for address in addresses {
        match address.as_str() {
            Some(address) if is_deposit_address(address) && !lot.iter().any(|known| known == address) => {
                lot.push(address.to_owned());
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(lot))
}

/// The lot's record opened with the integration's keys.
pub(crate) fn open_lot(event: &Event, access: &IntegrationKey) -> Option<Opened<Vec<String>>> {
    let keys = channel_keys(&access.key);
    let address = lot_address(&access.key);
    open_event(
        event,
        &Expected {
            record_type: LOT_RECORD_TYPE,
            encryption_key: &keys.encryption_key,
            address: &address,
            author: &access.team,
        },
        |value, event| parse_lot(value, event.created_at),
    )
}

/// The addresses of the integration's lot, read on the merchant's `relays` as soon as a majority
/// answered: the newest valid copy. Empty when there is none, or when a copy of a newer format is
/// as new or newer (logged: update the crate). The order means nothing. `network` when fewer than
/// a majority answered.
pub(crate) async fn read_lot(
    pool: &RelayPool,
    access: &IntegrationKey,
    relays: &[String],
    random: &dyn Random,
    logger: &dyn Logger,
) -> Result<Vec<String>, Error> {
    let address = lot_address(&access.key);
    let keys = channel_keys(&access.key);
    let team = access.team.clone();
    let encryption_key = keys.encryption_key.clone();
    let keep = records_that_open(Arc::new(move |_, author| (author == team).then(|| encryption_key.clone())));
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![access.team.clone()]),
        d: Some(vec![address]),
        ..Filter::default()
    };
    // A relay that asks to authenticate (NIP-42) gets a key of this read alone.
    let read = pool.query_relays(relays, &filter, &read_key(random), &keep, ReadOf::query(relays)).await;
    if !read.majority_answered(relays.len()) {
        return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
    }
    let newest = newest_record(&read.answers, |event| open_lot(event, access));
    if let Some(unreadable) = newest.newest_unreadable
        && newest.newest.as_ref().is_none_or(|(event, _)| unreadable >= event.created_at)
    {
        logger.warn(
                "sattleme-checkout: the integration's lot of addresses has a newer format than this version reads; update the crate (no on-chain payment until then)",
            );
        return Ok(Vec::new());
    }
    Ok(newest.newest.map(|(_, lot)| lot).unwrap_or_default())
}
