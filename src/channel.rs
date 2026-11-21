//! The integration's channel (SPEC.md §14): one record signed by the team, which the merchant's
//! app publishes on the account's relays and which only the integration's key opens. It gives the
//! merchant's Lightning address, registry and relays, or says that the integration was removed.

use std::sync::Arc;

use crate::checkout::{checkout_origin_of, is_business_name, is_public_key};
use crate::derive::channel_keys;
use crate::error::Error;
use crate::json::Json;
use crate::key::IntegrationKey;
use crate::lnurl::lightning_address_url;
use crate::nostr::event::Event;
use crate::nostr::record::{Expected, Newer, Parsed, newest_record, open_event, records_that_open};
use crate::nostr::relay::{Filter, ReadOf, RelayPool, read_key};
use crate::onchain::node::{BitcoinNode, bitcoin_node_of};
use crate::onchain::tolerance::tolerance_of;
use crate::protocol::{CHANNEL_RECORD_TYPE, CHANNEL_VERSION, MAX_RELAY_MOVES, RECORD_KIND};
use crate::relays::relay_list_of;
use crate::runtime::{Logger, Random};
use crate::text::is_hex32;

/// An active channel, as far as the server uses it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ActiveChannel {
    pub(crate) business_name: String,
    /// Never shown to the integrator by the app: the crate does not return it either.
    pub(crate) lightning_address: String,
    /// Hex, 32 bytes.
    pub(crate) registry_key: String,
    /// Hex: the public half of the merchant's reading key.
    pub(crate) registry_reader: String,
    /// The account's relays, when the channel names them.
    pub(crate) relays: Option<Vec<String>>,
    /// The merchant's web app for checkout links (`checkout.origin`); `None` when the merchant's
    /// app gives none or an invalid one.
    pub(crate) checkout_origin: Option<String>,
    /// The merchant's tolerance of on-chain underpayments (basis points), 0 when the channel
    /// gives none or an invalid one. An order's lease keeps it; never returned to the integrator.
    pub(crate) tolerance: u64,
    /// The merchant's Bitcoin node (`bitcoinNode`, SPEC.md §31), `None` when the channel names
    /// none or an invalid one: the server then reads mempool.space.
    pub(crate) bitcoin_node: Option<BitcoinNode>,
    /// Unix seconds: the record's `created_at`.
    pub(crate) updated_at: i64,
}

impl std::fmt::Debug for ActiveChannel {
    /// Never the registry key (whoever holds it can lease the addresses of the merchant's lots,
    /// SPEC.md §27), the merchant's Lightning address (never shown to the integrator) nor the
    /// merchant's tolerance (never written where the shop or the customer reads).
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveChannel")
            .field("business_name", &self.business_name)
            .field("registry_reader", &self.registry_reader)
            .field("relays", &self.relays)
            .field("checkout_origin", &self.checkout_origin)
            .field("bitcoin_node", &self.bitcoin_node)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

/// The channel: active, or removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    Active(Box<ActiveChannel>),
    Removed { updated_at: i64 },
}

/// A channel's value, as the merchant's app reads it, for what the server uses (SPEC.md §14): version
/// 1, `updatedAt` = `created_at`, then removed, or active with the role of an integration, the
/// business's name, a Lightning address, the registry and an optional valid relay list, the web
/// app of checkout links when it gives a valid one (an invalid one gives none, and leaves the
/// channel valid), the merchant's tolerance and the merchant's Bitcoin node (each absent or
/// invalid: none, the channel valid). The other fields are the app's own and not read, so that a change to them never stops a shop.
pub(crate) fn parse_channel(value: &Json, created_at: i64) -> Parsed<Channel> {
    if !value.is_object() {
        return Ok(None);
    }
    if value.get("version").and_then(Json::as_f64).is_some_and(|version| version > CHANNEL_VERSION) {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(CHANNEL_VERSION))
        || !value.get("updatedAt").is_some_and(|updated| updated.is_number(created_at as f64))
    {
        return Ok(None);
    }
    let status = value.get("status").and_then(Json::as_str);
    if status == Some("removed") {
        return Ok(Some(Channel::Removed { updated_at: created_at }));
    }
    if status != Some("active") || value.get("role").and_then(Json::as_str) != Some("integration") {
        return Ok(None);
    }
    Ok(read_active(value, created_at).map(|active| Channel::Active(Box::new(active))))
}

fn read_active(value: &Json, created_at: i64) -> Option<ActiveChannel> {
    let profile = value.get("profile").filter(|profile| profile.is_object())?;
    let business_name = profile.get("businessName")?.as_str().filter(|name| is_business_name(name))?;
    let lightning_address = profile
        .get("lightningAddress")?
        .as_str()
        .filter(|address| lightning_address_url(address).is_some())?;
    // The reading key must be a point of the curve: every declaration's inside is sealed to it.
    let registry_key = value.get("registryKey")?.as_str().filter(|key| is_hex32(key))?;
    let registry_reader = value.get("registryReader")?.as_str().filter(|reader| is_public_key(reader))?;
    let relays = match value.get("relays") {
        None => None,
        Some(relays) => Some(relay_list_of(relays)?),
    };
    Some(ActiveChannel {
        business_name: business_name.to_owned(),
        lightning_address: lightning_address.to_owned(),
        registry_key: registry_key.to_owned(),
        registry_reader: registry_reader.to_owned(),
        relays,
        checkout_origin: checkout_origin_of(value.get("checkout")),
        // Absent or invalid, none: the channel stays valid.
        tolerance: tolerance_of(value.get("onchainTolerance")),
        // Absent or invalid in any way, none (mempool.space): the channel stays valid.
        bitcoin_node: bitcoin_node_of(value.get("bitcoinNode")),
        updated_at: created_at,
    })
}

/// What the relays of one list hold.
#[derive(Debug)]
pub(crate) enum Lookup {
    Found(Channel),
    /// A majority of the relays answered: no channel, or only one of a newer format.
    NotFound {
        newer: bool,
    },
    /// Fewer than a majority of the relays answered.
    Unreachable,
}

/// The channel's record opened with the integration's keys.
pub(crate) fn open_channel(
    event: &Event,
    access: &IntegrationKey,
) -> Option<crate::nostr::record::Opened<Channel>> {
    let keys = channel_keys(&access.key);
    open_event(
        event,
        &Expected {
            record_type: CHANNEL_RECORD_TYPE,
            encryption_key: &keys.encryption_key,
            address: &keys.address,
            author: &access.team,
        },
        |value, event| parse_channel(value, event.created_at),
    )
}

/// The newest copy of the integration's channel on `relays`, signed by its team: every relay at
/// once, read as soon as a majority answered (the app publishes the channel, and its removal, on a
/// majority of them: any two majorities share a relay).
pub(crate) async fn lookup_channel(
    pool: &RelayPool,
    access: &IntegrationKey,
    relays: &[String],
    random: &dyn Random,
    logger: &dyn Logger,
) -> Lookup {
    let keys = channel_keys(&access.key);
    // A relay that asks to authenticate (NIP-42) gets a key of this read alone.
    let auth_key = read_key(random);
    let team = access.team.clone();
    let encryption_key = keys.encryption_key.clone();
    let keep = records_that_open(Arc::new(move |_, author| (author == team).then(|| encryption_key.clone())));
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![access.team.clone()]),
        d: Some(vec![keys.address.clone()]),
        ..Filter::default()
    };
    let read = pool.query_relays(relays, &filter, &auth_key, &keep, ReadOf::query(relays)).await;
    if !read.majority_answered(relays.len()) {
        return Lookup::Unreachable;
    }
    let newest = newest_record(&read.answers, |event| open_channel(event, access));
    let newest_at = newest.newest.as_ref().map(|(event, _)| event.created_at);
    if let Some(unreadable) = newest.newest_unreadable
        && newest_at.is_none_or(|at| unreadable > at)
    {
        logger.warn(
                "sattleme-checkout: the integration's channel has a newer format than this version reads; update the crate",
            );
    }
    match newest.newest {
        Some((_, channel)) => Lookup::Found(channel),
        None => Lookup::NotFound { newer: newest.newest_unreadable.is_some() },
    }
}

/// The integration's channel, active, and the relays it was read on.
#[derive(Clone, Debug)]
pub(crate) struct ChannelRead {
    pub(crate) channel: ActiveChannel,
    /// Where the channel was read (the merchant's relays are the channel's, else the key's:
    /// SPEC.md §14). What the tests check of a move.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by the tests"))]
    pub(crate) relays: Vec<String>,
}

/// The integration's channel, active, on the account's current relays (SPEC.md §14): read on
/// the key's relays, then where the channel says the account moved (3 times at most), since only
/// the new list gets its later changes, its removal included. `revoked` when it is removed,
/// `network` when fewer than a majority of a list answered, `channel_not_found` when a majority of
/// the key's relays answered without it.
pub(crate) async fn read_channel(
    pool: &RelayPool,
    access: &IntegrationKey,
    random: &dyn Random,
    logger: &dyn Logger,
) -> Result<ChannelRead, Error> {
    let mut relays = access.relays.clone();
    let mut channel = match lookup_channel(pool, access, &relays, random, logger).await {
        Lookup::Unreachable => {
            return Err(Error::network("Fewer than a majority of the integration key's relays answered"));
        }
        Lookup::NotFound { newer } => return Err(Error::channel_not_found(newer)),
        Lookup::Found(channel) => channel,
    };
    for _ in 0..MAX_RELAY_MOVES {
        let Channel::Active(active) = &channel else { break };
        let Some(next) = active.relays.clone().filter(|next| *next != relays) else { break };
        match lookup_channel(pool, access, &next, random, logger).await {
            Lookup::Unreachable => {
                return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
            }
            // Not copied there (yet): the channel read so far stands, and the declarations still
            // go to the account's relays it names.
            Lookup::NotFound { .. } => break,
            Lookup::Found(found) => {
                channel = found;
                relays = next;
            }
        }
    }
    match channel {
        Channel::Removed { .. } => Err(Error::revoked()),
        Channel::Active(active) => Ok(ChannelRead { channel: *active, relays }),
    }
}
