//! Witnesses (SPEC.md §31, Witnesses): the integration records each transaction it sees paying an
//! address of its lot, and when: during the lease of an invoice of an order (that order's sale and
//! the invoice's end), or at no lease's time (`none`). So that every reader, the merchant's app
//! included, tells the same order paid. Only the integration writes them (signed by its seen
//! secret, sealed with its channel's key); the merchant's app reads them to attribute deposits and
//! to take paid addresses out of the lot.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::derive::{channel_keys, hmac_sha256, seen_keys};
use crate::error::Error;
use crate::json::Json;
use crate::nostr::event::{Event, has_valid_id, signature_checks};
use crate::nostr::record::{
    Expected, Newer, Opened, Parsed, Seal, open_event, records_that_open, replaces, seal_record,
};
use crate::nostr::relay::{Filter, Keep, ReadOf, RelayPool, majority, read_key};
use crate::onchain::address::is_deposit_address;
use crate::protocol::{
    MAX_SATS, MAX_WITNESS_INPUTS, NO_SALE, ORDER_TAG, RECORD_KIND, WITNESS_RECORD_TYPE, WITNESS_VERSION,
};
use crate::runtime::Random;
use crate::secret::Secret;
use crate::text::{is_hex32, to_hex};

/// The keys of the integration's witnesses. Secrets: never logged.
#[derive(Clone)]
pub(crate) struct SeenKeys {
    pub(crate) secret_key: Secret,
    /// Hex: the author of every witness.
    pub(crate) author: String,
    pub(crate) address_key: Secret,
    /// The channel's encryption key: the witnesses' NIP-44 conversation key.
    pub(crate) encryption_key: Secret,
}

impl std::fmt::Debug for SeenKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SeenKeys").field("author", &self.author).finish_non_exhaustive()
    }
}

pub(crate) fn seen_of(integration_key: &Secret) -> SeenKeys {
    let keys = seen_keys(integration_key);
    SeenKeys {
        secret_key: keys.secret_key,
        author: keys.author,
        address_key: keys.address_key,
        encryption_key: channel_keys(integration_key).encryption_key,
    }
}

fn mac(key: &Secret, text: &str) -> String {
    to_hex(&hmac_sha256(key.expose(), text.as_bytes()))
}

/// Where the witness of `txid` paying `address` for `sale` (a sale author, or `None`: none) is.
pub(crate) fn witness_address(address_key: &Secret, address: &str, txid: &str, sale: Option<&str>) -> String {
    mac(address_key, &format!("{address}/{txid}/{}", sale.unwrap_or(NO_SALE)))
}

/// The `o` tag of the witnesses of `address` for `sale` (`None`: none): how a check reads them.
pub(crate) fn order_tag(address_key: &Secret, address: &str, sale: Option<&str>) -> String {
    mac(address_key, &format!("order/{address}/{}", sale.unwrap_or(NO_SALE)))
}

/// The address tag of `address`: a witness's second `o` tag, which finds every witness of the
/// address, whatever its sale.
pub(crate) fn address_tag(address_key: &Secret, address: &str) -> String {
    mac(address_key, &format!("address/{address}"))
}

/// A coin, as a witness writes it: `<txid>:<vout>`, the vout an integer from 0 to 4 294 967 295 in
/// decimal without leading zeros.
pub(crate) fn is_coin(value: &str) -> bool {
    let Some((txid, vout)) = value.split_once(':') else {
        return false;
    };
    is_hex32(txid)
        && (1..=10).contains(&vout.len())
        && vout.bytes().all(|byte| byte.is_ascii_digit())
        && (vout == "0" || !vout.starts_with('0'))
        && vout.parse::<u64>().is_ok_and(|vout| vout <= u64::from(u32::MAX))
}

/// What a witness says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Witness {
    pub(crate) address: String,
    pub(crate) txid: String,
    /// The sale author (hex), or `None`: at no lease's time.
    pub(crate) sale: Option<String>,
    /// What `txid` pays `address`.
    pub(crate) sats: u64,
    /// The coins `txid` spends, its first 100, in their order.
    pub(crate) inputs: Vec<String>,
    /// Held for the sale only as a replacement of payments in time: `txid` came after the lease.
    pub(crate) replacement: bool,
    /// The `expiresAt` of the invoice whose lease `txid` came in (or stands for); `None` for none.
    pub(crate) expires_at: Option<i64>,
}

/// A witness's value.
pub(crate) fn witness_value(witness: &Witness) -> Json {
    let inputs =
        witness.inputs.iter().take(MAX_WITNESS_INPUTS).map(|coin| Json::from(coin.as_str())).collect();
    Json::object([
        ("version", Json::Number(WITNESS_VERSION)),
        ("address", Json::from(witness.address.as_str())),
        ("txid", Json::from(witness.txid.as_str())),
        ("sale", Json::optional_str(witness.sale.as_deref())),
        ("sats", Json::unsigned(witness.sats)),
        ("inputs", Json::array(inputs)),
        ("replacement", Json::Bool(witness.replacement)),
        (
            "expiresAt",
            if witness.sale.is_none() {
                Json::Null
            } else {
                witness.expires_at.map_or(Json::Null, Json::integer)
            },
        ),
    ])
}

/// The signed event of a witness, `created_at` when it was seen.
pub(crate) fn witness_event(
    seen: &SeenKeys,
    witness: &Witness,
    created_at: i64,
    random: &dyn Random,
) -> Event {
    let sale = witness.sale.as_deref();
    seal_record(
        Seal {
            record_type: WITNESS_RECORD_TYPE,
            value: witness_value(witness),
            signer: &seen.secret_key,
            encryption_key: &seen.encryption_key,
            address: &witness_address(&seen.address_key, &witness.address, &witness.txid, sale),
            created_at,
            tags: vec![
                vec![ORDER_TAG.to_owned(), order_tag(&seen.address_key, &witness.address, sale)],
                vec![ORDER_TAG.to_owned(), address_tag(&seen.address_key, &witness.address)],
            ],
        },
        random,
    )
    .expect("a witness fits NIP-44")
}

/// A witness's value, checked against its event's tags: its first `d` tag is the witness address
/// of what it names, an `o` tag its order tag and an `o` tag its address's tag.
fn parse_witness(value: &Json, event: &Event, address_key: &Secret) -> Parsed<Witness> {
    if !value.is_object() {
        return Ok(None);
    }
    if value.get("version").and_then(Json::as_f64).is_some_and(|version| version > WITNESS_VERSION) {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(WITNESS_VERSION)) {
        return Ok(None);
    }
    Ok(read_witness(value, event, address_key))
}

fn read_witness(v: &Json, event: &Event, address_key: &Secret) -> Option<Witness> {
    let address = v.get("address")?.as_str().filter(|address| is_deposit_address(address))?;
    let txid = v.get("txid")?.as_str().filter(|txid| is_hex32(txid))?;
    let sale = match v.get("sale")? {
        Json::Null => None,
        sale => Some(sale.as_str().filter(|sale| is_hex32(sale))?),
    };
    let sats = v.get("sats")?.as_safe_integer().and_then(|sats| u64::try_from(sats).ok())?;
    if !(1..=MAX_SATS).contains(&sats) {
        return None;
    }
    let inputs = v.get("inputs")?.as_array()?;
    if inputs.len() > MAX_WITNESS_INPUTS {
        return None;
    }
    let inputs: Vec<String> = inputs
        .iter()
        .map(|coin| coin.as_str().filter(|coin| is_coin(coin)).map(str::to_owned))
        .collect::<Option<_>>()?;
    if inputs.iter().collect::<HashSet<_>>().len() != inputs.len() {
        return None;
    }
    let replacement = v.get("replacement")?.as_bool()?;
    if sale.is_none() && replacement {
        return None;
    }
    // Null for none, the invoice's end for a sale; absent, it is no witness.
    let expires_at = match (sale, v.get("expiresAt")?) {
        (None, Json::Null) => None,
        (None, _) => return None,
        (Some(_), expires_at) => Some(expires_at.as_safe_integer()?),
    };
    let d =
        event.tags.iter().find(|tag| tag.first().map(String::as_str) == Some("d")).and_then(|tag| tag.get(1));
    let has_tag =
        |tag: &str| event.tags.iter().any(|item| item.len() >= 2 && item[0] == ORDER_TAG && item[1] == tag);
    if d.map(String::as_str) != Some(witness_address(address_key, address, txid, sale).as_str())
        || !has_tag(&order_tag(address_key, address, sale))
        || !has_tag(&address_tag(address_key, address))
    {
        return None;
    }
    Some(Witness {
        address: address.to_owned(),
        txid: txid.to_owned(),
        sale: sale.map(str::to_owned),
        sats,
        inputs,
        replacement,
        expires_at,
    })
}

/// A witness a relay sent, opened.
#[derive(Clone, Debug)]
pub(crate) enum OpenedWitness {
    Valid {
        event: Event,
        witness: Witness,
    },
    /// Authentic, but of a newer format: what it names cannot be read, its `d` tag can.
    Newer {
        event: Event,
    },
}

/// The first `d` tag of an event, when it is hex32.
fn d_of(event: &Event) -> Option<&str> {
    crate::declaration::d_tag(event)
}

/// An event that checked out, if it is a witness of this integration.
pub(crate) fn open_witness(event: &Event, seen: &SeenKeys) -> Option<OpenedWitness> {
    let d = d_of(event)?;
    let opened = open_event(
        event,
        &Expected {
            record_type: WITNESS_RECORD_TYPE,
            encryption_key: &seen.encryption_key,
            address: d,
            author: &seen.author,
        },
        |value, event| parse_witness(value, event, &seen.address_key),
    )?;
    Some(match opened {
        Opened::Newer { event } => OpenedWitness::Newer { event },
        Opened::Valid { event, value } => OpenedWitness::Valid { event, witness: value },
    })
}

/// A witness of the order's sale, as a check uses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SaleWitness {
    pub(crate) sats: u64,
    pub(crate) inputs: Vec<String>,
    pub(crate) replacement: bool,
    /// Its `created_at`: when it was seen.
    pub(crate) seen_at: i64,
}

/// The witnesses of an invoice: of this invoice (its sale and its `expiresAt`), of other
/// invoices (another sale, or another `expiresAt` of its sale), of none, and of a newer format.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OrderWitnesses {
    /// Of this invoice, by txid, in the order they were read.
    pub(crate) sale: Vec<(String, SaleWitness)>,
    /// Of other invoices, by txid: what they name counts for nothing here.
    pub(crate) others: Vec<(String, SaleWitness)>,
    /// The txids a witness none names.
    pub(crate) none: HashSet<String>,
    /// The witness addresses (`d` tags) of the witnesses of a newer format.
    pub(crate) newer: HashSet<String>,
}

impl OrderWitnesses {
    pub(crate) fn of_sale(&self, txid: &str) -> Option<&SaleWitness> {
        self.sale.iter().find(|(known, _)| known == txid).map(|(_, witness)| witness)
    }

    pub(crate) fn of_others(&self, txid: &str) -> bool {
        self.others.iter().any(|(known, _)| known == txid)
    }
}

/// The `o` tags of the read of an invoice's witnesses: of the sale, of none, of the address.
fn read_tags(seen: &SeenKeys, address: &str, sale_author: &str) -> Vec<String> {
    vec![
        order_tag(&seen.address_key, address, Some(sale_author)),
        order_tag(&seen.address_key, address, None),
        address_tag(&seen.address_key, address),
    ]
}

/// Sets `txid`'s witness, in place when it has one already (as a JavaScript `Map` does).
fn set(list: &mut Vec<(String, SaleWitness)>, txid: String, witness: SaleWitness) {
    match list.iter_mut().find(|(known, _)| *known == txid) {
        Some(entry) => entry.1 = witness,
        None => list.push((txid, witness)),
    }
}

/// The witnesses of the invoice with the address `address` and the end `expires_at`, for the
/// sale `sale_author`, from what the relays sent to its read: of each witness address, the newest
/// event that opens (one of a newer format, its event checked, is kept as such). A witness that
/// holds none of the read's `o` tags, or whose `address` is not `address`, is of no invoice of
/// this read and is ignored: only a relay that does not keep to the filter sends one.
pub(crate) fn order_witnesses_of<'a>(
    events: impl IntoIterator<Item = &'a Event>,
    seen: &SeenKeys,
    address: &str,
    sale_author: &str,
    expires_at: i64,
) -> OrderWitnesses {
    let tags: HashSet<String> = read_tags(seen, address, sale_author).into_iter().collect();
    let mut order: Vec<String> = Vec::new();
    let mut newest: HashMap<String, OpenedWitness> = HashMap::new();
    let mut checked: HashSet<String> = HashSet::new();
    for event in events {
        if checked.contains(&event.id) {
            continue;
        }
        let Some(opened) = open_witness(event, seen) else { continue };
        checked.insert(event.id.clone());
        let event = match &opened {
            OpenedWitness::Valid { event, .. } | OpenedWitness::Newer { event, .. } => event,
        };
        if !event.tags.iter().any(|tag| tag.len() >= 2 && tag[0] == ORDER_TAG && tags.contains(&tag[1])) {
            continue;
        }
        if let OpenedWitness::Valid { witness, .. } = &opened
            && witness.address != address
        {
            continue;
        }
        let d = d_of(event).expect("a witness has its d tag").to_owned();
        match newest.get(&d) {
            Some(known) => {
                let known_event = match known {
                    OpenedWitness::Valid { event, .. } | OpenedWitness::Newer { event, .. } => event,
                };
                if replaces(event, known_event) {
                    newest.insert(d, opened);
                }
            }
            None => {
                order.push(d.clone());
                newest.insert(d, opened);
            }
        }
    }
    let mut witnesses = OrderWitnesses::default();
    for d in order {
        match newest.remove(&d).expect("each address read") {
            OpenedWitness::Newer { .. } => {
                witnesses.newer.insert(d);
            }
            OpenedWitness::Valid { event, witness } => {
                let of = SaleWitness {
                    sats: witness.sats,
                    inputs: witness.inputs,
                    replacement: witness.replacement,
                    seen_at: event.created_at,
                };
                match &witness.sale {
                    None => {
                        witnesses.none.insert(witness.txid);
                    }
                    Some(sale) if sale == sale_author && witness.expires_at == Some(expires_at) => {
                        set(&mut witnesses.sale, witness.txid, of);
                    }
                    Some(_) => set(&mut witnesses.others, witness.txid, of),
                }
            }
        }
    }
    witnesses
}

/// An invoice whose witnesses are read: its address, its order's sale (its author), its end, and
/// the integration's seen keys.
#[derive(Clone, Copy)]
pub(crate) struct InvoiceOf<'a> {
    pub(crate) seen: &'a SeenKeys,
    pub(crate) address: &'a str,
    pub(crate) sale_author: &'a str,
    pub(crate) expires_at: i64,
}

/// The witnesses of `invoice`: read on the merchant's `relays` by their order tags (of the sale and
/// of none) and the address tag (every sale's), as soon as a majority answered (on every relay
/// with `every_relay`), with a key of this read alone. `network` when fewer than a majority
/// answered.
pub(crate) async fn read_order_witnesses(
    pool: &RelayPool,
    invoice: InvoiceOf<'_>,
    relays: &[String],
    random: &dyn Random,
    every_relay: bool,
) -> Result<OrderWitnesses, Error> {
    let InvoiceOf { seen, address, sale_author, expires_at } = invoice;
    let needed = majority(relays.len());
    let author = seen.author.clone();
    let encryption_key = seen.encryption_key.clone();
    let keep =
        records_that_open(Arc::new(move |_, pubkey| (pubkey == author).then(|| encryption_key.clone())));
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![seen.author.clone()]),
        o: Some(read_tags(seen, address, sale_author)),
        ..Filter::default()
    };
    let read = pool
        .query_relays(relays, &filter, &read_key(random), &keep, ReadOf { needed, paged: false, every_relay })
        .await;
    if !read.majority_answered(relays.len()) {
        return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
    }
    Ok(order_witnesses_of(read.events(), seen, address, sale_author, expires_at))
}

/// The addresses of `by_tag` (address tag → address) an event names (SPEC.md §31, Leasing an
/// address, step 3): when it is of `seen_author` and checks out (SPEC.md §11), each address whose
/// address tag it holds as an `o` tag, whatever its content (one that does not open as a witness,
/// or of a newer format, names it all the same); none otherwise. `checks` verifies its signature,
/// once its id was checked, and only of an event that would name an address (the cheap checks
/// first).
pub(crate) fn addresses_named(
    value: &Json,
    seen_author: &str,
    by_tag: &HashMap<String, String>,
    checks: &dyn Fn(&Event) -> bool,
) -> Vec<String> {
    if value.get("pubkey").and_then(Json::as_str) != Some(seen_author) {
        return Vec::new();
    }
    let Some(tags) = value.get("tags").and_then(Json::as_array) else { return Vec::new() };
    let mut named: Vec<String> = Vec::new();
    for tag in tags {
        let Some(tag) = tag.as_array() else { continue };
        if tag.first().and_then(Json::as_str) != Some(ORDER_TAG) {
            continue;
        }
        if let Some(address) = tag.get(1).and_then(Json::as_str).and_then(|tag| by_tag.get(tag))
            && !named.contains(address)
        {
            named.push(address.clone());
        }
    }
    if named.is_empty() {
        return named;
    }
    match has_valid_id(value) {
        Some(event) if checks(&event) => named,
        _ => Vec::new(),
    }
}

/// The addresses of `addresses` a witness names (SPEC.md §31, Leasing an address, step 2): read
/// on the merchant's `relays` by their address tags, not paged, as soon as a majority answered,
/// with a key of this read alone. Of each event, only the addresses it names are kept
/// ([`addresses_named`]). `network` when fewer than a majority answered.
pub(crate) async fn read_named_addresses(
    pool: &RelayPool,
    seen: &SeenKeys,
    addresses: &[String],
    relays: &[String],
    random: &dyn Random,
) -> Result<HashSet<String>, Error> {
    let mut named = HashSet::new();
    if addresses.is_empty() {
        return Ok(named);
    }
    let by_tag: HashMap<String, String> =
        addresses.iter().map(|address| (address_tag(&seen.address_key, address), address.clone())).collect();
    let author = seen.author.clone();
    // Whether each event's signature verifies: once, whatever relays send copies of it.
    let verdicts: Mutex<HashMap<(String, String), bool>> = Mutex::new(HashMap::new());
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![seen.author.clone()]),
        o: Some(addresses.iter().map(|address| address_tag(&seen.address_key, address)).collect()),
        ..Filter::default()
    };
    let keep: Keep<Vec<String>> = Arc::new(move |value: &Json| {
        let checks = |event: &Event| {
            let copy = (event.id.clone(), event.sig.clone());
            let known =
                verdicts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&copy).copied();
            known.unwrap_or_else(|| {
                let valid = signature_checks(&event.id, &event.pubkey, &event.sig);
                verdicts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(copy, valid);
                valid
            })
        };
        let names = addresses_named(value, &author, &by_tag, &checks);
        (!names.is_empty()).then_some(names)
    });
    let read = pool.query_relays(relays, &filter, &read_key(random), &keep, ReadOf::query(relays)).await;
    if !read.majority_answered(relays.len()) {
        return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
    }
    for names in read.events() {
        named.extend(names.iter().cloned());
    }
    Ok(named)
}

/// Publishes a witness on the merchant's `relays`, signed and authenticated with the seen secret:
/// once a majority took it, else `network`.
pub(crate) async fn publish_witness(
    pool: &RelayPool,
    seen: &SeenKeys,
    witness: &Witness,
    relays: &[String],
    created_at: i64,
    random: &dyn Random,
) -> Result<(), Error> {
    let event = witness_event(seen, witness, created_at, random);
    pool.publish_to_quorum(relays, &event, &seen.secret_key, majority(relays.len())).await.map_err(|_| {
        Error::network("Fewer than a majority of the merchant's relays took the witness of a payment")
    })
}
