//! Leases (SPEC.md §31, Leases): an order holds a deposit address of the lot for the time of its
//! invoice with a record in the merchant's registry, signed by the order's sale, at the address's
//! registry address. Outside, what anyone holding the registry key reads (when the lease ends, or
//! its withdrawal); inside, sealed to the merchant's reading key as a declaration's, the order's
//! terms. Like a declaration, a lease stays: a payment of its address in its time is the order's
//! for good.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::declaration::{DeclaredPrice, d_tag};
use crate::derive::{Sale, lease_address, outer_key};
use crate::json::{self, Json};
use crate::lightning::bolt11;
use crate::nostr::event::{Event, has_valid_id, signature_checks};
use crate::nostr::nip44;
use crate::nostr::record::{Expected, Newer, Opened, Parsed, Seal, d_tag_of, open_event, seal_record};
use crate::nostr::relay::{Filter, Keep, ReadOutcome, RelayPool, majority, read_key};
use crate::onchain::address::is_deposit_address;
use crate::onchain::tolerance::tolerance_of;
use crate::protocol::{
    CLOCK_TOLERANCE_SECONDS, GRACE_SECONDS, LEASE_LOOKBACK_SECONDS, LEASE_RECORD_TYPE, LEASE_VERSION,
    MAX_SATS, RECORD_KIND,
};
use crate::runtime::{Random, random32};
use crate::secret::Secret;
use crate::text::to_hex;
use crate::urls::parse_https_url;

/// What a lease holds of its order (the lease's JSON, inside).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaseTerms {
    pub(crate) address: String,
    pub(crate) sats: u64,
    /// The order's Lightning invoice and its verify URL; `None` for an order paid on-chain only.
    pub(crate) invoice: Option<String>,
    pub(crate) verify_url: Option<String>,
    /// The Invoice's dates (Unix seconds).
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) price: DeclaredPrice,
    /// The label: the note, else the reference.
    pub(crate) note: String,
    /// The order's tolerance (basis points): the channel's when the order was created, which
    /// judges its payment for good. 0: none (absent from the lease).
    pub(crate) tolerance: u64,
    /// `false` as first published, `true` once confirmed; `None` when absent (not confirmed).
    pub(crate) confirmed: Option<bool>,
}

impl LeaseTerms {
    /// Whether the lease is confirmed: `confirmed` true, nothing else.
    pub(crate) fn is_confirmed(&self) -> bool {
        self.confirmed == Some(true)
    }
}

/// The lease's JSON (inside), in the order the specification writes it: `tolerance` after
/// `taker` when above 0, `confirmed` after them when given.
pub(crate) fn lease_inside(sale: &Sale, terms: &LeaseTerms) -> Json {
    let mut members = vec![
        ("version", Json::Number(LEASE_VERSION)),
        ("address", Json::from(terms.address.as_str())),
        ("sats", Json::unsigned(terms.sats)),
        ("invoice", Json::optional_str(terms.invoice.as_deref())),
        ("verifyUrl", Json::optional_str(terms.verify_url.as_deref())),
        ("createdAt", Json::integer(terms.created_at)),
        ("expiresAt", Json::integer(terms.expires_at)),
        (
            "sale",
            Json::object([
                ("key", Json::from(to_hex(sale.key.expose()))),
                ("fiat", terms.price.to_json()),
                ("note", Json::from(terms.note.as_str())),
            ]),
        ),
        ("taker", Json::from(sale.taker.as_str())),
    ];
    if terms.tolerance > 0 {
        members.push(("tolerance", Json::unsigned(terms.tolerance)));
    }
    if let Some(confirmed) = terms.confirmed {
        members.push(("confirmed", Json::Bool(confirmed)));
    }
    Json::object_of(members)
}

fn seal_sale_record(
    sale: &Sale,
    address: &str,
    value: Json,
    created_at: i64,
    random: &dyn Random,
) -> Option<Event> {
    let d = lease_address(&sale.registry.key, address);
    seal_record(
        Seal {
            record_type: LEASE_RECORD_TYPE,
            value,
            signer: &sale.secret_key,
            encryption_key: &outer_key(&sale.registry.key, &d, &sale.author),
            address: &d,
            created_at,
            tags: Vec::new(),
        },
        random,
    )
}

/// The lease of `terms.address` for `sale`, signed at `created_at`; it ends at `expiresAt` + 120.
/// `None` when it does not fit NIP-44.
pub(crate) fn lease_event(
    sale: &Sale,
    terms: &LeaseTerms,
    created_at: i64,
    random: &dyn Random,
) -> Option<Event> {
    let nonce = random32(random);
    let sealed = nip44::encrypt(&json::stringify(&lease_inside(sale, terms)), &sale.inner_key, &nonce)?;
    let outside = Json::object([
        ("version", Json::Number(LEASE_VERSION)),
        ("end", Json::integer(terms.expires_at + GRACE_SECONDS)),
        ("sealed", Json::from(sealed)),
    ]);
    seal_sale_record(sale, &terms.address, outside, created_at, random)
}

/// The withdrawal of `sale`'s lease of `address`, which replaces it (same author and `d` tag):
/// its `created_at` strictly after the lease's.
pub(crate) fn withdrawal_event(sale: &Sale, address: &str, created_at: i64, random: &dyn Random) -> Event {
    let value = Json::object([("version", Json::Number(LEASE_VERSION)), ("withdrawn", Json::Bool(true))]);
    seal_sale_record(sale, address, value, created_at, random).expect("a withdrawal fits NIP-44")
}

/// A record's outside, as anyone holding the registry key reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LeaseOutside {
    Lease {
        end: i64,
        sealed: String,
    },
    Withdrawn,
    /// Authentic, but of a newer format: an unreadable lease is never written over.
    Newer,
}

fn parse_outside(value: &Json) -> Parsed<LeaseOutside> {
    if !value.is_object() {
        return Ok(None);
    }
    if value.get("version").and_then(Json::as_f64).is_some_and(|version| version > LEASE_VERSION) {
        return Err(Newer);
    }
    if !value.get("version").is_some_and(|version| version.is_number(LEASE_VERSION)) {
        return Ok(None);
    }
    if value.get("withdrawn") == Some(&Json::Bool(true)) {
        return Ok(Some(LeaseOutside::Withdrawn));
    }
    let (Some(end), Some(sealed)) =
        (value.get("end").and_then(Json::as_safe_integer), value.get("sealed").and_then(Json::as_str))
    else {
        return Ok(None);
    };
    Ok(Some(LeaseOutside::Lease { end, sealed: sealed.to_owned() }))
}

/// What a read of leases keeps of a record's event, its id checked: what the walk of its address
/// and a lease's confirmation need, and its signature; never its tags nor its content (SPEC.md
/// §13, Limits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaseEvent {
    pub(crate) id: String,
    pub(crate) pubkey: String,
    pub(crate) created_at: i64,
    pub(crate) sig: String,
}

impl LeaseEvent {
    pub(crate) fn of(event: &Event) -> Self {
        Self {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            created_at: event.created_at,
            sig: event.sig.clone(),
        }
    }
}

/// Whether `a` replaces `b` as relays keep them: a later `created_at`, then the lowest id.
pub(crate) fn replaces(a: &LeaseEvent, b: &LeaseEvent) -> bool {
    a.created_at > b.created_at || (a.created_at == b.created_at && a.id < b.id)
}

/// What a read of leases keeps of a record's outside: whether, and until when, it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseHold {
    Lease { end: i64 },
    Withdrawn,
    Newer,
}

/// A record at a deposit address's registry address, as the walk of the address reads it.
pub(crate) trait HoldRecord {
    fn lease_event(&self) -> &LeaseEvent;
    fn hold(&self) -> LeaseHold;
    /// Whether its signature checks out: checked once, when the walk needs it.
    fn signed(&self) -> bool;
}

/// A record of the registry at a deposit address's registry address `d`, by any author: its id
/// checked, its signature not yet (SPEC.md §31, Opening a lease). `signed` checks it once: whether
/// a copy of the event (its id) a relay sent carries a signature that checks out, so that a
/// relay's copy with a damaged signature never hides the valid one another relay sent.
#[derive(Debug)]
pub(crate) struct LeaseRecord {
    pub(crate) event: LeaseEvent,
    pub(crate) d: String,
    pub(crate) outside: LeaseHold,
    /// The signatures of the copies relays sent (the event's first).
    signatures: Vec<String>,
    /// 0: not checked; 1: does not check out; 2: checks out.
    signed: AtomicU8,
}

impl LeaseRecord {
    pub(crate) fn new(event: LeaseEvent, d: String, outside: LeaseHold) -> Self {
        let signatures = vec![event.sig.clone()];
        Self { event, d, outside, signatures, signed: AtomicU8::new(0) }
    }

    /// Takes the signature of another relay's copy of the same event (its id is its hash): one
    /// more to try.
    pub(crate) fn add_copy(&mut self, sig: &str) {
        if self.signatures.iter().any(|known| known == sig) {
            return;
        }
        self.signatures.push(sig.to_owned());
        if self.signed.load(Ordering::Relaxed) == 1 {
            self.signed.store(0, Ordering::Relaxed);
        }
    }
}

impl HoldRecord for LeaseRecord {
    fn lease_event(&self) -> &LeaseEvent {
        &self.event
    }

    fn hold(&self) -> LeaseHold {
        self.outside
    }

    fn signed(&self) -> bool {
        match self.signed.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let valid = self
                    .signatures
                    .iter()
                    .any(|sig| signature_checks(&self.event.id, &self.event.pubkey, sig));
                self.signed.store(if valid { 2 } else { 1 }, Ordering::Relaxed);
                valid
            }
        }
    }
}

/// What a relay sent, opened as a record of type `registry-onchain` at the registry address `d`,
/// with the outer key of `d` and of the event's own author (SPEC.md §31, Opening a lease): its id
/// first; a content of a newer NIP-44 version is no record here (anybody can write one at `d`);
/// its signature not checked. `None` when it is not one.
pub(crate) fn open_lease_outside(
    value: &Json,
    registry_key: &Secret,
    d: &str,
) -> Option<(LeaseEvent, LeaseOutside)> {
    let event = has_valid_id(value)?;
    if event.kind != RECORD_KIND || d_tag_of(value) != Some(d) {
        return None;
    }
    // A content of a newer NIP-44 version included: only the outer key seals a newer lease.
    let plaintext = nip44::decrypt(&event.content, &outer_key(registry_key, d, &event.pubkey)).ok()?;
    let envelope = json::parse(&plaintext)?;
    if !envelope.is_object()
        || !envelope.has("v")
        || envelope.get("t").and_then(Json::as_str) != Some(LEASE_RECORD_TYPE)
    {
        return None;
    }
    let outside = match parse_outside(envelope.get("v").expect("checked")) {
        Ok(Some(outside)) => outside,
        Ok(None) => return None,
        Err(Newer) => LeaseOutside::Newer,
    };
    Some((LeaseEvent::of(&event), outside))
}

/// `open_lease_outside`, keeping of the record what holding needs.
pub(crate) fn open_lease_record(value: &Json, registry_key: &Secret, d: &str) -> Option<LeaseRecord> {
    let (event, outside) = open_lease_outside(value, registry_key, d)?;
    let hold = match outside {
        LeaseOutside::Lease { end, .. } => LeaseHold::Lease { end },
        LeaseOutside::Withdrawn => LeaseHold::Withdrawn,
        LeaseOutside::Newer => LeaseHold::Newer,
    };
    Some(LeaseRecord::new(event, d.to_owned(), hold))
}

/// Whether a record holds its address at `t`: a lease whose end is at most 300 s before `t`
/// (another server's clock may be behind), or of a newer format.
fn holds(hold: LeaseHold, t: i64) -> bool {
    match hold {
        LeaseHold::Newer => true,
        LeaseHold::Lease { end } => end >= t - CLOCK_TOLERANCE_SECONDS,
        LeaseHold::Withdrawn => false,
    }
}

/// Whether the records of one address lease it at `t` (SPEC.md §31, Leases): of each author, its
/// records from the newest: one that holds the address leases it; one that holds nothing ends the
/// author's records, unless an older one of them holds and its signature does not check out (it
/// is then passed over). A record that holds is never checked for its signature: only a holder of
/// the registry key seals one, and it may lease.
pub(crate) fn is_leased<R: HoldRecord>(records: &[&R], t: i64) -> bool {
    let mut authors: Vec<&str> = Vec::new();
    let mut by_author: HashMap<&str, Vec<&R>> = HashMap::new();
    for record in records {
        let author = record.lease_event().pubkey.as_str();
        by_author.entry(author).or_insert_with(|| {
            authors.push(author);
            Vec::new()
        });
        by_author.get_mut(author).expect("inserted").push(record);
    }
    let mut leased = false;
    // Every author walked, as the vectors count the signatures checked.
    for author in authors {
        let mut walk = by_author.remove(author).expect("an author of the records");
        walk.sort_by(|a, b| {
            if replaces(a.lease_event(), b.lease_event()) {
                std::cmp::Ordering::Less
            } else if replaces(b.lease_event(), a.lease_event()) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        for (index, record) in walk.iter().enumerate() {
            if holds(record.hold(), t) {
                leased = true;
                break;
            }
            if !walk[index + 1..].iter().any(|older| holds(older.hold(), t)) {
                break;
            }
            if record.signed() {
                break;
            }
        }
    }
    leased
}

/// Whether the lease `own` (an event of the sale) is confirmed by `records`, a complete read of
/// its address's records (SPEC.md §31, Leasing an address, step 3.3): it is among them, no record
/// of another author holds the address at `t`, and `own` is the newest record of its author there.
pub(crate) fn is_confirmed<R: HoldRecord>(records: &[&R], own: &LeaseEvent, t: i64) -> bool {
    if !records.iter().any(|record| record.lease_event().id == own.id) {
        return false;
    }
    let others: Vec<&R> =
        records.iter().copied().filter(|record| record.lease_event().pubkey != own.pubkey).collect();
    if is_leased(&others, t) {
        return false;
    }
    !records.iter().any(|record| {
        let event = record.lease_event();
        event.pubkey == own.pubkey && event.id != own.id && replaces(event, own)
    })
}

/// The records of the registry at the registry addresses of deposit addresses.
#[derive(Debug)]
pub(crate) struct LeaseRead {
    /// By address (every address asked, in the order asked).
    pub(crate) records: Vec<(String, Vec<LeaseRecord>)>,
    /// Whether a majority of the relays answered: else the read is no answer (SPEC.md §13).
    pub(crate) answered: bool,
    /// Whether a majority of the relays read them completely.
    pub(crate) complete: bool,
}

impl LeaseRead {
    /// The records of `address`.
    pub(crate) fn of(&self, address: &str) -> Vec<&LeaseRecord> {
        self.records
            .iter()
            .find(|(known, _)| known == address)
            .map(|(_, records)| records.iter().collect())
            .unwrap_or_default()
    }
}

/// The records of the registry at the registry addresses of `addresses`, by address: a complete
/// read on the merchant's `relays` since 7200 s before `now` (older leases have ended), with a key
/// of this read alone (leases are signed by sales the integration does not know); on every relay
/// with `every_relay`. Each relay's first copy of an event counts, its signature tried with the
/// other relays' copies.
pub(crate) async fn read_leases(
    pool: &RelayPool,
    registry_key: &Secret,
    addresses: &[String],
    relays: &[String],
    now: i64,
    random: &dyn Random,
    every_relay: bool,
) -> LeaseRead {
    let mut found: Vec<(String, Vec<LeaseRecord>)> =
        addresses.iter().map(|address| (address.clone(), Vec::new())).collect();
    if addresses.is_empty() {
        return LeaseRead { records: found, answered: true, complete: true };
    }
    let by_d: HashMap<String, usize> = addresses
        .iter()
        .enumerate()
        .map(|(index, address)| (lease_address(registry_key, address), index))
        .collect();
    let needed = majority(relays.len());
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        d: Some(addresses.iter().map(|address| lease_address(registry_key, address)).collect()),
        since: Some(now - LEASE_LOOKBACK_SECONDS),
        ..Filter::default()
    };
    let key = registry_key.clone();
    let lookup = by_d.clone();
    // At a lease's address, by any author: the record each event opens to, as it comes (its id
    // checked; a content of a newer NIP-44 version is no record here: anybody writes one).
    let keep: Keep<LeaseRecord> = Arc::new(move |value: &Json| {
        let d = d_tag_of(value)?;
        if !lookup.contains_key(d) {
            return None;
        }
        open_lease_record(value, &key, d)
    });
    let complete_read =
        pool.query_complete(relays, &filter, &read_key(random), needed, &keep, every_relay).await;
    // A relay still reading did not answer: its pages are records, and that is all.
    let ReadOutcome { answered, complete } = complete_read.outcome(relays.len());
    let read = complete_read.read;
    // Ids that checked out: another copy of one is the same event, its signature one more to try.
    let mut checked: HashMap<String, (usize, usize)> = HashMap::new();
    for (_, records) in read.answers.into_iter().chain(read.pages) {
        // A relay's first copy of each id: at most one signature per relay to try.
        let mut of_relay: HashSet<String> = HashSet::new();
        for record in records {
            if !of_relay.insert(record.event.id.clone()) {
                continue;
            }
            if let Some(&(address, position)) = checked.get(&record.event.id) {
                found[address].1[position].add_copy(&record.event.sig);
                continue;
            }
            let address = by_d[&record.d];
            checked.insert(record.event.id.clone(), (address, found[address].1.len()));
            found[address].1.push(record);
        }
    }
    LeaseRead { records: found, answered, complete }
}

/// A lease of the sale, opened by the sale (or the merchant): its terms.
#[derive(Clone, Debug)]
pub(crate) struct OpenedLease {
    pub(crate) event: Event,
    /// The `d` tag: the registry address of `terms.address`.
    pub(crate) d: String,
    pub(crate) terms: LeaseTerms,
}

/// The inside of a lease's outside, opened with the sale's inner key (SPEC.md §31, Opening it as
/// the sale): its terms, `None` when they are not valid (its tolerance read as 0 when absent or not
/// one); a newer version, `Newer`.
pub(crate) fn open_lease_inside(sealed: &str, end: i64, d: &str, sale: &Sale) -> Parsed<(LeaseTerms, Json)> {
    let Ok(text) = nip44::decrypt(sealed, &sale.inner_key) else {
        return Ok(None);
    };
    let Some(inside) = json::parse(&text) else {
        return Ok(None);
    };
    if !inside.is_object() {
        return Ok(None);
    }
    if inside.get("version").and_then(Json::as_f64).is_some_and(|version| version > LEASE_VERSION) {
        return Err(Newer);
    }
    if !inside.get("version").is_some_and(|version| version.is_number(LEASE_VERSION)) {
        return Ok(None);
    }
    Ok(read_terms(&inside, end, d, sale).map(|terms| (terms, inside)))
}

fn read_terms(v: &Json, end: i64, d: &str, sale: &Sale) -> Option<LeaseTerms> {
    let address = v.get("address")?.as_str().filter(|address| is_deposit_address(address))?;
    if lease_address(&sale.registry.key, address) != d {
        return None;
    }
    let sats = v.get("sats")?.as_safe_integer().and_then(|sats| u64::try_from(sats).ok())?;
    if !(1..=MAX_SATS).contains(&sats) {
        return None;
    }
    let created_at = v.get("createdAt")?.as_safe_integer()?;
    let expires_at = v.get("expiresAt")?.as_safe_integer()?;
    if created_at >= expires_at || end != expires_at + GRACE_SECONDS {
        return None;
    }
    let invoice = v.get("invoice")?;
    let verify_url = v.get("verifyUrl")?;
    let (invoice, verify_url) = if invoice.is_null() {
        if !verify_url.is_null() {
            return None;
        }
        (None, None)
    } else {
        let invoice = invoice.as_str()?;
        let verify_url = verify_url.as_str().filter(|url| parse_https_url(url).is_some())?;
        let decoded = bolt11::decode(invoice)?;
        if decoded.network != "bc"
            || decoded.amount_msat.map(u128::from) != Some(u128::from(sats) * 1000)
            || decoded.timestamp != created_at
            || decoded.expires_at() != expires_at
        {
            return None;
        }
        (Some(invoice.to_owned()), Some(verify_url.to_owned()))
    };
    let sale_value = v.get("sale").filter(|value| value.is_object())?;
    if sale_value.get("key").and_then(Json::as_str) != Some(to_hex(sale.key.expose()).as_str()) {
        return None;
    }
    let note = sale_value.get("note")?.as_json_string()?;
    let price = DeclaredPrice::parse(sale_value.get("fiat")?, 0)?;
    Some(LeaseTerms {
        address: address.to_owned(),
        sats,
        invoice,
        verify_url,
        created_at,
        expires_at,
        price,
        note: note.to_string_lossy().into_owned(),
        // Absent (a lease without tolerance) or invalid: none.
        tolerance: tolerance_of(v.get("tolerance")),
        // Absent, or anything but true: not confirmed.
        confirmed: v.get("confirmed").map(|confirmed| *confirmed == Json::Bool(true)),
    })
}

/// A record of the sale at a registry address: its lease, its withdrawal, or one of a newer
/// format (authentic, unreadable: the newest at its address, it leaves no lease there).
#[derive(Clone, Debug)]
pub(crate) enum SaleLeaseRecord {
    Lease(Box<OpenedLease>),
    Withdrawn { event: Event, d: String },
    Newer { event: Event, d: String },
}

impl SaleLeaseRecord {
    pub(crate) fn event(&self) -> &Event {
        match self {
            Self::Lease(lease) => &lease.event,
            Self::Withdrawn { event, .. } | Self::Newer { event, .. } => event,
        }
    }

    pub(crate) fn d(&self) -> &str {
        match self {
            Self::Lease(lease) => &lease.d,
            Self::Withdrawn { d, .. } | Self::Newer { d, .. } => d,
        }
    }
}

/// An event that checked out, if it is a lease (or a withdrawal) of `sale`: at a registry address
/// (its `d` tag, hex32), signed by the sale, with valid terms inside; of a newer format, `Newer`.
pub(crate) fn open_sale_lease(event: &Event, sale: &Sale) -> Option<Result<SaleLeaseRecord, Newer>> {
    let d = d_tag(event)?;
    if event.pubkey != sale.author {
        return None;
    }
    let key = outer_key(&sale.registry.key, d, &sale.author);
    let opened = open_event(
        event,
        &Expected { record_type: LEASE_RECORD_TYPE, encryption_key: &key, address: d, author: &sale.author },
        |outside, _| parse_outside(outside),
    )?;
    let (event, outside) = match opened {
        Opened::Newer { .. } => return Some(Err(Newer)),
        Opened::Valid { event, value } => (event, value),
    };
    match outside {
        LeaseOutside::Newer => Some(Err(Newer)),
        LeaseOutside::Withdrawn => Some(Ok(SaleLeaseRecord::Withdrawn { event, d: d.to_owned() })),
        LeaseOutside::Lease { end, sealed } => match open_lease_inside(&sealed, end, d, sale) {
            Err(Newer) => Some(Err(Newer)),
            Ok(None) => None,
            Ok(Some((terms, _))) => {
                Some(Ok(SaleLeaseRecord::Lease(Box::new(OpenedLease { event, d: d.to_owned(), terms }))))
            }
        },
    }
}
