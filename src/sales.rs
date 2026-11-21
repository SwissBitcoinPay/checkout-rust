//! The invoices declared for a sale, read back from the merchant's registry (SPEC.md §21): its
//! declarations and its leases of deposit addresses. What `create_invoice` checks before a new
//! invoice, and `find_invoices` gives.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use num_bigint::BigUint;

use crate::declaration::{DeclaredPrice, OpenedDeclaration, open_declaration};
use crate::derive::{Sale, outer_key};
use crate::error::Error;
use crate::model::{DeclaredInvoice, Fiat, PaymentStatus};
use crate::nostr::event::Event;
use crate::nostr::record::{Newer, Opened, records_that_open, replaces};
use crate::nostr::relay::{Filter, Read, ReadOf, RelayPool, majority};
use crate::onchain::address::payment_uri;
use crate::onchain::lease::{OpenedLease, SaleLeaseRecord, open_sale_lease};
use crate::onchain::rest::{RestInvoice, by_rest_order, rest_invoice_of};
use crate::protocol::{GRACE_SECONDS, RECORD_KIND, SATS_CURRENCY};
use crate::rates::{Decimal, format_decimal};
use crate::runtime::Logger;
use crate::text::ascii_lower;

/// A declared invoice, with its signed declaration (`None` for an order paid on-chain only) and
/// lease (`None` without an address): published again when the invoice may still be paid.
#[derive(Clone, Debug)]
pub(crate) struct SaleDeclaration {
    pub(crate) invoice: DeclaredInvoice,
    pub(crate) event: Option<Event>,
    pub(crate) lease: Option<Event>,
}

impl SaleDeclaration {
    /// Its last record: its declaration, or for an invoice paid on-chain only its lease's event
    /// (its mark). The one shown has it on a majority of the relays; one whose `create_invoice`
    /// failed before that, on a minority.
    pub(crate) fn last_record(&self) -> &Event {
        self.event.as_ref().or(self.lease.as_ref()).expect("a declared invoice has a declaration or a lease")
    }
}

/// What the registry holds of a sale.
#[derive(Clone, Debug, Default)]
pub(crate) struct SaleRecords {
    /// The order's invoices, oldest first.
    pub(crate) invoices: Vec<SaleDeclaration>,
    /// The rest invoices of each invoice with an address, by `rest_key_of` its address and end: its
    /// declarations with `rest`, by date then payment hash.
    pub(crate) rests: HashMap<String, Vec<RestInvoice>>,
    /// The declarations of rest invoices fewer than a majority of the merchant's relays sent, by
    /// payment hash: their publication may have reached a minority only, and a later read may miss
    /// them. Published again on a majority before they are used.
    pub(crate) unsure_rests: HashMap<String, Event>,
    /// The sale's leases still held (not withdrawn), by address: the order's terms.
    pub(crate) leases: HashMap<String, OpenedLease>,
    /// How many relays sent each event, by id: of a read on every relay, which relays hold it.
    pub(crate) sent_by: HashMap<String, usize>,
}

/// The key, in `SaleRecords::rests`, of the invoice with `address` and the end `expires_at`.
pub(crate) fn rest_key_of(address: &str, expires_at: i64) -> String {
    format!("{address}/{expires_at}")
}

/// The price of a declared sale as a Fiat: `None` for a sale in sats.
pub(crate) fn fiat_of(price: &DeclaredPrice) -> Option<Fiat> {
    (price.currency != SATS_CURRENCY).then(|| Fiat {
        amount: format_decimal(&Decimal { units: BigUint::from(price.minor), scale: price.digits }),
        currency: price.currency.clone(),
        minor: price.minor,
        digits: price.digits,
    })
}

/// The invoices of `sale` on `relays`, oldest first: read page after page as soon as a majority of
/// the relays answered (on every relay with `every_relay`, SPEC.md §13). `network` when fewer than
/// a majority answered.
pub(crate) async fn read_sale_declarations(
    pool: &RelayPool,
    sale: &Sale,
    relays: &[String],
    logger: &dyn Logger,
    every_relay: bool,
) -> Result<SaleRecords, Error> {
    let needed = majority(relays.len());
    let author = sale.author.clone();
    let registry_key = sale.registry.key.clone();
    // Its declarations and its records at registry addresses: sealed with the outer key of their
    // address and of the sale.
    let keep = records_that_open(Arc::new(move |d, pubkey| match d {
        Some(d) if pubkey == author => Some(outer_key(&registry_key, d, pubkey)),
        _ => None,
    }));
    let filter = Filter {
        kinds: Some(vec![RECORD_KIND]),
        authors: Some(vec![sale.author.clone()]),
        ..Filter::default()
    };
    let read = pool
        .query_relays(relays, &filter, &sale.secret_key, &keep, ReadOf { needed, paged: true, every_relay })
        .await;
    if !read.majority_answered(relays.len()) {
        return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
    }
    Ok(sale_records_of(&read, sale, needed, logger))
}

/// The sale's records from what the relays sent (each relay's events, checked): of the relays that
/// answered, and on every relay the pages of those still reading, whose events count all the same
/// (a relay that sent an event holds it), though they did not answer.
pub(crate) fn sale_records_of(
    read: &Read<Event>,
    sale: &Sale,
    needed: usize,
    logger: &dyn Logger,
) -> SaleRecords {
    let mut declarations: Vec<OpenedDeclaration> = Vec::new();
    let mut by_hash: HashSet<String> = HashSet::new();
    // The sale's records at registry addresses of addresses.
    let mut records: Vec<SaleLeaseRecord> = Vec::new();
    // Event ids that checked out: another copy of one is the same event, not opened again.
    let mut checked: HashSet<String> = HashSet::new();
    let mut sent_by: HashMap<String, usize> = HashMap::new();
    let mut newer = false;
    for (_, events) in read.answers.iter().chain(read.pages.iter()) {
        // A relay counts for an event when it sent a copy whose id is its hash: it holds it.
        let ids: HashSet<&str> = events.iter().map(|event| event.id.as_str()).collect();
        for id in ids {
            *sent_by.entry(id.to_owned()).or_default() += 1;
        }
    }
    for event in read.events() {
        if checked.contains(&event.id) {
            continue;
        }
        let opened = match open_declaration(event, sale) {
            Some(Opened::Valid { value, .. }) => Ok(Some(value)),
            Some(Opened::Newer { .. }) => Err(Newer),
            None => Ok(None),
        };
        match opened {
            Ok(Some(declaration)) => {
                checked.insert(event.id.clone());
                if by_hash.insert(declaration.decoded.payment_hash.clone()) {
                    declarations.push(declaration);
                }
            }
            Ok(None) => match open_sale_lease(event, sale) {
                Some(Ok(record)) => {
                    checked.insert(event.id.clone());
                    records.push(record);
                }
                Some(Err(Newer)) => {
                    newer = true;
                    if let Some(d) = crate::declaration::d_tag(event) {
                        checked.insert(event.id.clone());
                        records.push(SaleLeaseRecord::Newer { event: event.clone(), d: d.to_owned() });
                    }
                }
                None => {}
            },
            Err(Newer) => {
                newer = true;
                // Authentic (its signature checked before its format), at a registry address:
                // the newest there, it leaves no lease of the sale.
                if let Some(d) = crate::declaration::d_tag(event) {
                    checked.insert(event.id.clone());
                    records.push(SaleLeaseRecord::Newer { event: event.clone(), d: d.to_owned() });
                }
            }
        }
    }
    if newer {
        logger.warn("sattleme-checkout: a declaration or a lease of this order has a newer format than this version reads; update the crate");
    }
    let newest = newest_records(records);
    let mut rests: HashMap<String, Vec<RestInvoice>> = HashMap::new();
    let mut unsure_rests: HashMap<String, Event> = HashMap::new();
    let mut invoices: Vec<OpenedDeclaration> = Vec::new();
    for declaration in declarations {
        let Some(rest) = &declaration.rest else {
            invoices.push(declaration);
            continue;
        };
        if sent_by.get(&declaration.event.id).copied().unwrap_or(0) < needed {
            unsure_rests.insert(declaration.decoded.payment_hash.clone(), declaration.event.clone());
        }
        rests
            .entry(rest_key_of(&rest.address, rest.expires_at))
            .or_default()
            .push(rest_invoice_of(&declaration));
    }
    for list in rests.values_mut() {
        list.sort_by(by_rest_order);
    }
    let leases = newest
        .iter()
        .filter_map(|record| match record {
            SaleLeaseRecord::Lease(lease) => Some((lease.terms.address.clone(), (**lease).clone())),
            _ => None,
        })
        .collect();
    SaleRecords {
        invoices: invoices_of(&sale.reference, &invoices, &newest),
        rests,
        unsure_rests,
        leases,
        sent_by,
    }
}

/// Of the sale's records at registry addresses, the newest at each (the highest `created_at`, then
/// the lowest id): its lease there, or its withdrawal, which leaves none.
pub(crate) fn newest_records(records: Vec<SaleLeaseRecord>) -> Vec<SaleLeaseRecord> {
    let mut order: Vec<String> = Vec::new();
    let mut newest: HashMap<String, SaleLeaseRecord> = HashMap::new();
    for record in records {
        let d = record.d().to_owned();
        match newest.get(&d) {
            Some(known) if !replaces(record.event(), known.event()) => {}
            Some(_) => {
                newest.insert(d, record);
            }
            None => {
                order.push(d.clone());
                newest.insert(d, record);
            }
        }
    }
    order.into_iter().map(|d| newest.remove(&d).expect("each address")).collect()
}

/// The sale's invoices, oldest first (by date, then payment hash, none first, then address), from
/// its declarations (one per payment hash; one with `rest` gives none) and its newest record at
/// each registry address. Only a confirmed lease gives an address (SPEC.md §31, Leasing an
/// address). One invoice per declaration, with the address of the newest confirmed lease naming its
/// invoice; and one per confirmed lease of an order paid on-chain only. A lease naming an invoice
/// without a declaration is left out: that invoice was never shown.
pub(crate) fn invoices_of(
    reference: &str,
    declarations: &[OpenedDeclaration],
    newest: &[SaleLeaseRecord],
) -> Vec<SaleDeclaration> {
    let confirmed: Vec<&OpenedLease> = newest
        .iter()
        .filter_map(|record| match record {
            SaleLeaseRecord::Lease(lease) if lease.terms.is_confirmed() => Some(&**lease),
            _ => None,
        })
        .collect();
    let mut found: Vec<SaleDeclaration> = Vec::new();
    for declaration in declarations {
        // A rest invoice's: no invoice of the order.
        if declaration.rest.is_some() {
            continue;
        }
        let invoice = ascii_lower(&declaration.invoice);
        let lease = confirmed
            .iter()
            .filter(|lease| lease.terms.invoice.as_deref().is_some_and(|named| ascii_lower(named) == invoice))
            .fold(None::<&OpenedLease>, |best, lease| match best {
                Some(best) if !replaces(&lease.event, &best.event) => Some(best),
                _ => Some(lease),
            });
        let onchain_address = lease.map(|lease| lease.terms.address.clone());
        found.push(SaleDeclaration {
            invoice: DeclaredInvoice {
                reference: reference.to_owned(),
                bolt11: Some(declaration.invoice.clone()),
                payment_hash: Some(declaration.decoded.payment_hash.clone()),
                verify_url: Some(declaration.verify_url.clone()),
                payment_uri: payment_uri(
                    onchain_address.as_deref(),
                    declaration.sats,
                    Some(&declaration.invoice),
                ),
                onchain_address,
                sats: declaration.sats,
                fiat: fiat_of(&declaration.price),
                note: declaration.note.clone(),
                created_at: declaration.decoded.timestamp,
                expires_at: declaration.decoded.expires_at(),
                declared_at: declaration.declared_at,
            },
            event: Some(declaration.event.clone()),
            lease: lease.map(|lease| lease.event.clone()),
        });
    }
    for lease in confirmed {
        if lease.terms.invoice.is_some() {
            continue;
        }
        let terms = &lease.terms;
        found.push(SaleDeclaration {
            invoice: DeclaredInvoice {
                reference: reference.to_owned(),
                bolt11: None,
                payment_hash: None,
                verify_url: None,
                onchain_address: Some(terms.address.clone()),
                payment_uri: payment_uri(Some(&terms.address), terms.sats, None),
                sats: terms.sats,
                fiat: fiat_of(&terms.price),
                note: terms.note.clone(),
                created_at: terms.created_at,
                expires_at: terms.expires_at,
                // Its mark's date (SPEC.md §31, Leasing an address).
                declared_at: lease.event.created_at,
            },
            event: None,
            lease: Some(lease.event.clone()),
        });
    }
    found.sort_by(|a, b| {
        let (a, b) = (&a.invoice, &b.invoice);
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| {
                a.payment_hash.as_deref().unwrap_or("").cmp(b.payment_hash.as_deref().unwrap_or(""))
            })
            .then_with(|| {
                a.onchain_address.as_deref().unwrap_or("").cmp(b.onchain_address.as_deref().unwrap_or(""))
            })
    });
    found
}

/// Step 1 of SPEC.md §21: the indices of the invoices (oldest first) that may still be paid at
/// `now`, until their end and its grace period.
pub(crate) fn may_still_be_paid(invoices: &[DeclaredInvoice], now: i64) -> Vec<usize> {
    invoices
        .iter()
        .enumerate()
        .filter(|(_, invoice)| now < invoice.expires_at + GRACE_SECONDS)
        .map(|(index, _)| index)
        .collect()
}

/// What the check of an order's invoices that may still be paid ends with (SPEC.md §21, step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pending {
    /// The first paid: `order_paid`, whatever the read.
    Paid(usize),
    /// Else the first that failed: its error.
    Failed(usize),
    /// Else, of several, fewer than a majority answered the read on every relay: `network`.
    Unread,
    /// The one handed out.
    HandOut(usize),
}

/// Of the invoices that may still be paid (oldest first, one or more), from the payment check of
/// each and, of several, whether a majority of the relays sent its last record (`held`, read on
/// every relay; `None` when fewer than a majority answered that read): the first paid; else the
/// first error; else, unread; else the one handed out: the only one; of several, the only one
/// held (the one shown), else the newest that received something (unconfirmed, or open with
/// `received` above 0), else the newest.
pub(crate) fn pending_outcome(statuses: &[Result<PaymentStatus, Error>], held: Option<&[bool]>) -> Pending {
    if let Some(paid) = statuses.iter().position(|status| matches!(status, Ok(PaymentStatus::Paid(_)))) {
        return Pending::Paid(paid);
    }
    if let Some(failed) = statuses.iter().position(Result::is_err) {
        return Pending::Failed(failed);
    }
    if statuses.len() == 1 {
        return Pending::HandOut(0);
    }
    let Some(held) = held else {
        return Pending::Unread;
    };
    let shown: Vec<usize> =
        held.iter().enumerate().filter(|(_, held)| **held).map(|(index, _)| index).collect();
    if let [only] = shown.as_slice() {
        return Pending::HandOut(*only);
    }
    let received = statuses.iter().rposition(|status| {
        matches!(
            status,
            Ok(PaymentStatus::Unconfirmed { .. }) | Ok(PaymentStatus::Open { received: 1.., .. })
        )
    });
    Pending::HandOut(received.unwrap_or(statuses.len() - 1))
}
