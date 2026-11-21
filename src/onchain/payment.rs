//! The payment of an invoice (SPEC.md §31, The on-chain payment): its on-chain part, from the
//! explorer and the witnesses of its order, its rest part (the Lightning invoices of the rest of
//! an underpayment), and how they combine with its Lightning part.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use crate::error::{Error, ErrorCode};
use crate::http::Http;
use crate::lnurl::LightningPart;
use crate::model::{Payment, PaymentStatus};
use crate::onchain::explorer::{
    Explorer, ExplorerTx, address_transactions, chain_height, confirmations_of, pays_to, received_at,
};
use crate::onchain::merchant_acceptance::MerchantAcceptance;
use crate::onchain::replacements::{Part, PaymentTx, payment_parts};
use crate::onchain::rest::{RestInvoice, by_rest_order, rest_of};
use crate::onchain::tolerance::due_onchain;
use crate::onchain::witness::{OrderWitnesses, Witness};
use crate::protocol::{CONFIRMATIONS, GRACE_SECONDS, MAX_WITNESS_INPUTS};
use crate::runtime::{Clock, Logger, seconds};
use crate::transport::BoxFuture;

/// A part's outcome: its result, or the error it failed with.
pub(crate) type Settled<T> = Result<T, Error>;

/// The on-chain part of an invoice with an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OnchainPart {
    /// Less than due came in time: final once the lease ended and nothing is undecided.
    Underpaid {
        received: u64,
        is_final: bool,
    },
    Unconfirmed {
        received: u64,
        confirmations: u64,
        txids: Vec<String>,
    },
    /// 3 confirmations on the explorer read.
    Paid {
        received: u64,
        txids: Vec<String>,
    },
}

impl OnchainPart {
    pub(crate) fn received(&self) -> u64 {
        match self {
            Self::Underpaid { received, .. }
            | Self::Unconfirmed { received, .. }
            | Self::Paid { received, .. } => *received,
        }
    }
}

/// What the on-chain part reads and writes on the relays: the order's witnesses, their
/// publication, and the merchant's acceptance of the invoice.
pub(crate) trait Witnesses: Sync {
    /// The witnesses of the invoice (`network` when fewer than a majority answered); on every
    /// relay with `every_relay`.
    fn read(&self, every_relay: bool) -> BoxFuture<'_, Result<OrderWitnesses, Error>>;
    /// The merchant's acceptance of the invoice (merchant_acceptance.rs), read on every relay
    /// (`network` when fewer than a majority answered).
    fn merchant_acceptance(&self) -> BoxFuture<'_, Result<MerchantAcceptance, Error>>;
    /// The witness address of `txid` paying the address for the sale, or for none (`None`).
    fn witness_address(&self, txid: &str, sale: Option<&str>) -> String;
    /// Publishes a witness on a majority of the merchant's relays, else `network`.
    fn publish<'a>(&'a self, witness: &'a Witness) -> BoxFuture<'a, Result<(), Error>>;
}

/// What the on-chain part of an invoice needs.
pub(crate) struct OnchainCheck<'a> {
    /// The invoice's deposit address, its amount and its end.
    pub(crate) address: &'a str,
    pub(crate) sats: u64,
    pub(crate) expires_at: i64,
    /// The order's sale: its author (hex).
    pub(crate) sale: &'a str,
    /// The server's clock: read once the explorer answered (a transaction it lists was broadcast
    /// by then), never before.
    pub(crate) clock: &'a dyn Clock,
    /// The explorer (explorer.rs): mempool.space, or the merchant's Bitcoin node with its
    /// fallback. The address's transactions and the chain's height are one read of it, both of one
    /// explorer.
    pub(crate) explorer: &'a Explorer,
    /// For the explorer and BlockCypher.
    pub(crate) http: &'a Http,
    pub(crate) witnesses: &'a dyn Witnesses,
    pub(crate) logger: &'a dyn Logger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    InTime,
    Replacement,
    Late,
    Undecided,
    Anothers,
}

/// The parts of the transactions paying the address (SPEC.md §31, step 2): from the witnesses of
/// this invoice and of other invoices (in the order they were seen), then the transactions no such
/// witness names (their order unknown).
fn parts_of(
    read: &OrderWitnesses,
    paying: &[(ExplorerTx, u64)],
    listed: &HashSet<String>,
) -> HashMap<String, Vec<Part>> {
    let mut txs: Vec<PaymentTx> = read
        .sale
        .iter()
        .chain(read.others.iter())
        .map(|(txid, witness)| PaymentTx {
            txid: txid.clone(),
            sats: witness.sats,
            inputs: witness.inputs.clone(),
            order: Some(witness.seen_at),
            listed: listed.contains(txid),
        })
        .collect();
    txs.extend(
        paying.iter().filter(|(tx, _)| read.of_sale(&tx.txid).is_none() && !read.of_others(&tx.txid)).map(
            |(tx, pays)| PaymentTx {
                txid: tx.txid.clone(),
                sats: *pays,
                inputs: tx.coins.clone(),
                order: None,
                listed: true,
            },
        ),
    );
    payment_parts(&txs)
}

/// Another invoice's: a witness of another invoice names it, or the root of one of its parts.
fn anothers(read: &OrderWitnesses, parts: &HashMap<String, Vec<Part>>, txid: &str) -> bool {
    read.of_others(txid)
        || parts.get(txid).is_some_and(|parts| parts.iter().any(|part| read.of_others(&part.root)))
}

/// The on-chain part of an invoice (SPEC.md §31, The on-chain payment), checked at the time the
/// explorer answered: each transaction paying its address in time (while the lease ran, as a
/// witness of the sale or BlockCypher's time says), a replacement of payments in time, late,
/// undecided or another invoice's; what counts of them; and, once enough counts, their
/// confirmations on the explorer read: paid at 3. Publishes the witnesses it finds (of the sale on a majority,
/// else `network`; of none for the merchant's app only, a failure logged), never over a witness
/// of a newer format. The merchant's acceptance is read with the witnesses, on every relay. What
/// is due on-chain is the least the order's `tolerance` accepts of the amount (the amount without
/// one), or the `received` of the merchant's acceptance a majority of the relays sent when less,
/// less what its rest invoices paid (`paid_by_rests`), a sat at least (`due_onchain`): the
/// tolerance and what the rest invoices paid are awaited only then, so that they are read
/// meanwhile. `network` when the explorer (with its fallback), BlockCypher or the relays fail.
pub(crate) async fn check_onchain_part(
    check: &OnchainCheck<'_>,
    paid_by_rests: impl Future<Output = u64>,
    tolerance: impl Future<Output = u64>,
) -> Result<OnchainPart, Error> {
    let OnchainCheck { address, sats, http, sale, .. } = *check;
    let end = check.expires_at + GRACE_SECONDS;
    // One read, of one explorer: a transaction's confirmations compare its block's height with
    // that explorer's height. Either failing, both are asked of the next explorer (SPEC.md §31).
    let (txs, height) = check
        .explorer
        .read(|at| async move {
            tokio::try_join!(address_transactions(&at, address, http), chain_height(&at, http))
        })
        .await?;
    // Now, once the explorer answered: what it lists was broadcast by now (step 3.4).
    let now = seconds(check.clock);
    let mut paying: Vec<(ExplorerTx, u64)> = Vec::new();
    for tx in txs {
        let pays = pays_to(&tx, address);
        if pays > 0 && !paying.iter().any(|(other, _)| other.txid == tx.txid) {
            paying.push((tx, pays));
        }
    }
    // The witnesses, and the merchant's acceptance with them (on every relay), when some
    // transaction pays the address.
    let (witnesses, accepted) = if paying.is_empty() {
        (OrderWitnesses::default(), MerchantAcceptance::default())
    } else {
        tokio::try_join!(check.witnesses.read(false), check.witnesses.merchant_acceptance())?
    };
    // A witness of a newer format, logged once per check (SPEC.md §12).
    let newer_witness = || {
        check.logger.warn(
            "sattleme-checkout: a witness of a payment of this order has a newer format than this version reads; update the crate",
        );
    };
    if !witnesses.newer.is_empty() {
        newer_witness();
    }
    if accepted.newer {
        check.logger.warn(
            "sattleme-checkout: a merchant's acceptance of this order has a newer format than this version reads; update the crate",
        );
    }
    let listed: HashSet<String> = paying.iter().map(|(tx, _)| tx.txid.clone()).collect();
    let parts = parts_of(&witnesses, &paying, &listed);

    let newer_names =
        |txid: &str| witnesses.newer.contains(&check.witnesses.witness_address(txid, Some(sale)));
    // A witness of a newer format that names no transaction listed may be of a payment replaced.
    let newer_elsewhere = witnesses.newer.iter().any(|d| {
        !paying.iter().any(|(tx, _)| {
            *d == check.witnesses.witness_address(&tx.txid, Some(sale))
                || *d == check.witnesses.witness_address(&tx.txid, None)
        })
    });

    let mut kinds: HashMap<String, Kind> = HashMap::new();
    // Witnesses of the sale to publish (on a majority), and of none (logged when they fail).
    let mut of_sale: Vec<Witness> = Vec::new();
    let mut of_none: Vec<Witness> = Vec::new();
    let witness_of = |tx: &ExplorerTx, pays: u64, for_sale: bool, replacement: bool| Witness {
        address: address.to_owned(),
        txid: tx.txid.clone(),
        sale: for_sale.then(|| sale.to_owned()),
        sats: pays,
        inputs: tx.coins.iter().take(MAX_WITNESS_INPUTS).cloned().collect(),
        replacement,
        expires_at: for_sale.then_some(check.expires_at),
    };
    for (tx, pays) in &paying {
        let txid = tx.txid.as_str();
        // Another invoice's: a transaction counts for one invoice at most.
        if anothers(&witnesses, &parts, txid) {
            kinds.insert(txid.to_owned(), Kind::Anothers);
            continue;
        }
        let witness = witnesses.of_sale(txid);
        if witness.is_some_and(|witness| !witness.replacement) {
            kinds.insert(txid.to_owned(), Kind::InTime);
            continue;
        }
        if newer_names(txid) {
            kinds.insert(txid.to_owned(), Kind::Undecided);
            continue;
        }
        if now <= end {
            // Listed now, it was broadcast by now: while the lease runs.
            kinds.insert(txid.to_owned(), Kind::InTime);
            of_sale.push(witness_of(tx, *pays, true, false));
            continue;
        }
        if witness.is_some() {
            // An earlier check found it a replacement, and BlockCypher's time of it late.
            kinds.insert(txid.to_owned(), Kind::Replacement);
            continue;
        }
        // No check saw it in time.
        let own = &parts[txid];
        let replaces = own.iter().any(|part| part.root != txid);
        if own.iter().any(|part| part.root == txid)
            && let Some(time) = received_at(txid, http).await?
            && time <= end * 1000
        {
            kinds.insert(txid.to_owned(), Kind::InTime);
            of_sale.push(witness_of(tx, *pays, true, false));
            continue;
        }
        if newer_elsewhere {
            kinds.insert(txid.to_owned(), Kind::Undecided);
        } else if replaces {
            kinds.insert(txid.to_owned(), Kind::Replacement);
            of_sale.push(witness_of(tx, *pays, true, true));
        } else {
            // Its payment reaches the merchant's wallet, but no order. Its witness none, unless one
            // names it already, or one of a newer format holds its address: never written over.
            kinds.insert(txid.to_owned(), Kind::Late);
            if !witnesses.none.contains(txid)
                && !witnesses.newer.contains(&check.witnesses.witness_address(txid, None))
            {
                of_none.push(witness_of(tx, *pays, false, false));
            }
        }
    }
    let sale_publications =
        futures_util::future::join_all(of_sale.iter().map(|witness| check.witnesses.publish(witness)));
    let none_publications = futures_util::future::join_all(of_none.iter().map(|witness| async move {
        if let Err(error) = check.witnesses.publish(witness).await {
            if error.code() != ErrorCode::Network {
                return Err(error);
            }
            check.logger.warn(&format!(
                "sattleme-checkout: the witness of a late payment was not published: {}",
                error.message()
            ));
        }
        Ok(())
    }));
    let (sale_results, none_results) = tokio::join!(sale_publications, none_publications);
    for result in sale_results.into_iter().chain(none_results) {
        result?;
    }
    // Its witnesses on a majority, read again on every relay: of two checks that publish witnesses
    // of one transaction at once, the later reader sees both, whatever one relay hides.
    if !of_sale.is_empty() {
        let again = check.witnesses.read(true).await?;
        if witnesses.newer.is_empty() && !again.newer.is_empty() {
            newer_witness();
        }
        let parts_again = parts_of(&again, &paying, &listed);
        for (tx, _) in &paying {
            if anothers(&again, &parts_again, &tx.txid) {
                kinds.insert(tx.txid.clone(), Kind::Anothers);
            }
        }
    }

    let in_time = |root: &str| {
        if listed.contains(root) {
            kinds.get(root) == Some(&Kind::InTime)
        } else {
            witnesses.of_sale(root).is_some_and(|witness| !witness.replacement)
        }
    };
    let mut counted: HashMap<String, u64> = HashMap::new();
    for (tx, _) in &paying {
        if matches!(kinds.get(&tx.txid), Some(Kind::Undecided | Kind::Anothers)) {
            continue;
        }
        let sum: u64 = parts[&tx.txid].iter().filter(|part| in_time(&part.root)).map(|part| part.sats).sum();
        if sum > 0 {
            counted.insert(tx.txid.clone(), sum);
        }
    }
    // What each transaction counts is at most what it pays the address, every bitcoin at most
    // (`parse_transaction`), and an answer of 1 MiB lists 4 619 transactions at most (226 bytes
    // each, the fewest): 9.7 × 10^18 sats in all, below u64::MAX (1.8 × 10^19). These sums never
    // wrap.
    let received: u64 = counted.values().sum();
    let (paid_by_rests, tolerance) = tokio::join!(paid_by_rests, tolerance);
    // Nothing due when the rest invoices paid it all; else the least the order's tolerance
    // accepts, or what the merchant accepted when less, less what they paid, at least a sat.
    let due = due_onchain(sats, tolerance, paid_by_rests, accepted.received);
    if due == 0 {
        return Ok(OnchainPart::Paid { received, txids: Vec::new() });
    }
    if received < due {
        let undecided = kinds.values().any(|kind| *kind == Kind::Undecided);
        return Ok(OnchainPart::Underpaid { received, is_final: now > end && !undecided });
    }
    let order: Vec<&ExplorerTx> =
        paying.iter().map(|(tx, _)| tx).filter(|tx| counted.contains_key(&tx.txid)).collect();
    let txids: Vec<String> = order.iter().map(|tx| tx.txid.clone()).collect();
    let confirmations = order.iter().map(|tx| confirmations_of(tx, height)).min().unwrap_or(0);
    if confirmations >= CONFIRMATIONS {
        return Ok(OnchainPart::Paid { received, txids });
    }
    Ok(OnchainPart::Unconfirmed { received, confirmations, txids })
}

/// The rest part of an invoice: its rest invoices, and the Lightning part of each, in order.
#[derive(Clone, Debug, Default)]
pub(crate) struct RestPart {
    pub(crate) invoices: Vec<RestInvoice>,
    pub(crate) results: Vec<Settled<LightningPart>>,
    /// The sale's records could not be read: whether a rest invoice was paid cannot be told.
    pub(crate) error: Option<Error>,
    /// The payment hashes of the rest invoices whose rest record is not known on a majority of
    /// the relays: never the status's `bolt11`.
    pub(crate) unrecorded: HashSet<String>,
}

/// What the rest invoices of a rest part paid.
#[derive(Debug, Default)]
pub(crate) struct RestSummary {
    /// Each payment hash once; one that failed counts as not paid.
    pub(crate) paid: u64,
    /// The preimages of those paid, in the order of the rest invoices.
    pub(crate) preimages: Vec<String>,
    pub(crate) hashes: HashSet<String>,
    /// Whether each is final.
    pub(crate) is_final: bool,
    /// The first error.
    pub(crate) error: Option<Error>,
}

/// What the rest invoices of `rests` paid, their preimages in order, whether each is final, and
/// the first error.
pub(crate) fn rest_summary(rests: Option<&RestPart>) -> RestSummary {
    let mut summary = RestSummary { is_final: true, ..RestSummary::default() };
    let Some(rests) = rests else {
        return summary;
    };
    if let Some(error) = &rests.error {
        summary.is_final = false;
        summary.error = Some(error.clone());
    }
    // In the order of the rest invoices (by date, then payment hash), whatever the order given.
    let mut order: Vec<(&RestInvoice, &Settled<LightningPart>)> =
        rests.invoices.iter().zip(rests.results.iter()).collect();
    order.sort_by(|a, b| by_rest_order(a.0, b.0));
    for (invoice, result) in order {
        match result {
            Err(error) => {
                summary.is_final = false;
                summary.error.get_or_insert_with(|| error.clone());
            }
            Ok(LightningPart::Paid(preimage)) => {
                if summary.hashes.insert(invoice.payment_hash.clone()) {
                    summary.paid += invoice.sats;
                    summary.preimages.push(preimage.clone());
                }
            }
            Ok(LightningPart::Open) => summary.is_final = false,
            Ok(LightningPart::Expired) => {}
        }
    }
    summary
}

/// What an invoice is, for its status: its amount, its end and its address.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InvoiceTerms<'a> {
    pub(crate) sats: u64,
    pub(crate) expires_at: i64,
    pub(crate) address: Option<&'a str>,
}

/// The status of an invoice from its parts (SPEC.md §31): paid in Lightning, else paid by its
/// rest invoices alone, else paid on-chain (mixed when rest invoices paid part of it), else
/// unconfirmed on-chain, else an error of a part (the Lightning part's first, then the rest
/// part's, then the on-chain part's), else expired once every part is final, else open, with its
/// rest. A part is `None` when the invoice has none (no Lightning invoice, no address).
pub(crate) fn combine_parts(
    invoice: InvoiceTerms<'_>,
    now: i64,
    lightning: Option<&Settled<LightningPart>>,
    onchain: Option<&Settled<OnchainPart>>,
    rests: Option<&RestPart>,
) -> Result<PaymentStatus, Error> {
    if let Some(Ok(LightningPart::Paid(preimage))) = lightning {
        return Ok(PaymentStatus::Paid(Payment::Lightning { preimage: preimage.clone() }));
    }
    let summary = rest_summary(rests);
    let onchain_ok = onchain.and_then(|part| part.as_ref().ok());
    if summary.paid >= invoice.sats {
        // What came on-chain in time counts too (0 when the on-chain part failed).
        let onchain_received = onchain_ok.map_or(0, OnchainPart::received);
        return Ok(PaymentStatus::Paid(Payment::Mixed {
            received: onchain_received + summary.paid,
            txids: Vec::new(),
            preimages: summary.preimages,
        }));
    }
    match onchain_ok {
        Some(OnchainPart::Paid { received, txids }) => {
            let received = received + summary.paid;
            return Ok(PaymentStatus::Paid(if summary.paid > 0 {
                Payment::Mixed { received, txids: txids.clone(), preimages: summary.preimages }
            } else {
                Payment::Onchain { received, txids: txids.clone() }
            }));
        }
        Some(OnchainPart::Unconfirmed { received, confirmations, txids }) => {
            return Ok(PaymentStatus::Unconfirmed {
                received: received + summary.paid,
                confirmations: *confirmations,
                txids: txids.clone(),
            });
        }
        _ => {}
    }
    if let Some(Err(error)) = lightning {
        return Err(error.clone());
    }
    if let Some(error) = summary.error {
        return Err(error);
    }
    if let Some(Err(error)) = onchain {
        return Err(error.clone());
    }
    let underpaid = match onchain_ok {
        Some(OnchainPart::Underpaid { received, is_final }) => Some((*received, *is_final)),
        _ => None,
    };
    let received = underpaid.map_or(0, |(received, _)| received) + summary.paid;
    let lightning_final = matches!(lightning, None | Some(Ok(LightningPart::Expired)));
    let onchain_final = onchain.is_none() || underpaid.is_some_and(|(_, is_final)| is_final);
    if lightning_final && onchain_final && summary.is_final {
        return Ok(PaymentStatus::Expired { received });
    }
    let rest = invoice.address.and_then(|address| {
        let shown: Vec<&RestInvoice> = rests
            .map(|rests| {
                rests
                    .invoices
                    .iter()
                    .filter(|invoice| !rests.unrecorded.contains(&invoice.payment_hash))
                    .collect()
            })
            .unwrap_or_default();
        rest_of(invoice.sats, invoice.expires_at, address, received, now, &shown, &summary.hashes)
    });
    Ok(PaymentStatus::Open { expires_at: invoice.expires_at, received, rest })
}
