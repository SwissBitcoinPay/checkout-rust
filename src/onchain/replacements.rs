//! Replacements (SPEC.md §31, Replacements): a payer whose transaction is slow to confirm may
//! broadcast another one in its place (RBF), which spends a coin of the same. A replacement keeps
//! the time of the payment it replaces, for at most what that payment paid the address: what it
//! pays more counts at its own time, as any other payment would.

use std::collections::{HashMap, HashSet};

/// A transaction paying the address, as the parts are made of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaymentTx {
    pub(crate) txid: String,
    /// What it pays the address.
    pub(crate) sats: u64,
    /// The coins it spends (`<txid>:<vout>`), or those recorded of it.
    pub(crate) inputs: Vec<String>,
    /// When it was seen (a witness's `created_at`); `None`: unknown, after every known one.
    pub(crate) order: Option<i64>,
    /// Whether the explorer lists it now.
    pub(crate) listed: bool,
}

/// A part of a listed transaction: sats it pays as its `root` (itself, for a part of its own).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Part {
    pub(crate) sats: u64,
    pub(crate) root: String,
}

/// The parts of each listed transaction, by txid: a txid given twice is taken once (its first
/// entry); the transactions in order (unknown last, then by txid); the roots of each are those
/// before it that spend one of its coins (their roots, put together), else itself; each root
/// gives at most its sats, in that order, then what a transaction still pays is a part of its own.
pub(crate) fn payment_parts(txs: &[PaymentTx]) -> HashMap<String, Vec<Part>> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut sorted: Vec<&PaymentTx> = txs.iter().filter(|tx| seen.insert(tx.txid.as_str())).collect();
    sorted.sort_by(|a, b| match (a.order, b.order) {
        (Some(x), Some(y)) if x != y => x.cmp(&y),
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        _ => a.txid.cmp(&b.txid),
    });
    let mut roots: Vec<Vec<usize>> = Vec::with_capacity(sorted.len());
    for (index, tx) in sorted.iter().enumerate() {
        let coins: HashSet<&str> = tx.inputs.iter().map(String::as_str).collect();
        let before: Vec<usize> = (0..index)
            .filter(|&other| sorted[other].inputs.iter().any(|coin| coins.contains(coin.as_str())))
            .collect();
        if before.is_empty() {
            roots.push(vec![index]);
            continue;
        }
        let mut together: Vec<usize> = Vec::new();
        for other in before {
            for &root in &roots[other] {
                if !together.contains(&root) {
                    together.push(root);
                }
            }
        }
        // In the order of step 1: their positions.
        together.sort_unstable();
        roots.push(together);
    }
    let mut to_give: Vec<u64> = sorted.iter().map(|tx| tx.sats).collect();
    let mut parts: HashMap<String, Vec<Part>> = HashMap::new();
    for (index, tx) in sorted.iter().enumerate() {
        if !tx.listed {
            continue;
        }
        let own = &roots[index];
        let mut owed = tx.sats;
        let mut list = Vec::new();
        if own.len() == 1 && own[0] == index {
            // A payment of its own: all its sats, which it no longer has to give.
            to_give[index] = 0;
        } else {
            for &root in own {
                let take = owed.min(to_give[root]);
                if take > 0 {
                    list.push(Part { sats: take, root: sorted[root].txid.clone() });
                    to_give[root] -= take;
                    owed -= take;
                }
            }
        }
        if owed > 0 {
            list.push(Part { sats: owed, root: tx.txid.clone() });
        }
        parts.insert(tx.txid.clone(), list);
    }
    parts
}
