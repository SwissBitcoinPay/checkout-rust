//! The methods of an order by its amount (SPEC.md §31, Methods by amount): Lightning when the
//! amount is within the Lightning address's sendable sats, on-chain from 1 000 sats when an
//! address can be leased. Nothing is repaired: an amount is never split between the two, nor
//! moved into the sendable sats.

use crate::error::Error;
use crate::protocol::ONCHAIN_FLOOR_SATS;

/// The methods of an order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Methods {
    pub(crate) lightning: bool,
    pub(crate) onchain: bool,
}

/// The methods `sats` may be paid with, before an address is leased: `invalid_order` (`param`,
/// `sats` or `fiat`) below 1 000 sats and outside the sendable sats.
pub(crate) fn payment_methods(
    sats: u64,
    sendable: (u64, u64),
    param: &'static str,
) -> Result<Methods, Error> {
    let lightning = sats >= sendable.0 && sats <= sendable.1;
    let onchain = sats >= ONCHAIN_FLOOR_SATS;
    if !lightning && !onchain {
        return Err(Error::invalid_order(
            param,
            &format!("{sats} sats is outside the merchant's bounds ({} to {} sats)", sendable.0, sendable.1),
        ));
    }
    Ok(Methods { lightning, onchain })
}

/// What leasing an address gave: one, none, or the explorer's failure.
#[derive(Debug)]
pub(crate) enum LeaseOutcome {
    Leased,
    None,
    ExplorerFailed(Error),
}

/// The methods once leasing an address gave `outcome`: without an address, Lightning only; an
/// order that can only be paid on-chain then fails with `onchain_unavailable`, or the explorer's
/// `network`.
pub(crate) fn methods_with(methods: Methods, outcome: LeaseOutcome) -> Result<Methods, Error> {
    if !methods.onchain || matches!(outcome, LeaseOutcome::Leased) {
        return Ok(methods);
    }
    if !methods.lightning {
        return Err(match outcome {
            LeaseOutcome::ExplorerFailed(error) => error,
            _ => Error::onchain_unavailable(),
        });
    }
    Ok(Methods { lightning: true, onchain: false })
}
