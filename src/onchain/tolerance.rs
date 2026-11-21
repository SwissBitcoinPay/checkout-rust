//! The merchant's tolerance of on-chain underpayments (SPEC.md §31, The merchant's tolerance):
//! the share of an order's amount its payment in time may miss and still pay it, in basis points.
//! The channel gives it, an order's lease keeps the one of its creation: every check of the order
//! judges its payment with that one, as the merchant's app does. It is never written where the
//! shop's page or the customer reads (an Invoice, a PaymentStatus, a checkout link's record, an
//! error, a log): a customer who knew it could pay that much less on purpose.

use crate::json::Json;
use crate::protocol::{MAX_TOLERANCE, TOLERANCE_SCALE};

/// A tolerance as a channel or a lease writes it: an integer from 0 to 1000, else (absent, a
/// fraction, a string, a negative number, above 1000) 0.
pub(crate) fn tolerance_of(value: Option<&Json>) -> u64 {
    value
        .and_then(Json::as_integer)
        .filter(|tolerance| (0.0..=MAX_TOLERANCE as f64).contains(tolerance))
        .map_or(0, |tolerance| tolerance as u64)
}

/// The least accepted of `sats` with `tolerance`: `sats − floor(sats × tolerance / 10000)`, so that
/// the merchant never accepts more missing than its tolerance. On integers.
pub(crate) fn least_accepted(sats: u64, tolerance: u64) -> u64 {
    let tolerance = tolerance.min(MAX_TOLERANCE);
    sats - (u128::from(sats) * u128::from(tolerance) / u128::from(TOLERANCE_SCALE)) as u64
}

/// What is due on-chain of an invoice of `sats` with `tolerance`, its rest invoices having paid
/// `paid_by_rests`, with the `received` of the merchant's acceptance that counts,
/// `merchant_accepted` (`None` without one: merchant_acceptance.rs) (SPEC.md §31, The on-chain
/// payment, step 4): nothing when they paid `sats` or more; else max(1, min(L, M) − R), L the
/// least accepted, M the merchant's acceptance's `received` (`sats` without one), R what they
/// paid. R is taken once from the lesser: M counts the rest invoices paid when the merchant
/// accepted, as L counts every payment. At least 1 sat: something must count on-chain for the
/// tolerance or the merchant's acceptance to apply.
pub(crate) fn due_onchain(
    sats: u64,
    tolerance: u64,
    paid_by_rests: u64,
    merchant_accepted: Option<u64>,
) -> u64 {
    if paid_by_rests >= sats {
        return 0;
    }
    let least = least_accepted(sats, tolerance);
    let accepted = merchant_accepted.map_or(least, |accepted| accepted.min(least));
    accepted.saturating_sub(paid_by_rests).max(1)
}
