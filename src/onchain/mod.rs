//! On-chain payments (SPEC.md §31): deposit addresses, the lot, leases, witnesses, the explorer
//! (mempool.space, or the merchant's Bitcoin node), the on-chain part of a payment, the rest of an
//! underpayment, the merchant's acceptance, acceptance records, the explorer's WebSocket.

pub(crate) mod acceptance;
pub(crate) mod address;
pub(crate) mod explorer;
pub(crate) mod lease;
pub(crate) mod lot;
pub(crate) mod merchant_acceptance;
pub(crate) mod methods;
pub(crate) mod node;
pub(crate) mod payment;
pub(crate) mod replacements;
pub(crate) mod rest;
pub(crate) mod tolerance;
pub(crate) mod watch;
pub(crate) mod witness;
