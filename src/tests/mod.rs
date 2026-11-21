//! The crate's tests: the conformance vectors of the pinned specification, the official NIP-44
//! vectors, the app's vectors, and the integration tests of PORTING.md "Steps" 5 against local
//! relays and fakes, mirroring checkout-node's test files one for one.

mod support;

mod app_vector;
mod bitcoin_node;
mod bitcoin_nodes_vectors;
mod channel;
mod checkout;
mod checkout_rest_vector;
mod checkout_vector;
mod conformance;
mod declaration;
mod hardening;
mod invoice;
mod json;
mod key;
mod lifetime;
mod merchant_acceptance;
mod nip44;
mod onchain;
mod onchain_security;
mod onchain_security_review;
mod onchain_vectors;
mod payment;
mod rates;
mod relay_reads;
mod rest;
mod rest_vectors;
mod spec_pin;
mod tolerance;
mod transport;
mod watch;
