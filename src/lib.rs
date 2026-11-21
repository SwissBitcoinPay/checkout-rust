//! Take Lightning and on-chain payments for a [sattle.me](https://sattle.me) merchant from an
//! online shop's **server**: the invoice of each order (a Lightning invoice, a deposit address of
//! the merchant's wallet, or both), its declaration in the merchant's registry, and the check of
//! its payment.
//!
//! - Everything runs on the server, which holds the integration's secret key (`sattleme_ck_…`).
//!   The customer's browser only ever gets the invoice and its address: on the shop's page, or on
//!   the merchant's web app through a checkout link.
//! - Payments go straight to the merchant's wallet. sattle.me runs no server and no API for
//!   integrations: the crate talks to the merchant's Lightning address, to the merchant's Nostr
//!   relays and, for on-chain payments, to one block explorer (mempool.space, or the merchant's own
//!   Bitcoin node when its app names one) and BlockCypher (and to the rate source chosen, for
//!   prices in a currency).
//! - Amounts are exact integers (sats, a currency's minor units), never floating-point; in JSON,
//!   strings of digits.
//!
//! The protocol is [sattleme/checkout-spec](https://github.com/sattleme/checkout-spec)'s
//! `SPEC.md`: the crate passes its conformance vectors, and the invoices it stores are the JSON
//! every implementation reads ([`Invoice::to_json`], [`InvoiceToCheck::from_json`]).
//!
//! # Quick start
//!
//! ```no_run
//! use sattleme_checkout::{Client, ErrorCode, InvoiceToCheck, Order, PaymentStatus};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Nothing to connect nor to close: each call reads the merchant, opens one connection per
//! // relay and closes it when it is done.
//! let client = Client::new(std::env::var("SATTLEME_INTEGRATION_KEY")?)?;
//!
//! // When the customer checks out: the order's invoice, stored with the order as JSON.
//! let order = Order::sats("ORD-1042", 49_000).duration_seconds(900).note("Order 1042");
//! let stored = match client.create_invoice(&order).await {
//!     Ok(invoice) => invoice.to_json(),
//!     // An invoice of this order may still be paid (say, after a crash): keep that one.
//!     Err(error) if error.code() == ErrorCode::InvoicePending => {
//!         error.invoice().expect("invoice_pending carries the invoice").to_json()
//!     }
//!     Err(error) => return Err(error.into()),
//! };
//!
//! // When the payment page asks for the order's status (every 1 to 2 seconds):
//! match client.get_status(InvoiceToCheck::from_json(&stored)?).await? {
//!     // Mark the order paid, keeping the payment: its preimage, or its transactions.
//!     PaymentStatus::Paid(payment) => println!("Paid: {payment:?}"),
//!     PaymentStatus::Expired { .. } => { /* never paid: the order may get a new invoice */ }
//!     _ => { /* open, or unconfirmed on-chain: ask again */ }
//! }
//! # Ok(())
//! # }
//! # fn main() { let _ = example(); }
//! ```
//!
//! # Cancellation
//!
//! A call is cancelled by dropping its future (a timeout, a `select!`, an aborted task): it stops
//! at once, nothing it started runs on, and it gives no [`Error`]. Every call's future is `Send`,
//! and `'static` once it owns what it borrows: it can be spawned.
//!
//! # Errors
//!
//! Every failure is an [`Error`]: a stable [`ErrorCode`], whether the same call may succeed later
//! ([`Error::retryable`]), and what its code carries ([`Error::param`], [`Error::invoice`]…).
//! None ever holds a secret.

#![doc(test(attr(deny(warnings))))]

pub(crate) mod channel;
pub(crate) mod checkout;
pub(crate) mod client;
pub(crate) mod currencies;
pub(crate) mod declaration;
pub(crate) mod derive;
pub(crate) mod encoding;
pub(crate) mod error;
pub(crate) mod http;
pub(crate) mod json;
pub(crate) mod key;
pub(crate) mod lightning;
pub(crate) mod lnurl;
pub(crate) mod model;
pub(crate) mod nostr;
pub(crate) mod onchain;
pub(crate) mod order;
pub(crate) mod protocol;
pub(crate) mod rates;
pub(crate) mod relays;
pub(crate) mod runtime;
pub(crate) mod sales;
pub(crate) mod secp;
pub(crate) mod secret;
pub(crate) mod text;
pub(crate) mod transport;
pub(crate) mod urls;
pub(crate) mod web;
pub(crate) mod websocket;

pub use client::{Client, ClientBuilder, WaitOptions};
pub use currencies::currency_digits;
pub use error::{Error, ErrorCode};
pub use http::{HttpBody, HttpClient, HttpRequest, HttpResponse};
pub use model::{
    DeclaredInvoice, Fiat, Invoice, InvoiceToCheck, Merchant, Payment, PaymentStatus, RateInfo, Rest,
};
pub use order::Order;
pub use rates::{CustomPrice, CustomRateError, CustomRateSource, RateSource};
pub use runtime::{Clock, LogLogger, Logger, OsRandom, Random, SystemClock};
pub use transport::{BoxFuture, TransportError};
pub use websocket::{WebSocketClient, WebSocketConnection, WebSocketRequest};
#[cfg(test)]
mod tests;
