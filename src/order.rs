//! What a caller gives, checked before any request (SPEC.md §17, §22): an order, a stored
//! invoice. Refused, never repaired.

use crate::checkout::redirect_shown;
use crate::error::Error;
use crate::lightning::bolt11;
use crate::lnurl::LightningInvoice;
use crate::model::{Fiat, InvoiceToCheck};
use crate::onchain::address::is_deposit_address;
use crate::protocol::{
    DEFAULT_DURATION_SECONDS, MAX_DURATION_SECONDS, MAX_NOTE_LENGTH, MAX_REF_LENGTH, MAX_SAFE_INTEGER,
    MAX_SATS, MIN_DURATION_SECONDS, REF_RULE,
};
use crate::rates::{RATE_SOURCE_RULE, RateSource, parse_fiat, rate_source_list};
use crate::text::{code_point_len, has_control_character, is_hex32};
use crate::urls::parse_https_url;

/// The amount of an order: in sats, or a price in a currency.
#[derive(Clone, Debug)]
enum Amount {
    Sats(u64),
    Fiat { amount: String, currency: String },
}

/// An order, for [`Client::create_invoice`]: its reference, and its amount in sats or a price in
/// a currency; optionally its rate sources, its duration, its note and a checkout link.
///
/// ```
/// use sattleme_checkout::Order;
///
/// let in_sats = Order::sats("ORD-1042", 49_000).note("Order 1042");
/// let in_francs = Order::fiat("ORD-1043", "24.50", "CHF").duration_seconds(600);
/// let with_link = Order::sats("ORD-1044", 21_000)
///     .checkout(true)
///     .redirect_url("https://shop.example/orders/1044/thanks");
/// # let _ = (in_sats, in_francs, with_link);
/// ```
///
/// Nothing is checked until `create_invoice`, which refuses an invalid order with
/// `invalid_order` naming its parameter, before any request.
///
/// [`Client::create_invoice`]: crate::Client::create_invoice
#[derive(Clone, Debug)]
pub struct Order {
    reference: String,
    amount: Amount,
    rate_sources: Option<Vec<RateSource>>,
    duration_seconds: Option<u64>,
    note: Option<String>,
    checkout: bool,
    redirect_url: Option<String>,
}

impl Order {
    /// An order of `sats` (1 to 2 100 000 000 000 000). `reference`: 1 to 64 characters
    /// `A–Z a–z 0–9 . _ : -`; one order, one sale: never reused for another order by anything that
    /// holds the key, never taken from what the customer sends.
    pub fn sats(reference: impl Into<String>, sats: u64) -> Self {
        Self::of(reference.into(), Amount::Sats(sats))
    }

    /// An order priced in a currency: `amount` its price as written (`"24.50"`: digits and an
    /// optional fraction, never a float), `currency` an upper-case ISO 4217 code of the
    /// specification's table (`"CHF"`). Converted to sats at the rate of the order's sources, else
    /// the client's.
    pub fn fiat(
        reference: impl Into<String>,
        amount: impl Into<String>,
        currency: impl Into<String>,
    ) -> Self {
        Self::of(reference.into(), Amount::Fiat { amount: amount.into(), currency: currency.into() })
    }

    fn of(reference: String, amount: Amount) -> Self {
        Self {
            reference,
            amount,
            rate_sources: None,
            duration_seconds: None,
            note: None,
            checkout: false,
            redirect_url: None,
        }
    }

    /// This order's rate source (an order in a currency only), in place of the client's.
    pub fn rate_source(self, source: RateSource) -> Self {
        self.rate_sources([source])
    }

    /// This order's rate sources (an order in a currency only), asked in their order, the next one
    /// only when the previous one gives no usable price; in place of the client's. 1 or more, no
    /// name twice.
    pub fn rate_sources(mut self, sources: impl IntoIterator<Item = RateSource>) -> Self {
        self.rate_sources = Some(sources.into_iter().collect());
        self
    }

    /// Seconds the invoice can be paid: 60 to 3600; 900 by default.
    pub fn duration_seconds(mut self, seconds: u64) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// What the merchant's app shows (and the customer, with a checkout link): no control
    /// characters, its leading and trailing spaces removed, 100 code points at most; empty, the
    /// reference is shown.
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Whether the invoice gets a checkout link ([`Invoice::checkout_url`]): a page of the
    /// merchant's web app where the customer pays it. False by default.
    ///
    /// [`Invoice::checkout_url`]: crate::Invoice::checkout_url
    pub fn checkout(mut self, checkout: bool) -> Self {
        self.checkout = checkout;
        self
    }

    /// With a checkout link only: where it sends the customer once the invoice is paid, an https
    /// URL (lower-case host, no user name nor password) or an app's link (`myshop://order/42`),
    /// 2048 characters at most, without spaces nor other characters to escape. Not a proof of
    /// payment.
    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.redirect_url = Some(url.into());
        self
    }

    /// The order's reference.
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// An order, checked.
#[derive(Clone, Debug)]
pub(crate) struct CheckedOrder {
    pub(crate) reference: String,
    /// Exactly one of `sats` and `fiat`.
    pub(crate) sats: Option<u64>,
    pub(crate) fiat: Option<Fiat>,
    /// The rate sources of an order in a currency, in the order they are asked.
    pub(crate) rate_sources: Option<Vec<RateSource>>,
    pub(crate) duration_seconds: i64,
    /// The note, else the reference: what the declaration and the invoice's comment carry.
    pub(crate) label: String,
    pub(crate) checkout: bool,
    /// With `checkout` only: the redirect URL.
    pub(crate) redirect_url: Option<String>,
}

/// Whether `reference` is 1 to 64 characters `A–Z a–z 0–9 . _ : -`.
pub(crate) fn is_ref(reference: &str) -> bool {
    (1..=MAX_REF_LENGTH).contains(&reference.len())
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// `reference`, checked: `invalid_order` (`ref`) unless it is 1 to 64 characters of the rule.
pub(crate) fn check_ref(reference: &str) -> Result<(), Error> {
    if is_ref(reference) { Ok(()) } else { Err(Error::invalid_order("ref", REF_RULE)) }
}

/// The note, without the spaces (U+0020) around it, else the reference: 100 code points at most,
/// without control characters (a Rust string holds no lone surrogate).
pub(crate) fn label_of(note: Option<&str>, reference: &str) -> Result<String, Error> {
    let Some(note) = note else {
        return Ok(reference.to_owned());
    };
    if has_control_character(note) {
        return Err(Error::invalid_order("note", "no control characters"));
    }
    let trimmed = note.trim_matches(' ');
    let label = if trimmed.is_empty() { reference } else { trimmed };
    if code_point_len(label) > MAX_NOTE_LENGTH {
        return Err(Error::invalid_order("note", &format!("{MAX_NOTE_LENGTH} characters at most")));
    }
    Ok(label.to_owned())
}

/// The order's parameters, checked (SPEC.md §17, The order), in the order of the specification's
/// table. `client_sources` are the client's: an order in a currency without its own uses them.
pub(crate) fn check_order(order: &Order, client_sources: &[RateSource]) -> Result<CheckedOrder, Error> {
    check_ref(&order.reference)?;
    let (sats, fiat) = match &order.amount {
        Amount::Sats(sats) => {
            if !(1..=MAX_SATS).contains(sats) {
                return Err(Error::invalid_order(
                    "sats",
                    &format!("a whole number of sats, from 1 to {MAX_SATS}"),
                ));
            }
            (Some(*sats), None)
        }
        Amount::Fiat { amount, currency } => (None, Some(parse_fiat(amount, currency)?)),
    };
    let rate_sources = match &order.rate_sources {
        Some(sources) => {
            if fiat.is_none() {
                return Err(Error::invalid_order(
                    "rateSource",
                    "only for an order priced in a currency (fiat)",
                ));
            }
            Some(
                rate_source_list(sources.clone())
                    .ok_or_else(|| Error::invalid_order("rateSource", RATE_SOURCE_RULE))?,
            )
        }
        None => fiat.is_some().then(|| client_sources.to_vec()),
    };
    let duration_seconds = match order.duration_seconds {
        None => DEFAULT_DURATION_SECONDS,
        Some(seconds) => i64::try_from(seconds)
            .ok()
            .filter(|seconds| (MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(seconds))
            .ok_or_else(|| {
                Error::invalid_order(
                    "durationSeconds",
                    &format!("{MIN_DURATION_SECONDS} to {MAX_DURATION_SECONDS} seconds"),
                )
            })?,
    };
    let label = label_of(order.note.as_deref(), &order.reference)?;
    let redirect_url = match &order.redirect_url {
        None => None,
        Some(_) if !order.checkout => {
            return Err(Error::invalid_order("redirectUrl", "only with checkout: true"));
        }
        Some(url) => {
            if redirect_shown(url).is_none() {
                return Err(Error::invalid_order(
                    "redirectUrl",
                    "an https URL (lowercase host, no user name nor password) or an app's link (scheme://…), 2048 characters at most, without spaces nor other characters to escape",
                ));
            }
            Some(url.clone())
        }
    };
    Ok(CheckedOrder {
        reference: order.reference.clone(),
        sats,
        fiat,
        rate_sources,
        duration_seconds,
        label,
        checkout: order.checkout,
        redirect_url,
    })
}

/// A stored invoice, checked: what its payment check asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredInvoice {
    /// Its order's reference, with an address.
    pub(crate) reference: Option<String>,
    /// Its Lightning invoice; `None` for an order paid on-chain only.
    pub(crate) lightning: Option<LightningInvoice>,
    pub(crate) onchain_address: Option<String>,
    pub(crate) sats: u64,
    pub(crate) expires_at: i64,
}

const NOT_STORED: &str = "not an invoice made by createInvoice";

/// A stored invoice, checked (SPEC.md §22): its sats and end; a mainnet invoice of exactly its
/// sats, its own payment hash and end, an https verify URL, or none of the three; a deposit
/// address, or none; at least one of the two. With an address, its reference: the witnesses of
/// its payment are its order's. `invalid_order` (`invoice`) otherwise.
pub(crate) fn check_stored_invoice(invoice: &InvoiceToCheck) -> Result<StoredInvoice, Error> {
    let not_stored = || Error::invalid_order("invoice", NOT_STORED);
    if !(1..=MAX_SATS).contains(&invoice.sats) || invoice.expires_at.abs() > MAX_SAFE_INTEGER {
        return Err(not_stored());
    }
    let lightning = match &invoice.bolt11 {
        None => {
            if invoice.payment_hash.is_some() || invoice.verify_url.is_some() {
                return Err(not_stored());
            }
            None
        }
        Some(bolt11) => {
            let decoded = bolt11::decode(bolt11).ok_or_else(not_stored)?;
            let payment_hash =
                invoice.payment_hash.as_deref().filter(|hash| is_hex32(hash)).ok_or_else(not_stored)?;
            let verify_url = invoice
                .verify_url
                .as_deref()
                .filter(|url| parse_https_url(url).is_some())
                .ok_or_else(not_stored)?;
            if decoded.network != "bc"
                || decoded.amount_msat.map(u128::from) != Some(u128::from(invoice.sats) * 1000)
                || decoded.payment_hash != payment_hash
                || decoded.expires_at() != invoice.expires_at
            {
                return Err(not_stored());
            }
            Some(LightningInvoice {
                bolt11: bolt11.clone(),
                payment_hash: payment_hash.to_owned(),
                verify_url: verify_url.to_owned(),
                expires_at: invoice.expires_at,
            })
        }
    };
    if invoice.onchain_address.as_deref().is_some_and(|address| !is_deposit_address(address)) {
        return Err(not_stored());
    }
    if lightning.is_none() && invoice.onchain_address.is_none() {
        return Err(not_stored());
    }
    let reference = match &invoice.onchain_address {
        None => None,
        Some(_) => match invoice.reference.as_deref() {
            Some(reference) if is_ref(reference) => Some(reference.to_owned()),
            _ => {
                return Err(Error::invalid_order(
                    "invoice",
                    &format!("{NOT_STORED}: with an address, its ref ({REF_RULE})"),
                ));
            }
        },
    };
    Ok(StoredInvoice {
        reference,
        lightning,
        onchain_address: invoice.onchain_address.clone(),
        sats: invoice.sats,
        expires_at: invoice.expires_at,
    })
}

/// A whole number of milliseconds within `min..=max`, `fallback` when absent: `invalid_option`
/// (`name`) otherwise.
pub(crate) fn check_milliseconds(
    value: Option<u64>,
    fallback: u64,
    min: u64,
    max: u64,
    name: &'static str,
) -> Result<u64, Error> {
    match value {
        None => Ok(fallback),
        Some(value) if (min..=max).contains(&value) => Ok(value),
        Some(_) => {
            Err(Error::invalid_option(name, &format!("a whole number of milliseconds, {min} to {max}")))
        }
    }
}
