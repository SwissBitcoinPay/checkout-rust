//! What the client gives and takes (SPEC.md §3): the types an integrator stores, and their JSON.
//!
//! Every one is written as exactly the JSON of the specification, whatever the language: the same
//! field names (`ref`, `paymentHash`, `expiresAt`…), every amount a string of digits (sats, minor
//! units), never a float, every date an integer of Unix seconds, an absent value `null`. So an
//! invoice stored by another implementation (checkout-node's, checkout-php's…) is read and checked
//! here, and the other way round. Each type implements [`serde::Serialize`] and
//! [`serde::Deserialize`] with that JSON, and has `to_json`; the types a payment check reads back
//! have `from_json` too, which reads JSON as JavaScript does (SPEC.md §2: of members with one name
//! the last counts, `500.0` is 500) and fails with [`ErrorCode::InvalidOrder`] (`invoice`).
//!
//! [`ErrorCode::InvalidOrder`]: crate::ErrorCode::InvalidOrder

use std::fmt;

use serde::de::Error as _;

use crate::error::Error;
use crate::json::{self, Json};

/// A price in a currency: `minor` units with `digits` decimals (`"2450"`, 2, `"CHF"` is 24.50
/// CHF).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fiat {
    /// The price as written, with exactly the currency's decimals: `"24.50"`.
    pub amount: String,
    /// The currency: ISO 4217, upper case (`"CHF"`).
    pub currency: String,
    /// The price in the currency's minor units (JSON: a string of digits, `"2450"`).
    pub minor: u64,
    /// The currency's decimals (`2`), as the merchant's app uses them (`currencies.json`).
    pub digits: u32,
}

/// The rate an amount in a currency was converted at: for the audit, and to answer a customer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RateInfo {
    /// The source that gave it: `"coingecko"`, `"mempool"`, `"opennode"`, `"coinbase"`,
    /// `"kraken"` or `"custom"`.
    pub source: String,
    /// The currency: ISO 4217, upper case.
    pub currency: String,
    /// The price of one bitcoin in `currency`, an exact decimal written plainly and shortest
    /// (`"69012.5"`, `"0.00000008"`).
    pub price: String,
    /// Unix seconds: when the client read it (JSON `fetchedAt`).
    pub fetched_at: i64,
    /// Unix seconds: when the source says the price was set; `None` when it does not say.
    pub time: Option<i64>,
}

/// The invoice of an order, what [`Client::create_invoice`] returns: store it with the order (its
/// JSON, [`Invoice::to_json`]). The shop's page needs [`payment_uri`] (or [`bolt11`] and
/// [`onchain_address`]) and [`expires_at`] only; with a checkout link, the shop sends its customer
/// to [`checkout_url`] instead. At least one of `bolt11` and `onchain_address` is set.
///
/// [`Client::create_invoice`]: crate::Client::create_invoice
/// [`payment_uri`]: Invoice::payment_uri
/// [`bolt11`]: Invoice::bolt11
/// [`onchain_address`]: Invoice::onchain_address
/// [`expires_at`]: Invoice::expires_at
/// [`checkout_url`]: Invoice::checkout_url
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Invoice {
    /// The order's reference (JSON `ref`).
    pub reference: String,
    /// The BOLT11 invoice, as the Lightning address wrote it; `None` for an order paid on-chain
    /// only.
    pub bolt11: Option<String>,
    /// Its payment hash (hex); `None` without `bolt11` (JSON `paymentHash`).
    pub payment_hash: Option<String>,
    /// Its LUD-21 verify URL; `None` without `bolt11` (JSON `verifyUrl`).
    pub verify_url: Option<String>,
    /// The deposit address of the merchant's wallet the order leased (`bc1p…`); `None` without
    /// one (JSON `onchainAddress`).
    pub onchain_address: Option<String>,
    /// What the shop's page shows as one QR code: `bitcoin:<address>?amount=<BTC>`, followed by
    /// `&lightning=<bolt11>` with a Lightning invoice, with an address; else `lightning:<bolt11>`
    /// (JSON `paymentUri`).
    pub payment_uri: String,
    /// The amount in sats: the invoice's, and what the address must receive (JSON: a string of
    /// digits).
    pub sats: u64,
    /// The order's price when it was given in a currency.
    pub fiat: Option<Fiat>,
    /// The rate `fiat` was converted at.
    pub rate: Option<RateInfo>,
    /// What the merchant's app shows: the order's note, else its reference.
    pub note: String,
    /// Unix seconds: the invoice's date, its BOLT11 timestamp; without `bolt11`, when the address
    /// was leased (JSON `createdAt`).
    pub created_at: i64,
    /// Unix seconds: when it can no longer be paid (JSON `expiresAt`).
    pub expires_at: i64,
    /// The URL of its checkout link (the order asked for one), where the shop sends its customer
    /// to pay (JSON `checkoutUrl`).
    pub checkout_url: Option<String>,
    /// Where the checkout link sends the customer once the invoice is paid (JSON `redirectUrl`).
    pub redirect_url: Option<String>,
}

/// An invoice declared for an order, as the merchant's registry holds it
/// ([`Client::find_invoices`], and the errors `invoice_pending` and `order_paid`): the fields of
/// an [`Invoice`] but `rate`, `checkout_url` and `redirect_url`, which only the shop keeps, and
/// `declared_at`.
///
/// [`Client::find_invoices`]: crate::Client::find_invoices
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeclaredInvoice {
    /// The order's reference (JSON `ref`).
    pub reference: String,
    /// The BOLT11 invoice; `None` for an order paid on-chain only.
    pub bolt11: Option<String>,
    /// Its payment hash (hex); `None` without `bolt11`.
    pub payment_hash: Option<String>,
    /// Its LUD-21 verify URL; `None` without `bolt11`.
    pub verify_url: Option<String>,
    /// The deposit address the order leased; `None` without one.
    pub onchain_address: Option<String>,
    /// What to show as one QR code, as an [`Invoice`]'s.
    pub payment_uri: String,
    /// The amount in sats (JSON: a string of digits).
    pub sats: u64,
    /// The order's price when it was given in a currency.
    pub fiat: Option<Fiat>,
    /// What the merchant's app shows: the declared note.
    pub note: String,
    /// Unix seconds: the invoice's date.
    pub created_at: i64,
    /// Unix seconds: when it can no longer be paid.
    pub expires_at: i64,
    /// Unix seconds: when it was declared (the `created_at` of its declaration; without `bolt11`,
    /// of its lease's mark) (JSON `declaredAt`).
    pub declared_at: i64,
}

/// What a payment check needs of an invoice ([`Client::get_status`],
/// [`Client::wait_for_payment`]): an [`Invoice`] or a [`DeclaredInvoice`] gives one (`From`), and
/// so does the JSON of either ([`InvoiceToCheck::from_json`]). With an address, its order's
/// reference too: the witnesses of its payment, its lease and its rest invoices are its order's.
///
/// [`Client::get_status`]: crate::Client::get_status
/// [`Client::wait_for_payment`]: crate::Client::wait_for_payment
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InvoiceToCheck {
    /// The order's reference (JSON `ref`): needed with an address.
    pub reference: Option<String>,
    /// The BOLT11 invoice; `None` for an order paid on-chain only.
    pub bolt11: Option<String>,
    /// Its payment hash (hex); `None` without `bolt11`.
    pub payment_hash: Option<String>,
    /// Its LUD-21 verify URL; `None` without `bolt11`.
    pub verify_url: Option<String>,
    /// The deposit address the order leased; `None` without one (absent from the JSON: `None`).
    pub onchain_address: Option<String>,
    /// The amount in sats (JSON: a string of digits).
    pub sats: u64,
    /// Unix seconds: when it can no longer be paid.
    pub expires_at: i64,
}

impl From<&Invoice> for InvoiceToCheck {
    fn from(invoice: &Invoice) -> Self {
        Self {
            reference: Some(invoice.reference.clone()),
            bolt11: invoice.bolt11.clone(),
            payment_hash: invoice.payment_hash.clone(),
            verify_url: invoice.verify_url.clone(),
            onchain_address: invoice.onchain_address.clone(),
            sats: invoice.sats,
            expires_at: invoice.expires_at,
        }
    }
}

impl From<Invoice> for InvoiceToCheck {
    fn from(invoice: Invoice) -> Self {
        Self::from(&invoice)
    }
}

impl From<&DeclaredInvoice> for InvoiceToCheck {
    fn from(invoice: &DeclaredInvoice) -> Self {
        Self {
            reference: Some(invoice.reference.clone()),
            bolt11: invoice.bolt11.clone(),
            payment_hash: invoice.payment_hash.clone(),
            verify_url: invoice.verify_url.clone(),
            onchain_address: invoice.onchain_address.clone(),
            sats: invoice.sats,
            expires_at: invoice.expires_at,
        }
    }
}

impl From<DeclaredInvoice> for InvoiceToCheck {
    fn from(invoice: DeclaredInvoice) -> Self {
        Self::from(&invoice)
    }
}

impl From<&InvoiceToCheck> for InvoiceToCheck {
    fn from(invoice: &InvoiceToCheck) -> Self {
        invoice.clone()
    }
}

/// What is left to pay of an invoice underpaid on-chain ([`PaymentStatus::Open`] with
/// `received` above 0, before the invoice's end).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rest {
    /// All that is left to pay, in sats: the amount less what was received, whatever the
    /// merchant's tolerance or acceptance (JSON: a string of digits).
    pub sats: u64,
    /// A Lightning invoice of exactly that amount, declared for the order; `None` while there is
    /// none (asked again at the next check), or outside the Lightning address's sendable sats.
    pub bolt11: Option<String>,
    /// What to show as one QR code: `bitcoin:<address>?amount=<BTC>` (with `&lightning=<bolt11>`
    /// when there is one) from 1 000 sats, else `lightning:<bolt11>`; `None` with neither (JSON
    /// `paymentUri`).
    pub payment_uri: Option<String>,
}

/// How a paid invoice was paid ([`PaymentStatus::Paid`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Payment {
    /// Paid in Lightning, with its own invoice: `preimage` (hex) is the proof of payment, to keep
    /// with the order.
    Lightning {
        /// The preimage of the payment hash, lowercase hex.
        preimage: String,
    },
    /// Paid on-chain by the transactions `txids` (3 confirmations on the explorer read).
    Onchain {
        /// What the order received in time, in sats: below the amount when the merchant's
        /// tolerance, or the merchant's acceptance of what came (in its app), accepted it.
        received: u64,
        /// The order's transactions.
        txids: Vec<String>,
    },
    /// Paid on-chain by `txids` (3 confirmations on the explorer read; empty when the invoices of
    /// the rest alone pay the amount), and in Lightning by invoices of the rest of that
    /// underpayment, whose `preimages` are the proofs of those payments, to keep with the order.
    Mixed {
        /// What the order received in time, on-chain and by the invoices of the rest.
        received: u64,
        /// The order's transactions.
        txids: Vec<String>,
        /// The preimages of the rest invoices paid, in the order of the rest invoices.
        preimages: Vec<String>,
    },
}

/// Where the payment of an invoice is ([`Client::get_status`]).
///
/// `received` is what the order received in time, in sats: on-chain to its address, and in
/// Lightning by invoices of the rest of an on-chain underpayment; 0 without an address. Below the
/// amount in `Unconfirmed` and `Paid` (on-chain or mixed) when the merchant's tolerance of on-chain
/// underpayments, or the merchant's acceptance of what came (in its app), accepted less: the order
/// is paid all the same.
///
/// [`Client::get_status`]: crate::Client::get_status
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PaymentStatus {
    /// Not paid (yet): it may still be, until `expires_at`, and is reported up to 120 s later.
    Open {
        /// Unix seconds: the invoice's end.
        expires_at: i64,
        /// What came in time so far: above 0, an on-chain underpayment.
        received: u64,
        /// With `received` above 0 before the invoice's end: what is left to pay, and how.
        rest: Option<Rest>,
    },
    /// Enough was received in time (the amount, or less within the merchant's tolerance or down
    /// to what the merchant accepted), on-chain by `txids` (and in Lightning by invoices of the
    /// rest), not deep enough yet (3 confirmations): not paid yet, it may still fail (a
    /// transaction replaced or dropped).
    Unconfirmed {
        /// What the order received in time.
        received: u64,
        /// The least confirmations of the order's transactions.
        confirmations: u64,
        /// The order's transactions.
        txids: Vec<String>,
    },
    /// Paid, for good: mark the order paid.
    Paid(Payment),
    /// Never paid, for good: the order may get a new invoice. `received` above 0: the merchant
    /// received that much, less than the amount (settle it with the customer). One exception, the
    /// merchant's acceptance (SPEC.md §3): when a relay that holds it fails at a check after the
    /// lease's end, that check may give `Expired`, and a later one, which the relay answers,
    /// `Unconfirmed`, then `Paid`; an order cancelled on `Expired` is then settled by hand.
    Expired {
        /// What the order received in time.
        received: u64,
    },
}

impl PaymentStatus {
    /// `"open"`, `"unconfirmed"`, `"paid"` or `"expired"`: its JSON `state`.
    pub fn state(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Unconfirmed { .. } => "unconfirmed",
            Self::Paid(_) => "paid",
            Self::Expired { .. } => "expired",
        }
    }

    /// Whether it is final: paid or expired.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Paid(_) | Self::Expired { .. })
    }

    /// Whether the invoice was paid.
    pub fn is_paid(&self) -> bool {
        matches!(self, Self::Paid(_))
    }
}

/// The merchant, as the integration's channel, its Lightning address and its lot give it
/// ([`Client::merchant`]). Never the merchant's Lightning address: the app never shows it to the
/// integrator.
///
/// [`Client::merchant`]: crate::Client::merchant
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Merchant {
    /// The business's name, as the merchant's app gives it (JSON `businessName`).
    pub business_name: String,
    /// The smallest invoice the Lightning address makes, in sats (JSON `minSats`, a string of
    /// digits).
    pub min_sats: u64,
    /// The largest invoice the Lightning address makes, in sats (JSON `maxSats`, a string of
    /// digits).
    pub max_sats: u64,
    /// The deposit addresses of the integration's lot, leased or not: 0 takes no on-chain
    /// payment (JSON `onchainAddresses`, a number).
    pub onchain_addresses: u64,
}

// ---------------------------------------------------------------------------------------------
// Writing.

fn digits(value: u64) -> Json {
    Json::from(value.to_string())
}

fn texts(values: &[String]) -> Json {
    Json::array(values.iter().map(|value| Json::from(value.as_str())).collect())
}

impl Fiat {
    pub(crate) fn to_value(&self) -> Json {
        Json::object([
            ("amount", Json::from(self.amount.as_str())),
            ("currency", Json::from(self.currency.as_str())),
            ("minor", digits(self.minor)),
            ("digits", Json::unsigned(u64::from(self.digits))),
        ])
    }
}

impl RateInfo {
    pub(crate) fn to_value(&self) -> Json {
        Json::object([
            ("source", Json::from(self.source.as_str())),
            ("currency", Json::from(self.currency.as_str())),
            ("price", Json::from(self.price.as_str())),
            ("fetchedAt", Json::integer(self.fetched_at)),
            ("time", self.time.map_or(Json::Null, Json::integer)),
        ])
    }
}

fn optional_fiat(fiat: Option<&Fiat>) -> Json {
    fiat.map_or(Json::Null, Fiat::to_value)
}

impl Invoice {
    pub(crate) fn to_value(&self) -> Json {
        Json::object([
            ("ref", Json::from(self.reference.as_str())),
            ("bolt11", Json::optional_str(self.bolt11.as_deref())),
            ("paymentHash", Json::optional_str(self.payment_hash.as_deref())),
            ("verifyUrl", Json::optional_str(self.verify_url.as_deref())),
            ("onchainAddress", Json::optional_str(self.onchain_address.as_deref())),
            ("paymentUri", Json::from(self.payment_uri.as_str())),
            ("sats", digits(self.sats)),
            ("fiat", optional_fiat(self.fiat.as_ref())),
            ("rate", self.rate.as_ref().map_or(Json::Null, RateInfo::to_value)),
            ("note", Json::from(self.note.as_str())),
            ("createdAt", Json::integer(self.created_at)),
            ("expiresAt", Json::integer(self.expires_at)),
            ("checkoutUrl", Json::optional_str(self.checkout_url.as_deref())),
            ("redirectUrl", Json::optional_str(self.redirect_url.as_deref())),
        ])
    }
}

impl DeclaredInvoice {
    pub(crate) fn to_value(&self) -> Json {
        Json::object([
            ("ref", Json::from(self.reference.as_str())),
            ("bolt11", Json::optional_str(self.bolt11.as_deref())),
            ("paymentHash", Json::optional_str(self.payment_hash.as_deref())),
            ("verifyUrl", Json::optional_str(self.verify_url.as_deref())),
            ("onchainAddress", Json::optional_str(self.onchain_address.as_deref())),
            ("paymentUri", Json::from(self.payment_uri.as_str())),
            ("sats", digits(self.sats)),
            ("fiat", optional_fiat(self.fiat.as_ref())),
            ("note", Json::from(self.note.as_str())),
            ("createdAt", Json::integer(self.created_at)),
            ("expiresAt", Json::integer(self.expires_at)),
            ("declaredAt", Json::integer(self.declared_at)),
        ])
    }
}

impl InvoiceToCheck {
    pub(crate) fn to_value(&self) -> Json {
        let mut members = Vec::with_capacity(7);
        if let Some(reference) = &self.reference {
            members.push(("ref", Json::from(reference.as_str())));
        }
        members.extend([
            ("bolt11", Json::optional_str(self.bolt11.as_deref())),
            ("paymentHash", Json::optional_str(self.payment_hash.as_deref())),
            ("verifyUrl", Json::optional_str(self.verify_url.as_deref())),
            ("onchainAddress", Json::optional_str(self.onchain_address.as_deref())),
            ("sats", digits(self.sats)),
            ("expiresAt", Json::integer(self.expires_at)),
        ]);
        Json::object_of(members)
    }
}

impl Rest {
    pub(crate) fn to_value(&self) -> Json {
        Json::object([
            ("sats", digits(self.sats)),
            ("bolt11", Json::optional_str(self.bolt11.as_deref())),
            ("paymentUri", Json::optional_str(self.payment_uri.as_deref())),
        ])
    }
}

impl PaymentStatus {
    pub(crate) fn to_value(&self) -> Json {
        match self {
            Self::Open { expires_at, received, rest } => Json::object([
                ("state", Json::from("open")),
                ("expiresAt", Json::integer(*expires_at)),
                ("received", digits(*received)),
                ("rest", rest.as_ref().map_or(Json::Null, Rest::to_value)),
            ]),
            Self::Unconfirmed { received, confirmations, txids } => Json::object([
                ("state", Json::from("unconfirmed")),
                ("received", digits(*received)),
                ("confirmations", Json::unsigned(*confirmations)),
                ("txids", texts(txids)),
            ]),
            Self::Paid(Payment::Lightning { preimage }) => Json::object([
                ("state", Json::from("paid")),
                ("method", Json::from("lightning")),
                ("preimage", Json::from(preimage.as_str())),
            ]),
            Self::Paid(Payment::Onchain { received, txids }) => Json::object([
                ("state", Json::from("paid")),
                ("method", Json::from("onchain")),
                ("received", digits(*received)),
                ("txids", texts(txids)),
            ]),
            Self::Paid(Payment::Mixed { received, txids, preimages }) => Json::object([
                ("state", Json::from("paid")),
                ("method", Json::from("mixed")),
                ("received", digits(*received)),
                ("txids", texts(txids)),
                ("preimages", texts(preimages)),
            ]),
            Self::Expired { received } => {
                Json::object([("state", Json::from("expired")), ("received", digits(*received))])
            }
        }
    }
}

impl Merchant {
    pub(crate) fn to_value(&self) -> Json {
        Json::object([
            ("businessName", Json::from(self.business_name.as_str())),
            ("minSats", digits(self.min_sats)),
            ("maxSats", digits(self.max_sats)),
            ("onchainAddresses", Json::unsigned(self.onchain_addresses)),
        ])
    }
}

// ---------------------------------------------------------------------------------------------
// Reading, as JavaScript reads the JSON (SPEC.md §2). Each reader says which field is wrong.

/// Why a value is not one of these types: the field that is not as SPEC.md §3 writes it.
#[derive(Debug)]
pub(crate) struct ReadError(pub(crate) String);

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

type Read<T> = Result<T, ReadError>;

fn wrong(name: &str, rule: &str) -> ReadError {
    ReadError(format!("{name}: {rule}"))
}

fn object<'a>(value: &'a Json, what: &str) -> Read<&'a Json> {
    if value.is_object() { Ok(value) } else { Err(ReadError(format!("not {what}: an object expected"))) }
}

fn member<'a>(value: &'a Json, name: &str) -> Read<&'a Json> {
    value.get(name).ok_or_else(|| wrong(name, "missing"))
}

/// A string (well-formed: SPEC.md §6).
fn text(value: &Json, name: &str) -> Read<String> {
    member(value, name)?.as_str().map(str::to_owned).ok_or_else(|| wrong(name, "a string"))
}

/// Null, or a string; absent: null. Only for `onchainAddress`, the one member SPEC.md lets an
/// invoice leave out (§3, InvoiceToCheck: "without onchainAddress, it reads as null"; §22).
fn optional_text(value: &Json, name: &str) -> Read<Option<String>> {
    match value.get(name) {
        None | Some(Json::Null) => Ok(None),
        Some(item) => {
            item.as_str().map(|text| Some(text.to_owned())).ok_or_else(|| wrong(name, "null or a string"))
        }
    }
}

/// Null, or a string, present: a member is `null` only when it is there with that value (SPEC.md
/// §2).
fn nullable_text(value: &Json, name: &str) -> Read<Option<String>> {
    member(value, name)?;
    optional_text(value, name)
}

/// A string of 1 to `max` digits (ASCII), read as an integer.
fn digit_string(item: &Json, name: &str, max: usize) -> Read<u64> {
    let rule = "a string of digits";
    let text = item.as_str().ok_or_else(|| wrong(name, rule))?;
    if text.is_empty() || text.len() > max || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(wrong(name, rule));
    }
    text.parse().map_err(|_| wrong(name, rule))
}

/// The amounts of SPEC.md §3: at most 2 100 000 000 000 000 sats, 2^53 − 1 minor units, so 16
/// digits at most (as checkout-node reads a stored invoice's).
const AMOUNT_DIGITS: usize = 16;

fn amount(value: &Json, name: &str) -> Read<u64> {
    digit_string(member(value, name)?, name, AMOUNT_DIGITS)
}

/// A safe integer (a JSON number: `1791378280.0` is 1791378280).
fn safe_integer(value: &Json, name: &str) -> Read<i64> {
    member(value, name)?.as_safe_integer().ok_or_else(|| wrong(name, "an integer"))
}

/// Null, or a safe integer, present (SPEC.md §2).
fn nullable_safe_integer(value: &Json, name: &str) -> Read<Option<i64>> {
    match member(value, name)? {
        Json::Null => Ok(None),
        item => item.as_safe_integer().map(Some).ok_or_else(|| wrong(name, "null or an integer")),
    }
}

fn count(value: &Json, name: &str) -> Read<u64> {
    let number = safe_integer(value, name)?;
    u64::try_from(number).map_err(|_| wrong(name, "a non-negative integer"))
}

fn text_list(value: &Json, name: &str) -> Read<Vec<String>> {
    member(value, name)?
        .as_array()
        .ok_or_else(|| wrong(name, "an array of strings"))?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or_else(|| wrong(name, "an array of strings")))
        .collect()
}

impl Fiat {
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "a Fiat")?;
        let digits = count(value, "digits")?;
        Ok(Self {
            amount: text(value, "amount")?,
            currency: text(value, "currency")?,
            minor: amount(value, "minor")?,
            digits: u32::try_from(digits).map_err(|_| wrong("digits", "an integer"))?,
        })
    }
}

/// The `fiat` member: null, or a Fiat, present (SPEC.md §2).
fn nullable_fiat(value: &Json) -> Read<Option<Fiat>> {
    match member(value, "fiat")? {
        Json::Null => Ok(None),
        fiat => Fiat::from_value(fiat).map(Some).map_err(|error| ReadError(format!("fiat.{error}"))),
    }
}

impl RateInfo {
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "a RateInfo")?;
        Ok(Self {
            source: text(value, "source")?,
            currency: text(value, "currency")?,
            price: text(value, "price")?,
            fetched_at: safe_integer(value, "fetchedAt")?,
            time: nullable_safe_integer(value, "time")?,
        })
    }
}

impl Invoice {
    /// An Invoice's JSON (SPEC.md §3): every member there, `null` where it may be (an absent one
    /// is no `null`, SPEC.md §2), but `onchainAddress`, which reads as null when absent (§3).
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "an Invoice")?;
        let rate = match member(value, "rate")? {
            Json::Null => None,
            rate => Some(RateInfo::from_value(rate).map_err(|error| ReadError(format!("rate.{error}")))?),
        };
        Ok(Self {
            reference: text(value, "ref")?,
            bolt11: nullable_text(value, "bolt11")?,
            payment_hash: nullable_text(value, "paymentHash")?,
            verify_url: nullable_text(value, "verifyUrl")?,
            onchain_address: optional_text(value, "onchainAddress")?,
            payment_uri: text(value, "paymentUri")?,
            sats: amount(value, "sats")?,
            fiat: nullable_fiat(value)?,
            rate,
            note: text(value, "note")?,
            created_at: safe_integer(value, "createdAt")?,
            expires_at: safe_integer(value, "expiresAt")?,
            checkout_url: nullable_text(value, "checkoutUrl")?,
            redirect_url: nullable_text(value, "redirectUrl")?,
        })
    }
}

impl DeclaredInvoice {
    /// A DeclaredInvoice's JSON (SPEC.md §3), as an Invoice's: an absent member is no `null`, but
    /// `onchainAddress`.
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "a DeclaredInvoice")?;
        Ok(Self {
            reference: text(value, "ref")?,
            bolt11: nullable_text(value, "bolt11")?,
            payment_hash: nullable_text(value, "paymentHash")?,
            verify_url: nullable_text(value, "verifyUrl")?,
            onchain_address: optional_text(value, "onchainAddress")?,
            payment_uri: text(value, "paymentUri")?,
            sats: amount(value, "sats")?,
            fiat: nullable_fiat(value)?,
            note: text(value, "note")?,
            created_at: safe_integer(value, "createdAt")?,
            expires_at: safe_integer(value, "expiresAt")?,
            declared_at: safe_integer(value, "declaredAt")?,
        })
    }
}

impl InvoiceToCheck {
    /// An Invoice's or a DeclaredInvoice's JSON, as a payment check reads it (SPEC.md §22): `sats`
    /// a string of digits, `expiresAt` a safe integer, `bolt11`, `paymentHash` and `verifyUrl`
    /// each null or a string (present), `onchainAddress` null, absent or a string. `ref` when it is
    /// a string: the check reads it only with an address, where it must be a reference
    /// (`check_stored_invoice`). Its other fields are not read.
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "an invoice")?;
        // Not read without an address (SPEC.md §22: "the others are not read"): whatever it holds
        // then, the invoice is checked as it would be without it.
        let reference = value.get("ref").and_then(Json::as_str).map(str::to_owned);
        Ok(Self {
            reference,
            bolt11: nullable_text(value, "bolt11")?,
            payment_hash: nullable_text(value, "paymentHash")?,
            verify_url: nullable_text(value, "verifyUrl")?,
            onchain_address: optional_text(value, "onchainAddress")?,
            sats: amount(value, "sats")?,
            expires_at: safe_integer(value, "expiresAt")?,
        })
    }
}

impl Rest {
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "a Rest")?;
        Ok(Self {
            sats: amount(value, "sats")?,
            bolt11: nullable_text(value, "bolt11")?,
            payment_uri: nullable_text(value, "paymentUri")?,
        })
    }
}

impl PaymentStatus {
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "a PaymentStatus")?;
        let received = || amount(value, "received");
        let state = text(value, "state")?;
        Ok(match state.as_str() {
            "open" => {
                let rest = match member(value, "rest")? {
                    Json::Null => None,
                    rest => Some(Rest::from_value(rest).map_err(|error| ReadError(format!("rest.{error}")))?),
                };
                Self::Open { expires_at: safe_integer(value, "expiresAt")?, received: received()?, rest }
            }
            "unconfirmed" => Self::Unconfirmed {
                received: received()?,
                confirmations: count(value, "confirmations")?,
                txids: text_list(value, "txids")?,
            },
            "paid" => Self::Paid(match text(value, "method")?.as_str() {
                "lightning" => Payment::Lightning { preimage: text(value, "preimage")? },
                "onchain" => Payment::Onchain { received: received()?, txids: text_list(value, "txids")? },
                "mixed" => Payment::Mixed {
                    received: received()?,
                    txids: text_list(value, "txids")?,
                    preimages: text_list(value, "preimages")?,
                },
                _ => return Err(wrong("method", r#""lightning", "onchain" or "mixed""#)),
            }),
            "expired" => Self::Expired { received: received()? },
            _ => return Err(wrong("state", r#""open", "unconfirmed", "paid" or "expired""#)),
        })
    }
}

impl Merchant {
    pub(crate) fn from_value(value: &Json) -> Read<Self> {
        let value = object(value, "a Merchant")?;
        Ok(Self {
            business_name: text(value, "businessName")?,
            min_sats: amount(value, "minSats")?,
            max_sats: amount(value, "maxSats")?,
            onchain_addresses: count(value, "onchainAddresses")?,
        })
    }
}

/// `to_json`, `Serialize` and `Deserialize` of each type, through its JSON value.
macro_rules! json_type {
    ($type:ident, $what:literal) => {
        impl $type {
            #[doc = concat!("Its JSON (SPEC.md §3), as every implementation writes ", $what, ".")]
            pub fn to_json(&self) -> String {
                json::stringify(&self.to_value())
            }
        }

        impl serde::Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.to_value().serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = Json::deserialize(deserializer)?;
                Self::from_value(&value).map_err(|error| {
                    D::Error::custom(format!(concat!("not ", $what, " (SPEC.md §3): {}"), error))
                })
            }
        }
    };
}

json_type!(Fiat, "a Fiat");
json_type!(RateInfo, "a RateInfo");
json_type!(Invoice, "an Invoice");
json_type!(DeclaredInvoice, "a DeclaredInvoice");
json_type!(InvoiceToCheck, "an InvoiceToCheck");
json_type!(Rest, "a Rest");
json_type!(PaymentStatus, "a PaymentStatus");
json_type!(Merchant, "a Merchant");

/// `from_json` of the types a payment check reads back.
macro_rules! from_json {
    ($type:ident, $what:literal) => {
        impl $type {
            #[doc = concat!(
                "Reads ", $what, " from its JSON (SPEC.md §3), as JavaScript reads JSON (SPEC.md §2): ",
                "what an implementation stored, this one or another. Fails with `invalid_order` ",
                "(`invoice`) when it is not one."
            )]
            pub fn from_json(text: &str) -> Result<Self, Error> {
                let value = json::parse(text)
                    .ok_or_else(|| Error::invalid_order("invoice", "not JSON"))?;
                Self::from_value(&value).map_err(|error| Error::invalid_order("invoice", &error.0))
            }
        }
    };
}

from_json!(Invoice, "an Invoice");
from_json!(DeclaredInvoice, "a DeclaredInvoice");
from_json!(InvoiceToCheck, "an invoice to check (an Invoice's or a DeclaredInvoice's JSON)");
