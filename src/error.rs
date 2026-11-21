//! The errors of the crate (SPEC.md §5). Every error a call fails with is an [`Error`], but for a
//! cancellation: a call is cancelled by dropping its future, which then never completes.
//!
//! An error says what failed, never with a secret: neither the integration key, nor a sale's key,
//! nor any key derived from them is ever put in a message, its `Debug` or its source.

use std::fmt;

use crate::model::{DeclaredInvoice, Payment, PaymentStatus};

/// The code of an [`Error`]: stable, for programs (SPEC.md §5). Its text (`as_str`, `Display`) is
/// the code every implementation uses: `"invalid_key"`, `"network"`…
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `invalid_key`: the key is not an integration key (SPEC.md §8).
    InvalidKey,
    /// `invalid_option`: an option of the client or of a call is invalid ([`Error::param`] names
    /// it).
    InvalidOption,
    /// `invalid_order`: a parameter of the order, or a stored invoice, is invalid
    /// ([`Error::param`] names it).
    InvalidOrder,
    /// `revoked`: the merchant removed the integration.
    Revoked,
    /// `channel_not_found`: a majority of the relays answered without the integration's channel
    /// (or only with one of a newer format: [`Error::newer_format`]).
    ChannelNotFound,
    /// `network`: a relay, the Lightning address, a rate source or an explorer did not answer
    /// usably, or fewer than a majority of the relays answered or took a record.
    Network,
    /// `invalid_invoice`: an invoice, a pay request or a payment answer failed the checks.
    InvalidInvoice,
    /// `invoice_pending`: an earlier invoice of the order may still be paid
    /// ([`Error::invoice`], [`Error::checkout_url`]).
    InvoicePending,
    /// `order_paid`: an earlier invoice of the order was paid ([`Error::invoice`],
    /// [`Error::status`], [`Error::preimage`]).
    OrderPaid,
    /// `unsupported_currency`: none of the rate sources has a price in the currency
    /// ([`Error::currency`]).
    UnsupportedCurrency,
    /// `rate`: no usable price (invalid, too old, or a custom source failed).
    Rate,
    /// `checkout_unavailable`: a checkout link was asked, and the merchant's app gives no web app
    /// for it.
    CheckoutUnavailable,
    /// `onchain_unavailable`: the order can only be paid on-chain, and no address of the lot could
    /// be leased.
    OnchainUnavailable,
}

impl ErrorCode {
    /// The code, as every implementation writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidKey => "invalid_key",
            Self::InvalidOption => "invalid_option",
            Self::InvalidOrder => "invalid_order",
            Self::Revoked => "revoked",
            Self::ChannelNotFound => "channel_not_found",
            Self::Network => "network",
            Self::InvalidInvoice => "invalid_invoice",
            Self::InvoicePending => "invoice_pending",
            Self::OrderPaid => "order_paid",
            Self::UnsupportedCurrency => "unsupported_currency",
            Self::Rate => "rate",
            Self::CheckoutUnavailable => "checkout_unavailable",
            Self::OnchainUnavailable => "onchain_unavailable",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The cause of an error, when another one led to it (a connection that failed, a custom rate
/// source's own error).
pub(crate) type Cause = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A cause, shared by the copies of an error.
type SharedCause = std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>;

/// Every error of the crate (SPEC.md §5): a stable [`code`](Error::code), whether the same call
/// may succeed later unchanged ([`retryable`](Error::retryable)), and what its code carries.
/// [`std::error::Error::source`] gives its cause, when another error led to it.
#[derive(Clone)]
pub struct Error(Box<Inner>);

#[derive(Clone)]
struct Inner {
    code: ErrorCode,
    message: String,
    retryable: bool,
    param: Option<&'static str>,
    newer_format: bool,
    invoice: Option<DeclaredInvoice>,
    checkout_url: Option<String>,
    status: Option<PaymentStatus>,
    preimage: Option<String>,
    currency: Option<String>,
    source: Option<SharedCause>,
}

impl Error {
    fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self(Box::new(Inner {
            code,
            message: message.into(),
            retryable,
            param: None,
            newer_format: false,
            invoice: None,
            checkout_url: None,
            status: None,
            preimage: None,
            currency: None,
            source: None,
        }))
    }

    /// The error a custom rate source fails with when it has no price in `currency` (SPEC.md
    /// §26): the next source of a list is then asked.
    pub fn unsupported_currency(currency: impl Into<String>) -> Self {
        let currency = currency.into();
        let mut error = Self::new(
            ErrorCode::UnsupportedCurrency,
            format!("The rate source has no price in {currency}"),
            false,
        );
        error.0.currency = Some(currency);
        error
    }

    /// Its code.
    pub fn code(&self) -> ErrorCode {
        self.0.code
    }

    /// Whether the same call may succeed later, unchanged (a relay or a service down, a lot
    /// empty for now, a newer format: no).
    pub fn retryable(&self) -> bool {
        self.0.retryable
    }

    /// What it says, a sentence (`Display` writes the same).
    pub fn message(&self) -> &str {
        &self.0.message
    }

    /// With [`ErrorCode::InvalidOption`] and [`ErrorCode::InvalidOrder`]: the option or the
    /// parameter that is invalid, as SPEC.md §5 names it (`"relayTimeoutMs"`, `"sats"`,
    /// `"redirectUrl"`, `"invoice"`…).
    pub fn param(&self) -> Option<&str> {
        self.0.param
    }

    /// With [`ErrorCode::ChannelNotFound`]: whether only a channel of a newer format was found
    /// (update this crate; the error is then not retryable).
    pub fn newer_format(&self) -> bool {
        self.0.newer_format
    }

    /// With [`ErrorCode::InvoicePending`]: the invoice that may still be paid, to show instead of
    /// making another; with [`ErrorCode::OrderPaid`]: the invoice that was paid.
    pub fn invoice(&self) -> Option<&DeclaredInvoice> {
        self.0.invoice.as_ref()
    }

    /// With [`ErrorCode::InvoicePending`]: the URL of a new checkout link to the pending invoice,
    /// when the order asked for one and that invoice may still be paid.
    pub fn checkout_url(&self) -> Option<&str> {
        self.0.checkout_url.as_deref()
    }

    /// With [`ErrorCode::OrderPaid`]: the paid invoice's status ([`PaymentStatus::Paid`]).
    pub fn status(&self) -> Option<&PaymentStatus> {
        self.0.status.as_ref()
    }

    /// With [`ErrorCode::OrderPaid`]: the preimage of the paid invoice (the proof of payment),
    /// when it was paid by its own Lightning invoice; `None` when it was paid on-chain or mixed.
    pub fn preimage(&self) -> Option<&str> {
        self.0.preimage.as_deref()
    }

    /// With [`ErrorCode::UnsupportedCurrency`]: the currency.
    pub fn currency(&self) -> Option<&str> {
        self.0.currency.as_deref()
    }

    pub(crate) fn with_source(mut self, source: impl Into<Cause>) -> Self {
        let source: Cause = source.into();
        self.0.source = Some(SharedCause::from(source));
        self
    }

    pub(crate) fn invalid_key(message: &str) -> Self {
        Self::new(ErrorCode::InvalidKey, message, false)
    }

    pub(crate) fn invalid_option(param: &'static str, rule: &str) -> Self {
        let mut error = Self::new(ErrorCode::InvalidOption, format!("{param}: {rule}"), false);
        error.0.param = Some(param);
        error
    }

    pub(crate) fn invalid_order(param: &'static str, rule: &str) -> Self {
        let mut error = Self::new(ErrorCode::InvalidOrder, format!("{param}: {rule}"), false);
        error.0.param = Some(param);
        error
    }

    pub(crate) fn revoked() -> Self {
        Self::new(ErrorCode::Revoked, "The merchant removed this integration", false)
    }

    pub(crate) fn channel_not_found(newer_format: bool) -> Self {
        let mut error = if newer_format {
            Self::new(
                ErrorCode::ChannelNotFound,
                "The integration's channel is of a newer format: update sattleme-checkout",
                false,
            )
        } else {
            Self::new(
                ErrorCode::ChannelNotFound,
                "The integration's channel was not found on its relays",
                true,
            )
        };
        error.0.newer_format = newer_format;
        error
    }

    pub(crate) fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Network, message, true)
    }

    pub(crate) fn invalid_invoice(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInvoice, message, false)
    }

    pub(crate) fn unsupported_currency_of(currency: &str, source: &str) -> Self {
        let mut error =
            Self::new(ErrorCode::UnsupportedCurrency, format!("{source} has no price in {currency}"), false);
        error.0.currency = Some(currency.to_owned());
        error
    }

    pub(crate) fn unsupported_currency_with(currency: &str, message: String) -> Self {
        let mut error = Self::new(ErrorCode::UnsupportedCurrency, message, false);
        error.0.currency = Some(currency.to_owned());
        error
    }

    pub(crate) fn rate(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Rate, message, true)
    }

    pub(crate) fn invoice_pending(invoice: DeclaredInvoice, checkout_url: Option<String>) -> Self {
        let mut error =
            Self::new(ErrorCode::InvoicePending, "This order still has an invoice that may be paid", false);
        error.0.invoice = Some(invoice);
        error.0.checkout_url = checkout_url;
        error
    }

    pub(crate) fn order_paid(invoice: DeclaredInvoice, status: PaymentStatus) -> Self {
        let mut error = Self::new(ErrorCode::OrderPaid, "This order was already paid", false);
        error.0.preimage = match &status {
            PaymentStatus::Paid(Payment::Lightning { preimage }) => Some(preimage.clone()),
            _ => None,
        };
        error.0.invoice = Some(invoice);
        error.0.status = Some(status);
        error
    }

    pub(crate) fn checkout_unavailable() -> Self {
        Self::new(
            ErrorCode::CheckoutUnavailable,
            "The merchant's app gives no web app for checkout links: show the invoice on the shop's page",
            false,
        )
    }

    pub(crate) fn onchain_unavailable() -> Self {
        Self::new(
            ErrorCode::OnchainUnavailable,
            "No deposit address of the integration's lot could be leased: try again later",
            true,
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = &self.0;
        let mut debug = formatter.debug_struct("Error");
        debug
            .field("code", &inner.code)
            .field("message", &inner.message)
            .field("retryable", &inner.retryable);
        if let Some(param) = inner.param {
            debug.field("param", &param);
        }
        if inner.newer_format {
            debug.field("newer_format", &true);
        }
        if let Some(invoice) = &inner.invoice {
            debug.field("invoice", invoice);
        }
        if let Some(url) = &inner.checkout_url {
            debug.field("checkout_url", url);
        }
        if let Some(status) = &inner.status {
            debug.field("status", status);
        }
        if let Some(currency) = &inner.currency {
            debug.field("currency", currency);
        }
        if let Some(source) = &inner.source {
            debug.field("source", source);
        }
        debug.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source.as_ref().map(|source| &**source as &(dyn std::error::Error + 'static))
    }
}
