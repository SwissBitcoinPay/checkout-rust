//! Prices in a currency, converted to sats on the integrator's server at the rate of the source it
//! chooses (SPEC.md §25, §26). Amounts are exact integers end to end: the price of one bitcoin is
//! read as the exact decimal its source wrote, and the sats are rounded up to the next whole sat:
//! the merchant never receives less than the price.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use num_bigint::BigUint;

use crate::currencies::currency_digits;
use crate::error::{Error, ErrorCode};
use crate::http::Http;
use crate::json::{Json, number_to_string};
use crate::model::{Fiat, RateInfo};
use crate::protocol::{
    CLOCK_TOLERANCE_SECONDS, MAX_MINOR_UNITS, MAX_PRICE_EXPONENT, MAX_PRICE_LENGTH, MAX_RATE_AGE_SECONDS,
    MAX_SAFE_INTEGER, SATS_PER_BTC,
};
use crate::runtime::Logger;
use crate::transport::BoxFuture;

/// The header of CoinGecko's Demo key, sent to CoinGecko only.
pub(crate) const COINGECKO_KEY_HEADER: &str = "x-cg-demo-api-key";

/// An exact positive decimal: `units` × 10^-`scale`, in its shortest writing (no trailing zero in
/// its fraction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decimal {
    pub(crate) units: BigUint,
    pub(crate) scale: u32,
}

/// A price as an exact decimal (SPEC.md §25): digits, an optional fraction and an optional
/// exponent (`"69025.1084416666694295"`, `"8e-8"`), 64 characters at most, an exponent of 64 at
/// most either way, nothing around it. `None` unless it is strictly positive.
pub(crate) fn parse_decimal(value: &str) -> Option<Decimal> {
    if value.len() > MAX_PRICE_LENGTH {
        return None;
    }
    let (mantissa, exponent) = match value.find(['e', 'E']) {
        Some(at) => (&value[..at], Some(&value[at + 1..])),
        None => (value, None),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (mantissa, None),
    };
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(whole) || fraction.is_some_and(|fraction| !digits(fraction)) {
        return None;
    }
    let fraction = fraction.unwrap_or("");
    let exponent: i64 = match exponent {
        None => 0,
        Some(text) => {
            let (negative, magnitude) = match text.as_bytes().first() {
                Some(b'+') => (false, &text[1..]),
                Some(b'-') => (true, &text[1..]),
                _ => (false, text),
            };
            if !digits(magnitude) {
                return None;
            }
            let significant = magnitude.trim_start_matches('0');
            // More than 3 digits, beyond 64 either way.
            if significant.len() > 3 {
                return None;
            }
            let value: i64 = if significant.is_empty() { 0 } else { significant.parse().ok()? };
            if negative { -value } else { value }
        }
    };
    if exponent.abs() > MAX_PRICE_EXPONENT {
        return None;
    }
    let mut units: BigUint = format!("{whole}{fraction}").parse().ok()?;
    let mut scale = fraction.len() as i64 - exponent;
    if scale < 0 {
        units *= BigUint::from(10u32).pow((-scale) as u32);
        scale = 0;
    }
    // The shortest exact writing: 69012.50 is 69012.5.
    let ten = BigUint::from(10u32);
    let zero = BigUint::from(0u32);
    while scale > 0 && &units % &ten == zero {
        units /= &ten;
        scale -= 1;
    }
    (units > zero).then_some(Decimal { units, scale: scale as u32 })
}

/// The text of a JSON number a source answered: the shortest decimal that reads back as the same
/// IEEE 754 double (ECMAScript's `Number::toString`).
pub(crate) fn number_text(value: f64) -> Option<String> {
    value.is_finite().then(|| number_to_string(value))
}

/// The plain decimal writing of an exact decimal: `69012.5`, `0.00000008`.
pub(crate) fn format_decimal(decimal: &Decimal) -> String {
    let digits = decimal.units.to_string();
    let scale = decimal.scale as usize;
    if scale == 0 {
        return digits;
    }
    let digits = format!("{digits:0>width$}", width = scale + 1);
    let (whole, fraction) = digits.split_at(digits.len() - scale);
    format!("{whole}.{fraction}")
}

/// A price in a currency (SPEC.md §25, The price of an order): the currency a code of
/// `currencies.json` (upper case), the amount 1 to 15 digits and an optional fraction of 1 to 15
/// digits, with at most the currency's decimals (trailing zeros aside), nothing around it; its
/// minor units from 1 to 2^53 − 1. `invalid_order` (`fiat`) otherwise.
pub(crate) fn parse_fiat(amount: &str, currency: &str) -> Result<Fiat, Error> {
    let digits = currency_digits(currency)
        .ok_or_else(|| Error::invalid_order("fiat", "currency: an ISO 4217 code in upper case, as CHF"))?;
    let (whole, fraction) = match amount.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (amount, None),
    };
    let is_digits =
        |text: &str| (1..=15).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit());
    if !is_digits(whole) || fraction.is_some_and(|fraction| !is_digits(fraction)) {
        return Err(Error::invalid_order("fiat", r#"amount: digits, as "24.50""#));
    }
    let fraction = fraction.unwrap_or("").trim_end_matches('0');
    if fraction.len() > digits as usize {
        return Err(Error::invalid_order(
            "fiat",
            &format!("amount: {currency} has {digits} decimals at most"),
        ));
    }
    // 15 digits and 8 decimals at most: within u128.
    let whole: u128 = whole.parse().expect("1 to 15 digits");
    let fraction: u128 = format!("{fraction:0<width$}", width = digits as usize).parse().unwrap_or(0);
    let minor = whole * 10u128.pow(digits) + fraction;
    if minor < 1 || minor > u128::from(MAX_MINOR_UNITS) {
        return Err(Error::invalid_order("fiat", "amount: more than 0, and not that large"));
    }
    let minor = minor as u64;
    Ok(Fiat {
        amount: format_decimal(&Decimal { units: BigUint::from(minor), scale: digits }),
        currency: currency.to_owned(),
        minor,
        digits,
    })
}

/// Sats for `minor` units of a currency with `digits` decimals at `price` (one bitcoin in that
/// currency), rounded up to the next whole sat, on integers:
/// `ceil(minor × 10^8 × 10^scale / (units × 10^digits))`.
pub(crate) fn minor_to_sats(minor: u64, digits: u32, price: &Decimal) -> BigUint {
    let ten = BigUint::from(10u32);
    let dividend = BigUint::from(minor) * BigUint::from(SATS_PER_BTC) * ten.pow(price.scale);
    let divisor = &price.units * ten.pow(digits);
    (dividend + &divisor - BigUint::from(1u32)) / divisor
}

/// Sats for a price in a currency at the price of one bitcoin (a decimal string): exact, rounded
/// up to the next whole sat. `invalid_order` for an invalid price in a currency, `rate` for an
/// invalid price of one bitcoin.
#[cfg(test)]
pub(crate) fn fiat_to_sats(amount: &str, currency: &str, price: &str) -> Result<BigUint, Error> {
    let fiat = parse_fiat(amount, currency)?;
    let decimal =
        parse_decimal(price).ok_or_else(|| Error::rate("A price must be a decimal string above 0"))?;
    Ok(minor_to_sats(fiat.minor, fiat.digits, &decimal))
}

/// The price of one bitcoin a custom source gives: an exact decimal string (`"69012.5"`, never a
/// float, which may already have lost digits), and when the source says it was set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomPrice {
    /// An exact decimal: digits, an optional fraction and an optional exponent, 64 characters at
    /// most (SPEC.md §25).
    pub price: String,
    /// Unix seconds: when the source set it; `None` when it does not say (its age then cannot be
    /// checked).
    pub time: Option<i64>,
}

impl From<String> for CustomPrice {
    fn from(price: String) -> Self {
        Self { price, time: None }
    }
}

impl From<&str> for CustomPrice {
    fn from(price: &str) -> Self {
        Self::from(price.to_owned())
    }
}

/// The error a custom rate source fails with: an [`Error`] goes through as it is
/// ([`Error::unsupported_currency`] when it has no price in the currency); any other becomes a
/// `rate` error whose source it is.
pub type CustomRateError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A rate source of the integrator's (SPEC.md §26, A custom source): CoinGecko Pro, a self-hosted
/// mempool, several sources checked against each other… Its RateInfo `source` is `custom`. A call
/// cancelled while it runs drops its future.
pub trait CustomRateSource: Send + Sync {
    /// The price of one bitcoin in `currency` (ISO 4217, upper case).
    fn price<'a>(&'a self, currency: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>>;
}

/// Where the rate of an invoice in a currency comes from (SPEC.md §26): a source the crate knows,
/// by its name, or the integrator's own.
#[derive(Clone)]
#[non_exhaustive]
pub enum RateSource {
    /// `coingecko`: CoinGecko's `/simple/price`, dated. Without a key, limited by IP (give a Demo
    /// key: `coingecko_api_key`).
    Coingecko,
    /// `mempool`: mempool.space's `/api/v1/prices`, dated; USD, EUR, GBP, CAD, CHF, AUD and JPY
    /// only.
    Mempool,
    /// `opennode`: OpenNode's `/v1/rates`, undated.
    Opennode,
    /// `coinbase`: Coinbase's `/v2/exchange-rates?currency=BTC`, undated.
    Coinbase,
    /// `kraken`: Kraken's `/0/public/Ticker`, the last trade's price, undated.
    Kraken,
    /// The integrator's own: [`CustomRateSource`].
    Custom(Arc<dyn CustomRateSource>),
}

impl RateSource {
    /// The default list, in the order it is asked: `coingecko`, `mempool`, `coinbase`, `kraken`,
    /// `opennode` (the dated sources first, their price's age checked).
    pub fn defaults() -> Vec<RateSource> {
        vec![Self::Coingecko, Self::Mempool, Self::Coinbase, Self::Kraken, Self::Opennode]
    }

    /// A custom source.
    pub fn custom(source: impl CustomRateSource + 'static) -> Self {
        Self::Custom(Arc::new(source))
    }

    /// Its name: `"coingecko"`, `"mempool"`, `"opennode"`, `"coinbase"`, `"kraken"`, or `"custom"`
    /// (the RateInfo's `source`).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Coingecko => "coingecko",
            Self::Mempool => "mempool",
            Self::Opennode => "opennode",
            Self::Coinbase => "coinbase",
            Self::Kraken => "kraken",
            Self::Custom(_) => "custom",
        }
    }
}

impl fmt::Debug for RateSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(_) => formatter.write_str("Custom(..)"),
            source => formatter.write_str(source.name()),
        }
    }
}

impl FromStr for RateSource {
    type Err = Error;

    /// A source by its name, exactly (`"kraken"`; never `"Kraken"`, nor `"custom"`, which is no
    /// name: a custom source is the integrator's code).
    fn from_str(name: &str) -> Result<Self, Error> {
        match name {
            "coingecko" => Ok(Self::Coingecko),
            "mempool" => Ok(Self::Mempool),
            "opennode" => Ok(Self::Opennode),
            "coinbase" => Ok(Self::Coinbase),
            "kraken" => Ok(Self::Kraken),
            _ => Err(Error::invalid_option("rateSource", RATE_SOURCE_RULE)),
        }
    }
}

/// What a rate source must be, for messages.
pub(crate) const RATE_SOURCE_RULE: &str = r#""coingecko", "mempool", "opennode", "coinbase", "kraken" or a custom source, or a non-empty list of them without the same name twice"#;

/// A list of rate sources, checked: 1 or more, no name twice (SPEC.md §26, Which sources).
pub(crate) fn rate_source_list(sources: Vec<RateSource>) -> Option<Vec<RateSource>> {
    if sources.is_empty() {
        return None;
    }
    let names: Vec<&str> = sources
        .iter()
        .filter(|source| !matches!(source, RateSource::Custom(_)))
        .map(RateSource::name)
        .collect();
    let distinct: std::collections::HashSet<&str> = names.iter().copied().collect();
    (distinct.len() == names.len()).then_some(sources)
}

/// A price of one bitcoin, as a source gave it: the text of its price, and its date (a JSON
/// number, unchecked).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Quote {
    pub(crate) price: String,
    pub(crate) time: Option<f64>,
}

/// A price of one bitcoin, checked, and what an Invoice keeps of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rate {
    pub(crate) price: Decimal,
    pub(crate) info: RateInfo,
}

/// What a source may use.
pub(crate) struct RateContext<'a> {
    pub(crate) http: &'a Http,
    /// CoinGecko's Demo key, for `coingecko`.
    pub(crate) coingecko_api_key: Option<&'a str>,
}

/// A quote, checked (SPEC.md §25): an exact positive decimal, dated (when it is) by a safe
/// integer not further ahead than 300 s and not older than 3600 s. `rate` otherwise.
pub(crate) fn check_quote(name: &str, currency: &str, quote: Quote, now: i64) -> Result<Rate, Error> {
    let price = parse_decimal(&quote.price)
        .ok_or_else(|| Error::rate(format!("{name} gave no valid price in {currency}")))?;
    let time = match quote.time {
        None => None,
        Some(time) => {
            let safe = time.is_finite() && time.fract() == 0.0 && time.abs() <= MAX_SAFE_INTEGER as f64;
            if !safe || time > (now + CLOCK_TOLERANCE_SECONDS) as f64 {
                return Err(Error::rate(format!("{name} gave an invalid date for its price")));
            }
            let time = time as i64;
            if now - time > MAX_RATE_AGE_SECONDS {
                return Err(Error::rate(format!("{name}'s price in {currency} is too old")));
            }
            Some(time)
        }
    };
    Ok(Rate {
        info: RateInfo {
            source: name.to_owned(),
            currency: currency.to_owned(),
            price: format_decimal(&price),
            fetched_at: now,
            time,
        },
        price,
    })
}

/// The price of one bitcoin in `currency` from `source`, checked.
pub(crate) async fn fetch_rate(
    source: &RateSource,
    currency: &str,
    context: &RateContext<'_>,
    now: i64,
) -> Result<Rate, Error> {
    let quote = fetch_quote(source, currency, context).await?;
    check_quote(source.name(), currency, quote, now)
}

/// Asks one source of a list for its price, checked: [`Sources`], or a test's.
pub(crate) trait AskRate: Sync {
    fn ask<'a>(
        &'a self,
        source: &'a RateSource,
        currency: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Rate, Error>>;
}

/// The rate sources of the client, with what they may use.
pub(crate) struct Sources<'a> {
    pub(crate) context: RateContext<'a>,
}

impl AskRate for Sources<'_> {
    fn ask<'a>(
        &'a self,
        source: &'a RateSource,
        currency: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Rate, Error>> {
        Box::pin(fetch_rate(source, currency, &self.context, now))
    }
}

/// The first usable price of `sources`, asked one at a time in their order (SPEC.md §26, A
/// list): the next source only when the previous one gives no usable price (`network`, `rate` or
/// `unsupported_currency`, each logged as a warning). Any other error a custom source raises stops
/// the list. With no price: `unsupported_currency` when every source raised it, else the last
/// `network` or `rate` error.
pub(crate) async fn fetch_first_rate(
    sources: &[RateSource],
    currency: &str,
    now: &(dyn Fn() -> i64 + Sync),
    logger: &dyn Logger,
    ask: &dyn AskRate,
) -> Result<Rate, Error> {
    let mut failure: Option<Error> = None;
    let mut unsupported: Option<Error> = None;
    for (index, source) in sources.iter().enumerate() {
        let error = match ask.ask(source, currency, now()).await {
            Ok(rate) => return Ok(rate),
            Err(error) => error,
        };
        let line = format!("{} failed ({}): {}", source.name(), error.code(), error.message());
        match error.code() {
            ErrorCode::UnsupportedCurrency => unsupported = Some(error),
            ErrorCode::Network | ErrorCode::Rate => failure = Some(error),
            _ => return Err(error),
        }
        if let Some(next) = sources.get(index + 1) {
            logger.warn(&format!("Rate source {line}; trying {}", next.name()));
        }
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    if sources.len() > 1 {
        let names: Vec<&str> = sources.iter().map(RateSource::name).collect();
        let names = names.join(", ");
        return Err(Error::unsupported_currency_with(
            currency,
            format!("None of {names} has a price in {currency}"),
        ));
    }
    Err(unsupported.expect("a list of one source that gave no price raised an error"))
}

/// A source's quote, unchecked.
async fn fetch_quote(source: &RateSource, currency: &str, context: &RateContext<'_>) -> Result<Quote, Error> {
    match source {
        RateSource::Custom(custom) => match custom.price(currency).await {
            Ok(price) => Ok(Quote { price: price.price, time: price.time.map(|time| time as f64) }),
            Err(error) => match error.downcast::<Error>() {
                Ok(error) => Err(*error),
                Err(error) => Err(Error::rate("The custom rate source failed").with_source(error)),
            },
        },
        RateSource::Coingecko => coingecko(currency, context).await,
        RateSource::Mempool => mempool(currency, context).await,
        RateSource::Opennode => opennode(currency, context).await,
        RateSource::Coinbase => coinbase(currency, context).await,
        RateSource::Kraken => kraken(currency, context).await,
    }
}

/// GET a source's JSON object: `network` without an answer (a redirect included, SPEC.md §15) or
/// with HTTP 500 to 599, 408 or 429; `rate` for anything else (600 and above too).
async fn source_json(
    name: &str,
    url: &str,
    context: &RateContext<'_>,
    headers: &[(&str, &str)],
) -> Result<Json, Error> {
    let answer = context.http.get_json(url, headers).await?;
    if !answer.ok() {
        let status = answer.status;
        return Err(if (500..=599).contains(&status) || status == 408 || status == 429 {
            Error::network(format!("{name} answered HTTP {status}"))
        } else {
            Error::rate(format!("{name} answered HTTP {status}"))
        });
    }
    answer.body.filter(Json::is_object).ok_or_else(|| Error::rate(format!("{name} gave no JSON object")))
}

fn object_at<'a>(value: Option<&'a Json>, name: &str) -> Result<&'a Json, Error> {
    value.filter(|value| value.is_object()).ok_or_else(|| Error::rate(format!("{name}: unexpected answer")))
}

/// A source's price: a string as written, a JSON number as its shortest decimal; absent, the
/// source has no price in the currency.
fn price_of(value: Option<&Json>, name: &str, currency: &str) -> Result<String, Error> {
    let value = value.ok_or_else(|| Error::unsupported_currency_of(currency, name))?;
    let text = match value {
        Json::String(text) => text.as_str().map(str::to_owned),
        Json::Number(number) => number_text(*number),
        _ => None,
    };
    text.ok_or_else(|| Error::rate(format!("{name}: unexpected price")))
}

/// CoinGecko (`/simple/price`, dated with `include_last_updated_at`), its Demo key when given.
async fn coingecko(currency: &str, context: &RateContext<'_>) -> Result<Quote, Error> {
    let code = currency.to_ascii_lowercase();
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={code}&include_last_updated_at=true"
    );
    let headers: Vec<(&str, &str)> =
        context.coingecko_api_key.map(|key| (COINGECKO_KEY_HEADER, key)).into_iter().collect();
    let body = source_json("coingecko", &url, context, &headers).await?;
    let bitcoin = object_at(body.get("bitcoin"), "coingecko")?;
    // Dated when it is a number (checked then); undated otherwise.
    let time = bitcoin.get("last_updated_at").and_then(Json::as_f64);
    Ok(Quote { price: price_of(bitcoin.get(&code), "coingecko", currency)?, time })
}

/// The currencies of mempool.space's `/api/v1/prices`.
const MEMPOOL_CURRENCIES: [&str; 7] = ["USD", "EUR", "GBP", "CAD", "CHF", "AUD", "JPY"];

/// mempool.space (`/api/v1/prices`, dated): 7 currencies, the others refused before any request.
async fn mempool(currency: &str, context: &RateContext<'_>) -> Result<Quote, Error> {
    if !MEMPOOL_CURRENCIES.contains(&currency) {
        return Err(Error::unsupported_currency_of(currency, "mempool"));
    }
    let body = source_json("mempool", "https://mempool.space/api/v1/prices", context, &[]).await?;
    let time = body.get("time").and_then(Json::as_f64).ok_or_else(|| Error::rate("mempool: no time"))?;
    Ok(Quote { price: price_of(body.get(currency), "mempool", currency)?, time: Some(time) })
}

/// OpenNode (`/v1/rates`): some 140 currencies, undated.
async fn opennode(currency: &str, context: &RateContext<'_>) -> Result<Quote, Error> {
    let body = source_json("opennode", "https://api.opennode.com/v1/rates", context, &[]).await?;
    let data = object_at(body.get("data"), "opennode")?;
    let pair = data
        .get(&format!("BTC{currency}"))
        .ok_or_else(|| Error::unsupported_currency_of(currency, "opennode"))?;
    let pair = object_at(Some(pair), "opennode")?;
    Ok(Quote { price: price_of(pair.get(currency), "opennode", currency)?, time: None })
}

/// Coinbase (`/v2/exchange-rates?currency=BTC`): prices as decimal strings, read as written.
async fn coinbase(currency: &str, context: &RateContext<'_>) -> Result<Quote, Error> {
    let body =
        source_json("coinbase", "https://api.coinbase.com/v2/exchange-rates?currency=BTC", context, &[])
            .await?;
    let data = object_at(body.get("data"), "coinbase")?;
    if data.get("currency").and_then(Json::as_str) != Some("BTC") {
        return Err(Error::rate("coinbase: not the rates of BTC"));
    }
    let rates = object_at(data.get("rates"), "coinbase")?;
    Ok(Quote { price: price_of(rates.get(currency), "coinbase", currency)?, time: None })
}

/// Kraken (`/0/public/Ticker?pair=XBT<currency>`): the last trade's price (`c[0]`) of the only
/// entry of `result` (its key is not always the pair asked: XBTUSD gives XXBTZUSD).
async fn kraken(currency: &str, context: &RateContext<'_>) -> Result<Quote, Error> {
    let url = format!("https://api.kraken.com/0/public/Ticker?pair=XBT{currency}");
    let body = source_json("kraken", &url, context, &[]).await?;
    let errors =
        body.get("error").and_then(Json::as_array).ok_or_else(|| Error::rate("kraken: unexpected answer"))?;
    if errors
        .iter()
        .any(|error| error.as_str().is_some_and(|error| error.starts_with("EQuery:Unknown asset pair")))
    {
        return Err(Error::unsupported_currency_of(currency, "kraken"));
    }
    if let Some(first) = errors.first() {
        let shown = match first {
            Json::String(text) => text.to_string_lossy().into_owned(),
            other => crate::json::stringify(other),
        };
        return Err(Error::rate(format!("kraken: {shown}")));
    }
    let result = object_at(body.get("result"), "kraken")?.as_object().expect("an object");
    if result.len() != 1 {
        return Err(Error::rate("kraken: unexpected answer"));
    }
    let (_, entry) = result.iter().next().expect("one entry");
    let last = object_at(Some(entry), "kraken")?
        .get("c")
        .and_then(Json::as_array)
        .ok_or_else(|| Error::rate("kraken: unexpected answer"))?;
    Ok(Quote { price: price_of(last.first(), "kraken", currency)?, time: None })
}
