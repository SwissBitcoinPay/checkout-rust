//! The merchant's Lightning address (LUD-16, LUD-06, LUD-12, LUD-21; SPEC.md §16 to §18, §22):
//! plain HTTPS requests to the merchant's LNURL server (breez.tips), which makes invoices for the
//! merchant's wallet even while it is offline.

use crate::derive::sha256;
use crate::error::Error;
use crate::http::{Http, host_of};
use crate::json::{Json, JsonString};
use crate::lightning::bolt11::{self, Bolt11};
use crate::protocol::{CLOCK_TOLERANCE_SECONDS, GRACE_SECONDS, NOT_FOUND_REASON};
use crate::text::{ascii_lower, from_hex32, to_hex, trim_ascii_whitespace};
use crate::urls::{parse_https_url, same_host};
use crate::web::Target;

/// An LNURL answer: a JSON object, or the service's refusal (`{"status": "ERROR"}`), with its
/// reason.
enum LnurlAnswer {
    Object(Json),
    Refusal(JsonString),
}

/// An LNURL error answer (LUD-06): `{"status": "ERROR", "reason": …}`, `ERROR` in any case.
fn is_service_error(body: &Json) -> bool {
    body.is_object()
        && body.get("status").and_then(Json::as_str).is_some_and(|status| ascii_lower(status) == "error")
}

/// An LNURL answer, by its HTTP status and body (SPEC.md §16): a 2xx or a 4xx but 408 and 429
/// whose body is an object of `status` `ERROR`: a refusal; else a status that is not 2xx, or a
/// body that is not an object: `network`; else the answer's object.
async fn lnurl_get(url: &str, http: &Http) -> Result<LnurlAnswer, Error> {
    let answer = http.get_json(url, &[]).await?;
    let refusal_status = (400..500).contains(&answer.status) && answer.status != 408 && answer.status != 429;
    let ok = answer.ok();
    match answer.body {
        Some(body) if (ok || refusal_status) && is_service_error(&body) => {
            let reason = body.get("reason").and_then(Json::as_json_string).cloned();
            Ok(LnurlAnswer::Refusal(reason.unwrap_or_else(|| JsonString::Text(String::new()))))
        }
        Some(body) if ok && body.is_object() => Ok(LnurlAnswer::Object(body)),
        _ => Err(Error::network(format!(
            "{} answered HTTP {} without an LNURL answer",
            host_of(url),
            answer.status
        ))),
    }
}

/// Millisatoshis of a JSON number: a non-negative safe integer.
fn msat(value: Option<&Json>) -> Option<u64> {
    value.and_then(Json::as_safe_integer).and_then(|value| u64::try_from(value).ok())
}

/// LUD-16: the pay URL of a Lightning address (its leading and trailing ASCII whitespace removed,
/// its ASCII letters lowered, as the app reads it), or `None` when it is not one: the name of
/// `a–z 0–9 - _ . +`, the domain of labels `a–z 0–9 -`, two at least, and the pay URL an https
/// URL (SPEC.md §15): so the domain is a host, never an IP address nor `localhost`.
pub(crate) fn lightning_address_url(address: &str) -> Option<String> {
    let address = ascii_lower(trim_ascii_whitespace(address));
    let (name, domain) = address.split_once('@')?;
    let name_ok = !name.is_empty()
        && name.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'+'));
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty() && label.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        });
    if !name_ok || !domain_ok {
        return None;
    }
    let url = format!("https://{domain}/.well-known/lnurlp/{name}");
    parse_https_url(&url).map(|_| url)
}

/// The LNURL-pay parameters of the merchant's Lightning address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PayRequest {
    /// An https URL.
    pub(crate) callback: String,
    pub(crate) min_sendable_msat: u64,
    pub(crate) max_sendable_msat: u64,
    /// The raw metadata: the invoices' description hash is its SHA-256 (LUD-06).
    pub(crate) metadata: String,
    /// The longest comment accepted (LUD-12), 0 when none.
    pub(crate) comment_allowed: u64,
}

/// Reads the LNURL-pay parameters of a Lightning address (LUD-16): a refusal is `network`; an
/// answer without `tag` `payRequest`, an https `callback`, non-negative safe integer
/// `minSendable` ≤ `maxSendable` and a string `metadata` is `invalid_invoice`.
pub(crate) async fn fetch_pay_request(address: &str, http: &Http) -> Result<PayRequest, Error> {
    let url = lightning_address_url(address)
        .ok_or_else(|| Error::invalid_invoice("The merchant's Lightning address is invalid"))?;
    let json = match lnurl_get(&url, http).await? {
        LnurlAnswer::Refusal(reason) => {
            return Err(Error::network(format!(
                "{} refused the Lightning address: {}",
                host_of(&url),
                reason.to_string_lossy()
            )));
        }
        LnurlAnswer::Object(json) => json,
    };
    let callback =
        json.get("callback").and_then(Json::as_str).filter(|callback| parse_https_url(callback).is_some());
    let min = msat(json.get("minSendable"));
    let max = msat(json.get("maxSendable"));
    let metadata = json.get("metadata").and_then(Json::as_str);
    let (Some(callback), Some(min), Some(max), Some(metadata)) = (callback, min, max, metadata) else {
        return Err(Error::invalid_invoice(format!("{} gave no valid LNURL-pay request", host_of(&url))));
    };
    if json.get("tag").and_then(Json::as_str) != Some("payRequest") || min > max {
        return Err(Error::invalid_invoice(format!("{} gave no valid LNURL-pay request", host_of(&url))));
    }
    let comment_allowed =
        json.get("commentAllowed").and_then(Json::as_safe_integer).map_or(0, |allowed| allowed.max(0) as u64);
    Ok(PayRequest {
        callback: callback.to_owned(),
        min_sendable_msat: min,
        max_sendable_msat: max,
        metadata: metadata.to_owned(),
        comment_allowed,
    })
}

/// The whole sats the Lightning address accepts: its millisatoshi bounds rounded inwards (the
/// minimum up, the maximum down).
pub(crate) fn sendable_sats(pay: &PayRequest) -> (u64, u64) {
    (pay.min_sendable_msat.div_ceil(1000), pay.max_sendable_msat / 1000)
}

/// The description hash of the invoices of `pay` (hex): SHA-256 of the UTF-8 of its metadata
/// (LUD-06), the string its pay request's JSON gives, never read as JSON itself.
pub(crate) fn description_hash_of(pay: &PayRequest) -> String {
    to_hex(&sha256(pay.metadata.as_bytes()))
}

/// What the Lightning address answered: an invoice and its LUD-21 verify URL, not checked yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvoiceAnswer {
    pub(crate) pr: String,
    pub(crate) verify: String,
}

/// The callback URL of an invoice of `sats` (LUD-06): `amount` in millisatoshis, `expiry` in
/// seconds, and `comment` only when its UTF-8 bytes fit `commentAllowed` (LUD-12 does not say how
/// a comment's length counts: bytes are never fewer than characters). The callback's own query
/// parameters are kept, its fragment dropped, as `URLSearchParams` sets parameters.
pub(crate) fn invoice_url(
    pay: &PayRequest,
    sats: u64,
    expiry_seconds: i64,
    comment: Option<&str>,
) -> Option<String> {
    let mut target = Target::of(&pay.callback)?;
    target.set_query_parameter("amount", &(u128::from(sats) * 1000).to_string());
    target.set_query_parameter("expiry", &expiry_seconds.to_string());
    if let Some(comment) =
        comment.filter(|comment| !comment.is_empty() && comment.len() as u64 <= pay.comment_allowed)
    {
        target.set_query_parameter("comment", comment);
    }
    Some(target.url())
}

/// Asks the Lightning address for an invoice of `sats` ([`invoice_url`]). A refusal is
/// `network`; an answer without `pr` and `verify` strings, `invalid_invoice`. The invoice is not
/// checked here: [`check_invoice`] does.
pub(crate) async fn request_invoice(
    pay: &PayRequest,
    sats: u64,
    expiry_seconds: i64,
    comment: Option<&str>,
    http: &Http,
) -> Result<InvoiceAnswer, Error> {
    let url = invoice_url(pay, sats, expiry_seconds, comment)
        .ok_or_else(|| Error::network("The Lightning address's callback cannot be asked"))?;
    let json = match lnurl_get(&url, http).await? {
        LnurlAnswer::Refusal(reason) => {
            return Err(Error::network(format!(
                "The Lightning address refused the invoice: {}",
                reason.to_string_lossy()
            )));
        }
        LnurlAnswer::Object(json) => json,
    };
    match (json.get("pr").and_then(Json::as_str), json.get("verify").and_then(Json::as_str)) {
        (Some(pr), Some(verify)) => Ok(InvoiceAnswer { pr: pr.to_owned(), verify: verify.to_owned() }),
        _ => Err(Error::invalid_invoice("The Lightning address gave no invoice or no verify URL (LUD-21)")),
    }
}

/// The checks of an invoice (SPEC.md §18), in their order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvoiceCheck {
    Bolt11,
    Network,
    Amount,
    DescriptionHash,
    VerifyUrl,
    Duration,
    Expired,
    Clock,
}

impl InvoiceCheck {
    /// The name the vectors give it.
    #[cfg(test)]
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Bolt11 => "bolt11",
            Self::Network => "network",
            Self::Amount => "amount",
            Self::DescriptionHash => "description_hash",
            Self::VerifyUrl => "verify_url",
            Self::Duration => "duration",
            Self::Expired => "expired",
            Self::Clock => "clock",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Bolt11 => "Not a BOLT11 invoice",
            Self::Network => "Not a Bitcoin mainnet invoice",
            Self::Amount => "The invoice's amount differs from the order's",
            Self::DescriptionHash => "The invoice does not pay the merchant's Lightning address",
            Self::VerifyUrl => "No verify URL (LUD-21) on the Lightning address's host",
            Self::Duration => "The invoice lasts longer than asked",
            Self::Expired => "The invoice has no time left",
            Self::Clock => "The invoice's date is too far from this server's clock",
        }
    }
}

impl From<InvoiceCheck> for Error {
    fn from(check: InvoiceCheck) -> Self {
        Error::invalid_invoice(check.message())
    }
}

/// Checks an invoice before it is declared or shown (SPEC.md §18): Bitcoin mainnet, exactly
/// `sats`, the merchant's description hash (breez.tips serves the invoices of all its users), a
/// verify URL in https on the callback's host, an expiry no longer than asked and above 0, a date
/// within 300 s of the clock, time left before its end. The first check failed.
pub(crate) fn check_invoice(
    answer: &InvoiceAnswer,
    pay: &PayRequest,
    sats: u64,
    duration_seconds: i64,
    now: i64,
) -> Result<Bolt11, InvoiceCheck> {
    let decoded = bolt11::decode(&answer.pr).ok_or(InvoiceCheck::Bolt11)?;
    if decoded.network != "bc" {
        return Err(InvoiceCheck::Network);
    }
    if decoded.amount_msat.map(u128::from) != Some(u128::from(sats) * 1000) {
        return Err(InvoiceCheck::Amount);
    }
    if decoded.description_hash.as_deref() != Some(description_hash_of(pay).as_str()) {
        return Err(InvoiceCheck::DescriptionHash);
    }
    let callback = parse_https_url(&pay.callback).ok_or(InvoiceCheck::VerifyUrl)?;
    match parse_https_url(&answer.verify) {
        Some(verify) if same_host(&verify, &callback) => {}
        _ => return Err(InvoiceCheck::VerifyUrl),
    }
    if decoded.expiry_seconds > duration_seconds {
        return Err(InvoiceCheck::Duration);
    }
    if decoded.expiry_seconds <= 0 {
        return Err(InvoiceCheck::Expired);
    }
    if (decoded.timestamp - now).abs() > CLOCK_TOLERANCE_SECONDS {
        return Err(InvoiceCheck::Clock);
    }
    // Dated up to 5 minutes back, a short invoice may already be over: never declared nor shown.
    if decoded.expires_at() <= now {
        return Err(InvoiceCheck::Expired);
    }
    Ok(decoded)
}

/// What the Lightning part of a payment check needs of an invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LightningInvoice {
    pub(crate) bolt11: String,
    /// Hex.
    pub(crate) payment_hash: String,
    pub(crate) verify_url: String,
    pub(crate) expires_at: i64,
}

/// The Lightning part of an invoice's payment (SPEC.md §22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LightningPart {
    Open,
    Expired,
    /// Paid: its preimage, lowercase hex.
    Paid(String),
}

/// The Lightning part of an invoice's payment (LUD-21), checked (SPEC.md §22): the verify answer
/// names this very invoice (`pr`, whatever the case of its ASCII letters), `settled` is true and
/// the preimage's SHA-256 is the payment hash. Once final (now ≥ its end + 120 s), "not settled"
/// and a refusal `Not found` are `Expired`; before, any refusal keeps it `Open`.
pub(crate) async fn verify_payment(
    invoice: &LightningInvoice,
    http: &Http,
    now: i64,
) -> Result<LightningPart, Error> {
    let is_final = now >= invoice.expires_at + GRACE_SECONDS;
    let json = match lnurl_get(&invoice.verify_url, http).await? {
        LnurlAnswer::Refusal(reason) => {
            if !is_final {
                return Ok(LightningPart::Open);
            }
            if reason.as_str() == Some(NOT_FOUND_REASON) {
                return Ok(LightningPart::Expired);
            }
            return Err(Error::network(format!(
                "The payment check was refused: {}",
                reason.to_string_lossy()
            )));
        }
        LnurlAnswer::Object(json) => json,
    };
    let Some(pr) = json.get("pr").and_then(Json::as_json_string) else {
        return Err(Error::invalid_invoice("The payment check names no invoice (LUD-21 pr)"));
    };
    // BOLT11 is case-insensitive (bech32): the same invoice may be written in upper case.
    if pr.as_str().map(ascii_lower) != Some(ascii_lower(&invoice.bolt11)) {
        return Err(Error::invalid_invoice("The payment check is about another invoice"));
    }
    if json.get("settled") != Some(&Json::Bool(true)) {
        return Ok(if is_final { LightningPart::Expired } else { LightningPart::Open });
    }
    let preimage = json
        .get("preimage")
        .and_then(Json::as_str)
        .filter(|preimage| preimage.len() == 64 && preimage.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| Error::invalid_invoice("Paid without a valid preimage"))?;
    let proof = ascii_lower(preimage);
    let bytes = from_hex32(&proof).ok_or_else(|| Error::invalid_invoice("Paid without a valid preimage"))?;
    if to_hex(&sha256(&bytes)) != invoice.payment_hash {
        return Err(Error::invalid_invoice("The preimage does not match the payment hash"));
    }
    Ok(LightningPart::Paid(proof))
}
