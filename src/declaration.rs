//! The declaration of an invoice in the merchant's registry of payments (SPEC.md §20), as the
//! merchant's app reads it: published on a majority of the merchant's relays before the invoice
//! is shown, so that its payment counts for this order's sale and for no other. Its format is the
//! app's, version 1: changing it needs a new version there first, but for an optional field the
//! app ignores (as `taker`): `rest`, in a rest invoice's.

use crate::derive::{Registry, Sale, outer_key, registry_address};
use crate::json::{self, Json};
use crate::lightning::bolt11::{self, Bolt11};
use crate::nostr::event::Event;
use crate::nostr::nip44;
use crate::nostr::record::{Expected, Newer, Opened, Parsed, Seal, open_event, seal_record};
use crate::onchain::address::is_deposit_address;
use crate::protocol::{DECLARATION_RECORD_TYPE, DECLARATION_VERSION, MAX_DECLARED_DIGITS};
use crate::runtime::{Random, random32};
use crate::secret::Secret;
use crate::text::{from_hex32, is_hex32, to_hex};
use crate::urls::parse_https_url;

/// The price a sale is declared with, as the declaration's JSON holds it: `minor` a JSON number
/// (at most 2^53 − 1). For a sale in sats: `{"minor": <sats>, "digits": 0, "currency": "SAT"}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeclaredPrice {
    pub(crate) minor: u64,
    pub(crate) digits: u32,
    pub(crate) currency: String,
}

impl DeclaredPrice {
    pub(crate) fn to_json(&self) -> Json {
        Json::object([
            ("minor", Json::unsigned(self.minor)),
            ("digits", Json::unsigned(u64::from(self.digits))),
            ("currency", Json::from(self.currency.as_str())),
        ])
    }

    /// A price as a declaration or a lease holds it: `minor` a safe integer of at least
    /// `least_minor`, `digits` an integer from 0 to 8, `currency` three letters `A–Z`.
    pub(crate) fn parse(value: &Json, least_minor: u64) -> Option<Self> {
        let minor = value.get("minor")?.as_safe_integer()?;
        let minor = u64::try_from(minor).ok().filter(|&minor| minor >= least_minor)?;
        let digits = value.get("digits")?.as_integer()?;
        if !(0.0..=f64::from(MAX_DECLARED_DIGITS)).contains(&digits) {
            return None;
        }
        let currency = value.get("currency")?.as_str()?;
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return None;
        }
        Some(Self { minor, digits: digits as u32, currency: currency.to_owned() })
    }
}

/// The invoice an invoice of the rest is of: its deposit address and its end (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestOf {
    pub(crate) address: String,
    pub(crate) expires_at: i64,
}

impl RestOf {
    pub(crate) fn to_json(&self) -> Json {
        Json::object([
            ("address", Json::from(self.address.as_str())),
            ("expiresAt", Json::integer(self.expires_at)),
        ])
    }
}

/// What a declaration declares.
pub(crate) struct DeclarationInput<'a> {
    pub(crate) sale: &'a Sale,
    /// The invoice, checked.
    pub(crate) invoice: &'a str,
    pub(crate) verify_url: &'a str,
    /// Hex.
    pub(crate) payment_hash: &'a str,
    pub(crate) price: &'a DeclaredPrice,
    /// What the merchant's app shows: the note, else the reference.
    pub(crate) note: &'a str,
    /// Unix seconds.
    pub(crate) created_at: i64,
    /// The invoice whose rest this invoice is (SPEC.md §31); `None` for an invoice of the order.
    pub(crate) rest: Option<&'a RestOf>,
}

/// The declaration's JSON (the inside, before it is sealed).
pub(crate) fn declaration_json(input: &DeclarationInput<'_>) -> Json {
    let mut members = vec![
        ("version", Json::Number(DECLARATION_VERSION)),
        ("invoice", Json::from(input.invoice)),
        ("verifyUrl", Json::from(input.verify_url)),
        (
            "sale",
            Json::object([
                ("key", Json::from(to_hex(input.sale.key.expose()))),
                ("fiat", input.price.to_json()),
                ("note", Json::from(input.note)),
            ]),
        ),
        // "By" in the app: this integration.
        ("taker", Json::from(input.sale.taker.as_str())),
    ];
    // Only in a rest invoice's: the app ignores it, and counts the payment for the sale.
    if let Some(rest) = input.rest {
        members.push(("rest", rest.to_json()));
    }
    Json::object_of(members)
}

/// The signed declaration of an invoice for its sale (SPEC.md §20): the declaration (inside,
/// NIP-44 with the ECDH conversation key of the sale's secret and the merchant's reading key),
/// then a sealed record of type `registry-declaration` of `{"sealed": …}` (outside, the outer
/// key), at the registry address of the payment hash, signed by the sale's secret. `None` when it
/// does not fit a NIP-44 plaintext (65 535 bytes).
pub(crate) fn declaration_event(input: &DeclarationInput<'_>, random: &dyn Random) -> Option<Event> {
    let sale = input.sale;
    let nonce = random32(random);
    let sealed = nip44::encrypt(&json::stringify(&declaration_json(input)), &sale.inner_key, &nonce)?;
    let address = registry_address(&sale.registry.key, input.payment_hash);
    seal_record(
        Seal {
            record_type: DECLARATION_RECORD_TYPE,
            value: Json::object([("sealed", Json::from(sealed))]),
            signer: &sale.secret_key,
            encryption_key: &outer_key(&sale.registry.key, &address, &sale.author),
            address: &address,
            created_at: input.created_at,
            tags: Vec::new(),
        },
        random,
    )
}

/// A declaration's `rest`: absent (`Some(None)`), or the invoice it names; `None` when invalid.
fn rest_of(value: Option<&Json>) -> Option<Option<RestOf>> {
    let Some(value) = value else {
        return Some(None);
    };
    let address = value.get("address")?.as_str().filter(|address| is_deposit_address(address))?;
    let expires_at = value.get("expiresAt")?.as_safe_integer().filter(|&expires_at| expires_at >= 0)?;
    Some(Some(RestOf { address: address.to_owned(), expires_at }))
}

/// A declaration of the sale, opened by its holder.
#[derive(Clone, Debug)]
pub(crate) struct OpenedDeclaration {
    pub(crate) event: Event,
    pub(crate) invoice: String,
    pub(crate) decoded: Bolt11,
    /// Its amount in whole sats (above 0).
    pub(crate) sats: u64,
    pub(crate) verify_url: String,
    pub(crate) price: DeclaredPrice,
    /// The declared note (a lone surrogate, which no implementation writes, read as U+FFFD).
    pub(crate) note: String,
    /// Unix seconds: the event's `created_at`.
    pub(crate) declared_at: i64,
    /// The invoice whose rest it is; `None` for an invoice of the order.
    pub(crate) rest: Option<RestOf>,
}

/// The first `d` tag of an event, when it is hex32.
pub(crate) fn d_tag(event: &Event) -> Option<&str> {
    event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("d"))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
        .filter(|d| is_hex32(d))
}

/// The inside of a declaration of `sale` (SPEC.md §20, Opening), its outside opened.
fn parse_inside(outside: &Json, event: &Event, sale: &Sale, address: &str) -> Parsed<OpenedDeclaration> {
    let Some(sealed) = outside.get("sealed").and_then(Json::as_str) else {
        return Ok(None);
    };
    let Ok(text) = nip44::decrypt(sealed, &sale.inner_key) else {
        return Ok(None);
    };
    let Some(inside) = json::parse(&text) else {
        return Ok(None);
    };
    if !inside.is_object() {
        return Ok(None);
    }
    if inside.get("version").and_then(Json::as_f64).is_some_and(|version| version > DECLARATION_VERSION) {
        return Err(Newer);
    }
    if !inside.get("version").is_some_and(|version| version.is_number(DECLARATION_VERSION)) {
        return Ok(None);
    }
    let Some(invoice) = inside.get("invoice").and_then(Json::as_str) else {
        return Ok(None);
    };
    let Some(verify_url) =
        inside.get("verifyUrl").and_then(Json::as_str).filter(|url| parse_https_url(url).is_some())
    else {
        return Ok(None);
    };
    let Some(sale_value) = inside.get("sale").filter(|value| value.is_object()) else {
        return Ok(None);
    };
    if sale_value.get("key").and_then(Json::as_str) != Some(to_hex(sale.key.expose()).as_str()) {
        return Ok(None);
    }
    let Some(note) = sale_value.get("note").and_then(Json::as_json_string) else {
        return Ok(None);
    };
    let Some(price) = sale_value.get("fiat").and_then(|fiat| DeclaredPrice::parse(fiat, 0)) else {
        return Ok(None);
    };
    let Some(rest) = rest_of(inside.get("rest")) else {
        return Ok(None);
    };
    let Some((decoded, sats)) = bolt11::decode_mainnet(invoice) else {
        return Ok(None);
    };
    if address != registry_address(&sale.registry.key, &decoded.payment_hash) {
        return Ok(None);
    }
    Ok(Some(OpenedDeclaration {
        event: event.clone(),
        invoice: invoice.to_owned(),
        decoded,
        sats,
        verify_url: verify_url.to_owned(),
        price,
        note: note.to_string_lossy().into_owned(),
        declared_at: event.created_at,
        rest,
    }))
}

/// An event that checked out, if it is a declaration of `sale`: its `d` tag hex32 (the address of
/// its own invoice), the outer and inner encryption, the sale's own key inside.
pub(crate) fn open_declaration(event: &Event, sale: &Sale) -> Option<Opened<OpenedDeclaration>> {
    let address = d_tag(event)?;
    let key = outer_key(&sale.registry.key, address, &sale.author);
    open_event(
        event,
        &Expected {
            record_type: DECLARATION_RECORD_TYPE,
            encryption_key: &key,
            address,
            author: &sale.author,
        },
        |outside, event| parse_inside(outside, event, sale, address),
    )
}

/// The registry of a channel's hex fields (checked: `registryKey` hex32, `registryReader` a
/// point).
pub(crate) fn registry_of(registry_key: &str, registry_reader: &str) -> Registry {
    Registry {
        key: Secret::new(
            from_hex32(registry_key).expect("a channel's registry key is hex32 (checked when read)"),
        ),
        reader: registry_reader.to_owned(),
    }
}
