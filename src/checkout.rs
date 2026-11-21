//! Checkout links (SPEC.md §30): a URL of the merchant's web app,
//! `<origin>/pay#c.<author>.<key>.<relays>`, whose page reads the invoice from the merchant's
//! relays, shows it, checks its payment from the customer's browser and, once it is paid, sends the
//! customer to the order's redirect URL. The record is sealed with a key of the link alone (in the
//! URL's fragment, which browsers never send to the web app's host) and signed by an author of the
//! link alone, whose secret is forgotten once it is published: nobody, the integrator included,
//! can change a link afterwards. The crate writes links; it also reads them (fragments, records),
//! as the page does, for the conformance vectors.

use crate::declaration::DeclaredPrice;
use crate::derive::{derive_key, public_key_of};
use crate::encoding::to_base64url;
use crate::json::Json;
use crate::nostr::event::Event;
use crate::nostr::record::{Seal, seal_record};
use crate::onchain::node::RecordNode;
use crate::protocol::{
    CHECKOUT_ADDRESS_INFO, CHECKOUT_ENCRYPTION_INFO, CHECKOUT_LIFE_SECONDS, CHECKOUT_MARKER,
    CHECKOUT_ONCHAIN_VERSION, CHECKOUT_PATH, CHECKOUT_RECORD_TYPE, CHECKOUT_SALT, CHECKOUT_VERSION,
    MAX_BUSINESS_NAME_LENGTH, MAX_REDIRECT_SCHEME_LENGTH, MAX_REDIRECT_URL_LENGTH, REFUSED_REDIRECT_SCHEMES,
};
use crate::relays::encode_relay_list;
use crate::runtime::{Random, random32};
use crate::secret::Secret;
use crate::text::{code_point_len, from_hex32, is_hex32, to_hex, trim_ascii_whitespace};
use crate::urls::{has_url_characters, parse_https_url};

/// Whether `value` is a checkout origin: `https://`, a host as in a relay address, an optional
/// port, then nothing (SPEC.md §30, The web app's origin).
pub(crate) fn is_checkout_origin(value: &str) -> bool {
    parse_https_url(value).is_some() && !value["https://".len()..].contains(['/', '?', '#'])
}

/// The origin a channel's `checkout` field gives: `None` when it gives none or an invalid one.
pub(crate) fn checkout_origin_of(checkout: Option<&Json>) -> Option<String> {
    let origin = checkout.filter(|checkout| checkout.is_object())?.get("origin")?.as_str()?;
    is_checkout_origin(origin).then(|| origin.to_owned())
}

/// What the page shows of a redirect URL ("Redirecting to …", SPEC.md §30): the host and port of
/// an https URL as written, the scheme and `://` of an app's link. `None` when `value` is not a
/// redirect URL: nothing is repaired.
pub(crate) fn redirect_shown(value: &str) -> Option<String> {
    if value.len() > MAX_REDIRECT_URL_LENGTH || !has_url_characters(value) {
        return None;
    }
    if let Some(rest) = value.strip_prefix("https://") {
        parse_https_url(value)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        return Some(rest[..end].to_owned());
    }
    let (scheme, _) = value.split_once("://")?;
    let mut bytes = scheme.bytes();
    let first_ok = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let rest_ok = bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'+' | b'.' | b'-'));
    if !first_ok
        || !rest_ok
        || scheme.len() > MAX_REDIRECT_SCHEME_LENGTH
        || scheme == "https"
        || REFUSED_REDIRECT_SCHEMES.contains(&scheme)
    {
        return None;
    }
    Some(format!("{scheme}://"))
}

/// The keys of a link (its link key): its `d` tag (hex) and its NIP-44 conversation key.
pub(crate) struct CheckoutKeys {
    pub(crate) address: String,
    pub(crate) encryption_key: Secret,
}

pub(crate) fn checkout_keys(link_key: &Secret) -> CheckoutKeys {
    CheckoutKeys {
        address: to_hex(derive_key(link_key.expose(), CHECKOUT_SALT, CHECKOUT_ADDRESS_INFO).expose()),
        encryption_key: derive_key(link_key.expose(), CHECKOUT_SALT, CHECKOUT_ENCRYPTION_INFO),
    }
}

/// A link author's secret: 32 random bytes, drawn again until they are a secp256k1 secret key.
fn author_secret(random: &dyn Random) -> Secret {
    loop {
        let bytes = random32(random);
        if crate::secp::is_secret_key(&bytes) {
            return Secret::new(bytes);
        }
    }
}

/// The URL of a link: `<origin>/pay#c.<author>.<key>.<relays>`.
pub(crate) fn checkout_url(origin: &str, author: &str, link_key: &Secret, relays: &[String]) -> String {
    let author = from_hex32(author).expect("an author is hex32");
    format!(
        "{origin}{CHECKOUT_PATH}#{CHECKOUT_MARKER}.{}.{}.{}",
        to_base64url(&author),
        to_base64url(link_key.expose()),
        encode_relay_list(relays)
    )
}

/// The rest author (hex) and the rest key of an invoice with an address, as its links' records
/// carry them (SPEC.md §31, Rest records): they read rest records, never write one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestReader {
    pub(crate) author: String,
    /// Hex.
    pub(crate) key: String,
}

/// What a link's record holds (SPEC.md §30, The record): version 1 for an invoice without an
/// address, version 2 for one with an address.
pub(crate) struct CheckoutValue {
    pub(crate) business_name: String,
    pub(crate) invoice: Option<String>,
    pub(crate) verify_url: Option<String>,
    pub(crate) onchain_address: Option<String>,
    pub(crate) sats: u64,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    /// The order's price as declared; `None` for an order in sats.
    pub(crate) fiat: Option<DeclaredPrice>,
    /// The label: the note, else the reference.
    pub(crate) note: String,
    pub(crate) redirect_url: Option<String>,
    /// With an address: its rest author and rest key.
    pub(crate) rest: Option<RestReader>,
    /// With an address: the merchant's Bitcoin node the page reads the chain from (the channel's
    /// with `payers` true, [`crate::onchain::node::record_node_for`]); `None` for mempool.space.
    /// Never in a record of version 1.
    pub(crate) bitcoin_node: Option<RecordNode>,
}

impl CheckoutValue {
    pub(crate) fn to_json(&self) -> Json {
        let fiat = self.fiat.as_ref().map_or(Json::Null, DeclaredPrice::to_json);
        let Some(address) = &self.onchain_address else {
            return Json::object([
                ("version", Json::Number(CHECKOUT_VERSION)),
                ("businessName", Json::from(self.business_name.as_str())),
                ("invoice", Json::optional_str(self.invoice.as_deref())),
                ("verifyUrl", Json::optional_str(self.verify_url.as_deref())),
                ("fiat", fiat),
                ("note", Json::from(self.note.as_str())),
                ("redirectUrl", Json::optional_str(self.redirect_url.as_deref())),
            ]);
        };
        let mut members = vec![
            ("version", Json::Number(CHECKOUT_ONCHAIN_VERSION)),
            ("businessName", Json::from(self.business_name.as_str())),
            ("invoice", Json::optional_str(self.invoice.as_deref())),
            ("verifyUrl", Json::optional_str(self.verify_url.as_deref())),
            ("onchainAddress", Json::from(address.as_str())),
            ("sats", Json::unsigned(self.sats)),
            ("createdAt", Json::integer(self.created_at)),
            ("expiresAt", Json::integer(self.expires_at)),
            ("fiat", fiat),
            ("note", Json::from(self.note.as_str())),
            ("redirectUrl", Json::optional_str(self.redirect_url.as_deref())),
        ];
        if let Some(rest) = &self.rest {
            members.push(("restAuthor", Json::from(rest.author.as_str())));
            members.push(("restKey", Json::from(rest.key.as_str())));
        }
        // Absent, never null, without one: a page that does not know it reads mempool.space.
        if let Some(node) = &self.bitcoin_node {
            members.push(("bitcoinNode", node.to_json()));
        }
        Json::object_of(members)
    }
}

/// A new link, before it is published.
pub(crate) struct NewCheckoutLink {
    pub(crate) url: String,
    pub(crate) event: Event,
    /// The author's secret: it answers the relays' authentication while the event is published,
    /// then is dropped. Never stored, returned to the caller nor logged.
    pub(crate) secret_key: Secret,
}

/// A new link to the invoice `value` holds, ending `expires_at`: a fresh link key and author, the
/// record signed at `created_at`, dropped by the relays a week after the invoice's end, and the
/// URL on `origin` naming `relays` (where it is to be published). `None` when the record does
/// not fit NIP-44.
pub(crate) fn new_checkout_link(
    origin: &str,
    relays: &[String],
    value: &CheckoutValue,
    expires_at: i64,
    created_at: i64,
    random: &dyn Random,
) -> Option<NewCheckoutLink> {
    let link_key = Secret::new(random32(random));
    let secret_key = author_secret(random);
    let keys = checkout_keys(&link_key);
    let event = seal_record(
        Seal {
            record_type: CHECKOUT_RECORD_TYPE,
            value: value.to_json(),
            signer: &secret_key,
            encryption_key: &keys.encryption_key,
            address: &keys.address,
            created_at,
            tags: vec![vec!["expiration".to_owned(), (expires_at + CHECKOUT_LIFE_SECONDS).to_string()]],
        },
        random,
    )?;
    Some(NewCheckoutLink {
        url: checkout_url(origin, &public_key_of(&secret_key), &link_key, relays),
        event,
        secret_key,
    })
}

/// Whether `value` is a business's name: a string, not empty once ASCII whitespace is trimmed,
/// at most 200 code points.
pub(crate) fn is_business_name(value: &str) -> bool {
    !trim_ascii_whitespace(value).is_empty() && code_point_len(value) <= MAX_BUSINESS_NAME_LENGTH
}

/// Whether `value` is an x-only public key (lowercase hex) of a point of secp256k1 (BIP-340
/// `lift_x`).
pub(crate) fn is_public_key(value: &str) -> bool {
    is_hex32(value) && from_hex32(value).is_some_and(|x| crate::secp::lift_x(&x))
}

#[cfg(test)]
pub(crate) use page::{CheckoutFragment, CheckoutRecord, parse_checkout_fragment, parse_checkout_value};

/// What the merchant's web app reads of a link (SPEC.md §30, Reading the fragment, Reading a
/// record): the crate writes links, and reads them as the page does for the conformance vectors.
#[cfg(test)]
mod page {
    use super::{RestReader, is_business_name, is_public_key, redirect_shown};
    use crate::declaration::DeclaredPrice;
    use crate::encoding::from_base64url;
    use crate::json::Json;
    use crate::lightning::bolt11;
    use crate::nostr::record::{Newer, Parsed};
    use crate::onchain::address::is_deposit_address;
    use crate::onchain::node::{RecordNode, record_node_of};
    use crate::protocol::{
        CHECKOUT_MARKER, CHECKOUT_ONCHAIN_VERSION, CHECKOUT_VERSION, KEY_BYTES, MAX_NOTE_LENGTH, MAX_SATS,
        SATS_CURRENCY,
    };
    use crate::relays::decode_relay_list;
    use crate::secret::Secret;
    use crate::text::{code_point_len, has_control_character, is_hex32, to_hex};
    use crate::urls::parse_https_url;

    /// What a fragment names (SPEC.md §30, Reading the fragment).
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum CheckoutFragment {
        Link {
            author: String,
            link_key: Secret,
            relays: Vec<String>,
        },
        /// A link of a newer format: the page asks to be updated.
        Newer,
        Invalid,
        /// Not a checkout link: another link of the page.
        Other,
    }

    /// The link a URL's fragment (with or without its `#`) names.
    pub(crate) fn parse_checkout_fragment(fragment: &str) -> CheckoutFragment {
        let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
        let parts: Vec<&str> = fragment.split('.').collect();
        let marker = parts[0];
        if marker != CHECKOUT_MARKER {
            let newer = (1..=8).contains(&marker.len())
                && marker.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9'));
            return if newer { CheckoutFragment::Newer } else { CheckoutFragment::Other };
        }
        let [_, author, key, relays] = parts.as_slice() else {
            return CheckoutFragment::Invalid;
        };
        let author = from_base64url(author).and_then(|bytes| <[u8; KEY_BYTES]>::try_from(bytes).ok());
        let key = from_base64url(key).and_then(|bytes| <[u8; KEY_BYTES]>::try_from(bytes).ok());
        let (Some(author), Some(key), Some(relays)) = (author, key, decode_relay_list(relays)) else {
            return CheckoutFragment::Invalid;
        };
        if !crate::secp::lift_x(&author) {
            return CheckoutFragment::Invalid;
        }
        CheckoutFragment::Link { author: to_hex(&author), link_key: Secret::new(key), relays }
    }

    /// A link's record, checked: what the page shows.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct CheckoutRecord {
        pub(crate) business_name: String,
        /// The Lightning invoice; `None` for an order paid on-chain only.
        pub(crate) invoice: Option<String>,
        pub(crate) payment_hash: Option<String>,
        pub(crate) verify_url: Option<String>,
        /// The deposit address; `None` without one (a record of version 1).
        pub(crate) onchain_address: Option<String>,
        /// Whole sats: the invoice's amount, and what the address must receive.
        pub(crate) sats: u64,
        pub(crate) created_at: i64,
        pub(crate) expires_at: i64,
        pub(crate) fiat: Option<DeclaredPrice>,
        pub(crate) note: String,
        pub(crate) redirect_url: Option<String>,
        /// What the page shows of `redirect_url`.
        pub(crate) redirect_shown: Option<String>,
        /// The rest author and rest key of a record of version 2 that carries them.
        pub(crate) rest: Option<RestReader>,
        /// The merchant's Bitcoin node the page reads the chain from: a record of version 2's
        /// valid `bitcoinNode`; `None` for mempool.space (none, one set aside, or version 1).
        pub(crate) bitcoin_node: Option<RecordNode>,
    }

    /// A link's `fiat`: null, or a price in a currency (`minor` from 1, not `SAT`); `None` when
    /// invalid.
    fn checkout_price(value: Option<&Json>) -> Option<Option<DeclaredPrice>> {
        match value? {
            Json::Null => Some(None),
            value => {
                let price = DeclaredPrice::parse(value, 1)?;
                (price.currency != SATS_CURRENCY).then_some(Some(price))
            }
        }
    }

    /// A record's value, checked as the page reads it (SPEC.md §30, Reading a record): version 1 or
    /// 2; above, a newer format.
    pub(crate) fn parse_checkout_value(value: &Json) -> Parsed<CheckoutRecord> {
        if !value.is_object() {
            return Ok(None);
        }
        let version = value.get("version").and_then(Json::as_f64);
        if version.is_some_and(|version| version > CHECKOUT_ONCHAIN_VERSION) {
            return Err(Newer);
        }
        let onchain = version == Some(CHECKOUT_ONCHAIN_VERSION);
        if !onchain && version != Some(CHECKOUT_VERSION) {
            return Ok(None);
        }
        Ok(read_checkout_value(value, onchain))
    }

    fn read_checkout_value(value: &Json, onchain: bool) -> Option<CheckoutRecord> {
        let business_name = value.get("businessName")?.as_str().filter(|name| is_business_name(name))?;
        let invoice = value.get("invoice");
        let verify_url = value.get("verifyUrl");
        let mut lightning: Option<(String, String, String, u64, i64, i64)> = None;
        if !onchain || !invoice.is_some_and(Json::is_null) || !verify_url.is_some_and(Json::is_null) {
            let invoice = invoice?.as_str()?;
            let (decoded, sats) = bolt11::decode_mainnet(invoice)?;
            let verify_url = verify_url?.as_str().filter(|url| parse_https_url(url).is_some())?;
            lightning = Some((
                invoice.to_owned(),
                verify_url.to_owned(),
                decoded.payment_hash.clone(),
                sats,
                decoded.timestamp,
                decoded.expires_at(),
            ));
        }
        let mut onchain_address = None;
        let mut rest = None;
        let mut bitcoin_node = None;
        let (sats, created_at, expires_at) = if onchain {
            let address =
                value.get("onchainAddress")?.as_str().filter(|address| is_deposit_address(address))?;
            let sats = value.get("sats")?.as_safe_integer().and_then(|sats| u64::try_from(sats).ok())?;
            if !(1..=MAX_SATS).contains(&sats) {
                return None;
            }
            let created_at = value.get("createdAt")?.as_safe_integer()?;
            let expires_at = value.get("expiresAt")?.as_safe_integer()?;
            if created_at >= expires_at {
                return None;
            }
            if let Some((_, _, _, invoice_sats, invoice_created, invoice_expires)) = &lightning
                && (*invoice_sats != sats || *invoice_created != created_at || *invoice_expires != expires_at)
            {
                return None;
            }
            onchain_address = Some(address.to_owned());
            let (author, key) = (value.get("restAuthor"), value.get("restKey"));
            if author.is_some() || key.is_some() {
                let author = author?.as_str().filter(|author| is_public_key(author))?;
                let key = key?.as_str().filter(|key| is_hex32(key))?;
                rest = Some(RestReader { author: author.to_owned(), key: key.to_owned() });
            }
            // Invalid in any way (null included), set aside: the page reads mempool.space, and the
            // record stays valid. In version 1, ignored.
            bitcoin_node = record_node_of(value.get("bitcoinNode"));
            (sats, created_at, expires_at)
        } else {
            let (_, _, _, sats, created_at, expires_at) = lightning.as_ref()?;
            (*sats, *created_at, *expires_at)
        };
        let fiat = checkout_price(value.get("fiat"))?;
        let note = value.get("note")?.as_str()?;
        if has_control_character(note) || !(1..=MAX_NOTE_LENGTH).contains(&code_point_len(note)) {
            return None;
        }
        let redirect_url = match value.get("redirectUrl")? {
            Json::Null => None,
            url => Some(url.as_str()?.to_owned()),
        };
        let redirect = match &redirect_url {
            Some(url) => Some(redirect_shown(url)?),
            None => None,
        };
        let (invoice, verify_url, payment_hash) = match lightning {
            Some((invoice, verify_url, payment_hash, ..)) => {
                (Some(invoice), Some(verify_url), Some(payment_hash))
            }
            None => (None, None, None),
        };
        Some(CheckoutRecord {
            business_name: business_name.to_owned(),
            invoice,
            payment_hash,
            verify_url,
            onchain_address,
            sats,
            created_at,
            expires_at,
            fiat,
            note: note.to_owned(),
            redirect_url,
            redirect_shown: redirect,
            rest,
            bitcoin_node,
        })
    }
}
