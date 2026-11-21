//! Lists of Nostr relays, as the merchant's app writes them (SPEC.md §9): every address a `wss://`
//! URL in its one spelling, 1 to 10 of them, none twice. A list that is not so is refused, never
//! repaired.

use crate::encoding::from_base64url;
use crate::json::Json;
use crate::protocol::{MAX_RELAY_URL_LENGTH, MAX_RELAYS};
use crate::text::{code_point_len, decode_utf8};
use crate::urls::{is_host, is_port};

const PREFIX: &str = "wss://";

/// Whether `character` may be in a relay address's path: anything but ECMAScript's whitespace
/// (the merchant's app checks with JavaScript's `\s`), `?`, `#` and `,`.
fn is_path_character(character: char) -> bool {
    !matches!(
        character,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
            | '?'
            | '#'
            | ','
    )
}

/// Whether `url` is a relay address in its one spelling: `wss://`, a host (lower case, not
/// `localhost` nor a name under it, never an IP address), an optional port (1 to 65535) and an
/// optional path without a trailing slash, 120 code points at most.
pub(crate) fn is_relay_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix(PREFIX) else {
        return false;
    };
    // The host ends at the first `:` or `/`.
    let host_end = rest.find([':', '/']).unwrap_or(rest.len());
    let (host, rest) = rest.split_at(host_end);
    let (port, path) = match rest.strip_prefix(':') {
        Some(after) => {
            let end = after.find('/').unwrap_or(after.len());
            let (digits, path) = after.split_at(end);
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            (Some(digits), path)
        }
        None => (None, rest),
    };
    if !path.is_empty()
        && (!path.starts_with('/') || path.ends_with('/') || !path.chars().all(is_path_character))
    {
        return false;
    }
    is_host(host) && is_port(port) && code_point_len(url) <= MAX_RELAY_URL_LENGTH
}

/// A valid list of relay addresses (1 to 10, each in its one spelling, none twice), else `None`.
pub(crate) fn relay_list<'a>(addresses: impl IntoIterator<Item = &'a str>) -> Option<Vec<String>> {
    let mut list: Vec<String> = Vec::new();
    for address in addresses {
        if list.len() == MAX_RELAYS || !is_relay_url(address) || list.iter().any(|relay| relay == address) {
            return None;
        }
        list.push(address.to_owned());
    }
    (!list.is_empty()).then_some(list)
}

/// A relay list a record holds (a JSON array of strings), else `None`: a string holding a lone
/// surrogate is no relay address (SPEC.md §6).
pub(crate) fn relay_list_of(value: &Json) -> Option<Vec<String>> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_RELAYS {
        return None;
    }
    let texts: Option<Vec<&str>> = items.iter().map(Json::as_str).collect();
    relay_list(texts?)
}

/// The list of a key's part (and of a checkout link's): base64url of the UTF-8 of the hosts
/// without `wss://`, joined by `,`. UTF-8 is decoded strictly: a byte order mark stays U+FEFF,
/// which is no host.
pub(crate) fn decode_relay_list(text: &str) -> Option<Vec<String>> {
    let bytes = from_base64url(text)?;
    if bytes.is_empty() {
        return None;
    }
    let decoded = decode_utf8(&bytes)?;
    let addresses: Vec<String> = decoded.split(',').map(|host| format!("{PREFIX}{host}")).collect();
    relay_list(addresses.iter().map(String::as_str))
}

/// A list as a key's part writes it: the hosts without `wss://`, joined by `,`, in base64url.
pub(crate) fn encode_relay_list(relays: &[String]) -> String {
    let hosts: Vec<&str> = relays.iter().map(|relay| relay.strip_prefix(PREFIX).unwrap_or(relay)).collect();
    crate::encoding::to_base64url(hosts.join(",").as_bytes())
}
