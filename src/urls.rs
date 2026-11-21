//! Hosts and https URLs, in their one spelling (SPEC.md §9, §15, §30): what the crate asks over
//! the network (relays, the Lightning address's pay URL, its callback and verify URLs) and what a
//! checkout link sends the customer to. Nothing is repaired: a URL that is not so is refused, so
//! that no request goes to an IP address, to the machine itself (`localhost` and the names under
//! it, RFC 6761) or to a host other than the one checked.

use crate::protocol::{MAX_HOST_LENGTH, MAX_HTTPS_URL_LENGTH};

/// Whether `host` is a host as in a relay address: labels of `a–z 0–9 -` separated by `.`, at
/// least two, the last of at least two letters `a–z` and not `localhost`; at most 253
/// characters. So never an IP address, never upper case.
pub(crate) fn is_host(host: &str) -> bool {
    if host.len() > MAX_HOST_LENGTH {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let Some((last, others)) = labels.split_last() else {
        return false;
    };
    !others.is_empty()
        && others.iter().all(|label| {
            !label.is_empty() && label.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        })
        && last.len() >= 2
        && last.bytes().all(|byte| byte.is_ascii_lowercase())
        && *last != "localhost"
}

/// Whether `port` (its digits, absent when the URL names none) is absent or 1 to 65535. Its
/// digits were checked: 1 to 5 of them (`00080` is 80, as JavaScript's `Number` reads it).
pub(crate) fn is_port(port: Option<&str>) -> bool {
    port.is_none_or(|digits| digits.parse::<u32>().is_ok_and(|number| (1..=65_535).contains(&number)))
}

/// Whether `character` is one a redirect URL and an https URL may hold, but for `%`: RFC 3986's
/// unreserved and reserved characters.
fn is_url_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=".contains(&byte)
}

/// Whether `text` is 1 or more characters a redirect URL may hold (SPEC.md §30): RFC 3986's, or
/// `%` followed by two hex digits.
pub(crate) fn has_url_characters(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let (Some(high), Some(low)) = (bytes.get(index + 1), bytes.get(index + 2)) else {
                return false;
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }
            index += 3;
        } else if is_url_character(bytes[index]) {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

/// An https URL's host and port: 443 when it names none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpsUrl {
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// The host and the port of an authority (what follows `scheme://` up to the first `/`, `?` or
/// `#`): a host as in a relay address, then nothing or `:` and 1 to 5 digits (1 to 65535).
pub(crate) fn authority_of(authority: &str) -> Option<HttpsUrl> {
    let (host, port) = match authority.split_once(':') {
        Some((host, digits)) => {
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            (host, Some(digits))
        }
        None => (authority, None),
    };
    if !is_host(host) || !is_port(port) {
        return None;
    }
    let port = port.map_or(Some(443), |digits| digits.parse().ok())?;
    Some(HttpsUrl { host: host.to_owned(), port })
}

/// `value` as an https URL (SPEC.md §15, rule 1 of a redirect URL): 1 to 2048 characters a
/// redirect URL may hold, `https://`, a host, an optional port, then nothing, or `/`, `?` or `#`
/// followed by anything. So no upper case in the scheme or the host, no user name nor password,
/// no IP address, no whitespace, no `\`. `None` when it is not one.
pub(crate) fn parse_https_url(value: &str) -> Option<HttpsUrl> {
    if value.len() > MAX_HTTPS_URL_LENGTH || !has_url_characters(value) {
        return None;
    }
    let rest = value.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    authority_of(&rest[..end])
}

/// Whether two https URLs are on the same host: their hosts and their ports are equal.
pub(crate) fn same_host(a: &HttpsUrl, b: &HttpsUrl) -> bool {
    a == b
}
