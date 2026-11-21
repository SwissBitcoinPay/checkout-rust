//! The few parts of the WHATWG URL standard that decide what goes on the wire, so that a request
//! of this crate asks exactly what checkout-node's (`fetch`, the `ws` package) asks for the same
//! checked URL: the path's dot segments resolved and its characters percent-encoded as the
//! standard does for a special scheme (`https`, `wss`), the query's (`'` is `%27`), the fragment
//! never sent, the default port (443) left out, and query parameters set as `URLSearchParams`
//! sets them (`application/x-www-form-urlencoded`).
//!
//! Only checked URLs come here (SPEC.md §9, §15): a host in lower case, a port of 1 to 65535. Of
//! a merchant's Bitcoin node (SPEC.md §31), `http` and `ws` too, whose default port is 80, to a host
//! of its own rule ([`Target::of_node`]).

use std::fmt::Write as _;

/// Whether `byte` (of the UTF-8 of a path) is percent-encoded in a special URL's path: the C0
/// controls, space, `"`, `#`, `<`, `>`, `?`, `` ` ``, `{`, `}`, DEL and every non-ASCII byte.
fn in_path_set(byte: u8) -> bool {
    !(0x21..=0x7e).contains(&byte) || matches!(byte, b'"' | b'#' | b'<' | b'>' | b'?' | b'`' | b'{' | b'}')
}

/// Whether `byte` (of the UTF-8 of a query) is percent-encoded in a special URL's query: the C0
/// controls, space, `"`, `#`, `<`, `>`, `'`, DEL and every non-ASCII byte.
fn in_query_set(byte: u8) -> bool {
    !(0x21..=0x7e).contains(&byte) || matches!(byte, b'"' | b'#' | b'<' | b'>' | b'\'')
}

fn percent_encode(text: &str, encode: fn(u8) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if encode(byte) {
            let _ = write!(out, "%{byte:02X}");
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

fn is_single_dot(segment: &str) -> bool {
    segment == "." || segment.eq_ignore_ascii_case("%2e")
}

fn is_double_dot(segment: &str) -> bool {
    matches!(segment.to_ascii_lowercase().as_str(), ".." | ".%2e" | "%2e." | "%2e%2e")
}

/// A special URL's path as the standard writes it: `\` read as `/`, its `.` and `..` segments
/// resolved, its characters percent-encoded. `path` is empty or starts with `/`.
pub(crate) fn path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut segments: Vec<String> = Vec::new();
    let parts: Vec<&str> = if path.is_empty() { vec![""] } else { path[1..].split('/').collect() };
    let last = parts.len() - 1;
    for (index, segment) in parts.iter().enumerate() {
        let at_end = index == last;
        if is_double_dot(segment) {
            segments.pop();
            if at_end {
                segments.push(String::new());
            }
        } else if is_single_dot(segment) {
            if at_end {
                segments.push(String::new());
            }
        } else {
            segments.push(percent_encode(segment, in_path_set));
        }
    }
    format!("/{}", segments.join("/"))
}

/// A special URL's query as the standard writes it.
pub(crate) fn query(query: &str) -> String {
    percent_encode(query, in_query_set)
}

/// An https or wss URL, checked, in the parts a request needs; or a URL of a merchant's Bitcoin
/// node (`http`, `https`, `ws` or `wss`, [`Target::of_node`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    /// `https` or `wss`; for a merchant's Bitcoin node, `http` or `ws` too.
    pub(crate) scheme: &'static str,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The path as the standard writes it, never empty.
    pub(crate) path: String,
    /// The query without its `?`, as the standard writes it; `None` without one.
    pub(crate) query: Option<String>,
}

impl Target {
    /// `url`, a checked `https://` or `wss://` URL, in its parts; its fragment (from its first
    /// `#`) dropped. `None` for another scheme or an authority that is not a host and a port.
    pub(crate) fn of(url: &str) -> Option<Self> {
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            ("https", rest)
        } else {
            ("wss", url.strip_prefix("wss://")?)
        };
        Self::parts(scheme, rest, |authority| {
            crate::urls::authority_of(authority).map(|authority| (authority.host, authority.port))
        })
    }

    /// `url`, a URL under a merchant's Bitcoin node's (SPEC.md §31: what the explorer reads at
    /// `<url>/api` and `<url>`'s WebSocket), in its parts: `https` or `wss` to a host of the node's
    /// rule (an IPv4 address, or a name), or `http` or `ws` to a local one only
    /// ([`crate::onchain::node::node_authority`]); its fragment dropped. `None` for anything
    /// else: never plain HTTP to a host that is not local.
    pub(crate) fn of_node(url: &str) -> Option<Self> {
        let (scheme, rest) = [("https", "https://"), ("http", "http://"), ("wss", "wss://"), ("ws", "ws://")]
            .into_iter()
            .find_map(|(scheme, prefix)| Some((scheme, url.strip_prefix(prefix)?)))?;
        let secure = matches!(scheme, "https" | "wss");
        Self::parts(scheme, rest, |authority| {
            crate::onchain::node::node_authority(authority, secure)
                .map(|authority| (authority.host, authority.port))
        })
    }

    /// What follows `<scheme>://`, its authority checked by `authority_of`.
    fn parts(
        scheme: &'static str,
        rest: &str,
        authority_of: impl FnOnce(&str) -> Option<(String, u16)>,
    ) -> Option<Self> {
        let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
        let authority_end = rest.find(['/', '?', '\\']).unwrap_or(rest.len());
        let (host, port) = authority_of(&rest[..authority_end])?;
        let rest = &rest[authority_end..];
        let (path_part, query) = match rest.split_once('?') {
            Some((path_part, query)) => (path_part, Some(self::query(query))),
            None => (rest, None),
        };
        Some(Self { scheme, host, port, path: path(path_part), query })
    }

    /// Whether it goes over TLS: `https` and `wss`, never `http` nor `ws`.
    pub(crate) fn is_secure(&self) -> bool {
        matches!(self.scheme, "https" | "wss")
    }

    /// The `Host` header: the host, and the port when it is not the scheme's default (443, or 80
    /// in clear).
    pub(crate) fn authority(&self) -> String {
        let default = if self.is_secure() { 443 } else { 80 };
        if self.port == default { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }

    /// The request target: the path and the query.
    pub(crate) fn path_and_query(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }

    /// The URL as the standard serializes it.
    pub(crate) fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority(), self.path_and_query())
    }

    /// Sets the query parameter `name` to `value` as `URLSearchParams.set` does: the first pair of
    /// that name takes the value and the others go, else the pair is added at the end; the whole
    /// query is then written again as `application/x-www-form-urlencoded`.
    pub(crate) fn set_query_parameter(&mut self, name: &str, value: &str) {
        let mut pairs = parse_form(self.query.as_deref().unwrap_or(""));
        match pairs.iter().position(|(key, _)| key == name) {
            Some(first) => {
                pairs[first].1 = value.to_owned();
                let mut index = 0;
                pairs.retain(|(key, _)| {
                    let keep = key != name || index == first;
                    index += 1;
                    keep
                });
            }
            None => pairs.push((name.to_owned(), value.to_owned())),
        }
        self.query = Some(serialize_form(&pairs));
    }
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let hex = |at: usize| bytes.get(at).and_then(|&digit| char::from(digit).to_digit(16));
        if byte == b'%'
            && let (Some(high), Some(low)) = (hex(index + 1), hex(index + 2))
        {
            out.push((high * 16 + low) as u8);
            index += 3;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    out
}

/// `application/x-www-form-urlencoded` parsing: the pairs of a query, `+` read as a space, then
/// percent-decoded, then UTF-8 decoded (an invalid byte read as U+FFFD, as the standard does).
fn parse_form(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|sequence| !sequence.is_empty())
        .map(|sequence| {
            let (name, value) = sequence.split_once('=').unwrap_or((sequence, ""));
            let decode =
                |part: &str| String::from_utf8_lossy(&percent_decode(&part.replace('+', " "))).into_owned();
            (decode(name), decode(value))
        })
        .collect()
}

fn serialize_form_part(text: &str, out: &mut String) {
    for &byte in text.as_bytes() {
        match byte {
            b'*' | b'-' | b'.' | b'_' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => out.push(char::from(byte)),
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
}

/// `application/x-www-form-urlencoded` serialization.
fn serialize_form(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        serialize_form_part(name, &mut out);
        out.push('=');
        serialize_form_part(value, &mut out);
    }
    out
}

/// The query parameters of `url`, as `URLSearchParams` reads them.
#[cfg(test)]
pub(crate) fn query_parameters(url: &str) -> Vec<(String, String)> {
    let query =
        url.split_once('#').map_or(url, |(before, _)| before).split_once('?').map_or("", |(_, query)| query);
    parse_form(query)
}

/// The value of the query parameter `name` (the first), as `URLSearchParams.get` reads it.
#[cfg(test)]
pub(crate) fn query_parameter(url: &str, name: &str) -> Option<String> {
    query_parameters(url).into_iter().find(|(key, _)| key == name).map(|(_, value)| value)
}
