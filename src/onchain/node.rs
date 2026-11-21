//! The merchant's Bitcoin node (SPEC.md §31, The merchant's Bitcoin node): a node of its own that
//! serves mempool.space's API (an Umbrel, a server of its own), which the channel names
//! (`bitcoinNode`, §14) and the server then reads the blockchain from, rather than from
//! mempool.space. Its URL follows a rule of its own, not the https URL's (§15): `http` is allowed
//! for a host of a local network, and so is an IPv4 address. Nothing is repaired: a URL that is not
//! in its one spelling is no node URL, and the channel then names no node.

use crate::json::Json;
use crate::protocol::{MAX_HOST_LENGTH, MAX_NODE_URL_LENGTH};

/// What the server does when the node does not answer a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum NodeFallback {
    /// The same read of mempool.space.
    Mempool,
    /// Never mempool.space: while the node does not answer, nothing is judged on-chain.
    None,
}

impl NodeFallback {
    /// `"mempool"` or `"none"`, exactly; `None` for anything else (`"Mempool"`, `null`, absent).
    pub(crate) fn of(value: Option<&Json>) -> Option<Self> {
        match value?.as_str()? {
            "mempool" => Some(Self::Mempool),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// As the channel and a checkout link's record write it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mempool => "mempool",
            Self::None => "none",
        }
    }
}

/// The channel's `bitcoinNode`, valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BitcoinNode {
    /// A node URL ([`parse_node_url`]), as the channel writes it.
    pub(crate) url: String,
    pub(crate) fallback: NodeFallback,
    /// Whether the pages of checkout links read the node too (a node of the Internet only).
    pub(crate) payers: bool,
}

/// The node a checkout link's record names (SPEC.md §30): its URL and its fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordNode {
    pub(crate) url: String,
    pub(crate) fallback: NodeFallback,
}

impl RecordNode {
    /// `{"url": …, "fallback": …}`, as a record of version 2 holds it.
    pub(crate) fn to_json(&self) -> Json {
        Json::object([
            ("url", Json::from(self.url.as_str())),
            ("fallback", Json::from(self.fallback.as_str())),
        ])
    }
}

/// A node URL, checked: where the node is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeUrl {
    /// The URL, as written.
    pub(crate) url: String,
    /// `<url>/api`: the `<explorer>` of SPEC.md §31, Explorers.
    pub(crate) rest: String,
    /// `<url>` with `ws` for its leading `http`, then `/api/v1/ws`.
    pub(crate) websocket: String,
    /// Whether the host is of a local network: a local IPv4 range, or a name under `.local`.
    pub(crate) local: bool,
    /// Whether it is a node of the Internet: `https`, and a name whose last label is not `local`.
    pub(crate) internet: bool,
}

/// The four numbers of an IPv4 address, each from 0 to 255 without a leading zero (`0` alone is
/// one); `None` when `host` is not one.
pub(crate) fn ipv4_of(host: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = host.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        let leading_zero = part.len() > 1 && part.starts_with('0');
        if part.is_empty()
            || part.len() > 3
            || leading_zero
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    parts.next().is_none().then_some(octets)
}

/// Whether an IPv4 address is of a local range: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or
/// 100.64.0.0/10 (the shared address space of RFC 6598, which Tailscale uses).
fn is_local_ipv4([a, b, _, _]: [u8; 4]) -> bool {
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
}

/// Whether `label` is a label of a node's name: 1 to 63 of `a–z 0–9 -`, neither starting nor
/// ending with `-`.
fn is_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Whether `host` is a node's name: 2 labels or more, the last starting with a letter `a–z`, never
/// `localhost` nor a name under it; 253 characters at most. So no trailing dot, no empty label.
pub(crate) fn is_node_name(host: &str) -> bool {
    if host.len() > MAX_HOST_LENGTH {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let last = labels[labels.len() - 1];
    labels.len() >= 2
        && labels.iter().all(|label| is_label(label))
        && last.starts_with(|first: char| first.is_ascii_lowercase())
        && last != "localhost"
}

/// A node's host and port, checked (SPEC.md §31, A node URL): an IPv4 address (never in
/// 0.0.0.0/8 nor 127.0.0.0/8) or a name; `http` for a local host only. The scheme's default port
/// when the URL names none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeAuthority {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Whether the host is of a local network.
    pub(crate) local: bool,
    pub(crate) ipv4: bool,
}

/// The host and the port of a node URL's authority, with `secure` for `https` (or `wss`):
/// `<host>[:<port>]`, the port 1 to 5 digits without a leading zero, 1 to 65535. `None` when it
/// is not a node's, or when it is `http` (`secure` false) to a host that is not local.
pub(crate) fn node_authority(authority: &str, secure: bool) -> Option<NodeAuthority> {
    let (host, port) = match authority.split_once(':') {
        Some((host, digits)) => {
            let digits_ok = (1..=5).contains(&digits.len())
                && !digits.starts_with('0')
                && digits.bytes().all(|byte| byte.is_ascii_digit());
            if !digits_ok {
                return None;
            }
            (host, Some(digits.parse::<u32>().ok().filter(|port| *port <= 65_535)? as u16))
        }
        None => (authority, None),
    };
    let (local, ipv4) = match ipv4_of(host) {
        // Never the machine itself, nor "this network".
        Some([0 | 127, ..]) => return None,
        Some(octets) => (is_local_ipv4(octets), true),
        None if is_node_name(host) => (host.ends_with(".local"), false),
        None => return None,
    };
    if !secure && !local {
        return None;
    }
    let port = port.unwrap_or(if secure { 443 } else { 80 });
    Some(NodeAuthority { host: host.to_owned(), port, local, ipv4 })
}

/// Whether `path` (after the authority, empty when absent) is a node URL's: empty, or `/` and
/// visible ASCII but `?`, `#`, `@` and `\`, ending neither with `/` (so `/` alone is not one) nor
/// with `/api`, its case ignored (the node's URL, not its API's).
fn is_node_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    path.starts_with('/')
        && path
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && !matches!(byte, b'?' | b'#' | b'@' | b'\\'))
        && !path.ends_with('/')
        && !(path.len() >= 4 && path[path.len() - 4..].eq_ignore_ascii_case("/api"))
}

/// `value` as a node URL (SPEC.md §31, A node URL), with where the node is read; `None` when it
/// is not one. `<scheme>://<host>[:<port>][<path>]`, 200 characters at most: `https`, or `http`
/// for a local host; a host in lowercase, an IPv4 address (never in 0.0.0.0/8 nor 127.0.0.0/8) or
/// a name (never `localhost` nor under it); a port from 1 to 65535 without a leading zero; a path
/// that ends neither with `/` nor with `/api`. So no user name nor password, no query, no
/// fragment, no IPv6 address, no whitespace.
pub(crate) fn parse_node_url(value: &str) -> Option<NodeUrl> {
    // Longer than 200 characters, or any character beyond ASCII: never one (its host and path are
    // ASCII), so its length in bytes is its length in characters.
    if value.len() > MAX_NODE_URL_LENGTH || !value.is_ascii() {
        return None;
    }
    let (secure, rest) = match value.strip_prefix("https://") {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix("http://")?),
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    let authority = node_authority(authority, secure)?;
    if !is_node_path(path) {
        return None;
    }
    Some(NodeUrl {
        url: value.to_owned(),
        rest: format!("{value}/api"),
        websocket: format!("ws{}/api/v1/ws", &value["http".len()..]),
        local: authority.local,
        internet: secure && !authority.ipv4 && !authority.local,
    })
}

/// The channel's `bitcoinNode` (SPEC.md §14, §31): an object whose `url` is a node URL, whose
/// `fallback` is exactly `"mempool"` or `"none"` and whose `payers` is a JSON boolean, `true` only
/// for a node of the Internet; its other members ignored. `None` when it is absent or invalid in
/// any way: there is none, the server reads mempool.space, and the channel stays valid.
pub(crate) fn bitcoin_node_of(value: Option<&Json>) -> Option<BitcoinNode> {
    let value = value.filter(|value| value.is_object())?;
    let node = parse_node_url(value.get("url")?.as_str()?)?;
    let fallback = NodeFallback::of(value.get("fallback"))?;
    let payers = value.get("payers")?.as_bool()?;
    // A link must never make each customer's browser probe its own local network.
    if payers && !node.internet {
        return None;
    }
    Some(BitcoinNode { url: node.url, fallback, payers })
}

/// What a checkout link's record of version 2 holds of `node` (SPEC.md §30): its `url` and
/// `fallback`, copied as they are, never `payers`; `None` (the field absent) when the channel names
/// no node or its `payers` is false.
pub(crate) fn record_node_for(node: Option<&BitcoinNode>) -> Option<RecordNode> {
    node.filter(|node| node.payers).map(|node| RecordNode { url: node.url.clone(), fallback: node.fallback })
}

/// The node a page reads from a record of version 2's `bitcoinNode` (SPEC.md §30, Reading a
/// record): an object whose `url` is a node URL of a node of the Internet and whose `fallback` is
/// exactly `"mempool"` or `"none"` (its other members ignored); anything else (`null` included) is
/// set aside, the page reading mempool.space, and leaves the record valid.
#[cfg(test)]
pub(crate) fn record_node_of(value: Option<&Json>) -> Option<RecordNode> {
    let value = value.filter(|value| value.is_object())?;
    let node = parse_node_url(value.get("url")?.as_str()?).filter(|node| node.internet)?;
    let fallback = NodeFallback::of(value.get("fallback"))?;
    Some(RecordNode { url: node.url, fallback })
}
