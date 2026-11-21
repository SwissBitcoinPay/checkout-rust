//! Sealed records, as the merchant's app writes and reads them (SPEC.md §12): one addressable
//! event of kind 30078 (NIP-78), an opaque `d` tag, a NIP-44 v2 content whose plaintext
//! `{"t": <type>, "v": <value>}` is padded with spaces to a multiple of 256 bytes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::json::{self, Json};
use crate::nostr::event::{Event, EventTemplate, has_valid_id, sign_event, signature_checks};
use crate::nostr::nip44::{self, Nip44Error};
use crate::nostr::relay::{Answers, Keep};
use crate::protocol::{RECORD_BLOCK_BYTES, RECORD_KIND};
use crate::runtime::{Random, random32};
use crate::secret::Secret;
use crate::text::is_hex32;

/// A record of a newer format than this crate reads: authentic, but never used nor written over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Newer;

/// What a record's value reads as: valid, invalid (`Ok(None)`), or of a newer format.
pub(crate) type Parsed<T> = Result<Option<T>, Newer>;

/// What a record is sealed from.
pub(crate) struct Seal<'a> {
    pub(crate) record_type: &'a str,
    pub(crate) value: Json,
    /// Signs it: its author.
    pub(crate) signer: &'a Secret,
    /// The NIP-44 conversation key.
    pub(crate) encryption_key: &'a Secret,
    /// The `d` tag.
    pub(crate) address: &'a str,
    /// Unix seconds.
    pub(crate) created_at: i64,
    /// Tags after the `d` tag: an `expiration` (NIP-40), a witness's `o` tags.
    pub(crate) tags: Vec<Vec<String>>,
}

/// The plaintext of a record: `{"t": <type>, "v": <value>}`, then spaces up to the next multiple
/// of 256 bytes (none when it is one already).
pub(crate) fn plaintext(record_type: &str, value: &Json) -> String {
    let mut text = json::stringify(&Json::object([("t", Json::from(record_type)), ("v", value.clone())]));
    let length = text.len();
    let padded = length.div_ceil(RECORD_BLOCK_BYTES) * RECORD_BLOCK_BYTES;
    text.extend(std::iter::repeat_n(' ', padded - length));
    text
}

/// The signed event of a record; encryption and signature randomized. `None` when its plaintext
/// does not fit NIP-44 (65 535 bytes).
pub(crate) fn seal_record(seal: Seal<'_>, random: &dyn Random) -> Option<Event> {
    let text = plaintext(seal.record_type, &seal.value);
    let nonce = random32(random);
    let content = nip44::encrypt(&text, seal.encryption_key, &nonce)?;
    let mut tags = vec![vec!["d".to_owned(), seal.address.to_owned()]];
    tags.extend(seal.tags);
    Some(sign_event(
        EventTemplate { created_at: seal.created_at, kind: RECORD_KIND, tags, content },
        seal.signer,
        random,
    ))
}

/// A record that opened: its value, or of a newer format.
#[derive(Clone, Debug)]
pub(crate) enum Opened<T> {
    Valid {
        event: Event,
        value: T,
    },
    /// Authentic (its event checked out), but of a newer format.
    Newer {
        event: Event,
    },
}

/// What a record must be to open: its type, its key, its `d` tag and its author.
pub(crate) struct Expected<'a> {
    pub(crate) record_type: &'a str,
    pub(crate) encryption_key: &'a Secret,
    pub(crate) address: &'a str,
    /// Hex.
    pub(crate) author: &'a str,
}

/// The value inside a record's content: `Ok(Some(value))`, `Ok(None)` when it does not open or
/// is of another type, `Err(Newer)` for a content of a newer NIP-44 version.
fn read_content(content: &str, expected: &Expected<'_>) -> Result<Option<Json>, Newer> {
    let text = match nip44::decrypt(content, expected.encryption_key) {
        Ok(text) => text,
        Err(Nip44Error::UnknownVersion) => return Err(Newer),
        Err(Nip44Error::Invalid) => return Ok(None),
    };
    let Some(envelope) = json::parse(&text) else {
        return Ok(None);
    };
    if !envelope.is_object() || !envelope.has("v") {
        return Ok(None);
    }
    if envelope.get("t").and_then(Json::as_str) != Some(expected.record_type) {
        return Ok(None);
    }
    Ok(envelope.get("v").cloned())
}

/// Opens an event that checked out (its id and signature) as a record of `expected`, in the order
/// of SPEC.md §12: kind, author and `d` tag, then the content, then the value (`parse`).
pub(crate) fn open_event<T>(
    event: &Event,
    expected: &Expected<'_>,
    parse: impl FnOnce(&Json, &Event) -> Parsed<T>,
) -> Option<Opened<T>> {
    if event.kind != RECORD_KIND
        || event.pubkey != expected.author
        || !event.tags.iter().any(|tag| tag.len() >= 2 && tag[0] == "d" && tag[1] == expected.address)
    {
        return None;
    }
    let value = match read_content(&event.content, expected) {
        Err(Newer) => return Some(Opened::Newer { event: event.clone() }),
        Ok(None) => return None,
        Ok(Some(value)) => value,
    };
    match parse(&value, event) {
        Ok(Some(value)) => Some(Opened::Valid { event: event.clone(), value }),
        Ok(None) => None,
        Err(Newer) => Some(Opened::Newer { event: event.clone() }),
    }
}

/// Opens what a relay sent as a record of `expected` (SPEC.md §12): the cheap checks first, then
/// the content, then the event's id and signature (a newer format counts only once the event
/// checked out), then the value. `None` for anything else: a relay is never trusted. What the
/// pages of checkout links and the merchant's app do; the crate itself reads with
/// `records_that_open`, then `open_event`.
#[cfg(test)]
pub(crate) fn open_record<T>(
    value: &Json,
    expected: &Expected<'_>,
    parse: impl FnOnce(&Json, &Event) -> Parsed<T>,
) -> Option<Opened<T>> {
    if value.get("kind").and_then(Json::as_f64) != Some(RECORD_KIND)
        || value.get("pubkey").and_then(Json::as_str) != Some(expected.author)
        || !value.get("content").is_some_and(Json::is_string)
        || !value.get("tags").and_then(Json::as_array).is_some_and(|tags| {
            tags.iter().any(|tag| {
                tag.as_array().is_some_and(|tag| {
                    tag.first().and_then(Json::as_str) == Some("d")
                        && tag.get(1).and_then(Json::as_str) == Some(expected.address)
                })
            })
        })
    {
        return None;
    }
    let content = value.get("content").and_then(Json::as_str)?;
    // The cheap check before the signature: the content opens with the key, or is of a newer
    // NIP-44 version.
    if matches!(read_content(content, expected), Ok(None)) {
        return None;
    }
    let event = crate::nostr::event::valid_event(value)?;
    open_event(&event, expected, parse)
}

/// The `d` tag of a value a relay sent, when it is hex32 (its first `d` tag).
pub(crate) fn d_tag_of(value: &Json) -> Option<&str> {
    let tags = value.get("tags")?.as_array()?;
    let tag = tags
        .iter()
        .find(|tag| tag.as_array().and_then(|tag| tag.first()).and_then(Json::as_str) == Some("d"))?;
    tag.as_array()?.get(1)?.as_str().filter(|d| is_hex32(d))
}

/// The key a read opens a record with, from its `d` tag (hex32, else `None`) and its author:
/// `None` for an author or an address the read does not open.
pub(crate) type KeyOf = dyn Fn(Option<&str>, &str) -> Option<Secret> + Send + Sync;

/// What a read of sealed records keeps of each event (SPEC.md §13: the event, when it opens): an
/// event of kind 30078 whose content decrypts with the key of its first `d` tag and its author
/// (NIP-44 v2, its MAC checked), or is of a newer NIP-44 version, and that checks out (§11). Its
/// signature too: anybody may send a copy of a record under an id of its own, its content and
/// signature left as they are, and only the signature tells it from the record. Checked once per
/// id and signature, whatever relays send copies. Its value is not checked here: the read opens
/// what it keeps.
pub(crate) fn records_that_open(key_of: Arc<KeyOf>) -> Keep<Event> {
    let verified: Arc<Mutex<HashMap<(String, String), bool>>> = Arc::new(Mutex::new(HashMap::new()));
    Arc::new(move |value: &Json| {
        if value.get("kind").and_then(Json::as_f64) != Some(RECORD_KIND) {
            return None;
        }
        let content = value.get("content")?.as_json_string()?;
        let pubkey = value.get("pubkey")?.as_json_string()?;
        let key = key_of(d_tag_of(value), pubkey.as_str()?)?;
        // A content that holds a lone surrogate is no base64: it does not decrypt.
        match nip44::decrypt(content.as_str()?, &key) {
            Ok(_) | Err(Nip44Error::UnknownVersion) => {}
            Err(Nip44Error::Invalid) => return None,
        }
        let event = has_valid_id(value)?;
        let copy = (event.id.clone(), event.sig.clone());
        let known = verified.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&copy).copied();
        let valid = known.unwrap_or_else(|| {
            let valid = signature_checks(&event.id, &event.pubkey, &event.sig);
            verified.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(copy, valid);
            valid
        });
        valid.then_some(event)
    })
}

/// Whether `a` replaces `b` as relays keep them: a later `created_at`, then the lowest id
/// (NIP-01).
pub(crate) fn replaces(a: &Event, b: &Event) -> bool {
    a.created_at > b.created_at || (a.created_at == b.created_at && a.id < b.id)
}

/// The newest of the records relays sent.
pub(crate) struct Newest<T> {
    pub(crate) newest: Option<(Event, T)>,
    /// The `created_at` of the newest copy of a newer format.
    pub(crate) newest_unreadable: Option<i64>,
}

/// Reads the answers of a query: each copy opened with `open`, once per event id that checked out
/// (a copy with the id of one already opened is the same event); the newest by `created_at` wins
/// (on a tie, the lowest id: the one relays keep).
pub(crate) fn newest_record<T>(
    answers: &Answers<Event>,
    open: impl Fn(&Event) -> Option<Opened<T>>,
) -> Newest<T> {
    let mut checked: HashSet<String> = HashSet::new();
    let mut newest: Option<(Event, T)> = None;
    let mut newest_unreadable: Option<i64> = None;
    for (_, events) in answers {
        for event in events {
            if checked.contains(&event.id) {
                continue;
            }
            let Some(copy) = open(event) else { continue };
            checked.insert(event.id.clone());
            match copy {
                Opened::Newer { event } => {
                    newest_unreadable =
                        Some(newest_unreadable.map_or(event.created_at, |at| at.max(event.created_at)));
                }
                Opened::Valid { event, value } => {
                    if newest.as_ref().is_none_or(|(current, _)| replaces(&event, current)) {
                        newest = Some((event, value));
                    }
                }
            }
        }
    }
    Newest { newest, newest_unreadable }
}
