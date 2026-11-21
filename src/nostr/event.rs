//! Nostr events (NIP-01; SPEC.md §11): their id, their BIP-340 signature, and the checks of an
//! event a relay sent. A relay is never trusted: an event is used only once it checks out.

use crate::derive::sha256;
use crate::json::{Json, JsonString, number_to_string, write_string};
use crate::runtime::{Random, random32};
use crate::secret::Secret;
use crate::text::{from_hex, from_hex32, is_hex32, is_hex64, to_hex};

/// A signed event (NIP-01), checked or made here: its strings well-formed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Event {
    /// Hex SHA-256 of the serialized event.
    pub(crate) id: String,
    /// Hex x-only public key of the author.
    pub(crate) pubkey: String,
    /// Unix seconds: a safe integer.
    pub(crate) created_at: i64,
    /// An integer (30078, 22242: whatever a relay wrote, as a double).
    pub(crate) kind: f64,
    pub(crate) tags: Vec<Vec<String>>,
    pub(crate) content: String,
    /// Hex BIP-340 signature of `id`.
    pub(crate) sig: String,
}

/// What an event says, before it is signed.
pub(crate) struct EventTemplate {
    pub(crate) created_at: i64,
    pub(crate) kind: f64,
    pub(crate) tags: Vec<Vec<String>>,
    pub(crate) content: String,
}

impl Event {
    /// The event as it is sent: `{kind, created_at, tags, content, id, pubkey, sig}`.
    pub(crate) fn to_json(&self) -> Json {
        Json::object([
            ("kind", Json::Number(self.kind)),
            ("created_at", Json::integer(self.created_at)),
            (
                "tags",
                Json::array(
                    self.tags
                        .iter()
                        .map(|tag| Json::array(tag.iter().map(|item| Json::from(item.as_str())).collect()))
                        .collect(),
                ),
            ),
            ("content", Json::from(self.content.as_str())),
            ("id", Json::from(self.id.as_str())),
            ("pubkey", Json::from(self.pubkey.as_str())),
            ("sig", Json::from(self.sig.as_str())),
        ])
    }

    /// The value of its first tag named `name`, if it has one.
    #[cfg(test)]
    pub(crate) fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some(name))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
    }
}

/// The event id: SHA-256 of the UTF-8 of its serialization ([`serialized_event`]).
pub(crate) fn event_hash(
    pubkey: &str,
    created_at: i64,
    kind: f64,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    sha256(serialized_event(pubkey, created_at, kind, tags, content).as_bytes())
}

/// What an event's id hashes (SPEC.md §11): `[0, pubkey, created_at, kind, tags, content]`, written
/// as `JSON.stringify` writes it (NIP-01: no whitespace; numbers as integers, whatever their
/// spelling in what the relay sent; `"` and `\` escaped, U+0008, U+0009, U+000A, U+000C and U+000D
/// as `\b`, `\t`, `\n`, `\f` and `\r`, any other character below U+0020 as `\u` and four
/// lowercase hex digits, every other character as it is).
pub(crate) fn serialized_event(
    pubkey: &str,
    created_at: i64,
    kind: f64,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let mut text = String::with_capacity(content.len() + 256);
    text.push_str("[0,");
    write_string(&mut text, &JsonString::Text(pubkey.to_owned()));
    text.push(',');
    text.push_str(&number_to_string(created_at as f64));
    text.push(',');
    text.push_str(&number_to_string(kind));
    text.push_str(",[");
    for (index, tag) in tags.iter().enumerate() {
        if index > 0 {
            text.push(',');
        }
        text.push('[');
        for (position, item) in tag.iter().enumerate() {
            if position > 0 {
                text.push(',');
            }
            write_string(&mut text, &JsonString::Text(item.clone()));
        }
        text.push(']');
    }
    text.push_str("],");
    write_string(&mut text, &JsonString::Text(content.to_owned()));
    text.push(']');
    text
}

/// Signs `template` with `secret` (BIP-340, 32 fresh random bytes of auxiliary data, as the BIP
/// recommends).
pub(crate) fn sign_event(template: EventTemplate, secret: &Secret, random: &dyn Random) -> Event {
    let public = crate::secp::x_only_public_key(secret.expose())
        .expect("events are signed by secret keys of the curve");
    let pubkey = to_hex(&public);
    let hash = event_hash(&pubkey, template.created_at, template.kind, &template.tags, &template.content);
    let aux = random32(random);
    let signature = crate::secp::sign(&hash, secret.expose(), &aux).expect("a secret key of the curve signs");
    Event {
        id: to_hex(&hash),
        pubkey,
        created_at: template.created_at,
        kind: template.kind,
        tags: template.tags,
        content: template.content,
        sig: to_hex(&signature),
    }
}

/// `value` as an event whose id is its hash (SPEC.md §11), its signature not checked yet: `id`
/// and `pubkey` hex32, `sig` 128 lowercase hex characters, `created_at` a safe integer, `kind` an
/// integer, `content` a string, `tags` an array of arrays of strings, no string of `content` or
/// `tags` holding a lone surrogate (its UTF-8, which the hash needs, does not exist). What is
/// checked of a record before anything else where anybody may write (SPEC.md §31, Opening a
/// lease); its signature only where it decides.
pub(crate) fn has_valid_id(value: &Json) -> Option<Event> {
    let id = value.get("id")?.as_str().filter(|id| is_hex32(id))?;
    let pubkey = value.get("pubkey")?.as_str().filter(|key| is_hex32(key))?;
    let sig = value.get("sig")?.as_str().filter(|sig| is_hex64(sig))?;
    let created_at = value.get("created_at")?.as_safe_integer()?;
    let kind = value.get("kind")?.as_integer()?;
    let content = value.get("content")?.as_str()?;
    let tags = value
        .get("tags")?
        .as_array()?
        .iter()
        .map(|tag| {
            tag.as_array()?
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
        })
        .collect::<Option<Vec<Vec<String>>>>()?;
    let hash = event_hash(pubkey, created_at, kind, &tags, content);
    (to_hex(&hash) == id).then(|| Event {
        id: id.to_owned(),
        pubkey: pubkey.to_owned(),
        created_at,
        kind,
        tags,
        content: content.to_owned(),
        sig: sig.to_owned(),
    })
}

/// Whether the signature `sig` of the event `id` by `pubkey` (all hex, checked) verifies.
pub(crate) fn signature_checks(id: &str, pubkey: &str, sig: &str) -> bool {
    let (Some(id), Some(pubkey), Some(sig)) = (from_hex32(id), from_hex32(pubkey), from_hex(sig)) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    crate::secp::verify(&sig, &id, &pubkey)
}

/// `value` as an event that checks out: its id is its hash and its signature verifies.
#[cfg(test)]
pub(crate) fn valid_event(value: &Json) -> Option<Event> {
    let event = has_valid_id(value)?;
    signature_checks(&event.id, &event.pubkey, &event.sig).then_some(event)
}
