//! A declaration (or a lease), opened as the merchant's app does: with the registry key and the
//! reading key.

use crate::derive::outer_key;
use crate::json::{self, Json};
use crate::nostr::event::Event;
use crate::nostr::nip44::{conversation_key, decrypt};
use crate::secret::Secret;

/// The inside of a declaration, opened as its owner: the outside with the outer key of its
/// address and author, then the sealed inside with the reading key.
pub(crate) fn open_as_owner(event: &Event, registry_key: &Secret, reader_secret: &Secret) -> Json {
    let address = event.tag("d").expect("a d tag");
    let outside =
        decrypt(&event.content, &outer_key(registry_key, address, &event.pubkey)).expect("the outside opens");
    let outside = json::parse(&outside).expect("JSON");
    assert_eq!(outside.get("t").and_then(Json::as_str), Some("registry-declaration"), "Not a declaration");
    let sealed = outside.get("v").and_then(|v| v.get("sealed")).and_then(Json::as_str).expect("sealed");
    let key = conversation_key(reader_secret, &event.pubkey).expect("a conversation key");
    json::parse(&decrypt(sealed, &key).expect("the inside opens")).expect("JSON")
}
