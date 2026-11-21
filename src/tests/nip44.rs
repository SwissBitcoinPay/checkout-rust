//! NIP-44 v2 against the official vectors (https://github.com/paulmillr/nip44, the app's copy in
//! spec/vectors/nip44/), and what SPEC.md §6 and §12 add: a plaintext's byte order mark is kept,
//! and a record whose plaintext starts with one is no JSON.

use super::support::vectors::{Field, spec};
use crate::derive::public_key_of;
use crate::json::Json;
use crate::nostr::event::{EventTemplate, sign_event};
use crate::nostr::nip44::{Nip44Error, conversation_key, decrypt, encrypt, message_keys, padded_len};
use crate::nostr::record::{Expected, Opened, Seal, open_record, seal_record};
use crate::runtime::{OsRandom, random32};
use crate::secret::Secret;
use crate::text::to_hex;

fn vectors() -> Json {
    spec("vectors/nip44/nip44.vectors.json")
}

fn random_secret() -> Secret {
    loop {
        let bytes = random32(&OsRandom);
        if crate::secp::is_secret_key(&bytes) {
            return Secret::new(bytes);
        }
    }
}

#[test]
fn pads_plaintexts_to_the_spec_lengths() {
    let vectors = vectors();
    let cases = vectors.list("calc_padded_len");
    assert!(!cases.is_empty());
    for case in cases {
        let pair = case.as_array().unwrap();
        let length = pair[0].as_safe_integer().unwrap() as usize;
        let padded = pair[1].as_safe_integer().unwrap() as usize;
        assert_eq!(padded_len(length), padded, "{length}");
    }
}

#[test]
fn derives_the_spec_conversation_keys_and_refuses_invalid_ones() {
    let vectors = vectors();
    let valid = vectors.list("get_conversation_key");
    assert!(!valid.is_empty());
    for case in valid {
        let key = conversation_key(&case.secret("sec1"), case.text("pub2")).expect("a conversation key");
        assert_eq!(to_hex(key.expose()), case.text("conversation_key"));
    }
    let invalid = vectors.list("invalid_get_conversation_key");
    assert!(!invalid.is_empty());
    for case in invalid {
        assert!(conversation_key(&case.secret("sec1"), case.text("pub2")).is_none(), "{}", case.text("note"));
    }
}

#[test]
fn gives_both_parties_the_same_conversation_key() {
    let a = random_secret();
    let b = random_secret();
    let ab = conversation_key(&a, &public_key_of(&b)).unwrap();
    let ba = conversation_key(&b, &public_key_of(&a)).unwrap();
    assert_eq!(ab.expose(), ba.expose());
}

#[test]
fn derives_the_spec_message_keys() {
    let vectors = vectors();
    let message = vectors.field("get_message_keys");
    let key = message.secret("conversation_key");
    let cases = message.list("keys");
    assert!(!cases.is_empty());
    for case in cases {
        let keys = message_keys(&key, &case.hex32("nonce"));
        assert_eq!(to_hex(&keys.chacha_key), case.text("chacha_key"));
        assert_eq!(to_hex(&keys.chacha_nonce), case.text("chacha_nonce"));
        assert_eq!(to_hex(&keys.hmac_key), case.text("hmac_key"));
    }
}

#[test]
fn encrypts_and_decrypts_the_spec_payloads() {
    let vectors = vectors();
    let cases = vectors.list("encrypt_decrypt");
    assert!(!cases.is_empty());
    for case in cases {
        let key = case.secret("conversation_key");
        let plaintext = case.text("plaintext");
        assert_eq!(encrypt(plaintext, &key, &case.hex32("nonce")).as_deref(), Some(case.text("payload")));
        assert_eq!(decrypt(case.text("payload"), &key).as_deref(), Ok(plaintext));
    }
}

#[test]
fn refuses_the_spec_invalid_payloads_telling_another_version_apart() {
    let vectors = vectors();
    let cases = vectors.list("invalid_decrypt");
    assert!(!cases.is_empty());
    for case in cases {
        assert!(
            decrypt(case.text("payload"), &case.secret("conversation_key")).is_err(),
            "{}",
            case.text("note")
        );
    }
    assert_eq!(decrypt("#future", &Secret::new([0; 32])), Err(Nip44Error::UnknownVersion));
}

#[test]
fn keeps_a_plaintext_leading_byte_order_mark_utf8_is_decoded_strictly() {
    let key = Secret::new(random32(&OsRandom));
    let payload = encrypt("\u{feff}{}", &key, &random32(&OsRandom)).unwrap();
    assert_eq!(decrypt(&payload, &key).as_deref(), Ok("\u{feff}{}"));
}

#[test]
fn opens_no_record_whose_plaintext_starts_with_a_byte_order_mark_not_json() {
    let signer = Secret::new([3; 32]);
    let encryption_key = Secret::new([4; 32]);
    let address = "ab".repeat(32);
    let created_at = 1_791_378_000;
    let author = public_key_of(&signer);
    let expected =
        Expected { record_type: "t", encryption_key: &encryption_key, address: &address, author: &author };
    let open = |value: &Json| open_record(value, &expected, |value, _| Ok(Some(value.clone())));
    let sealed = seal_record(
        Seal {
            record_type: "t",
            value: Json::unsigned(1),
            signer: &signer,
            encryption_key: &encryption_key,
            address: &address,
            created_at,
            tags: Vec::new(),
        },
        &OsRandom,
    )
    .unwrap();
    match open(&sealed.to_json()) {
        Some(Opened::Valid { value, .. }) => assert_eq!(value, Json::unsigned(1)),
        other => panic!("{other:?}"),
    }
    // The same record, its plaintext after a byte order mark, signed by its author.
    let mut plaintext = format!("\u{feff}{}", r#"{"t":"t","v":1}"#);
    while plaintext.encode_utf16().count() < 256 {
        plaintext.push(' ');
    }
    let event = sign_event(
        EventTemplate {
            created_at,
            kind: 30078.0,
            tags: vec![vec!["d".to_owned(), address.clone()]],
            content: encrypt(&plaintext, &encryption_key, &random32(&OsRandom)).unwrap(),
        },
        &signer,
        &OsRandom,
    );
    assert!(open(&event.to_json()).is_none());
}

#[test]
fn draws_a_fresh_nonce_each_time() {
    let key = Secret::new(random32(&OsRandom));
    let first = encrypt("Sunrise Bakery", &key, &random32(&OsRandom)).unwrap();
    let second = encrypt("Sunrise Bakery", &key, &random32(&OsRandom)).unwrap();
    assert_ne!(first, second);
}
