//! NIP-44 version 2 (<https://github.com/nostr-protocol/nips/blob/master/44.md>), as the
//! merchant's app implements it (SPEC.md §12): ChaCha20 (IETF, 12-byte nonce), HMAC-SHA256 over
//! the nonce and the ciphertext, per-message keys from a random 32-byte nonce, plaintext padded.
//! Checked against the official test vectors. A record's conversation key is a 32-byte HKDF
//! output used as it is, except inside a registry declaration: the ECDH conversation key.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::derive::{hmac_sha256, hmac_sha256_verify};
use crate::encoding::{from_base64, to_base64};
use crate::secret::Secret;
use crate::text::{decode_utf8, from_hex32, is_hex32};

const VERSION: u8 = 2;
const MIN_PLAINTEXT: usize = 1;
const MAX_PLAINTEXT: usize = 0xffff;

/// Why a payload does not decrypt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Nip44Error {
    /// A payload of another NIP-44 version (empty, `#…`, or another version byte): written by a
    /// newer client.
    UnknownVersion,
    /// Malformed, or not sealed with the key.
    Invalid,
}

/// The conversation key of two parties (`get_conversation_key`): the x coordinate of the ECDH
/// of `secret` with the x-only public key `public_key` (hex), through HKDF-extract with the salt
/// `nip44-v2`. `None` for a secret out of range or a key off the curve.
pub(crate) fn conversation_key(secret: &Secret, public_key: &str) -> Option<Secret> {
    if !is_hex32(public_key) {
        return None;
    }
    let x = from_hex32(public_key)?;
    let shared = crate::secp::shared_x(secret.expose(), &x)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared);
    Some(Secret::new(prk.into()))
}

/// The padded length of a plaintext of `length` bytes (`calc_padded_len`).
pub(crate) fn padded_len(length: usize) -> usize {
    if length <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (length - 1).leading_zeros());
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((length - 1) / chunk + 1)
}

/// The keys of one message (`get_message_keys`): the ChaCha20 key and nonce, the HMAC key.
pub(crate) struct MessageKeys {
    pub(crate) chacha_key: [u8; 32],
    pub(crate) chacha_nonce: [u8; 12],
    pub(crate) hmac_key: [u8; 32],
}

pub(crate) fn message_keys(conversation_key: &Secret, nonce: &[u8; 32]) -> MessageKeys {
    let hkdf =
        Hkdf::<Sha256>::from_prk(conversation_key.expose()).expect("a 32-byte key is a pseudorandom key");
    let mut keys = [0u8; 76];
    hkdf.expand(nonce, &mut keys).expect("76 bytes is a length HKDF-SHA256 gives");
    let mut message = MessageKeys { chacha_key: [0; 32], chacha_nonce: [0; 12], hmac_key: [0; 32] };
    message.chacha_key.copy_from_slice(&keys[..32]);
    message.chacha_nonce.copy_from_slice(&keys[32..44]);
    message.hmac_key.copy_from_slice(&keys[44..76]);
    message
}

/// Encrypts `text` under `conversation_key` with `nonce` (32 fresh random bytes). `None` when
/// the text is empty or longer than 65 535 bytes, which NIP-44 does not take.
pub(crate) fn encrypt(text: &str, conversation_key: &Secret, nonce: &[u8; 32]) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() < MIN_PLAINTEXT || bytes.len() > MAX_PLAINTEXT {
        return None;
    }
    let mut padded = vec![0u8; 2 + padded_len(bytes.len())];
    padded[..2].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
    padded[2..2 + bytes.len()].copy_from_slice(bytes);
    let keys = message_keys(conversation_key, nonce);
    ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into()).apply_keystream(&mut padded);
    let mut data = Vec::with_capacity(1 + 32 + padded.len() + 32);
    data.push(VERSION);
    data.extend_from_slice(nonce);
    data.extend_from_slice(&padded);
    let mut authenticated = Vec::with_capacity(32 + padded.len());
    authenticated.extend_from_slice(nonce);
    authenticated.extend_from_slice(&padded);
    data.extend_from_slice(&hmac_sha256(&keys.hmac_key, &authenticated));
    Some(to_base64(&data))
}

/// The text of a NIP-44 v2 payload sealed with `conversation_key`. Refused: another version
/// (`UnknownVersion`); a payload shorter than 132 or longer than 87 472 characters, not strict
/// padded base64, decoded data shorter than 99 or longer than 65 603 bytes, a wrong MAC
/// (compared in constant time), a wrong padding, a plaintext that is not UTF-8 (`Invalid`).
pub(crate) fn decrypt(payload: &str, conversation_key: &Secret) -> Result<String, Nip44Error> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err(Nip44Error::UnknownVersion);
    }
    // In characters as JavaScript counts them: base64 is ASCII, anything else is refused below.
    let length = payload.encode_utf16().count();
    if !(132..=87_472).contains(&length) {
        return Err(Nip44Error::Invalid);
    }
    let data = from_base64(payload).ok_or(Nip44Error::Invalid)?;
    if !(99..=65_603).contains(&data.len()) {
        return Err(Nip44Error::Invalid);
    }
    if data[0] != VERSION {
        return Err(Nip44Error::UnknownVersion);
    }
    let nonce: [u8; 32] = data[1..33].try_into().expect("32 bytes");
    let ciphertext = &data[33..data.len() - 32];
    let mac = &data[data.len() - 32..];
    let keys = message_keys(conversation_key, &nonce);
    if !hmac_sha256_verify(&keys.hmac_key, &[&nonce, ciphertext], mac) {
        return Err(Nip44Error::Invalid);
    }
    let mut padded = ciphertext.to_vec();
    ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into()).apply_keystream(&mut padded);
    let length = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    if length < MIN_PLAINTEXT || padded.len() != 2 + padded_len(length) {
        return Err(Nip44Error::Invalid);
    }
    decode_utf8(&padded[2..2 + length]).map(str::to_owned).ok_or(Nip44Error::Invalid)
}
