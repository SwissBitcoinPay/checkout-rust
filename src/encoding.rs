//! Base64 (RFC 4648), as the merchant's app writes it (SPEC.md §2): decoding is strict, one value
//! has one spelling, anything else is refused. Lenient decoders (whitespace skipped, both
//! alphabets taken, unused trailing bits ignored) would read a damaged key as another one.

/// RFC 4648 §4.
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// RFC 4648 §5.
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        let characters = (chunk.len() * 8).div_ceil(6);
        for index in 0..characters {
            let sextet = (value >> (18 - index * 6)) & 63;
            text.push(char::from(alphabet[sextet as usize]));
        }
    }
    text
}

/// Unpadded text of `alphabet` as bytes; `None` unless it is the canonical encoding of some
/// bytes (every character of the alphabet, the left-over bits zero).
fn decode(text: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() * 6 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = alphabet.iter().position(|&a| a == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    // Left-over bits are padding: zero in the canonical encoding.
    (buffer == 0).then_some(bytes)
}

/// Base64url without padding (RFC 4648 §5).
pub(crate) fn to_base64url(bytes: &[u8]) -> String {
    encode(bytes, URL_SAFE)
}

/// The bytes of unpadded base64url text; `None` when it is not canonical.
pub(crate) fn from_base64url(text: &str) -> Option<Vec<u8>> {
    decode(text, URL_SAFE)
}

/// Standard base64 with `=` padding (RFC 4648 §4), as NIP-44 payloads use it.
pub(crate) fn to_base64(bytes: &[u8]) -> String {
    let mut text = encode(bytes, STANDARD);
    while !text.len().is_multiple_of(4) {
        text.push('=');
    }
    text
}

/// The bytes of padded standard base64 text; `None` when it is not canonical (padding exactly
/// where RFC 4648 §4 puts it, and nowhere else).
pub(crate) fn from_base64(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let unpadded = text.strip_suffix("==").or_else(|| text.strip_suffix('=')).unwrap_or(text);
    if unpadded.contains('=') {
        return None;
    }
    decode(unpadded, STANDARD)
}
