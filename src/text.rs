//! Text rules that every implementation applies alike (SPEC.md §6): lengths in Unicode code
//! points, case folding and trimming of ASCII only, strict UTF-8. A Rust `String` holds code
//! points and no lone surrogate; a JSON string that holds one is a `JsonString::Units`, never a
//! text (crate::json).

/// Unicode code points of `text`.
pub(crate) fn code_point_len(text: &str) -> usize {
    text.chars().count()
}

/// Whether `character` is ASCII whitespace: space, tab, line feed, carriage return, nothing else.
pub(crate) fn is_ascii_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r')
}

/// `text` without leading and trailing ASCII whitespace (space, tab, line feed, carriage
/// return); no other character is trimmed.
pub(crate) fn trim_ascii_whitespace(text: &str) -> &str {
    text.trim_matches(is_ascii_whitespace)
}

/// `text` with A–Z lowered to a–z, and nothing else changed (never Unicode case mapping, which
/// lowers U+212A KELVIN SIGN to `k`).
pub(crate) fn ascii_lower(text: &str) -> String {
    text.to_ascii_lowercase()
}

/// Whether `text` holds a C0 control character (U+0000 to U+001F) or DEL (U+007F).
pub(crate) fn has_control_character(text: &str) -> bool {
    text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}

/// The text of UTF-8 `bytes`, decoded strictly: invalid bytes make it no text, never U+FFFD.
/// A leading byte order mark stays U+FEFF: only an HTTP body drops one (SPEC.md §15).
pub(crate) fn decode_utf8(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

/// Whether `value` is 64 lowercase hex characters (32 bytes).
pub(crate) fn is_hex32(value: &str) -> bool {
    is_lower_hex(value, 64)
}

/// Whether `value` is 128 lowercase hex characters (64 bytes).
pub(crate) fn is_hex64(value: &str) -> bool {
    is_lower_hex(value, 128)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Lowercase hex of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// The bytes of hex text (either case); `None` when it is not hex.
pub(crate) fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
}

/// The 32 bytes of 64 hex characters; `None` otherwise.
pub(crate) fn from_hex32(text: &str) -> Option<[u8; 32]> {
    from_hex(text)?.try_into().ok()
}
