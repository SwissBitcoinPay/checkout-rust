//! Bech32 decoding (BIP-173), without the 90-character limit: BOLT11 invoices are longer. Bech32m
//! (BIP-350), for taproot addresses, differs by its checksum's constant alone. Case is ASCII's
//! (SPEC.md §6): a text is all lowercase or all uppercase, never mixed, and no other character
//! changes case.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

/// The checksum's constant: BIP-173's bech32.
pub(crate) const BECH32: u32 = 1;
/// The checksum's constant: BIP-350's bech32m.
pub(crate) const BECH32M: u32 = 0x2bc8_30a3;

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut checksum: u32 = 1;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

/// A decoded bech32 text.
pub(crate) struct Bech32 {
    /// The human-readable part, lowercase.
    pub(crate) hrp: String,
    /// The 5-bit words, the checksum removed.
    pub(crate) words: Vec<u8>,
}

/// Decodes a bech32 text (either case, never mixed) with the checksum constant `constant`;
/// `None` when it is not one.
pub(crate) fn decode(input: &str, constant: u32) -> Option<Bech32> {
    let has_lower = input.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = input.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let text = input.to_ascii_lowercase();
    let separator = text.rfind('1')?;
    if separator < 1 || separator + 7 > text.len() {
        return None;
    }
    let hrp = &text[..separator];
    if !hrp.bytes().all(|byte| (33..=126).contains(&byte)) {
        return None;
    }
    let values: Vec<u8> = text[separator + 1..]
        .bytes()
        .map(|byte| CHARSET.iter().position(|&c| c == byte).map(|value| value as u8))
        .collect::<Option<_>>()?;
    let expanded = hrp.bytes().map(|byte| byte >> 5).chain([0]).chain(hrp.bytes().map(|byte| byte & 31));
    if polymod(expanded.chain(values.iter().copied())) != constant {
        return None;
    }
    let words = values[..values.len() - 6].to_vec();
    Some(Bech32 { hrp: hrp.to_owned(), words })
}

/// Regroups 5-bit words into bytes; the trailing padding bits (fewer than 8) are dropped, and
/// returned (their value, their count) for who must check them.
pub(crate) fn words_to_bytes(words: &[u8]) -> (Vec<u8>, u32, u32) {
    let mut bytes = Vec::with_capacity(words.len() * 5 / 8);
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for &word in words {
        accumulator = ((accumulator << 5) | u32::from(word)) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
        }
    }
    (bytes, accumulator & ((1 << bits) - 1), bits)
}

/// The big-endian unsigned integer of 5-bit words (at most 12 of them: 60 bits).
pub(crate) fn words_to_integer(words: &[u8]) -> u64 {
    words.iter().fold(0, |value, &word| value * 32 + u64::from(word))
}
