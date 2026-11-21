//! BOLT11 invoices built for tests, so that a test chooses their fields. The signature is 65 zero
//! bytes: nothing verifies it. Written apart from the crate's bech32, so that the tests do not
//! check the crate against itself.

use crate::derive::sha256;
use crate::text::{from_hex, to_hex};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
/// The checksum constant of bech32 (BIP-173).
pub(crate) const BECH32: u32 = 1;
/// The checksum constant of bech32m (BIP-350).
pub(crate) const BECH32M: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn expand_hrp(hrp: &str) -> Vec<u8> {
    let mut expanded: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    expanded.push(0);
    expanded.extend(hrp.bytes().map(|c| c & 31));
    expanded
}

/// `hrp`, `1`, the words and their checksum of `constant`.
pub(crate) fn encode_bech32(hrp: &str, words: &[u8], constant: u32) -> String {
    let mut values = expand_hrp(hrp);
    values.extend_from_slice(words);
    values.extend_from_slice(&[0; 6]);
    let modulus = polymod(&values) ^ constant;
    let mut out = format!("{hrp}1");
    for &word in words {
        out.push(char::from(CHARSET[usize::from(word)]));
    }
    for i in 0..6 {
        out.push(char::from(CHARSET[((modulus >> (5 * (5 - i))) & 31) as usize]));
    }
    out
}

/// Bytes as 5-bit words, the last one padded with zeros.
pub(crate) fn bytes_to_words(bytes: &[u8]) -> Vec<u8> {
    let mut words = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((accumulator >> bits) & 31) as u8);
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits > 0 {
        words.push(((accumulator << (5 - bits)) & 31) as u8);
    }
    words
}

/// An integer as 5-bit words, big-endian, left-padded with zeros to `length`.
pub(crate) fn integer_words(value: u64, length: Option<usize>) -> Vec<u8> {
    let mut words = Vec::new();
    let mut rest = value;
    loop {
        words.insert(0, (rest % 32) as u8);
        rest /= 32;
        if rest == 0 {
            break;
        }
    }
    while length.is_some_and(|length| words.len() < length) {
        words.insert(0, 0);
    }
    words
}

fn field(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut words = vec![tag, (data.len() / 32) as u8, (data.len() % 32) as u8];
    words.extend_from_slice(data);
    words
}

/// A 32-byte preimage made of `seed`, and its payment hash, hex.
pub(crate) fn preimage_pair(seed: u32) -> (String, String) {
    let preimage = [(seed & 0xff) as u8; 32];
    (to_hex(&preimage), to_hex(&sha256(&preimage)))
}

/// The description hash of a Lightning address's metadata.
pub(crate) fn metadata_hash(metadata: &str) -> String {
    to_hex(&sha256(metadata.as_bytes()))
}

fn amount_part(msat: u128) -> String {
    if msat.is_multiple_of(100_000_000_000) {
        format!("{}", msat / 100_000_000_000)
    } else if msat.is_multiple_of(100_000_000) {
        format!("{}m", msat / 100_000_000)
    } else if msat.is_multiple_of(100_000) {
        format!("{}u", msat / 100_000)
    } else if msat.is_multiple_of(100) {
        format!("{}n", msat / 100)
    } else {
        format!("{}p", msat * 10)
    }
}

/// What a test invoice says.
#[derive(Clone, Debug)]
pub(crate) struct InvoiceSpec {
    pub(crate) amount_msat: Option<u128>,
    /// `bc` for mainnet.
    pub(crate) network: String,
    pub(crate) payment_hash: String,
    pub(crate) description_hash: Option<String>,
    pub(crate) timestamp: i64,
    pub(crate) expiry_seconds: Option<u64>,
    /// More tagged fields, after the others: (tag, 5-bit words).
    pub(crate) extra: Vec<(u8, Vec<u8>)>,
}

impl InvoiceSpec {
    /// A mainnet invoice of `payment_hash` at `timestamp`, nothing else.
    pub(crate) fn new(payment_hash: &str, timestamp: i64) -> Self {
        Self {
            amount_msat: None,
            network: "bc".to_owned(),
            payment_hash: payment_hash.to_owned(),
            description_hash: None,
            timestamp,
            expiry_seconds: None,
            extra: Vec::new(),
        }
    }
}

/// The BOLT11 text of `spec`.
pub(crate) fn make_invoice(spec: &InvoiceSpec) -> String {
    let hrp = format!("ln{}{}", spec.network, spec.amount_msat.map(amount_part).unwrap_or_default());
    let mut words = integer_words(u64::try_from(spec.timestamp).expect("a timestamp after 1970"), Some(7));
    words.extend(field(1, &bytes_to_words(&from_hex(&spec.payment_hash).expect("hex"))));
    if let Some(hash) = &spec.description_hash {
        words.extend(field(23, &bytes_to_words(&from_hex(hash).expect("hex"))));
    }
    if let Some(expiry) = spec.expiry_seconds {
        words.extend(field(6, &integer_words(expiry, None)));
    }
    for (tag, data) in &spec.extra {
        words.extend(field(*tag, data));
    }
    words.extend_from_slice(&[0; 104]);
    encode_bech32(&hrp, &words, BECH32)
}
