//! The fields of a BOLT11 invoice the crate checks (SPEC.md §19): network, amount, payment hash,
//! description hash, date and expiry
//! (<https://github.com/lightning/bolts/blob/master/11-payment-encoding.md>). The signature is not
//! verified: the payee is the LNURL server's node, which nothing here can check it against; the
//! description hash ties the invoice to the merchant's Lightning address instead. As the
//! merchant's app reads them: the first `p` and `h` fields of 52 words count and the last `x`; an
//! `x` field of more than 7 words or an amount above 21 million bitcoins makes the invoice
//! invalid.

use crate::lightning::bech32::{self, BECH32, words_to_bytes, words_to_integer};
use crate::protocol::{MAX_BOLT11_AMOUNT_MSAT, MAX_BOLT11_EXPIRY_WORDS};
use crate::text::to_hex;

/// A BOLT11 invoice, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bolt11 {
    /// `bc` mainnet, `tb` testnet, `tbs` signet, `bcrt` regtest.
    pub(crate) network: String,
    /// The exact amount in millisatoshis; `None` for an invoice without one.
    pub(crate) amount_msat: Option<u64>,
    /// Unix seconds.
    pub(crate) timestamp: i64,
    /// Seconds after `timestamp` (3600 when the invoice does not say).
    pub(crate) expiry_seconds: i64,
    /// Hex, 32 bytes.
    pub(crate) payment_hash: String,
    /// Hex, 32 bytes; `None` when the invoice carries a plain description.
    pub(crate) description_hash: Option<String>,
}

impl Bolt11 {
    /// When it can no longer be paid: its timestamp plus its expiry.
    pub(crate) fn expires_at(&self) -> i64 {
        self.timestamp + self.expiry_seconds
    }

    /// Its amount in whole sats: `None` without an amount, or one that is no whole number of sats.
    pub(crate) fn whole_sats(&self) -> Option<u64> {
        self.amount_msat.filter(|msat| msat % 1000 == 0).map(|msat| msat / 1000)
    }
}

const TIMESTAMP_WORDS: usize = 7;
/// The 65-byte signature, as 5-bit words.
const SIGNATURE_WORDS: usize = 104;
const TAG_PAYMENT_HASH: u8 = 1;
const TAG_DESCRIPTION_HASH: u8 = 23;
const TAG_EXPIRY: u8 = 6;
/// 256 bits, as 5-bit words.
const HASH_WORDS: usize = 52;
const DEFAULT_EXPIRY_SECONDS: i64 = 3600;

/// The network and the amount of a human-readable part: `ln`, the network (`bcrt`, `bc`, `tbs`,
/// `tb`), optional digits without a leading zero, an optional multiplier (`m`, `u`, `n`, `p`); a
/// multiplier alone is refused, as an amount above 21 million bitcoins or pico-bitcoins that are
/// not whole millisatoshis. `None` when it is not one.
fn read_hrp(hrp: &str) -> Option<(&'static str, Option<u64>)> {
    let rest = hrp.strip_prefix("ln")?;
    for network in ["bcrt", "bc", "tbs", "tb"] {
        let Some(amount) = rest.strip_prefix(network) else { continue };
        let digits_end = amount.find(|c: char| !c.is_ascii_digit()).unwrap_or(amount.len());
        let (digits, multiplier) = amount.split_at(digits_end);
        if !matches!(multiplier, "" | "m" | "u" | "n" | "p") {
            // As the regex would: try the next network (`tb` after `tbs`).
            continue;
        }
        return amount_msat(digits, multiplier).map(|amount| (network, amount));
    }
    None
}

/// The amount in millisatoshis: `Some(None)` without one, `None` when it is invalid.
fn amount_msat(digits: &str, multiplier: &str) -> Option<Option<u64>> {
    if digits.is_empty() {
        return if multiplier.is_empty() { Some(None) } else { None };
    }
    // A leading zero, or longer than any amount up to 21 million bitcoins whatever the multiplier.
    if (digits.len() > 1 && digits.starts_with('0')) || digits.len() > 22 {
        return None;
    }
    let value: u128 = digits.parse().ok()?;
    let msat: u128 = match multiplier {
        // A pico-bitcoin is a tenth of a millisatoshi: only whole millisatoshis are valid.
        "p" => {
            if !value.is_multiple_of(10) {
                return None;
            }
            value / 10
        }
        "n" => value * 100,
        "u" => value * 100_000,
        "m" => value * 100_000_000,
        _ => value * 100_000_000_000,
    };
    if msat > u128::from(MAX_BOLT11_AMOUNT_MSAT) {
        return None;
    }
    Some(Some(msat as u64))
}

/// Decodes a BOLT11 invoice; `None` when it is not a valid one.
pub(crate) fn decode(input: &str) -> Option<Bolt11> {
    let decoded = bech32::decode(input, BECH32)?;
    let (network, amount_msat) = read_hrp(&decoded.hrp)?;
    let words = decoded.words;
    if words.len() < TIMESTAMP_WORDS + SIGNATURE_WORDS {
        return None;
    }
    let timestamp = words_to_integer(&words[..TIMESTAMP_WORDS]) as i64;
    let fields = &words[TIMESTAMP_WORDS..words.len() - SIGNATURE_WORDS];
    let mut payment_hash: Option<String> = None;
    let mut description_hash: Option<String> = None;
    let mut expiry_seconds: Option<i64> = None;
    let mut index = 0;
    while index < fields.len() {
        if index + 3 > fields.len() {
            return None;
        }
        let tag = fields[index];
        let length = usize::from(fields[index + 1]) * 32 + usize::from(fields[index + 2]);
        let data = fields.get(index + 3..index + 3 + length)?;
        // Fields of another length are skipped, as BOLT11 says for `p` and `h`; the first of each
        // counts, and the last `x` (as the app reads them).
        if tag == TAG_PAYMENT_HASH && length == HASH_WORDS && payment_hash.is_none() {
            payment_hash = Some(to_hex(&words_to_bytes(data).0));
        } else if tag == TAG_DESCRIPTION_HASH && length == HASH_WORDS && description_hash.is_none() {
            description_hash = Some(to_hex(&words_to_bytes(data).0));
        } else if tag == TAG_EXPIRY {
            if length > MAX_BOLT11_EXPIRY_WORDS {
                return None;
            }
            expiry_seconds = Some(words_to_integer(data) as i64);
        }
        index += 3 + length;
    }
    Some(Bolt11 {
        network: network.to_owned(),
        amount_msat,
        timestamp,
        expiry_seconds: expiry_seconds.unwrap_or(DEFAULT_EXPIRY_SECONDS),
        payment_hash: payment_hash?,
        description_hash,
    })
}

/// A decoded invoice on Bitcoin's main network with an amount above 0 of a whole number of sats
/// (what a declaration, a lease or a checkout link's record holds), and that amount.
pub(crate) fn decode_mainnet(input: &str) -> Option<(Bolt11, u64)> {
    let decoded = decode(input)?;
    if decoded.network != "bc" {
        return None;
    }
    let sats = decoded.whole_sats().filter(|&sats| sats > 0)?;
    Some((decoded, sats))
}
