//! Deposit addresses (SPEC.md §31, Deposit addresses, Payment URIs): the taproot addresses the
//! merchant's wallet hands out, in their one spelling, and what the shop's page shows of an
//! invoice as one QR code.

use crate::lightning::bech32::{self, BECH32M};
use crate::protocol::SATS_PER_BTC;

/// `bc1p` and 58 more characters.
const DEPOSIT_ADDRESS_LENGTH: usize = 62;

/// A text of a deposit address's length (`bc1p` and 58 more): what a lease's size is measured
/// with before its address is chosen (SPEC.md §17 step 6). No address: its checksum is not one.
pub(crate) const SIZED_ADDRESS: &str = "bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
const _: () = assert!(SIZED_ADDRESS.len() == DEPOSIT_ADDRESS_LENGTH);
/// The witness version (1) and the 32-byte program, as 5-bit words.
const PROGRAM_WORDS: usize = 53;

/// Whether `value` is a deposit address: the bech32m encoding (BIP-350) of the human-readable
/// part `bc`, witness version 1 and a 32-byte program (BIP-341), in lowercase. Another network,
/// witness version or length, bech32 instead of bech32m, upper case or a padding with bits that
/// are not zero is not one.
pub(crate) fn is_deposit_address(value: &str) -> bool {
    if value.len() != DEPOSIT_ADDRESS_LENGTH
        || !value.starts_with("bc1")
        || !value[3..].bytes().all(|byte| b"qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(&byte))
    {
        return false;
    }
    let Some(decoded) = bech32::decode(value, BECH32M) else {
        return false;
    };
    let words = decoded.words;
    // 52 words after the version: 256 bits of program and 4 bits of padding, which are zeros.
    decoded.hrp == "bc"
        && words.len() == PROGRAM_WORDS
        && words[0] == 1
        && words[PROGRAM_WORDS - 1] & 0b1111 == 0
}

/// `sats` in bitcoins, exact, as BIP-21's `amount`: no trailing zero in the fraction, no fraction
/// when whole (49 000 sats is `0.00049`, 100 000 000 sats is `1`).
pub(crate) fn btc_amount(sats: u64) -> String {
    let whole = sats / SATS_PER_BTC;
    let fraction = format!("{:08}", sats % SATS_PER_BTC);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() { whole.to_string() } else { format!("{whole}.{fraction}") }
}

/// What the shop's page shows as one QR code: `bitcoin:<address>?amount=<BTC>`, with
/// `&lightning=<invoice>` when there is one (BIP-21, the "unified QR" wallets read), or
/// `lightning:<invoice>` without an address. Both are written as they are.
pub(crate) fn payment_uri(address: Option<&str>, sats: u64, bolt11: Option<&str>) -> String {
    match (address, bolt11) {
        (None, bolt11) => format!("lightning:{}", bolt11.unwrap_or_default()),
        (Some(address), None) => format!("bitcoin:{address}?amount={}", btc_amount(sats)),
        (Some(address), Some(bolt11)) => {
            format!("bitcoin:{address}?amount={}&lightning={bolt11}", btc_amount(sats))
        }
    }
}
