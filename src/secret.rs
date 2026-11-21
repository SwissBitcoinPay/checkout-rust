//! Secrets in memory: the integration key and every key derived from it (SPEC.md §27). Never in a
//! message, a log, an error or a debug representation: their `Debug` prints `<redacted>`, they
//! implement neither `Display` nor `Serialize`, and their bytes are overwritten when dropped (a
//! best effort: copies made by the hash and curve libraries are theirs).

use std::fmt;

use zeroize::Zeroizing;

/// 32 secret bytes: a key, a secret key of the curve, a conversation key.
#[derive(Clone)]
pub(crate) struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes, for the computation that needs them.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl PartialEq for Secret {
    /// Constant time: a secret is never compared byte by byte up to its first difference.
    fn eq(&self, other: &Self) -> bool {
        let mut difference = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

impl Eq for Secret {}

/// A secret text: the integration key as given, until it is read.
#[derive(Clone)]
pub(crate) struct SecretText(Zeroizing<String>);

impl SecretText {
    pub(crate) fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}
