//! What a client takes from its environment (SPEC.md §4): where warnings go, the clock and
//! random bytes. The clock and the randomness are injectable for tests only.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Where warnings go: a newer format than this crate reads, a rate source that failed and was
/// replaced, a payment check that failed and is retried. Never given a secret.
///
/// The default, [`LogLogger`], hands them to the [`log`] crate's `warn!`.
pub trait Logger: Send + Sync {
    /// One warning, a sentence.
    fn warn(&self, message: &str);
}

/// The default [`Logger`]: `log::warn!` with the target `sattleme_checkout`.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogLogger;

impl Logger for LogLogger {
    fn warn(&self, message: &str) {
        log::warn!(target: "sattleme_checkout", "{message}");
    }
}

/// The server's clock, in Unix milliseconds. It must be synchronized (NTP): an invoice more than
/// 300 s off is refused. Injectable for tests only: [`SystemClock`] by default.
pub trait Clock: Send + Sync {
    /// Now, in Unix milliseconds.
    fn now_ms(&self) -> i64;
}

/// The default [`Clock`]: the system's.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
    }
}

/// Where random bytes come from: NIP-44 nonces, the auxiliary data of BIP-340 signatures, the
/// keys of a single relay read, subscription ids, checkout links' keys, the order addresses are
/// tried in. Injectable for reproducible tests only: [`OsRandom`], the operating system's CSPRNG,
/// by default, never a general-purpose generator.
pub trait Random: Send + Sync {
    /// Fills `bytes` with random bytes.
    fn fill(&self, bytes: &mut [u8]);
}

/// The default [`Random`]: the operating system's CSPRNG (`getrandom`).
#[derive(Clone, Copy, Default)]
pub struct OsRandom;

impl fmt::Debug for OsRandom {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OsRandom")
    }
}

impl Random for OsRandom {
    /// # Panics
    ///
    /// When the operating system gives no random bytes: nothing this crate does is safe without
    /// them, and no other generator may replace them.
    fn fill(&self, bytes: &mut [u8]) {
        getrandom::fill(bytes).expect("the operating system's CSPRNG gave no random bytes");
    }
}

/// Zeros in place of random bytes, for what is built for its size alone and dropped, never
/// published nor kept (a lease's, SPEC.md §17 step 6): the client's randomness is left alone, and
/// so are the random bytes a reproducible test gives.
pub(crate) struct Zeros;

impl Random for Zeros {
    fn fill(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

/// 32 random bytes.
pub(crate) fn random32(random: &dyn Random) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    random.fill(&mut bytes);
    bytes
}

/// Unix seconds of a clock: now, rounded down.
pub(crate) fn seconds(clock: &dyn Clock) -> i64 {
    clock.now_ms().div_euclid(1000)
}
