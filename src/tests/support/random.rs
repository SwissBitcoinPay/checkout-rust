//! Randomness and time for tests: reproducible random bytes, and the test's clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};

use crate::derive::sha256;
use crate::runtime::{Clock, Random};

/// Random bytes from a counter: the same events, byte for byte, at every run. Each block of 32
/// bytes is SHA-256(label, counter), the counter one byte.
pub(crate) struct FixedRandom {
    label: String,
    counter: AtomicU8,
}

impl FixedRandom {
    pub(crate) fn new(label: &str) -> Self {
        Self { label: label.to_owned(), counter: AtomicU8::new(0) }
    }
}

impl Random for FixedRandom {
    fn fill(&self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(32) {
            let counter = self.counter.fetch_add(1, Ordering::SeqCst);
            let mut input = self.label.as_bytes().to_vec();
            input.push(counter);
            let block = sha256(&input);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

/// Fixed bytes: tests are reproducible.
pub(crate) fn bytes(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// The clock of a test: Unix seconds a test sets (`now`), shared with every client it makes.
#[derive(Clone, Debug)]
pub(crate) struct TestClock(Arc<AtomicI64>);

impl TestClock {
    pub(crate) fn new(seconds: i64) -> Self {
        Self(Arc::new(AtomicI64::new(seconds)))
    }

    /// Unix seconds.
    pub(crate) fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    pub(crate) fn set(&self, seconds: i64) {
        self.0.store(seconds, Ordering::SeqCst);
    }

    pub(crate) fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        self.now() * 1000
    }
}
