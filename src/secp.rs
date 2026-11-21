//! secp256k1, through rust-bitcoin's bindings to libsecp256k1 (Bitcoin Core's library, which
//! BIP-340 was written with): BIP-340 Schnorr signatures with 32 bytes of auxiliary data,
//! x-only public keys and `lift_x`, and the ECDH point NIP-44 needs. The curve is never this
//! crate's own code.

use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey, ecdh, schnorr};

/// Whether `secret` is a secret key of the curve: from 1 to its order minus 1.
pub(crate) fn is_secret_key(secret: &[u8; 32]) -> bool {
    SecretKey::from_secret_bytes(*secret).is_ok()
}

/// The BIP-340 x-only public key of `secret`; `None` when it is not a secret key.
pub(crate) fn x_only_public_key(secret: &[u8; 32]) -> Option<[u8; 32]> {
    let keypair = Keypair::from_secret_bytes(*secret).ok()?;
    Some(keypair.x_only_public_key().0.to_byte_array())
}

/// Whether `x` is the x coordinate of a point of the curve (BIP-340 `lift_x` succeeds).
pub(crate) fn lift_x(x: &[u8; 32]) -> bool {
    XOnlyPublicKey::from_byte_array(*x).is_ok()
}

/// The BIP-340 signature of the 32-byte `message` by `secret`, with `aux` as auxiliary random
/// data (32 fresh bytes of the CSPRNG); `None` when `secret` is not a secret key.
pub(crate) fn sign(message: &[u8; 32], secret: &[u8; 32], aux: &[u8; 32]) -> Option<[u8; 64]> {
    let keypair = Keypair::from_secret_bytes(*secret).ok()?;
    Some(schnorr::sign_with_aux_rand(message, &keypair, aux).to_byte_array())
}

/// Whether `signature` is a BIP-340 signature of `message` by the x-only key `public_key`.
pub(crate) fn verify(signature: &[u8; 64], message: &[u8; 32], public_key: &[u8; 32]) -> bool {
    #[cfg(test)]
    verifications::count();
    let Ok(key) = XOnlyPublicKey::from_byte_array(*public_key) else {
        return false;
    };
    schnorr::verify(&schnorr::Signature::from_byte_array(*signature), message, &key).is_ok()
}

/// The x coordinate of the ECDH point of `secret` and the x-only public key `x` (its point of
/// even y), unhashed: what NIP-44's conversation key is extracted from. `None` when `secret` is
/// not a secret key or `x` not a point.
pub(crate) fn shared_x(secret: &[u8; 32], x: &[u8; 32]) -> Option<[u8; 32]> {
    let secret = SecretKey::from_secret_bytes(*secret).ok()?;
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);
    let point = PublicKey::from_byte_array_compressed(compressed).ok()?;
    let xy = ecdh::shared_secret_point(&point, &secret);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&xy[..32]);
    Some(shared)
}

/// The signatures verified by this thread, for the tests that count them (a read must not check
/// one per record anybody wrote).
#[cfg(test)]
pub(crate) mod verifications {
    use std::cell::Cell;

    thread_local! {
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn count() {
        COUNT.with(|count| count.set(count.get() + 1));
    }

    /// Signatures verified by this thread so far.
    pub(crate) fn total() -> usize {
        COUNT.with(Cell::get)
    }
}
