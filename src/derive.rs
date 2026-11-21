//! The keys an integration's server derives (SPEC.md §10): HKDF-SHA256 (RFC 5869), 32 bytes,
//! salt and info in UTF-8; HMAC-SHA256. They never change: the integration's channel, its sales
//! and their declarations derive from them, in the merchant's app as here (the tests check them
//! against the app's vectors, spec/vectors/app/app.json).

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::protocol::{
    ACCEPTANCE_ADDRESS_INFO, CHANNEL_ADDRESS_INFO, CHANNEL_ENCRYPTION_INFO, CHECKOUT_SALT, DECLARATION_SALT,
    INTEGRATION_SALT, LEASE_ADDRESS_PREFIX, LOT_ADDRESS_INFO, REST_ENCRYPTION_INFO, SALE_NOSTR_SECRET_INFO,
    SALE_SALT, SEEN_ADDRESS_KEY_INFO, SEEN_SECRET_INFO, TAKER_INFO, TAKER_TAG_BYTES,
    merchant_acceptance_info, outer_info, rest_address_info, rest_key_info, rest_secret_info, sale_info,
};
use crate::secret::Secret;
use crate::text::{from_hex32, to_hex};

/// SHA-256 of `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 of `data` under `key`.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Whether `tag` is the HMAC-SHA256 of `data` under `key`, compared in constant time.
pub(crate) fn hmac_sha256_verify(key: &[u8], data: &[&[u8]], tag: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length");
    for part in data {
        mac.update(part);
    }
    mac.verify_slice(tag).is_ok()
}

/// HKDF-SHA256 of `secret` with `salt` and `info` (UTF-8), 32 bytes.
pub(crate) fn derive_key(secret: &[u8], salt: &str, info: &str) -> Secret {
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret);
    let mut okm = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut okm).expect("32 bytes is a length HKDF-SHA256 gives");
    Secret::new(okm)
}

/// The x-only public key (hex) of a secret derived by HKDF: a valid secret key but with a
/// negligible probability (below 2^-127, SPEC.md §10).
pub(crate) fn public_key_of(secret: &Secret) -> String {
    let public = crate::secp::x_only_public_key(secret.expose())
        .expect("an HKDF output is a secret key of the curve but with negligible probability");
    to_hex(&public)
}

/// The integration's channel: its `d` tag (hex) and its NIP-44 conversation key.
pub(crate) struct ChannelKeys {
    pub(crate) address: String,
    pub(crate) encryption_key: Secret,
}

pub(crate) fn channel_keys(integration_key: &Secret) -> ChannelKeys {
    ChannelKeys {
        address: to_hex(
            derive_key(integration_key.expose(), INTEGRATION_SALT, CHANNEL_ADDRESS_INFO).expose(),
        ),
        encryption_key: derive_key(integration_key.expose(), INTEGRATION_SALT, CHANNEL_ENCRYPTION_INFO),
    }
}

/// Where the integration's lot of deposit addresses is: its `d` tag (hex).
pub(crate) fn lot_address(integration_key: &Secret) -> String {
    to_hex(derive_key(integration_key.expose(), INTEGRATION_SALT, LOT_ADDRESS_INFO).expose())
}

/// What the integration's witnesses are made with: the seen secret (it signs them), its public
/// key (their author) and the key of their addresses and order tags.
pub(crate) struct SeenKeys {
    pub(crate) secret_key: Secret,
    pub(crate) author: String,
    pub(crate) address_key: Secret,
}

pub(crate) fn seen_keys(integration_key: &Secret) -> SeenKeys {
    let secret_key = derive_key(integration_key.expose(), INTEGRATION_SALT, SEEN_SECRET_INFO);
    SeenKeys {
        author: public_key_of(&secret_key),
        secret_key,
        address_key: derive_key(integration_key.expose(), INTEGRATION_SALT, SEEN_ADDRESS_KEY_INFO),
    }
}

/// The key that marks the integration's declarations ("By" in the app).
pub(crate) fn taker_key(integration_key: &Secret) -> Secret {
    derive_key(integration_key.expose(), INTEGRATION_SALT, TAKER_INFO)
}

/// The sale of an order: its own key, its Nostr secret and public key (the declarations' author).
pub(crate) struct SaleKeys {
    pub(crate) key: Secret,
    pub(crate) secret_key: Secret,
    pub(crate) author: String,
}

pub(crate) fn sale_keys(integration_key: &Secret, reference: &str) -> SaleKeys {
    let key = derive_key(integration_key.expose(), INTEGRATION_SALT, &sale_info(reference));
    let secret_key = derive_key(key.expose(), SALE_SALT, SALE_NOSTR_SECRET_INFO);
    SaleKeys { author: public_key_of(&secret_key), key, secret_key }
}

/// The keys of the rest records of the order's invoice with the deposit address `address` and
/// the end `expires_at` (SPEC.md §31, Rest records): the rest key (its checkout links' records
/// carry it), the rest secret (it signs the records; only the integration key derives it) and its
/// public key, the author, and the records' encryption key.
#[derive(Clone)]
pub(crate) struct RestKeys {
    pub(crate) key: Secret,
    pub(crate) secret_key: Secret,
    pub(crate) author: String,
    pub(crate) encryption_key: Secret,
}

pub(crate) fn rest_keys(
    integration_key: &Secret,
    reference: &str,
    address: &str,
    expires_at: i64,
) -> RestKeys {
    let key = derive_key(
        integration_key.expose(),
        INTEGRATION_SALT,
        &rest_key_info(reference, address, expires_at),
    );
    let secret_key = derive_key(
        integration_key.expose(),
        INTEGRATION_SALT,
        &rest_secret_info(reference, address, expires_at),
    );
    RestKeys {
        author: public_key_of(&secret_key),
        secret_key,
        encryption_key: derive_key(key.expose(), CHECKOUT_SALT, REST_ENCRYPTION_INFO),
        key,
    }
}

/// The `d` tag (hex) of the rest record of the invoice whose payment hash is `payment_hash`.
pub(crate) fn rest_record_address(rest_key: &Secret, payment_hash: &str) -> String {
    to_hex(derive_key(rest_key.expose(), CHECKOUT_SALT, &rest_address_info(payment_hash)).expose())
}

/// The `d` tag (hex) of the acceptance record of the invoice whose rest key is `rest_key`.
pub(crate) fn acceptance_record_address(rest_key: &Secret) -> String {
    to_hex(derive_key(rest_key.expose(), CHECKOUT_SALT, ACCEPTANCE_ADDRESS_INFO).expose())
}

/// The `d` tag (hex) of the merchant's acceptance of the invoice of the sale `sale_author` with the
/// deposit address `address` and the end `expires_at` (SPEC.md §31, The merchant's acceptance):
/// one per invoice.
pub(crate) fn merchant_acceptance_address(
    integration_key: &Secret,
    sale_author: &str,
    address: &str,
    expires_at: i64,
) -> String {
    to_hex(
        derive_key(
            integration_key.expose(),
            INTEGRATION_SALT,
            &merchant_acceptance_info(sale_author, address, expires_at),
        )
        .expose(),
    )
}

/// d(H): where the declarations of the payment hash `payment_hash` (hex32) are.
pub(crate) fn registry_address(registry_key: &Secret, payment_hash: &str) -> String {
    let hash = from_hex32(payment_hash).expect("a payment hash is 32 bytes of hex");
    to_hex(&hmac_sha256(registry_key.expose(), &hash))
}

/// Where the leases of the deposit address `address` are: HMAC(registry key, "onchain/v1/" +
/// address).
pub(crate) fn lease_address(registry_key: &Secret, address: &str) -> String {
    to_hex(&hmac_sha256(registry_key.expose(), format!("{LEASE_ADDRESS_PREFIX}{address}").as_bytes()))
}

/// The outer key of a record at `address` by `author` (hex).
pub(crate) fn outer_key(registry_key: &Secret, address: &str, author: &str) -> Secret {
    derive_key(registry_key.expose(), DECLARATION_SALT, &outer_info(address, author))
}

/// Who took a sale: the first 16 bytes of HMAC-SHA256(taker key, author), hex.
pub(crate) fn taker_tag(taker_key: &Secret, sale_author: &str) -> String {
    let author = from_hex32(sale_author).expect("an author is 32 bytes of hex");
    to_hex(&hmac_sha256(taker_key.expose(), &author)[..TAKER_TAG_BYTES])
}

/// The merchant's registry, as the integration's channel gives it.
#[derive(Clone, Debug)]
pub(crate) struct Registry {
    /// The registry key (32 bytes).
    pub(crate) key: Secret,
    /// Hex: the public half of the merchant's reading key.
    pub(crate) reader: String,
}

/// Everything the sale of a reference needs, derived once: its keys, its taker tag and the
/// conversation key (ECDH) of its declarations' inside with the merchant's reading key.
#[derive(Clone)]
pub(crate) struct Sale {
    pub(crate) reference: String,
    pub(crate) key: Secret,
    pub(crate) secret_key: Secret,
    pub(crate) author: String,
    pub(crate) taker: String,
    pub(crate) registry: Registry,
    pub(crate) inner_key: Secret,
}

impl std::fmt::Debug for Sale {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sale")
            .field("reference", &self.reference)
            .field("author", &self.author)
            .finish_non_exhaustive()
    }
}

pub(crate) fn sale_of(integration_key: &Secret, registry: &Registry, reference: &str) -> Sale {
    let SaleKeys { key, secret_key, author } = sale_keys(integration_key, reference);
    let inner_key = crate::nostr::nip44::conversation_key(&secret_key, &registry.reader)
        .expect("a channel's reading key is a point of the curve (checked when it is read)");
    Sale {
        reference: reference.to_owned(),
        taker: taker_tag(&taker_key(integration_key), &author),
        key,
        secret_key,
        author,
        registry: registry.clone(),
        inner_key,
    }
}
