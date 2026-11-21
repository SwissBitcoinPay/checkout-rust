//! Every constant of the protocol, in one place (SPEC.md §28): every implementation, in any
//! language, uses these values. Those marked "never changes" are fixed by data already published
//! (keys, channels, declarations): changing one loses merchants' sales or stops their
//! integrations.

/// The beginning of every integration key (`sattleme` sattle.me, `ck` checkout key). Never
/// changes: a later format of the key takes another prefix (`sattleme_ck2_`).
pub(crate) const INTEGRATION_KEY_PREFIX: &str = "sattleme_ck_";
/// Bytes of the team's public key and of the integration's key.
pub(crate) const KEY_BYTES: usize = 32;

/// HKDF-SHA256 salts (UTF-8). Never change.
pub(crate) const INTEGRATION_SALT: &str = "sattle.me/integration";
pub(crate) const SALE_SALT: &str = "sattle.me/sale";
pub(crate) const DECLARATION_SALT: &str = "sattle.me/registry-declaration";

/// HKDF-SHA256 `info` strings (UTF-8). Never change.
pub(crate) const CHANNEL_ADDRESS_INFO: &str = "channel/address/v1";
pub(crate) const CHANNEL_ENCRYPTION_INFO: &str = "channel/encryption-key/v1";
pub(crate) const TAKER_INFO: &str = "taker/v1";
pub(crate) const SALE_NOSTR_SECRET_INFO: &str = "nostr-secret-key/v1";

/// The `info` of the sale key of the order `reference`. Never changes.
pub(crate) fn sale_info(reference: &str) -> String {
    format!("sale/{reference}/v1")
}

/// The `info` of the outer key of a record at `address` by `author` (hex). Never changes.
pub(crate) fn outer_info(address: &str, author: &str) -> String {
    format!("outer/v1/{address}/{author}")
}

/// Bytes of HMAC-SHA256(taker key, author) kept as the taker tag.
pub(crate) const TAKER_TAG_BYTES: usize = 16;

/// NIP-78 application data: every record of the app.
pub(crate) const RECORD_KIND: f64 = 30078.0;
/// NIP-42 authentication.
pub(crate) const AUTH_KIND: f64 = 22242.0;
/// A record's plaintext is padded with spaces to a multiple of this many bytes.
pub(crate) const RECORD_BLOCK_BYTES: usize = 256;

pub(crate) const CHANNEL_RECORD_TYPE: &str = "team-channel";
pub(crate) const CHANNEL_VERSION: f64 = 1.0;
/// At most this many moves of the merchant's relays are followed.
pub(crate) const MAX_RELAY_MOVES: usize = 3;
/// Longest business name, in Unicode code points.
pub(crate) const MAX_BUSINESS_NAME_LENGTH: usize = 200;

pub(crate) const DECLARATION_RECORD_TYPE: &str = "registry-declaration";
pub(crate) const DECLARATION_VERSION: f64 = 1.0;
/// The currency of a sale declared in sats: its `minor` is the sats, its `digits` 0.
pub(crate) const SATS_CURRENCY: &str = "SAT";
/// Most decimals a declared price may have.
pub(crate) const MAX_DECLARED_DIGITS: u32 = 8;
/// Largest amount in minor units (2^53 − 1: a JSON number every reader holds exactly).
pub(crate) const MAX_MINOR_UNITS: u64 = 9_007_199_254_740_991;
/// The largest integer a JSON number holds exactly, either way (`Number.MAX_SAFE_INTEGER`).
pub(crate) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// The deepest a JSON text nests, arrays and objects counted together (SPEC.md §2): a deeper text
/// is no JSON, whatever a platform's reader takes.
pub(crate) const MAX_JSON_DEPTH: usize = 64;

/// Checkout links (SPEC.md §30): the salt and `info` strings never change; the merchant's web
/// app derives the same keys.
pub(crate) const CHECKOUT_SALT: &str = "sattle.me/checkout";
pub(crate) const CHECKOUT_ADDRESS_INFO: &str = "address/v1";
pub(crate) const CHECKOUT_ENCRYPTION_INFO: &str = "encryption-key/v1";
pub(crate) const CHECKOUT_RECORD_TYPE: &str = "checkout";
pub(crate) const CHECKOUT_VERSION: f64 = 1.0;
/// The version of a checkout link's record for an invoice with an address.
pub(crate) const CHECKOUT_ONCHAIN_VERSION: f64 = 2.0;
/// The first part of a checkout link's fragment: a link of this version. Never changes.
pub(crate) const CHECKOUT_MARKER: &str = "c";
/// The page of the merchant's web app that reads checkout links.
pub(crate) const CHECKOUT_PATH: &str = "/pay";
/// A checkout link's record lives this long after its invoice's end (NIP-40): a week.
pub(crate) const CHECKOUT_LIFE_SECONDS: i64 = 604_800;
/// Longest redirect URL, in characters (ASCII only).
pub(crate) const MAX_REDIRECT_URL_LENGTH: usize = 2048;
/// Longest scheme of an app's redirect URL.
pub(crate) const MAX_REDIRECT_SCHEME_LENGTH: usize = 32;

/// Schemes a redirect URL never has (SPEC.md §30, Redirect URLs): the browser's own, files and
/// scripts; other browsers (they open any web page given in the rest of the link, whose host the
/// page would not show: a web page is an https URL); other transports; any Android activity;
/// payments (a second invoice right after the first); calls and messages; installing software or
/// running system tools. `https` follows its own rule.
pub(crate) const REFUSED_REDIRECT_SCHEMES: &[&str] = &[
    "about",
    "blob",
    "chrome",
    "chrome-extension",
    "content",
    "data",
    "file",
    "filesystem",
    "javascript",
    "moz-extension",
    "resource",
    "safari-extension",
    "vbscript",
    "view-source",
    "brave",
    "com-apple-mobilesafari-tab",
    "ddgquicklink",
    "firefox",
    "firefox-focus",
    "googlechrome",
    "googlechrome-x-callback",
    "googlechromes",
    "microsoft-edge",
    "microsoft-edge-http",
    "microsoft-edge-https",
    "onionbrowser",
    "onionbrowsers",
    "opera-http",
    "opera-https",
    "x-safari-http",
    "x-safari-https",
    "ftp",
    "http",
    "ws",
    "wss",
    "android-app",
    "intent",
    "bitcoin",
    "keyauth",
    "lightning",
    "liquidnetwork",
    "lnurl",
    "lnurlc",
    "lnurlp",
    "lnurlw",
    "callto",
    "facetime",
    "facetime-audio",
    "mailto",
    "sip",
    "sms",
    "tel",
    "itms-services",
    "ms-msdt",
    "search-ms",
];

/// Most relays a list holds, and the longest relay address (`wss://` included), in code points.
pub(crate) const MAX_RELAYS: usize = 10;
pub(crate) const MAX_RELAY_URL_LENGTH: usize = 120;
/// Longest host of a relay address, a checkout origin, a redirect URL or an https URL.
pub(crate) const MAX_HOST_LENGTH: usize = 253;
/// Longest https URL (a pay URL, a callback, a verify URL), in characters (ASCII only).
pub(crate) const MAX_HTTPS_URL_LENGTH: usize = 2048;

/// The characters of an order's reference, and its length: one order, one sale.
pub(crate) const MAX_REF_LENGTH: usize = 64;
pub(crate) const REF_RULE: &str = "1 to 64 characters A-Z a-z 0-9 . _ : -";
/// Invoice durations, in seconds.
pub(crate) const MIN_DURATION_SECONDS: i64 = 60;
pub(crate) const MAX_DURATION_SECONDS: i64 = 3600;
pub(crate) const DEFAULT_DURATION_SECONDS: i64 = 900;
/// Longest note, in Unicode code points.
pub(crate) const MAX_NOTE_LENGTH: usize = 100;

/// After an invoice's end, a payment of its last seconds may still be reported (SPEC.md §22):
/// until then, "not paid" is not final.
pub(crate) const GRACE_SECONDS: i64 = 120;
/// An invoice's date may be this far from the server's clock (synchronized by NTP).
pub(crate) const CLOCK_TOLERANCE_SECONDS: i64 = 300;
/// The LUD-21 refusal that means "never paid" once the grace period is over.
pub(crate) const NOT_FOUND_REASON: &str = "Not found";

/// A dated price older than this is refused; one dated further than the clock tolerance ahead
/// too.
pub(crate) const MAX_RATE_AGE_SECONDS: i64 = 3600;
/// Longest price text a rate source may give.
pub(crate) const MAX_PRICE_LENGTH: usize = 64;
/// Largest exponent (either sign) of a price written in exponent notation.
pub(crate) const MAX_PRICE_EXPONENT: i64 = 64;

/// Most events read from one relay for one query, and most pages of a paged read.
pub(crate) const MAX_EVENTS_PER_QUERY: usize = 1000;
pub(crate) const MAX_PAGES: usize = 20;
/// The `limit` of each page of a complete read (SPEC.md §13, Complete reads): a page of fewer
/// events is the relay's last.
pub(crate) const COMPLETE_READ_LIMIT: usize = 100;
/// The User-Agent of every HTTP request and WebSocket handshake: the same in every
/// implementation and version (CoinGecko refuses a request without one; relays behind bot
/// protection refuse a handshake without one; one naming a language or a version would help
/// single it out).
pub(crate) const USER_AGENT: &str = "sattleme-Checkout/1";
/// Largest message read from a relay, and largest HTTP answer body read.
pub(crate) const MAX_RELAY_MESSAGE_BYTES: usize = 1 << 20;
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 1 << 20;
/// What the default HTTP client reads of one answer at most, in all (SPEC.md §15, Head): its
/// status line and headers, the size lines of a chunked body, the body and its framing: the head
/// and the size lines are so at most 10 MiB, and a body of 1 MiB fits (in chunks of one byte, some
/// 6 MiB in all).
pub(crate) const MAX_HTTP_ANSWER_BYTES: usize = 10 << 20;
/// Earlier invoices of an order checked at once (createInvoice).
pub(crate) const MAX_PARALLEL_PAYMENT_CHECKS: usize = 4;

/// Per request timeouts, in milliseconds: the default and the bounds a caller may choose.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 10_000;
pub(crate) const MIN_TIMEOUT_MS: u64 = 100;
pub(crate) const MAX_TIMEOUT_MS: u64 = 60_000;
/// waitForPayment's interval, in milliseconds.
pub(crate) const DEFAULT_INTERVAL_MS: u64 = 2000;
pub(crate) const MIN_INTERVAL_MS: u64 = 250;
pub(crate) const MAX_INTERVAL_MS: u64 = 60_000;

/// Longest `x` (expiry) field of a BOLT11 invoice, in 5-bit words (35 bits, as its date).
pub(crate) const MAX_BOLT11_EXPIRY_WORDS: usize = 7;
/// Largest BOLT11 amount: 21 million bitcoins, in millisatoshis.
pub(crate) const MAX_BOLT11_AMOUNT_MSAT: u64 = 2_100_000_000_000_000_000;

/// Below this amount, an order is Lightning only (SPEC.md §31).
pub(crate) const ONCHAIN_FLOOR_SATS: u64 = 1000;
/// The largest amount of an order: 21 million bitcoins, in sats.
pub(crate) const MAX_SATS: u64 = 2_100_000_000_000_000;
pub(crate) const SATS_PER_BTC: u64 = 100_000_000;

pub(crate) const LOT_RECORD_TYPE: &str = "integration-onchain-lot";
pub(crate) const LOT_VERSION: f64 = 1.0;
pub(crate) const LOT_ADDRESS_INFO: &str = "onchain-lot/address/v1";
/// Most addresses a lot holds.
pub(crate) const MAX_LOT_ADDRESSES: usize = 100;

pub(crate) const LEASE_RECORD_TYPE: &str = "registry-onchain";
pub(crate) const LEASE_VERSION: f64 = 1.0;
/// What a deposit address's registry address is the HMAC of: this, then the address (UTF-8).
pub(crate) const LEASE_ADDRESS_PREFIX: &str = "onchain/v1/";
/// Leases read back this far: a lease ends at most 4 320 s after its `created_at` (a BOLT11 date
/// up to 300 s ahead, 3600 s, the grace period, the clock tolerance).
pub(crate) const LEASE_LOOKBACK_SECONDS: i64 = 7200;
/// Free addresses tried for one order.
pub(crate) const MAX_ADDRESS_TRIES: usize = 3;

pub(crate) const WITNESS_RECORD_TYPE: &str = "integration-onchain-seen";
pub(crate) const WITNESS_VERSION: f64 = 1.0;
pub(crate) const SEEN_SECRET_INFO: &str = "onchain-seen/nostr-secret-key/v1";
pub(crate) const SEEN_ADDRESS_KEY_INFO: &str = "onchain-seen/address-key/v1";
/// The tag of a witness that names its order (its address and sale), and its address.
pub(crate) const ORDER_TAG: &str = "o";
/// The coins of a transaction a witness keeps: its first 100.
pub(crate) const MAX_WITNESS_INPUTS: usize = 100;
/// The `sale` a witness names when the transaction came at no lease's time.
pub(crate) const NO_SALE: &str = "none";

/// mempool.space (Esplora REST): the explorer, the only one asked what the blockchain shows (a
/// payment counts as made on what it alone shows).
pub(crate) const MEMPOOL_URL: &str = "https://mempool.space/api";
/// mempool.space's WebSocket, which waitForPayment watches an address on.
pub(crate) const MEMPOOL_WEBSOCKET_URL: &str = "wss://mempool.space/api/v1/ws";
/// The longest URL of a merchant's Bitcoin node (SPEC.md §31, A node URL), in characters.
pub(crate) const MAX_NODE_URL_LENGTH: usize = 200;
/// A merchant's Bitcoin node that failed a read less than this long ago, in the same call, is asked
/// after mempool.space (`fallback` `"mempool"`), so that a node that does not answer does not make
/// each read wait for its timeout.
pub(crate) const NODE_FAILED_RECENTLY_MS: i64 = 60_000;
/// When a transaction was received, asked only for one no check saw while its lease ran.
pub(crate) const BLOCKCYPHER_URL: &str = "https://api.blockcypher.com/v1/btc/main";
/// Confirmations of an on-chain payment, on the explorer read.
pub(crate) const CONFIRMATIONS: u64 = 3;
/// The on-chain part is checked at least this often while waitForPayment waits.
pub(crate) const ONCHAIN_CHECK_INTERVAL_MS: u64 = 60_000;
/// The explorer's WebSocket, lost: connected again after this, doubled at each failure…
pub(crate) const RECONNECT_FIRST_MS: u64 = 1000;
/// …up to this.
pub(crate) const RECONNECT_MAX_MS: u64 = 30_000;

/// The rest of an on-chain underpayment (SPEC.md §31, The rest of an underpayment). The type,
/// the salts and the `info` strings never change: the merchant's web app reads the same records.
pub(crate) const REST_RECORD_TYPE: &str = "checkout-rest";
pub(crate) const REST_VERSION: f64 = 1.0;

/// The `info` of the rest key of the invoice of the order `reference` with the deposit address
/// `address` and the end `expires_at` (Unix seconds, decimal).
pub(crate) fn rest_key_info(reference: &str, address: &str, expires_at: i64) -> String {
    format!("checkout-rest/{reference}/{address}/{expires_at}/key/v1")
}

/// The `info` of the rest secret of the same invoice.
pub(crate) fn rest_secret_info(reference: &str, address: &str, expires_at: i64) -> String {
    format!("checkout-rest/{reference}/{address}/{expires_at}/nostr-secret-key/v1")
}

/// HKDF `info` (salt `CHECKOUT_SALT`) of a rest record's encryption key.
pub(crate) const REST_ENCRYPTION_INFO: &str = "rest/encryption-key/v1";

/// HKDF `info` (salt `CHECKOUT_SALT`) of the address of the rest record of payment hash `hash`.
pub(crate) fn rest_address_info(payment_hash: &str) -> String {
    format!("rest/address/{payment_hash}/v1")
}

/// A rest invoice is asked only with this long left before the invoice's end.
pub(crate) const MIN_REST_SECONDS: i64 = 60;

/// The merchant's tolerance of on-chain underpayments (SPEC.md §31, The merchant's tolerance):
/// an integer of basis points, from 0 to this (10 %); anything else is 0.
pub(crate) const MAX_TOLERANCE: u64 = 1000;
/// Basis points in a whole.
pub(crate) const TOLERANCE_SCALE: u64 = 10_000;

/// Acceptance records (SPEC.md §31, Acceptance records). The type and the `info` string never
/// change: the merchant's web app reads them.
pub(crate) const ACCEPTANCE_RECORD_TYPE: &str = "checkout-accepted";
pub(crate) const ACCEPTANCE_VERSION: f64 = 1.0;
pub(crate) const ACCEPTANCE_ADDRESS_INFO: &str = "rest/accepted/v1";

/// The merchant's acceptance (SPEC.md §31, The merchant's acceptance): the merchant accepts by
/// hand, in its app, what an order underpaid on-chain received as paying it. A record of the team
/// (never the integration's: it opens one but cannot make one), sealed with the channel's key, at
/// an address the integration key derives (salt `INTEGRATION_SALT`) from the order's sale author,
/// the invoice's deposit address and its `expiresAt`. The type and the `info` string never
/// change: the merchant's app writes the same records.
pub(crate) const MERCHANT_ACCEPTANCE_RECORD_TYPE: &str = "integration-onchain-accepted";
pub(crate) const MERCHANT_ACCEPTANCE_VERSION: f64 = 1.0;

/// The `info` of the merchant's acceptance address of the invoice of the sale `sale` (its author,
/// hex) with the deposit address `address` and the end `expires_at` (Unix seconds, decimal).
pub(crate) fn merchant_acceptance_info(sale: &str, address: &str, expires_at: i64) -> String {
    format!("onchain-accepted/{sale}/{address}/{expires_at}/v1")
}
