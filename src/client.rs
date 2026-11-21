//! The client (SPEC.md §4): a shop's server for one sattle.me integration. It makes the invoice of
//! each order (a Lightning invoice, a deposit address of the merchant's wallet, or both), declares
//! it in the merchant's registry, and checks its payment. Made for a server that may live for one
//! call: nothing is kept between calls, each call reads the merchant (a removal stops the next
//! invoice), opens one connection per relay and closes them when it is done.
//!
//! A call returns only once every task it started ended (its relays' connections, closed, and its
//! publications past a quorum, not awaited): what it no longer waits for of its own future (an
//! HTTP request, a read) is dropped with it. Nothing it started runs on once it returned (SPEC.md
//! §4, §13).
//!
//! Cancellation is Rust's own: drop a call's future (`tokio::time::timeout`, `tokio::select!`, a
//! task aborted) and the call stops at once, sending nothing more: every task it started (its
//! relays' connections, its publications past a quorum) is aborted with it, its HTTP requests and
//! its explorer's WebSocket dropped. A dropped call fails with no error of the crate: it never
//! completes. A call dropped after a lease of a deposit address was published and before it was
//! confirmed leaves that lease unwithdrawn (as a withdrawal that failed): it holds its address
//! until its end, never gives its invoice an address, and the order does without that address
//! (SPEC.md §31: a failed withdrawal is only logged). A confirmed lease is never withdrawn, dropped
//! or not.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::future::{BoxFuture as SharedBoxFuture, Shared};
use num_bigint::BigUint;
use tokio::sync::{mpsc, oneshot};

use crate::channel::read_channel;
use crate::checkout::{CheckoutValue, RestReader, new_checkout_link};
use crate::declaration::{DeclarationInput, DeclaredPrice, RestOf, declaration_event, registry_of};
use crate::derive::{Registry, Sale, rest_keys, rest_record_address, sale_of};
use crate::error::{Error, ErrorCode};
use crate::http::{DefaultHttpClient, Http, HttpClient};
use crate::key::{IntegrationKey, parse_integration_key};
use crate::lightning::bolt11::Bolt11;
use crate::lnurl::{
    InvoiceAnswer, LightningInvoice, LightningPart, check_invoice, fetch_pay_request, request_invoice,
    sendable_sats, verify_payment,
};
use crate::model::{DeclaredInvoice, Invoice, InvoiceToCheck, Merchant, PaymentStatus, RateInfo};
use crate::nostr::event::Event;
use crate::nostr::relay::{CallTasks, PoolConfig, RelayPool, majority};
use crate::onchain::acceptance::{AcceptanceOf, publish_acceptance};
use crate::onchain::address::{SIZED_ADDRESS, payment_uri};
use crate::onchain::explorer::{Explorer, ExplorerTx, NodeFailures, address_transactions, pays_to};
use crate::onchain::lease::{
    HoldRecord, LeaseEvent, LeaseHold, LeaseTerms, is_confirmed, is_leased, lease_event, read_leases,
    withdrawal_event,
};
use crate::onchain::lot::read_lot;
use crate::onchain::merchant_acceptance::{
    AcceptedInvoice, MerchantAcceptance, MerchantAcceptanceKeys, read_merchant_acceptance,
};
use crate::onchain::methods::{LeaseOutcome, methods_with, payment_methods};
use crate::onchain::node::{BitcoinNode, NodeFallback, record_node_for};
use crate::onchain::payment::{
    InvoiceTerms, OnchainCheck, OnchainPart, RestPart, Settled, Witnesses, check_onchain_part, combine_parts,
    rest_summary,
};
use crate::onchain::rest::{
    RestAsk, RestInvoice, RestLinkTerms, RestReaderKeys, publish_rest_record, read_rest_records,
    rest_record_event, rest_to_ask, sendable,
};
use crate::onchain::watch::watch_address;
use crate::onchain::witness::{
    InvoiceOf, OrderWitnesses, SeenKeys, Witness, publish_witness, read_named_addresses,
    read_order_witnesses, seen_of, witness_address,
};
use crate::order::{
    CheckedOrder, Order, StoredInvoice, check_milliseconds, check_order, check_ref, check_stored_invoice,
};
use crate::protocol::{
    DEFAULT_INTERVAL_MS, DEFAULT_TIMEOUT_MS, GRACE_SECONDS, MAX_ADDRESS_TRIES, MAX_INTERVAL_MS,
    MAX_PARALLEL_PAYMENT_CHECKS, MAX_SATS, MAX_TIMEOUT_MS, MAX_WITNESS_INPUTS, MIN_INTERVAL_MS,
    MIN_TIMEOUT_MS, ONCHAIN_CHECK_INTERVAL_MS, SATS_CURRENCY,
};
use crate::rates::{
    RATE_SOURCE_RULE, Rate, RateContext, RateSource, Sources, fetch_first_rate, minor_to_sats,
    rate_source_list,
};
use crate::runtime::{Clock, LogLogger, Logger, OsRandom, Random, SystemClock, Zeros, seconds};
use crate::sales::{
    Pending, SaleDeclaration, SaleRecords, may_still_be_paid, pending_outcome, read_sale_declarations,
    rest_key_of,
};
use crate::secret::SecretText;
use crate::transport::{BoxFuture, Transport};
use crate::websocket::{DefaultWebSocketClient, WebSocketClient};

/// What the server needs of the merchant, read with the key alone (the integration's channel).
/// No `Debug`: it holds the registry key, the Lightning address and the merchant's tolerance.
#[derive(Clone)]
struct MerchantChannel {
    business_name: String,
    /// Never given to the integrator.
    lightning_address: String,
    registry: Registry,
    /// The account's relays: where declarations, leases, witnesses and checkout links go.
    relays: Vec<String>,
    /// The merchant's web app for checkout links; `None` when its app gives none.
    checkout_origin: Option<String>,
    /// The merchant's tolerance of on-chain underpayments (basis points): a new order's lease
    /// keeps it. Never in what the integrator or the customer gets.
    tolerance: u64,
    /// The merchant's Bitcoin node (SPEC.md §31), `None` for mempool.space: the pages of checkout
    /// links read it too when its `payers` is true.
    bitcoin_node: Option<BitcoinNode>,
    /// The explorer the call reads: the node with its fallback, else mempool.space.
    explorer: Explorer,
}

/// What the reads of the explorer of one call share (SPEC.md §31, "in the same call"): when the
/// node failed, and, for `wait_for_payment`, who hears the node each channel read names (its
/// WebSocket follows it).
#[derive(Clone, Default)]
struct CallExplorer {
    failures: NodeFailures,
    nodes: Option<mpsc::UnboundedSender<Option<BitcoinNode>>>,
}

/// A client of one sattle.me integration ([`Client::builder`]). Cheap to clone: clones share
/// their configuration and their order of calls per order (calls for one order's reference run
/// one after the other within one client and its clones).
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    access: IntegrationKey,
    rate_sources: Vec<RateSource>,
    coingecko_api_key: Option<SecretText>,
    http: Http,
    websocket: Arc<dyn WebSocketClient>,
    relay_timeout: Duration,
    logger: Arc<dyn Logger>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    /// One invoice at a time per order, in this client.
    orders: Locks,
    /// One invoice of the rest at a time per invoice (`ref/address`), in this client.
    rest_asks: Locks,
}

impl fmt::Debug for Client {
    /// The integration's team and relays: never its key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("team", &self.inner.access.team)
            .field("relays", &self.inner.access.relays)
            .finish_non_exhaustive()
    }
}

/// Locks by name: calls of one name run one after the other.
#[derive(Default)]
struct Locks(Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>);

/// A lock held: released (and forgotten when nobody waits for it) when dropped.
struct Held<'a> {
    locks: &'a Locks,
    name: String,
    lock: Option<Arc<tokio::sync::Mutex<()>>>,
    _guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Locks {
    async fn lock(&self, name: &str) -> Held<'_> {
        let lock = {
            let mut locks = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            locks.entry(name.to_owned()).or_default().clone()
        };
        let mut held = Held { locks: self, name: name.to_owned(), lock: Some(lock.clone()), _guard: None };
        held._guard = Some(lock.lock_owned().await);
        held
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self._guard.take();
        let lock = self.lock.take();
        let mut locks = self.locks.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(lock);
        // Only the map holds it: nobody waits.
        if locks.get(&self.name).is_some_and(|lock| Arc::strong_count(lock) == 1) {
            locks.remove(&self.name);
        }
    }
}

/// How a client is made: [`Client::builder`].
pub struct ClientBuilder {
    key: SecretText,
    rate_sources: Option<Vec<RateSource>>,
    coingecko_api_key: Option<SecretText>,
    relay_timeout_ms: Option<u64>,
    http_timeout_ms: Option<u64>,
    http_client: Option<Arc<dyn HttpClient>>,
    websocket_client: Option<Arc<dyn WebSocketClient>>,
    logger: Option<Arc<dyn Logger>>,
    clock: Option<Arc<dyn Clock>>,
    random: Option<Arc<dyn Random>>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBuilder")
            .field("key", &self.key)
            .field("rate_sources", &self.rate_sources)
            .field("coingecko_api_key", &self.coingecko_api_key)
            .field("relay_timeout_ms", &self.relay_timeout_ms)
            .field("http_timeout_ms", &self.http_timeout_ms)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Where invoices priced in a currency get their rate (SPEC.md §26): one source, in place of
    /// the default list. Each order may give its own.
    pub fn rate_source(self, source: RateSource) -> Self {
        self.rate_sources([source])
    }

    /// Where invoices priced in a currency get their rate: a list of sources asked in its order,
    /// the next one only when the previous one gives no usable price; 1 or more, no name twice.
    /// The default list ([`RateSource::defaults`]) when not given.
    pub fn rate_sources(mut self, sources: impl IntoIterator<Item = RateSource>) -> Self {
        self.rate_sources = Some(sources.into_iter().collect());
        self
    }

    /// CoinGecko's Demo API key, sent to CoinGecko only (the header `x-cg-demo-api-key`): 1 or
    /// more visible ASCII characters. Without it, CoinGecko's keyless API (limited by IP).
    pub fn coingecko_api_key(mut self, key: impl Into<String>) -> Self {
        self.coingecko_api_key = Some(SecretText::new(key.into()));
        self
    }

    /// Per relay request (a page of a read, a publication), the wait for its connection included:
    /// 100 to 60 000 ms, 10 000 by default.
    pub fn relay_timeout_ms(mut self, milliseconds: u64) -> Self {
        self.relay_timeout_ms = Some(milliseconds);
        self
    }

    /// Per HTTP request (the Lightning address, the rate sources, the explorer), its body
    /// included: 100 to 60 000 ms, 10 000 by default.
    pub fn http_timeout_ms(mut self, milliseconds: u64) -> Self {
        self.http_timeout_ms = Some(milliseconds);
        self
    }

    /// The HTTP client: for tests, proxies, or to restrict what the server reaches (SPEC.md §27).
    /// The default one is hyper's, over rustls with the Mozilla roots of `webpki-roots`.
    pub fn http_client(mut self, client: impl HttpClient + 'static) -> Self {
        self.http_client = Some(Arc::new(client));
        self
    }

    /// The WebSocket client, for the relays and the explorer's WebSocket. The default one is
    /// tokio-tungstenite's, over rustls; its handshake bounded by `relay_timeout_ms`.
    pub fn websocket_client(mut self, client: impl WebSocketClient + 'static) -> Self {
        self.websocket_client = Some(Arc::new(client));
        self
    }

    /// Where warnings go: the `log` crate's `warn!` by default ([`LogLogger`]). Never given a
    /// secret.
    pub fn logger(mut self, logger: impl Logger + 'static) -> Self {
        self.logger = Some(Arc::new(logger));
        self
    }

    /// The clock, for tests only: the system's by default ([`SystemClock`]).
    pub fn clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Some(Arc::new(clock));
        self
    }

    /// Where random bytes come from, for reproducible tests only: the operating system's CSPRNG
    /// by default ([`OsRandom`]).
    pub fn random(mut self, random: impl Random + 'static) -> Self {
        self.random = Some(Arc::new(random));
        self
    }

    /// The client, its options checked (SPEC.md §4): `invalid_key` for a key that is not an
    /// integration key, `invalid_option` naming an invalid option, before any request.
    pub fn build(self) -> Result<Client, Error> {
        let access = parse_integration_key(self.key.expose())?;
        let rate_sources = match self.rate_sources {
            None => RateSource::defaults(),
            Some(sources) => rate_source_list(sources)
                .ok_or_else(|| Error::invalid_option("rateSource", RATE_SOURCE_RULE))?,
        };
        // Visible ASCII: its HTTP header carries it as it is.
        if let Some(key) = &self.coingecko_api_key {
            let text = key.expose();
            if text.is_empty() || !text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
                return Err(Error::invalid_option("coingeckoApiKey", "1 or more visible ASCII characters"));
            }
        }
        let relay_timeout = check_milliseconds(
            self.relay_timeout_ms,
            DEFAULT_TIMEOUT_MS,
            MIN_TIMEOUT_MS,
            MAX_TIMEOUT_MS,
            "relayTimeoutMs",
        )?;
        let http_timeout = check_milliseconds(
            self.http_timeout_ms,
            DEFAULT_TIMEOUT_MS,
            MIN_TIMEOUT_MS,
            MAX_TIMEOUT_MS,
            "httpTimeoutMs",
        )?;
        let relay_timeout = Duration::from_millis(relay_timeout);
        let needs_transport = self.http_client.is_none() || self.websocket_client.is_none();
        let transport = needs_transport.then(Transport::system);
        let http_client = self.http_client.unwrap_or_else(|| {
            Arc::new(DefaultHttpClient::new(transport.clone().expect("made when needed")))
        });
        let websocket = self.websocket_client.unwrap_or_else(|| {
            Arc::new(DefaultWebSocketClient::new(transport.clone().expect("made when needed"), relay_timeout))
        });
        Ok(Client {
            inner: Arc::new(Inner {
                access,
                rate_sources,
                coingecko_api_key: self.coingecko_api_key,
                http: Http { client: http_client, timeout: Duration::from_millis(http_timeout) },
                websocket,
                relay_timeout,
                logger: self.logger.unwrap_or_else(|| Arc::new(LogLogger)),
                clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
                random: self.random.unwrap_or_else(|| Arc::new(OsRandom)),
                orders: Locks::default(),
                rest_asks: Locks::default(),
            }),
        })
    }
}

/// What hears each status `wait_for_payment` gives.
type StatusHook = Box<dyn FnMut(&PaymentStatus) + Send>;

/// How `wait_for_payment` waits (SPEC.md §23).
#[derive(Default)]
pub struct WaitOptions {
    interval_ms: Option<u64>,
    on_status: Option<StatusHook>,
}

impl fmt::Debug for WaitOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitOptions")
            .field("interval_ms", &self.interval_ms)
            .field("on_status", &self.on_status.as_ref().map(|_| ".."))
            .finish()
    }
}

impl WaitOptions {
    /// Between two checks: 250 to 60 000 ms, 2000 by default.
    pub fn interval_ms(mut self, milliseconds: u64) -> Self {
        self.interval_ms = Some(milliseconds);
        self
    }

    /// Hears each status.
    pub fn on_status(mut self, on_status: impl FnMut(&PaymentStatus) + Send + 'static) -> Self {
        self.on_status = Some(Box::new(on_status));
        self
    }
}

/// A deposit address leased for an order: its lease confirmed and marked.
struct Leased {
    address: String,
}

/// What leasing an address gave.
enum LeaseResult {
    Leased(Leased),
    None,
    ExplorerFailed(Error),
}

/// The last result of each part of an invoice (`None`: it has none).
#[derive(Clone, Debug, Default)]
struct Parts {
    lightning: Option<Settled<LightningPart>>,
    onchain: Option<Settled<OnchainPart>>,
    rests: Option<RestPart>,
}

/// The status of `stored` from its parts, at `now`; a part's error.
fn status_of(stored: &StoredInvoice, parts: &Parts, now: i64) -> Result<PaymentStatus, Error> {
    combine_parts(
        InvoiceTerms {
            sats: stored.sats,
            expires_at: stored.expires_at,
            address: stored.onchain_address.as_deref(),
        },
        now,
        parts.lightning.as_ref(),
        parts.onchain.as_ref(),
        parts.rests.as_ref(),
    )
}

/// What the Lightning part of a payment check needs of a rest invoice.
fn lightning_of(invoice: &RestInvoice) -> LightningInvoice {
    LightningInvoice {
        bolt11: invoice.bolt11.clone(),
        payment_hash: invoice.payment_hash.clone(),
        verify_url: invoice.verify_url.clone(),
        expires_at: invoice.expires_at,
    }
}

/// Whether a Lightning part is final: paid, or expired for good.
fn is_final(result: &Settled<LightningPart>) -> bool {
    matches!(result, Ok(LightningPart::Paid(_) | LightningPart::Expired))
}

fn is_paid(result: &Settled<LightningPart>) -> bool {
    matches!(result, Ok(LightningPart::Paid(_)))
}

/// What a payment check asks of a declared invoice.
fn stored_of(invoice: &DeclaredInvoice) -> StoredInvoice {
    StoredInvoice {
        reference: Some(invoice.reference.clone()),
        lightning: invoice.bolt11.as_ref().map(|bolt11| LightningInvoice {
            bolt11: bolt11.clone(),
            payment_hash: invoice.payment_hash.clone().unwrap_or_default(),
            verify_url: invoice.verify_url.clone().unwrap_or_default(),
            expires_at: invoice.expires_at,
        }),
        onchain_address: invoice.onchain_address.clone(),
        sats: invoice.sats,
        expires_at: invoice.expires_at,
    }
}

/// The warnings of the checks of one `wait_for_payment` (SPEC.md §23): a warning each check meets
/// again is logged once, and again only once a check went without it.
struct OnceWarnings {
    logger: Arc<dyn Logger>,
    /// What the last check met, and what this one met so far.
    seen: Mutex<(HashSet<String>, HashSet<String>)>,
}

impl OnceWarnings {
    fn new(logger: Arc<dyn Logger>) -> Self {
        Self { logger, seen: Mutex::new((HashSet::new(), HashSet::new())) }
    }

    /// Warns of a check that failed (`network`): it is checked again.
    fn failed(&self, error: &Error) {
        self.warn(&format!(
            "sattleme-checkout: the payment check failed ({}); checked again",
            error.message()
        ));
    }

    /// A check ended: a warning it did not meet stopped.
    fn checked(&self) {
        let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = std::mem::take(&mut seen.1);
        seen.0 = now;
    }
}

impl Logger for OnceWarnings {
    fn warn(&self, message: &str) {
        let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !seen.0.contains(message) && !seen.1.contains(message) {
            self.logger.warn(message);
        }
        seen.1.insert(message.to_owned());
    }
}

/// `items` in a random order, from the CSPRNG (so that two servers rarely try the same address
/// first): Fisher–Yates, each draw without bias.
fn shuffle<T>(mut items: Vec<T>, random: &dyn Random) -> Vec<T> {
    for index in (1..items.len()).rev() {
        let bound = (index + 1) as u64;
        // The largest multiple of `bound` within 2^32: draws at or above it are drawn again.
        let limit = (1u64 << 32) - ((1u64 << 32) % bound);
        let draw = loop {
            let mut bytes = [0u8; 4];
            random.fill(&mut bytes);
            let draw = u64::from(u32::from_be_bytes(bytes));
            if draw < limit {
                break draw;
            }
        };
        items.swap(index, (draw % bound) as usize);
    }
    items
}

/// `first`, and `rest` meanwhile: an error of `first` wins at once (`rest` dropped); else `rest`'s
/// outcome too.
async fn first_then<A, B>(
    first: impl Future<Output = Result<A, Error>>,
    rest: impl Future<Output = B>,
) -> Result<(A, B), Error> {
    let mut first = pin!(first);
    let mut rest = pin!(rest);
    let mut rest_out = None;
    let a = loop {
        tokio::select! {
            a = &mut first => break a?,
            b = &mut rest, if rest_out.is_none() => rest_out = Some(b),
        }
    };
    let b = match rest_out {
        Some(b) => b,
        None => rest.await,
    };
    Ok((a, b))
}

/// The relays, the merchant and the sale's records a check may use (else it reads its own).
struct Scope<'a> {
    pool: &'a RelayPool,
    merchant: &'a MerchantChannel,
    records: Option<&'a SaleRecords>,
}

/// The order's witnesses, and the merchant's acceptance of the invoice, on the merchant's relays,
/// for the on-chain part of a check.
struct RelayWitnesses<'a> {
    client: &'a Client,
    pool: &'a RelayPool,
    seen: SeenKeys,
    address: &'a str,
    sale: &'a str,
    expires_at: i64,
    relays: &'a [String],
    /// The keys of the merchant's acceptance of the invoice (the team's record), and its terms.
    accepted: MerchantAcceptanceKeys,
    invoice: AcceptedInvoice,
}

impl Witnesses for RelayWitnesses<'_> {
    fn read(&self, every_relay: bool) -> BoxFuture<'_, Result<OrderWitnesses, Error>> {
        Box::pin(read_order_witnesses(
            self.pool,
            InvoiceOf {
                seen: &self.seen,
                address: self.address,
                sale_author: self.sale,
                expires_at: self.expires_at,
            },
            self.relays,
            &*self.client.inner.random,
            every_relay,
        ))
    }

    fn merchant_acceptance(&self) -> BoxFuture<'_, Result<MerchantAcceptance, Error>> {
        Box::pin(read_merchant_acceptance(
            self.pool,
            &self.accepted,
            self.invoice,
            self.relays,
            &*self.client.inner.random,
        ))
    }

    fn witness_address(&self, txid: &str, sale: Option<&str>) -> String {
        witness_address(&self.seen.address_key, self.address, txid, sale)
    }

    fn publish<'a>(&'a self, witness: &'a Witness) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(publish_witness(
            self.pool,
            &self.seen,
            witness,
            self.relays,
            self.client.seconds(),
            &*self.client.inner.random,
        ))
    }
}

type LightningFuture<'a> = Shared<SharedBoxFuture<'a, Option<Settled<LightningPart>>>>;

impl Client {
    /// A client for the integration key `key` (`sattleme_ck_…`), its options to be set: then
    /// [`ClientBuilder::build`]. The key is a secret: from the environment or a vault, never in a
    /// repository nor a log.
    pub fn builder(key: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            key: SecretText::new(key.into()),
            rate_sources: None,
            coingecko_api_key: None,
            relay_timeout_ms: None,
            http_timeout_ms: None,
            http_client: None,
            websocket_client: None,
            logger: None,
            clock: None,
            random: None,
        }
    }

    /// A client for the integration key `key`, with every option's default.
    pub fn new(key: impl Into<String>) -> Result<Self, Error> {
        Self::builder(key).build()
    }

    fn seconds(&self) -> i64 {
        seconds(&*self.inner.clock)
    }

    fn logger(&self) -> &dyn Logger {
        &*self.inner.logger
    }

    /// Relays of the call `call`: one connection per relay, closed once the call is done (the pool
    /// dropped, and what still runs past a quorum ended by `call` before the call returns).
    fn pool(&self, call: &CallTasks) -> RelayPool {
        RelayPool::new(PoolConfig {
            websocket: self.inner.websocket.clone(),
            timeout: self.inner.relay_timeout,
            random: self.inner.random.clone(),
            clock: self.inner.clock.clone(),
            call: call.clone(),
        })
    }

    /// The integration's channel, read on the connections of `pool`, with the explorer of a call
    /// of its own.
    async fn channel(&self, pool: &RelayPool, logger: &dyn Logger) -> Result<MerchantChannel, Error> {
        self.channel_of_call(pool, logger, NodeFailures::default()).await
    }

    /// The integration's channel, read on the connections of `pool`, with the explorer of the call:
    /// its node's failures in `failures`.
    async fn channel_of_call(
        &self,
        pool: &RelayPool,
        logger: &dyn Logger,
        failures: NodeFailures,
    ) -> Result<MerchantChannel, Error> {
        let read = read_channel(pool, &self.inner.access, &*self.inner.random, logger).await?;
        let channel = read.channel;
        Ok(MerchantChannel {
            explorer: Explorer::new(channel.bitcoin_node.as_ref(), failures, self.inner.clock.clone()),
            business_name: channel.business_name,
            lightning_address: channel.lightning_address,
            registry: registry_of(&channel.registry_key, &channel.registry_reader),
            relays: channel.relays.unwrap_or_else(|| self.inner.access.relays.clone()),
            checkout_origin: channel.checkout_origin,
            tolerance: channel.tolerance,
            bitcoin_node: channel.bitcoin_node,
        })
    }

    /// The integration's lot of deposit addresses, read on the merchant's relays.
    async fn lot(&self, pool: &RelayPool, merchant: &MerchantChannel) -> Result<Vec<String>, Error> {
        read_lot(pool, &self.inner.access, &merchant.relays, &*self.inner.random, self.logger()).await
    }

    /// The merchant (SPEC.md §4): its business's name, the sendable sats of its Lightning address,
    /// and how many deposit addresses the integration's lot holds. `revoked` when the merchant
    /// removed the integration. Never its Lightning address.
    pub async fn merchant(&self) -> Result<Merchant, Error> {
        let call = CallTasks::default();
        ended(&call, self.merchant_in(&call)).await
    }

    async fn merchant_in(&self, call: &CallTasks) -> Result<Merchant, Error> {
        let pool = self.pool(call);
        let merchant = self.channel(&pool, self.logger()).await?;
        let (lot, pay) = tokio::join!(
            self.lot(&pool, &merchant),
            fetch_pay_request(&merchant.lightning_address, &self.inner.http)
        );
        let lot = lot?;
        let (min, max) = sendable_sats(&pay?);
        Ok(Merchant {
            business_name: merchant.business_name,
            min_sats: min,
            max_sats: max,
            onchain_addresses: lot.len() as u64,
        })
    }

    /// The invoice of an order (SPEC.md §17): a Lightning invoice asked to the merchant's
    /// Lightning address and checked, when its amount is within the address's sendable sats; a
    /// deposit address of the merchant's wallet leased from the integration's lot, from 1 000
    /// sats (or both). Then the invoice is declared in the merchant's registry on a majority of
    /// its relays: only then may it be shown. Store it with the order ([`Invoice::to_json`]).
    ///
    /// One order, one invoice at a time: `invoice_pending` (with that invoice) while an earlier
    /// invoice of the same reference may still be paid (or its on-chain payment is being
    /// confirmed), `order_paid` when one was paid. `onchain_unavailable` when the order can only
    /// be paid on-chain and no address could be leased. With [`Order::checkout`], the invoice also
    /// gets a checkout link, published on a majority of the merchant's relays before the invoice
    /// is declared; `checkout_unavailable` when the merchant's app gives no web app for it.
    ///
    /// Calls for one reference run one after the other in this client; across processes, lock the
    /// order (in the shop's database) around this call.
    pub async fn create_invoice(&self, order: &Order) -> Result<Invoice, Error> {
        let order = check_order(order, &self.inner.rate_sources)?;
        // One at a time per order: two calls for one reference would both pass the check of its
        // earlier invoices.
        let _held = self.inner.orders.lock(&order.reference).await;
        let call = CallTasks::default();
        ended(&call, self.create_invoice_now(&order, &call)).await
    }

    async fn create_invoice_now(&self, order: &CheckedOrder, call: &CallTasks) -> Result<Invoice, Error> {
        let pool = self.pool(call);
        let merchant = self.channel(&pool, self.logger()).await?;
        if order.checkout && merchant.checkout_origin.is_none() {
            return Err(Error::checkout_unavailable());
        }
        let sale = sale_of(&self.inner.access.key, &merchant.registry, &order.reference);
        let http = &self.inner.http;
        // Asked while the registry is read: the Lightning address and the rate need nothing of it.
        let pay_request = fetch_pay_request(&merchant.lightning_address, http);
        let quote = async {
            match (&order.fiat, &order.rate_sources) {
                (Some(fiat), Some(sources)) => {
                    let sources_context = Sources {
                        context: RateContext {
                            http,
                            coingecko_api_key: self.inner.coingecko_api_key.as_ref().map(SecretText::expose),
                        },
                    };
                    let now = || self.seconds();
                    fetch_first_rate(sources, &fiat.currency, &now, self.logger(), &sources_context)
                        .await
                        .map(Some)
                }
                _ => Ok(None),
            }
        };
        let ((), (pay, quote)) =
            first_then(self.check_earlier_invoices(&pool, &sale, &merchant, order), async {
                tokio::join!(pay_request, quote)
            })
            .await?;
        let pay = pay?;
        let quote: Option<Rate> = quote?;

        let mut rate: Option<RateInfo> = None;
        let sats: u64 = match (&order.fiat, quote) {
            (Some(fiat), Some(quote)) => {
                let sats = minor_to_sats(fiat.minor, fiat.digits, &quote.price);
                if sats > BigUint::from(MAX_SATS) {
                    return Err(Error::invalid_order(
                        "fiat",
                        &format!("{sats} sats is more than 21 million bitcoins"),
                    ));
                }
                rate = Some(quote.info);
                u64::try_from(sats).expect("at most 21 million bitcoins")
            }
            _ => order.sats.expect("an order in sats, or in a currency with its rate"),
        };
        let methods =
            payment_methods(sats, sendable_sats(&pay), if order.fiat.is_some() { "fiat" } else { "sats" })?;

        let mut answer: Option<InvoiceAnswer> = None;
        let mut decoded: Option<Bolt11> = None;
        if methods.lightning {
            let asked = request_invoice(&pay, sats, order.duration_seconds, Some(&order.label), http).await?;
            decoded = Some(check_invoice(&asked, &pay, sats, order.duration_seconds, self.seconds())?);
            answer = Some(asked);
        }
        let leased_at = self.seconds();
        let created_at = decoded.as_ref().map_or(leased_at, |decoded| decoded.timestamp);
        let expires_at = decoded.as_ref().map_or(leased_at + order.duration_seconds, Bolt11::expires_at);
        let price = match &order.fiat {
            Some(fiat) => {
                DeclaredPrice { minor: fiat.minor, digits: fiat.digits, currency: fiat.currency.clone() }
            }
            None => DeclaredPrice { minor: sats, digits: 0, currency: SATS_CURRENCY.to_owned() },
        };

        let mut declaration: Option<Event> = None;
        if let (Some(answer), Some(decoded)) = (&answer, &decoded) {
            let input = DeclarationInput {
                sale: &sale,
                invoice: &answer.pr,
                verify_url: &answer.verify,
                payment_hash: &decoded.payment_hash,
                price: &price,
                note: &order.label,
                created_at: self.seconds(),
                rest: None,
            };
            // A valid invoice too long for a NIP-44 plaintext (65 535 bytes) cannot be declared.
            declaration = Some(
                declaration_event(&input, &*self.inner.random)
                    .ok_or_else(|| Error::invalid_invoice("The invoice is too large to be declared"))?,
            );
        }

        // What the lease of an address holds, with on-chain.
        let terms = LeaseTerms {
            address: String::new(),
            sats,
            invoice: answer.as_ref().map(|answer| answer.pr.clone()),
            verify_url: answer.as_ref().map(|answer| answer.verify.clone()),
            created_at,
            expires_at,
            price: price.clone(),
            note: order.label.clone(),
            // The order's for good: every check judges its payment with it.
            tolerance: merchant.tolerance,
            confirmed: None,
        };
        if methods.onchain {
            // The lease holds the invoice too, sealed twice: a lease that does not fit a NIP-44
            // plaintext fails now, before anything is read or published (SPEC.md §17 step 6). The
            // real one differs from this one by its address alone, of one length for every deposit
            // address (as first published, unconfirmed: its mark is no longer).
            let sized =
                LeaseTerms { address: SIZED_ADDRESS.to_owned(), confirmed: Some(false), ..terms.clone() };
            // Never published: its size alone counts, the client's random bytes are left alone.
            if lease_event(&sale, &sized, leased_at, &Zeros).is_none() {
                return Err(Error::invalid_invoice("The invoice is too large for the lease of an address"));
            }
        }

        // The address before the link and the declaration: when the lease fails, nothing is
        // published.
        let mut lease: Option<Leased> = None;
        if methods.onchain {
            // Without an invoice, the lease's date is the Invoice's.
            let leased = self
                .lease_address(&pool, &merchant, &sale, terms, decoded.is_none().then_some(leased_at))
                .await?;
            let outcome = match leased {
                LeaseResult::Leased(leased) => {
                    lease = Some(leased);
                    LeaseOutcome::Leased
                }
                LeaseResult::None => LeaseOutcome::None,
                LeaseResult::ExplorerFailed(error) => {
                    if methods.lightning {
                        self.logger().warn(&format!(
                            "sattleme-checkout: no deposit address leased, the explorer did not answer ({}): Lightning only",
                            error.message()
                        ));
                    }
                    LeaseOutcome::ExplorerFailed(error)
                }
            };
            methods_with(methods, outcome)?;
        }
        let onchain_address = lease.as_ref().map(|lease| lease.address.clone());

        // On a failure below, the lease stays: it holds its address until its end (a withdrawal on
        // some relays only would leave them disagreeing), and was confirmed: §21 may hand it out.
        let mut checkout_url: Option<String> = None;
        // The link before the declaration: when the link fails, nothing is declared and the order
        // gets a new invoice at once; when the declaration fails, the link's URL was never given
        // and its keys are gone, so nobody can open it.
        if order.checkout {
            let rest = onchain_address.as_ref().map(|address| {
                let keys = rest_keys(&self.inner.access.key, &order.reference, address, expires_at);
                RestReader { author: keys.author, key: crate::text::to_hex(keys.key.expose()) }
            });
            let value = CheckoutValue {
                business_name: merchant.business_name.clone(),
                invoice: answer.as_ref().map(|answer| answer.pr.clone()),
                verify_url: answer.as_ref().map(|answer| answer.verify.clone()),
                onchain_address: onchain_address.clone(),
                sats,
                created_at,
                expires_at,
                fiat: order.fiat.as_ref().map(|_| price.clone()),
                note: order.label.clone(),
                redirect_url: order.redirect_url.clone(),
                rest,
                // With an address only: never in a record of version 1.
                bitcoin_node: onchain_address
                    .as_ref()
                    .and_then(|_| record_node_for(merchant.bitcoin_node.as_ref())),
            };
            checkout_url = Some(self.publish_checkout(&pool, &merchant, &value, expires_at).await?);
        }
        if let Some(event) = &declaration {
            self.declare(&pool, event, &sale, &merchant).await?;
        }
        let bolt11 = answer.as_ref().map(|answer| answer.pr.clone());
        Ok(Invoice {
            reference: order.reference.clone(),
            payment_uri: payment_uri(onchain_address.as_deref(), sats, bolt11.as_deref()),
            bolt11,
            payment_hash: decoded.as_ref().map(|decoded| decoded.payment_hash.clone()),
            verify_url: answer.as_ref().map(|answer| answer.verify.clone()),
            onchain_address,
            sats,
            fiat: order.fiat.clone(),
            rate,
            note: order.label.clone(),
            created_at,
            expires_at,
            checkout_url,
            redirect_url: if order.checkout { order.redirect_url.clone() } else { None },
        })
    }

    /// Leases a deposit address of the integration's lot for `sale` (SPEC.md §31, Leasing an
    /// address): the lot and its leases read; of its free addresses, in a random order, at most 3
    /// tried, one at a time: one the explorer shows paid already is skipped (its witness none
    /// published), the explorer read with its fallback (SPEC.md §31: the merchant's Bitcoin node
    /// with `"none"` and down, no address: [`LeaseResult::ExplorerFailed`]); else the lease is
    /// published on a majority, the address's leases read again on every relay, and the lease
    /// confirmed then marked, or withdrawn when it is not confirmed. A lease once confirmed is
    /// never withdrawn. `leased_at`: the lease's date when it is the
    /// Invoice's (an order paid on-chain only).
    async fn lease_address(
        &self,
        pool: &RelayPool,
        merchant: &MerchantChannel,
        sale: &Sale,
        terms: LeaseTerms,
        leased_at: Option<i64>,
    ) -> Result<LeaseResult, Error> {
        let lot = self.lot(pool, merchant).await?;
        if lot.is_empty() {
            return Ok(LeaseResult::None);
        }
        let relays = &merchant.relays;
        let seen = seen_of(&self.inner.access.key);
        // The leases, complete or not (the confirmation decides), and the addresses a witness names.
        let (leases, named) = tokio::join!(
            read_leases(
                pool,
                &merchant.registry.key,
                &lot,
                relays,
                self.seconds(),
                &*self.inner.random,
                false
            ),
            read_named_addresses(pool, &seen, &lot, relays, &*self.inner.random),
        );
        if !leases.answered {
            return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
        }
        // A lease of a newer format holds its address (its signature never checked: only a holder
        // of the registry key seals one): update the crate (SPEC.md §12).
        if leases
            .records
            .iter()
            .any(|(_, records)| records.iter().any(|record| record.outside == LeaseHold::Newer))
        {
            self.logger().warn(
                "sattleme-checkout: a lease of the integration's addresses has a newer format than this version reads; update the crate",
            );
        }
        let named = named?;
        let now = self.seconds();
        // Not where the read shows a record of the sale (its signature checked): an earlier call of
        // the order tried it, and a new lease could be of the second of its withdrawal, and either
        // replace the other.
        let free: Vec<String> = lot
            .iter()
            .filter(|address| {
                let records = leases.of(address);
                !named.contains(*address)
                    && !is_leased(&records, now)
                    && !records.iter().any(|record| record.event.pubkey == sale.author && record.signed())
            })
            .cloned()
            .collect();
        let free = shuffle(free, &*self.inner.random);
        for address in free.into_iter().take(MAX_ADDRESS_TRIES) {
            let http = &self.inner.http;
            let read = merchant.explorer.read(|at| {
                let address = &address;
                async move { address_transactions(&at, address, http).await }
            });
            let txs = match read.await {
                Ok(txs) => txs,
                Err(error) => return Ok(LeaseResult::ExplorerFailed(error)),
            };
            let paid: Vec<ExplorerTx> = txs.into_iter().filter(|tx| pays_to(tx, &address) > 0).collect();
            if !paid.is_empty() {
                // Paid on-chain already: of no order, for good.
                self.publish_witnesses_of_none(pool, merchant, &seen, &address, &paid).await;
                continue;
            }
            // Published unconfirmed: it holds the address, never gives the invoice one.
            let unconfirmed =
                LeaseTerms { address: address.clone(), confirmed: Some(false), ..terms.clone() };
            let event = lease_event(
                sale,
                &unconfirmed,
                leased_at.unwrap_or_else(|| self.seconds()),
                &*self.inner.random,
            )
            .ok_or_else(|| Error::invalid_invoice("The invoice is too large for the lease of an address"))?;
            if let Err(error) = self.publish_lease_record(pool, relays, &event, sale).await {
                // On some relays only: withdrawn, never the order's.
                self.withdraw(pool, relays, sale, &address, &event).await;
                return Err(error);
            }
            // On every relay, each until its timeout: a relay that hides a lease cannot hide it
            // while one that holds it answers in time (SPEC.md §13, §27).
            let again = read_leases(
                pool,
                &merchant.registry.key,
                std::slice::from_ref(&address),
                relays,
                self.seconds(),
                &*self.inner.random,
                true,
            )
            .await;
            let records = again.of(&address);
            let own = LeaseEvent::of(&event);
            let confirmed = again.answered && again.complete && is_confirmed(&records, &own, self.seconds());
            if !confirmed {
                // Another server leased it at once (the later reader sees both), the read could not
                // be complete, or fewer than a majority answered: withdrawn (safe on some relays
                // only: the address was never the order's), unless the read shows another record of
                // the sale there whose signature checks out: another call of the order made it at
                // once (its lock failed, SPEC.md §17), and it is not this call's to end.
                let another = records.iter().any(|record| {
                    record.event.pubkey == sale.author && record.event.id != event.id && record.signed()
                });
                if !another {
                    self.withdraw(pool, relays, sale, &address, &event).await;
                }
                if !again.answered {
                    return Err(Error::network("Fewer than a majority of the merchant's relays answered"));
                }
                continue;
            }
            // Confirmed: never withdrawn from now on, whatever fails. Marked confirmed: from now on
            // the address is the order's, its invoice's in §21 too.
            let marked_terms =
                LeaseTerms { address: address.clone(), confirmed: Some(true), ..terms.clone() };
            let marked = lease_event(
                sale,
                &marked_terms,
                self.seconds().max(event.created_at + 1),
                &*self.inner.random,
            )
            .ok_or_else(|| Error::invalid_invoice("The invoice is too large for the lease of an address"))?;
            self.publish_lease_record(pool, relays, &marked, sale).await?;
            return Ok(LeaseResult::Leased(Leased { address }));
        }
        Ok(LeaseResult::None)
    }

    /// Withdraws `lease`, the lease of `address` by `sale` that was not confirmed: its withdrawal,
    /// a second after it (so that it replaces the lease, and no later record of the sale), on the
    /// merchant's relays; a failure only logged (the lease then holds its address until its end,
    /// and never gives its invoice one).
    async fn withdraw(&self, pool: &RelayPool, relays: &[String], sale: &Sale, address: &str, lease: &Event) {
        let event = withdrawal_event(sale, address, lease.created_at + 1, &*self.inner.random);
        if pool.publish_to_quorum(relays, &event, &sale.secret_key, majority(relays.len())).await.is_err() {
            self.logger().warn(
                "sattleme-checkout: a lease that was not confirmed could not be withdrawn; it holds its deposit address until its end",
            );
        }
    }

    /// Publishes a lease record on a majority of the merchant's `relays`, else `network`.
    async fn publish_lease_record(
        &self,
        pool: &RelayPool,
        relays: &[String],
        event: &Event,
        sale: &Sale,
    ) -> Result<(), Error> {
        pool.publish_to_quorum(relays, event, &sale.secret_key, majority(relays.len())).await.map_err(|_| {
            Error::network("Fewer than a majority of the merchant's relays took the lease of a deposit address: try again")
        })
    }

    /// Publishes a witness none of each transaction of `txs` paying `address`, failures logged.
    async fn publish_witnesses_of_none(
        &self,
        pool: &RelayPool,
        merchant: &MerchantChannel,
        seen: &SeenKeys,
        address: &str,
        txs: &[ExplorerTx],
    ) {
        let witnesses: Vec<Witness> = txs
            .iter()
            .map(|tx| Witness {
                address: address.to_owned(),
                txid: tx.txid.clone(),
                sale: None,
                sats: pays_to(tx, address),
                inputs: tx.coins.iter().take(MAX_WITNESS_INPUTS).cloned().collect(),
                replacement: false,
                expires_at: None,
            })
            .collect();
        let results = futures_util::future::join_all(witnesses.iter().map(|witness| {
            publish_witness(pool, seen, witness, &merchant.relays, self.seconds(), &*self.inner.random)
        }))
        .await;
        for error in results.into_iter().filter_map(Result::err) {
            self.logger().warn(&format!(
                "sattleme-checkout: the witness of a paid address was not published: {}",
                error.message()
            ));
        }
    }

    /// Publishes a new checkout link holding `value` on a majority of the merchant's relays, and
    /// gives its URL. The author's secret answers the relays' authentication, then is dropped with
    /// the link: nobody can change it afterwards. `network` when fewer than a majority took it.
    async fn publish_checkout(
        &self,
        pool: &RelayPool,
        merchant: &MerchantChannel,
        value: &CheckoutValue,
        expires_at: i64,
    ) -> Result<String, Error> {
        let origin =
            merchant.checkout_origin.as_deref().expect("checked: the merchant gives a checkout origin");
        let link = new_checkout_link(
            origin,
            &merchant.relays,
            value,
            expires_at,
            self.seconds(),
            &*self.inner.random,
        )
        .ok_or_else(|| Error::invalid_invoice("The invoice is too large for a checkout link"))?;
        pool.publish_to_quorum(
            &merchant.relays,
            &link.event,
            &link.secret_key,
            majority(merchant.relays.len()),
        )
        .await
        .map_err(|_| {
            Error::network("Fewer than a majority of the merchant's relays took the checkout link: try again")
        })?;
        Ok(link.url)
    }

    /// Refuses a new invoice for the sale while an earlier one may still be paid (until its end
    /// plus 120 s, or while its on-chain payment is being confirmed or undecided), or when one was
    /// paid: read in the registry, so that it holds even when the shop lost what it stored
    /// (SPEC.md §21).
    async fn check_earlier_invoices(
        &self,
        pool: &RelayPool,
        sale: &Sale,
        merchant: &MerchantChannel,
        order: &CheckedOrder,
    ) -> Result<(), Error> {
        let records = self.declared(pool, sale, merchant, false, self.logger()).await?;
        let earlier = &records.invoices;
        let scope = Scope { pool, merchant, records: Some(&records) };
        let invoices: Vec<DeclaredInvoice> =
            earlier.iter().map(|declaration| declaration.invoice.clone()).collect();
        let may_be_paid: Vec<&SaleDeclaration> =
            may_still_be_paid(&invoices, self.seconds()).into_iter().map(|index| &earlier[index]).collect();
        if !may_be_paid.is_empty() {
            // Their payments checked, even of one alone: an invoice already paid is never handed
            // out again. Several: the sale's records are read on every relay at the same time, and
            // the one shown is the one a majority holds.
            let everywhere = async {
                if may_be_paid.len() > 1 {
                    Some(self.declared(pool, sale, merchant, true, self.logger()).await)
                } else {
                    None
                }
            };
            let (statuses, everywhere) = tokio::join!(self.check_all(&may_be_paid, &scope), everywhere);
            let needed = majority(merchant.relays.len());
            let held: Option<Vec<bool>> = match &everywhere {
                Some(Ok(read)) => Some(
                    may_be_paid
                        .iter()
                        .map(|declaration| {
                            read.sent_by.get(&declaration.last_record().id).copied().unwrap_or(0) >= needed
                        })
                        .collect(),
                ),
                _ => None,
            };
            let open = match pending_outcome(&statuses, held.as_deref()) {
                Pending::Paid(index) => {
                    let status = statuses[index].clone().expect("a paid status");
                    return Err(Error::order_paid(may_be_paid[index].invoice.clone(), status));
                }
                Pending::Failed(index) => return Err(statuses[index].clone().expect_err("a failed check")),
                // Fewer than a majority answered the read again: after a payment and an error.
                Pending::Unread => {
                    return Err(match everywhere {
                        Some(Err(error)) => error,
                        _ => Error::network("Fewer than a majority of the merchant's relays answered"),
                    });
                }
                Pending::HandOut(index) => may_be_paid[index],
            };
            // Its createInvoice may have failed with fewer than a majority of the relays holding
            // its declaration or its lease ("do not show this invoice"): published again before it
            // is handed out. Its lease, with an address, was confirmed: the address is the order's.
            if let Some(event) = &open.event {
                self.declare(pool, event, sale, merchant).await?;
            }
            if let Some(lease) = &open.lease {
                self.publish_lease(pool, lease, sale, merchant).await?;
            }
            let invoice = &open.invoice;
            // A new link to it, for a shop that lost the one it stored (or never got it): links
            // only show the invoice, several of them change nothing.
            let checkout_url = if order.checkout {
                let rest = invoice.onchain_address.as_ref().map(|address| {
                    let keys =
                        rest_keys(&self.inner.access.key, &order.reference, address, invoice.expires_at);
                    RestReader { author: keys.author, key: crate::text::to_hex(keys.key.expose()) }
                });
                let value = CheckoutValue {
                    business_name: merchant.business_name.clone(),
                    invoice: invoice.bolt11.clone(),
                    verify_url: invoice.verify_url.clone(),
                    onchain_address: invoice.onchain_address.clone(),
                    sats: invoice.sats,
                    created_at: invoice.created_at,
                    expires_at: invoice.expires_at,
                    fiat: invoice.fiat.as_ref().map(|fiat| DeclaredPrice {
                        minor: fiat.minor,
                        digits: fiat.digits,
                        currency: fiat.currency.clone(),
                    }),
                    note: invoice.note.clone(),
                    redirect_url: order.redirect_url.clone(),
                    rest,
                    // The node of the channel this call read, with an address only.
                    bitcoin_node: invoice
                        .onchain_address
                        .as_ref()
                        .and_then(|_| record_node_for(merchant.bitcoin_node.as_ref())),
                };
                Some(self.publish_checkout(pool, merchant, &value, invoice.expires_at).await?)
            } else {
                None
            };
            return Err(Error::invoice_pending(invoice.clone(), checkout_url));
        }
        let all: Vec<&SaleDeclaration> = earlier.iter().collect();
        let statuses = self.check_all(&all, &scope).await;
        for (index, status) in statuses.iter().enumerate() {
            if let Ok(status @ PaymentStatus::Paid(_)) = status {
                return Err(Error::order_paid(earlier[index].invoice.clone(), status.clone()));
            }
        }
        // An on-chain payment being confirmed, or a transaction undecided: its time to be paid is
        // over, nothing is published again, and no new link.
        if let Some(index) = statuses.iter().position(|status| {
            matches!(status, Ok(PaymentStatus::Unconfirmed { .. } | PaymentStatus::Open { .. }))
        }) {
            return Err(Error::invoice_pending(earlier[index].invoice.clone(), None));
        }
        if let Some(Err(error)) = statuses.into_iter().find(Result::is_err) {
            return Err(error);
        }
        Ok(())
    }

    /// The payment of each of `invoices` checked (with their rest invoices), a few at a time: a
    /// paid invoice wins over a service that did not answer about another one.
    async fn check_all(
        &self,
        invoices: &[&SaleDeclaration],
        scope: &Scope<'_>,
    ) -> Vec<Result<PaymentStatus, Error>> {
        use futures_util::stream::{self, StreamExt};
        // Each check boxed as a `Send` future, made at once: no closure stays in the call's
        // future, so that the call can be spawned (the compiler cannot prove a future a closure
        // makes `Send` for every lifetime).
        let checks: Vec<BoxFuture<'_, Result<PaymentStatus, Error>>> = invoices
            .iter()
            .map(|declaration| -> BoxFuture<'_, Result<PaymentStatus, Error>> {
                Box::pin(self.check_declared(declaration, scope))
            })
            .collect();
        stream::iter(checks).buffered(MAX_PARALLEL_PAYMENT_CHECKS).collect().await
    }

    /// The payment of a declared invoice checked, with the records of `scope`.
    async fn check_declared(
        &self,
        declaration: &SaleDeclaration,
        scope: &Scope<'_>,
    ) -> Result<PaymentStatus, Error> {
        let stored = stored_of(&declaration.invoice);
        let parts = self.check(&stored, Some(scope), self.logger(), scope.pool.call(), None).await;
        status_of(&stored, &parts, self.seconds())
    }

    /// Publishes a declaration on a majority of the merchant's relays, else `network`.
    async fn declare(
        &self,
        pool: &RelayPool,
        event: &Event,
        sale: &Sale,
        merchant: &MerchantChannel,
    ) -> Result<(), Error> {
        pool.publish_to_quorum(&merchant.relays, event, &sale.secret_key, majority(merchant.relays.len())).await.map_err(|_| {
            Error::network(
                "Fewer than a majority of the merchant's relays took the invoice's declaration: do not show this invoice, try again",
            )
        })
    }

    /// Publishes a lease again on a majority of the merchant's relays, else `network`.
    async fn publish_lease(
        &self,
        pool: &RelayPool,
        event: &Event,
        sale: &Sale,
        merchant: &MerchantChannel,
    ) -> Result<(), Error> {
        pool.publish_to_quorum(&merchant.relays, event, &sale.secret_key, majority(merchant.relays.len())).await.map_err(|_| {
            Error::network("Fewer than a majority of the merchant's relays took the invoice's lease: do not show this invoice, try again")
        })
    }

    /// Where the payment of an invoice is (SPEC.md §22): its Lightning part from the merchant's
    /// Lightning address (LUD-21), its on-chain part from the explorer and the witnesses of its
    /// order, and the Lightning invoices of the rest of an on-chain underpayment, all at once.
    /// Underpaid on-chain, it asks the merchant's Lightning address for an invoice of the rest,
    /// declares it and publishes it for the order's checkout links (a failure is logged, the next
    /// check asks again). It never opens the explorer's WebSocket. `invalid_order` (`invoice`) for
    /// an invoice no implementation made; `network` (retry) when a service does not answer;
    /// `invalid_invoice` when an answer is not about this invoice or its preimage is wrong.
    pub async fn get_status(&self, invoice: impl Into<InvoiceToCheck>) -> Result<PaymentStatus, Error> {
        let stored = check_stored_invoice(&invoice.into())?;
        let call = CallTasks::default();
        let parts = ended(&call, self.check(&stored, None, self.logger(), &call, None)).await;
        status_of(&stored, &parts, self.seconds())
    }

    /// Every part of `stored` checked at once (SPEC.md §31): its Lightning part, and with an
    /// address its on-chain part and its rest part, read on the merchant's relays (those of
    /// `scope`, with the sale's records when already read; else over the connections of a call of
    /// its own, of `call`, the explorer's failures those of `explorer` when given, which hears the
    /// node of the channel read); an invoice of the rest asked when the status calls for one. A part
    /// that fails is its error.
    async fn check(
        &self,
        stored: &StoredInvoice,
        scope: Option<&Scope<'_>>,
        logger: &dyn Logger,
        call: &CallTasks,
        explorer: Option<&CallExplorer>,
    ) -> Parts {
        let now = self.seconds();
        let lightning: LightningFuture<'_> = {
            let invoice = stored.lightning.clone();
            let http = &self.inner.http;
            async move {
                match invoice {
                    Some(invoice) => Some(verify_payment(&invoice, http, now).await),
                    None => None,
                }
            }
            .boxed()
            .shared()
        };
        if stored.onchain_address.is_none() {
            return Parts { lightning: lightning.await, onchain: None, rests: None };
        }
        let address_parts = async {
            match scope {
                Some(scope) => Ok(self.address_parts(stored, scope, lightning.clone(), logger).await),
                None => {
                    let pool = self.pool(call);
                    let failures = explorer.map(|explorer| explorer.failures.clone()).unwrap_or_default();
                    match self.channel_of_call(&pool, logger, failures).await {
                        Ok(merchant) => {
                            if let Some(nodes) = explorer.and_then(|explorer| explorer.nodes.as_ref()) {
                                let _ = nodes.send(merchant.bitcoin_node.clone());
                            }
                            let scope = Scope { pool: &pool, merchant: &merchant, records: None };
                            Ok(self.address_parts(stored, &scope, lightning.clone(), logger).await)
                        }
                        Err(error) => Err(error),
                    }
                }
            }
        };
        let (own, parts) = tokio::join!(lightning.clone(), address_parts);
        match parts {
            Ok(parts) => parts,
            // The relays or the channel failed: the address's parts cannot be told.
            Err(error) => Parts { lightning: own, onchain: Some(Err(error)), rests: None },
        }
    }

    /// The on-chain part and the rest part of `stored` (it has an address and a reference), at
    /// once: the sale's records (its rest invoices, its lease) read while the explorer is asked;
    /// then, when the status is open with a rest and no invoice of it, one asked; the records of
    /// its rest invoices published again where a majority does not hold them; its acceptance
    /// record published when the status calls for one.
    async fn address_parts(
        &self,
        stored: &StoredInvoice,
        scope: &Scope<'_>,
        lightning: LightningFuture<'_>,
        logger: &dyn Logger,
    ) -> Parts {
        let Scope { pool, merchant, records } = *scope;
        let address = stored.onchain_address.as_deref().expect("an invoice with an address");
        let reference =
            stored.reference.as_deref().expect("checked: an invoice with an address has its reference");
        let sale = sale_of(&self.inner.access.key, &merchant.registry, reference);
        let http = &self.inner.http;
        let (tolerance_sender, tolerance_receiver) = oneshot::channel::<u64>();
        let (paid_sender, paid_receiver) = oneshot::channel::<u64>();
        let rest_side = async {
            let found: Result<SaleRecords, Error> = match records {
                Some(records) => Ok(records.clone()),
                None => self.declared(pool, &sale, merchant, false, logger).await,
            };
            // The order's tolerance, its lease's (the invoice's own terms): without the records,
            // or another lease of the address, none.
            let tolerance = match &found {
                Ok(found) => found
                    .leases
                    .get(address)
                    .map(|lease| &lease.terms)
                    .filter(|terms| terms.sats == stored.sats && terms.expires_at == stored.expires_at)
                    .map_or(0, |terms| terms.tolerance),
                Err(_) => 0,
            };
            let _ = tolerance_sender.send(tolerance);
            let rest_check: Result<RestPart, Error> = match &found {
                Err(error) => Err(error.clone()),
                Ok(found) => {
                    async {
                        // This invoice's own: another invoice of the order may have leased the address.
                        let invoices = found
                            .rests
                            .get(&rest_key_of(address, stored.expires_at))
                            .cloned()
                            .unwrap_or_default();
                        // One whose declaration may be on a minority of the relays only: on a majority
                        // before it counts, is shown or recorded, else the rest part fails.
                        for invoice in &invoices {
                            if let Some(event) = found.unsure_rests.get(&invoice.payment_hash) {
                                self.declare(pool, event, &sale, merchant).await?;
                            }
                        }
                        let results = futures_util::future::join_all(invoices.iter().map(|invoice| {
                            verify_payment_owned(lightning_of(invoice), http, self.seconds())
                        }))
                        .await;
                        Ok(RestPart { invoices, results, ..RestPart::default() })
                    }
                    .await
                }
            };
            // A rest invoice that failed counts as not paid: the on-chain part then needs more.
            let _ = paid_sender.send(match &rest_check {
                Ok(rests) => rest_summary(Some(rests)).paid,
                Err(_) => 0,
            });
            (found, rest_check)
        };
        let seen = seen_of(&self.inner.access.key);
        // The merchant's acceptance of this invoice: the team's record, read on every relay.
        let accepted = MerchantAcceptanceKeys::of(
            &self.inner.access.key,
            &self.inner.access.team,
            &sale.author,
            address,
            stored.expires_at,
        );
        let witnesses = RelayWitnesses {
            client: self,
            pool,
            seen,
            address,
            sale: &sale.author,
            expires_at: stored.expires_at,
            relays: &merchant.relays,
            accepted,
            invoice: AcceptedInvoice { sats: stored.sats, expires_at: stored.expires_at },
        };
        let onchain_check = OnchainCheck {
            address,
            sats: stored.sats,
            expires_at: stored.expires_at,
            sale: &sale.author,
            clock: &*self.inner.clock,
            explorer: &merchant.explorer,
            http,
            witnesses: &witnesses,
            logger,
        };
        let onchain_side =
            check_onchain_part(&onchain_check, async { paid_receiver.await.unwrap_or(0) }, async {
                tolerance_receiver.await.unwrap_or(0)
            });
        let (own, first_onchain, (found, rest_result)) = tokio::join!(lightning, onchain_side, rest_side);
        let tolerance = match &found {
            Ok(found) => found
                .leases
                .get(address)
                .map(|lease| &lease.terms)
                .filter(|terms| terms.sats == stored.sats && terms.expires_at == stored.expires_at)
                .map_or(0, |terms| terms.tolerance),
            Err(_) => 0,
        };
        let mut onchain = first_onchain;
        let (mut rests, found) = match (rest_result, found) {
            (Ok(rests), Ok(found)) => (rests, found),
            // The sale's records unread: whether a rest invoice was paid cannot be told.
            (Err(error), _) | (Ok(_), Err(error)) => {
                return Parts {
                    lightning: own,
                    onchain: Some(onchain),
                    rests: Some(RestPart { error: Some(error), ..RestPart::default() }),
                };
            }
        };
        // The rest invoices whose rest record a majority took in this check.
        let mut recorded: HashSet<String> = HashSet::new();
        if let Some(lease) = found.leases.get(address).map(|lease| &lease.terms) {
            let parts =
                Parts { lightning: own.clone(), onchain: Some(onchain.clone()), rests: Some(rests.clone()) };
            let asking = RestAsking {
                stored,
                parts: &parts,
                lease,
                known: &rests.invoices,
                pool,
                merchant,
                sale: &sale,
                logger,
            };
            // Most checks ask for nothing: the lock only when this one may (decided again in it).
            let asked = match rest_ask_of(&asking, self.seconds()) {
                Some(_) => self.ask_rest(&asking).await,
                None => None,
            };
            if let Some(asked) = asked {
                if asked.recorded {
                    recorded.insert(asked.invoice.payment_hash.clone());
                }
                let paid = is_paid(&asked.result);
                rests.invoices.push(asked.invoice);
                rests.results.push(asked.result);
                // Asked meanwhile by another check and paid already: less is due on-chain.
                if paid {
                    let paid_by_rests = rest_summary(Some(&rests)).paid;
                    onchain = check_onchain_part(
                        &onchain_check,
                        std::future::ready(paid_by_rests),
                        std::future::ready(tolerance),
                    )
                    .await;
                }
            }
        }
        if !rests.invoices.is_empty() && self.seconds() < stored.expires_at + GRACE_SECONDS {
            rests.unrecorded =
                self.publish_missing_rests(stored, &rests.invoices, &recorded, pool, merchant, logger).await;
        }
        let parts = Parts { lightning: own, onchain: Some(onchain), rests: Some(rests) };
        self.publish_acceptance(stored, &parts, pool, merchant, logger).await;
        parts
    }

    /// When the order's tolerance or the merchant's acceptance accepted less than its amount (the
    /// status `parts` give is being confirmed, or paid on-chain), has the pages of its checkout
    /// links know it: its acceptance record published ([`publish_acceptance`]). A part failed:
    /// nothing is accepted.
    async fn publish_acceptance(
        &self,
        stored: &StoredInvoice,
        parts: &Parts,
        pool: &RelayPool,
        merchant: &MerchantChannel,
        logger: &dyn Logger,
    ) {
        let now = self.seconds();
        let Ok(status) = status_of(stored, parts, now) else { return };
        let address = stored.onchain_address.as_deref().expect("an invoice with an address");
        let reference = stored.reference.as_deref().expect("an invoice with an address has its reference");
        let keys = rest_keys(&self.inner.access.key, reference, address, stored.expires_at);
        publish_acceptance(
            pool,
            &status,
            AcceptanceOf { sats: stored.sats, expires_at: stored.expires_at, keys: &keys },
            &merchant.relays,
            now,
            &*self.inner.random,
            logger,
        )
        .await;
    }

    /// Asks the merchant's Lightning address for an invoice of the rest, declares it with `rest`
    /// (the price and note of the sale's lease of the address) on a majority of the merchant's
    /// relays, then publishes its rest record (SPEC.md §31, Asking for a rest invoice). One at a
    /// time per invoice in this client, each after the rest invoices were read again: another
    /// check's invoice of the same rest, declared meanwhile, is taken instead. Whether to ask, the
    /// invoice's expiry, its checks and its records go by the clock read then, inside the lock:
    /// never a time read before the explorer, the witnesses or BlockCypher answered, nor before
    /// the wait for the lock. `None` when none could be made: no longer called for, outside the
    /// address's sendable sats, or a failure, logged as a warning (the next check asks again).
    async fn ask_rest(&self, asking: &RestAsking<'_>) -> Option<AskedRest> {
        let address = asking.stored.onchain_address.as_deref().expect("an invoice with an address");
        let _held = self.inner.rest_asks.lock(&format!("{}/{address}", asking.sale.reference)).await;
        match self.ask_rest_now(asking).await {
            Ok(asked) => asked,
            Err(error) => {
                asking.logger.warn(&format!(
                    "sattleme-checkout: no Lightning invoice of the rest of an underpayment ({}); asked again at the next check",
                    error.message()
                ));
                None
            }
        }
    }

    async fn ask_rest_now(&self, asking: &RestAsking<'_>) -> Result<Option<AskedRest>, Error> {
        let RestAsking { stored, lease, known, pool, merchant, sale, logger, .. } = *asking;
        let address = stored.onchain_address.as_deref().expect("an invoice with an address");
        let http = &self.inner.http;
        // Another check may have asked for it meanwhile.
        let again = self.declared(pool, sale, merchant, false, logger).await?;
        // Decided now, in the lock.
        let now = self.seconds();
        let Some(ask) = rest_ask_of(asking, now) else { return Ok(None) };
        let before: HashSet<&str> = known.iter().map(|invoice| invoice.payment_hash.as_str()).collect();
        let meanwhile = again.rests.get(&rest_key_of(address, stored.expires_at)).and_then(|invoices| {
            invoices.iter().find(|invoice| {
                !before.contains(invoice.payment_hash.as_str())
                    && invoice.sats == ask.sats
                    && now < invoice.expires_at
            })
        });
        if let Some(meanwhile) = meanwhile {
            // On a majority, as any rest invoice found.
            if let Some(event) = again.unsure_rests.get(&meanwhile.payment_hash) {
                self.declare(pool, event, sale, merchant).await?;
            }
            // Checked as any rest invoice: it may have been paid already.
            let result = verify_payment(&lightning_of(meanwhile), http, now).await;
            return Ok(Some(AskedRest { invoice: meanwhile.clone(), result, recorded: false }));
        }
        let pay = fetch_pay_request(&merchant.lightning_address, http).await?;
        if !sendable(ask.sats, sendable_sats(&pay)) {
            return Ok(None);
        }
        let answer = request_invoice(&pay, ask.sats, ask.expiry_seconds, Some(&lease.note), http).await?;
        let decoded = check_invoice(&answer, &pay, ask.sats, ask.expiry_seconds, now)?;
        let rest_of = RestOf { address: address.to_owned(), expires_at: stored.expires_at };
        let input = DeclarationInput {
            sale,
            invoice: &answer.pr,
            verify_url: &answer.verify,
            payment_hash: &decoded.payment_hash,
            price: &lease.price,
            note: &lease.note,
            created_at: now,
            rest: Some(&rest_of),
        };
        let event = declaration_event(&input, &*self.inner.random)
            .ok_or_else(|| Error::invalid_invoice("The invoice is too large to be declared"))?;
        self.declare(pool, &event, sale, merchant).await?;
        let invoice = RestInvoice {
            bolt11: answer.pr.clone(),
            payment_hash: decoded.payment_hash.clone(),
            verify_url: answer.verify.clone(),
            sats: ask.sats,
            created_at: decoded.timestamp,
            expires_at: decoded.expires_at(),
        };
        // Declared: it may be shown. Its record, for the checkout links' pages.
        let recorded = self.publish_rest(stored, &invoice, now, pool, merchant, logger).await;
        Ok(Some(AskedRest { invoice, result: Ok(LightningPart::Open), recorded }))
    }

    /// Publishes the rest record of `invoice` on a majority, dated `created_at`; a failure only
    /// logged.
    async fn publish_rest(
        &self,
        stored: &StoredInvoice,
        invoice: &RestInvoice,
        created_at: i64,
        pool: &RelayPool,
        merchant: &MerchantChannel,
        logger: &dyn Logger,
    ) -> bool {
        let address = stored.onchain_address.as_deref().expect("an invoice with an address");
        let reference = stored.reference.as_deref().expect("an invoice with an address has its reference");
        let keys = rest_keys(&self.inner.access.key, reference, address, stored.expires_at);
        let Some(event) =
            rest_record_event(&keys, invoice, stored.expires_at, created_at, &*self.inner.random)
        else {
            return false;
        };
        match publish_rest_record(pool, &event, &keys, &merchant.relays).await {
            Ok(()) => true,
            Err(error) => {
                logger.warn(&format!(
                    "sattleme-checkout: the record of an invoice of the rest was not published ({}); published again at the next check",
                    error.message()
                ));
                false
            }
        }
    }

    /// Publishes again the rest records of `invoices` that fewer than a majority of the relays
    /// sent (their first publication may have failed), so that the checkout links' pages see each
    /// of them; never over a record of a newer format a relay sent at its address: a newer version
    /// recorded it, never written over (SPEC.md §12), and it counts as known. The payment hashes
    /// of those still not known: neither sent by a majority, nor taken by one in this check
    /// (`recorded`, or published again here), nor held by a record of a newer format; when fewer
    /// than a majority answered, all of them but `recorded`. Those are never the status's
    /// `bolt11`.
    async fn publish_missing_rests(
        &self,
        stored: &StoredInvoice,
        invoices: &[RestInvoice],
        recorded: &HashSet<String>,
        pool: &RelayPool,
        merchant: &MerchantChannel,
        logger: &dyn Logger,
    ) -> HashSet<String> {
        let address = stored.onchain_address.as_deref().expect("an invoice with an address");
        let reference = stored.reference.as_deref().expect("an invoice with an address has its reference");
        let keys = rest_keys(&self.inner.access.key, reference, address, stored.expires_at);
        let terms = RestLinkTerms {
            sats: stored.sats,
            created_at: -crate::protocol::MAX_SAFE_INTEGER,
            expires_at: stored.expires_at,
        };
        let held = read_rest_records(
            pool,
            &RestReaderKeys::of(&keys),
            &terms,
            &merchant.relays,
            &*self.inner.random,
        )
        .await;
        let unknown: Vec<&RestInvoice> =
            invoices.iter().filter(|invoice| !recorded.contains(&invoice.payment_hash)).collect();
        // Not read: whether the page can see the others is not known.
        let Some(held) = held else {
            return unknown.into_iter().map(|invoice| invoice.payment_hash.clone()).collect();
        };
        if !held.newer.is_empty() {
            logger.warn(
                "sattleme-checkout: a record of an invoice of the rest of an underpayment has a newer format than this version reads; update the crate",
            );
        }
        let needed = majority(merchant.relays.len());
        let mut unrecorded = HashSet::new();
        for invoice in unknown {
            let address = rest_record_address(&keys.key, &invoice.payment_hash);
            // Sent by a majority, or recorded by a newer version: known, never written over.
            if held.held_by(&address, needed) || held.newer.contains(&address) {
                continue;
            }
            if !self.publish_rest(stored, invoice, self.seconds(), pool, merchant, logger).await {
                unrecorded.insert(invoice.payment_hash.clone());
            }
        }
        unrecorded
    }

    /// Checks the payment until it is `paid` or `expired` (SPEC.md §23): its Lightning part, and
    /// the invoices of the rest of an on-chain underpayment, every `interval_ms`; its on-chain part
    /// (with an address) each time the explorer's WebSocket (mempool.space's, or the merchant's
    /// Bitcoin node's with its fallback, opened once a check read the channel) says something
    /// changed for the address, every 60 s at least, and at once when an invoice of the rest is
    /// paid. `network`
    /// errors are retried (one that each check meets again logged once, and again only after it
    /// stopped); any other error ends it. `on_status` hears each status. An on-chain payment takes
    /// about 30 minutes to be `paid` once `unconfirmed`: a server that cannot wait that long checks
    /// again later with [`Client::get_status`]. `invalid_option` (`intervalMs`), or `invalid_order`
    /// (`invoice`), before any request.
    pub async fn wait_for_payment(
        &self,
        invoice: impl Into<InvoiceToCheck>,
        options: WaitOptions,
    ) -> Result<PaymentStatus, Error> {
        let interval = Duration::from_millis(check_milliseconds(
            options.interval_ms,
            DEFAULT_INTERVAL_MS,
            MIN_INTERVAL_MS,
            MAX_INTERVAL_MS,
            "intervalMs",
        )?);
        let stored = check_stored_invoice(&invoice.into())?;
        let mut on_status = options.on_status;
        // A failure each check meets again is logged once, and again only after it stopped.
        let warnings = OnceWarnings::new(self.inner.logger.clone());
        let call = CallTasks::default();
        if stored.onchain_address.is_some() {
            return ended(&call, self.wait_with_address(&stored, interval, on_status, &warnings, &call))
                .await;
        }
        loop {
            // Without an address: no relay, nothing started that outlives the check.
            let parts = self.check(&stored, None, &warnings, &call, None).await;
            match status_of(&stored, &parts, self.seconds()) {
                Ok(status) => {
                    if let Some(on_status) = on_status.as_mut() {
                        on_status(&status);
                    }
                    if status.is_final() {
                        return Ok(status);
                    }
                }
                Err(error) if error.code() == ErrorCode::Network => warnings.failed(&error),
                Err(error) => return Err(error),
            }
            warnings.checked();
            tokio::time::sleep(interval).await;
        }
    }

    /// `wait_for_payment` of an invoice with an address: each status combines the last result of
    /// each part. A full check (every part, an invoice of the rest asked when needed) at each
    /// change the explorer's WebSocket pushes and every 60 s; between them, the Lightning invoice
    /// and the rest invoices the last full check found, every `interval`.
    async fn wait_with_address(
        &self,
        stored: &StoredInvoice,
        interval: Duration,
        mut on_status: Option<StatusHook>,
        warnings: &OnceWarnings,
        call: &CallTasks,
    ) -> Result<PaymentStatus, Error> {
        let address = stored.onchain_address.as_deref().expect("an invoice with an address");
        let mut wait = Waiting {
            // The last result of each part; `None` until it was checked once.
            lightning: if stored.lightning.is_some() { None } else { Some(None) },
            onchain: None,
            rests: None,
            rests_generation: 0,
            started: 0,
            ended: 0,
            wait_for: 0,
        };
        let mut again = false;
        // The explorer's WebSocket: of the node the last channel read names (SPEC.md §31), with its
        // fallback, opened once a check read the channel (before, whether mempool.space may be
        // asked is not known), and opened again when the channel names another node. The node's
        // failures are the call's, shared by its checks and its WebSocket (the 60 s rule).
        let (nodes, mut named) = mpsc::unbounded_channel();
        let explorer = CallExplorer { failures: NodeFailures::default(), nodes: Some(nodes) };
        let (changes, mut changed) = mpsc::unbounded_channel();
        let mut watcher: Option<BoxFuture<'_, ()>> = None;
        // What the watcher watches: the node's fallback and URL, or mempool.space.
        let mut watched: Option<Option<(NodeFallback, String)>> = None;
        let mut full_check: Option<(BoxFuture<'_, Parts>, u64)> = None;
        let mut lightning_check: Option<(LightningCheck<'_>, Option<RestPart>, u64)> = None;
        let mut lightning_timer: Option<Pin<Box<tokio::time::Sleep>>> = None;
        let mut onchain_timer: Option<Pin<Box<tokio::time::Sleep>>> = None;
        let mut check_onchain = true;
        loop {
            if std::mem::take(&mut check_onchain) {
                if full_check.is_some() {
                    again = true;
                } else {
                    wait.started += 1;
                    // Every 60 s at least: a socket may go quiet without closing.
                    onchain_timer =
                        Some(Box::pin(tokio::time::sleep(Duration::from_millis(ONCHAIN_CHECK_INTERVAL_MS))));
                    full_check = Some((
                        Box::pin(self.check(stored, None, warnings, call, Some(&explorer))),
                        wait.started,
                    ));
                }
            }
            let mut report = false;
            let mut schedule = false;
            tokio::select! {
                () = async { watcher.as_mut().expect("guarded").await }, if watcher.is_some() => {
                    unreachable!("the watcher never ends")
                }
                Some(node) = named.recv() => {
                    let key = node.as_ref().map(|node: &BitcoinNode| (node.fallback, node.url.clone()));
                    if watched.as_ref() != Some(&key) {
                        watched = Some(key);
                        let websocket = &*self.inner.websocket;
                        let explorer =
                            Explorer::new(node.as_ref(), explorer.failures.clone(), self.inner.clock.clone());
                        let changes = changes.clone();
                        // The former one, dropped, closes its socket.
                        watcher = Some(Box::pin(async move {
                            watch_address(websocket, &explorer, address, changes).await;
                        }));
                    }
                }
                Some(()) = changed.recv() => check_onchain = true,
                () = async { onchain_timer.as_mut().expect("guarded").await }, if onchain_timer.is_some() => {
                    onchain_timer = None;
                    check_onchain = true;
                }
                parts = async { full_check.as_mut().expect("guarded").0.as_mut().await }, if full_check.is_some() => {
                    let (_, id) = full_check.take().expect("guarded");
                    wait.ended = id;
                    wait.onchain = Some(parts.onchain);
                    wait.rests = parts.rests;
                    wait.rests_generation += 1;
                    if parts.lightning.is_some() {
                        wait.lightning = Some(parts.lightning);
                    }
                    report = true;
                    // A full check ended: what it, and the checks of the Lightning invoices since
                    // the last one, no longer met has stopped.
                    warnings.checked();
                    schedule = true;
                    if std::mem::take(&mut again) {
                        check_onchain = true;
                    }
                }
                () = async { lightning_timer.as_mut().expect("guarded").await }, if lightning_timer.is_some() => {
                    lightning_timer = None;
                    let known = wait.rests.clone();
                    let check = self.check_lightning(stored, wait.lightning.clone(), known.clone());
                    lightning_check = Some((check, known, wait.rests_generation));
                }
                checked = async { lightning_check.as_mut().expect("guarded").0.as_mut().await }, if lightning_check.is_some() => {
                    let (_, known, generation) = lightning_check.take().expect("guarded");
                    let (own, results) = checked;
                    if own.is_some() {
                        wait.lightning = own;
                    }
                    let mut paid = false;
                    // A full check may have found other rest invoices meanwhile: its results stand.
                    if let Some(known) = known
                        && generation == wait.rests_generation {
                            paid = results.iter().zip(known.results.iter()).any(|(now, before)| is_paid(now) && !is_paid(before));
                            wait.rests = Some(RestPart { results, ..known });
                        }
                    // Paid by a rest invoice: what is due on-chain changed, a full check tells the
                    // status.
                    if paid {
                        wait.wait_for = wait.started + 1;
                        check_onchain = true;
                    } else {
                        report = true;
                    }
                    schedule = true;
                }
            }
            if report && let Some(outcome) = wait.report(stored, self.seconds(), on_status.as_mut(), warnings)
            {
                return outcome;
            }
            // The Lightning invoices (the order's, and those of the rest) every interval while one
            // may still change.
            if schedule && lightning_timer.is_none() && lightning_check.is_none() && wait.lightning_pending()
            {
                lightning_timer = Some(Box::pin(tokio::time::sleep(interval)));
            }
        }
    }

    /// The Lightning invoice of `stored` (unless its last result is final) and the rest invoices
    /// of `known` that are not final, checked: what `wait_with_address` checks every interval.
    fn check_lightning<'a>(
        &'a self,
        stored: &'a StoredInvoice,
        current: Option<Option<Settled<LightningPart>>>,
        known: Option<RestPart>,
    ) -> LightningCheck<'a> {
        let http = &self.inner.http;
        Box::pin(async move {
            let own_pending =
                current.as_ref().is_none_or(|own| own.as_ref().is_some_and(|own| !is_final(own)));
            let own = async {
                match &stored.lightning {
                    Some(invoice) if own_pending => {
                        Some(Some(verify_payment(invoice, http, self.seconds()).await))
                    }
                    _ => current,
                }
            };
            let pairs: Vec<(LightningInvoice, Settled<LightningPart>)> = known
                .iter()
                .flat_map(|rests| rests.invoices.iter().zip(rests.results.iter()))
                .map(|(invoice, result)| (lightning_of(invoice), result.clone()))
                .collect();
            let results =
                futures_util::future::join_all(pairs.into_iter().map(|(invoice, result)| async move {
                    if is_final(&result) {
                        result
                    } else {
                        verify_payment(&invoice, http, self.seconds()).await
                    }
                }));
            tokio::join!(own, results)
        })
    }

    /// The invoices declared for the order `reference` in the merchant's registry, oldest first
    /// (SPEC.md §24): to find an order's invoice again after a failure. Read on a majority of the
    /// merchant's relays; `network` when fewer answered. It publishes nothing: to show an order's
    /// invoice again, call `create_invoice`, whose `invoice_pending` carries the pending invoice.
    pub async fn find_invoices(&self, reference: &str) -> Result<Vec<DeclaredInvoice>, Error> {
        check_ref(reference)?;
        let call = CallTasks::default();
        ended(&call, async {
            let pool = self.pool(&call);
            let merchant = self.channel(&pool, self.logger()).await?;
            let sale = sale_of(&self.inner.access.key, &merchant.registry, reference);
            let declared = self.declared(&pool, &sale, &merchant, false, self.logger()).await?;
            Ok(declared.invoices.into_iter().map(|declaration| declaration.invoice).collect())
        })
        .await
    }

    async fn declared(
        &self,
        pool: &RelayPool,
        sale: &Sale,
        merchant: &MerchantChannel,
        every_relay: bool,
        logger: &dyn Logger,
    ) -> Result<SaleRecords, Error> {
        read_sale_declarations(pool, sale, &merchant.relays, logger, every_relay).await
    }
}

/// `work`, a call's, then the end of every task it started (`call`): once a call returned, nothing
/// it started runs on, a publication's relays past its majority included (SPEC.md §4, §13).
async fn ended<T>(call: &CallTasks, work: impl Future<Output = T>) -> T {
    let result = work.await;
    call.end().await;
    result
}

/// `verify_payment` of an owned invoice.
async fn verify_payment_owned(invoice: LightningInvoice, http: &Http, now: i64) -> Settled<LightningPart> {
    verify_payment(&invoice, http, now).await
}

/// A check of the Lightning invoices of a waiting: the order's own (unchanged when final) and
/// those of its rest.
type LightningCheck<'a> = Pin<
    Box<
        dyn Future<Output = (Option<Option<Settled<LightningPart>>>, Vec<Settled<LightningPart>>)>
            + Send
            + 'a,
    >,
>;

/// The state of `wait_with_address`: the last result of each part.
struct Waiting {
    /// `None` until checked once; `Some(None)` without a Lightning invoice.
    lightning: Option<Option<Settled<LightningPart>>>,
    onchain: Option<Option<Settled<OnchainPart>>>,
    rests: Option<RestPart>,
    /// Each full check sets `rests` anew: a Lightning check of an older one does not.
    rests_generation: u64,
    /// Full checks started, the last one that ended, and the first one a status must wait for.
    started: u64,
    ended: u64,
    wait_for: u64,
}

impl Waiting {
    /// Whether a Lightning invoice (the order's, or one of the rest) may still change.
    fn lightning_pending(&self) -> bool {
        let own = self.lightning.as_ref().is_none_or(|own| own.as_ref().is_some_and(|own| !is_final(own)));
        own || self.rests.as_ref().is_some_and(|rests| rests.results.iter().any(|result| !is_final(result)))
    }

    /// The status of the last results, handed to `on_status`: the outcome once it is final (or an
    /// error that is not `network`).
    fn report(
        &self,
        stored: &StoredInvoice,
        now: i64,
        on_status: Option<&mut StatusHook>,
        warnings: &OnceWarnings,
    ) -> Option<Result<PaymentStatus, Error>> {
        let (Some(lightning), Some(onchain)) = (&self.lightning, &self.onchain) else { return None };
        // A rest invoice was paid after the last full check began: its on-chain part was judged
        // against what was due then, never combined with it (it might read underpaid for good).
        if self.ended < self.wait_for {
            return None;
        }
        let parts =
            Parts { lightning: lightning.clone(), onchain: onchain.clone(), rests: self.rests.clone() };
        match status_of(stored, &parts, now) {
            Ok(status) => {
                if let Some(on_status) = on_status {
                    on_status(&status);
                }
                status.is_final().then_some(Ok(status))
            }
            Err(error) if error.code() == ErrorCode::Network => {
                warnings.failed(&error);
                None
            }
            Err(error) => Some(Err(error)),
        }
    }
}

/// An invoice of the rest a check asked for (or found).
struct AskedRest {
    invoice: RestInvoice,
    result: Settled<LightningPart>,
    /// Whether a majority took its rest record in this call.
    recorded: bool,
}

/// What asking for an invoice of the rest of `stored` needs: its parts as the check found them,
/// the sale's lease of its address, the rest invoices known, the call's relays.
#[derive(Clone, Copy)]
struct RestAsking<'a> {
    stored: &'a StoredInvoice,
    parts: &'a Parts,
    lease: &'a LeaseTerms,
    known: &'a [RestInvoice],
    pool: &'a RelayPool,
    merchant: &'a MerchantChannel,
    sale: &'a Sale,
    logger: &'a dyn Logger,
}

/// The invoice of the rest a check asks for at `now` (SPEC.md §31, Asking for a rest invoice): its
/// status open with a rest and no invoice of it, 60 s left at least, the sale's lease of the
/// address of the invoice's terms. `None` when a part failed (the status is its error).
fn rest_ask_of(asking: &RestAsking<'_>, now: i64) -> Option<RestAsk> {
    let RestAsking { stored, parts, lease, .. } = *asking;
    match status_of(stored, parts, now).ok()? {
        PaymentStatus::Open { rest, .. } => rest_to_ask(
            rest.as_ref(),
            stored.sats,
            stored.expires_at,
            now,
            Some((lease.sats, lease.expires_at)),
        ),
        _ => None,
    }
}
