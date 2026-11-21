//! What a call started ends when it returns (SPEC.md §4, §13): once a call returned, nothing it
//! started runs on, nor sends anything, nor calls what the client was given (the HTTP and
//! WebSocket clients, the clock, the logger, the randomness), and its relays' connections are
//! closed. A publication's relays past its majority end with the call: their requests are not
//! awaited. The crate's work runs in the call's own future (what a call no longer waits for is
//! dropped with it), but for the tasks of its relays' pools, which the call ends before it returns.
//!
//! Each test holds a request of the call (an HTTP request that never answers until it is dropped,
//! an authentication answered late) while the call returns on another branch.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use super::support::chain::{deposit_address, payment, txid};
use super::support::http::FakeHttp;
use super::support::merchant::{PAY_URL, TestMerchant};
use super::support::random::TestClock;
use super::support::relay::{RelayBehaviour, RelayNet};
use crate::client::Client;
use crate::derive::lot_address;
use crate::error::ErrorCode;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::json::Json;
use crate::order::Order;
use crate::protocol::MEMPOOL_URL;
use crate::runtime::{Clock, Logger, OsRandom, Random};
use crate::transport::{BoxFuture, TransportError};
use crate::websocket::{WebSocketClient, WebSocketConnection, WebSocketRequest};

/// Every call of what the client was given, with when it came; and when each request held ended.
#[derive(Clone, Default)]
struct Watch {
    calls: Arc<Mutex<Vec<(Instant, String)>>>,
    held: Arc<Mutex<Vec<Option<Instant>>>>,
}

impl Watch {
    fn record(&self, what: String) {
        self.calls.lock().unwrap().push((Instant::now(), what));
    }

    /// What was called after `instant`.
    fn after(&self, instant: Instant) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at > instant)
            .map(|(_, what)| what.clone())
            .collect()
    }
}

/// Ends a held request: when it is dropped.
struct Held {
    watch: Watch,
    index: usize,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.watch.held.lock().unwrap()[self.index] = Some(Instant::now());
    }
}

/// The merchant's fakes, watched: the requests `hold` gives true for never answer (until they are
/// dropped), those `fail` gives true for answer HTTP 500, 10 ms late.
struct WatchedHttp {
    watch: Watch,
    inner: FakeHttp,
    hold: fn(&str) -> bool,
    fail: fn(&str) -> bool,
}

impl HttpClient for WatchedHttp {
    fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        self.watch.record(format!("GET {}", request.url));
        if (self.hold)(&request.url) {
            let held = {
                let mut held = self.watch.held.lock().unwrap();
                held.push(None);
                Held { watch: self.watch.clone(), index: held.len() - 1 }
            };
            return Box::pin(async move {
                let _held = held;
                std::future::pending().await
            });
        }
        if (self.fail)(&request.url) {
            // A moment later: what the call asks at the same time was asked by then.
            return Box::pin(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(HttpResponse::from_bytes(500, "down"))
            });
        }
        self.inner.get(request)
    }
}

struct WatchedSockets(Watch, RelayNet);

impl WebSocketClient for WatchedSockets {
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
        self.0.record(format!("connect {}", request.url));
        self.1.connect(request)
    }
}

struct WatchedClock(Watch, TestClock);

impl Clock for WatchedClock {
    fn now_ms(&self) -> i64 {
        self.0.record("clock".to_owned());
        self.1.now_ms()
    }
}

struct WatchedRandom(Watch);

impl Random for WatchedRandom {
    fn fill(&self, bytes: &mut [u8]) {
        self.0.record("random".to_owned());
        OsRandom.fill(bytes);
    }
}

struct WatchedLogger(Watch);

impl Logger for WatchedLogger {
    fn warn(&self, message: &str) {
        self.0.record(format!("warn {message}"));
    }
}

fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, super::support::j!({})), 100);
    merchant.publish_lot(&(1..=3).map(deposit_address).collect::<Vec<_>>(), 90);
    merchant
}

/// A client of `merchant` whose HTTP requests `hold` gives true for never answer, those `fail`
/// gives true for fail, everything it was given watched by `watch`.
fn client(merchant: &TestMerchant, watch: &Watch, hold: fn(&str) -> bool, fail: fn(&str) -> bool) -> Client {
    merchant
        .client()
        .http_client(WatchedHttp { watch: watch.clone(), inner: merchant.http.clone(), hold, fail })
        .websocket_client(WatchedSockets(watch.clone(), merchant.net.clone()))
        .clock(WatchedClock(watch.clone(), merchant.clock.clone()))
        .random(WatchedRandom(watch.clone()))
        .logger(WatchedLogger(watch.clone()))
        .http_timeout_ms(3000)
        .build()
        .unwrap()
}

/// Once the call returned (at `returned`): its relays' connections closed already, every request
/// it held ended by then, and, a minute later, nothing it was given called, nothing a relay
/// received, since.
async fn nothing_runs_on(merchant: &TestMerchant, watch: &Watch, returned: Instant, what: &str) {
    for url in &merchant.key_relays {
        assert_eq!(merchant.net.get(url).open_connections(), 0, "{what}: {url} open once it returned");
    }
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(watch.after(returned), Vec::<String>::new(), "{what}: called once it returned");
    let held = watch.held.lock().unwrap().clone();
    assert!(held.iter().all(|ended| ended.is_some_and(|ended| ended <= returned)), "{what}: {held:?}");
    for url in &merchant.key_relays {
        let after: Vec<String> = merchant
            .net
            .get(url)
            .messages()
            .into_iter()
            .filter(|(at, _)| *at > returned)
            .map(|(_, message)| message)
            .collect();
        assert!(after.is_empty(), "{what}: {url} received {after:?} once it returned");
    }
}

#[tokio::test(start_paused = true)]
async fn create_invoice_a_publication_s_relay_past_its_majority_ends_with_the_call() {
    let merchant = merchant();
    // relay-c takes the declaration only once authenticated, and answers its authentication late:
    // its publication is still under way when a majority took the declaration.
    merchant.net.get("wss://relay-c.test").set_behaviour(RelayBehaviour {
        require_auth: true,
        auth_delay_ms: Some(500),
        ..RelayBehaviour::default()
    });
    let watch = Watch::default();
    let client = client(&merchant, &watch, |_| false, |_| false);
    let invoice = client.create_invoice(&Order::sats("E-1", 500)).await.unwrap();
    let returned = Instant::now();
    assert!(invoice.bolt11.is_some());
    // It was under way: the declaration sent, refused until authenticated, the authentication sent.
    let c = merchant.net.get("wss://relay-c.test");
    assert!(c.messages().iter().any(|(_, message)| message == "AUTH"), "{:?}", c.messages());
    nothing_runs_on(&merchant, &watch, returned, "create_invoice").await;
}

#[tokio::test(start_paused = true)]
async fn merchant_the_pay_request_when_the_lot_cannot_be_read() {
    let merchant = merchant();
    // Two relays of three never answer the read of the lot: fewer than a majority answer it.
    let lot = Json::from(lot_address(&merchant.integration_key));
    for url in &merchant.key_relays[1..] {
        let lot = lot.clone();
        merchant.net.get(url).update(move |behaviour| {
            behaviour.mute_query = Some(Arc::new(move |filter: &Json| {
                filter.get("#d").and_then(Json::as_array).is_some_and(|ds| ds.contains(&lot))
            }));
        });
    }
    let watch = Watch::default();
    let client = client(&merchant, &watch, |url| url.starts_with(PAY_URL), |_| false);
    let error = client.merchant().await.unwrap_err();
    let returned = Instant::now();
    assert_eq!(error.code(), ErrorCode::Network);
    assert_eq!(watch.held.lock().unwrap().len(), 1, "the pay request was asked");
    nothing_runs_on(&merchant, &watch, returned, "merchant").await;
}

#[tokio::test(start_paused = true)]
async fn create_invoice_the_pay_request_and_the_rate_when_an_earlier_invoice_was_paid() {
    let merchant = merchant();
    let earlier = merchant.client().build().unwrap().create_invoice(&Order::sats("E-2", 500)).await.unwrap();
    merchant.pay_invoice(earlier.payment_hash.as_deref().unwrap());
    let watch = Watch::default();
    // The pay request and every rate source never answer.
    let client = client(&merchant, &watch, |url| !url.contains("/verify/"), |_| false);
    let error = client.create_invoice(&Order::fiat("E-2", "24.50", "CHF")).await.unwrap_err();
    let returned = Instant::now();
    assert_eq!(error.code(), ErrorCode::OrderPaid);
    // Both asked (the first rate source of the default list), neither answered.
    assert_eq!(
        watch.held.lock().unwrap().len(),
        2,
        "{:?}",
        watch.after(Instant::now() - Duration::from_secs(3600))
    );
    nothing_runs_on(&merchant, &watch, returned, "create_invoice").await;
}

#[tokio::test(start_paused = true)]
async fn get_status_the_explorer_s_height_when_its_list_of_the_address_s_transactions_failed() {
    let merchant = merchant();
    let invoice =
        merchant.client().build().unwrap().create_invoice(&Order::sats("E-3", 49_000)).await.unwrap();
    let address = invoice.onchain_address.clone().unwrap();
    merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
    let watch = Watch::default();
    let client = client(
        &merchant,
        &watch,
        |url| url == format!("{MEMPOOL_URL}/blocks/tip/height"),
        |url| url.starts_with(&format!("{MEMPOOL_URL}/address/")),
    );
    let error = client.get_status(&invoice).await.unwrap_err();
    let returned = Instant::now();
    assert_eq!(error.code(), ErrorCode::Network);
    assert_eq!(watch.held.lock().unwrap().len(), 1, "the height was asked");
    nothing_runs_on(&merchant, &watch, returned, "get_status").await;
}

#[tokio::test(start_paused = true)]
async fn create_invoice_the_read_of_the_leases_when_the_read_of_the_named_addresses_failed() {
    let merchant = merchant();
    // Two relays of three never answer the read of the addresses a witness names (by their
    // address tags); the third answers the read of the leases late, after it authenticated late.
    for url in &merchant.key_relays[..2] {
        merchant.net.get(url).update(|behaviour| {
            behaviour.mute_query = Some(Arc::new(|filter: &Json| filter.has("#o")));
        });
    }
    merchant.net.get("wss://relay-c.test").update(|behaviour| {
        behaviour.require_auth = true;
        behaviour.auth_delay_ms = Some(1500);
    });
    let watch = Watch::default();
    let client = client(&merchant, &watch, |_| false, |_| false);
    let error = client.create_invoice(&Order::sats("E-4", 49_000)).await.unwrap_err();
    let returned = Instant::now();
    assert_eq!(error.code(), ErrorCode::Network);
    nothing_runs_on(&merchant, &watch, returned, "create_invoice").await;
}
