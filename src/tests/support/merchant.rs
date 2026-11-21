//! A merchant for tests, as the app would set it up: a team, an integration's key, the channel the
//! team publishes on local relays, the registry, and a Lightning address (breez.tips) answered by
//! a fake HTTP client that makes real-looking invoices.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::chain::{FakeChain, FakeExplorerSocket};
use super::http::{Answer, Call, FakeHttp};
use super::lightning::{InvoiceSpec, make_invoice, metadata_hash, preimage_pair};
use super::random::{TestClock, bytes};
use super::relay::{RelayBehaviour, RelayNet};
use super::{j, merged};
use crate::client::{Client, ClientBuilder};
use crate::derive::{channel_keys, lot_address, public_key_of};
use crate::encoding::to_base64url;
use crate::json::Json;
use crate::nostr::event::Event;
use crate::nostr::record::{Seal, seal_record};
use crate::protocol::{INTEGRATION_KEY_PREFIX, MEMPOOL_WEBSOCKET_URL};
use crate::runtime::{Logger, OsRandom};
use crate::secret::Secret;
use crate::text::{from_hex, to_hex};

pub(crate) const LIGHTNING_ADDRESS: &str = "sattleme02c6047f94@breez.tips";
pub(crate) const PAY_URL: &str = "https://breez.tips/.well-known/lnurlp/sattleme02c6047f94";
pub(crate) const CALLBACK: &str = "https://breez.tips/lnurlp/sattleme02c6047f94/invoice";

/// The metadata of the Lightning address, as `JSON.stringify` writes it.
pub(crate) fn metadata() -> String {
    format!(r#"[["text/identifier","{LIGHTNING_ADDRESS}"],["text/plain","Pay to Sunrise Bakery"]]"#)
}

/// The text of an integration key, as the merchant's app writes it.
pub(crate) fn format_key(team: &str, key: &[u8; 32], relays: &[String]) -> String {
    let hosts: Vec<&str> = relays.iter().map(|relay| relay.strip_prefix("wss://").unwrap_or(relay)).collect();
    format!(
        "{INTEGRATION_KEY_PREFIX}{}.{}.{}",
        to_base64url(&from_hex(team).expect("hex")),
        to_base64url(key),
        to_base64url(hosts.join(",").as_bytes())
    )
}

/// A logger that hears nothing.
pub(crate) struct Quiet;

impl Logger for Quiet {
    fn warn(&self, _: &str) {}
}

/// A logger that keeps every warning.
#[derive(Clone, Default)]
pub(crate) struct Warnings(pub(crate) Arc<Mutex<Vec<String>>>);

impl Warnings {
    pub(crate) fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl Logger for Warnings {
    fn warn(&self, message: &str) {
        self.0.lock().unwrap().push(message.to_owned());
    }
}

/// An invoice the fake breez.tips made, with what pays it.
#[derive(Clone, Debug)]
pub(crate) struct MadeInvoice {
    pub(crate) pr: String,
    pub(crate) verify: String,
    pub(crate) payment_hash: String,
    pub(crate) preimage: String,
    pub(crate) amount_msat: u128,
    pub(crate) expiry: u64,
    pub(crate) comment: Option<String>,
}

type Tamper = Arc<dyn Fn(MadeInvoice) -> MadeInvoice + Send + Sync>;
type Override = Arc<dyn Fn(&Call) -> Option<Answer> + Send + Sync>;

struct MerchantState {
    /// In the order they were made; one per payment hash.
    invoices: Vec<MadeInvoice>,
    paid: HashSet<String>,
    pay: Json,
    tamper: Option<Tamper>,
    override_route: Option<Override>,
    seed: u32,
}

/// The merchant of a test.
pub(crate) struct TestMerchant {
    pub(crate) net: RelayNet,
    pub(crate) team_secret: Secret,
    pub(crate) team: String,
    pub(crate) integration_key: Secret,
    pub(crate) registry_key: Secret,
    pub(crate) reader_secret: Secret,
    pub(crate) reader: String,
    /// The relays of the key.
    pub(crate) key_relays: Vec<String>,
    /// The clock of the test (Unix seconds), every client's.
    pub(crate) clock: TestClock,
    /// The explorers and BlockCypher.
    pub(crate) chain: FakeChain,
    /// breez.tips, the explorers and whatever a test overrides.
    pub(crate) http: FakeHttp,
    state: Arc<Mutex<MerchantState>>,
}

/// The default pay request of breez.tips.
fn default_pay() -> Json {
    j!({
        "tag": "payRequest",
        "callback": CALLBACK,
        "minSendable": 1000,
        "maxSendable": 100_000_000_000_u64,
        "metadata": metadata(),
        "commentAllowed": 255
    })
}

impl TestMerchant {
    /// A merchant at 1 791 378 000, its key naming three relays (not started).
    pub(crate) fn new() -> Self {
        let team_secret = Secret::new(bytes(1));
        let reader_secret = Secret::new(bytes(4));
        let state = Arc::new(Mutex::new(MerchantState {
            invoices: Vec::new(),
            paid: HashSet::new(),
            pay: default_pay(),
            tamper: None,
            override_route: None,
            seed: 10,
        }));
        let clock = TestClock::new(1_791_378_000);
        let chain = FakeChain::new();
        let http = {
            let state = state.clone();
            let clock = clock.clone();
            let chain = chain.clone();
            FakeHttp::new(move |call| route(&state, &clock, &chain, call))
        };
        Self {
            net: RelayNet::default(),
            team: public_key_of(&team_secret),
            team_secret,
            integration_key: Secret::new(bytes(2)),
            registry_key: Secret::new(bytes(3)),
            reader: public_key_of(&reader_secret),
            reader_secret,
            key_relays: ["wss://relay-a.test", "wss://relay-b.test", "wss://relay-c.test"]
                .map(str::to_owned)
                .to_vec(),
            clock,
            chain,
            http,
            state,
        }
    }

    /// Starts the key's relays.
    pub(crate) fn start(self) -> Self {
        self.start_with(&[], HashMap::new())
    }

    /// Starts the key's relays and `others`, each with its behaviour.
    pub(crate) fn start_with(self, others: &[&str], mut behaviours: HashMap<&str, RelayBehaviour>) -> Self {
        let mut urls: Vec<String> = self.key_relays.clone();
        for other in others {
            if !urls.iter().any(|url| url == other) {
                urls.push((*other).to_owned());
            }
        }
        for url in urls {
            self.net.add(&url, behaviours.remove(url.as_str()).unwrap_or_default());
        }
        self
    }

    /// The integration key.
    pub(crate) fn key(&self) -> String {
        format_key(&self.team, self.integration_key.expose(), &self.key_relays)
    }

    /// Unix seconds: the test's clock.
    pub(crate) fn now(&self) -> i64 {
        self.clock.now()
    }

    pub(crate) fn set_now(&self, seconds: i64) {
        self.clock.set(seconds);
    }

    pub(crate) fn advance(&self, seconds: i64) {
        self.clock.advance(seconds);
    }

    /// A client of this merchant: its HTTP and WebSocket fakes, its clock, relays answering
    /// within a second, warnings unheard.
    pub(crate) fn client(&self) -> ClientBuilder {
        Client::builder(self.key())
            .http_client(self.http.clone())
            .websocket_client(self.net.clone())
            .clock(self.clock.clone())
            .relay_timeout_ms(1000)
            .logger(Quiet)
    }

    /// The channel's value, active, as the merchant's app writes it, with `extra` members (each
    /// one in place of the member of its name, as JavaScript's spread does).
    pub(crate) fn channel_value(&self, created_at: i64, extra: Json) -> Json {
        let value = j!({
            "version": 1,
            "status": "active",
            "name": "Shopify store",
            "role": "integration",
            "profile": {
                "businessName": "Sunrise Bakery",
                "lightningAddress": LIGHTNING_ADDRESS,
                "currency": "CHF",
                "onchain": true,
                "logo": null
            },
            "registryKey": to_hex(self.registry_key.expose()),
            "registryReader": self.reader,
            "linkOwner": "ab".repeat(32),
            "updatedAt": created_at
        });
        merged(&value, &extra)
    }

    /// The channel's event, signed by `signer` (the team by default).
    pub(crate) fn channel_event(&self, value: &Json, created_at: i64, signer: Option<&Secret>) -> Event {
        let keys = channel_keys(&self.integration_key);
        seal_record(
            Seal {
                record_type: "team-channel",
                value: value.clone(),
                signer: signer.unwrap_or(&self.team_secret),
                encryption_key: &keys.encryption_key,
                address: &keys.address,
                created_at,
                tags: Vec::new(),
            },
            &OsRandom,
        )
        .expect("a channel fits a record")
    }

    /// Publishes the channel on the key's relays.
    pub(crate) fn publish_channel(&self, value: &Json, created_at: i64) -> Event {
        let relays = self.key_relays.clone();
        self.publish_channel_on(value, created_at, &relays, None)
    }

    /// Publishes the channel on `relays`, signed by `signer` (the team by default).
    pub(crate) fn publish_channel_on(
        &self,
        value: &Json,
        created_at: i64,
        relays: &[String],
        signer: Option<&Secret>,
    ) -> Event {
        let event = self.channel_event(value, created_at, signer);
        for relay in relays {
            self.net.get(relay).store_event(&event);
        }
        event
    }

    /// Publishes the integration's lot of deposit addresses on the key's relays, as the
    /// merchant's app does.
    pub(crate) fn publish_lot(&self, addresses: &[String], created_at: i64) -> Event {
        let relays = self.key_relays.clone();
        self.publish_lot_on(addresses, created_at, &relays)
    }

    pub(crate) fn publish_lot_on(&self, addresses: &[String], created_at: i64, relays: &[String]) -> Event {
        let keys = channel_keys(&self.integration_key);
        let value = Json::object([
            ("version", Json::unsigned(1)),
            (
                "addresses",
                Json::array(addresses.iter().map(|address| Json::from(address.as_str())).collect()),
            ),
            ("updatedAt", Json::integer(created_at)),
        ]);
        let event = seal_record(
            Seal {
                record_type: "integration-onchain-lot",
                value,
                signer: &self.team_secret,
                encryption_key: &keys.encryption_key,
                address: &lot_address(&self.integration_key),
                created_at,
                tags: Vec::new(),
            },
            &OsRandom,
        )
        .expect("a lot fits a record");
        for relay in relays {
            self.net.get(relay).store_event(&event);
        }
        event
    }

    /// Starts the explorer's WebSocket (wss://mempool.space/api/v1/ws).
    pub(crate) fn start_explorer_socket(&self) -> FakeExplorerSocket {
        self.net.add_server(MEMPOOL_WEBSOCKET_URL)
    }

    /// Marks an invoice paid on breez.tips.
    pub(crate) fn pay_invoice(&self, payment_hash: &str) {
        self.state.lock().unwrap().paid.insert(payment_hash.to_owned());
    }

    /// Marks invoices paid on breez.tips, from wherever a test needs (a route of its own).
    pub(crate) fn pay_marker(&self) -> impl Fn(&str) + Send + Sync + 'static {
        let state = self.state.clone();
        move |payment_hash| {
            state.lock().unwrap().paid.insert(payment_hash.to_owned());
        }
    }

    /// What breez.tips's pay request says.
    pub(crate) fn pay(&self) -> Json {
        self.state.lock().unwrap().pay.clone()
    }

    pub(crate) fn set_pay(&self, pay: Json) {
        self.state.lock().unwrap().pay = pay;
    }

    /// Sets one member of the pay request (`null` included); `None` removes it.
    pub(crate) fn set_pay_field(&self, name: &str, value: Option<Json>) {
        let mut state = self.state.lock().unwrap();
        let mut members: Vec<(String, Json)> = state
            .pay
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(name, value)| (name.to_string_lossy().into_owned(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        match (members.iter().position(|(member, _)| member == name), value) {
            (Some(index), Some(value)) => members[index].1 = value,
            (Some(index), None) => {
                members.remove(index);
            }
            (None, Some(value)) => members.push((name.to_owned(), value)),
            (None, None) => {}
        }
        state.pay =
            Json::object_of(members.iter().map(|(name, value)| (name.as_str(), value.clone())).collect());
    }

    /// Changes the invoices breez.tips gives (a test of a check); `None` stops.
    pub(crate) fn set_tamper(
        &self,
        tamper: Option<impl Fn(MadeInvoice) -> MadeInvoice + Send + Sync + 'static>,
    ) {
        self.state.lock().unwrap().tamper = tamper.map(|tamper| Arc::new(tamper) as Tamper);
    }

    /// Answers the requests it gives an answer for before anything else; `None` stops.
    pub(crate) fn set_override(
        &self,
        route: Option<impl Fn(&Call) -> Option<Answer> + Send + Sync + 'static>,
    ) {
        self.state.lock().unwrap().override_route = route.map(|route| Arc::new(route) as Override);
    }

    /// The invoices breez.tips made, in order.
    pub(crate) fn invoices(&self) -> Vec<MadeInvoice> {
        self.state.lock().unwrap().invoices.clone()
    }

    /// Every record (kind 30078) the key's relays received: the declarations, unless a test
    /// makes more.
    pub(crate) fn declarations(&self) -> Vec<Event> {
        self.key_relays
            .iter()
            .flat_map(|url| self.net.get(url).received())
            .filter(|event| event.kind == 30078.0)
            .collect()
    }

    /// The invoice of `payment_hash` breez.tips made.
    pub(crate) fn invoice(&self, payment_hash: &str) -> Option<MadeInvoice> {
        self.invoices().into_iter().find(|made| made.payment_hash == payment_hash)
    }
}

/// What breez.tips and the explorers answer.
fn route(state: &Mutex<MerchantState>, clock: &TestClock, chain: &FakeChain, call: &Call) -> Option<Answer> {
    let override_route = state.lock().unwrap().override_route.clone();
    if let Some(answer) = override_route.and_then(|route| route(call)) {
        return Some(answer);
    }
    if let Some(answer) = chain.route(call) {
        return Some(answer);
    }
    if call.url == PAY_URL {
        return Some(Answer::json(&state.lock().unwrap().pay));
    }
    if call.path() == CALLBACK {
        let amount: u128 = call.param("amount")?.parse().ok()?;
        let expiry: u64 = call.param("expiry").map_or(Some(3600), |expiry| expiry.parse().ok())?;
        let (tamper, seed) = {
            let mut state = state.lock().unwrap();
            state.seed += 1;
            (state.tamper.clone(), state.seed - 1)
        };
        let (preimage, payment_hash) = preimage_pair(seed);
        let mut spec = InvoiceSpec::new(&payment_hash, clock.now());
        spec.amount_msat = Some(amount);
        spec.description_hash = Some(metadata_hash(&metadata()));
        spec.expiry_seconds = Some(expiry);
        let mut made = MadeInvoice {
            pr: make_invoice(&spec),
            verify: format!("https://breez.tips/lnurlp/verify/{payment_hash}"),
            payment_hash,
            preimage,
            amount_msat: amount,
            expiry,
            comment: call.param("comment"),
        };
        if let Some(tamper) = tamper {
            made = tamper(made);
        }
        let mut state = state.lock().unwrap();
        match state.invoices.iter().position(|other| other.payment_hash == made.payment_hash) {
            Some(index) => state.invoices[index] = made.clone(),
            None => state.invoices.push(made.clone()),
        }
        return Some(Answer::json(&Json::object([
            ("pr", Json::from(made.pr.as_str())),
            ("verify", Json::from(made.verify.as_str())),
            ("routes", Json::array(Vec::new())),
        ])));
    }
    if let Some(hash) = call.url.strip_prefix("https://breez.tips/lnurlp/verify/") {
        let hash = call.path().rsplit('/').next().unwrap_or(hash);
        let state = state.lock().unwrap();
        let Some(made) = state.invoices.iter().find(|made| made.payment_hash == hash) else {
            return Some(Answer::json(&j!({ "status": "ERROR", "reason": "Not found" })));
        };
        let settled = state.paid.contains(hash);
        return Some(Answer::json(&Json::object([
            ("status", Json::from("OK")),
            ("settled", Json::Bool(settled)),
            ("preimage", if settled { Json::from(made.preimage.as_str()) } else { Json::Null }),
            ("pr", Json::from(made.pr.as_str())),
        ])));
    }
    None
}
