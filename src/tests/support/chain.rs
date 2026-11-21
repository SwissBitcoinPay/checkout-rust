//! The blockchain for tests: deposit addresses (taproot, bech32m) made from a seed, and fakes of
//! the explorers (mempool.space and a merchant's Bitcoin node, Esplora REST, which show the same
//! chain), of BlockCypher and of the explorer's WebSocket (`track-address`). Never the network.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::sync::{Arc, Mutex};

use super::http::{Answer, Call};
use super::lightning::{BECH32M, bytes_to_words, encode_bech32};
use super::relay::Peer;
use crate::derive::sha256;
use crate::json::{self, Json};
use crate::protocol::{BLOCKCYPHER_URL, MEMPOOL_URL};
use crate::text::to_hex;

/// The deposit address (`bc1p…`) of a 32-byte program derived from `seed`.
pub(crate) fn deposit_address(seed: impl Display) -> String {
    let program = sha256(format!("deposit address {seed}").as_bytes());
    let mut words = vec![1];
    words.extend(bytes_to_words(&program));
    encode_bech32("bc", &words, BECH32M)
}

/// A txid made from `seed`.
pub(crate) fn txid(seed: impl Display) -> String {
    to_hex(&sha256(format!("transaction {seed}").as_bytes()))
}

/// An input of a transaction, as Esplora writes it.
#[derive(Clone, Debug)]
pub(crate) struct Vin {
    pub(crate) txid: Option<String>,
    pub(crate) vout: Option<u64>,
    pub(crate) is_coinbase: bool,
}

/// A transaction, as Esplora writes it.
#[derive(Clone, Debug)]
pub(crate) struct EsploraTx {
    pub(crate) txid: String,
    pub(crate) vin: Vec<Vin>,
    /// (value, scriptpubkey_address)
    pub(crate) vout: Vec<(u64, Option<String>)>,
    /// The height of its block; `None` in the mempool.
    pub(crate) height: Option<u64>,
}

impl EsploraTx {
    pub(crate) fn to_json(&self) -> Json {
        let vin = self
            .vin
            .iter()
            .map(|input| {
                let mut members = Vec::new();
                if let Some(txid) = &input.txid {
                    members.push(("txid", Json::from(txid.as_str())));
                }
                if let Some(vout) = input.vout {
                    members.push(("vout", Json::unsigned(vout)));
                }
                members.push(("is_coinbase", Json::Bool(input.is_coinbase)));
                Json::object_of(members)
            })
            .collect();
        let vout = self
            .vout
            .iter()
            .map(|(value, address)| {
                let mut members = vec![("value", Json::unsigned(*value))];
                if let Some(address) = address {
                    members.push(("scriptpubkey_address", Json::from(address.as_str())));
                }
                Json::object_of(members)
            })
            .collect();
        let status = match self.height {
            None => Json::object([("confirmed", Json::Bool(false))]),
            Some(height) => {
                Json::object([("confirmed", Json::Bool(true)), ("block_height", Json::unsigned(height))])
            }
        };
        Json::object([
            ("txid", Json::from(self.txid.as_str())),
            ("vin", Json::array(vin)),
            ("vout", Json::array(vout)),
            ("status", status),
        ])
    }

    /// The coins it spends, `<txid>:<vout>`.
    pub(crate) fn coins(&self) -> Vec<String> {
        self.vin
            .iter()
            .map(|input| {
                format!("{}:{}", input.txid.clone().unwrap_or_default(), input.vout.unwrap_or_default())
            })
            .collect()
    }
}

/// How a test transaction is made: the coins it spends (`<txid>:<vout>`), its block.
#[derive(Clone, Debug, Default)]
pub(crate) struct Paying {
    pub(crate) coins: Option<Vec<String>>,
    pub(crate) height: Option<u64>,
}

/// A transaction paying `address` `sats`, spending one coin of its own, and some change.
pub(crate) fn payment(id: &str, address: &str, sats: u64) -> EsploraTx {
    payment_with(id, address, sats, Paying::default())
}

/// A transaction paying `address` `sats`, spending `coins` (one of its own by default), in the
/// block `height` (the mempool by default), and some change.
pub(crate) fn payment_with(id: &str, address: &str, sats: u64, paying: Paying) -> EsploraTx {
    let coins = paying.coins.unwrap_or_else(|| vec![format!("{}:0", txid(format!("coin of {id}")))]);
    EsploraTx {
        txid: id.to_owned(),
        vin: coins
            .iter()
            .map(|coin| {
                let (spent, vout) = coin.split_once(':').expect("<txid>:<vout>");
                Vin {
                    txid: Some(spent.to_owned()),
                    vout: Some(vout.parse().expect("a vout")),
                    is_coinbase: false,
                }
            })
            .collect(),
        vout: vec![(sats, Some(address.to_owned())), (5000, Some(deposit_address("change")))],
        height: paying.height,
    }
}

/// A service of the chain that can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Service {
    /// mempool.space: HTTP 503.
    Explorer,
    /// The merchant's Bitcoin node: unreachable (a server outside the merchant's network), no
    /// answer.
    Node,
    Blockcypher,
}

#[derive(Default)]
struct ChainState {
    height: u64,
    txs: HashMap<String, Vec<EsploraTx>>,
    received: HashMap<String, String>,
    down: HashSet<Service>,
    asked: Vec<String>,
    /// The merchant's Bitcoin node's URL (its REST API at `<url>/api`), when there is one.
    node: Option<String>,
}

impl ChainState {
    /// An Esplora explorer's answer to `path` (after its `/api`).
    fn esplora(&self, path: &str) -> Answer {
        if path == "/blocks/tip/height" {
            return Answer::text(200, &self.height.to_string());
        }
        if let Some(address) = path.strip_prefix("/address/").and_then(|rest| rest.strip_suffix("/txs"))
            && !address.is_empty()
            && address.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            let txs = self
                .txs
                .get(address)
                .map(|txs| txs.iter().map(EsploraTx::to_json).collect())
                .unwrap_or_default();
            return Answer::json(&Json::array(txs));
        }
        Answer::text(404, "Not found")
    }
}

/// The explorers and BlockCypher, as a test sets them.
#[derive(Clone)]
pub(crate) struct FakeChain(Arc<Mutex<ChainState>>);

impl FakeChain {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(ChainState { height: 970_000, ..ChainState::default() })))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.0.lock().unwrap()
    }

    /// The chain's height, on the explorer.
    pub(crate) fn height(&self) -> u64 {
        self.state().height
    }

    /// Adds `tx` to the transactions of `address`, first (the explorer lists the newest first).
    pub(crate) fn add(&self, address: &str, tx: EsploraTx) {
        self.state().txs.entry(address.to_owned()).or_default().insert(0, tx);
    }

    /// Drops `id` from the mempool (replaced, or dropped).
    pub(crate) fn drop_tx(&self, address: &str, id: &str) {
        if let Some(txs) = self.state().txs.get_mut(address) {
            txs.retain(|tx| tx.txid != id);
        }
    }

    /// Confirms `id` at `height`.
    pub(crate) fn confirm(&self, address: &str, id: &str, height: u64) {
        if let Some(txs) = self.state().txs.get_mut(address) {
            for tx in txs.iter_mut().filter(|tx| tx.txid == id) {
                tx.height = Some(height);
            }
        }
    }

    /// When BlockCypher received `txid` (RFC 3339).
    pub(crate) fn set_received(&self, txid: &str, received: &str) {
        self.state().received.insert(txid.to_owned(), received.to_owned());
    }

    /// Makes `service` fail (HTTP 5xx), or answer again.
    pub(crate) fn set_down(&self, service: Service, down: bool) {
        if down {
            self.state().down.insert(service);
        } else {
            self.state().down.remove(&service);
        }
    }

    /// Every URL of the chain asked.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.state().asked.clone()
    }

    /// Serves the merchant's Bitcoin node at `url` (its REST API at `<url>/api`); `None`: none.
    pub(crate) fn set_node(&self, url: Option<&str>) {
        self.state().node = url.map(str::to_owned);
    }

    /// The URLs of mempool.space asked.
    pub(crate) fn mempool_asked(&self) -> Vec<String> {
        self.asked().into_iter().filter(|url| url.starts_with(&format!("{MEMPOOL_URL}/"))).collect()
    }

    /// The URLs of the merchant's Bitcoin node asked (unreachable ones too).
    pub(crate) fn node_asked(&self) -> Vec<String> {
        let Some(node) = self.state().node.clone() else { return Vec::new() };
        self.asked().into_iter().filter(|url| url.starts_with(&format!("{node}/"))).collect()
    }

    /// The URLs of BlockCypher asked.
    pub(crate) fn blockcypher_asked(&self) -> Vec<String> {
        self.asked().into_iter().filter(|url| url.starts_with(BLOCKCYPHER_URL)).collect()
    }

    /// The answer to `call`, or `None` when it is not an explorer's.
    pub(crate) fn route(&self, call: &Call) -> Option<Answer> {
        let href = call.url.as_str();
        let mut state = self.state();
        let node_path =
            state.node.as_ref().and_then(|node| href.strip_prefix(&format!("{node}/api"))).map(str::to_owned);
        if let Some(path) = node_path {
            state.asked.push(href.to_owned());
            if state.down.contains(&Service::Node) {
                return None;
            }
            return Some(state.esplora(&path));
        }
        if let Some(path) = href.strip_prefix(MEMPOOL_URL) {
            state.asked.push(href.to_owned());
            if state.down.contains(&Service::Explorer) {
                return Some(Answer::text(503, "down"));
            }
            return Some(state.esplora(path));
        }
        if href.starts_with(BLOCKCYPHER_URL) {
            state.asked.push(href.to_owned());
            if state.down.contains(&Service::Blockcypher) {
                return Some(Answer::status_json(500, &Json::object([("error", Json::from("down"))])));
            }
            let id = call.path().rsplit('/').next().unwrap_or_default().to_owned();
            return Some(match state.received.get(&id) {
                None => Answer::status_json(
                    404,
                    &Json::object([("error", Json::from(format!("Transaction {id} not found.")))]),
                ),
                Some(received) => Answer::json(&Json::object([
                    ("hash", Json::from(id.as_str())),
                    ("received", Json::from(received.as_str())),
                    ("confirmations", Json::unsigned(0)),
                ])),
            });
        }
        None
    }
}

#[derive(Default)]
struct SocketState {
    messages: Vec<Json>,
    connections: usize,
    clients: Vec<Arc<Peer>>,
    handshakes: Vec<crate::websocket::WebSocketRequest>,
}

/// mempool.space's WebSocket for tests: records what each client sends, and pushes what a test
/// says changed.
#[derive(Clone, Default)]
pub(crate) struct FakeExplorerSocket(Arc<Mutex<SocketState>>);

impl FakeExplorerSocket {
    /// Every message a client sent, as JSON.
    pub(crate) fn messages(&self) -> Vec<Json> {
        self.0.lock().unwrap().messages.clone()
    }

    pub(crate) fn connections(&self) -> usize {
        self.0.lock().unwrap().connections
    }

    /// How many clients are connected.
    pub(crate) fn open_clients(&self) -> usize {
        self.0.lock().unwrap().clients.iter().filter(|client| client.is_open()).count()
    }

    /// Every opening handshake, its headers.
    pub(crate) fn handshakes(&self) -> Vec<crate::websocket::WebSocketRequest> {
        self.0.lock().unwrap().handshakes.clone()
    }

    /// Pushes `message` to every client.
    pub(crate) fn push(&self, message: &Json) {
        let text = json::stringify(message);
        for client in &self.0.lock().unwrap().clients {
            client.send(text.clone());
        }
    }

    /// Drops every client's connection.
    pub(crate) fn drop_clients(&self) {
        let clients = std::mem::take(&mut self.0.lock().unwrap().clients);
        for client in clients {
            client.close();
        }
    }

    /// A client connects: what it sends is recorded.
    pub(crate) fn accept(&self, request: crate::websocket::WebSocketRequest) -> super::relay::MemorySocket {
        let peer = Arc::new(Peer::default());
        let (socket, sender) = super::relay::MemorySocket::new(peer.clone());
        peer.open(sender);
        let mut state = self.0.lock().unwrap();
        state.connections += 1;
        state.handshakes.push(request);
        state.clients.push(peer);
        let shared = self.0.clone();
        socket.on_message(move |text| {
            if let Some(message) = json::parse(&text) {
                shared.lock().unwrap().messages.push(message);
            }
        })
    }
}
