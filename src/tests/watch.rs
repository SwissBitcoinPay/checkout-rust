//! The explorer's WebSocket while `wait_for_payment` waits (SPEC.md §31, Waiting for an on-chain
//! payment): a lost socket connects again after 1 s, doubled at each failure up to 30 s, a
//! connection lost before it received a message being a failure. Each connection starts a full
//! check: a server that accepts and drops every connection must not have one every second. With
//! the merchant's Bitcoin node (SPEC.md §31, The merchant's Bitcoin node): its WebSocket, never
//! mempool.space's while it answers; with `fallback` `"mempool"`, mempool.space's at once when a
//! connection to the node fails or is lost before any message, the node tried after it for 60 s;
//! with `"none"`, the node's alone.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::support::chain::deposit_address;
use super::support::relay::{MemorySocket, Peer};
use crate::json::{self, Json};
use crate::onchain::explorer::{Explorer, NodeFailures};
use crate::onchain::node::{BitcoinNode, NodeFallback};
use crate::onchain::watch::watch_address;
use crate::protocol::MEMPOOL_WEBSOCKET_URL;
use crate::runtime::Clock;
use crate::transport::{BoxFuture, TransportError};
use crate::websocket::{WebSocketClient, WebSocketConnection, WebSocketRequest};

/// One connection the watcher opened: its URL, the explorer's end, what the watcher sent.
struct Opened {
    url: String,
    peer: Arc<Peer>,
    sent: Arc<Mutex<Vec<String>>>,
}

/// An explorer in memory: each connection accepted (but to the URLs it refuses), then answered and
/// dropped by the test.
#[derive(Clone, Default)]
struct Server {
    connections: Arc<Mutex<Vec<Opened>>>,
    /// Every URL asked, refused ones included.
    asked: Arc<Mutex<Vec<String>>>,
    /// The URLs that refuse the connection (a node that does not answer).
    refused: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn count(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    /// The `index`th connection's explorer end and what the watcher sent on it.
    fn connection(&self, index: usize) -> (String, Arc<Peer>, Vec<String>) {
        let connections = self.connections.lock().unwrap();
        let opened = &connections[index];
        (opened.url.clone(), opened.peer.clone(), opened.sent.lock().unwrap().clone())
    }

    fn last(&self) -> Arc<Peer> {
        self.connection(self.count() - 1).1
    }
}

impl WebSocketClient for Server {
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
        self.asked.lock().unwrap().push(request.url.clone());
        if self.refused.lock().unwrap().contains(&request.url) {
            return Box::pin(async { Err(TransportError::new("refused")) });
        }
        let peer = Arc::new(Peer::default());
        let (socket, sender) = MemorySocket::new(peer.clone());
        peer.open(sender);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let socket = {
            let sent = sent.clone();
            socket.on_message(move |text| sent.lock().unwrap().push(text))
        };
        self.connections.lock().unwrap().push(Opened { url: request.url, peer, sent });
        Box::pin(async move { Ok(Box::new(socket) as Box<dyn WebSocketConnection>) })
    }
}

/// Tokio's clock (virtual in these tests), in milliseconds.
struct TokioClock(tokio::time::Instant);

impl Clock for TokioClock {
    fn now_ms(&self) -> i64 {
        1_791_378_000_000 + self.0.elapsed().as_millis() as i64
    }
}

/// The watcher of a deposit address on `server`, of mempool.space's WebSocket, run on its own
/// task, and what it signals.
fn watch(server: &Server) -> (JoinHandle<()>, mpsc::UnboundedReceiver<()>) {
    watch_with(server, None, NodeFailures::default())
}

/// The watcher of a deposit address on `server`, of `node`'s WebSocket with its fallback (`None`:
/// mempool.space's), the node's failures in `failures`.
fn watch_with(
    server: &Server,
    node: Option<BitcoinNode>,
    failures: NodeFailures,
) -> (JoinHandle<()>, mpsc::UnboundedReceiver<()>) {
    let (changes, heard) = mpsc::unbounded_channel();
    let server = server.clone();
    let explorer = Explorer::new(node.as_ref(), failures, Arc::new(TokioClock(tokio::time::Instant::now())));
    let watcher =
        tokio::spawn(async move { watch_address(&server, &explorer, &deposit_address(1), changes).await });
    (watcher, heard)
}

/// Lets the watcher's task run on what changed (virtual time stands still meanwhile).
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// Whether the watcher connects again exactly `ms` after now: not a millisecond before.
async fn connects_after(explorer: &Server, ms: u64) -> bool {
    let before = explorer.count();
    tokio::time::advance(Duration::from_millis(ms - 1)).await;
    settle().await;
    if explorer.count() != before {
        return false;
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    settle().await;
    explorer.count() == before + 1
}

fn signals(heard: &mut mpsc::UnboundedReceiver<()>) -> usize {
    let mut count = 0;
    while heard.try_recv().is_ok() {
        count += 1;
    }
    count
}

#[tokio::test(start_paused = true)]
async fn tracks_the_address_and_checks_at_each_connection() {
    let explorer = Server::default();
    let (watcher, mut heard) = watch(&explorer);
    settle().await;
    assert_eq!(explorer.count(), 1);
    let (url, peer, sent) = explorer.connection(0);
    assert_eq!(url, MEMPOOL_WEBSOCKET_URL);
    let sent: Vec<String> = sent.iter().map(|text| json::stringify(&json::parse(text).unwrap())).collect();
    assert_eq!(
        sent,
        vec![
            r#"{"action":"want","data":["blocks"]}"#.to_owned(),
            format!(r#"{{"track-address":"{}"}}"#, deposit_address(1))
        ]
    );
    assert_eq!(signals(&mut heard), 1);
    peer.send(json::stringify(&Json::object([(
        "block",
        Json::object([("height", Json::unsigned(970_001))]),
    )])));
    settle().await;
    assert_eq!(signals(&mut heard), 1);
    // A message about nothing that changed: no check.
    peer.send(r#"{"conversions":{"USD":69012}}"#.to_owned());
    settle().await;
    assert_eq!(signals(&mut heard), 0);
    watcher.abort();
}

#[tokio::test(start_paused = true)]
async fn waits_longer_at_each_connection_dropped_before_a_message_1_s_doubled_up_to_30_s() {
    let explorer = Server::default();
    let (watcher, mut heard) = watch(&explorer);
    settle().await;
    for delay in [1000, 2000, 4000, 8000, 16_000, 30_000, 30_000] {
        explorer.last().close();
        settle().await;
        assert!(connects_after(&explorer, delay).await, "not connected again {delay} ms after a drop");
    }
    // One check per connection: eight in some 91 s, never one a second.
    assert_eq!(explorer.count(), 8);
    assert_eq!(signals(&mut heard), 8);
    watcher.abort();
}

#[tokio::test(start_paused = true)]
async fn waits_1_s_again_once_a_connection_received_a_message() {
    let explorer = Server::default();
    let (watcher, _heard) = watch(&explorer);
    settle().await;
    explorer.last().close();
    settle().await;
    assert!(connects_after(&explorer, 1000).await);
    explorer.last().close();
    settle().await;
    assert!(connects_after(&explorer, 2000).await);
    let peer = explorer.last();
    peer.send(r#"{"address-transactions":[]}"#.to_owned());
    settle().await;
    peer.close();
    settle().await;
    assert!(connects_after(&explorer, 1000).await);
    watcher.abort();
}

#[tokio::test(start_paused = true)]
async fn connects_no_more_once_its_future_is_dropped() {
    let explorer = Server::default();
    let (watcher, _heard) = watch(&explorer);
    settle().await;
    explorer.last().close();
    settle().await;
    watcher.abort();
    settle().await;
    tokio::time::advance(Duration::from_secs(60)).await;
    settle().await;
    assert_eq!(explorer.count(), 1);
}

const NODE: &str = "http://192.168.1.10:3006";
const NODE_WS: &str = "ws://192.168.1.10:3006/api/v1/ws";

fn node(fallback: NodeFallback) -> Option<BitcoinNode> {
    Some(BitcoinNode { url: NODE.to_owned(), fallback, payers: false })
}

#[tokio::test(start_paused = true)]
async fn watches_the_node_s_websocket_never_mempool_space_s_while_it_answers() {
    for fallback in [NodeFallback::Mempool, NodeFallback::None] {
        let server = Server::default();
        let (watcher, mut heard) = watch_with(&server, node(fallback), NodeFailures::default());
        settle().await;
        let (url, peer, sent) = server.connection(0);
        assert_eq!(url, NODE_WS);
        assert_eq!(sent.len(), 2);
        assert_eq!(signals(&mut heard), 1);
        peer.send(r#"{"block":{"height":970001}}"#.to_owned());
        settle().await;
        assert_eq!(signals(&mut heard), 1);
        // Lost after a message: the node again, after 1 s.
        peer.close();
        settle().await;
        assert!(connects_after(&server, 1000).await);
        assert_eq!(*server.asked.lock().unwrap(), vec![NODE_WS.to_owned(), NODE_WS.to_owned()]);
        watcher.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn with_fallback_mempool_goes_to_mempool_space_s_at_once_when_the_node_s_fails() {
    let server = Server::default();
    server.refused.lock().unwrap().push(NODE_WS.to_owned());
    let failures = NodeFailures::default();
    let (watcher, mut heard) = watch_with(&server, node(NodeFallback::Mempool), failures.clone());
    settle().await;
    // Refused, then mempool.space's at once: the node failed for the call.
    assert_eq!(*server.asked.lock().unwrap(), vec![NODE_WS.to_owned(), MEMPOOL_WEBSOCKET_URL.to_owned()]);
    assert!(failures.lock().unwrap().contains_key(NODE));
    assert_eq!(signals(&mut heard), 1);
    // Lost before any message: a failure of the last one tried, 1 s later; within the 60 s,
    // mempool.space's first, the node's not asked while it answers.
    server.last().close();
    settle().await;
    assert!(connects_after(&server, 1000).await);
    assert_eq!(server.asked.lock().unwrap()[2], MEMPOOL_WEBSOCKET_URL);
    assert_eq!(server.asked.lock().unwrap().len(), 3);
    // mempool.space's lost before any message: the node after it at once (refused, failed now
    // again), then mempool.space's first 2 s later.
    server.last().close();
    settle().await;
    assert_eq!(server.asked.lock().unwrap()[3], NODE_WS);
    assert!(connects_after(&server, 2000).await);
    assert_eq!(server.asked.lock().unwrap()[4], MEMPOOL_WEBSOCKET_URL);
    // Lost after a message, more than 60 s after the node failed: the node first again.
    let peer = server.last();
    peer.send(r#"{"block":{"height":970001}}"#.to_owned());
    settle().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    peer.close();
    settle().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    let asked = server.asked.lock().unwrap().clone();
    assert_eq!(asked[5..], [NODE_WS.to_owned(), MEMPOOL_WEBSOCKET_URL.to_owned()]);
    watcher.abort();
}

#[tokio::test(start_paused = true)]
async fn with_fallback_mempool_a_node_s_connection_lost_before_any_message_goes_to_mempool_space_s() {
    let server = Server::default();
    let (watcher, _heard) = watch_with(&server, node(NodeFallback::Mempool), NodeFailures::default());
    settle().await;
    server.last().close();
    settle().await;
    assert_eq!(*server.asked.lock().unwrap(), vec![NODE_WS.to_owned(), MEMPOOL_WEBSOCKET_URL.to_owned()]);
    watcher.abort();
}

#[tokio::test(start_paused = true)]
async fn with_fallback_none_never_goes_to_mempool_space_s_and_connects_to_the_node_again_later() {
    let server = Server::default();
    server.refused.lock().unwrap().push(NODE_WS.to_owned());
    let (watcher, mut heard) = watch_with(&server, node(NodeFallback::None), NodeFailures::default());
    settle().await;
    for delay in [1000, 2000, 4000] {
        let before = server.asked.lock().unwrap().len();
        tokio::time::advance(Duration::from_millis(delay - 1)).await;
        settle().await;
        assert_eq!(server.asked.lock().unwrap().len(), before);
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(server.asked.lock().unwrap().len(), before + 1, "{delay}");
    }
    assert!(server.asked.lock().unwrap().iter().all(|url| url == NODE_WS));
    assert_eq!(signals(&mut heard), 0);
    watcher.abort();
}
