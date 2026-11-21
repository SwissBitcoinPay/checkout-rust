//! The explorer's WebSocket (SPEC.md §31, Waiting for an on-chain payment): while
//! `wait_for_payment` waits, the explorer (mempool.space, or the merchant's Bitcoin node) pushes
//! what changes for the address (a transaction entering the mempool, confirmed, or leaving it) and
//! each new block (one more confirmation). Only a signal to check the on-chain part again: what it
//! pushes is never trusted, the check asks the explorer.

use std::time::Duration;

use tokio::sync::mpsc;

use crate::json::{self, Json};
use crate::onchain::explorer::{Explorer, ExplorerName, ExplorerSource};
use crate::protocol::{MAX_RELAY_MESSAGE_BYTES, RECONNECT_FIRST_MS, RECONNECT_MAX_MS};
use crate::websocket::{WebSocketClient, request_for};

/// The messages that say something changed for the address, or for its confirmations.
const CHANGES: [&str; 4] =
    ["address-transactions", "block-transactions", "address-removed-transactions", "block"];

/// Whether a message of the explorer says something changed.
pub(crate) fn is_change(text: &str) -> bool {
    json::parse(text).is_some_and(|message| message.is_object() && CHANGES.iter().any(|key| message.has(key)))
}

/// How one connection to an explorer's WebSocket ended.
enum Watched {
    /// It failed, or was lost before any message.
    Failed,
    /// It was lost after a message.
    Lost,
}

/// One connection to the WebSocket of `source`, as long as it lasts: `changes` hears a signal once
/// it is connected (what happened before was not pushed) and at each message about the address or
/// a new block; `delay` goes back to 1 s at each message.
async fn watch_on(
    client: &dyn WebSocketClient,
    source: &ExplorerSource,
    address: &str,
    changes: &mpsc::UnboundedSender<()>,
    delay: &mut u64,
) -> Watched {
    let Ok(mut socket) = client.connect(request_for(&source.websocket)).await else {
        return Watched::Failed;
    };
    let want = json::stringify(&Json::object([
        ("action", Json::from("want")),
        ("data", Json::array(vec![Json::from("blocks")])),
    ]));
    let track = json::stringify(&Json::object([("track-address", Json::from(address))]));
    if socket.send(want).await.is_err() || socket.send(track).await.is_err() {
        return Watched::Failed;
    }
    let _ = changes.send(());
    let mut answered = false;
    while let Some(Ok(text)) = socket.receive().await {
        if text.len() > MAX_RELAY_MESSAGE_BYTES {
            break;
        }
        // The explorer answers: the next loss waits 1 s again.
        answered = true;
        *delay = RECONNECT_FIRST_MS;
        if is_change(&text) {
            let _ = changes.send(());
        }
    }
    if answered { Watched::Lost } else { Watched::Failed }
}

/// Watches `address` on the WebSocket of `explorer`, as long as the returned future is polled (it
/// never ends: dropping it closes the socket): `changes` hears a signal at each connection (what
/// happened before was not pushed) and at each message about the address or a new block. Each
/// connection tries the WebSockets of the explorer's sources in order ([`Explorer::sources`]): one
/// that fails, or is lost before any message, goes to the next at once (the node's to
/// mempool.space's with `fallback` `"mempool"`, a node that failed less than 60 s ago being tried
/// after it; with `"none"`, the node's alone), and a node's failure is the call's
/// ([`Explorer::node_failed`]). A lost socket connects again after 1 s, doubled at each failure (of
/// the last one tried) up to 30 s; a connection lost before it received a message is a failure, so
/// that a server that accepts and drops each connection (each one starts a check) is connected to
/// less and less often.
pub(crate) async fn watch_address(
    client: &dyn WebSocketClient,
    explorer: &Explorer,
    address: &str,
    changes: mpsc::UnboundedSender<()>,
) {
    let mut delay = RECONNECT_FIRST_MS;
    loop {
        for source in explorer.sources() {
            match watch_on(client, &source, address, &changes, &mut delay).await {
                Watched::Lost => break,
                Watched::Failed => {
                    if source.name == ExplorerName::Node {
                        explorer.node_failed();
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(delay)).await;
        delay = (delay * 2).min(RECONNECT_MAX_MS);
    }
}
