//! The merchant's Bitcoin node (SPEC.md §31, The merchant's Bitcoin node), end to end against
//! local relays and fakes of breez.tips, of mempool.space and of a node on the merchant's network
//! (REST and WebSocket), as PORTING.md step 5 lists: every read of an address and of the chain's
//! height, and `wait_for_payment`'s WebSocket, asked of the node and never of mempool.space while
//! it answers; its `fallback` when it does not; the 60 s after a failure; a check's two reads of
//! one explorer; an invalid `bitcoinNode` read as none; the node in a checkout link's record.
//! Mirrors checkout-node's test/bitcoin-node.test.ts.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::onchain_security::iso;
use super::support::chain::{Paying, Service, deposit_address, payment_with, txid};
use super::support::http::Answer;
use super::support::merchant::TestMerchant;
use crate::checkout::{CheckoutFragment, checkout_keys, parse_checkout_fragment, parse_checkout_value};
use crate::client::{Client, ClientBuilder, WaitOptions};
use crate::error::ErrorCode;
use crate::json::{self, Json};
use crate::model::{Invoice, Payment, PaymentStatus};
use crate::nostr::event::valid_event;
use crate::nostr::nip44::decrypt;
use crate::onchain::node::{NodeFallback, RecordNode};
use crate::order::Order;
use crate::protocol::{MEMPOOL_URL, MEMPOOL_WEBSOCKET_URL, USER_AGENT};
use crate::runtime::{OsRandom, Random};

const ORIGIN: &str = "https://pay.example";
const NODE: &str = "http://192.168.1.10:3006";
const NODE_WS: &str = "ws://192.168.1.10:3006/api/v1/ws";
const INTERNET_NODE: &str = "https://mempool.shop.example";

fn address() -> String {
    deposit_address(1)
}

/// A merchant whose lot holds one address.
fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    merchant.publish_lot(&[address()], 90);
    merchant
}

/// Publishes the channel naming `bitcoin_node` (`None`: without the field), whose node the fake
/// serves.
fn publish_channel(merchant: &TestMerchant, bitcoin_node: Option<Json>) {
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    let mut extra = vec![("relays", relays), ("checkout", Json::object([("origin", Json::from(ORIGIN))]))];
    if let Some(node) = &bitcoin_node {
        extra.push(("bitcoinNode", node.clone()));
    }
    merchant.publish_channel(&merchant.channel_value(100, Json::object_of(extra)), 100);
    let url = bitcoin_node.as_ref().and_then(|node| node.get("url")).and_then(Json::as_str);
    merchant.chain.set_node(url);
}

/// A channel's `bitcoinNode`: `{url, fallback, payers}`.
fn node(url: &str, fallback: &str, payers: bool) -> Option<Json> {
    Some(Json::object([
        ("url", Json::from(url)),
        ("fallback", Json::from(fallback)),
        ("payers", Json::Bool(payers)),
    ]))
}

fn builder(merchant: &TestMerchant) -> ClientBuilder {
    merchant.client()
}

fn client(merchant: &TestMerchant) -> Client {
    builder(merchant).build().unwrap()
}

/// Above the Lightning address's bounds: an order paid on-chain only.
fn onchain_only(merchant: &TestMerchant) {
    merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
}

fn json(status: &PaymentStatus) -> serde_json::Value {
    serde_json::to_value(status).unwrap()
}

/// The record of the link `url` the first relay holds, as its page opens it.
fn record_of(merchant: &TestMerchant, url: &str) -> Json {
    let CheckoutFragment::Link { link_key, .. } = parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("Not a link: {url}")
    };
    let keys = checkout_keys(&link_key);
    let event = merchant
        .net
        .get(&merchant.key_relays[0])
        .events()
        .into_iter()
        .filter_map(|value| valid_event(&value))
        .find(|event| event.tag("d") == Some(keys.address.as_str()))
        .expect("the link's record");
    let envelope = json::parse(&decrypt(&event.content, &keys.encryption_key).unwrap()).unwrap();
    envelope.get("v").unwrap().clone()
}

async fn until(condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(condition());
}

/// The explorers the chain was asked since `mark`, one name per run of requests to one explorer
/// (the two requests of a check's step 1 are one read).
fn explorers_since(merchant: &TestMerchant, mark: &mut usize) -> Vec<&'static str> {
    let asked = merchant.chain.asked();
    let mut runs: Vec<&'static str> = Vec::new();
    for url in &asked[*mark..] {
        let name = if url.starts_with(NODE) {
            "node"
        } else if url.starts_with(MEMPOOL_URL) {
            "mempool"
        } else {
            continue;
        };
        if runs.last() != Some(&name) {
            runs.push(name);
        }
    }
    *mark = asked.len();
    runs
}

/// The statuses `wait_for_payment` gives, as they come.
type Statuses = Arc<Mutex<Vec<PaymentStatus>>>;

/// `wait_for_payment` of `invoice` on its own task, Lightning checked once a minute: what moves
/// here is the WebSocket.
fn wait(
    client: &Client,
    invoice: &Invoice,
) -> (Statuses, tokio::task::JoinHandle<Result<PaymentStatus, crate::Error>>) {
    let statuses: Statuses = Arc::default();
    let heard = statuses.clone();
    let options = WaitOptions::default()
        .interval_ms(60_000)
        .on_status(move |status| heard.lock().unwrap().push(status.clone()));
    let (client, invoice) = (client.clone(), invoice.clone());
    (statuses, tokio::spawn(async move { client.wait_for_payment(&invoice, options).await }))
}

mod a_node_that_answers {
    use super::*;

    fn answering() -> TestMerchant {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "mempool", false));
        merchant
    }

    #[tokio::test(start_paused = true)]
    async fn is_the_only_explorer_asked_the_lease_every_check_paid_at_3_confirmations() {
        let merchant = answering();
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("N-1", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, Some(address()));
        // The lease: whether the address was paid already, of the node.
        assert_eq!(merchant.chain.node_asked(), vec![format!("{NODE}/api/address/{}/txs", address())]);
        let tx = payment_with(&txid("node"), &address(), 49_000, Paying::default());
        merchant.chain.add(&address(), tx.clone());
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "unconfirmed");
        merchant.chain.confirm(&address(), &tx.txid, merchant.chain.height() - 2);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": "49000", "txids": [tx.txid] })
        );
        assert_eq!(merchant.chain.mempool_asked(), Vec::<String>::new());
        let heights: Vec<String> = merchant
            .chain
            .node_asked()
            .into_iter()
            .filter(|url| url.ends_with("/blocks/tip/height"))
            .collect();
        assert_eq!(heights, vec![format!("{NODE}/api/blocks/tip/height"); 2]);
        // Over http, with the User-Agent of every request (SPEC.md §15).
        let calls: Vec<_> = merchant
            .http
            .calls()
            .into_iter()
            .filter(|call| call.url.starts_with(&format!("{NODE}/")))
            .collect();
        assert!(!calls.is_empty());
        for call in calls {
            assert_eq!(call.header("User-Agent"), Some(USER_AGENT));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn follows_no_redirect_of_the_node_a_failure_mempool_space_then_asked() {
        let merchant = answering();
        let invoice = client(&merchant).create_invoice(&Order::sats("N-2", 49_000)).await.unwrap();
        merchant.set_override(Some(|call: &super::super::support::http::Call| {
            call.url.starts_with(&format!("{NODE}/")).then(|| Answer { status: 302, body: Vec::new() })
        }));
        assert_eq!(client(&merchant).get_status(&invoice).await.unwrap().state(), "open");
        // The address's transactions and the chain's height, of mempool.space.
        assert_eq!(merchant.chain.mempool_asked().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn is_watched_by_wait_for_payment_on_the_node_s_websocket_never_mempool_space_s() {
        let merchant = answering();
        let node = merchant.net.add_server(NODE_WS);
        let mempool = merchant.start_explorer_socket();
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("N-3", 49_000)).await.unwrap();
        let (statuses, waiting) = wait(&client, &invoice);
        until(|| node.messages().len() == 2 && !statuses.lock().unwrap().is_empty()).await;
        let sent: Vec<String> = node.messages().iter().map(json::stringify).collect();
        assert_eq!(
            sent,
            vec![
                r#"{"action":"want","data":["blocks"]}"#.to_owned(),
                format!(r#"{{"track-address":"{}"}}"#, address())
            ]
        );
        assert_eq!(node.handshakes()[0].headers, vec![("User-Agent".to_owned(), USER_AGENT.to_owned())]);
        let tx = payment_with(
            &txid("watched"),
            &address(),
            49_000,
            Paying { height: Some(merchant.chain.height() - 2), ..Paying::default() },
        );
        merchant.chain.add(&address(), tx.clone());
        node.push(&Json::object([("address-transactions", Json::array(vec![tx.to_json()]))]));
        let last = waiting.await.unwrap().unwrap();
        assert!(matches!(last, PaymentStatus::Paid(Payment::Onchain { .. })), "{last:?}");
        assert_eq!(mempool.connections(), 0);
        assert_eq!(merchant.chain.mempool_asked(), Vec::<String>::new());
    }
}

mod a_node_that_does_not_answer_fallback_mempool {
    use super::*;

    /// A random source whose draws of 4 bytes (the shuffle's) keep the lot's order.
    struct LotOrder;

    impl Random for LotOrder {
        fn fill(&self, bytes: &mut [u8]) {
            if bytes.len() == 4 {
                bytes.fill(255);
            } else {
                OsRandom.fill(bytes);
            }
        }
    }

    fn unreachable() -> TestMerchant {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "mempool", false));
        // A server outside the merchant's network: no answer.
        merchant.chain.set_down(Service::Node, true);
        merchant
    }

    #[tokio::test(start_paused = true)]
    async fn reads_mempool_space_instead_and_network_when_both_fail() {
        let merchant = unreachable();
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("F-1", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, Some(address()));
        let tx = payment_with(
            &txid("fallback"),
            &address(),
            49_000,
            Paying { height: Some(merchant.chain.height() - 2), ..Paying::default() },
        );
        merchant.chain.add(&address(), tx);
        assert_eq!(json(&client.get_status(&invoice).await.unwrap())["method"], "onchain");
        merchant.chain.set_down(Service::Explorer, true);
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn asks_the_node_after_mempool_space_for_60_s_once_it_failed_in_the_same_call() {
        // Two addresses: the first paid already (skipped), the second leased. The node fails the
        // first's read: the second's is asked of mempool.space first.
        let merchant = unreachable();
        let second = deposit_address(2);
        merchant.publish_lot(&[address(), second.clone()], 91);
        merchant.chain.add(
            &address(),
            payment_with(&txid("earlier"), &address(), 1000, Paying { height: Some(1), ..Paying::default() }),
        );
        let client = builder(&merchant).random(LotOrder).build().unwrap();
        let invoice = client.create_invoice(&Order::sats("F-2", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, Some(second.clone()));
        let asked: Vec<String> = merchant
            .chain
            .asked()
            .iter()
            .map(|url| {
                let explorer = if url.starts_with(NODE) { "node" } else { "mempool" };
                format!("{explorer} {}", url.split("/address/").nth(1).unwrap())
            })
            .collect();
        assert_eq!(
            asked,
            vec![
                format!("node {}/txs", address()),
                format!("mempool {}/txs", address()),
                format!("mempool {second}/txs"),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn asks_the_node_after_mempool_space_within_60_s_in_every_check_of_one_wait_for_payment() {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "mempool", false));
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("F-3", 49_000)).await.unwrap();
        merchant.chain.set_down(Service::Node, true);
        let mempool = merchant.start_explorer_socket();
        let mut mark = merchant.chain.asked().len();
        let (statuses, waiting) = wait(&client, &invoice);
        // The first check: the node, then mempool.space; its WebSocket: mempool.space's connected
        // (the node's refused first, unless the check's read failed before it connected: the node
        // is then tried after mempool.space), which starts a check, of mempool.space alone (the
        // node failed less than 60 s ago, and mempool.space answers).
        until(|| statuses.lock().unwrap().len() == 2).await;
        assert_eq!(explorers_since(&merchant, &mut mark), vec!["node", "mempool"]);
        assert!(merchant.net.connections(NODE_WS) <= 1);
        assert_eq!(mempool.connections(), 1);
        // mempool.space failing within the 60 s: the node after it, which answers.
        merchant.chain.set_down(Service::Explorer, true);
        merchant.chain.set_down(Service::Node, false);
        mempool.push(&Json::object([("block", Json::object([("height", Json::unsigned(970_000))]))]));
        until(|| statuses.lock().unwrap().len() == 3).await;
        assert_eq!(explorers_since(&merchant, &mut mark), vec!["mempool", "node"]);
        assert_eq!(statuses.lock().unwrap().last().unwrap().state(), "open");
        // 60 s after its failure: the node first again.
        merchant.advance(60);
        merchant.chain.set_down(Service::Explorer, false);
        mempool.push(&Json::object([("block", Json::object([("height", Json::unsigned(970_000))]))]));
        until(|| statuses.lock().unwrap().len() == 4).await;
        assert_eq!(explorers_since(&merchant, &mut mark), vec!["node"]);
        waiting.abort();
    }
}

mod a_node_that_does_not_answer_fallback_none {
    use super::*;

    fn unreachable() -> TestMerchant {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "none", false));
        merchant.chain.set_down(Service::Node, true);
        merchant
    }

    #[tokio::test(start_paused = true)]
    async fn leases_no_address_network_for_an_order_paid_onchain_only_lightning_only_otherwise() {
        let merchant = unreachable();
        onchain_only(&merchant);
        let error = client(&merchant).create_invoice(&Order::sats("X-1", 2_000_000)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(100_000_000_000)));
        let invoice = client(&merchant).create_invoice(&Order::sats("X-2", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, None);
        assert!(invoice.bolt11.as_deref().is_some_and(|bolt11| bolt11.starts_with("lnbc")));
        assert_eq!(merchant.chain.mempool_asked(), Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn is_network_never_expired_however_long_the_node_is_down_then_paid_once_it_answers() {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "none", false));
        onchain_only(&merchant);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("X-3", 2_000_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, Some(address()));
        merchant.chain.set_down(Service::Node, true);
        // Paid while the lease ran, which no check saw: BlockCypher tells it in time.
        let tx = payment_with(
            &txid("unseen"),
            &address(),
            2_000_000,
            Paying { height: Some(merchant.chain.height() - 5), ..Paying::default() },
        );
        merchant.chain.add(&address(), tx.clone());
        merchant.chain.set_received(&tx.txid, &iso(invoice.created_at + 60));
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        // A new invoice of the order: refused while its earlier one cannot be told.
        let error = client.create_invoice(&Order::sats("X-3", 2_000_000)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
        // A day later still: never expired.
        merchant.advance(86_400);
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        assert_eq!(merchant.chain.mempool_asked(), Vec::<String>::new());
        merchant.chain.set_down(Service::Node, false);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": "2000000", "txids": [tx.txid] })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn is_never_final_underpaid_while_the_node_is_down() {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "none", false));
        onchain_only(&merchant);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("X-5", 2_000_000)).await.unwrap();
        // A part paid in time, seen by a check.
        merchant.chain.add(&address(), payment_with(&txid("part"), &address(), 1_000_000, Paying::default()));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Open { received: 1_000_000, .. }), "{status:?}");
        merchant.chain.set_down(Service::Node, true);
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        merchant.chain.set_down(Service::Node, false);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "1000000" })
        );
        assert_eq!(merchant.chain.mempool_asked(), Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn is_watched_on_the_node_s_websocket_alone_connected_again_while_it_is_down() {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "none", false));
        let mempool = merchant.start_explorer_socket();
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("X-4", 49_000)).await.unwrap();
        merchant.chain.set_down(Service::Node, true);
        let (_, waiting) = wait(&client, &invoice);
        // No node's WebSocket listens: refused, tried again after 1 s.
        until(|| merchant.net.connections(NODE_WS) >= 2).await;
        waiting.abort();
        assert_eq!(mempool.connections(), 0);
        assert_eq!(merchant.net.connections(MEMPOOL_WEBSOCKET_URL), 0);
        assert_eq!(merchant.chain.mempool_asked(), Vec::<String>::new());
    }
}

mod wait_for_payment_s_websocket_fallback_mempool {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn goes_to_mempool_space_s_when_the_node_s_fails_and_is_woken_by_it() {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "mempool", false));
        let mempool = merchant.start_explorer_socket();
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("W-1", 49_000)).await.unwrap();
        let (statuses, waiting) = wait(&client, &invoice);
        // The node's WebSocket refuses the connection: mempool.space's at once.
        until(|| mempool.messages().len() == 2 && !statuses.lock().unwrap().is_empty()).await;
        assert_eq!(merchant.net.connections(NODE_WS), 1);
        let tx = payment_with(
            &txid("socket"),
            &address(),
            49_000,
            Paying { height: Some(merchant.chain.height() - 2), ..Paying::default() },
        );
        merchant.chain.add(&address(), tx.clone());
        mempool.push(&Json::object([("address-transactions", Json::array(vec![tx.to_json()]))]));
        let last = waiting.await.unwrap().unwrap();
        assert!(matches!(last, PaymentStatus::Paid(Payment::Onchain { .. })), "{last:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn one_explorer_for_a_check_s_two_reads_both_of_mempool_space_when_the_node_fails_either() {
    for failing in ["/blocks/tip/height".to_owned(), format!("/address/{}/txs", address())] {
        let merchant = merchant();
        publish_channel(&merchant, node(NODE, "mempool", false));
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("O-1", 49_000)).await.unwrap();
        // The node gives one of the two, and fails the other.
        let tx = payment_with(
            &txid("one"),
            &address(),
            49_000,
            Paying { height: Some(merchant.chain.height() - 2), ..Paying::default() },
        );
        merchant.chain.add(&address(), tx);
        let failing_url = format!("{NODE}/api{failing}");
        merchant.set_override(Some(move |call: &super::support::http::Call| {
            (call.url == failing_url).then(|| Answer::text(500, "down"))
        }));
        let before = merchant.chain.mempool_asked().len();
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "paid", "{failing}");
        let asked = merchant.chain.mempool_asked()[before..].to_vec();
        assert!(asked.contains(&format!("{MEMPOOL_URL}/address/{}/txs", address())), "{asked:?}");
        assert!(asked.contains(&format!("{MEMPOOL_URL}/blocks/tip/height")), "{asked:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn an_invalid_bitcoin_node_reads_mempool_space_the_channel_still_valid() {
    let cases = [
        ("http to a public host", node("http://node.example", "mempool", false)),
        ("a fallback of another spelling", node(NODE, "Mempool", false)),
        ("payers absent", Some(Json::object([("url", Json::from(NODE)), ("fallback", Json::from("none"))]))),
        (
            "payers not a boolean",
            Some(Json::object([
                ("url", Json::from(INTERNET_NODE)),
                ("fallback", Json::from("none")),
                ("payers", Json::from("true")),
            ])),
        ),
        ("payers true for a local node", node(NODE, "none", true)),
    ];
    for (what, bitcoin_node) in cases {
        let merchant = merchant();
        publish_channel(&merchant, bitcoin_node);
        let invoice =
            client(&merchant).create_invoice(&Order::sats("I-1", 49_000).checkout(true)).await.unwrap();
        assert_eq!(invoice.onchain_address, Some(address()), "{what}");
        assert_eq!(merchant.chain.node_asked(), Vec::<String>::new(), "{what}");
        assert_eq!(
            merchant.chain.mempool_asked(),
            vec![format!("{MEMPOOL_URL}/address/{}/txs", address())],
            "{what}"
        );
        assert!(!record_of(&merchant, invoice.checkout_url.as_deref().unwrap()).has("bitcoinNode"), "{what}");
    }
}

mod the_record_of_a_checkout_link {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn holds_the_node_s_url_and_fallback_never_payers_with_payers_true() {
        let merchant = merchant();
        let mut bitcoin_node = vec![
            ("url", Json::from(INTERNET_NODE)),
            ("fallback", Json::from("none")),
            ("payers", Json::Bool(true)),
        ];
        bitcoin_node.push(("name", Json::from("Shop node")));
        publish_channel(&merchant, Some(Json::object_of(bitcoin_node)));
        let client = client(&merchant);
        let order = Order::sats("L-1", 49_000).checkout(true);
        let invoice = client.create_invoice(&order).await.unwrap();
        let record = record_of(&merchant, invoice.checkout_url.as_deref().unwrap());
        assert_eq!(record.get("version").and_then(Json::as_f64), Some(2.0));
        assert_eq!(record.get("onchainAddress").and_then(Json::as_str), Some(address().as_str()));
        let expected = RecordNode { url: INTERNET_NODE.to_owned(), fallback: NodeFallback::None };
        assert_eq!(record.get("bitcoinNode"), Some(&expected.to_json()));
        assert_eq!(parse_checkout_value(&record).unwrap().unwrap().bitcoin_node, Some(expected.clone()));
        // The link made again for invoice_pending holds it too.
        let pending = client.create_invoice(&order).await.unwrap_err();
        assert_eq!(pending.code(), ErrorCode::InvoicePending);
        let again = pending.checkout_url().unwrap();
        assert_ne!(Some(again), invoice.checkout_url.as_deref());
        assert_eq!(record_of(&merchant, again).get("bitcoinNode"), Some(&expected.to_json()));
    }

    #[tokio::test(start_paused = true)]
    async fn holds_no_node_with_payers_false_nor_without_a_node() {
        for bitcoin_node in [node(INTERNET_NODE, "mempool", false), None] {
            let merchant = merchant();
            publish_channel(&merchant, bitcoin_node);
            let invoice =
                client(&merchant).create_invoice(&Order::sats("L-2", 49_000).checkout(true)).await.unwrap();
            let record = record_of(&merchant, invoice.checkout_url.as_deref().unwrap());
            assert_eq!(record.get("version").and_then(Json::as_f64), Some(2.0));
            assert!(!record.has("bitcoinNode"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn holds_no_node_in_version_1_an_order_without_an_address() {
        let merchant = merchant();
        publish_channel(&merchant, node(INTERNET_NODE, "mempool", true));
        // Below the on-chain floor: Lightning only.
        let invoice =
            client(&merchant).create_invoice(&Order::sats("L-3", 999).checkout(true)).await.unwrap();
        assert_eq!(invoice.onchain_address, None);
        let record = record_of(&merchant, invoice.checkout_url.as_deref().unwrap());
        assert_eq!(record.get("version").and_then(Json::as_f64), Some(1.0));
        assert!(!record.has("bitcoinNode"));
    }
}
