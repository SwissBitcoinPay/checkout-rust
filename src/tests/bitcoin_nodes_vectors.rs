//! The merchant's Bitcoin node against bitcoin-nodes.json (SPEC.md §31, The merchant's Bitcoin
//! node; §30, the record), through the crate's own functions, as PORTING.md step 4 asks: its
//! `urls` through the check of a node URL and the URLs the node is read at, its `channels` through
//! the reading of the channel, its `reads` through the explorer's reads (REST, the two reads of a
//! check's step 1, and the WebSocket's connections), its `records` through the reading of a checkout link's record (as the page
//! reads it), and its `writes` through the making of one. Mirrors checkout-node's
//! test/bitcoin-nodes-vectors.test.ts.

use super::conformance::{every_case, expect_same};
use super::support::chain::deposit_address;
use super::support::vectors::{Field, spec};
use crate::channel::{Channel, parse_channel};
use crate::checkout::{CheckoutValue, is_checkout_origin, parse_checkout_value};
use crate::error::{Error, ErrorCode};
use crate::json::{Json, JsonObject, JsonString};
use crate::lnurl::lightning_address_url;
use crate::onchain::explorer::{Explorer, ExplorerName, NodeFailures, explorers_to_ask};
use crate::onchain::node::{
    BitcoinNode, NodeFallback, RecordNode, bitcoin_node_of, parse_node_url, record_node_for,
};
use crate::protocol::{MEMPOOL_URL, NODE_FAILED_RECENTLY_MS};
use crate::relays::is_relay_url;
use crate::runtime::Clock;
use crate::urls::parse_https_url;

fn vectors() -> Json {
    spec("vectors/bitcoin-nodes.json")
}

/// A node as the vectors write it: `{url, fallback, payers}`.
fn node_json(node: &BitcoinNode) -> Json {
    Json::object([
        ("url", Json::from(node.url.as_str())),
        ("fallback", Json::from(node.fallback.as_str())),
        ("payers", Json::Bool(node.payers)),
    ])
}

/// A record's node as the vectors write it: `{url, fallback}`.
fn record_node_json(node: Option<&RecordNode>) -> Json {
    node.map_or(Json::Null, RecordNode::to_json)
}

/// The app's channel, valid, with `bitcoinNode` set to `value` (absent: without the field), read.
fn channel_with(value: Option<&Json>) -> Channel {
    let app = spec("vectors/app/app.json");
    let channel = app.field("channel");
    let mut members: Vec<(JsonString, Json)> = channel
        .field("value")
        .field("v")
        .as_object()
        .expect("an object")
        .iter()
        .filter(|(name, _)| name.as_str() != Some("bitcoinNode"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    if let Some(value) = value {
        members.push((JsonString::Text("bitcoinNode".to_owned()), value.clone()));
    }
    let created_at = channel.field("event").int("created_at");
    match parse_channel(&Json::Object(JsonObject::new(members)), created_at) {
        Ok(Some(channel)) => channel,
        other => panic!("the channel is valid either way: {other:?}"),
    }
}

#[test]
fn urls() {
    every_case("bitcoin-nodes.json urls", vectors().list("urls"), |case| {
        let actual = parse_node_url(case.text("url")).map_or(Json::Null, |node| {
            Json::object([
                ("rest", Json::from(node.rest.as_str())),
                ("webSocket", Json::from(node.websocket.as_str())),
            ])
        });
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn channels() {
    every_case("bitcoin-nodes.json channels", vectors().list("channels"), |case| {
        let value = case.get("value");
        let Channel::Active(active) = channel_with(value) else {
            return Err("the channel is active".to_owned());
        };
        let read = active.bitcoin_node.as_ref().map_or(Json::Null, node_json);
        expect_same(&read, case.field("expected"))?;
        expect_same(&bitcoin_node_of(value).as_ref().map_or(Json::Null, node_json), case.field("expected"))
    });
}

mod reads {
    //! One read of the explorer: the node (its `fallback`, whether it failed a read less than 60 s
    //! ago in the same call, whether it answers), mempool.space (whether it answers), and the
    //! explorers asked, in order, and whose answer the read gives.

    use std::sync::{Arc, Mutex};

    use super::*;

    const NODE: &str = "http://192.168.1.10:3006";
    const NOW_MS: i64 = 1_791_378_000_000;

    /// A clock that stays at `NOW_MS`.
    struct Fixed;

    impl Clock for Fixed {
        fn now_ms(&self) -> i64 {
            NOW_MS
        }
    }

    fn fallback_of(case: &Json) -> Option<(NodeFallback, bool)> {
        let node = case.opt("node")?;
        let fallback = NodeFallback::of(node.get("fallback")).expect("a fallback");
        Some((fallback, node.field("failedRecently").as_bool().expect("a boolean")))
    }

    /// The explorer of a case: its node failed 1 ms inside the 60 s when `failedRecently`.
    fn explorer_of(case: &Json) -> Explorer {
        let failures = NodeFailures::default();
        let node = fallback_of(case).map(|(fallback, failed_recently)| {
            if failed_recently {
                failures.lock().unwrap().insert(NODE.to_owned(), NOW_MS - NODE_FAILED_RECENTLY_MS + 1);
            }
            BitcoinNode { url: NODE.to_owned(), fallback, payers: false }
        });
        Explorer::new(node.as_ref(), failures, Arc::new(Fixed))
    }

    fn name_of(rest: &str) -> &'static str {
        match rest {
            MEMPOOL_URL => "mempool",
            rest if rest == format!("{NODE}/api") => "node",
            other => panic!("not an explorer of the case: {other}"),
        }
    }

    fn answers(case: &Json, name: &str) -> bool {
        match name {
            "node" => case.field("node").field("answers").as_bool().unwrap(),
            _ => case.field("mempoolAnswers").as_bool().unwrap(),
        }
    }

    fn names(names: &[String]) -> Json {
        Json::array(names.iter().map(|name| Json::from(name.as_str())).collect())
    }

    fn outcome(asked: &[String], result: Result<&str, Error>) -> Result<Json, String> {
        let result = match result {
            Ok(name) => name.to_owned(),
            Err(error) if error.code() == ErrorCode::Network => "network".to_owned(),
            Err(error) => return Err(format!("not network: {error}")),
        };
        Ok(Json::object([("asked", names(asked)), ("result", Json::from(result.as_str()))]))
    }

    #[test]
    fn the_explorers_asked_first() {
        every_case("bitcoin-nodes.json reads, the order", vectors().list("reads"), |case| {
            // Every explorer a read may ask; the read stops at the first answer.
            let order: Vec<String> = explorers_to_ask(fallback_of(case))
                .into_iter()
                .map(|name| match name {
                    ExplorerName::Node => "node".to_owned(),
                    ExplorerName::Mempool => "mempool".to_owned(),
                })
                .collect();
            let asked = case.field("expected").list("asked");
            expect_same(&names(&order[..asked.len().min(order.len())]), &Json::array(asked.to_vec()))
        });
    }

    #[tokio::test]
    async fn a_rest_read() {
        for case in vectors().list("reads") {
            let asked = Mutex::new(Vec::new());
            let result = explorer_of(case)
                .read(|at| {
                    let name = name_of(&at.rest);
                    asked.lock().unwrap().push(name.to_owned());
                    let answers = answers(case, name);
                    async move {
                        if answers { Ok(name) } else { Err(Error::network(format!("{name} did not answer"))) }
                    }
                })
                .await;
            let actual = outcome(&asked.lock().unwrap(), result).unwrap();
            if let Err(problem) = expect_same(&actual, case.field("expected")) {
                panic!("bitcoin-nodes.json reads, REST: {}: {problem}", case.name());
            }
        }
    }

    #[tokio::test]
    async fn step_1_one_read_of_two_requests() {
        // The address's transactions and the chain's height, of one explorer: when either fails,
        // both are asked of the next one, never one from each.
        for case in vectors().list("reads") {
            for failing in ["transactions", "height"] {
                let asked = Mutex::new(Vec::new());
                let request = |name: &'static str, what: &'static str| {
                    asked.lock().unwrap().push(format!("{name} {what}"));
                    let fails = !answers(case, name) && what == failing;
                    async move {
                        tokio::task::yield_now().await;
                        if fails { Err(Error::network(format!("{name} failed"))) } else { Ok(name) }
                    }
                };
                let result = explorer_of(case)
                    .read(|at| {
                        let name = name_of(&at.rest);
                        let both = futures_util::future::try_join(
                            request(name, "transactions"),
                            request(name, "height"),
                        );
                        async move {
                            let (txs, height) = both.await?;
                            assert_eq!(txs, height, "one explorer");
                            Ok(txs)
                        }
                    })
                    .await;
                let expected = case.field("expected");
                let both: Vec<String> = expected
                    .texts("asked")
                    .iter()
                    .flat_map(|name| [format!("{name} transactions"), format!("{name} height")])
                    .collect();
                let actual = outcome(&asked.lock().unwrap(), result).unwrap();
                let expected =
                    Json::object([("asked", names(&both)), ("result", expected.field("result").clone())]);
                if let Err(problem) = expect_same(&actual, &expected) {
                    panic!(
                        "bitcoin-nodes.json reads, step 1 ({failing} failing): {}: {problem}",
                        case.name()
                    );
                }
            }
        }
    }

    /// A WebSocket in memory: it answers (opens, then a message) or fails (refused).
    struct Sockets<'a> {
        case: &'a Json,
        asked: Mutex<Vec<String>>,
        connected: Mutex<Option<&'static str>>,
    }

    /// An open socket that sends one message, then nothing.
    struct Answering(bool);

    impl crate::websocket::WebSocketConnection for Answering {
        fn send(&mut self, _: String) -> crate::transport::BoxFuture<'_, Result<(), crate::TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn receive(
            &mut self,
        ) -> crate::transport::BoxFuture<'_, Option<Result<String, crate::TransportError>>> {
            let first = !std::mem::replace(&mut self.0, true);
            Box::pin(async move {
                if first { Some(Ok(r#"{"block":{}}"#.to_owned())) } else { std::future::pending().await }
            })
        }
    }

    impl crate::websocket::WebSocketClient for Sockets<'_> {
        fn connect(
            &self,
            request: crate::websocket::WebSocketRequest,
        ) -> crate::transport::BoxFuture<
            '_,
            Result<Box<dyn crate::websocket::WebSocketConnection>, crate::TransportError>,
        > {
            let name = match request.url.as_str() {
                crate::protocol::MEMPOOL_WEBSOCKET_URL => "mempool",
                "ws://192.168.1.10:3006/api/v1/ws" => "node",
                other => panic!("not an explorer's WebSocket of the case: {other}"),
            };
            self.asked.lock().unwrap().push(name.to_owned());
            let answers = answers(self.case, name);
            if answers {
                *self.connected.lock().unwrap() = Some(name);
            }
            Box::pin(async move {
                if answers {
                    Ok(Box::new(Answering(false)) as Box<dyn crate::websocket::WebSocketConnection>)
                } else {
                    Err(crate::TransportError::new("refused"))
                }
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_websocket_s_connection() {
        for case in vectors().list("reads") {
            let sockets = Sockets { case, asked: Mutex::new(Vec::new()), connected: Mutex::new(None) };
            let explorer = explorer_of(case);
            let (changes, _heard) = tokio::sync::mpsc::unbounded_channel();
            let address = deposit_address(1);
            let watching = crate::onchain::watch::watch_address(&sockets, &explorer, &address, changes);
            // As long as it runs at this instant: a failure waits a second before it connects again.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(1), watching).await;
            let connected = *sockets.connected.lock().unwrap();
            let actual =
                outcome(&sockets.asked.lock().unwrap(), connected.ok_or_else(|| Error::network("none")));
            if let Err(problem) = expect_same(&actual.unwrap(), case.field("expected")) {
                panic!("bitcoin-nodes.json reads, WebSocket: {}: {problem}", case.name());
            }
        }
    }
}

#[test]
fn records() {
    every_case("bitcoin-nodes.json records", vectors().list("records"), |case| {
        // Valid in every case: a node set aside leaves the record valid.
        match parse_checkout_value(case.field("value")) {
            Ok(Some(record)) => {
                expect_same(&record_node_json(record.bitcoin_node.as_ref()), case.field("expected"))
            }
            other => Err(format!("a valid record: {other:?}")),
        }
    });
}

#[test]
fn writes() {
    let app = spec("vectors/app/app.json");
    let invoice = app.field("realInvoice").text("invoice").to_owned();
    every_case("bitcoin-nodes.json writes", vectors().list("writes"), |case| {
        // The channel create_invoice read, then the record of its checkout link.
        let Channel::Active(channel) = channel_with(case.get("channel")) else {
            return Err("the channel is active".to_owned());
        };
        let address = case.field("address").as_bool().expect("a boolean");
        let value = CheckoutValue {
            business_name: "Sunrise Bakery".to_owned(),
            invoice: (!address).then(|| invoice.clone()),
            verify_url: (!address).then(|| "https://breez.tips/lnurlp/verify/x".to_owned()),
            onchain_address: address.then(|| deposit_address(1)),
            sats: 150_000_000,
            created_at: 1_791_381_280,
            expires_at: 1_791_382_180,
            fiat: None,
            note: "Order 1042".to_owned(),
            redirect_url: None,
            rest: None,
            bitcoin_node: if address { record_node_for(channel.bitcoin_node.as_ref()) } else { None },
        };
        let record = value.to_json();
        if record.field("version").as_f64() != Some(if address { 2.0 } else { 1.0 }) {
            return Err("the record's version".to_owned());
        }
        // Absent, never null, when it has none.
        if record.has("bitcoinNode") == case.field("expected").is_null() {
            return Err("bitcoinNode present or absent".to_owned());
        }
        expect_same(record.get("bitcoinNode").unwrap_or(&Json::Null), case.field("expected"))
    });
}

#[test]
fn leaves_every_other_url_to_its_own_rule_no_http_no_ip_address() {
    // The node URLs only the node's rule allows: http, or an IPv4 host (SPEC.md §15, §9, §30).
    let vectors = vectors();
    let node_only: Vec<String> = vectors
        .list("urls")
        .iter()
        .filter(|case| !case.field("expected").is_null())
        .map(|case| case.text("url").to_owned())
        .filter(|url| {
            let host = url.strip_prefix("https://").unwrap_or_default();
            url.starts_with("http://")
                || host.split([':', '/']).next().is_some_and(|host| {
                    !host.is_empty() && host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
                })
        })
        .collect();
    assert!(node_only.len() > 15, "{node_only:?}");
    for url in &node_only {
        // An https URL (a pay request's callback, a verify URL, a redirect URL), a checkout origin,
        // a relay: refused.
        assert_eq!(parse_https_url(url), None, "{url}");
        assert!(!is_checkout_origin(url), "{url}");
        assert!(!is_relay_url(&format!("ws{}", &url["http".len()..])), "{url}");
        // An IP address is never a relay's host, nor a Lightning address's.
        let host = url.split("://").nth(1).unwrap().split([':', '/']).next().unwrap();
        if host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') {
            assert!(!is_relay_url(&format!("wss://{host}")), "{url}");
            assert_eq!(lightning_address_url(&format!("sattleme@{host}")), None, "{url}");
        }
    }
}
