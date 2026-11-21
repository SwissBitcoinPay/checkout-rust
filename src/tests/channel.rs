//! Reading the integration's channel (SPEC.md §14) on local relays.

use std::collections::HashMap;

use tokio::time::Instant;

use super::support::j;
use super::support::merchant::{Quiet, TestMerchant, Warnings};
use super::support::random::bytes;
use super::support::relay::{RelayBehaviour, RelayNet, pool};
use super::support::vectors::{Field, spec};
use crate::channel::{ChannelRead, read_channel};
use crate::error::{Error, ErrorCode};
use crate::json::Json;
use crate::key::{IntegrationKey, parse_integration_key};
use crate::runtime::{Logger, OsRandom};
use crate::secret::Secret;

/// The channel read over a pool of its own, closed once it is done.
async fn read_on(
    net: &RelayNet,
    access: &IntegrationKey,
    timeout_ms: u64,
    logger: &dyn Logger,
) -> Result<ChannelRead, Error> {
    let pool = pool(net, timeout_ms);
    read_channel(&pool, access, &OsRandom, logger).await
}

async fn read(merchant: &TestMerchant) -> Result<ChannelRead, Error> {
    read_on(&merchant.net, &parse_integration_key(&merchant.key()).unwrap(), 2000, &Quiet).await
}

fn code(result: Result<ChannelRead, Error>) -> ErrorCode {
    result.expect_err("an error").code()
}

#[tokio::test(start_paused = true)]
async fn reads_the_channel_of_the_app_vectors_with_its_key_alone() {
    let app = spec("vectors/app/app.json");
    let net = RelayNet::default();
    let relay = net.add("wss://relay.example", RelayBehaviour::default());
    relay.store(app.field("channel").field("event").clone());
    let read =
        read_on(&net, &parse_integration_key(app.text("secretKey")).unwrap(), 2000, &Quiet).await.unwrap();
    assert_eq!(read.channel.business_name, "Sunrise Bakery");
    assert_eq!(read.channel.lightning_address, "sattleme02c6047f94@breez.tips");
    assert_eq!(read.channel.registry_key, app.field("channel").field("value").field("v").text("registryKey"));
    assert_eq!(read.relays, vec!["wss://relay.example".to_owned()]);
    // Its debug representation holds neither the registry key nor the Lightning address.
    let shown = format!("{read:?}");
    assert!(shown.contains("Sunrise Bakery"), "{shown}");
    assert!(!shown.contains(&read.channel.registry_key) && !shown.contains("breez.tips"), "{shown}");
    let expected = j!({
        "kinds": [30078],
        "authors": [app.field("parsed").text("team")],
        "#d": [app.field("derived").text("channelAddress")]
    });
    let queries = relay.queries();
    assert_eq!(queries.len(), 1);
    super::support::vectors::assert_same(&queries[0], &expected, "the query");
}

#[tokio::test(start_paused = true)]
async fn keeps_the_newest_copy_and_ignores_one_signed_by_another_key() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    merchant.publish_channel_on(
        &merchant.channel_value(
            200,
            j!({ "profile": { "businessName": "Old", "lightningAddress": "a@b.test", "currency": "CHF" } }),
        ),
        200,
        // On a majority, as the app publishes it: any majority that answers holds it.
        &["wss://relay-a.test".to_owned(), "wss://relay-b.test".to_owned()],
        None,
    );
    // Newer, but by another author: whoever saw the address could publish there.
    merchant.publish_channel_on(
        &merchant.channel_value(300, j!({ "status": "removed" })),
        300,
        &merchant.key_relays,
        Some(&Secret::new(bytes(66))),
    );
    let read = read(&merchant).await.unwrap();
    assert_eq!(read.channel.business_name, "Old");
    assert_eq!(read.channel.updated_at, 200);
}

#[tokio::test(start_paused = true)]
async fn ignores_a_copy_whose_updated_at_is_not_its_date_or_that_is_damaged() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    merchant.publish_channel(&merchant.channel_value(150, j!({})), 200);
    let relay = merchant.net.get("wss://relay-b.test");
    let good = merchant.channel_event(&merchant.channel_value(300, j!({})), 300, None);
    let mut damaged = good.clone();
    damaged.content = format!("B{}", &good.content[1..]);
    relay.store_event(&damaged);
    let mut unsigned = good;
    unsigned.sig = "00".repeat(64);
    relay.store_event(&unsigned);
    assert_eq!(read(&merchant).await.unwrap().channel.updated_at, 100);
}

#[tokio::test(start_paused = true)]
async fn ignores_a_channel_whose_lightning_address_is_on_an_ip_address_or_under_localhost() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    for (at, changed) in [
        (
            200,
            j!({ "businessName": "Sunrise Bakery", "lightningAddress": "shop@10.0.0.1", "currency": "CHF" }),
        ),
        (
            201,
            j!({ "businessName": "Sunrise Bakery", "lightningAddress": "shop@pay.localhost", "currency": "CHF" }),
        ),
    ] {
        let value = merchant.channel_value(at, Json::object([("profile", changed)]));
        merchant.publish_channel(&value, at);
    }
    // A business name holding a lone surrogate: only a JSON escape writes one.
    let text = crate::json::stringify(&merchant.channel_value(202, j!({})))
        .replace("\"Sunrise Bakery\"", r#""Sunrise \ud800""#);
    merchant.publish_channel(&crate::json::parse(&text).unwrap(), 202);
    assert_eq!(read(&merchant).await.unwrap().channel.updated_at, 100);
}

#[tokio::test(start_paused = true)]
async fn fails_revoked_when_the_integration_was_removed() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    merchant.publish_channel(&j!({ "version": 1, "status": "removed", "updatedAt": 200 }), 200);
    assert_eq!(code(read(&merchant).await), ErrorCode::Revoked);
}

#[tokio::test(start_paused = true)]
async fn warns_of_a_newer_format_and_ignores_it() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    merchant.publish_channel(&merchant.channel_value(200, j!({ "version": 2 })), 200);
    let warnings = Warnings::default();
    let read = read_on(&merchant.net, &parse_integration_key(&merchant.key()).unwrap(), 2000, &warnings)
        .await
        .unwrap();
    assert_eq!(read.channel.updated_at, 100);
    assert_eq!(warnings.all().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn follows_the_account_relays_where_the_channel_moved_3_times_at_most() {
    let merchant = TestMerchant::new();
    let lists: Vec<Vec<String>> = vec![
        merchant.key_relays.clone(),
        vec!["wss://second.test".to_owned()],
        vec!["wss://third.test".to_owned(), "wss://third-b.test".to_owned()],
        vec!["wss://fourth.test".to_owned()],
        vec!["wss://fifth.test".to_owned()],
    ];
    let others: Vec<&str> = lists[1..].iter().flatten().map(String::as_str).collect();
    let merchant = merchant.start_with(&others, HashMap::new());
    for (i, list) in lists.iter().enumerate() {
        let next = lists.get(i + 1).unwrap_or(list);
        let at = 100 + i as i64;
        let value = merchant.channel_value(
            at,
            j!({
                "relays": next,
                "profile": { "businessName": format!("List {i}"), "lightningAddress": "sattleme02c6047f94@breez.tips", "currency": "CHF" }
            }),
        );
        merchant.publish_channel_on(&value, at, list, None);
    }
    let read = read(&merchant).await.unwrap();
    assert_eq!(read.channel.business_name, "List 3");
    assert_eq!(read.relays, vec!["wss://fourth.test".to_owned()]);
    assert_eq!(merchant.net.connections("wss://fifth.test"), 0);
}

#[tokio::test(start_paused = true)]
async fn sees_a_removal_on_the_list_the_channel_moved_to() {
    let merchant = TestMerchant::new().start_with(&["wss://new.test"], HashMap::new());
    merchant.publish_channel(&merchant.channel_value(100, j!({ "relays": ["wss://new.test"] })), 100);
    merchant.publish_channel_on(
        &j!({ "version": 1, "status": "removed", "updatedAt": 200 }),
        200,
        &["wss://new.test".to_owned()],
        None,
    );
    assert_eq!(code(read(&merchant).await), ErrorCode::Revoked);
}

#[tokio::test(start_paused = true)]
async fn fails_network_when_the_list_the_channel_moved_to_does_not_answer() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({ "relays": ["wss://gone.test"] })), 100);
    assert_eq!(code(read(&merchant).await), ErrorCode::Network);
}

#[tokio::test(start_paused = true)]
async fn fails_channel_not_found_when_the_relays_answer_without_it() {
    let merchant = TestMerchant::new().start();
    let error = read(&merchant).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::ChannelNotFound);
    assert!(!error.newer_format());
}

#[tokio::test(start_paused = true)]
async fn goes_on_once_a_majority_answered_past_a_silent_relay_and_one_asking_to_authenticate() {
    let merchant = TestMerchant::new().start_with(
        &[],
        HashMap::from([
            ("wss://relay-a.test", RelayBehaviour::mute()),
            ("wss://relay-b.test", RelayBehaviour { require_auth: true, ..RelayBehaviour::default() }),
        ]),
    );
    merchant.publish_channel_on(
        &merchant.channel_value(100, j!({})),
        100,
        &["wss://relay-b.test".to_owned()],
        None,
    );
    let started = Instant::now();
    // relay-b and relay-c are a majority: the silent relay's 5 s are not waited for.
    let read =
        read_on(&merchant.net, &parse_integration_key(&merchant.key()).unwrap(), 5000, &Quiet).await.unwrap();
    assert!(started.elapsed().as_millis() < 1000);
    assert_eq!(read.channel.updated_at, 100);
    // A key of this read alone: never the team's nor a sale's.
    let authenticated = merchant.net.get("wss://relay-b.test").authenticated();
    assert_eq!(authenticated.len(), 1);
    assert_ne!(authenticated[0], merchant.team);
}

#[tokio::test(start_paused = true)]
async fn leaves_a_relay_that_never_completes_the_handshake() {
    let merchant = TestMerchant::new().start();
    merchant.net.add_blackhole("wss://hole.test");
    merchant.publish_channel_on(
        &merchant.channel_value(100, j!({})),
        100,
        &["wss://relay-b.test".to_owned()],
        None,
    );
    let access = parse_integration_key(&merchant.key()).unwrap();
    let on = |list: &[&str]| IntegrationKey {
        team: access.team.clone(),
        key: Secret::new(*access.key.expose()),
        relays: list.iter().map(|relay| (*relay).to_owned()).collect(),
    };
    // Read on the two others, a majority of three; the hole's connection dropped meanwhile.
    let read = read_on(
        &merchant.net,
        &on(&["wss://hole.test", "wss://relay-b.test", "wss://relay-c.test"]),
        300,
        &Quiet,
    )
    .await;
    assert_eq!(read.unwrap().channel.updated_at, 100);
    // One of two is no majority: no answer is no absence.
    let read = read_on(&merchant.net, &on(&["wss://hole.test", "wss://relay-b.test"]), 300, &Quiet).await;
    assert_eq!(code(read), ErrorCode::Network);
}

#[tokio::test(start_paused = true)]
async fn fails_network_not_an_absence_when_no_relay_answers() {
    let merchant =
        TestMerchant::new().start_with(&[], HashMap::from([("wss://relay-a.test", RelayBehaviour::mute())]));
    merchant.net.remove("wss://relay-b.test");
    merchant.net.remove("wss://relay-c.test");
    let started = Instant::now();
    let read = read_on(&merchant.net, &parse_integration_key(&merchant.key()).unwrap(), 300, &Quiet).await;
    assert_eq!(code(read), ErrorCode::Network);
    assert!(started.elapsed().as_millis() < 2000);
}

#[tokio::test(start_paused = true)]
async fn reads_the_merchant_at_every_call_as_json_and_keeps_nothing_open() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    let client = merchant.client().build().unwrap();
    let found = client.merchant().await.unwrap();
    let json = serde_json::to_value(&found).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "businessName": "Sunrise Bakery",
            "minSats": "1",
            "maxSats": "100000000",
            // No lot of addresses yet: no on-chain payment.
            "onchainAddresses": 0
        })
    );
    assert_eq!(serde_json::from_value::<crate::model::Merchant>(json).unwrap(), found);
    // Nothing kept: a removal stops the very next call.
    merchant.publish_channel(&j!({ "version": 1, "status": "removed", "updatedAt": 200 }), 200);
    assert_eq!(client.merchant().await.unwrap_err().code(), ErrorCode::Revoked);
    assert_eq!(merchant.net.connections("wss://relay-a.test"), 2);
    tokio::task::yield_now().await;
    for url in &merchant.key_relays {
        assert_eq!(merchant.net.get(url).open_connections(), 0, "{url}");
    }
}
