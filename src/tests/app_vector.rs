//! The crate's half of the cross-check with the merchant's app (vectors/app/
//! implementation-declaration.json): the declaration another implementation made, end to end,
//! with the integration key and the registry of vectors/app/app.json, opens as the app's sale
//! ORD-2001 opens it; and a declaration this crate makes, end to end (`create_invoice`), for the
//! same order (same reference, invoice, verify URL, price, note and `created_at`) is a valid
//! record of the sale with the vector's `d` tag, opening into exactly the same declaration.

use super::declaration::event_of;
use super::support::merchant::{MadeInvoice, TestMerchant};
use super::support::random::FixedRandom;
use super::support::rates::price;
use super::support::vectors::{Field, assert_same, spec};
use crate::declaration::{open_declaration, registry_of};
use crate::derive::{Sale, registry_address, sale_keys, sale_of, taker_key, taker_tag};
use crate::json::{self, Json};
use crate::key::parse_integration_key;
use crate::nostr::event::{Event, valid_event};
use crate::nostr::nip44::decrypt;
use crate::nostr::record::Opened;
use crate::order::Order;

fn vector() -> Json {
    spec("vectors/app/implementation-declaration.json")
}

fn app() -> Json {
    spec("vectors/app/app.json")
}

fn sale(app: &Json, reference: &str) -> Sale {
    let key = parse_integration_key(app.text("secretKey")).unwrap().key;
    let channel = app.field("channel").field("value").field("v");
    sale_of(&key, &registry_of(channel.text("registryKey"), channel.text("registryReader")), reference)
}

/// The inside of a declaration opened as its sale opens it: the outer key of its address and
/// author, then its inner conversation key.
fn inside_of(event: &Event, sale: &Sale) -> String {
    let address = event.tag("d").unwrap();
    let outer = crate::derive::outer_key(&sale.registry.key, address, &sale.author);
    let outside = decrypt(&event.content, &outer).unwrap();
    assert_eq!(outside.len() % 256, 0);
    let envelope = json::parse(&outside).unwrap();
    assert_eq!(envelope.get("t").and_then(Json::as_str), Some("registry-declaration"));
    let sealed = envelope.get("v").and_then(|v| v.get("sealed")).and_then(Json::as_str).unwrap();
    decrypt(sealed, &sale.inner_key).unwrap()
}

#[test]
fn opens_the_declaration_of_another_implementation_as_the_sale_of_ord_2001() {
    let vector = vector();
    let app = app();
    let sale = sale(&app, vector.text("ref"));
    let key = parse_integration_key(app.text("secretKey")).unwrap().key;
    assert_eq!(sale.author, vector.text("saleAuthor"));
    assert_eq!(taker_tag(&taker_key(&key), &sale.author), vector.text("taker"));
    assert_eq!(sale_keys(&key, vector.text("ref")).author, vector.text("saleAuthor"));
    let event = event_of(vector.field("event"));
    assert_eq!(event.pubkey, vector.text("saleAuthor"));
    // The payment of the app's declaration: the same registry address, another sale (a conflict).
    let address = registry_address(&sale.registry.key, vector.text("paymentHash"));
    assert_eq!(event.tags, vec![vec!["d".to_owned(), address.clone()]]);
    assert_eq!(address, app.field("declaration").text("address"));
    assert_eq!(vector.text("paymentHash"), app.field("declaration").text("paymentHash"));
    let Some(Opened::Valid { value: opened, .. }) = open_declaration(&event, &sale) else {
        panic!("the sale opens it")
    };
    assert_eq!(opened.invoice, vector.text("invoice"));
    assert_eq!(opened.decoded.payment_hash, vector.text("paymentHash"));
    assert_eq!(opened.verify_url, vector.text("verifyUrl"));
    assert_eq!(opened.sats.to_string(), vector.text("sats"));
    assert_same(&opened.price.to_json(), vector.field("fiat"), "the price");
    assert_eq!(opened.note, vector.text("note"));
    assert_eq!(opened.declared_at, event.created_at);
    assert!(opened.rest.is_none());
    let inside = json::parse(&inside_of(&event, &sale)).unwrap();
    assert_same(
        &inside,
        &Json::object([
            ("version", Json::unsigned(1)),
            ("invoice", Json::from(vector.text("invoice"))),
            ("verifyUrl", Json::from(vector.text("verifyUrl"))),
            (
                "sale",
                Json::object([
                    ("key", Json::from(crate::text::to_hex(sale.key.expose()).as_str())),
                    ("fiat", vector.field("fiat").clone()),
                    ("note", Json::from(vector.text("note"))),
                ]),
            ),
            ("taker", Json::from(vector.text("taker"))),
        ]),
        "the inside",
    );
    // The app's own sale of ORD-1042 does not open it.
    assert!(open_declaration(&event, &self::sale(&app, "ORD-1042")).is_none());
}

#[tokio::test(start_paused = true)]
async fn makes_the_same_declaration_end_to_end() {
    let vector = vector();
    let app = app();
    let mut merchant = TestMerchant::new();
    merchant.key_relays = app.field("parsed").texts("relays");
    let merchant = merchant.start();
    merchant.set_now(vector.field("event").int("created_at"));
    merchant.net.get("wss://relay.example").store(app.field("channel").field("event").clone());
    // breez.tips answers the invoice of the vector: of the same payment as the app's declaration.
    let (invoice, verify, hash) = (
        vector.text("invoice").to_owned(),
        vector.text("verifyUrl").to_owned(),
        vector.text("paymentHash").to_owned(),
    );
    merchant.set_tamper(Some(move |made: MadeInvoice| MadeInvoice {
        pr: invoice.clone(),
        verify: verify.clone(),
        payment_hash: hash.clone(),
        ..made
    }));
    let client = crate::client::Client::builder(app.text("secretKey"))
        .http_client(merchant.http.clone())
        .websocket_client(merchant.net.clone())
        .clock(merchant.clock.clone())
        .relay_timeout_ms(1000)
        .logger(super::support::merchant::Quiet)
        .rate_source(price("99000"))
        .random(FixedRandom::new("app-vector"))
        .build()
        .unwrap();
    let order =
        Order::fiat(vector.text("ref"), "0.02", "CHF").note(vector.text("note")).duration_seconds(600);
    let made = client.create_invoice(&order).await.unwrap();
    // 0.02 CHF at 99 000 CHF/BTC: ⌈2 × 10^8 / 9 900 000⌉ = ⌈20.2…⌉ = 21 sats.
    assert_eq!(made.sats.to_string(), vector.text("sats"));
    assert_eq!(made.bolt11.as_deref(), Some(vector.text("invoice")));
    let received = merchant.net.get("wss://relay.example").received();
    assert_eq!(received.len(), 1);
    let event = &received[0];
    assert!(valid_event(&event.to_json()).is_some());
    assert_eq!(event.kind, 30078.0);
    assert_eq!(event.pubkey, vector.text("saleAuthor"));
    assert_eq!(event.created_at, vector.field("event").int("created_at"));
    assert_eq!(event.tags, event_of(vector.field("event")).tags);
    let sale = sale(&app, vector.text("ref"));
    // Exactly the declaration of the vector, opened the same way.
    let ours = inside_of(event, &sale);
    let theirs = inside_of(&event_of(vector.field("event")), &sale);
    assert_same(&json::parse(&ours).unwrap(), &json::parse(&theirs).unwrap(), "the inside");
    assert_eq!(ours, theirs);
}
