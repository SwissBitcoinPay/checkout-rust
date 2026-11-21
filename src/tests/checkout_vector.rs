//! The crate's half of the cross-check with the merchant's web app for checkout links
//! (vectors/app/checkout-link.json, PORTING.md "Definition of done", 3): a link the crate makes,
//! end to end (`create_invoice` with a checkout link), for the order of the vector (same channel
//! origin, relays, business's name, pay request, price, invoice and verify URL) holds exactly the
//! vector's `value`, in a valid record signed by its own author, with the tags of SPEC.md §30,
//! whose content opens with the encryption key its URL's link key derives.

use super::support::j;
use super::support::merchant::{MadeInvoice, TestMerchant};
use super::support::random::FixedRandom;
use super::support::rates::price;
use super::support::vectors::{Field, assert_same, spec};
use crate::checkout::{CheckoutFragment, checkout_keys, parse_checkout_fragment, parse_checkout_value};
use crate::json::{self, Json};
use crate::nostr::event::valid_event;
use crate::nostr::nip44::decrypt;
use crate::order::Order;
use crate::text::to_hex;

/// What a link's record opens to with its link key: its type, its value, and its plaintext's
/// length in bytes.
pub(crate) fn open_link(content: &str, link_key: &crate::secret::Secret) -> (String, Json, usize) {
    let keys = checkout_keys(link_key);
    let plaintext = decrypt(content, &keys.encryption_key).expect("the record opens with the link's key");
    let envelope = json::parse(&plaintext).expect("JSON");
    let record_type = envelope.get("t").and_then(Json::as_str).expect("a type").to_owned();
    (record_type, envelope.get("v").cloned().expect("a value"), plaintext.len())
}

#[tokio::test(start_paused = true)]
async fn makes_a_link_holding_exactly_the_vector_value() {
    let vector = spec("vectors/app/checkout-link.json");
    let order = vector.field("order");
    let mut merchant = TestMerchant::new();
    merchant.key_relays = vector.texts("relays");
    let merchant = merchant.start();
    let created_at = vector.field("event").int("created_at");
    merchant.set_now(created_at);
    // What the merchant's Lightning address answers (SPEC.md §16): its bounds, its metadata.
    merchant.set_pay(vector.field("payRequest").clone());
    merchant.publish_channel(
        &merchant.channel_value(
            created_at - 60,
            Json::object([("checkout", Json::object([("origin", Json::from(vector.text("origin")))]))]),
        ),
        created_at - 60,
    );
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
    let client = merchant
        .client()
        .rate_source(price(vector.text("price")))
        .random(FixedRandom::new("checkout-vector"))
        .build()
        .unwrap();
    let fiat = order.field("fiat");
    let made = client
        .create_invoice(
            &Order::fiat(order.text("ref"), fiat.text("amount"), fiat.text("currency"))
                .note(order.text("note"))
                .duration_seconds(order.int("durationSeconds") as u64)
                .checkout(true)
                .redirect_url(order.text("redirectUrl")),
        )
        .await
        .unwrap();
    // 0.02 CHF at 98 000 CHF/BTC: ⌈2 × 10^8 / 9 800 000⌉ = ⌈20.4…⌉ = 21 sats.
    assert_eq!(made.sats.to_string(), vector.text("sats"));
    assert_eq!(made.expires_at, vector.int("expiresAt"));
    assert_eq!(made.bolt11.as_deref(), Some(vector.text("invoice")));

    // The URL: <origin>/pay#c.<author>.<key>.<relays>.
    let url = made.checkout_url.expect("a checkout link");
    let prefix = format!("{}/pay#c.", vector.text("origin"));
    assert!(url.starts_with(&prefix), "{url}");
    let parts: Vec<&str> = url[prefix.len()..].split('.').collect();
    assert_eq!(parts.len(), 3, "{url}");
    assert_eq!(parts[2], vector.text("url").rsplit('.').next().unwrap(), "the relays part");
    let CheckoutFragment::Link { author, link_key, relays } =
        parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("a checkout link: {url}")
    };
    assert_eq!(relays, vector.texts("relays"));

    // Its record: signed by its own author, at the link's address, until a week after its end.
    let keys = checkout_keys(&link_key);
    let received = merchant.net.get("wss://relay.example").received();
    let event = received.iter().find(|event| event.pubkey == author).expect("the link's record");
    assert!(valid_event(&event.to_json()).is_some());
    assert_eq!(event.kind, 30078.0);
    assert_eq!(event.created_at, created_at);
    assert_eq!(
        event.tags,
        vec![
            vec!["d".to_owned(), keys.address.clone()],
            vec!["expiration".to_owned(), (vector.int("expiresAt") + 604_800).to_string()]
        ]
    );
    let (record_type, value, length) = open_link(&event.content, &link_key);
    assert_eq!(record_type, "checkout");
    assert_eq!(length % 256, 0);
    // Exactly the vector's value.
    assert_same(&value, vector.field("value"), "the link's value");
    let record = parse_checkout_value(&value).unwrap().unwrap();
    assert_eq!(record.sats, 21);
    assert_eq!(record.redirect_shown.as_deref(), Some("shop.example"));
    // Published before the declaration (SPEC.md §30): the record first, then the sale's event.
    let position = |pubkey: &str| received.iter().position(|event| event.pubkey == pubkey).unwrap();
    let sale = crate::derive::sale_keys(&merchant.integration_key, order.text("ref")).author;
    assert!(position(&author) < position(&sale));
}

#[test]
fn opens_the_vector_link_as_the_web_app_does() {
    let vector = spec("vectors/app/checkout-link.json");
    let url = vector.text("url");
    let CheckoutFragment::Link { author, link_key, relays } =
        parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("a checkout link")
    };
    assert_eq!(author, vector.text("author"));
    assert_eq!(to_hex(link_key.expose()), vector.text("linkKey"));
    assert_eq!(relays, vector.texts("relays"));
    let keys = checkout_keys(&link_key);
    assert_eq!(keys.address, vector.text("address"));
    assert_eq!(to_hex(keys.encryption_key.expose()), vector.text("encryptionKey"));
    let event = valid_event(vector.field("event")).expect("a valid event");
    assert_eq!(event.pubkey, author);
    let (record_type, value, length) = open_link(&event.content, &link_key);
    assert_eq!((record_type.as_str(), length % 256), ("checkout", 0));
    assert_same(&value, vector.field("value"), "the value");
    let record = parse_checkout_value(&value).unwrap().unwrap();
    assert_eq!(record.payment_hash.as_deref(), Some(vector.text("paymentHash")));
    assert_eq!(record.expires_at, vector.int("expiresAt"));
    assert_eq!(record.redirect_shown.as_deref(), Some("shop.example"));
    assert_same(
        &record.fiat.unwrap().to_json(),
        &j!({ "minor": 2, "digits": 2, "currency": "CHF" }),
        "the price",
    );
}
