//! The crate's half of the cross-check with the merchant's web app for the rest of an on-chain
//! underpayment (vectors/app/checkout-rest.json): a checkout link to an invoice with an address
//! (`create_invoice` with a checkout link), then a payment check that sees 20 000 of its 49 000
//! sats on-chain and asks an invoice of the rest, end to end. Every deterministic value is the
//! vector's (the rest key, author and encryption key, the rest record's address, the link's value
//! with its rest author and key, the rest record's value); the events are valid and open.

use super::checkout_vector::open_link;
use super::support::chain::{deposit_address, payment, txid};
use super::support::merchant::{MadeInvoice, TestMerchant};
use super::support::random::FixedRandom;
use super::support::vectors::{Field, assert_same, spec};
use crate::checkout::{CheckoutFragment, checkout_keys, parse_checkout_fragment, parse_checkout_value};
use crate::derive::{rest_keys, rest_record_address};
use crate::json::{self, Json};
use crate::model::PaymentStatus;
use crate::nostr::event::valid_event;
use crate::nostr::nip44::decrypt;
use crate::onchain::rest::{RestLinkTerms, RestReaderKeys, open_rest_event};
use crate::order::Order;
use crate::text::to_hex;

#[tokio::test(start_paused = true)]
async fn makes_the_link_and_the_rest_record_of_the_vector() {
    let vector = spec("vectors/app/checkout-rest.json");
    let order = vector.field("order");
    let address = deposit_address("checkout-rest");
    assert_eq!(address, vector.text("onchainAddress"));
    let mut merchant = TestMerchant::new();
    merchant.key_relays = vector.texts("relays");
    let merchant = merchant.start();
    assert_eq!(to_hex(merchant.integration_key.expose()), vector.text("integrationKey"));
    let created_at = vector.int("createdAt");
    merchant.set_now(created_at);
    merchant.set_pay(vector.field("payRequest").clone());
    merchant.publish_channel(
        &merchant.channel_value(
            created_at - 60,
            Json::object([("checkout", Json::object([("origin", Json::from(vector.text("origin")))]))]),
        ),
        created_at - 60,
    );
    merchant.publish_lot(std::slice::from_ref(&address), created_at - 30);
    // breez.tips answers the vector's invoices: the order's, then its rest's.
    let link_value = vector.field("link").field("value").clone();
    let rest = vector.field("rest").clone();
    let (order_invoice, order_verify) =
        (link_value.text("invoice").to_owned(), link_value.text("verifyUrl").to_owned());
    let (rest_invoice, rest_verify, rest_hash) = (
        rest.text("invoice").to_owned(),
        rest.text("verifyUrl").to_owned(),
        rest.text("paymentHash").to_owned(),
    );
    merchant.set_tamper(Some(move |made: MadeInvoice| {
        if made.amount_msat == 49_000_000 {
            let hash = crate::lightning::bolt11::decode(&order_invoice).unwrap().payment_hash;
            MadeInvoice {
                pr: order_invoice.clone(),
                verify: order_verify.clone(),
                payment_hash: hash,
                ..made
            }
        } else {
            MadeInvoice {
                pr: rest_invoice.clone(),
                verify: rest_verify.clone(),
                payment_hash: rest_hash.clone(),
                ..made
            }
        }
    }));
    let client = merchant.client().random(FixedRandom::new("checkout-rest-vector")).build().unwrap();
    let invoice = client
        .create_invoice(
            &Order::sats(order.text("ref"), order.digits("sats"))
                .note(order.text("note"))
                .duration_seconds(order.int("durationSeconds") as u64)
                .checkout(true)
                .redirect_url(order.text("redirectUrl")),
        )
        .await
        .unwrap();
    assert_eq!(invoice.onchain_address.as_deref(), Some(address.as_str()));
    assert_eq!(invoice.sats.to_string(), vector.text("sats"));
    assert_eq!((invoice.created_at, invoice.expires_at), (created_at, vector.int("expiresAt")));

    // The link: its record holds exactly the vector's value, its rest author and key included.
    let url = invoice.checkout_url.clone().unwrap();
    let CheckoutFragment::Link { author, link_key, .. } =
        parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("a link")
    };
    let relay = merchant.net.get("wss://relay.example");
    let link_event =
        relay.received().into_iter().find(|event| event.pubkey == author).expect("the link's record");
    assert!(valid_event(&link_event.to_json()).is_some());
    assert_eq!(link_event.tags[0], vec!["d".to_owned(), checkout_keys(&link_key).address]);
    let (record_type, value, length) = open_link(&link_event.content, &link_key);
    assert_eq!((record_type.as_str(), length % 256), ("checkout", 0));
    assert_same(&value, &link_value, "the link's value");
    let record = parse_checkout_value(&value).unwrap().unwrap();
    let reader = record.rest.expect("the rest reader");
    assert_eq!(
        (reader.author.as_str(), reader.key.as_str()),
        (rest.text("restAuthor"), rest.text("restKey"))
    );

    // 20 000 sats in the mempool, a minute later: the check asks an invoice of the 29 000 left.
    merchant.advance(60);
    let transaction = vector.field("transaction");
    let tx = payment(&txid("checkout-rest"), &address, 20_000);
    assert_eq!(tx.txid, transaction.text("txid"));
    merchant.chain.add(&address, tx);
    let status = client.get_status(&invoice).await.unwrap();
    assert_eq!(serde_json::to_value(&status).unwrap(), serde_json::to_value(vector.field("status")).unwrap());
    let PaymentStatus::Open { rest: Some(asked), .. } = &status else {
        panic!("open, with a rest: {status:?}")
    };
    assert_eq!(asked.bolt11.as_deref(), Some(rest.text("invoice")));
    assert_eq!(
        asked.payment_uri,
        Some(format!("bitcoin:{address}?amount=0.00029&lightning={}", rest.text("invoice")))
    );

    // The rest keys, the rest record's address and value: the vector's.
    let keys = rest_keys(&merchant.integration_key, order.text("ref"), &address, invoice.expires_at);
    assert_eq!(to_hex(keys.key.expose()), rest.text("restKey"));
    assert_eq!(keys.author, rest.text("restAuthor"));
    assert_eq!(to_hex(keys.encryption_key.expose()), rest.text("encryptionKey"));
    assert_eq!(rest_record_address(&keys.key, rest.text("paymentHash")), rest.text("address"));
    let rest_event =
        relay.received().into_iter().find(|event| event.pubkey == keys.author).expect("the rest record");
    assert!(valid_event(&rest_event.to_json()).is_some());
    assert_eq!(rest_event.created_at, rest.field("event").int("created_at"));
    assert_eq!(
        rest_event.tags,
        vec![
            vec!["d".to_owned(), rest.text("address").to_owned()],
            vec!["expiration".to_owned(), (invoice.expires_at + 604_800).to_string()]
        ]
    );
    let plaintext = decrypt(&rest_event.content, &keys.encryption_key).unwrap();
    assert_eq!(plaintext.len() % 256, 0);
    let envelope = json::parse(&plaintext).unwrap();
    assert_same(envelope.get("v").unwrap(), rest.field("value"), "the rest record's value");
    // As the page opens it, with what the link carries.
    let terms =
        RestLinkTerms { sats: invoice.sats, created_at: invoice.created_at, expires_at: invoice.expires_at };
    let reader_keys = RestReaderKeys::new(
        crate::secret::Secret::new(crate::text::from_hex32(&reader.key).unwrap()),
        reader.author.clone(),
    );
    let opened = open_rest_event(&rest_event, &reader_keys, &terms).unwrap().unwrap();
    assert_eq!((opened.bolt11.as_str(), opened.sats), (rest.text("invoice"), 29_000));
}

#[test]
fn opens_the_vector_events_as_the_web_app_does() {
    let vector = spec("vectors/app/checkout-rest.json");
    let link = vector.field("link");
    let rest = vector.field("rest");
    let url = link.text("url");
    let CheckoutFragment::Link { author, link_key, relays } =
        parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("a link")
    };
    assert_eq!(
        (author.as_str(), to_hex(link_key.expose())),
        (link.text("author"), link.text("linkKey").to_owned())
    );
    assert_eq!(relays, vector.texts("relays"));
    let keys = checkout_keys(&link_key);
    assert_eq!(
        (keys.address.as_str(), to_hex(keys.encryption_key.expose())),
        (link.text("address"), link.text("encryptionKey").to_owned())
    );
    let link_event = valid_event(link.field("event")).unwrap();
    let (_, value, _) = open_link(&link_event.content, &link_key);
    assert_same(&value, link.field("value"), "the link's value");
    let record = parse_checkout_value(&value).unwrap().unwrap();
    let reader = record.rest.unwrap();
    assert_eq!(
        (reader.author.as_str(), reader.key.as_str()),
        (rest.text("restAuthor"), rest.text("restKey"))
    );
    let reader_keys = RestReaderKeys::new(rest.secret("restKey"), rest.text("restAuthor").to_owned());
    assert_eq!(to_hex(reader_keys.encryption_key.expose()), rest.text("encryptionKey"));
    let terms =
        RestLinkTerms { sats: record.sats, created_at: record.created_at, expires_at: record.expires_at };
    let rest_event = valid_event(rest.field("event")).unwrap();
    let opened = open_rest_event(&rest_event, &reader_keys, &terms).unwrap().unwrap();
    assert_eq!(opened.bolt11, rest.text("invoice"));
    assert_eq!(opened.payment_hash, rest.text("paymentHash"));
    assert_eq!(opened.verify_url, rest.text("verifyUrl"));
    assert_eq!(opened.sats.to_string(), rest.text("sats"));
}
