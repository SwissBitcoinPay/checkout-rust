//! Checkout links (SPEC.md §30): asked with the order, published on a majority of the merchant's
//! relays before the invoice is declared, read by the merchant's web app with what its URL holds
//! alone.

use super::support::j;
use super::support::merchant::TestMerchant;
use super::support::owner::open_as_owner;
use super::support::rates::price;
use super::support::relay::RelayBehaviour;
use super::support::vectors::assert_same;
use crate::checkout::{
    CheckoutFragment, CheckoutRecord, checkout_keys, checkout_url, parse_checkout_fragment,
    parse_checkout_value, redirect_shown,
};
use crate::client::Client;
use crate::derive::{public_key_of, sale_keys};
use crate::error::ErrorCode;
use crate::json::{self, Json};
use crate::nostr::event::{Event, valid_event};
use crate::nostr::nip44::decrypt;
use crate::order::Order;
use crate::secret::Secret;
use crate::text::to_hex;

const ORIGIN: &str = "https://pay.example";

fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    merchant.publish_channel(
        &merchant.channel_value(
            100,
            Json::object([("relays", relays), ("checkout", Json::object([("origin", Json::from(ORIGIN))]))]),
        ),
        100,
    );
    merchant
}

fn client(merchant: &TestMerchant) -> Client {
    merchant.client().rate_source(price("99000")).build().unwrap()
}

/// Every event the relays received, in the order the first relay received them.
fn received(merchant: &TestMerchant) -> Vec<Event> {
    merchant.net.get(&merchant.key_relays[0]).received()
}

fn is_checkout(event: &Event) -> bool {
    event.tags.iter().any(|tag| tag.first().map(String::as_str) == Some("expiration"))
}

struct Link {
    author: String,
    link_key: Secret,
    relays: Vec<String>,
    event: Event,
    copies: Vec<Option<Json>>,
    value: Json,
    record: Option<CheckoutRecord>,
}

/// The link of a checkout URL, read as the page reads it, with its record from the relays.
fn open_link(merchant: &TestMerchant, url: &str) -> Link {
    assert!(url.starts_with(&format!("{ORIGIN}/pay#c.")), "{url}");
    let CheckoutFragment::Link { author, link_key, relays } =
        parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("Not a link: {url}")
    };
    let keys = checkout_keys(&link_key);
    let copies: Vec<Option<Json>> = relays
        .iter()
        .map(|relay| {
            merchant.net.get(relay).events().into_iter().find(|value| {
                value.get("pubkey").and_then(Json::as_str) == Some(author.as_str())
                    && value.get("tags").and_then(Json::as_array).is_some_and(|tags| {
                        tags.iter().any(|tag| {
                            tag.as_array().is_some_and(|tag| {
                                tag.first().and_then(Json::as_str) == Some("d")
                                    && tag.get(1).and_then(Json::as_str) == Some(keys.address.as_str())
                            })
                        })
                    })
            })
        })
        .collect();
    let event = valid_event(copies[0].as_ref().expect("Not on the relays")).expect("a valid event");
    let envelope = json::parse(&decrypt(&event.content, &keys.encryption_key).unwrap()).unwrap();
    assert_eq!(envelope.get("t").and_then(Json::as_str), Some("checkout"));
    let value = envelope.get("v").unwrap().clone();
    let record = parse_checkout_value(&value).ok().flatten();
    Link { author, link_key, relays, event, copies, value, record }
}

mod create_invoice_with_checkout {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn publishes_the_link_before_the_declaration_and_gives_its_url() {
        let merchant = merchant();
        let invoice = client(&merchant)
            .create_invoice(
                &Order::fiat("ORD-1042", "24.50", "CHF")
                    .note("Order 1042")
                    .checkout(true)
                    .redirect_url("https://shop.example/orders/1042/thanks"),
            )
            .await
            .unwrap();
        let made = merchant.invoices()[0].clone();
        assert_eq!(invoice.redirect_url.as_deref(), Some("https://shop.example/orders/1042/thanks"));
        // JSON as is, with exactly the fields of SPEC.md "Data model": no secret of the link.
        let stored = serde_json::to_value(&invoice).unwrap();
        let mut names: Vec<&str> = stored.as_object().unwrap().keys().map(String::as_str).collect();
        names.sort_unstable();
        let mut expected = vec![
            "ref",
            "bolt11",
            "paymentHash",
            "verifyUrl",
            "onchainAddress",
            "paymentUri",
            "sats",
            "fiat",
            "rate",
            "note",
            "createdAt",
            "expiresAt",
            "checkoutUrl",
            "redirectUrl",
        ];
        expected.sort_unstable();
        assert_eq!(names, expected);

        let link = open_link(&merchant, invoice.checkout_url.as_deref().unwrap());
        // On every relay of the merchant, which the URL names.
        assert_eq!(link.relays, merchant.key_relays);
        assert!(
            link.copies.iter().all(|copy| copy
                .as_ref()
                .and_then(|copy| copy.get("id"))
                .and_then(Json::as_str)
                == Some(link.event.id.as_str()))
        );
        // The link first, then the declaration: a link never names an invoice its URL was not
        // given for.
        let order: Vec<&str> = received(&merchant)
            .iter()
            .map(|event| if is_checkout(event) { "link" } else { "declaration" })
            .collect();
        assert_eq!(order, vec!["link", "declaration"]);
        // Its own author, not the sale's; dropped by the relays a week after the invoice's end.
        assert_ne!(link.event.pubkey, sale_keys(&merchant.integration_key, "ORD-1042").author);
        assert_eq!(link.event.pubkey, link.author);
        assert_eq!(
            link.event.tags,
            vec![
                vec!["d".to_owned(), checkout_keys(&link.link_key).address],
                vec!["expiration".to_owned(), (invoice.expires_at + 604_800).to_string()]
            ]
        );
        assert_eq!(link.event.created_at, merchant.now());
        assert_same(
            &link.value,
            &j!({
                "version": 1,
                "businessName": "Sunrise Bakery",
                "invoice": made.pr,
                "verifyUrl": made.verify,
                "fiat": { "minor": 2450, "digits": 2, "currency": "CHF" },
                "note": "Order 1042",
                "redirectUrl": "https://shop.example/orders/1042/thanks"
            }),
            "the link's value",
        );
        let record = link.record.unwrap();
        assert_eq!(record.sats, invoice.sats);
        assert_eq!(record.redirect_shown.as_deref(), Some("shop.example"));
    }

    #[tokio::test(start_paused = true)]
    async fn writes_an_order_in_sats_without_a_price_and_without_a_redirect_url() {
        let merchant = merchant();
        let invoice =
            client(&merchant).create_invoice(&Order::sats("A-1", 49_000).checkout(true)).await.unwrap();
        assert_eq!(invoice.redirect_url, None);
        let link = open_link(&merchant, invoice.checkout_url.as_deref().unwrap());
        assert_eq!(link.value.get("fiat"), Some(&Json::Null));
        assert_eq!(link.value.get("note").and_then(Json::as_str), Some("A-1"));
        assert_eq!(link.value.get("redirectUrl"), Some(&Json::Null));
    }

    #[tokio::test(start_paused = true)]
    async fn authenticates_the_link_publication_as_its_author() {
        let merchant = merchant();
        for relay in &merchant.key_relays {
            merchant
                .net
                .get(relay)
                .set_behaviour(RelayBehaviour { require_auth: true, ..RelayBehaviour::default() });
        }
        let invoice =
            client(&merchant).create_invoice(&Order::sats("A-1", 100).checkout(true)).await.unwrap();
        let link = open_link(&merchant, invoice.checkout_url.as_deref().unwrap());
        assert!(merchant.net.get(&merchant.key_relays[0]).authenticated().contains(&link.author));
    }

    #[tokio::test(start_paused = true)]
    async fn gives_a_new_link_with_new_keys_to_each_invoice() {
        let merchant = merchant();
        let first = client(&merchant).create_invoice(&Order::sats("A-1", 100).checkout(true)).await.unwrap();
        let second = client(&merchant).create_invoice(&Order::sats("A-2", 100).checkout(true)).await.unwrap();
        let a = open_link(&merchant, first.checkout_url.as_deref().unwrap());
        let b = open_link(&merchant, second.checkout_url.as_deref().unwrap());
        assert_ne!(a.author, b.author);
        assert_ne!(to_hex(a.link_key.expose()), to_hex(b.link_key.expose()));
    }

    #[tokio::test(start_paused = true)]
    async fn publishes_nothing_more_without_checkout() {
        let merchant = merchant();
        let invoice = client(&merchant).create_invoice(&Order::sats("A-1", 100)).await.unwrap();
        assert_eq!(invoice.checkout_url, None);
        assert_eq!(invoice.redirect_url, None);
        assert!(!received(&merchant).iter().any(is_checkout));
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_checkout_when_the_merchant_app_gives_no_web_app_before_any_invoice() {
        let merchant = merchant();
        let relays =
            Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
        let invalid: Vec<Option<Json>> = vec![
            None,
            Some(Json::Null),
            Some(Json::from(ORIGIN)),
            Some(j!({ "origin": "http://pay.example" })),
        ];
        for (index, checkout) in invalid.iter().enumerate() {
            let at = 200 + index as i64;
            let mut extra = vec![("relays", relays.clone())];
            if let Some(checkout) = checkout {
                extra.push(("checkout", checkout.clone()));
            }
            let value = merchant.channel_value(at, Json::object_of(extra));
            assert_eq!(value.get("checkout"), checkout.as_ref());
            merchant.publish_channel(&value, at);
            let error = client(&merchant)
                .create_invoice(&Order::sats(format!("A-{index}"), 100).checkout(true))
                .await
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::CheckoutUnavailable, "{checkout:?}");
            // The channel stays valid: an invoice without checkout is made.
            let plain =
                client(&merchant).create_invoice(&Order::sats(format!("B-{index}"), 100)).await.unwrap();
            assert_eq!(plain.checkout_url, None);
        }
        let error =
            client(&merchant).create_invoice(&Order::sats("C-1", 100).checkout(true)).await.unwrap_err();
        assert_eq!((error.code(), error.retryable()), (ErrorCode::CheckoutUnavailable, false));
        // Only the invoices made without checkout.
        assert_eq!(merchant.invoices().len(), invalid.len());
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_invalid_redirect_url_before_any_request() {
        // A checkout or a redirect URL of another type: the types refuse them.
        let invalid = [
            Order::sats("A-1", 100).redirect_url("https://shop.example/thanks"),
            Order::sats("A-1", 100).checkout(false).redirect_url("https://shop.example/thanks"),
            Order::sats("A-1", 100).checkout(true).redirect_url("http://shop.example/thanks"),
            Order::sats("A-1", 100).checkout(true).redirect_url("javascript://alert(1)"),
            Order::sats("A-1", 100).checkout(true).redirect_url("https://user:pass@shop.example/"),
            Order::sats("A-1", 100).checkout(true).redirect_url(""),
        ];
        let merchant = merchant();
        for order in invalid {
            let error = client(&merchant).create_invoice(&order).await.unwrap_err();
            assert_eq!(
                (error.code(), error.param()),
                (ErrorCode::InvalidOrder, Some("redirectUrl")),
                "{order:?}"
            );
        }
        assert!(merchant.http.calls().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn takes_an_order_without_a_redirect_url_as_none() {
        let merchant = merchant();
        let invoice =
            client(&merchant).create_invoice(&Order::sats("A-1", 100).checkout(true)).await.unwrap();
        assert_eq!(invoice.redirect_url, None);
        assert!(invoice.checkout_url.is_some());
    }

    fn refuse(links: bool) -> RelayBehaviour {
        RelayBehaviour {
            refuse_event: Some(std::sync::Arc::new(move |event: &Event| {
                (is_checkout(event) == links).then(|| "blocked: no".to_owned())
            })),
            ..RelayBehaviour::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn declares_nothing_when_fewer_than_a_majority_take_the_link() {
        let merchant = merchant();
        merchant.net.get("wss://relay-a.test").set_behaviour(refuse(true));
        merchant.net.get("wss://relay-b.test").set_behaviour(refuse(true));
        let error =
            client(&merchant).create_invoice(&Order::sats("A-1", 100).checkout(true)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
        assert!(received(&merchant).iter().all(is_checkout));
        // The order gets a new invoice at once: nothing was declared.
        merchant.net.get("wss://relay-a.test").set_behaviour(RelayBehaviour::default());
        merchant.net.get("wss://relay-b.test").set_behaviour(RelayBehaviour::default());
        let invoice =
            client(&merchant).create_invoice(&Order::sats("A-1", 100).checkout(true)).await.unwrap();
        assert_eq!(invoice.reference, "A-1");
        assert_eq!(merchant.invoices().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_no_url_when_the_declaration_fails_after_the_link() {
        let merchant = merchant();
        merchant.net.get("wss://relay-a.test").set_behaviour(refuse(false));
        merchant.net.get("wss://relay-b.test").set_behaviour(refuse(false));
        let error =
            client(&merchant).create_invoice(&Order::sats("A-1", 100).checkout(true)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
        assert_eq!(error.checkout_url(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_a_new_link_to_the_pending_invoice_of_an_order_with_this_call_redirect_url() {
        let merchant = merchant();
        let first = client(&merchant)
            .create_invoice(
                &Order::fiat("ORD-7", "0.02", "CHF")
                    .note("Order 7")
                    .checkout(true)
                    .redirect_url("https://shop.example/7"),
            )
            .await
            .unwrap();
        let pending = client(&merchant)
            .create_invoice(
                &Order::fiat("ORD-7", "0.02", "CHF").checkout(true).redirect_url("myshop://orders/7"),
            )
            .await
            .unwrap_err();
        assert_eq!(pending.code(), ErrorCode::InvoicePending);
        assert_eq!(pending.invoice().unwrap().bolt11, first.bolt11);
        let url = pending.checkout_url().expect("a new link");
        assert_ne!(Some(url), first.checkout_url.as_deref());
        let link = open_link(&merchant, url);
        assert_same(
            &link.value,
            &j!({
                "version": 1,
                "businessName": "Sunrise Bakery",
                "invoice": first.bolt11,
                "verifyUrl": first.verify_url,
                "fiat": { "minor": 2, "digits": 2, "currency": "CHF" },
                "note": "Order 7",
                "redirectUrl": "myshop://orders/7"
            }),
            "the new link's value",
        );
        assert_eq!(link.record.unwrap().redirect_shown.as_deref(), Some("myshop://"));
        // Without checkout, no link.
        let plain = client(&merchant).create_invoice(&Order::fiat("ORD-7", "0.02", "CHF")).await.unwrap_err();
        assert_eq!((plain.code(), plain.checkout_url()), (ErrorCode::InvoicePending, None));
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_the_declaration_as_it_was_no_redirect_url_in_the_registry() {
        let merchant = merchant();
        client(&merchant)
            .create_invoice(
                &Order::sats("A-1", 100).checkout(true).redirect_url("https://shop.example/thanks"),
            )
            .await
            .unwrap();
        let declaration = received(&merchant).into_iter().find(|event| !is_checkout(event)).unwrap();
        let inside = open_as_owner(&declaration, &merchant.registry_key, &merchant.reader_secret);
        let mut names: Vec<String> =
            inside.as_object().unwrap().iter().map(|(name, _)| name.to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, vec!["invoice", "sale", "taker", "verifyUrl", "version"]);
    }
}

mod a_link_parts {
    use super::*;

    #[test]
    fn reads_a_link_fragment_back_and_only_the_fragments_of_checkout_links() {
        let author = public_key_of(&Secret::new([7; 32]));
        let link_key = Secret::new([8; 32]);
        let relays = vec!["wss://relay.example".to_owned(), "wss://nos.lol".to_owned()];
        let url = checkout_url(ORIGIN, &author, &link_key, &relays);
        assert_eq!(
            parse_checkout_fragment(&url[url.find('#').unwrap()..]),
            CheckoutFragment::Link { author, link_key: Secret::new([8; 32]), relays }
        );
        assert_eq!(parse_checkout_fragment("#d.a.b.c"), CheckoutFragment::Newer);
        assert_eq!(parse_checkout_fragment("c2.a.b.c"), CheckoutFragment::Newer);
        assert_eq!(parse_checkout_fragment("c.a.b"), CheckoutFragment::Invalid);
        // A payment link of the point of sale: its author first, 43 characters.
        assert_eq!(
            parse_checkout_fragment(&format!("{}.{}", "A".repeat(43), "B".repeat(43))),
            CheckoutFragment::Other
        );
    }

    #[test]
    fn shows_the_host_of_an_https_url_and_the_scheme_of_an_app_link() {
        assert_eq!(redirect_shown("https://shop.example:8443/a?b#c").as_deref(), Some("shop.example:8443"));
        assert_eq!(redirect_shown("myshop://orders/42").as_deref(), Some("myshop://"));
        assert_eq!(redirect_shown("https://shop.example\\@evil.example"), None);
    }
}
