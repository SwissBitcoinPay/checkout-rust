//! `create_invoice` and `find_invoices` against local relays and a fake Lightning address
//! (SPEC.md §17–§21, §26): the order's checks, the invoice's checks, the declaration on a majority,
//! one order one invoice at a time, one connection per relay, rate sources by name.

use std::collections::HashSet;

use tokio::time::Instant;

use super::support::http::Answer;
use super::support::j;
use super::support::lightning::{InvoiceSpec, make_invoice, metadata_hash};
use super::support::merchant::{CALLBACK, MadeInvoice, TestMerchant, Warnings, metadata};
use super::support::owner::open_as_owner;
use super::support::rates::{Failing, price};
use super::support::relay::RelayBehaviour;
use super::support::vectors::assert_same;
use crate::derive::{sale_keys, taker_key, taker_tag};
use crate::error::{Error, ErrorCode};
use crate::json::{Json, JsonString};
use crate::model::Invoice;
use crate::nostr::event::valid_event;
use crate::order::Order;
use crate::rates::RateSource;
use crate::text::to_hex;

fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    merchant.publish_channel(&merchant.channel_value(100, Json::object([("relays", relays)])), 100);
    merchant
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
}

fn json(invoice: &Invoice) -> serde_json::Value {
    serde_json::to_value(invoice).unwrap()
}

fn code<T: std::fmt::Debug>(result: Result<T, Error>) -> ErrorCode {
    result.expect_err("an error").code()
}

/// An invoice of the fake Lightning address, its fields changed.
fn invoice_of(made: &MadeInvoice, change: impl FnOnce(&mut InvoiceSpec), now: i64) -> String {
    let mut spec = InvoiceSpec::new(&made.payment_hash, now);
    spec.amount_msat = Some(made.amount_msat);
    spec.description_hash = Some(metadata_hash(&metadata()));
    spec.expiry_seconds = Some(900);
    change(&mut spec);
    make_invoice(&spec)
}

mod create_invoice {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn keeps_the_callback_query_parameters_and_drops_its_fragment() {
        let merchant = merchant();
        merchant.set_pay_field("callback", Some(Json::from(format!("{CALLBACK}?k=1#tag"))));
        merchant.client().build().unwrap().create_invoice(&Order::sats("ORD-1", 1000)).await.unwrap();
        let call = merchant.http.calls().into_iter().find(|call| call.path().ends_with("/invoice")).unwrap();
        assert!(!call.url.contains('#'), "{}", call.url);
        assert_eq!(
            call.params(),
            pairs(&[("k", "1"), ("amount", "1000000"), ("expiry", "900"), ("comment", "ORD-1")])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_pay_request_whose_callback_is_not_an_https_url() {
        let merchant = merchant();
        for callback in ["https://10.0.0.1/cb", "https://pay.localhost/cb", "https://user@breez.tips/cb"] {
            merchant.set_pay_field("callback", Some(Json::from(callback)));
            let result = merchant.client().build().unwrap().create_invoice(&Order::sats("ORD-1", 1000)).await;
            assert_eq!(code(result), ErrorCode::InvalidInvoice, "{callback}");
        }
        assert!(merchant.http.calls().iter().all(|call| !call.path().ends_with("/cb")));
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_pay_request_whose_metadata_holds_a_lone_surrogate_it_has_no_utf8_to_hash() {
        let merchant = merchant();
        // Valid JSON (an escape), but no text (SPEC.md §6, §16): TextEncoder would hash U+FFFD in
        // its place, and an invoice made with that hash.
        let mut units: Vec<u16> = metadata().encode_utf16().collect();
        units.insert(units.len() - 3, 0xd800);
        let lossy = String::from_utf16_lossy(&units);
        merchant.set_pay_field("metadata", Some(Json::String(JsonString::Units(units))));
        let now = merchant.now();
        merchant.set_tamper(Some(move |made: MadeInvoice| {
            let mut spec = InvoiceSpec::new(&made.payment_hash, now);
            spec.amount_msat = Some(made.amount_msat);
            spec.description_hash = Some(metadata_hash(&lossy));
            spec.expiry_seconds = Some(made.expiry);
            MadeInvoice { pr: make_invoice(&spec), ..made }
        }));
        let result = merchant.client().build().unwrap().create_invoice(&Order::sats("ORD-1", 1000)).await;
        assert_eq!(code(result), ErrorCode::InvalidInvoice);
        // Before its callback is asked.
        assert!(merchant.http.calls().iter().all(|call| call.path() != CALLBACK));
        assert!(merchant.invoices().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn fails_network_on_a_callback_nothing_answers() {
        let merchant = merchant();
        // An https URL by its rule (SPEC.md §15), but a host nothing answers for.
        merchant.set_pay_field("callback", Some(Json::from("https://xn--abc.example/cb")));
        let result = merchant.client().build().unwrap().create_invoice(&Order::sats("ORD-1", 1000)).await;
        assert_eq!(code(result), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn asks_checks_and_declares_the_invoice_of_an_order_in_sats() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let invoice =
            client.create_invoice(&Order::sats("ORD-1042", 49_000).note("Order 1042")).await.unwrap();
        let made = merchant.invoices()[0].clone();
        let now = merchant.now();
        assert_eq!(
            json(&invoice),
            serde_json::json!({
                "ref": "ORD-1042",
                "bolt11": made.pr,
                "paymentHash": made.payment_hash,
                "verifyUrl": made.verify,
                // Within the Lightning address's bounds, and no lot of addresses: Lightning only.
                "onchainAddress": null,
                "paymentUri": format!("lightning:{}", made.pr),
                "sats": "49000",
                "fiat": null,
                "rate": null,
                "note": "Order 1042",
                "createdAt": now,
                "expiresAt": now + 900,
                // No checkout link was asked.
                "checkoutUrl": null,
                "redirectUrl": null
            })
        );
        // JSON as is: an integrator stores it with the order.
        assert_eq!(Invoice::from_json(&invoice.to_json()).unwrap(), invoice);

        let callback =
            merchant.http.calls().into_iter().find(|call| call.path().ends_with("/invoice")).unwrap();
        assert_eq!(
            callback.params(),
            pairs(&[("amount", "49000000"), ("expiry", "900"), ("comment", "Order 1042")])
        );
        // Every request, with the User-Agent every implementation sends (SPEC.md §15).
        client.get_status(&invoice).await.unwrap();
        let calls = merchant.http.calls();
        assert!(calls.len() >= 3);
        for call in calls {
            let headers: HashSet<(String, String)> = call.headers.iter().cloned().collect();
            let expected: HashSet<(String, String)> =
                [("Accept", "application/json"), ("User-Agent", "sattleme-Checkout/1")]
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect();
            assert_eq!(headers, expected, "{}", call.url);
        }

        // Declared on every relay of the account, signed by the order's sale.
        let events = merchant.declarations();
        assert_eq!(events.len(), 3);
        let event = &events[0];
        let sale = sale_keys(&merchant.integration_key, "ORD-1042");
        assert!(valid_event(&event.to_json()).is_some());
        assert_eq!(event.pubkey, sale.author);
        assert_same(
            &open_as_owner(event, &merchant.registry_key, &merchant.reader_secret),
            &j!({
                "version": 1,
                "invoice": made.pr,
                "verifyUrl": made.verify,
                "sale": {
                    "key": to_hex(sale.key.expose()),
                    "fiat": { "minor": 49000, "digits": 0, "currency": "SAT" },
                    "note": "Order 1042"
                },
                "taker": taker_tag(&taker_key(&merchant.integration_key), &sale.author)
            }),
            "the declaration",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn names_the_order_by_its_reference_without_a_note_and_comments_only_as_allowed() {
        let merchant = merchant();
        merchant.client().build().unwrap().create_invoice(&Order::sats("A-1", 100)).await.unwrap();
        merchant.set_pay_field("commentAllowed", Some(Json::unsigned(2)));
        merchant
            .client()
            .build()
            .unwrap()
            .create_invoice(&Order::sats("A-2", 100).duration_seconds(60))
            .await
            .unwrap();
        merchant.set_pay_field("commentAllowed", None);
        merchant
            .client()
            .build()
            .unwrap()
            .create_invoice(&Order::sats("A-3", 100).duration_seconds(3600))
            .await
            .unwrap();
        let comments: Vec<(Option<String>, u64)> =
            merchant.invoices().into_iter().map(|made| (made.comment, made.expiry)).collect();
        assert_eq!(comments, vec![(Some("A-1".to_owned()), 900), (None, 60), (None, 3600)]);
        let inside =
            open_as_owner(&merchant.declarations()[0], &merchant.registry_key, &merchant.reader_secret);
        assert_eq!(inside.get("sale").and_then(|sale| sale.get("note")).and_then(Json::as_str), Some("A-1"));
    }

    /// The invalid orders a Rust caller can write (a missing reference or amount, an amount of
    /// another type, both amounts at once, a duration that is not an integer: the types refuse
    /// them).
    fn invalid() -> Vec<(&'static str, Order)> {
        vec![
            ("ref", Order::sats("", 1)),
            ("ref", Order::sats("x".repeat(65), 1)),
            ("ref", Order::sats("CMD 1", 1)),
            ("ref", Order::sats("CMD/1", 1)),
            ("ref", Order::sats("Bestellung-ä", 1)),
            ("sats", Order::sats("A", 0)),
            ("sats", Order::sats("A", 9_007_199_254_740_992)),
            ("sats", Order::sats("A", 2_100_000_000_000_001)),
            ("durationSeconds", Order::sats("A", 1).duration_seconds(59)),
            ("durationSeconds", Order::sats("A", 1).duration_seconds(3601)),
            ("durationSeconds", Order::sats("A", 1).duration_seconds(0)),
            ("note", Order::sats("A", 1).note("n".repeat(101))),
            ("note", Order::sats("A", 1).note("line\nbreak")),
            ("fiat", Order::fiat("A", "24.5.0", "CHF")),
            ("fiat", Order::fiat("A", "24.50", "SAT")),
            ("rateSource", Order::sats("A", 1).rate_source(price("1"))),
            ("rateSource", Order::sats("A", 1).rate_source(RateSource::Kraken)),
            ("rateSource", Order::fiat("A", "1", "CHF").rate_sources([])),
            (
                "rateSource",
                Order::fiat("A", "1", "CHF").rate_sources([RateSource::Kraken, RateSource::Kraken]),
            ),
            ("rateSource", Order::sats("A", 1).rate_sources([RateSource::Kraken, RateSource::Coingecko])),
        ]
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_invalid_order_before_any_request() {
        let merchant = merchant();
        for (param, order) in invalid() {
            let error = merchant.client().build().unwrap().create_invoice(&order).await.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidOrder, "{param}: {error}");
            assert_eq!(error.param(), Some(param), "{param}: {error}");
            assert!(!error.retryable());
        }
        // A name that is no source's is no RateSource.
        assert!("bitstamp".parse::<RateSource>().is_err());
        assert!(merchant.invoices().is_empty());
        assert!(merchant.declarations().is_empty());
        assert!(merchant.http.calls().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn accepts_the_edges_64_characters_100_for_the_note_60_and_3600_seconds() {
        let merchant = merchant();
        let reference = format!("{}.:_-", "A".repeat(60));
        let order = Order::sats(reference, 1).note("é".repeat(100)).duration_seconds(60);
        merchant.client().build().unwrap().create_invoice(&order).await.unwrap();
        assert_eq!(merchant.declarations().len(), 3);
        merchant
            .client()
            .build()
            .unwrap()
            .create_invoice(&Order::sats("Z", 1).duration_seconds(3600))
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_an_amount_within_the_lightning_address_bounds_rounded_inwards() {
        let merchant = merchant();
        merchant.set_pay_field("minSendable", Some(Json::unsigned(10_001)));
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_999)));
        let client = merchant.client().build().unwrap();
        let found = client.merchant().await.unwrap();
        assert_eq!((found.min_sats, found.max_sats), (11, 1000));
        let below = client.create_invoice(&Order::sats("B-10", 10)).await.unwrap_err();
        assert_eq!((below.code(), below.param()), (ErrorCode::InvalidOrder, Some("sats")));
        // From 1 000 sats on, on-chain only: no address without a lot.
        let above = client.create_invoice(&Order::sats("B-1001", 1001)).await.unwrap_err();
        assert_eq!(above.code(), ErrorCode::OnchainUnavailable);
        assert!(above.retryable());
        client.create_invoice(&Order::sats("B-11", 11)).await.unwrap();
        client.create_invoice(&Order::sats("B-1000", 1000)).await.unwrap();
        assert_eq!(merchant.invoices().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_tampered_invoice_and_declares_nothing() {
        type Tamper = Box<dyn Fn(MadeInvoice, i64) -> MadeInvoice + Send + Sync>;
        let tampered: Vec<(&str, Tamper)> = vec![
            (
                "an invoice of another network",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.network = "tb".to_owned(), now),
                    ..m
                }),
            ),
            (
                "another amount",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.amount_msat = Some(m.amount_msat - 1000), now),
                    ..m
                }),
            ),
            (
                "no amount",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.amount_msat = None, now),
                    ..m
                }),
            ),
            (
                "another merchant's invoice",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.description_hash = Some(metadata_hash("[]")), now),
                    ..m
                }),
            ),
            (
                "a longer expiry",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.expiry_seconds = Some(901), now),
                    ..m
                }),
            ),
            (
                "no expiry (3600 s)",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.expiry_seconds = None, now),
                    ..m
                }),
            ),
            (
                "a date 5 minutes off",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.timestamp = now - 301, now),
                    ..m
                }),
            ),
            (
                "a date in the future",
                Box::new(|m, now| MadeInvoice {
                    pr: invoice_of(&m, |spec| spec.timestamp = now + 301, now),
                    ..m
                }),
            ),
            (
                "a verify URL in http",
                Box::new(|m, _| MadeInvoice {
                    verify: format!("http://breez.tips/lnurlp/verify/{}", m.payment_hash),
                    ..m
                }),
            ),
            (
                "a verify URL on another host",
                Box::new(|m, _| MadeInvoice {
                    verify: format!("https://evil.test/verify/{}", m.payment_hash),
                    ..m
                }),
            ),
            ("not an invoice", Box::new(|m, _| MadeInvoice { pr: "lnbc1nope".to_owned(), ..m })),
        ];
        for (name, tamper) in tampered {
            let merchant = merchant();
            let now = merchant.now();
            merchant.set_tamper(Some(move |made| tamper(made, now)));
            let result = merchant.client().build().unwrap().create_invoice(&Order::sats("C-1", 1000)).await;
            assert_eq!(code(result), ErrorCode::InvalidInvoice, "{name}");
            assert!(merchant.declarations().is_empty(), "{name}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_invoice_dated_within_5_minutes_but_already_over() {
        let merchant = merchant();
        let now = merchant.now();
        merchant.set_tamper(Some(move |m: MadeInvoice| MadeInvoice {
            pr: invoice_of(
                &m,
                |spec| {
                    spec.timestamp = now - 200;
                    spec.expiry_seconds = Some(60);
                },
                now,
            ),
            ..m
        }));
        let result = merchant
            .client()
            .build()
            .unwrap()
            .create_invoice(&Order::sats("C-3", 1000).duration_seconds(60))
            .await;
        assert_eq!(code(result), ErrorCode::InvalidInvoice);
        assert!(merchant.declarations().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_valid_invoice_too_large_to_be_declared_as_invalid_invoice() {
        let merchant = merchant();
        let now = merchant.now();
        // 70 unknown fields of 1023 words: some 72 000 characters, more than a NIP-44 plaintext holds.
        merchant.set_tamper(Some(move |m: MadeInvoice| MadeInvoice {
            pr: invoice_of(&m, |spec| spec.extra = (0..70).map(|_| (31, vec![0; 1023])).collect(), now),
            ..m
        }));
        let error =
            merchant.client().build().unwrap().create_invoice(&Order::sats("C-4", 1000)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInvoice);
        assert!(error.message().contains("too large to be declared"), "{error}");
        assert!(merchant.declarations().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn accepts_an_invoice_dated_within_5_minutes() {
        let merchant = merchant();
        let now = merchant.now();
        merchant.set_tamper(Some(move |m: MadeInvoice| MadeInvoice {
            pr: invoice_of(
                &m,
                |spec| {
                    spec.timestamp = now - 300;
                    spec.expiry_seconds = Some(899);
                },
                now,
            ),
            ..m
        }));
        let invoice =
            merchant.client().build().unwrap().create_invoice(&Order::sats("C-2", 1000)).await.unwrap();
        assert_eq!(invoice.expires_at, now - 300 + 899);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_answer_without_an_invoice_or_the_service_refusal() {
        let merchant = merchant();
        merchant.set_override(Some(|call: &super::super::support::http::Call| {
            call.path().ends_with("/invoice").then(|| Answer::json(&j!({ "verify": "https://breez.tips/v" })))
        }));
        assert_eq!(
            code(merchant.client().build().unwrap().create_invoice(&Order::sats("D-1", 1)).await),
            ErrorCode::InvalidInvoice
        );
        merchant.set_override(Some(|call: &super::super::support::http::Call| {
            call.path().ends_with("/invoice").then(|| {
                Answer::status_json(400, &j!({ "status": "ERROR", "reason": "Amount out of range" }))
            })
        }));
        assert_eq!(
            code(merchant.client().build().unwrap().create_invoice(&Order::sats("D-2", 1)).await),
            ErrorCode::Network
        );
        merchant.set_override(Some(|call: &super::super::support::http::Call| {
            call.path().ends_with("/invoice").then(|| Answer::status_json(502, &j!({})))
        }));
        assert_eq!(
            code(merchant.client().build().unwrap().create_invoice(&Order::sats("D-3", 1)).await),
            ErrorCode::Network
        );
        assert!(merchant.declarations().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn gives_the_invoice_once_a_majority_of_the_relays_took_its_declaration() {
        let merchant = merchant();
        merchant.net.get("wss://relay-a.test").set_behaviour(RelayBehaviour::refusing("blocked: no"));
        merchant.client().build().unwrap().create_invoice(&Order::sats("E-1", 1)).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn gives_no_invoice_without_a_majority_refusals_an_unreachable_relay() {
        let merchant = merchant();
        merchant.net.get("wss://relay-a.test").set_behaviour(RelayBehaviour::refusing("blocked: no"));
        merchant
            .net
            .get("wss://relay-b.test")
            .set_behaviour(RelayBehaviour::refusing("error: internal error"));
        assert_eq!(
            code(merchant.client().build().unwrap().create_invoice(&Order::sats("E-2", 1)).await),
            ErrorCode::Network
        );
        merchant.net.get("wss://relay-b.test").set_behaviour(RelayBehaviour::default());
        merchant.net.remove("wss://relay-c.test");
        assert_eq!(
            code(merchant.client().build().unwrap().create_invoice(&Order::sats("E-3", 1)).await),
            ErrorCode::Network
        );
    }

    #[tokio::test(start_paused = true)]
    async fn authenticates_to_a_relay_as_the_order_sale() {
        let merchant = merchant();
        for url in ["wss://relay-a.test", "wss://relay-b.test"] {
            merchant
                .net
                .get(url)
                .set_behaviour(RelayBehaviour { require_auth: true, ..RelayBehaviour::default() });
        }
        merchant.client().build().unwrap().create_invoice(&Order::sats("E-4", 1)).await.unwrap();
        let sale = sale_keys(&merchant.integration_key, "E-4").author;
        let relay = merchant.net.get("wss://relay-b.test");
        assert!(relay.authenticated().contains(&sale));
        let held = relay
            .events()
            .into_iter()
            .filter(|event| event.get("pubkey").and_then(Json::as_str) == Some(sale.as_str()))
            .count();
        assert_eq!(held, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn declares_on_the_account_relays_the_channel_names() {
        let merchant = TestMerchant::new()
            .start_with(&["wss://account-a.test", "wss://account-b.test"], Default::default());
        let mut everywhere = merchant.key_relays.clone();
        everywhere.extend(["wss://account-a.test".to_owned(), "wss://account-b.test".to_owned()]);
        merchant.publish_channel_on(
            &merchant.channel_value(100, j!({ "relays": ["wss://account-a.test", "wss://account-b.test"] })),
            100,
            &everywhere,
            None,
        );
        merchant.client().build().unwrap().create_invoice(&Order::sats("E-5", 1)).await.unwrap();
        assert_eq!(merchant.net.get("wss://account-b.test").events().len(), 2);
        assert!(merchant.net.get("wss://relay-a.test").received().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_once_the_merchant_removed_the_integration() {
        let merchant = merchant();
        merchant.publish_channel(&j!({ "version": 1, "status": "removed", "updatedAt": 200 }), 200);
        assert_eq!(
            code(merchant.client().build().unwrap().create_invoice(&Order::sats("F-1", 1)).await),
            ErrorCode::Revoked
        );
        assert!(merchant.http.calls().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn converts_a_price_in_a_currency_at_its_rate_and_declares_the_price() {
        let merchant = merchant();
        let client = merchant.client().rate_source(price("69012")).build().unwrap();
        let invoice =
            client.create_invoice(&Order::fiat("G-1", "24.50", "CHF").note("Order 1042")).await.unwrap();
        let json = json(&invoice);
        assert_eq!(json["sats"], "35502");
        assert_eq!(
            json["fiat"],
            serde_json::json!({ "amount": "24.50", "currency": "CHF", "minor": "2450", "digits": 2 })
        );
        assert_eq!(json["rate"]["source"], "custom");
        assert_eq!(json["rate"]["currency"], "CHF");
        assert_eq!(json["rate"]["price"], "69012");
        assert_eq!(json["rate"]["fetchedAt"], merchant.now());
        assert_eq!(merchant.invoices()[0].amount_msat, 35_502_000);
        let inside =
            open_as_owner(&merchant.declarations()[0], &merchant.registry_key, &merchant.reader_secret);
        assert_same(
            inside.get("sale").unwrap().get("fiat").unwrap(),
            &j!({ "minor": 2450, "digits": 2, "currency": "CHF" }),
            "the price",
        );
        // Another source for one invoice.
        let other = client
            .create_invoice(&Order::fiat("G-2", "1500", "JPY").rate_source(price("15000000")))
            .await
            .unwrap();
        assert_eq!(other.sats, 10_000);
        let rate = other.rate.unwrap();
        assert_eq!((rate.source.as_str(), rate.price.as_str()), ("custom", "15000000"));
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_converted_amount_outside_the_bounds() {
        let merchant = merchant();
        merchant.set_pay_field("minSendable", Some(Json::unsigned(100_000)));
        let client = merchant.client().rate_source(price("100000")).build().unwrap();
        let error = client.create_invoice(&Order::fiat("G-3", "0.05", "CHF")).await.unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("fiat")));
    }
}

mod one_order_one_invoice_at_a_time {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn refuses_a_second_invoice_while_the_first_may_be_paid_then_allows_one() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let first = client.create_invoice(&Order::sats("H-1", 1).duration_seconds(60)).await.unwrap();
        let pending = client.create_invoice(&Order::sats("H-1", 1)).await.unwrap_err();
        assert_eq!(pending.code(), ErrorCode::InvoicePending);
        let declared = pending.invoice().unwrap();
        assert_eq!(declared.bolt11, first.bolt11);
        assert_eq!(declared.expires_at, first.expires_at);
        assert_eq!(declared.sats, 1);
        assert_eq!(declared.fiat, None);
        assert_eq!(declared.note, "H-1");
        // Its end, then the 120 s a late payment may still be reported in.
        merchant.set_now(first.expires_at + 119);
        assert_eq!(code(client.create_invoice(&Order::sats("H-1", 1)).await), ErrorCode::InvoicePending);
        merchant.set_now(first.expires_at + 120);
        let second = client.create_invoice(&Order::sats("H-1", 1)).await.unwrap();
        assert_ne!(second.bolt11, first.bolt11);
        // Another order is another sale.
        client.create_invoice(&Order::sats("H-2", 1)).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_new_invoice_for_an_order_already_paid() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let first = client.create_invoice(&Order::sats("H-3", 1).duration_seconds(60)).await.unwrap();
        let hash = first.payment_hash.clone().unwrap();
        merchant.pay_invoice(&hash);
        merchant.set_now(first.expires_at + 600);
        let error = client.create_invoice(&Order::sats("H-3", 1)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::OrderPaid);
        assert_eq!(error.preimage(), Some(merchant.invoice(&hash).unwrap().preimage.as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_new_invoice_for_an_order_paid_while_its_invoice_may_still_be_paid() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let first = client.create_invoice(&Order::sats("H-4", 1).checkout(false)).await.unwrap();
        let hash = first.payment_hash.clone().unwrap();
        merchant.pay_invoice(&hash);
        // Within its time: its payment checked even alone (SPEC.md §21, step 1).
        let error = client.create_invoice(&Order::sats("H-4", 1)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::OrderPaid);
        assert_eq!(error.invoice().unwrap().bolt11, first.bolt11);
        assert_eq!(
            serde_json::to_value(error.status().unwrap()).unwrap(),
            serde_json::json!({ "state": "paid", "method": "lightning", "preimage": merchant.invoice(&hash).unwrap().preimage })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gives_the_error_of_the_payment_check_of_the_only_invoice_that_may_still_be_paid() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let first = client.create_invoice(&Order::sats("H-5", 1)).await.unwrap();
        // Its Lightning address does not answer: it may have been paid.
        merchant.set_override(Some(|call: &super::super::support::http::Call| {
            call.url.starts_with("https://breez.tips/lnurlp/verify/").then(|| Answer::text(503, ""))
        }));
        assert_eq!(code(client.create_invoice(&Order::sats("H-5", 1)).await), ErrorCode::Network);
        merchant.set_override(None::<fn(&super::super::support::http::Call) -> Option<Answer>>);
        let pending = client.create_invoice(&Order::sats("H-5", 1)).await.unwrap_err();
        assert_eq!(pending.invoice().unwrap().bolt11, first.bolt11);
    }

    #[tokio::test(start_paused = true)]
    async fn declares_a_pending_invoice_on_a_majority_again_before_handing_it_out() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let a = merchant.net.get("wss://relay-a.test");
        let b = merchant.net.get("wss://relay-b.test");
        a.set_behaviour(RelayBehaviour::refusing("blocked: no"));
        b.set_behaviour(RelayBehaviour::refusing("blocked: no"));
        assert_eq!(code(client.create_invoice(&Order::sats("H-7", 1)).await), ErrorCode::Network);
        let made = merchant.invoices()[0].clone();
        // Only relay-c holds its declaration. relay-a answers reads late: relay-b and relay-c are
        // the majority read, and the declaration found is not handed out while the others refuse it.
        a.set_behaviour(RelayBehaviour {
            refuse: Some("blocked: no".to_owned()),
            query_delay_ms: Some(300),
            ..RelayBehaviour::default()
        });
        assert_eq!(code(client.create_invoice(&Order::sats("H-7", 1)).await), ErrorCode::Network);
        // Now a majority takes it again: then, and only then, it is handed out.
        a.set_behaviour(RelayBehaviour::delayed(300));
        b.set_behaviour(RelayBehaviour::default());
        let pending = client.create_invoice(&Order::sats("H-7", 1)).await.unwrap_err();
        assert_eq!(pending.code(), ErrorCode::InvoicePending);
        assert_eq!(pending.invoice().unwrap().bolt11.as_deref(), Some(made.pr.as_str()));
        let sale = sale_keys(&merchant.integration_key, "H-7").author;
        for url in &merchant.key_relays {
            let held = merchant
                .net
                .get(url)
                .events()
                .into_iter()
                .filter(|event| event.get("pubkey").and_then(Json::as_str) == Some(sale.as_str()))
                .count();
            assert_eq!(held, 1, "{url}");
        }
        assert_eq!(merchant.invoices().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn may_make_another_invoice_when_the_majority_read_lacks_one_never_handed_out() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        merchant.net.get("wss://relay-a.test").set_behaviour(RelayBehaviour::refusing("blocked: no"));
        merchant.net.get("wss://relay-b.test").set_behaviour(RelayBehaviour::refusing("blocked: no"));
        // Declared on relay-c alone: "do not show this invoice".
        assert_eq!(code(client.create_invoice(&Order::sats("H-10", 1)).await), ErrorCode::Network);
        // relay-a and relay-b answer first, without it: a new invoice, declared on a majority.
        merchant.net.get("wss://relay-a.test").set_behaviour(RelayBehaviour::default());
        merchant.net.get("wss://relay-b.test").set_behaviour(RelayBehaviour::default());
        merchant.net.get("wss://relay-c.test").set_behaviour(RelayBehaviour::delayed(300));
        let second = client.create_invoice(&Order::sats("H-10", 1)).await.unwrap();
        assert_eq!(merchant.invoices().len(), 2);
        assert_eq!(second.bolt11.as_deref(), Some(merchant.invoices()[1].pr.as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_new_invoice_for_a_paid_order_even_when_another_check_gets_no_answer() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let first = client.create_invoice(&Order::sats("H-8", 1).duration_seconds(60)).await.unwrap();
        merchant.set_now(first.expires_at + 120);
        let second = client.create_invoice(&Order::sats("H-8", 1).duration_seconds(60)).await.unwrap();
        merchant.pay_invoice(second.payment_hash.as_deref().unwrap());
        merchant.set_now(second.expires_at + 600);
        let first_hash = first.payment_hash.clone().unwrap();
        merchant.set_override(Some(move |call: &super::super::support::http::Call| {
            call.path().ends_with(&first_hash).then(|| Answer::status_json(502, &j!({})))
        }));
        let error = client.create_invoice(&Order::sats("H-8", 1)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::OrderPaid);
        assert_eq!(error.invoice().unwrap().bolt11, second.bolt11);
        // Unpaid, one check without an answer: retry later.
        let other = client.create_invoice(&Order::sats("H-9", 1).duration_seconds(60)).await.unwrap();
        merchant.set_now(other.expires_at + 120);
        let other_hash = other.payment_hash.clone().unwrap();
        merchant.set_override(Some(move |call: &super::super::support::http::Call| {
            call.path().ends_with(&other_hash).then(|| Answer::status_json(502, &j!({})))
        }));
        assert_eq!(code(client.create_invoice(&Order::sats("H-9", 1)).await), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn makes_one_invoice_when_two_calls_for_one_order_race() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let order = Order::sats("H-4", 1);
        let (a, b) = tokio::join!(client.create_invoice(&order), client.create_invoice(&order));
        assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
        let error = a.err().or(b.err()).unwrap();
        assert_eq!(error.code(), ErrorCode::InvoicePending);
        assert_eq!(merchant.invoices().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn finds_the_invoices_declared_for_an_order_and_needs_a_majority_to() {
        let merchant = merchant();
        let client = merchant.client().rate_source(price("69012")).build().unwrap();
        let first =
            client.create_invoice(&Order::fiat("H-5", "24.50", "CHF").duration_seconds(60)).await.unwrap();
        merchant.set_now(first.expires_at + 120);
        let second = client.create_invoice(&Order::sats("H-5", 7)).await.unwrap();
        let found = client.find_invoices("H-5").await.unwrap();
        let bolt11s: Vec<Option<String>> = found.iter().map(|invoice| invoice.bolt11.clone()).collect();
        assert_eq!(bolt11s, vec![first.bolt11.clone(), second.bolt11.clone()]);
        assert_eq!(
            serde_json::to_value(&found[0]).unwrap(),
            serde_json::json!({
                "ref": "H-5",
                "bolt11": first.bolt11,
                "paymentHash": first.payment_hash,
                "verifyUrl": first.verify_url,
                "onchainAddress": null,
                "paymentUri": format!("lightning:{}", first.bolt11.as_deref().unwrap()),
                "sats": "35502",
                "fiat": { "amount": "24.50", "currency": "CHF", "minor": "2450", "digits": 2 },
                "note": "H-5",
                "createdAt": first.created_at,
                "expiresAt": first.expires_at,
                "declaredAt": first.created_at
            })
        );
        assert_eq!((found[1].sats, found[1].fiat.clone()), (7, None));
        assert!(client.find_invoices("H-6").await.unwrap().is_empty());
        merchant.net.remove("wss://relay-a.test");
        merchant.net.remove("wss://relay-b.test");
        assert_eq!(code(client.find_invoices("H-5").await), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_invalid_reference_to_find() {
        let merchant = merchant();
        let error = merchant.client().build().unwrap().find_invoices("CMD 1").await.unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("ref")));
    }
}

mod relays_one_connection_each_per_call_a_majority_waited_for {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn makes_an_invoice_over_one_connection_per_relay_earlier_invoices_read_included() {
        let merchant = merchant();
        let client = merchant.client().build().unwrap();
        let first = client.create_invoice(&Order::sats("R-1", 1).duration_seconds(60)).await.unwrap();
        for url in &merchant.key_relays {
            assert_eq!(merchant.net.connections(url), 1, "{url}");
        }
        merchant.set_now(first.expires_at + 120);
        // The channel, the order's declarations page after page, the new declaration: one connection.
        client.create_invoice(&Order::sats("R-1", 1).duration_seconds(60)).await.unwrap();
        for url in &merchant.key_relays {
            assert_eq!(merchant.net.connections(url), 2, "{url}");
        }
        tokio::task::yield_now().await;
        for url in &merchant.key_relays {
            let relay = merchant.net.get(url);
            // Every subscription closed once read, and every connection once the call is done.
            assert!(!relay.closed_subscriptions().is_empty(), "{url}");
            assert_eq!(relay.open_connections(), 0, "{url}");
        }
    }

    async fn is_not_slowed_by_a_relay_that_never_answers(blackhole: bool) {
        let merchant = merchant();
        if blackhole {
            merchant.net.remove("wss://relay-c.test");
            merchant.net.add_blackhole("wss://relay-c.test");
        } else {
            merchant.net.get("wss://relay-c.test").set_behaviour(RelayBehaviour::mute());
        }
        let client = merchant.client().relay_timeout_ms(5000).build().unwrap();
        let started = Instant::now();
        client.create_invoice(&Order::sats("R-2", 1)).await.unwrap();
        assert!(started.elapsed().as_millis() < 1500, "{:?}", started.elapsed());
        assert_eq!(client.find_invoices("R-2").await.unwrap().len(), 1);
        assert!(started.elapsed().as_millis() < 3000, "{:?}", started.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_slowed_by_a_relay_that_never_answers_mute() {
        is_not_slowed_by_a_relay_that_never_answers(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_slowed_by_a_relay_that_never_answers_blackhole() {
        is_not_slowed_by_a_relay_that_never_answers(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_its_future_is_dropped_and_closes_its_connections() {
        let merchant = merchant();
        for url in &merchant.key_relays {
            merchant.net.get(url).set_behaviour(RelayBehaviour::delayed(2000));
        }
        let client = merchant.client().relay_timeout_ms(5000).build().unwrap();
        let started = Instant::now();
        // The shop's own deadline: the checkout left.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.create_invoice(&Order::sats("R-3", 1)),
        )
        .await;
        assert!(result.is_err(), "cancelled, with no error of the crate");
        assert!(started.elapsed().as_millis() < 1000);
        tokio::task::yield_now().await;
        for url in &merchant.key_relays {
            assert_eq!(merchant.net.get(url).open_connections(), 0, "{url}");
        }
        // Nothing more happens: the relays' late answers reach no one.
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert!(merchant.invoices().is_empty());
        assert!(merchant.declarations().is_empty());
    }
}

mod rates_by_name {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn takes_a_source_by_its_name_coingecko_with_its_demo_key() {
        let merchant = merchant();
        let now = merchant.now();
        merchant.set_override(Some(move |call: &super::super::support::http::Call| {
            match call.host().as_str() {
                "api.coingecko.com" => {
                    Some(Answer::json(&j!({ "bitcoin": { "chf": 69012, "last_updated_at": now - 30 } })))
                }
                "api.kraken.com" => Some(Answer::json(
                    &j!({ "error": [], "result": { "XBTCHF": { "c": ["70000.0", "0.1"] } } }),
                )),
                _ => None,
            }
        }));
        let client = merchant
            .client()
            .rate_source(RateSource::Coingecko)
            .coingecko_api_key("demo-key")
            .build()
            .unwrap();
        let invoice = client.create_invoice(&Order::fiat("S-1", "24.50", "CHF")).await.unwrap();
        assert_eq!(invoice.sats, 35_502);
        let rate = invoice.rate.unwrap();
        assert_eq!((rate.source.as_str(), rate.price.as_str()), ("coingecko", "69012"));
        let call = merchant.http.calls().into_iter().find(|call| call.host() == "api.coingecko.com").unwrap();
        assert_eq!(call.header("x-cg-demo-api-key"), Some("demo-key"));
        let other = client
            .create_invoice(&Order::fiat("S-2", "7", "CHF").rate_source(RateSource::Kraken))
            .await
            .unwrap();
        let rate = other.rate.unwrap();
        assert_eq!((rate.source.as_str(), rate.price.as_str()), ("kraken", "70000"));
    }

    #[test]
    fn refuses_an_unknown_source_when_the_client_is_made() {
        let merchant = TestMerchant::new();
        assert_eq!("bitstamp".parse::<RateSource>().unwrap_err().code(), ErrorCode::InvalidOption);
        for sources in [vec![], vec![RateSource::Kraken, RateSource::Kraken]] {
            let error = merchant.client().rate_sources(sources).build().unwrap_err();
            assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOption, Some("rateSource")));
        }
        let error = merchant.client().coingecko_api_key("").build().unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOption, Some("coingeckoApiKey")));
    }

    #[tokio::test(start_paused = true)]
    async fn without_rate_source_asks_the_default_list_in_order_until_one_gives_a_price() {
        let merchant = merchant();
        let now = merchant.now();
        merchant.set_override(Some(move |call: &super::super::support::http::Call| {
            match call.host().as_str() {
                "api.coingecko.com" => {
                    Some(Answer::status_json(429, &j!({ "status": { "error_code": 429 } })))
                }
                "mempool.space" => Some(Answer::json(&j!({ "time": now - 10, "CHF": 69012 }))),
                _ => None,
            }
        }));
        let warnings = Warnings::default();
        let client = merchant.client().logger(warnings.clone()).build().unwrap();
        let invoice = client.create_invoice(&Order::fiat("D-1", "24.50", "CHF")).await.unwrap();
        assert_eq!(invoice.sats, 35_502);
        let rate = invoice.rate.unwrap();
        assert_eq!((rate.source.as_str(), rate.price.as_str()), ("mempool", "69012"));
        let asked: Vec<String> = merchant
            .http
            .calls()
            .iter()
            .map(|call| call.host())
            .filter(|host| !host.ends_with("breez.tips"))
            .collect();
        assert_eq!(asked, vec!["api.coingecko.com".to_owned(), "mempool.space".to_owned()]);
        // No key given: CoinGecko is asked without one.
        let call = merchant.http.calls().into_iter().find(|call| call.host() == "api.coingecko.com").unwrap();
        assert_eq!(call.header("x-cg-demo-api-key"), None);
        assert_eq!(
            warnings.all(),
            vec![
                "Rate source coingecko failed (network): coingecko answered HTTP 429; trying mempool"
                    .to_owned()
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn asks_an_order_list_in_its_order_and_only_that_list() {
        let merchant = merchant();
        merchant.set_override(Some(|call: &super::super::support::http::Call| match call.host().as_str() {
            "api.kraken.com" => Some(Answer::json(&j!({ "error": ["EQuery:Unknown asset pair"] }))),
            "api.coinbase.com" => {
                Some(Answer::json(&j!({ "data": { "currency": "BTC", "rates": { "CHF": "69012.00" } } })))
            }
            _ => None,
        }));
        let client = merchant.client().rate_source(RateSource::Coingecko).build().unwrap();
        let order =
            Order::fiat("D-2", "24.50", "CHF").rate_sources([RateSource::Kraken, RateSource::Coinbase]);
        let invoice = client.create_invoice(&order).await.unwrap();
        let rate = invoice.rate.unwrap();
        assert_eq!((rate.source.as_str(), rate.price.as_str()), ("coinbase", "69012"));
        let hosts: Vec<String> = merchant.http.calls().iter().map(|call| call.host()).collect();
        assert!(hosts.contains(&"api.kraken.com".to_owned()));
        assert!(!hosts.contains(&"api.coingecko.com".to_owned()));
    }

    #[tokio::test(start_paused = true)]
    async fn gives_the_last_network_or_rate_error_when_no_source_of_the_list_has_a_price() {
        let merchant = merchant();
        merchant.set_override(Some(|call: &super::super::support::http::Call| match call.host().as_str() {
            "api.kraken.com" => Some(Answer::json(&j!({ "error": ["EQuery:Unknown asset pair"] }))),
            "api.coinbase.com" => Some(Answer::status_json(503, &j!({}))),
            _ => None,
        }));
        let client = merchant.client().build().unwrap();
        let order = Order::fiat("D-3", "1", "CHF").rate_sources([RateSource::Coinbase, RateSource::Kraken]);
        assert_eq!(code(client.create_invoice(&order).await), ErrorCode::Network);
        // Only sources without the currency: unsupported_currency, naming them.
        let order = Order::fiat("D-4", "1", "THB").rate_sources([RateSource::Kraken, RateSource::Mempool]);
        let error = client.create_invoice(&order).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsupportedCurrency);
        assert_eq!(error.message(), "None of kraken, mempool has a price in THB");
        assert_eq!(error.currency(), Some("THB"));
        assert!(merchant.invoices().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn puts_an_order_pending_invoice_before_a_failing_rate_source() {
        let merchant = merchant();
        let client = merchant.client().rate_source(price("69012")).build().unwrap();
        client.create_invoice(&Order::fiat("S-3", "1", "CHF")).await.unwrap();
        let failing = merchant
            .client()
            .rate_source(RateSource::custom(Failing(Error::network("down"))))
            .build()
            .unwrap();
        assert_eq!(
            code(failing.create_invoice(&Order::fiat("S-3", "1", "CHF")).await),
            ErrorCode::InvoicePending
        );
        assert_eq!(code(failing.create_invoice(&Order::fiat("S-4", "1", "CHF")).await), ErrorCode::Network);
        assert_eq!(merchant.invoices().len(), 1);
    }
}
