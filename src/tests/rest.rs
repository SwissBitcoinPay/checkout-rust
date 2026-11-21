//! The rest of an on-chain underpayment (SPEC.md §31, The rest of an underpayment), end to end
//! against local relays and fakes of breez.tips and of the explorers: the invoice of the rest
//! asked by a payment check, declared with `rest` and published in a rest record that a checkout
//! link's page reads; asked once, never without time left nor outside the Lightning address's
//! bounds; a failure only logged; what the rest invoices paid counted with the on-chain payment
//! (`mixed`).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use super::support::chain::{EsploraTx, deposit_address, payment, txid};
use super::support::http::{Answer, Call};
use super::support::j;
use super::support::merchant::{CALLBACK, MadeInvoice, PAY_URL, TestMerchant, Warnings, metadata};
use crate::checkout::{CheckoutFragment, checkout_keys, parse_checkout_fragment, parse_checkout_value};
use crate::client::{Client, WaitOptions};
use crate::declaration::{OpenedDeclaration, RestOf, open_declaration, registry_of};
use crate::derive::{Sale, rest_keys, rest_record_address, sale_of};
use crate::error::ErrorCode;
use crate::json::{self, Json, JsonString};
use crate::model::{Invoice, PaymentStatus};
use crate::nostr::event::{Event, valid_event};
use crate::nostr::nip44::decrypt;
use crate::nostr::record::{Opened, Seal, seal_record};
use crate::onchain::rest::{RestInvoice, RestLinkTerms, RestReaderKeys, open_rest_event};
use crate::order::Order;
use crate::runtime::OsRandom;
use crate::text::to_hex;

const ORIGIN: &str = "https://pay.example";

fn address() -> String {
    deposit_address(1)
}

struct Setup {
    merchant: TestMerchant,
    warnings: Warnings,
    client: Client,
    invoice: Invoice,
}

impl Setup {
    fn client(&self) -> Client {
        self.merchant.client().logger(self.warnings.clone()).build().unwrap()
    }
}

async fn setup() -> Setup {
    let merchant = TestMerchant::new().start();
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    merchant.publish_channel(
        &merchant.channel_value(
            100,
            Json::object([("relays", relays), ("checkout", Json::object([("origin", Json::from(ORIGIN))]))]),
        ),
        100,
    );
    merchant.publish_lot(&[address()], 90);
    let warnings = Warnings::default();
    let client = merchant.client().logger(warnings.clone()).build().unwrap();
    let invoice = client
        .create_invoice(&Order::sats("R-1", 49_000).duration_seconds(600).note("Order 1").checkout(true))
        .await
        .unwrap();
    assert_eq!(invoice.onchain_address.as_deref(), Some(address().as_str()));
    Setup { merchant, warnings, client, invoice }
}

/// The events every relay holds now (the first relay's), checked.
fn held(merchant: &TestMerchant) -> Vec<Event> {
    merchant.net.get(&merchant.key_relays[0]).events().iter().filter_map(valid_event).collect()
}

fn sale_of_ref(merchant: &TestMerchant, reference: &str) -> Sale {
    sale_of(
        &merchant.integration_key,
        &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
        reference,
    )
}

/// The declarations of the sale of `reference` the relays hold, opened as the sale.
fn declarations(merchant: &TestMerchant, reference: &str) -> Vec<OpenedDeclaration> {
    let sale = sale_of_ref(merchant, reference);
    held(merchant)
        .iter()
        .filter_map(|event| match open_declaration(event, &sale)? {
            Opened::Valid { value, .. } => Some(value),
            Opened::Newer { .. } => None,
        })
        .collect()
}

/// The rest records of `invoice` the relays hold, as a checkout link's page opens them.
fn rest_records(merchant: &TestMerchant, invoice: &Invoice) -> Vec<RestInvoice> {
    let keys = rest_keys(
        &merchant.integration_key,
        &invoice.reference,
        invoice.onchain_address.as_deref().unwrap(),
        invoice.expires_at,
    );
    let reader = RestReaderKeys::of(&keys);
    let terms =
        RestLinkTerms { sats: invoice.sats, created_at: invoice.created_at, expires_at: invoice.expires_at };
    held(merchant).iter().filter_map(|event| open_rest_event(event, &reader, &terms)?.ok()).collect()
}

/// The invoices breez.tips made of `sats`.
fn made_of(merchant: &TestMerchant, sats: u128) -> Vec<MadeInvoice> {
    merchant.invoices().into_iter().filter(|made| made.amount_msat == sats * 1000).collect()
}

fn json(status: &PaymentStatus) -> serde_json::Value {
    serde_json::to_value(status).unwrap()
}

fn rest_bolt11(status: &PaymentStatus) -> Option<Option<String>> {
    match status {
        PaymentStatus::Open { rest, .. } => rest.as_ref().map(|rest| rest.bolt11.clone()),
        _ => None,
    }
}

mod an_onchain_underpayment {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn asks_an_invoice_of_the_rest_declares_it_with_rest_and_publishes_its_record() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.advance(60);
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let status = client.get_status(&invoice).await.unwrap();
        let made = made_of(&merchant, 29_000).into_iter().next().expect("an invoice of the rest");
        assert_eq!(
            json(&status),
            serde_json::json!({
                "state": "open",
                "expiresAt": invoice.expires_at,
                "received": "20000",
                "rest": { "sats": "29000", "bolt11": made.pr, "paymentUri": format!("bitcoin:{address}?amount=0.00029&lightning={}", made.pr) }
            })
        );
        // Until the invoice's end, with the order's note.
        assert_eq!(made.expiry as i64, invoice.expires_at - merchant.now());
        assert_eq!(made.comment.as_deref(), Some("Order 1"));
        // Declared for the order's sale, with the order's price and note, marked as a rest.
        assert!(declarations(&merchant, "R-1").iter().any(|declaration| declaration.invoice == made.pr
            && declaration.note == "Order 1"
            && declaration.rest
                == Some(RestOf { address: address.clone(), expires_at: invoice.expires_at })));
        // Its record, which the checkout link's page reads with the keys its link's record carries.
        let records = rest_records(&merchant, &invoice);
        assert_eq!(records.len(), 1);
        assert_eq!(
            (records[0].bolt11.as_str(), records[0].sats, records[0].verify_url.as_str()),
            (made.pr.as_str(), 29_000, made.verify.as_str())
        );
        let url = invoice.checkout_url.clone().unwrap();
        let CheckoutFragment::Link { link_key, .. } = parse_checkout_fragment(&url[url.find('#').unwrap()..])
        else {
            panic!("Not a link")
        };
        let keys = checkout_keys(&link_key);
        let event = held(&merchant)
            .into_iter()
            .find(|event| {
                event.tags.iter().any(|tag| {
                    tag.first().map(String::as_str) == Some("d") && tag.get(1) == Some(&keys.address)
                })
            })
            .unwrap();
        let value = json::parse(&decrypt(&event.content, &keys.encryption_key).unwrap())
            .unwrap()
            .get("v")
            .unwrap()
            .clone();
        let rest = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let reader = parse_checkout_value(&value).unwrap().unwrap().rest.unwrap();
        assert_eq!((reader.author, reader.key), (rest.author.clone(), to_hex(rest.key.expose())));
        // The rest invoice is no invoice of the order.
        let found = client.find_invoices("R-1").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].bolt11.as_deref(), found[0].onchain_address.as_deref()),
            (invoice.bolt11.as_deref(), Some(address.as_str()))
        );
        assert!(warnings.all().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn is_asked_by_create_invoice_check_of_the_order_pending_invoice_before_invoice_pending() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.advance(60);
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        // Its payment checked, alone (SPEC.md §21 step 1): as any payment check, it asks for the rest.
        let pending = client.create_invoice(&Order::sats("R-1", 49_000).checkout(true)).await.unwrap_err();
        assert_eq!(pending.code(), ErrorCode::InvoicePending);
        assert_eq!(pending.invoice().unwrap().onchain_address.as_deref(), Some(address.as_str()));
        let made = made_of(&merchant, 29_000).into_iter().next().expect("an invoice of the rest");
        assert!(declarations(&merchant, "R-1").iter().any(|declaration| declaration.invoice == made.pr
            && declaration.rest
                == Some(RestOf { address: address.clone(), expires_at: invoice.expires_at })));
        // Its record, for the pages of the order's checkout links (the new one included).
        let records = rest_records(&merchant, &invoice);
        assert_eq!(
            records.iter().map(|record| record.bolt11.as_str()).collect::<Vec<_>>(),
            vec![made.pr.as_str()]
        );
        // Shown by the next check, never asked again.
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(Some(made.pr.clone())));
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
        assert!(warnings.all().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn asks_it_once_and_again_for_a_new_rest() {
        let setup = setup().await;
        let Setup { merchant, client, invoice, .. } = &setup;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let first = client.get_status(invoice).await.unwrap();
        assert_eq!(setup.client().get_status(invoice).await.unwrap(), first);
        assert_eq!(made_of(merchant, 29_000).len(), 1);
        // More sent on-chain: a new rest, a new invoice of it.
        merchant.chain.add(&address, payment(&txid("more"), &address, 10_000));
        let second = client.get_status(invoice).await.unwrap();
        let PaymentStatus::Open { received, rest: Some(rest), .. } = &second else { panic!("{second:?}") };
        assert_eq!((*received, rest.sats), (30_000, 19_000));
        assert_eq!(made_of(merchant, 19_000).len(), 1);
        let mut sats: Vec<u64> = rest_records(merchant, invoice).iter().map(|record| record.sats).collect();
        sats.sort_unstable();
        assert_eq!(sats, vec![19_000, 29_000]);
    }

    #[tokio::test(start_paused = true)]
    async fn is_lightning_only_below_1000_sats() {
        let Setup { merchant, client, invoice, .. } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 48_500));
        let status = client.get_status(&invoice).await.unwrap();
        let made = made_of(&merchant, 500).into_iter().next().unwrap();
        let PaymentStatus::Open { received, rest: Some(rest), .. } = &status else { panic!("{status:?}") };
        assert_eq!(*received, 48_500);
        assert_eq!(
            (rest.sats, rest.bolt11.as_deref(), rest.payment_uri.clone()),
            (500, Some(made.pr.as_str()), Some(format!("lightning:{}", made.pr)))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn asks_none_with_less_than_a_minute_left_nor_outside_the_lightning_address_bounds() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        merchant.set_now(invoice.expires_at - 59);
        let status = client.get_status(&invoice).await.unwrap();
        assert_eq!(
            json(&status)["rest"],
            serde_json::json!({ "sats": "29000", "bolt11": null, "paymentUri": format!("bitcoin:{address}?amount=0.00029") })
        );
        merchant.set_now(invoice.expires_at - 600);
        let pay = merchant.pay();
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(28_000_000)));
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        merchant.set_pay(pay);
        merchant.set_pay_field("minSendable", Some(Json::unsigned(29_001_000)));
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        assert!(made_of(&merchant, 29_000).is_empty());
        assert!(warnings.all().is_empty());
        // Past the end, no rest at all.
        merchant.set_now(invoice.expires_at);
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Open { rest: None, .. }), "{status:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn logs_a_lightning_address_that_fails_and_asks_again_at_the_next_check() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        merchant.set_override(Some(|call: &Call| {
            (call.path() == CALLBACK).then(|| Answer::status_json(500, &j!({ "oops": true })))
        }));
        let status = client.get_status(&invoice).await.unwrap();
        assert_eq!(rest_bolt11(&status), Some(None));
        let logged = warnings.all();
        assert_eq!(logged.len(), 1);
        assert!(logged[0].contains("no Lightning invoice of the rest"), "{}", logged[0]);
        merchant.set_override(None::<fn(&Call) -> Option<Answer>>);
        let again = client.get_status(&invoice).await.unwrap();
        assert_eq!(rest_bolt11(&again), Some(Some(made_of(&merchant, 29_000).last().unwrap().pr.clone())));
    }

    #[tokio::test(start_paused = true)]
    async fn logs_a_pay_request_whose_metadata_holds_a_lone_surrogate_and_gives_the_status() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        // No UTF-8 to hash (SPEC.md §16): no invoice of the rest is asked, the status is given
        // (SPEC.md §23), the failure logged.
        let mut units: Vec<u16> = metadata().encode_utf16().collect();
        units.insert(units.len() - 3, 0xd800);
        merchant.set_pay_field("metadata", Some(Json::String(JsonString::Units(units))));
        let asked = merchant.http.calls().len();
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Open { received: 20_000, .. }), "{status:?}");
        assert_eq!(rest_bolt11(&status), Some(None));
        assert!(merchant.http.calls()[asked..].iter().all(|call| call.path() != CALLBACK));
        assert!(merchant.http.calls()[asked..].iter().any(|call| call.path() == PAY_URL));
        let logged = warnings.all();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("no Lightning invoice of the rest"), "{}", logged[0]);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_invoice_that_does_not_pay_the_merchant_logged() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        merchant.set_tamper(Some(|made: MadeInvoice| MadeInvoice {
            pr: format!("{}qqqqqqqq", &made.pr[..made.pr.len() - 8]),
            ..made
        }));
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        assert_eq!(warnings.all().len(), 1);
        assert!(declarations(&merchant, "R-1").iter().all(|declaration| declaration.rest.is_none()));
    }

    #[tokio::test(start_paused = true)]
    async fn checks_an_invoice_of_the_rest_another_check_asked_meanwhile() {
        let Setup { merchant, client, invoice, .. } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        // Paid as soon as it is made: the check that waited for the other finds it paid.
        let marker = merchant.pay_marker();
        merchant.set_tamper(Some(move |made: MadeInvoice| {
            marker(&made.payment_hash);
            made
        }));
        let (first, second) = tokio::join!(client.get_status(&invoice), client.get_status(&invoice));
        let made = made_of(&merchant, 29_000);
        assert_eq!(made.len(), 1);
        let first = first.unwrap();
        assert_eq!(rest_bolt11(&first), Some(Some(made[0].pr.clone())), "{first:?}");
        let second = second.unwrap();
        assert!(matches!(second, PaymentStatus::Unconfirmed { received: 49_000, .. }), "{second:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn declares_again_on_a_majority_an_invoice_of_the_rest_a_minority_holds_before_it_is_used() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let sale = sale_of_ref(&merchant, "R-1");
        let relays: Vec<_> = merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect();
        let (a, b, c) = (&relays[0], &relays[1], &relays[2]);
        let author = sale.author.clone();
        let refuse: super::super::support::relay::OnRefuse =
            Arc::new(move |event: &Event| (event.pubkey == author).then(|| "blocked".to_owned()));
        // Its declaration reaches one relay of three: not to be shown.
        b.update(|behaviour| behaviour.refuse_event = Some(refuse.clone()));
        c.update(|behaviour| behaviour.refuse_event = Some(refuse.clone()));
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        assert_eq!(warnings.all().len(), 1);
        let made = made_of(&merchant, 29_000).into_iter().next().unwrap();
        // Still refused: read on the relay that holds it, it cannot be declared on a majority, so
        // nothing is told of the rest (and no other invoice of it is asked).
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
        // Taken again, the third relay slow: read on the first two, declared on a majority, shown.
        b.update(|behaviour| behaviour.refuse_event = None);
        c.update(|behaviour| {
            behaviour.refuse_event = None;
            behaviour.query_delay_ms = Some(500);
        });
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(Some(made.pr.clone())));
        let declared = |relay: &super::super::support::relay::LocalRelay| {
            relay.events().iter().filter_map(valid_event).any(|event| {
                event.pubkey == sale.author
                    && matches!(open_declaration(&event, &sale), Some(Opened::Valid { value, .. }) if value.decoded.payment_hash == made.payment_hash)
            })
        };
        assert!([a, b, c].iter().filter(|relay| declared(relay)).count() >= 2);
        // Paid, then read without the first relay: still counted, never asked again.
        merchant.pay_invoice(&made.payment_hash);
        c.update(|behaviour| behaviour.query_delay_ms = Some(0));
        a.update(|behaviour| behaviour.query_delay_ms = Some(500));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: 49_000, .. }), "{status:?}");
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn shows_an_invoice_of_the_rest_only_once_its_record_is_on_a_majority_of_the_relays() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let author = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at).author;
        let relays: Vec<_> = merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect();
        let recorded_on = || {
            relays
                .iter()
                .filter(|relay| {
                    relay
                        .events()
                        .iter()
                        .any(|event| event.get("pubkey").and_then(Json::as_str) == Some(author.as_str()))
                })
                .count()
        };
        // Its record taken by one relay of three: a checkout link's page reading the other two
        // would not see it, nor its payment. Declared, never shown.
        for relay in &relays[1..] {
            let author = author.clone();
            relay.update(move |behaviour| {
                behaviour.refuse_event = Some(Arc::new(move |event: &Event| {
                    (event.pubkey == author).then(|| "blocked: not now".to_owned())
                }));
            });
        }
        let status = client.get_status(&invoice).await.unwrap();
        assert_eq!(
            json(&status)["rest"],
            serde_json::json!({ "sats": "29000", "bolt11": null, "paymentUri": format!("bitcoin:{address}?amount=0.00029") })
        );
        assert_eq!(recorded_on(), 1);
        assert!(
            warnings.all()[0].contains("record of an invoice of the rest was not published"),
            "{:?}",
            warnings.all()
        );
        // Still refused: still not shown, never asked again.
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        let made = made_of(&merchant, 29_000).into_iter().next().unwrap();
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
        // Taken: published again on a majority at the next check, shown.
        for relay in &relays {
            relay.update(|behaviour| behaviour.refuse_event = None);
        }
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(Some(made.pr.clone())));
        assert!(recorded_on() >= 2);
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn never_publishes_a_rest_record_over_one_of_a_newer_format_which_records_it_and_warns() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let relays: Vec<_> = merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect();
        // Its record taken by the first relay alone: not known on a majority yet.
        for relay in &relays[1..] {
            let author = keys.author.clone();
            relay.update(move |behaviour| {
                behaviour.refuse_event = Some(Arc::new(move |event: &Event| {
                    (event.pubkey == author).then(|| "blocked: not now".to_owned())
                }));
            });
        }
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        let made = made_of(&merchant, 29_000).into_iter().next().unwrap();
        // A newer version wrote that invoice's record on the second relay, in a format (its version
        // 2) this one cannot read.
        let d = rest_record_address(&keys.key, &made.payment_hash);
        let newer = seal_record(
            Seal {
                record_type: "checkout-rest",
                value: j!({ "version": 2 }),
                signer: &keys.secret_key,
                encryption_key: &keys.encryption_key,
                address: &d,
                created_at: merchant.now() - 1,
                tags: vec![vec!["expiration".to_owned(), (invoice.expires_at + 604_800).to_string()]],
            },
            &OsRandom,
        )
        .unwrap();
        relays[1].take(&newer);
        for relay in &relays {
            relay.update(|behaviour| behaviour.refuse_event = None);
        }
        let written = || {
            relays
                .iter()
                .flat_map(|relay| relay.received())
                .filter(|event| event.tag("d") == Some(d.as_str()))
                .count()
        };
        let before = written();
        warnings.0.lock().unwrap().clear();
        // A newer version recorded the invoice: it is shown, and nothing is published over that
        // record, nor anywhere else at its address.
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(Some(made.pr.clone())));
        assert_eq!(written(), before);
        assert!(relays[1].events().contains(&newer.to_json()));
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
        let logged = warnings.all();
        assert!(
            logged.iter().any(|warning| {
                warning.contains("record of an invoice of the rest of an underpayment has a newer format")
            }),
            "{logged:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn asks_the_rest_with_the_expiry_and_the_dates_of_the_clock_read_when_deciding() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.advance(60);
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let decided = merchant.now();
        // The Lightning address answers its pay request 5 s later.
        let clock = merchant.clock.clone();
        merchant.set_override(Some(move |call: &Call| {
            if call.url == PAY_URL {
                clock.advance(5);
            }
            None
        }));
        let status = client.get_status(&invoice).await.unwrap();
        let made = made_of(&merchant, 29_000).into_iter().next().expect("an invoice of the rest");
        assert_eq!(rest_bolt11(&status), Some(Some(made.pr.clone())));
        // Its expiry, its declaration and its record: of the time it was decided.
        assert_eq!(made.expiry as i64, invoice.expires_at - decided);
        let declared = declarations(&merchant, "R-1")
            .into_iter()
            .find(|declaration| declaration.invoice == made.pr)
            .expect("declared");
        assert_eq!(declared.declared_at, decided);
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let d = rest_record_address(&keys.key, &made.payment_hash);
        let record = held(&merchant).into_iter().find(|event| event.tag("d") == Some(d.as_str())).unwrap();
        assert_eq!(record.created_at, decided);
        assert!(warnings.all().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn decides_by_the_clock_read_in_the_lock_once_another_check_of_the_invoice_asked() {
        let Setup { merchant, warnings, client, invoice } = setup().await;
        let address = address();
        merchant.advance(60);
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let start = merchant.now();
        // The Lightning address refuses the first check's invoice 7 s later; the other check of the
        // invoice waits for it, then decides.
        let clock = merchant.clock.clone();
        let callbacks = Arc::new(AtomicI64::new(0));
        let counted = callbacks.clone();
        merchant.set_override(Some(move |call: &Call| {
            (call.path() == CALLBACK && counted.fetch_add(1, Ordering::SeqCst) == 0).then(|| {
                clock.advance(7);
                Answer::status_json(500, &j!({ "status": "ERROR", "reason": "busy" }))
            })
        }));
        let (first, second) = tokio::join!(client.get_status(&invoice), client.get_status(&invoice));
        let made = made_of(&merchant, 29_000);
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].expiry as i64, invoice.expires_at - (start + 7));
        let shown = [rest_bolt11(&first.unwrap()), rest_bolt11(&second.unwrap())];
        assert!(shown.contains(&Some(None)) && shown.contains(&Some(Some(made[0].pr.clone()))), "{shown:?}");
        assert_eq!(callbacks.load(Ordering::SeqCst), 2);
        assert_eq!(warnings.all().len(), 1, "{:?}", warnings.all());
    }

    #[tokio::test(start_paused = true)]
    async fn shows_an_invoice_of_the_rest_whose_record_a_majority_took_in_the_check_though_fewer_than_a_majority_answer_the_read()
     {
        let Setup { merchant, client, invoice, .. } = setup().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("part"), &address, 20_000));
        let author = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at).author;
        // Two relays of three take its record, then stall on the read of the rest records.
        for url in &merchant.key_relays[1..] {
            let author = author.clone();
            merchant.net.get(url).update(move |behaviour| {
                behaviour.mute_query = Some(Arc::new(move |filter: &Json| {
                    filter
                        .get("authors")
                        .and_then(Json::as_array)
                        .is_some_and(|authors| authors.contains(&Json::from(author.as_str())))
                        && filter.get("#d").is_none()
                }));
            });
        }
        let status = client.get_status(&invoice).await.unwrap();
        let made = made_of(&merchant, 29_000).into_iter().next().unwrap();
        let PaymentStatus::Open { rest: Some(rest), .. } = &status else { panic!("{status:?}") };
        assert_eq!((rest.sats, rest.bolt11.as_deref()), (29_000, Some(made.pr.as_str())));
        assert_eq!(rest_records(&merchant, &invoice).len(), 1);
        // Its record, as the relays received it: published once.
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let d = rest_record_address(&keys.key, &made.payment_hash);
        let published = || {
            merchant
                .key_relays
                .iter()
                .flat_map(|url| merchant.net.get(url).received())
                .filter(|event| event.tag("d") == Some(d.as_str()))
                .count()
        };
        let once = published();
        assert!(once >= 2, "{once}");
        // The next check, which took nothing, cannot tell: not shown until a majority answers, and
        // its record not published again (what the relays that did not answer hold is unseen).
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(None));
        assert_eq!(published(), once);
        // Nor a second invoice of the rest asked: one of exactly the rest exists, not paid and
        // running, whatever its record (SPEC.md §31, Asking for a rest invoice).
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
        for url in &merchant.key_relays {
            merchant.net.get(url).update(|behaviour| behaviour.mute_query = None);
        }
        assert_eq!(rest_bolt11(&client.get_status(&invoice).await.unwrap()), Some(Some(made.pr.clone())));
        assert_eq!(made_of(&merchant, 29_000).len(), 1);
    }
}

mod a_mixed_payment {
    use super::*;

    /// 20 000 of 49 000 sats in the mempool, and the invoice of its rest made.
    async fn underpaid(setup: &Setup) -> (EsploraTx, MadeInvoice) {
        let address = address();
        let tx = payment(&txid("part"), &address, 20_000);
        setup.merchant.chain.add(&address, tx.clone());
        let status = setup.client.get_status(&setup.invoice).await.unwrap();
        assert!(matches!(&status, PaymentStatus::Open { rest: Some(_), .. }), "{status:?}");
        let made = made_of(&setup.merchant, 29_000).into_iter().next().unwrap();
        (tx, made)
    }

    #[tokio::test(start_paused = true)]
    async fn is_unconfirmed_once_the_rest_is_paid_then_paid_at_3_confirmations_with_the_preimage() {
        let setup = setup().await;
        let (tx, rest) = underpaid(&setup).await;
        let Setup { merchant, client, invoice, .. } = &setup;
        merchant.pay_invoice(&rest.payment_hash);
        assert_eq!(
            json(&client.get_status(invoice).await.unwrap()),
            serde_json::json!({ "state": "unconfirmed", "received": "49000", "confirmations": 0, "txids": [tx.txid] })
        );
        merchant.chain.confirm(&address(), &tx.txid, merchant.chain.height() - 2);
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(
            json(&client.get_status(invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "mixed", "received": "49000", "txids": [tx.txid], "preimages": [rest.preimage] })
        );
        // The order is paid: its next invoice is refused, without the preimage of its own invoice.
        let error = client.create_invoice(&Order::sats("R-1", 49_000)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::OrderPaid);
        assert_eq!(error.preimage(), None);
        assert_eq!(serde_json::to_value(error.status().unwrap()).unwrap()["method"], "mixed");
    }

    #[tokio::test(start_paused = true)]
    async fn counts_a_rest_paid_when_the_onchain_payment_is_gone_and_expires_with_all_received() {
        let setup = setup().await;
        let (tx, rest) = underpaid(&setup).await;
        let Setup { merchant, client, invoice, .. } = &setup;
        merchant.pay_invoice(&rest.payment_hash);
        merchant.chain.drop_tx(&address(), &tx.txid);
        let status = client.get_status(invoice).await.unwrap();
        let PaymentStatus::Open { received, rest: Some(left), .. } = &status else { panic!("{status:?}") };
        assert_eq!((*received, left.sats), (29_000, 20_000));
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(
            json(&client.get_status(invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "29000" })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn never_leases_the_address_again_for_the_order_once_a_witness_names_it_its_payment_gone() {
        let setup = setup().await;
        let (tx, rest) = underpaid(&setup).await;
        let Setup { merchant, client, invoice, .. } = &setup;
        merchant.pay_invoice(&rest.payment_hash);
        // The on-chain payment gone, the explorer shows nothing paid the address; its witness does
        // (SPEC.md §31, Leasing an address): the earlier invoice's 29 000 never counts for a new one.
        merchant.chain.drop_tx(&address(), &tx.txid);
        merchant.set_now(invoice.expires_at + 421);
        assert_eq!(
            json(&client.get_status(invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "29000" })
        );
        let next = client.create_invoice(&Order::sats("R-1", 49_000).duration_seconds(600)).await.unwrap();
        assert_eq!(next.onchain_address, None);
        assert_ne!(next.bolt11, invoice.bolt11);
    }

    #[tokio::test(start_paused = true)]
    async fn lets_the_order_get_a_new_invoice_once_the_invoice_and_its_rest_ended_unpaid() {
        let setup = setup().await;
        underpaid(&setup).await;
        let Setup { merchant, client, invoice, .. } = &setup;
        merchant.set_now(invoice.expires_at + 100);
        assert_eq!(
            client.create_invoice(&Order::sats("R-1", 49_000)).await.unwrap_err().code(),
            ErrorCode::InvoicePending
        );
        // The rest invoice ended with the invoice: both final 120 s later.
        merchant.set_now(invoice.expires_at + 200);
        let next = client.create_invoice(&Order::sats("R-1", 49_000)).await.unwrap();
        assert_ne!(next.bolt11, invoice.bolt11);
        // The address was paid: never leased again.
        assert_eq!(next.onchain_address, None);
    }

    #[tokio::test(start_paused = true)]
    async fn is_paid_by_wait_for_payment_once_the_rest_is_paid_without_a_push_of_the_explorer() {
        let setup = setup().await;
        let _socket = setup.merchant.start_explorer_socket();
        let (tx, rest) = underpaid(&setup).await;
        let Setup { merchant, client, invoice, .. } = &setup;
        merchant.chain.confirm(&address(), &tx.txid, merchant.chain.height() - 2);
        let statuses = Arc::new(std::sync::Mutex::new(Vec::<PaymentStatus>::new()));
        let recorded = statuses.clone();
        let waiting = {
            let (client, invoice) = (client.clone(), invoice.clone());
            let options = WaitOptions::default()
                .interval_ms(250)
                .on_status(move |status| recorded.lock().unwrap().push(status.clone()));
            tokio::spawn(async move { client.wait_for_payment(&invoice, options).await })
        };
        for _ in 0..200 {
            if !statuses.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let last = statuses.lock().unwrap().last().cloned().unwrap();
        assert!(
            matches!(&last, PaymentStatus::Open { rest: Some(rest), .. } if rest.sats == 29_000),
            "{last:?}"
        );
        merchant.pay_invoice(&rest.payment_hash);
        assert_eq!(
            json(&waiting.await.unwrap().unwrap()),
            serde_json::json!({ "state": "paid", "method": "mixed", "received": "49000", "txids": [tx.txid], "preimages": [rest.preimage] })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn never_ends_wait_for_payment_on_what_was_due_before_the_rest_was_paid() {
        let setup = setup().await;
        let (tx, rest) = underpaid(&setup).await;
        let Setup { merchant, client, invoice, .. } = &setup;
        merchant.chain.confirm(&address(), &tx.txid, merchant.chain.height() - 2);
        // The rest paid in time, its verify URL failing once past the grace period: the full check
        // (no push of the explorer here, the next one is 60 s later) judges the on-chain part
        // against the whole amount, final, and cannot tell the rest.
        merchant.pay_invoice(&rest.payment_hash);
        merchant.set_now(invoice.expires_at + 121);
        let failures = Arc::new(AtomicI64::new(1));
        {
            let failures = failures.clone();
            let verify = rest.verify.clone();
            merchant.set_override(Some(move |call: &Call| {
                (call.url == verify && failures.fetch_sub(1, Ordering::SeqCst) > 0)
                    .then(|| Answer::status_json(500, &j!({ "oops": true })))
            }));
        }
        let statuses = Arc::new(std::sync::Mutex::new(Vec::<PaymentStatus>::new()));
        let recorded = statuses.clone();
        // The rest seen paid by the next Lightning check: only a full check, with the 20 000
        // on-chain all that is due, gives the status (never "expired" with 49 000 received).
        let options = WaitOptions::default()
            .interval_ms(250)
            .on_status(move |status| recorded.lock().unwrap().push(status.clone()));
        let last = client.wait_for_payment(invoice, options).await.unwrap();
        assert_eq!(
            json(&last),
            serde_json::json!({ "state": "paid", "method": "mixed", "received": "49000", "txids": [tx.txid], "preimages": [rest.preimage] })
        );
        // Failed once, then read by the Lightning check and by the full check it started.
        assert_eq!(failures.load(Ordering::SeqCst), -2);
        assert!(statuses.lock().unwrap().iter().all(|status| status.state() != "expired"));
    }
}
