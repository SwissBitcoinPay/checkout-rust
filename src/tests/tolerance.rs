//! The merchant's tolerance of on-chain underpayments (SPEC.md §31, The merchant's tolerance,
//! Acceptance records), end to end against local relays and fakes of breez.tips and of the
//! explorers: read in the channel, kept in the order's lease, its payment judged with it whatever
//! the channel says later; a payment short by no more than it is paid (being confirmed first), one
//! short by more asks its whole rest; the pages of the order's checkout links told by an
//! acceptance record, never the tolerance itself.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::support::chain::{Paying, deposit_address, payment, payment_with, txid};
use super::support::j;
use super::support::merchant::{MadeInvoice, TestMerchant, Warnings};
use super::support::relay::RelayBehaviour;
use crate::checkout::{CheckoutFragment, checkout_keys, parse_checkout_fragment, parse_checkout_value};
use crate::client::{Client, WaitOptions};
use crate::declaration::registry_of;
use crate::derive::{Sale, acceptance_record_address, rest_keys, sale_of};
use crate::error::ErrorCode;
use crate::json::{self, Json};
use crate::model::{Invoice, PaymentStatus};
use crate::nostr::event::{Event, EventTemplate, sign_event, valid_event};
use crate::nostr::nip44::decrypt;
use crate::nostr::record::Opened;
use crate::onchain::acceptance::open_acceptance_event;
use crate::onchain::lease::{
    LeaseOutside, SaleLeaseRecord, open_lease_inside, open_lease_outside, open_sale_lease,
};
use crate::onchain::rest::RestReaderKeys;
use crate::order::Order;
use crate::runtime::OsRandom;
use crate::text::to_hex;

const ORIGIN: &str = "https://pay.example";
/// 5 %: of 49 000 sats, 2 450 may be missing, 46 550 pay the order.
const TOLERANCE: u64 = 500;
const SATS: u64 = 49_000;
const LEAST: u64 = 46_550;

fn address() -> String {
    deposit_address(1)
}

struct Setup {
    merchant: TestMerchant,
    warnings: Warnings,
    client: Client,
}

fn setup() -> Setup {
    let merchant = TestMerchant::new().start();
    merchant.publish_lot(&[address()], 90);
    let warnings = Warnings::default();
    let client = merchant.client().logger(warnings.clone()).build().unwrap();
    Setup { merchant, warnings, client }
}

/// Publishes the channel, with `tolerance` (none: no `onchainTolerance`), dated `created_at`.
fn publish_channel(merchant: &TestMerchant, tolerance: Option<Json>, created_at: i64) {
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    let mut extra = vec![("relays", relays), ("checkout", Json::object([("origin", Json::from(ORIGIN))]))];
    if let Some(tolerance) = tolerance {
        extra.push(("onchainTolerance", tolerance));
    }
    merchant.publish_channel(&merchant.channel_value(created_at, Json::object_of(extra)), created_at);
}

/// The events a relay holds, checked.
fn held(merchant: &TestMerchant, relay: &str) -> Vec<Event> {
    merchant.net.get(relay).events().iter().filter_map(valid_event).collect()
}

fn sale_of_ref(merchant: &TestMerchant, reference: &str) -> Sale {
    sale_of(
        &merchant.integration_key,
        &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
        reference,
    )
}

/// The inside of the sale of `reference`'s lease the relays hold.
fn lease_inside(merchant: &TestMerchant, reference: &str) -> Json {
    let sale = sale_of_ref(merchant, reference);
    let leases: Vec<Json> = held(merchant, &merchant.key_relays[0])
        .iter()
        .filter_map(|event| match open_sale_lease(event, &sale)? {
            Ok(SaleLeaseRecord::Lease(lease)) => {
                // Its inside as it was sealed, opened again from its outside.
                let (_, outside) =
                    open_lease_outside(&lease.event.to_json(), &merchant.registry_key, &lease.d)?;
                let LeaseOutside::Lease { end, sealed } = outside else { return None };
                open_lease_inside(&sealed, end, &lease.d, &sale).ok()?.map(|(_, inside)| inside)
            }
            _ => None,
        })
        .collect();
    assert_eq!(leases.len(), 1);
    leases[0].clone()
}

/// The acceptance records of `invoice` a relay holds, as a checkout link's page opens them.
fn acceptances(merchant: &TestMerchant, invoice: &Invoice, relay: &str) -> Vec<(u64, Event)> {
    let keys = rest_keys(
        &merchant.integration_key,
        &invoice.reference,
        invoice.onchain_address.as_deref().unwrap(),
        invoice.expires_at,
    );
    let reader = RestReaderKeys::of(&keys);
    held(merchant, relay)
        .iter()
        .filter_map(|event| match open_acceptance_event(event, &reader, invoice.sats)? {
            Opened::Valid { value, event } => Some((value, event)),
            Opened::Newer { .. } => None,
        })
        .collect()
}

fn made_of(merchant: &TestMerchant, sats: u64) -> Vec<MadeInvoice> {
    merchant.invoices().into_iter().filter(|made| made.amount_msat == u128::from(sats) * 1000).collect()
}

async fn create_invoice(client: &Client, reference: &str) -> Invoice {
    let invoice = client
        .create_invoice(&Order::sats(reference, SATS).duration_seconds(600).note("Order 1").checkout(true))
        .await
        .unwrap();
    assert_eq!(invoice.onchain_address.as_deref(), Some(address().as_str()));
    invoice
}

fn json(status: &PaymentStatus) -> serde_json::Value {
    serde_json::to_value(status).unwrap()
}

mod the_order_tolerance {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn is_the_channel_kept_in_the_order_lease_never_in_what_the_shop_gets() {
        let Setup { merchant, client, .. } = setup();
        publish_channel(&merchant, Some(Json::unsigned(TOLERANCE)), 100);
        let invoice = create_invoice(&client, "R-1").await;
        let inside = lease_inside(&merchant, "R-1");
        assert_eq!(
            (inside.get("sats"), inside.get("tolerance")),
            (Some(&Json::unsigned(SATS)), Some(&Json::unsigned(TOLERANCE)))
        );
        // Neither the Invoice nor the checkout link's record (the customer reads it) holds it.
        let stored = serde_json::to_value(&invoice).unwrap();
        let mut names: Vec<&str> = stored.as_object().unwrap().keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "bolt11",
                "checkoutUrl",
                "createdAt",
                "expiresAt",
                "fiat",
                "note",
                "onchainAddress",
                "paymentHash",
                "paymentUri",
                "rate",
                "redirectUrl",
                "ref",
                "sats",
                "verifyUrl"
            ]
        );
        assert!(!invoice.to_json().to_ascii_lowercase().contains("toleran"));
        let url = invoice.checkout_url.clone().unwrap();
        let CheckoutFragment::Link { author, link_key, .. } =
            parse_checkout_fragment(&url[url.find('#').unwrap()..])
        else {
            panic!("Not a checkout link")
        };
        let keys = checkout_keys(&link_key);
        let link = held(&merchant, &merchant.key_relays[0])
            .into_iter()
            .find(|event| event.pubkey == author)
            .unwrap();
        let plaintext = decrypt(&link.content, &keys.encryption_key).unwrap();
        assert!(!plaintext.to_ascii_lowercase().contains("toleran"));
        let record = json::parse(&plaintext).unwrap();
        assert_eq!(record.get("t").and_then(Json::as_str), Some("checkout"));
        assert!(parse_checkout_value(record.get("v").unwrap()).unwrap().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn is_none_when_the_channel_gives_none_or_an_invalid_one_the_lease_holds_none() {
        for (name, value) in [
            ("absent", None),
            ("0", Some(Json::unsigned(0))),
            ("a fraction", Some(Json::Number(2.5))),
            ("a string", Some(Json::from("500"))),
            ("negative", Some(Json::Number(-1.0))),
            ("above 10 %", Some(Json::unsigned(1001))),
        ] {
            let Setup { merchant, client, .. } = setup();
            publish_channel(&merchant, value, 100);
            create_invoice(&client, "R-1").await;
            assert!(!lease_inside(&merchant, "R-1").has("tolerance"), "{name}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn is_10_percent_at_most() {
        let Setup { merchant, client, .. } = setup();
        publish_channel(&merchant, Some(Json::unsigned(1000)), 100);
        create_invoice(&client, "R-1").await;
        assert_eq!(lease_inside(&merchant, "R-1").get("tolerance"), Some(&Json::unsigned(1000)));
    }
}

mod a_payment_within_the_tolerance {
    use super::*;

    async fn within() -> (Setup, Invoice) {
        let setup = setup();
        publish_channel(&setup.merchant, Some(Json::unsigned(TOLERANCE)), 100);
        let invoice = create_invoice(&setup.client, "R-1").await;
        setup.merchant.advance(60);
        (setup, invoice)
    }

    #[tokio::test(start_paused = true)]
    async fn pays_the_order_being_confirmed_then_paid_on_both_explorers_without_a_rest() {
        let (Setup { merchant, client, .. }, invoice) = within().await;
        let address = address();
        let tx = payment(&txid("least"), &address, LEAST);
        merchant.chain.add(&address, tx.clone());
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "unconfirmed", "received": LEAST.to_string(), "confirmations": 0, "txids": [tx.txid] })
        );
        assert!(made_of(&merchant, SATS - LEAST).is_empty());
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 2);
        merchant.set_now(invoice.expires_at + 3600);
        let paid = serde_json::json!({ "state": "paid", "method": "onchain", "received": LEAST.to_string(), "txids": [tx.txid] });
        assert_eq!(json(&client.get_status(&invoice).await.unwrap()), paid);
        // The order is paid: no new invoice for it.
        let error = client.create_invoice(&Order::sats("R-1", SATS)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::OrderPaid);
        assert_eq!(serde_json::to_value(error.status().unwrap()).unwrap(), paid);
        assert_eq!(error.preimage(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn asks_the_whole_rest_of_a_payment_short_by_more() {
        let (Setup { merchant, client, .. }, invoice) = within().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("short"), &address, LEAST - 1));
        let status = client.get_status(&invoice).await.unwrap();
        let made =
            made_of(&merchant, SATS - LEAST + 1).into_iter().next().expect("an invoice of the whole rest");
        assert_eq!(
            json(&status),
            serde_json::json!({
                "state": "open",
                "expiresAt": invoice.expires_at,
                "received": (LEAST - 1).to_string(),
                "rest": {
                    "sats": (SATS - LEAST + 1).to_string(),
                    "bolt11": made.pr,
                    "paymentUri": format!("bitcoin:{address}?amount=0.00002451&lightning={}", made.pr)
                }
            })
        );
        assert!(acceptances(&merchant, &invoice, &merchant.key_relays[0]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn is_reached_by_a_second_payment_after_an_underpayment() {
        let (Setup { merchant, client, .. }, invoice) = within().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("first"), &address, 44_100));
        let status = client.get_status(&invoice).await.unwrap();
        let PaymentStatus::Open { received, rest: Some(rest), .. } = &status else { panic!("{status:?}") };
        assert_eq!((*received, rest.sats), (44_100, 4900));
        merchant.chain.add(&address, payment(&txid("second"), &address, 2450));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: LEAST, .. }), "{status:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn with_an_invoice_of_the_rest_paid_needs_onchain_only_what_the_tolerance_leaves() {
        let (Setup { merchant, client, .. }, invoice) = within().await;
        let address = address();
        let tx = payment(&txid("part"), &address, 20_000);
        merchant.chain.add(&address, tx.clone());
        client.get_status(&invoice).await.unwrap();
        let rest = made_of(&merchant, 29_000).into_iter().next().unwrap();
        merchant.pay_invoice(&rest.payment_hash);
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 2);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "mixed", "received": "49000", "txids": [tx.txid], "preimages": [rest.preimage] })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn is_waited_for_by_wait_for_payment_until_paid() {
        let (Setup { merchant, client, .. }, invoice) = within().await;
        let _socket = merchant.start_explorer_socket();
        let address = address();
        let tx = payment(&txid("least"), &address, LEAST);
        merchant.chain.add(&address, tx.clone());
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 2);
        assert_eq!(
            json(&client.wait_for_payment(&invoice, WaitOptions::default().interval_ms(250)).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": LEAST.to_string(), "txids": [tx.txid] })
        );
    }
}

mod the_tolerance_of_the_order_creation {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn still_judges_its_payment_when_the_channel_one_is_lowered() {
        let Setup { merchant, client, .. } = setup();
        publish_channel(&merchant, Some(Json::unsigned(TOLERANCE)), 100);
        let invoice = create_invoice(&client, "R-1").await;
        publish_channel(&merchant, Some(Json::unsigned(0)), 200);
        merchant.advance(60);
        let address = address();
        merchant.chain.add(&address, payment(&txid("least"), &address, LEAST));
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "unconfirmed");
    }

    #[tokio::test(start_paused = true)]
    async fn never_judges_a_payment_of_an_order_created_without_one() {
        let Setup { merchant, client, .. } = setup();
        publish_channel(&merchant, None, 100);
        let invoice = create_invoice(&client, "R-1").await;
        publish_channel(&merchant, Some(Json::unsigned(TOLERANCE)), 200);
        merchant.advance(60);
        let address = address();
        merchant.chain.add(&address, payment(&txid("least"), &address, LEAST));
        let status = client.get_status(&invoice).await.unwrap();
        let PaymentStatus::Open { received, rest: Some(rest), .. } = &status else { panic!("{status:?}") };
        assert_eq!((*received, rest.sats), (LEAST, SATS - LEAST));
        // Past its end, for good: never paid by a tolerance set afterwards.
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": LEAST.to_string() })
        );
    }
}

mod the_acceptance_record {
    use super::*;

    async fn accepted() -> (Setup, Invoice) {
        let setup = setup();
        publish_channel(&setup.merchant, Some(Json::unsigned(TOLERANCE)), 100);
        let invoice = create_invoice(&setup.client, "R-1").await;
        setup.merchant.advance(60);
        (setup, invoice)
    }

    #[tokio::test(start_paused = true)]
    async fn tells_the_checkout_link_page_what_was_received_on_every_relay_once() {
        let (Setup { merchant, client, .. }, invoice) = accepted().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("least"), &address, 47_000));
        client.get_status(&invoice).await.unwrap();
        for relay in &merchant.key_relays {
            let received: Vec<u64> =
                acceptances(&merchant, &invoice, relay).iter().map(|(received, _)| *received).collect();
            assert_eq!(received, vec![47_000], "{relay}");
        }
        // Its address, from the invoice's rest key, and its life, the links'.
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let (_, event) = acceptances(&merchant, &invoice, &merchant.key_relays[0]).remove(0);
        assert_eq!(event.pubkey, keys.author);
        assert_eq!(
            event.tags,
            vec![
                vec!["d".to_owned(), acceptance_record_address(&keys.key)],
                vec!["expiration".to_owned(), (invoice.expires_at + 604_800).to_string()]
            ]
        );
        // What was received, never the tolerance.
        let plaintext = decrypt(&event.content, &keys.encryption_key).unwrap();
        super::super::support::vectors::assert_same(
            &json::parse(&plaintext).unwrap(),
            &j!({ "t": "checkout-accepted", "v": { "version": 1, "received": 47_000 } }),
            "the acceptance record",
        );
        let sent = merchant.net.get(&merchant.key_relays[0]).received().len();
        client.get_status(&invoice).await.unwrap();
        // Known on a majority: not published again.
        assert_eq!(merchant.net.get(&merchant.key_relays[0]).received().len(), sent);
    }

    #[tokio::test(start_paused = true)]
    async fn is_published_again_of_less_when_a_replacement_lowers_what_was_received() {
        let (Setup { merchant, client, .. }, invoice) = accepted().await;
        let address = address();
        let first = payment(&txid("first"), &address, 48_000);
        merchant.chain.add(&address, first.clone());
        client.get_status(&invoice).await.unwrap();
        merchant.advance(1);
        merchant.chain.drop_tx(&address, &first.txid);
        // A fee bump of the same coin, paying less.
        let bump = payment_with(
            &txid("bump"),
            &address,
            47_000,
            Paying { coins: Some(first.coins()), ..Paying::default() },
        );
        merchant.chain.add(&address, bump);
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: 47_000, .. }), "{status:?}");
        let mut records = acceptances(&merchant, &invoice, &merchant.key_relays[0]);
        records.sort_by_key(|(_, event)| std::cmp::Reverse(event.created_at));
        assert_eq!(records[0].0, 47_000);
    }

    #[tokio::test(start_paused = true)]
    async fn is_never_published_for_a_payment_of_the_whole_amount() {
        let (Setup { merchant, client, .. }, invoice) = accepted().await;
        let address = address();
        merchant.chain.add(&address, payment(&txid("whole"), &address, SATS));
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "unconfirmed");
        assert!(acceptances(&merchant, &invoice, &merchant.key_relays[0]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn never_writes_over_an_acceptance_record_of_a_newer_format_logged() {
        let (Setup { merchant, warnings, client }, invoice) = accepted().await;
        let address = address();
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let d = acceptance_record_address(&keys.key);
        // A newer version's acceptance record, on one relay.
        let newer = sign_event(
            EventTemplate {
                kind: 30078.0,
                created_at: merchant.now() - 10,
                tags: vec![
                    vec!["d".to_owned(), d.clone()],
                    vec!["expiration".to_owned(), (invoice.expires_at + 604_800).to_string()],
                ],
                content: "#".to_owned(),
            },
            &keys.secret_key,
            &OsRandom,
        );
        merchant.net.get(&merchant.key_relays[0]).store_event(&newer);
        merchant.chain.add(&address, payment(&txid("least"), &address, LEAST));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: LEAST, .. }), "{status:?}");
        let written = merchant
            .key_relays
            .iter()
            .flat_map(|relay| merchant.net.get(relay).received())
            .filter(|event| event.tag("d") == Some(d.as_str()))
            .count();
        assert_eq!(written, 0);
        let logged = warnings.all();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("acceptance record of a payment has a newer format"), "{logged:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn publishes_nothing_when_fewer_than_a_majority_answer_its_read_and_publishes_at_the_next_check() {
        let (Setup { merchant, warnings, client }, invoice) = accepted().await;
        let address = address();
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let d = acceptance_record_address(&keys.key);
        let muting = Arc::new(AtomicBool::new(true));
        for relay in &merchant.key_relays[1..] {
            let (muting, d) = (muting.clone(), d.clone());
            merchant.net.get(relay).set_behaviour(RelayBehaviour {
                // The read of the acceptance records alone never answered there.
                mute_query: Some(Arc::new(move |filter: &Json| {
                    muting.load(Ordering::SeqCst)
                        && filter.get("#d").and_then(Json::as_array).is_some_and(|addresses| {
                            addresses.iter().any(|address| address.as_str() == Some(d.as_str()))
                        })
                })),
                ..RelayBehaviour::default()
            });
        }
        merchant.chain.add(&address, payment(&txid("least"), &address, LEAST));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: LEAST, .. }), "{status:?}");
        // What those relays hold, of a newer format perhaps, cannot be told: nothing written over it.
        let written = |merchant: &TestMerchant| {
            merchant
                .key_relays
                .iter()
                .flat_map(|relay| merchant.net.get(relay).received())
                .filter(|event| event.tag("d") == Some(d.as_str()))
                .count()
        };
        assert_eq!(written(&merchant), 0);
        let logged = warnings.all();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("the acceptance record of a payment was not published"), "{}", logged[0]);
        assert!(logged[0].contains("published again at the next check"), "{}", logged[0]);
        muting.store(false, Ordering::SeqCst);
        client.get_status(&invoice).await.unwrap();
        for relay in &merchant.key_relays {
            let received: Vec<u64> =
                acceptances(&merchant, &invoice, relay).iter().map(|(received, _)| *received).collect();
            assert_eq!(received, vec![LEAST], "{relay}");
        }
        assert_eq!(written(&merchant), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn logs_a_failed_publication_never_the_check_error_and_publishes_at_the_next_check() {
        let (Setup { merchant, warnings, client }, invoice) = accepted().await;
        let address = address();
        let keys = rest_keys(&merchant.integration_key, "R-1", &address, invoice.expires_at);
        let d = acceptance_record_address(&keys.key);
        let refusing = Arc::new(AtomicBool::new(true));
        for relay in &merchant.key_relays {
            let (refusing, d) = (refusing.clone(), d.clone());
            merchant.net.get(relay).set_behaviour(RelayBehaviour {
                refuse_event: Some(Arc::new(move |event: &Event| {
                    (refusing.load(Ordering::SeqCst)
                        && event.tags.iter().any(|tag| {
                            tag.first().map(String::as_str) == Some("d") && tag.get(1) == Some(&d)
                        }))
                    .then(|| "blocked: no".to_owned())
                })),
                ..RelayBehaviour::default()
            });
        }
        merchant.chain.add(&address, payment(&txid("least"), &address, LEAST));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: LEAST, .. }), "{status:?}");
        let logged = warnings.all();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("the acceptance record of a payment was not published"), "{}", logged[0]);
        assert!(
            !logged[0].to_ascii_lowercase().contains("toleran") && !logged[0].contains("500"),
            "{}",
            logged[0]
        );
        assert!(acceptances(&merchant, &invoice, &merchant.key_relays[0]).is_empty());
        refusing.store(false, Ordering::SeqCst);
        client.get_status(&invoice).await.unwrap();
        let received: Vec<u64> = acceptances(&merchant, &invoice, &merchant.key_relays[0])
            .iter()
            .map(|(received, _)| *received)
            .collect();
        assert_eq!(received, vec![LEAST]);
    }
}
