//! On-chain payments (SPEC.md §31), end to end against local relays and fakes of breez.tips, of
//! the explorers (REST and WebSocket) and of BlockCypher: the methods of an order by its amount, a
//! lot read and an address leased, two servers leasing one address, a paid address skipped, the
//! witnesses written and read, the statuses of both parts, an order paid on-chain found again,
//! `wait_for_payment` woken by the explorer's WebSocket.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use super::support::chain::{EsploraTx, Paying, Service, deposit_address, payment, payment_with, txid};
use super::support::http::{Call, FakeHttp};
use super::support::j;
use super::support::lightning::{InvoiceSpec, make_invoice, metadata_hash};
use super::support::merchant::{MadeInvoice, TestMerchant, Warnings, metadata};
use super::support::relay::RelayBehaviour;
use super::support::vectors::assert_same;
use crate::checkout::{CheckoutFragment, checkout_keys, parse_checkout_fragment, parse_checkout_value};
use crate::client::{Client, WaitOptions};
use crate::declaration::{DeclarationInput, DeclaredPrice, declaration_event, registry_of};
use crate::derive::{Sale, lease_address, lot_address, outer_key, rest_keys, sale_keys, sale_of};
use crate::error::ErrorCode;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::json::{self, Json};
use crate::model::{Invoice, InvoiceToCheck, Payment, PaymentStatus};
use crate::nostr::event::{Event, EventTemplate, sign_event, valid_event};
use crate::nostr::nip44::{conversation_key, decrypt};
use crate::onchain::explorer::blockcypher_milliseconds;
use crate::onchain::lease::{LeaseHold, LeaseRecord, LeaseTerms, lease_event, open_lease_record};
use crate::onchain::witness::{
    OpenedWitness, Witness, address_tag, open_witness, order_tag, seen_of, witness_address,
};
use crate::order::Order;
use crate::protocol::{BLOCKCYPHER_URL, MEMPOOL_URL};
use crate::runtime::OsRandom;
use crate::text::to_hex;
use crate::transport::{BoxFuture, TransportError};

const ORIGIN: &str = "https://pay.example";

fn lot() -> Vec<String> {
    (1..=3).map(deposit_address).collect()
}

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
    merchant.publish_lot(&lot(), 90);
    merchant
}

fn client(merchant: &TestMerchant) -> Client {
    merchant.client().build().unwrap()
}

fn json(status: &PaymentStatus) -> serde_json::Value {
    serde_json::to_value(status).unwrap()
}

/// The records the first relay holds now.
fn held(merchant: &TestMerchant) -> Vec<Json> {
    merchant.net.get(&merchant.key_relays[0]).events()
}

/// The leases and withdrawals of `address` the first relay received, opened by the merchant.
fn leases_of(merchant: &TestMerchant, address: &str) -> Vec<(LeaseRecord, Event)> {
    let d = lease_address(&merchant.registry_key, address);
    merchant
        .net
        .get(&merchant.key_relays[0])
        .received()
        .into_iter()
        .filter_map(|event| {
            open_lease_record(&event.to_json(), &merchant.registry_key, &d).map(|record| (record, event))
        })
        .collect()
}

fn kinds(records: &[(LeaseRecord, Event)]) -> Vec<&'static str> {
    records
        .iter()
        .map(|(record, _)| match record.outside {
            LeaseHold::Lease { .. } => "lease",
            LeaseHold::Withdrawn => "withdrawn",
            LeaseHold::Newer => "newer",
        })
        .collect()
}

/// The inside of a lease, as the merchant's app opens it (registry key and reading key), its end
/// first.
fn open_as_merchant(merchant: &TestMerchant, event: &Event) -> Json {
    let d = event.tag("d").unwrap();
    let outside =
        json::parse(&decrypt(&event.content, &outer_key(&merchant.registry_key, d, &event.pubkey)).unwrap())
            .unwrap();
    assert_eq!(outside.get("t").and_then(Json::as_str), Some("registry-onchain"));
    let v = outside.get("v").unwrap();
    let key = conversation_key(&merchant.reader_secret, &event.pubkey).unwrap();
    let inside =
        json::parse(&decrypt(v.get("sealed").and_then(Json::as_str).unwrap(), &key).unwrap()).unwrap();
    let mut members = vec![("end".to_owned(), v.get("end").unwrap().clone())];
    members.extend(
        inside
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.to_string_lossy().into_owned(), value.clone())),
    );
    Json::object_of(members.iter().map(|(name, value)| (name.as_str(), value.clone())).collect())
}

/// The witnesses the relays hold, as the merchant's app reads them (by the seen author), each
/// with when it was seen.
fn witnesses(merchant: &TestMerchant) -> Vec<(Witness, i64)> {
    let seen = seen_of(&merchant.integration_key);
    held(merchant)
        .iter()
        .filter_map(|value| {
            let event = valid_event(value)?;
            match open_witness(&event, &seen)? {
                OpenedWitness::Valid { witness, event } => Some((witness, event.created_at)),
                OpenedWitness::Newer { .. } => None,
            }
        })
        .collect()
}

/// The sale of `reference`, in the merchant's registry.
fn sale_of_ref(merchant: &TestMerchant, reference: &str) -> Sale {
    sale_of(
        &merchant.integration_key,
        &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
        reference,
    )
}

mod the_methods_of_an_order_by_its_amount {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn leases_an_address_from_1000_sats_before_the_invoice_is_declared() {
        let merchant = merchant();
        let invoice =
            client(&merchant).create_invoice(&Order::sats("ORD-1", 49_000).note("Order 1")).await.unwrap();
        let address = invoice.onchain_address.clone().expect("an address");
        assert!(lot().contains(&address));
        let bolt11 = invoice.bolt11.clone().unwrap();
        assert!(bolt11.starts_with("lnbc"));
        assert_eq!(invoice.payment_uri, format!("bitcoin:{address}?amount=0.00049&lightning={bolt11}"));
        // The explorer was asked whether the address was paid already.
        assert!(merchant.chain.asked().contains(&format!("{MEMPOOL_URL}/address/{address}/txs")));
        // The lease first, then its mark once confirmed, then the declaration: an address is never
        // shown before its lease is confirmed.
        let sale = sale_keys(&merchant.integration_key, "ORD-1");
        let received = merchant.net.get(&merchant.key_relays[0]).received();
        let d = lease_address(&merchant.registry_key, &address);
        assert_eq!(
            received.iter().position(|event| event.tags.iter().any(|tag| tag.get(1) == Some(&d))),
            Some(0)
        );
        assert_eq!(received.len(), 3);
        assert!(received.iter().all(|event| event.pubkey == sale.author));
        assert!(received[1].created_at > received[0].created_at);
        assert_eq!(open_as_merchant(&merchant, &received[0]).get("confirmed"), Some(&Json::Bool(false)));
        assert_same(
            &open_as_merchant(&merchant, &received[1]),
            &j!({
                "end": invoice.expires_at + 120,
                "version": 1,
                "address": address,
                "sats": 49000,
                "invoice": bolt11,
                "verifyUrl": invoice.verify_url,
                "createdAt": invoice.created_at,
                "expiresAt": invoice.expires_at,
                "sale": {
                    "key": to_hex(sale.key.expose()),
                    "fiat": { "minor": 49000, "digits": 0, "currency": "SAT" },
                    "note": "Order 1"
                },
                "taker": sale_of_ref(&merchant, "ORD-1").taker,
                "confirmed": true
            }),
            "the confirmed lease",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn is_lightning_only_below_1000_sats_the_lot_is_not_even_read() {
        let merchant = merchant();
        let invoice = client(&merchant).create_invoice(&Order::sats("ORD-2", 999)).await.unwrap();
        assert_eq!(invoice.onchain_address, None);
        assert_eq!(invoice.payment_uri, format!("lightning:{}", invoice.bolt11.as_deref().unwrap()));
        assert!(merchant.chain.asked().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn is_onchain_only_above_the_lightning_address_maximum() {
        let merchant = merchant();
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(4_000_000_000)));
        let invoice = client(&merchant)
            .create_invoice(&Order::sats("ORD-3", 150_000_000).duration_seconds(600))
            .await
            .unwrap();
        let now = merchant.now();
        assert_eq!(
            (invoice.bolt11.as_deref(), invoice.payment_hash.as_deref(), invoice.verify_url.as_deref()),
            (None, None, None)
        );
        assert_eq!((invoice.sats, invoice.created_at, invoice.expires_at), (150_000_000, now, now + 600));
        assert_eq!(
            invoice.payment_uri,
            format!("bitcoin:{}?amount=1.5", invoice.onchain_address.as_deref().unwrap())
        );
        // No invoice asked, nothing declared: the lease alone, then its mark.
        assert!(merchant.invoices().is_empty());
        let received = merchant.net.get(&merchant.key_relays[0]).received();
        assert_eq!(received.len(), 2);
        let mark = open_as_merchant(&merchant, &received[1]);
        assert_eq!(mark.get("confirmed"), Some(&Json::Bool(true)));
        assert_eq!(mark.get("invoice"), Some(&Json::Null));
        assert_eq!(mark.get("verifyUrl"), Some(&Json::Null));
        assert_eq!(mark.get("createdAt"), Some(&Json::integer(now)));
        assert_eq!(mark.get("expiresAt"), Some(&Json::integer(now + 600)));
        assert_eq!(mark.get("end"), Some(&Json::integer(now + 720)));
        assert_eq!(
            json(&client(&merchant).get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "open", "expiresAt": invoice.expires_at, "received": "0", "rest": null })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn is_lightning_only_without_a_lot_and_fails_onchain_only() {
        let merchant = merchant();
        for relay in &merchant.key_relays {
            merchant.net.get(relay).clear_events();
        }
        let relays =
            Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
        merchant.publish_channel(&merchant.channel_value(100, Json::object([("relays", relays)])), 100);
        let client = client(&merchant);
        assert_eq!(client.merchant().await.unwrap().onchain_addresses, 0);
        assert_eq!(client.create_invoice(&Order::sats("ORD-4", 49_000)).await.unwrap().onchain_address, None);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        assert_eq!(
            client.create_invoice(&Order::sats("ORD-5", 49_000)).await.unwrap_err().code(),
            ErrorCode::OnchainUnavailable
        );
        // Nothing published for that order.
        assert_eq!(merchant.invoices().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn is_lightning_only_with_an_empty_lot() {
        let merchant = merchant();
        merchant.publish_lot(&[], 91);
        let client = client(&merchant);
        assert_eq!(client.merchant().await.unwrap().onchain_addresses, 0);
        assert_eq!(client.create_invoice(&Order::sats("ORD-9", 49_000)).await.unwrap().onchain_address, None);
        // Nothing asked of the explorers: no address to check.
        assert!(merchant.chain.asked().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn is_lightning_only_when_the_explorer_does_not_answer_and_network_onchain_only() {
        let merchant = merchant();
        merchant.chain.set_down(Service::Explorer, true);
        let client = client(&merchant);
        assert_eq!(client.create_invoice(&Order::sats("ORD-6", 49_000)).await.unwrap().onchain_address, None);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        assert_eq!(
            client.create_invoice(&Order::sats("ORD-7", 49_000)).await.unwrap_err().code(),
            ErrorCode::Network
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_more_than_21_million_bitcoins() {
        let merchant = merchant();
        let error =
            client(&merchant).create_invoice(&Order::sats("ORD-8", 2_100_000_000_000_001)).await.unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("sats")));
    }

    #[tokio::test(start_paused = true)]
    async fn counts_the_lot_addresses_in_merchant() {
        let merchant = merchant();
        assert_eq!(client(&merchant).merchant().await.unwrap().onchain_addresses, 3);
    }
}

mod leasing_an_address {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn never_leases_an_address_another_order_holds_until_its_lease_ended() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let client = client(&merchant);
        let first = client.create_invoice(&Order::sats("L-1", 49_000).duration_seconds(60)).await.unwrap();
        assert_eq!(first.onchain_address.as_deref(), Some(lot[0].as_str()));
        let second = client.create_invoice(&Order::sats("L-2", 49_000)).await.unwrap();
        assert_eq!(second.onchain_address, None);
        // Its lease ends 120 s after the invoice's end; another server's clock may be 300 s behind.
        merchant.set_now(first.expires_at + 120 + 300);
        assert_eq!(client.create_invoice(&Order::sats("L-3", 49_000)).await.unwrap().onchain_address, None);
        merchant.advance(1);
        assert_eq!(
            client.create_invoice(&Order::sats("L-4", 49_000)).await.unwrap().onchain_address.as_deref(),
            Some(lot[0].as_str())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn skips_an_address_paid_already_and_publishes_its_witness_none() {
        let merchant = merchant();
        let lot = lot();
        let paid = payment_with(
            &txid("old"),
            &lot[0],
            20_000,
            Paying { height: Some(960_000), ..Paying::default() },
        );
        merchant.chain.add(&lot[0], paid.clone());
        merchant.publish_lot(&lot[..2], 91);
        let invoice = client(&merchant).create_invoice(&Order::sats("L-5", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address.as_deref(), Some(lot[1].as_str()));
        // Whichever was tried first: the paid one is never leased.
        assert!(leases_of(&merchant, &lot[0]).is_empty());
        merchant.publish_lot(&lot[..1], 92);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("L-6", 49_000)).await.unwrap_err().code(),
            ErrorCode::OnchainUnavailable
        );
        assert_eq!(
            witnesses(&merchant),
            vec![(
                Witness {
                    address: lot[0].clone(),
                    txid: paid.txid.clone(),
                    sale: None,
                    sats: 20_000,
                    inputs: vec![format!("{}:0", txid(format!("coin of {}", paid.txid)))],
                    replacement: false,
                    expires_at: None,
                },
                merchant.now()
            )]
        );
    }

    /// A merchant whose lot is its first address, and an event of the seen author at no witness
    /// address, with that address's tag as an `o` tag: no witness (its content opens to nothing),
    /// its signature checking out or not.
    fn named_by_another_event(signed: bool) -> (TestMerchant, String) {
        let merchant = merchant();
        let address = lot()[0].clone();
        merchant.publish_lot(std::slice::from_ref(&address), 91);
        let seen = seen_of(&merchant.integration_key);
        let mut event = sign_event(
            EventTemplate {
                kind: 30078.0,
                created_at: merchant.now() - 100,
                tags: vec![
                    vec!["d".to_owned(), "ef".repeat(32)],
                    vec!["o".to_owned(), address_tag(&seen.address_key, &address)],
                ],
                content: "not a witness".to_owned(),
            },
            &seen.secret_key,
            &OsRandom,
        );
        if !signed {
            event.sig = "00".repeat(64);
        }
        for relay in &merchant.key_relays {
            merchant.net.get(relay).store_event(&event);
        }
        (merchant, address)
    }

    #[tokio::test(start_paused = true)]
    async fn never_leases_an_address_any_event_of_the_seen_author_names_a_witness_or_not() {
        let (merchant, _) = named_by_another_event(true);
        let invoice = client(&merchant).create_invoice(&Order::sats("N-9", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, None);
        // One whose signature does not check out names nothing.
        let (merchant, address) = named_by_another_event(false);
        let invoice = client(&merchant).create_invoice(&Order::sats("N-9", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address.as_deref(), Some(address.as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn withdraws_its_lease_unconfirmed_when_another_server_leased_the_address_at_once() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let other = sale_of_ref(&merchant, "ANOTHER-SERVER");
        let raced = Arc::new(AtomicBool::new(false));
        let now = merchant.now();
        // Another server's lease of the same address reaches every relay right after this one's.
        for url in &merchant.key_relays {
            let (raced, d, other, net, relays, address) = (
                raced.clone(),
                d.clone(),
                other.clone(),
                merchant.net.clone(),
                merchant.key_relays.clone(),
                lot[0].clone(),
            );
            merchant.net.get(url).set_behaviour(RelayBehaviour {
                on_event: Some(Arc::new(move |event: &Event, _| {
                    if raced.load(Ordering::SeqCst) || !event.tags.iter().any(|tag| tag.get(1) == Some(&d)) {
                        return;
                    }
                    raced.store(true, Ordering::SeqCst);
                    let terms = LeaseTerms {
                        address: address.clone(),
                        sats: 1000,
                        invoice: None,
                        verify_url: None,
                        created_at: now,
                        expires_at: now + 900,
                        price: DeclaredPrice { minor: 1000, digits: 0, currency: "SAT".to_owned() },
                        note: "Another order".to_owned(),
                        tolerance: 0,
                        confirmed: None,
                    };
                    let competing = lease_event(&other, &terms, now, &OsRandom).unwrap();
                    for relay in &relays {
                        net.get(relay).take(&competing);
                    }
                })),
                ..RelayBehaviour::default()
            });
        }
        let invoice = client(&merchant).create_invoice(&Order::sats("L-7", 49_000)).await.unwrap();
        // It saw the other lease after its own was on a majority: not confirmed, Lightning only. Its
        // lease, unmarked, is withdrawn: it gives the invoice no address.
        assert_eq!(invoice.onchain_address, None);
        let records: Vec<(LeaseRecord, Event)> = leases_of(&merchant, &lot[0])
            .into_iter()
            .filter(|(_, event)| event.pubkey != other.author)
            .collect();
        assert_eq!(kinds(&records), vec!["lease", "withdrawn"]);
        assert_eq!(open_as_merchant(&merchant, &records[0].1).get("confirmed"), Some(&Json::Bool(false)));
        assert!(records[1].1.created_at > records[0].1.created_at);
        let found = client(&merchant).find_invoices("L-7").await.unwrap();
        assert_eq!(
            (found[0].bolt11.as_deref(), found[0].onchain_address.as_deref()),
            (invoice.bolt11.as_deref(), None)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn leaves_its_lease_confirmed_when_the_declaration_fails_it_holds_the_address() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let d = lease_address(&merchant.registry_key, &lot[0]);
        for url in &merchant.key_relays[..2] {
            let d = d.clone();
            merchant.net.get(url).set_behaviour(RelayBehaviour {
                // Leases and withdrawals are taken, declarations refused.
                refuse_event: Some(Arc::new(move |event: &Event| {
                    (!event.tags.iter().any(|tag| tag.get(1) == Some(&d))).then(|| "blocked: no".to_owned())
                })),
                ..RelayBehaviour::default()
            });
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("L-8", 49_000)).await.unwrap_err().code(),
            ErrorCode::Network
        );
        // The lease and its mark: never withdrawn.
        assert_eq!(kinds(&leases_of(&merchant, &lot[0])), vec!["lease", "lease"]);
        for url in &merchant.key_relays {
            merchant.net.get(url).set_behaviour(RelayBehaviour::default());
        }
        // It holds the address until its end: another order gets none.
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("L-9", 49_000)).await.unwrap().onchain_address,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn never_withdraws_a_confirmed_lease_when_its_mark_fails() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let d = lease_address(&merchant.registry_key, &lot[0]);
        // Two relays of three take the lease, and refuse what comes after it at its address: its mark.
        for url in &merchant.key_relays[1..] {
            let d = d.clone();
            let taken = Arc::new(AtomicUsize::new(0));
            merchant.net.get(url).set_behaviour(RelayBehaviour {
                refuse_event: Some(Arc::new(move |event: &Event| {
                    (event.tags.iter().any(|tag| tag.get(1) == Some(&d))
                        && taken.fetch_add(1, Ordering::SeqCst) > 0)
                        .then(|| "blocked: no".to_owned())
                })),
                ..RelayBehaviour::default()
            });
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("L-11", 49_000)).await.unwrap_err().code(),
            ErrorCode::Network
        );
        // The lease and its mark where they were taken: never withdrawn.
        assert_eq!(kinds(&leases_of(&merchant, &lot[0])), vec!["lease", "lease"]);
        for url in &merchant.key_relays[1..] {
            let kinds: Vec<&str> = merchant
                .net
                .get(url)
                .events()
                .iter()
                .filter_map(|value| open_lease_record(value, &merchant.registry_key, &d))
                .map(|record| if record.outside == LeaseHold::Withdrawn { "withdrawn" } else { "lease" })
                .collect();
            assert_eq!(kinds, vec!["lease"], "{url}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn never_withdraws_a_confirmed_lease_when_its_checkout_link_fails() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        // Two relays of three refuse checkout links (their expiration tag).
        for url in &merchant.key_relays[1..] {
            merchant.net.get(url).set_behaviour(RelayBehaviour {
                refuse_event: Some(Arc::new(|event: &Event| {
                    event
                        .tags
                        .iter()
                        .any(|tag| tag.first().map(String::as_str) == Some("expiration"))
                        .then(|| "blocked: no".to_owned())
                })),
                ..RelayBehaviour::default()
            });
        }
        let result = client(&merchant).create_invoice(&Order::sats("L-12", 49_000).checkout(true)).await;
        assert_eq!(result.unwrap_err().code(), ErrorCode::Network);
        // Confirmed and marked, then the link failed: the lease holds its address until its end.
        assert_eq!(kinds(&leases_of(&merchant, &lot[0])), vec!["lease", "lease"]);
        for url in &merchant.key_relays {
            merchant.net.get(url).set_behaviour(RelayBehaviour::default());
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("L-13", 49_000)).await.unwrap().onchain_address,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn publishes_nothing_but_its_withdrawal_when_the_lease_does_not_reach_a_majority() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        for url in &merchant.key_relays[..2] {
            merchant.net.get(url).set_behaviour(RelayBehaviour::refusing("blocked: no"));
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("L-10", 49_000)).await.unwrap_err().code(),
            ErrorCode::Network
        );
        // The lease, then its withdrawal: no mark, no declaration, no link.
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let third: Vec<Option<&str>> = merchant
            .net
            .get(&merchant.key_relays[2])
            .received()
            .iter()
            .map(|event| {
                open_lease_record(&event.to_json(), &merchant.registry_key, &d).map(|record| {
                    match record.outside {
                        LeaseHold::Lease { .. } => "lease",
                        LeaseHold::Withdrawn => "withdrawn",
                        LeaseHold::Newer => "newer",
                    }
                })
            })
            .collect();
        assert_eq!(third, vec![Some("lease"), Some("withdrawn")]);
    }

    #[tokio::test(start_paused = true)]
    async fn writes_nothing_more_once_its_future_is_dropped_while_its_lease_is_confirmed() {
        let merchant = merchant();
        let address = lot()[0].clone();
        merchant.publish_lot(std::slice::from_ref(&address), 91);
        let d = lease_address(&merchant.registry_key, &address);
        let leased = Arc::new(AtomicBool::new(false));
        for (index, url) in merchant.key_relays.iter().enumerate() {
            let (muted, seen, d) = (leased.clone(), leased.clone(), d.clone());
            merchant.net.get(url).set_behaviour(RelayBehaviour {
                // Once the lease is published, two relays never answer the read of its address:
                // its confirmation waits for them.
                mute_query: Some(Arc::new(move |filter: &Json| {
                    index > 0
                        && muted.load(Ordering::SeqCst)
                        && filter
                            .get("#d")
                            .and_then(Json::as_array)
                            .is_some_and(|ds| ds.iter().any(|item| item.as_str() == Some(d.as_str())))
                })),
                on_event: Some(Arc::new(move |event: &Event, _| {
                    if event.tags.iter().any(|tag| tag.first().map(String::as_str) == Some("d")) {
                        seen.store(true, Ordering::SeqCst);
                    }
                })),
                ..RelayBehaviour::default()
            });
        }
        let client = client(&merchant);
        let order = Order::sats("X-1", 49_000).duration_seconds(600);
        let call = client.create_invoice(&order);
        // The shop's own deadline: dropped while the lease is being confirmed.
        assert!(tokio::time::timeout(Duration::from_millis(500), call).await.is_err());
        assert!(leased.load(Ordering::SeqCst), "dropped before its lease was published");
        let written: Vec<usize> =
            merchant.key_relays.iter().map(|url| merchant.net.get(url).received().len()).collect();
        tokio::time::sleep(Duration::from_secs(60)).await;
        // No withdrawal, no mark, no declaration: nothing written after.
        for (index, url) in merchant.key_relays.iter().enumerate() {
            assert_eq!(merchant.net.get(url).received().len(), written[index], "{url}");
        }
    }

    /// Has breez.tips make invoices of 40 550 characters: the lease seals the invoice twice, as the
    /// declaration does, with some 150 bytes more, so such an invoice fits a declaration (its
    /// inside within NIP-44's padded 40 960 bytes) and not a lease (padded to 49 152 bytes, too
    /// large once sealed again).
    fn invoices_too_large_for_a_lease(merchant: &TestMerchant) {
        invoices_of(merchant, 40_550);
    }

    /// Has breez.tips make invoices of `length` characters.
    fn invoices_of(merchant: &TestMerchant, length: usize) {
        let now = merchant.now();
        merchant.set_tamper(Some(move |made: MadeInvoice| {
            let sized = |words: usize| {
                let mut spec = InvoiceSpec::new(&made.payment_hash, now);
                spec.amount_msat = Some(made.amount_msat);
                spec.description_hash = Some(metadata_hash(&metadata()));
                spec.expiry_seconds = Some(made.expiry);
                spec.extra = (0..39).map(|_| (31, vec![0; 1023])).collect();
                spec.extra.push((31, vec![0; words]));
                make_invoice(&spec)
            };
            MadeInvoice { pr: sized(length - sized(0).len()), ..made }
        }));
    }

    /// Random bytes from the OS, counted.
    #[derive(Clone, Default)]
    struct Counted(Arc<AtomicUsize>);

    impl crate::runtime::Random for Counted {
        fn fill(&self, bytes: &mut [u8]) {
            self.0.fetch_add(1, Ordering::SeqCst);
            OsRandom.fill(bytes);
        }
    }

    /// The merchant's breez.tips, which tells `asked` how many random draws `random` made when the
    /// invoice was asked.
    struct CountsAtTheInvoice {
        http: FakeHttp,
        random: Counted,
        asked: Arc<Mutex<Option<usize>>>,
    }

    impl HttpClient for CountsAtTheInvoice {
        fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
            if request.url.starts_with(super::super::support::merchant::CALLBACK) {
                *self.asked.lock().unwrap() = Some(self.random.0.load(Ordering::SeqCst));
            }
            self.http.get(request)
        }
    }

    /// SPEC.md §17 step 6: the lease is measured as first published, `"confirmed": false` (the
    /// longer of its two forms), with a deposit address of 62 characters, and the client's random
    /// bytes left alone. At the boundary (an invoice whose lease fits marked `"confirmed": true`
    /// and not as first published), the invoice is `invalid_invoice` before anything is asked of
    /// the relays or the explorer, or published; one character less, its address is leased.
    #[tokio::test(start_paused = true)]
    async fn measures_the_lease_as_first_published_at_the_boundary_of_its_two_forms() {
        // The lease of an invoice of `length` characters, as the client makes it for "L-15" (49 000
        // sats, its note the reference, no tolerance), in a form: whether it fits.
        let probe = merchant();
        let sale = sale_of_ref(&probe, "L-15");
        let fits = |length: usize, confirmed: bool| {
            let mut spec = InvoiceSpec::new(&"00".repeat(32), probe.now());
            spec.amount_msat = Some(49_000_000);
            spec.description_hash = Some(metadata_hash(&metadata()));
            spec.expiry_seconds = Some(900);
            spec.extra = (0..39).map(|_| (31, vec![0; 1023])).collect();
            spec.extra.push((31, Vec::new()));
            let base = make_invoice(&spec).len();
            spec.extra.last_mut().unwrap().1 = vec![0; length - base];
            let invoice = make_invoice(&spec);
            assert_eq!(invoice.len(), length);
            let terms = LeaseTerms {
                address: crate::onchain::address::SIZED_ADDRESS.to_owned(),
                sats: 49_000,
                invoice: Some(invoice),
                verify_url: Some(format!("https://breez.tips/lnurlp/verify/{}", "00".repeat(32))),
                created_at: probe.now(),
                expires_at: probe.now() + 900,
                price: DeclaredPrice { minor: 49_000, digits: 0, currency: "SAT".to_owned() },
                note: "L-15".to_owned(),
                tolerance: 0,
                confirmed: Some(confirmed),
            };
            lease_event(&sale, &terms, probe.now(), &OsRandom).is_some()
        };
        let length = (40_400..42_000).find(|&length| !fits(length, false)).expect("a lease too large");
        assert!(fits(length, true), "{length}: marked, it fits");

        // At the boundary: refused before the lot, its leases or its witnesses are read, the
        // explorer asked, or anything published; no random byte drawn after the invoice was asked
        // but for its declaration, made before.
        let merchant = merchant();
        let address = lot()[0].clone();
        merchant.publish_lot(std::slice::from_ref(&address), 91);
        invoices_of(&merchant, length);
        let random = Counted::default();
        let asked = Arc::new(Mutex::new(None));
        let client = merchant
            .client()
            .random(random.clone())
            .http_client(CountsAtTheInvoice {
                http: merchant.http.clone(),
                random: random.clone(),
                asked: asked.clone(),
            })
            .build()
            .unwrap();
        let queries: Vec<usize> =
            merchant.key_relays.iter().map(|url| merchant.net.get(url).queries().len()).collect();
        let error = client.create_invoice(&Order::sats("L-15", 49_000)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInvoice, "{error}");
        assert!(error.message().contains("lease of an address"), "{error}");
        let made = merchant.invoices();
        assert_eq!(made[0].pr.len(), length);
        let lot_d = Json::from(lot_address(&merchant.integration_key));
        let lease_d = Json::from(lease_address(&merchant.registry_key, &address));
        for (index, url) in merchant.key_relays.iter().enumerate() {
            assert!(merchant.net.get(url).received().is_empty(), "published on {url}");
            for filter in &merchant.net.get(url).queries()[queries[index]..] {
                let ds = filter.get("#d").and_then(Json::as_array).unwrap_or_default();
                assert!(
                    !ds.contains(&lot_d) && !ds.contains(&lease_d) && filter.get("#o").is_none(),
                    "read on {url}: {}",
                    json::stringify(filter)
                );
            }
        }
        assert!(merchant.http.calls().iter().all(|call| !call.url.starts_with(MEMPOOL_URL)));
        let declaration = Counted::default();
        let input = DeclarationInput {
            sale: &sale_of_ref(&merchant, "L-15"),
            invoice: &made[0].pr,
            verify_url: &made[0].verify,
            payment_hash: &made[0].payment_hash,
            price: &DeclaredPrice { minor: 49_000, digits: 0, currency: "SAT".to_owned() },
            note: "L-15",
            created_at: merchant.now(),
            rest: None,
        };
        assert!(declaration_event(&input, &declaration).is_some());
        let after = random.0.load(Ordering::SeqCst) - asked.lock().unwrap().expect("the invoice was asked");
        assert_eq!(after, declaration.0.load(Ordering::SeqCst));

        // One character less: leased.
        let shorter = super::merchant();
        shorter.publish_lot(std::slice::from_ref(&address), 91);
        invoices_of(&shorter, length - 1);
        let invoice = super::client(&shorter).create_invoice(&Order::sats("L-15", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address.as_deref(), Some(address.as_str()));
        assert_eq!(shorter.invoices()[0].pr.len(), length - 1);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_invoice_its_lease_cannot_hold_before_anything_is_read_or_published() {
        // The lot's one address free, or paid already (its witness none would be published).
        for paid in [false, true] {
            let merchant = merchant();
            let address = lot()[0].clone();
            merchant.publish_lot(std::slice::from_ref(&address), 91);
            if paid {
                merchant.chain.add(&address, payment(&txid("earlier"), &address, 1000));
            }
            invoices_too_large_for_a_lease(&merchant);
            let queries: Vec<usize> =
                merchant.key_relays.iter().map(|url| merchant.net.get(url).queries().len()).collect();
            let error = client(&merchant).create_invoice(&Order::sats("L-14", 49_000)).await.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInvoice, "paid: {paid}: {error}");
            assert!(error.message().contains("lease of an address"), "{error}");
            // It fits a declaration: the lease alone cannot hold it.
            let made = merchant.invoices();
            assert_eq!(made.len(), 1);
            assert_eq!(made[0].pr.len(), 40_550);
            let sale = sale_of(
                &merchant.integration_key,
                &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
                "L-14",
            );
            let input = DeclarationInput {
                sale: &sale,
                invoice: &made[0].pr,
                verify_url: &made[0].verify,
                payment_hash: &made[0].payment_hash,
                price: &DeclaredPrice { minor: 49_000, digits: 0, currency: "SAT".to_owned() },
                note: "L-14",
                created_at: merchant.now(),
                rest: None,
            };
            assert!(declaration_event(&input, &OsRandom).is_some());
            // Nothing published (no lease, no witness none, no declaration), the lot not even read
            // (nor the leases of its addresses, nor its witnesses), the explorer not asked.
            let lot_d = Json::from(lot_address(&merchant.integration_key));
            let lease_d = Json::from(lease_address(&merchant.registry_key, &address));
            for (index, url) in merchant.key_relays.iter().enumerate() {
                assert!(merchant.net.get(url).received().is_empty(), "paid: {paid}: published on {url}");
                for filter in &merchant.net.get(url).queries()[queries[index]..] {
                    let ds = filter.get("#d").and_then(Json::as_array).unwrap_or_default();
                    assert!(
                        !ds.contains(&lot_d) && !ds.contains(&lease_d) && filter.get("#o").is_none(),
                        "paid: {paid}: read on {url}: {}",
                        json::stringify(filter)
                    );
                }
            }
            assert!(
                merchant.http.calls().iter().all(|call| !call.url.starts_with(MEMPOOL_URL)),
                "paid: {paid}"
            );
        }
    }
}

mod the_payment_of_an_invoice_with_an_address {
    use super::*;

    async fn setup() -> (TestMerchant, Client, Invoice, String) {
        let merchant = merchant();
        merchant.publish_lot(&lot()[..1], 91);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("P-1", 49_000).duration_seconds(600)).await.unwrap();
        let address = invoice.onchain_address.clone().unwrap();
        (merchant, client, invoice, address)
    }

    fn sale(merchant: &TestMerchant) -> String {
        sale_keys(&merchant.integration_key, "P-1").author
    }

    #[tokio::test(start_paused = true)]
    async fn is_unconfirmed_once_enough_is_sent_its_witness_published_then_paid_on_both_explorers() {
        let (merchant, client, invoice, address) = setup().await;
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "open", "expiresAt": invoice.expires_at, "received": "0", "rest": null })
        );
        let tx = payment(&txid("pay"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "unconfirmed", "received": "49000", "confirmations": 0, "txids": [tx.txid] })
        );
        // Seen while the lease runs: the witness of the order's sale, which the merchant's app reads.
        let seen = witnesses(&merchant);
        assert_eq!(seen.len(), 1);
        let (witness, _) = &seen[0];
        assert_eq!((witness.address.as_str(), witness.txid.as_str()), (address.as_str(), tx.txid.as_str()));
        assert_eq!(
            (witness.sale.clone(), witness.sats, witness.replacement),
            (Some(sale(&merchant)), 49_000, false)
        );
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 1);
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { confirmations: 2, .. }), "{status:?}");
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 2);
        // 3 confirmations on the explorer read (mempool.space): paid, no other explorer asked.
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": "49000", "txids": [tx.txid] })
        );
        assert_eq!(
            merchant.chain.asked().iter().filter(|url| !url.starts_with(&format!("{MEMPOOL_URL}/"))).count(),
            0
        );
        // Long after the invoice's end: the witness says it came in time.
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": "49000", "txids": [tx.txid] })
        );
        // One witness: a check that finds it adds nothing.
        assert_eq!(witnesses(&merchant).len(), 1);
        assert!(merchant.chain.blockcypher_asked().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn is_open_while_underpaid_then_expired_with_what_was_received() {
        let (merchant, client, invoice, address) = setup().await;
        merchant.chain.add(
            &address,
            payment_with(
                &txid("part"),
                &address,
                20_000,
                Paying { height: Some(969_990), ..Paying::default() },
            ),
        );
        // Its rest, asked in Lightning too (rest.rs).
        let status = client.get_status(&invoice).await.unwrap();
        let PaymentStatus::Open { expires_at, received, rest: Some(rest) } = &status else {
            panic!("{status:?}")
        };
        assert_eq!((*expires_at, *received, rest.sats), (invoice.expires_at, 20_000, 29_000));
        merchant.set_now(invoice.expires_at + 121);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "20000" })
        );
    }

    /// An RFC 3339 date of Unix seconds, as BlockCypher writes it (`toISOString`).
    fn iso(seconds: i64) -> String {
        let days = seconds.div_euclid(86_400);
        let rest = seconds.rem_euclid(86_400);
        // Days to a civil date (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        )
    }

    #[test]
    fn writes_dates_as_iso_strings() {
        assert_eq!(iso(1_791_637_512), "2026-10-10T13:05:12.000Z");
        assert_eq!(blockcypher_milliseconds(&iso(1_791_637_512)), Some(1_791_637_512_000));
    }

    #[tokio::test(start_paused = true)]
    async fn is_expired_for_a_payment_no_check_saw_received_late_by_blockcypher_time() {
        let (merchant, client, invoice, address) = setup().await;
        merchant.set_now(invoice.expires_at + 3600);
        let tx = payment(&txid("late"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        merchant.chain.set_received(&tx.txid, &iso(invoice.expires_at + 121));
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "0" })
        );
        assert_eq!(
            merchant.chain.blockcypher_asked(),
            vec![format!("{BLOCKCYPHER_URL}/txs/{}?limit=1&includeHex=false", tx.txid)]
        );
        // Of no order: a witness none, so that the merchant's app takes the address out of the lot.
        let seen = witnesses(&merchant);
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].0.txid.as_str(), seen[0].0.sale.as_deref()), (tx.txid.as_str(), None));
    }

    #[tokio::test(start_paused = true)]
    async fn never_publishes_the_witness_none_of_a_late_payment_over_a_witness_of_a_newer_format() {
        let (merchant, _, invoice, address) = setup().await;
        let warnings = Warnings::default();
        let client = merchant.client().logger(warnings.clone()).build().unwrap();
        merchant.set_now(invoice.expires_at + 3600);
        let tx = payment(&txid("late"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        merchant.chain.set_received(&tx.txid, &iso(invoice.expires_at + 121));
        // A newer version's witness none of it: what it says cannot be read, its address can.
        let seen = seen_of(&merchant.integration_key);
        let d = witness_address(&seen.address_key, &address, &tx.txid, None);
        let newer = sign_event(
            EventTemplate {
                kind: 30078.0,
                created_at: merchant.now() - 60,
                tags: vec![
                    vec!["d".to_owned(), d.clone()],
                    vec!["o".to_owned(), order_tag(&seen.address_key, &address, None)],
                    vec!["o".to_owned(), address_tag(&seen.address_key, &address)],
                ],
                content: "#".to_owned(),
            },
            &seen.secret_key,
            &OsRandom,
        );
        for relay in &merchant.key_relays {
            merchant.net.get(relay).store_event(&newer);
        }
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "0" })
        );
        // Late, named by it: no witness none published over it.
        let written = |relay: &String| {
            merchant
                .net
                .get(relay)
                .received()
                .iter()
                .filter(|event| event.tag("d") == Some(d.as_str()))
                .count()
        };
        assert_eq!(merchant.key_relays.iter().map(written).sum::<usize>(), 0);
        assert!(witnesses(&merchant).is_empty());
        let logged = warnings.all();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("witness of a payment of this order has a newer format"), "{logged:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn judges_a_payment_by_the_time_the_explorer_listed_it_never_an_earlier_one() {
        let (merchant, client, invoice, address) = setup().await;
        let end = invoice.expires_at + 120;
        // The check starts a second before the lease's end; the explorer answers 2 s later.
        merchant.set_now(end - 1);
        let tx = payment(&txid("at the end"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        merchant.chain.set_received(&tx.txid, &iso(end + 1));
        let clock = merchant.clock.clone();
        let listing = format!("{MEMPOOL_URL}/address/{address}/txs");
        merchant.set_override(Some(move |call: &Call| {
            if call.url == listing {
                clock.advance(2);
            }
            None
        }));
        // Listed after the lease's end: it may have been broadcast after it. BlockCypher's time
        // tells: late, of no order.
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "open", "expiresAt": invoice.expires_at, "received": "0", "rest": null })
        );
        assert_eq!(merchant.chain.blockcypher_asked().len(), 1);
        let seen = witnesses(&merchant);
        assert_eq!(seen.len(), 1);
        assert_eq!((seen[0].0.txid.as_str(), seen[0].0.sale.as_deref()), (tx.txid.as_str(), None));
    }

    #[tokio::test(start_paused = true)]
    async fn counts_a_payment_no_check_saw_that_blockcypher_received_in_time() {
        let (merchant, client, invoice, address) = setup().await;
        merchant.set_now(invoice.expires_at + 3600);
        let tx = payment(&txid("in time"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        merchant.chain.set_received(&tx.txid, &iso(invoice.expires_at + 100));
        let status = client.get_status(&invoice).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: 49_000, .. }), "{status:?}");
        let seen = witnesses(&merchant);
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].0.txid.as_str(), seen[0].0.sale.clone(), seen[0].0.replacement),
            (tx.txid.as_str(), Some(sale(&merchant)), false)
        );
        // Its witness spares the next check the question.
        client.get_status(&invoice).await.unwrap();
        assert_eq!(merchant.chain.blockcypher_asked().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn counts_a_fee_bump_after_the_lease_end_of_a_payment_seen_in_time() {
        let (merchant, client, invoice, address) = setup().await;
        let first = payment(&txid("first"), &address, 49_000);
        merchant.chain.add(&address, first.clone());
        client.get_status(&invoice).await.unwrap();
        merchant.set_now(invoice.expires_at + 3600);
        merchant.chain.drop_tx(&address, &first.txid);
        let mut coins = first.coins();
        coins.push(format!("{}:1", txid("fee")));
        let bump =
            payment_with(&txid("bump"), &address, 49_000, Paying { coins: Some(coins), ..Paying::default() });
        merchant.chain.add(&address, bump.clone());
        let status = client.get_status(&invoice).await.unwrap();
        assert_eq!(
            json(&status),
            serde_json::json!({ "state": "unconfirmed", "received": "49000", "confirmations": 0, "txids": [bump.txid] })
        );
        assert!(witnesses(&merchant).iter().any(|(witness, _)| witness.txid == bump.txid
            && witness.sale.as_deref() == Some(sale(&merchant).as_str())
            && witness.replacement));
        // Nothing to ask BlockCypher: all of it stands for the payment it replaces.
        assert!(merchant.chain.blockcypher_asked().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn fails_network_when_the_explorer_does_not_answer_unless_lightning_was_paid() {
        let (merchant, client, invoice, _) = setup().await;
        merchant.chain.set_down(Service::Explorer, true);
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        merchant.pay_invoice(invoice.payment_hash.as_deref().unwrap());
        let status = client.get_status(&invoice).await.unwrap();
        assert_eq!(json(&status)["method"], "lightning");
    }

    /// SPEC.md §14 step 3 and §31: a paid Lightning invoice wins over every failure of the
    /// on-chain part, not only `revoked`: relays that answer without the channel
    /// (`channel_not_found`), relays that do not answer (`network`).
    #[tokio::test(start_paused = true)]
    async fn is_paid_by_its_lightning_invoice_whatever_its_onchain_part_fails_with() {
        for failure in [ErrorCode::ChannelNotFound, ErrorCode::Network] {
            let merchant = merchant();
            merchant.publish_lot(&lot()[..2], 91);
            let client = client(&merchant);
            let unpaid = client.create_invoice(&Order::sats("F-1", 49_000)).await.unwrap();
            let paid = client.create_invoice(&Order::sats("F-2", 49_000)).await.unwrap();
            assert!(unpaid.onchain_address.is_some() && paid.onchain_address.is_some());
            merchant.pay_invoice(paid.payment_hash.as_deref().unwrap());
            for url in &merchant.key_relays {
                let relay = merchant.net.get(url);
                match failure {
                    // They answer, without the channel.
                    ErrorCode::ChannelNotFound => relay.clear_events(),
                    _ => relay.set_behaviour(RelayBehaviour::mute()),
                }
            }
            let code = |result: Result<PaymentStatus, crate::Error>| result.map_err(|error| error.code());
            assert_eq!(code(client.get_status(&unpaid).await).unwrap_err(), failure);
            let options = WaitOptions::default().interval_ms(250);
            let waited =
                tokio::time::timeout(Duration::from_secs(60), client.wait_for_payment(&unpaid, options))
                    .await;
            // A failure other than network ends the wait; network is retried until the end.
            if failure == ErrorCode::ChannelNotFound {
                assert_eq!(code(waited.unwrap()).unwrap_err(), failure);
            } else {
                assert!(waited.is_err(), "{waited:?}");
            }
            let status = client.get_status(&paid).await.unwrap();
            assert!(
                matches!(status, PaymentStatus::Paid(Payment::Lightning { .. })),
                "{failure:?}: {status:?}"
            );
            let options = WaitOptions::default().interval_ms(250);
            let waited =
                tokio::time::timeout(Duration::from_secs(60), client.wait_for_payment(&paid, options)).await;
            assert!(
                matches!(waited, Ok(Ok(PaymentStatus::Paid(Payment::Lightning { .. })))),
                "{failure:?}: {waited:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn is_found_by_the_order_next_invoice_pending_while_confirmed_then_paid() {
        let (merchant, client, invoice, address) = setup().await;
        let tx: EsploraTx = payment(&txid("order"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        client.get_status(&invoice).await.unwrap();
        merchant.set_now(invoice.expires_at + 600);
        let pending = client.create_invoice(&Order::sats("P-1", 49_000)).await.unwrap_err();
        assert_eq!(pending.code(), ErrorCode::InvoicePending);
        let declared = pending.invoice().unwrap();
        assert_eq!(
            (declared.bolt11.as_deref(), declared.onchain_address.as_deref()),
            (invoice.bolt11.as_deref(), Some(address.as_str()))
        );
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 5);
        let paid = client.create_invoice(&Order::sats("P-1", 49_000)).await.unwrap_err();
        assert_eq!(paid.code(), ErrorCode::OrderPaid);
        assert_eq!(paid.preimage(), None);
        assert_eq!(
            serde_json::to_value(paid.status().unwrap()).unwrap(),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": "49000", "txids": [tx.txid] })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn is_found_by_find_invoices_with_its_address_an_order_paid_onchain_only_too() {
        let (merchant, client, invoice, address) = setup().await;
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        merchant.publish_lot(&lot()[1..2], 92);
        let onchain_only = client.create_invoice(&Order::sats("P-2", 2_000_000).note("Big")).await.unwrap();
        let found = client.find_invoices("P-1").await.unwrap();
        assert_eq!(
            serde_json::to_value(&found[0]).unwrap(),
            serde_json::json!({
                "ref": "P-1",
                "bolt11": invoice.bolt11,
                "paymentHash": invoice.payment_hash,
                "verifyUrl": invoice.verify_url,
                "onchainAddress": address,
                "paymentUri": invoice.payment_uri,
                "sats": "49000",
                "fiat": null,
                "note": "P-1",
                "createdAt": invoice.created_at,
                "expiresAt": invoice.expires_at,
                "declaredAt": merchant.now()
            })
        );
        assert_eq!(
            serde_json::to_value(client.find_invoices("P-2").await.unwrap()).unwrap(),
            serde_json::json!([{
                "ref": "P-2",
                "bolt11": null,
                "paymentHash": null,
                "verifyUrl": null,
                "onchainAddress": onchain_only.onchain_address,
                "paymentUri": onchain_only.payment_uri,
                "sats": "2000000",
                "fiat": null,
                "note": "Big",
                "createdAt": onchain_only.created_at,
                "expiresAt": onchain_only.expires_at,
                // Its confirmed lease: marked a second after the lease.
                "declaredAt": onchain_only.created_at + 1
            }])
        );
        // Pending: its declaration and its lease published again, nothing else made.
        let before = merchant.invoices().len();
        assert_eq!(
            client.create_invoice(&Order::sats("P-2", 2_000_000)).await.unwrap_err().code(),
            ErrorCode::InvoicePending
        );
        assert_eq!(merchant.invoices().len(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_stored_invoice_with_an_address_but_no_reference() {
        let (_merchant, client, invoice, _) = setup().await;
        let mut stored = serde_json::to_value(&invoice).unwrap();
        stored.as_object_mut().unwrap().remove("ref");
        let read = InvoiceToCheck::from_json(&stored.to_string()).unwrap();
        assert_eq!(read.reference, None);
        assert_eq!(client.get_status(read).await.unwrap_err().code(), ErrorCode::InvalidOrder);
        let mut to_check = InvoiceToCheck::from(&invoice);
        to_check.reference = None;
        assert_eq!(client.get_status(to_check).await.unwrap_err().code(), ErrorCode::InvalidOrder);
        let mut changed = invoice.clone();
        changed.onchain_address = Some("bc1qnotanaddress".to_owned());
        assert_eq!(client.get_status(&changed).await.unwrap_err().code(), ErrorCode::InvalidOrder);
    }

    #[tokio::test(start_paused = true)]
    async fn reads_an_invoice_without_an_address_field_as_lightning_only() {
        let (merchant, client, invoice, _) = setup().await;
        let mut stored = serde_json::to_value(&invoice).unwrap();
        stored.as_object_mut().unwrap().remove("onchainAddress");
        stored.as_object_mut().unwrap().remove("paymentUri");
        merchant.chain.set_down(Service::Explorer, true);
        let to_check = InvoiceToCheck::from_json(&stored.to_string()).unwrap();
        let status = client.get_status(to_check).await.unwrap();
        assert!(matches!(status, PaymentStatus::Open { received: 0, .. }), "{status:?}");
    }
}

mod wait_for_payment_of_an_invoice_with_an_address {
    use super::*;

    async fn until(condition: impl Fn() -> bool) {
        for _ in 0..500 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(condition());
    }

    #[tokio::test(start_paused = true)]
    async fn checks_the_onchain_part_when_the_explorer_websocket_says_something_changed() {
        let merchant = merchant();
        let socket = merchant.start_explorer_socket();
        merchant.publish_lot(&lot()[..1], 91);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("W-1", 49_000)).await.unwrap();
        let address = invoice.onchain_address.clone().unwrap();
        let statuses: Arc<Mutex<Vec<PaymentStatus>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = statuses.clone();
        // Lightning checked once a minute: what moves here is the socket.
        let options = WaitOptions::default()
            .interval_ms(60_000)
            .on_status(move |status| recorded.lock().unwrap().push(status.clone()));
        let waiting = {
            let (client, invoice) = (client.clone(), invoice.clone());
            tokio::spawn(async move { client.wait_for_payment(&invoice, options).await })
        };
        until(|| socket.messages().len() == 2 && !statuses.lock().unwrap().is_empty()).await;
        assert_same(
            &Json::array(socket.messages()),
            &j!([{ "action": "want", "data": ["blocks"] }, { "track-address": address }]),
            "what the client sends",
        );
        assert_eq!(statuses.lock().unwrap().last().unwrap().state(), "open");
        // Its handshake, as every other: the User-Agent of every implementation.
        let handshakes = socket.handshakes();
        assert_eq!(handshakes.len(), 1);
        assert_eq!(handshakes[0].headers, vec![("User-Agent".to_owned(), "sattleme-Checkout/1".to_owned())]);

        let tx = payment(&txid("watched"), &address, 49_000);
        merchant.chain.add(&address, tx.clone());
        socket.push(&Json::object([("address-transactions", Json::array(vec![tx.to_json()]))]));
        until(|| statuses.lock().unwrap().last().is_some_and(|status| status.state() == "unconfirmed")).await;

        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 2);
        socket.push(&Json::object([(
            "block",
            Json::object([("height", Json::unsigned(merchant.chain.height()))]),
        )]));
        let last = waiting.await.unwrap().unwrap();
        assert_eq!(
            json(&last),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": "49000", "txids": [tx.txid] })
        );
        // Closed once done.
        until(|| socket.open_clients() == 0).await;
    }

    /// The explorer's answers to an address's transactions, held while `hold` is set, as a slow
    /// answer is: until `release` (or until the request's future is dropped).
    #[derive(Clone)]
    struct Holding {
        inner: FakeHttp,
        hold: Arc<AtomicBool>,
        held: Arc<AtomicUsize>,
        release: Arc<Notify>,
    }

    impl HttpClient for Holding {
        fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                if self.hold.load(Ordering::SeqCst) && request.url.ends_with("/txs") {
                    self.held.fetch_add(1, Ordering::SeqCst);
                    self.release.notified().await;
                }
                self.inner.get(request).await
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn leaves_nothing_running_once_it_returned_a_check_it_started_stops() {
        let merchant = merchant();
        let socket = merchant.start_explorer_socket();
        merchant.publish_lot(&lot()[..1], 91);
        let holding = Holding {
            inner: merchant.http.clone(),
            hold: Arc::new(AtomicBool::new(false)),
            held: Arc::new(AtomicUsize::new(0)),
            release: Arc::new(Notify::new()),
        };
        let client = merchant.client().http_client(holding.clone()).build().unwrap();
        let invoice = client.create_invoice(&Order::sats("W-6", 49_000)).await.unwrap();
        let address = invoice.onchain_address.clone().unwrap();
        let statuses = Arc::new(AtomicUsize::new(0));
        let waiting = {
            let (client, invoice, heard) = (client.clone(), invoice.clone(), statuses.clone());
            let options = WaitOptions::default().interval_ms(250).on_status(move |_| {
                heard.fetch_add(1, Ordering::SeqCst);
            });
            tokio::spawn(async move { client.wait_for_payment(&invoice, options).await })
        };
        until(|| socket.messages().len() == 2 && statuses.load(Ordering::SeqCst) > 0).await;
        // A block: a full check starts, and waits for the explorer's answer.
        holding.hold.store(true, Ordering::SeqCst);
        socket.push(&j!({ "block": { "height": 970_001 } }));
        until(|| holding.held.load(Ordering::SeqCst) > 0).await;
        // Meanwhile the Lightning invoice is paid: the wait returns.
        merchant.pay_invoice(invoice.payment_hash.as_deref().unwrap());
        let last = tokio::time::timeout(Duration::from_secs(30), waiting).await.unwrap().unwrap().unwrap();
        assert!(matches!(last, PaymentStatus::Paid(Payment::Lightning { .. })), "{last:?}");
        // Then the explorer answers, a part of the amount listed: the check it held would publish
        // its witness, ask an invoice of the rest and declare it. It stopped with the wait.
        let sent: Vec<usize> =
            merchant.key_relays.iter().map(|url| merchant.net.get(url).received().len()).collect();
        let calls = merchant.http.calls().len();
        let made = merchant.invoices().len();
        merchant.chain.add(&address, payment(&txid("late part"), &address, 10_000));
        holding.hold.store(false, Ordering::SeqCst);
        holding.release.notify_waiters();
        tokio::time::sleep(Duration::from_secs(120)).await;
        for (index, url) in merchant.key_relays.iter().enumerate() {
            assert_eq!(
                merchant.net.get(url).received().len(),
                sent[index],
                "published on {url} after the wait returned"
            );
        }
        let later: Vec<String> = merchant.http.calls()[calls..].iter().map(|call| call.url.clone()).collect();
        assert!(later.is_empty(), "asked after the wait returned: {later:?}");
        assert_eq!(merchant.invoices().len(), made);
    }

    #[tokio::test(start_paused = true)]
    async fn connects_the_explorer_websocket_again_after_a_second_doubled_up_to_30() {
        let merchant = merchant();
        let socket = merchant.start_explorer_socket();
        merchant.publish_lot(&lot()[..1], 91);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("W-3", 49_000)).await.unwrap();
        let waiting = {
            let (client, invoice) = (client.clone(), invoice.clone());
            tokio::spawn(async move {
                client.wait_for_payment(&invoice, WaitOptions::default().interval_ms(60_000)).await
            })
        };
        until(|| socket.messages().len() == 2).await;
        assert_eq!(socket.connections(), 1);
        // Dropped: connected again a second later, the address tracked again.
        socket.drop_clients();
        let dropped = tokio::time::Instant::now();
        until(|| socket.connections() == 2).await;
        let elapsed = dropped.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1000) && elapsed < Duration::from_millis(1100),
            "{elapsed:?}"
        );
        until(|| socket.messages().len() == 4).await;
        assert_same(&socket.messages()[2], &j!({ "action": "want", "data": ["blocks"] }), "asked again");
        // It answered on that connection: the next loss waits a second again (one before any
        // message would count as a failure, its delay doubled).
        socket.push(&j!({ "block": { "height": 970_001 } }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Gone: tried again after 1, 2, 4, 8, 16, then 30 s at most.
        merchant.net.remove_server(crate::protocol::MEMPOOL_WEBSOCKET_URL);
        let gone = tokio::time::Instant::now();
        let mut attempts = Vec::new();
        let mut seen = merchant.net.connections(crate::protocol::MEMPOOL_WEBSOCKET_URL);
        while attempts.len() < 7 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = merchant.net.connections(crate::protocol::MEMPOOL_WEBSOCKET_URL);
            if now > seen {
                attempts.push(gone.elapsed().as_secs());
                seen = now;
            }
        }
        assert_eq!(attempts, vec![1, 3, 7, 15, 31, 61, 91]);
        waiting.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_its_future_is_dropped() {
        let merchant = merchant();
        let socket = merchant.start_explorer_socket();
        merchant.publish_lot(&lot()[..1], 91);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("W-2", 49_000)).await.unwrap();
        let waiting = client.wait_for_payment(&invoice, WaitOptions::default());
        assert!(tokio::time::timeout(Duration::from_millis(50), waiting).await.is_err());
        // Its explorer's WebSocket closed with it.
        tokio::task::yield_now().await;
        assert_eq!(socket.open_clients(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn a_checkout_link_to_an_invoice_with_an_address_is_a_record_of_version_2() {
    let merchant = merchant();
    merchant.publish_lot(&lot()[..1], 91);
    let invoice = client(&merchant)
        .create_invoice(
            &Order::sats("C-1", 49_000).checkout(true).redirect_url("https://shop.example/thanks"),
        )
        .await
        .unwrap();
    let url = invoice.checkout_url.clone().unwrap();
    let CheckoutFragment::Link { link_key, .. } = parse_checkout_fragment(&url[url.find('#').unwrap()..])
    else {
        panic!("Not a link")
    };
    let keys = checkout_keys(&link_key);
    let event = held(&merchant)
        .into_iter()
        .filter_map(|value| valid_event(&value))
        .find(|event| {
            event
                .tags
                .iter()
                .any(|tag| tag.first().map(String::as_str) == Some("d") && tag.get(1) == Some(&keys.address))
        })
        .unwrap();
    let value = json::parse(&decrypt(&event.content, &keys.encryption_key).unwrap())
        .unwrap()
        .get("v")
        .unwrap()
        .clone();
    let address = invoice.onchain_address.clone().unwrap();
    let rest = rest_keys(&merchant.integration_key, "C-1", &address, invoice.expires_at);
    assert_same(
        &value,
        &j!({
            "version": 2,
            "businessName": "Sunrise Bakery",
            "invoice": invoice.bolt11,
            "verifyUrl": invoice.verify_url,
            "onchainAddress": address,
            "sats": 49000,
            "createdAt": invoice.created_at,
            "expiresAt": invoice.expires_at,
            "fiat": null,
            "note": "C-1",
            "redirectUrl": "https://shop.example/thanks",
            // The rest records of this invoice of the order: written by the integration key alone.
            "restAuthor": rest.author,
            "restKey": to_hex(rest.key.expose())
        }),
        "the link's value",
    );
    let record = parse_checkout_value(&value).unwrap().unwrap();
    assert_eq!(record.onchain_address.as_deref(), Some(address.as_str()));
    assert_eq!((record.sats, record.expires_at), (49_000, invoice.expires_at));
    let reader = record.rest.unwrap();
    assert_eq!(
        (reader.author.as_str(), reader.key.as_str()),
        (rest.author.as_str(), to_hex(rest.key.expose()).as_str())
    );
}

#[test]
fn reads_blockcypher_times_as_blockcypher_writes_them_and_refuses_anything_else() {
    assert_eq!(blockcypher_milliseconds("2026-10-10T13:05:12.345Z"), Some(1_791_637_512_345));
    assert_eq!(blockcypher_milliseconds("2026-10-10T13:05:12.91Z"), Some(1_791_637_512_910));
    assert_eq!(blockcypher_milliseconds("2026-10-10T13:05:12Z"), Some(1_791_637_512_000));
    // Dropped, never rounded (SPEC.md §31, Explorers).
    assert_eq!(blockcypher_milliseconds("2026-10-10T13:05:12.345999999Z"), Some(1_791_637_512_345));
    // Year 75, not 1975: before 1970, never a time in a lease.
    assert!(blockcypher_milliseconds("0075-01-01T00:00:00Z").unwrap() < 0);
    for text in [
        "2026-02-30T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-10-10T24:00:00Z",
        "2026-12-31T23:59:60Z",
        "2026-10-10 13:05:12Z",
        "2026-10-10T13:05:12",
        "2026-10-10t13:05:12z",
        "2026-10-10T15:05:12+02:00",
        "2026-10-10T13:05:12.Z",
        "2026-10-10T13:05:12.0000000000Z",
    ] {
        assert_eq!(blockcypher_milliseconds(text), None, "{text}");
    }
}

mod a_removed_integration {
    //! SPEC.md §14, step 3: once the merchant removed the integration, every call that reads the
    //! channel fails `revoked`: making an invoice, finding an order's invoices, reading the
    //! merchant, the on-chain part of a check (the check of an invoice with an address, and the
    //! wait for it, unless its Lightning invoice is paid). The check of an invoice without an
    //! address reads no relay and goes on.

    use super::*;

    fn queries(merchant: &TestMerchant) -> usize {
        merchant.key_relays.iter().map(|url| merchant.net.get(url).queries().len()).sum()
    }

    #[tokio::test(start_paused = true)]
    async fn stops_the_calls_that_read_the_channel_never_the_check_of_a_lightning_invoice() {
        let merchant = merchant();
        merchant.publish_lot(&lot()[..2], 91);
        let client = client(&merchant);
        let lightning = client.create_invoice(&Order::sats("V-1", 500)).await.unwrap();
        assert_eq!(lightning.onchain_address, None);
        let unpaid = client.create_invoice(&Order::sats("V-2", 49_000)).await.unwrap();
        let paid = client.create_invoice(&Order::sats("V-3", 49_000)).await.unwrap();
        assert!(unpaid.onchain_address.is_some() && paid.onchain_address.is_some());
        merchant.publish_channel(&j!({ "version": 1, "status": "removed", "updatedAt": 200 }), 200);

        let revoked = |result: Result<(), crate::Error>| result.map_err(|error| error.code());
        assert_eq!(
            revoked(client.create_invoice(&Order::sats("V-4", 500)).await.map(|_| ())),
            Err(ErrorCode::Revoked)
        );
        assert_eq!(revoked(client.find_invoices("V-2").await.map(|_| ())), Err(ErrorCode::Revoked));
        assert_eq!(revoked(client.merchant().await.map(|_| ())), Err(ErrorCode::Revoked));
        // With an address: its on-chain part reads the merchant's relays.
        assert_eq!(revoked(client.get_status(&unpaid).await.map(|_| ())), Err(ErrorCode::Revoked));
        let options = WaitOptions::default().interval_ms(250);
        let waited =
            tokio::time::timeout(Duration::from_secs(60), client.wait_for_payment(&unpaid, options)).await;
        assert_eq!(revoked(waited.unwrap().map(|_| ())), Err(ErrorCode::Revoked));
        // Unless its Lightning invoice is paid: paid.
        merchant.pay_invoice(paid.payment_hash.as_deref().unwrap());
        let status = client.get_status(&paid).await.unwrap();
        assert!(matches!(status, PaymentStatus::Paid(Payment::Lightning { .. })), "{status:?}");
        let options = WaitOptions::default().interval_ms(250);
        let waited =
            tokio::time::timeout(Duration::from_secs(60), client.wait_for_payment(&paid, options)).await;
        assert!(matches!(waited.unwrap(), Ok(PaymentStatus::Paid(Payment::Lightning { .. }))));
        // Without an address: no relay read, the check goes on (its verify URL needs nothing of
        // the key).
        let before = queries(&merchant);
        assert_eq!(client.get_status(&lightning).await.unwrap().state(), "open");
        merchant.pay_invoice(lightning.payment_hash.as_deref().unwrap());
        let status = client.get_status(&lightning).await.unwrap();
        assert!(matches!(status, PaymentStatus::Paid(Payment::Lightning { .. })), "{status:?}");
        let options = WaitOptions::default().interval_ms(250);
        assert!(client.wait_for_payment(&lightning, options).await.unwrap().is_paid());
        assert_eq!(queries(&merchant), before);
    }
}
