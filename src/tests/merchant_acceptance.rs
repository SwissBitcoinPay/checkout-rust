//! The merchant's acceptance (SPEC.md §31, The merchant's acceptance), end to end against local
//! relays and fakes of breez.tips and of the explorers: the team's record, read on every relay with
//! the witnesses, pays an order underpaid on-chain down to what the merchant accepted, only when a
//! majority of the merchant's relays hold it, whichever majority answers; the pages of the order's
//! checkout links told by an acceptance record (the server's); the check publishing nothing of it.
//! As checkout-node's test/merchant-acceptance.test.ts.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::support::chain::{EsploraTx, Paying, deposit_address, payment, payment_with, txid};
use super::support::merchant::{MadeInvoice, TestMerchant, Warnings};
use super::support::random::bytes;
use super::support::relay::RelayBehaviour;
use crate::client::{Client, WaitOptions};
use crate::declaration::registry_of;
use crate::derive::{channel_keys, merchant_acceptance_address, rest_keys, sale_of};
use crate::error::ErrorCode;
use crate::json::Json;
use crate::model::{Invoice, PaymentStatus};
use crate::nostr::event::{Event, valid_event};
use crate::nostr::record::{Opened, Seal, seal_record};
use crate::nostr::relay::Answers;
use crate::onchain::acceptance::open_acceptance_event;
use crate::onchain::merchant_acceptance::{
    AcceptedInvoice, MerchantAcceptance, MerchantAcceptanceKeys, merchant_acceptance_of,
};
use crate::onchain::rest::RestReaderKeys;
use crate::order::Order;
use crate::protocol::MERCHANT_ACCEPTANCE_RECORD_TYPE;
use crate::runtime::OsRandom;
use crate::secret::Secret;
use crate::text::{from_hex32, to_hex};

const ORIGIN: &str = "https://pay.example";
const SATS: u64 = 49_000;
/// What came on-chain, and what the merchant accepted.
const CAME: u64 = 30_000;

fn address() -> String {
    deposit_address(1)
}

/// Publishes the channel, with `tolerance` (none: no `onchainTolerance`), dated `created_at`.
fn publish_channel(merchant: &TestMerchant, tolerance: Option<u64>, created_at: i64) {
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    let mut extra = vec![("relays", relays), ("checkout", Json::object([("origin", Json::from(ORIGIN))]))];
    if let Some(tolerance) = tolerance {
        extra.push(("onchainTolerance", Json::unsigned(tolerance)));
    }
    merchant.publish_channel(&merchant.channel_value(created_at, Json::object_of(extra)), created_at);
}

fn sale_author(merchant: &TestMerchant, reference: &str) -> String {
    sale_of(
        &merchant.integration_key,
        &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
        reference,
    )
    .author
}

/// What a record changes of the invoice it is of: its order, its address, its end.
#[derive(Default)]
struct Of {
    reference: Option<&'static str>,
    address: Option<String>,
    expires_at: Option<i64>,
}

/// Where the merchant's acceptance of `invoice` is (or of what `of` changes of it).
fn address_of(merchant: &TestMerchant, invoice: &Invoice, of: &Of) -> String {
    merchant_acceptance_address(
        &merchant.integration_key,
        &sale_author(merchant, of.reference.unwrap_or(&invoice.reference)),
        of.address.as_deref().unwrap_or(invoice.onchain_address.as_deref().unwrap()),
        of.expires_at.unwrap_or(invoice.expires_at),
    )
}

/// How a test's merchant's acceptance differs from the app's: its date (a minute ago by default),
/// its signer (the team by default), its value, the invoice it is of.
#[derive(Default)]
struct Made {
    created_at: Option<i64>,
    signer: Option<Secret>,
    value: Option<Json>,
    of: Of,
}

/// The merchant's acceptance of `invoice` at `received`, as the merchant's app makes it: sealed
/// with the channel's key, signed by the team, `{"version": 1, "received": <received>}`, unless
/// `made` says otherwise.
fn acceptance(merchant: &TestMerchant, invoice: &Invoice, received: u64, made: Made) -> Event {
    seal_record(
        Seal {
            record_type: MERCHANT_ACCEPTANCE_RECORD_TYPE,
            value: made.value.unwrap_or_else(|| {
                Json::object([("version", Json::unsigned(1)), ("received", Json::unsigned(received))])
            }),
            signer: made.signer.as_ref().unwrap_or(&merchant.team_secret),
            encryption_key: &channel_keys(&merchant.integration_key).encryption_key,
            address: &address_of(merchant, invoice, &made.of),
            created_at: made.created_at.unwrap_or(merchant.now() - 60),
            tags: Vec::new(),
        },
        &OsRandom,
    )
    .unwrap()
}

/// The relays at `indexes` of the key's take `event`, as a relay keeps it.
fn hold(merchant: &TestMerchant, event: &Event, indexes: &[usize]) {
    for &index in indexes {
        merchant.net.get(&merchant.key_relays[index]).take(event);
    }
}

const EVERY: &[usize] = &[0, 1, 2];

/// The relays at `indexes` never answer the read of the merchant's acceptance of `invoice`; the
/// others answer everything.
fn mute_read(merchant: &TestMerchant, invoice: &Invoice, indexes: &[usize]) {
    let address = address_of(merchant, invoice, &Of::default());
    for (index, url) in merchant.key_relays.iter().enumerate() {
        let behaviour = if indexes.contains(&index) {
            let address = address.clone();
            RelayBehaviour {
                mute_query: Some(Arc::new(move |filter: &Json| {
                    filter.get("#d").and_then(Json::as_array).is_some_and(|addresses| {
                        addresses.iter().any(|d| d.as_str() == Some(address.as_str()))
                    })
                })),
                ..RelayBehaviour::default()
            }
        } else {
            RelayBehaviour::default()
        };
        merchant.net.get(url).set_behaviour(behaviour);
    }
}

/// The acceptance records of `invoice` the relay holds, as a checkout link's page opens them.
fn acceptance_records(merchant: &TestMerchant, invoice: &Invoice, relay: &str) -> Vec<u64> {
    let keys = rest_keys(
        &merchant.integration_key,
        &invoice.reference,
        invoice.onchain_address.as_deref().unwrap(),
        invoice.expires_at,
    );
    let reader = RestReaderKeys::of(&keys);
    merchant
        .net
        .get(relay)
        .events()
        .iter()
        .filter_map(valid_event)
        .filter_map(|event| match open_acceptance_event(&event, &reader, invoice.sats)? {
            Opened::Valid { value, .. } => Some(value),
            Opened::Newer { .. } => None,
        })
        .collect()
}

/// What the check sent the relays of the team's, or at the merchant's acceptance's address.
fn sent_of_the_team(merchant: &TestMerchant, invoice: &Invoice) -> Vec<Event> {
    let address = address_of(merchant, invoice, &Of::default());
    merchant
        .key_relays
        .iter()
        .flat_map(|url| merchant.net.get(url).received())
        .filter(|event| {
            event.pubkey == merchant.team || event.tags.iter().any(|tag| tag.get(1) == Some(&address))
        })
        .collect()
}

/// The invoices breez.tips made of `sats`.
fn made_of(merchant: &TestMerchant, sats: u64) -> Vec<MadeInvoice> {
    merchant.invoices().into_iter().filter(|made| made.amount_msat == u128::from(sats) * 1000).collect()
}

fn json(status: &PaymentStatus) -> serde_json::Value {
    serde_json::to_value(status).unwrap()
}

/// The status of an order of 49 000 sats with 30 000 in time and the rest asked of 19 000.
fn underpaid(merchant: &TestMerchant, invoice: &Invoice) -> serde_json::Value {
    let rest = made_of(merchant, SATS - CAME).into_iter().next().expect("an invoice of the rest");
    serde_json::json!({
        "state": "open",
        "expiresAt": invoice.expires_at,
        "received": CAME.to_string(),
        "rest": {
            "sats": (SATS - CAME).to_string(),
            "bolt11": rest.pr,
            "paymentUri": format!("bitcoin:{}?amount=0.00019&lightning={}", address(), rest.pr)
        }
    })
}

fn unconfirmed(tx: &EsploraTx) -> serde_json::Value {
    serde_json::json!({ "state": "unconfirmed", "received": CAME.to_string(), "confirmations": 0, "txids": [tx.txid] })
}

struct Setup {
    merchant: TestMerchant,
    warnings: Warnings,
    client: Client,
    invoice: Invoice,
    /// What came on-chain: 30 000 sats.
    tx: EsploraTx,
}

/// A merchant with a channel of `tolerance`, an invoice of 49 000 sats to the address, a minute
/// later `came` sats paying it.
async fn setup_with(tolerance: Option<u64>, came: u64) -> Setup {
    let merchant = TestMerchant::new().start();
    merchant.publish_lot(&[address()], 90);
    publish_channel(&merchant, tolerance, 100);
    let warnings = Warnings::default();
    let client = merchant.client().logger(warnings.clone()).build().unwrap();
    let invoice = client
        .create_invoice(&Order::sats("R-1", SATS).duration_seconds(600).note("Order 1").checkout(true))
        .await
        .unwrap();
    assert_eq!(invoice.onchain_address.as_deref(), Some(address().as_str()));
    merchant.advance(60);
    let tx = payment(&txid("came"), &address(), came);
    merchant.chain.add(&address(), tx.clone());
    Setup { merchant, warnings, client, invoice, tx }
}

async fn setup() -> Setup {
    setup_with(None, CAME).await
}

async fn status(setup: &Setup) -> serde_json::Value {
    json(&setup.client.get_status(&setup.invoice).await.unwrap())
}

mod a_merchant_acceptance_a_majority_of_the_relays_hold {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pays_the_order_down_to_it_unconfirmed_then_paid_the_pages_told_nothing_published_of_it() {
        let setup = setup().await;
        let Setup { merchant, warnings, client, invoice, tx } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), &[0, 1]);
        assert_eq!(status(&setup).await, unconfirmed(tx));
        // No rest asked: the order is paid.
        assert!(made_of(merchant, SATS - CAME).is_empty());
        // The acceptance record (the server's, for the pages of the order's checkout links), on
        // every relay: what was received, nothing of the merchant's acceptance itself.
        for relay in &merchant.key_relays {
            assert_eq!(acceptance_records(merchant, invoice, relay), vec![CAME], "{relay}");
        }
        // The merchant's acceptance never published again, nor anything of the team's.
        assert!(sent_of_the_team(merchant, invoice).is_empty());
        let d = address_of(merchant, invoice, &Of::default());
        assert!(!merchant.net.get(&merchant.key_relays[2]).events().iter().any(|event| {
            event.get("pubkey").and_then(Json::as_str) == Some(merchant.team.as_str())
                && event.get("tags").is_some_and(|tags| crate::json::stringify(tags).contains(&d))
        }));

        merchant.chain.confirm(&address(), &tx.txid, merchant.chain.height() - 2);
        merchant.set_now(invoice.expires_at + 3600);
        let paid = serde_json::json!({ "state": "paid", "method": "onchain", "received": CAME.to_string(), "txids": [tx.txid] });
        assert_eq!(status(&setup).await, paid);
        let error = client.create_invoice(&Order::sats("R-1", SATS)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::OrderPaid);
        assert_eq!(serde_json::to_value(error.status().unwrap()).unwrap(), paid);
        assert_eq!(warnings.all(), Vec::<String>::new());
    }

    /// Held by `holders`, its read failing on `failing`: counted.
    async fn counted_whichever_majority_answers(holders: &[usize], failing: &[usize]) {
        let setup = setup().await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), holders);
        mute_read(merchant, invoice, failing);
        assert_eq!(status(&setup).await, unconfirmed(tx));
    }

    #[tokio::test(start_paused = true)]
    async fn counts_whichever_majority_answers_the_third_failing() {
        counted_whichever_majority_answers(&[0, 1], &[2]).await;
    }

    #[tokio::test(start_paused = true)]
    async fn counts_whichever_majority_answers_the_first_failing_the_2_others_holding_it() {
        counted_whichever_majority_answers(&[1, 2], &[0]).await;
    }

    #[tokio::test(start_paused = true)]
    async fn counts_whichever_majority_answers_every_relay_answering() {
        counted_whichever_majority_answers(&[0, 1], &[]).await;
    }

    #[tokio::test(start_paused = true)]
    async fn waits_for_a_relay_that_holds_it_and_answers_late() {
        let setup = setup().await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), &[0, 1]);
        merchant.net.get(&merchant.key_relays[0]).set_behaviour(RelayBehaviour::delayed(400));
        assert_eq!(status(&setup).await, unconfirmed(tx));
    }

    #[tokio::test(start_paused = true)]
    async fn counts_one_made_before_the_end_after_the_lease_end_never_expired() {
        let setup = setup().await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        let made = Made { created_at: Some(invoice.expires_at - 60), ..Made::default() };
        hold(merchant, &acceptance(merchant, invoice, CAME, made), &[1, 2]);
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(status(&setup).await, unconfirmed(tx));
    }

    #[tokio::test(start_paused = true)]
    async fn counts_one_of_less_than_what_came_what_came_pays() {
        let setup = setup().await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, 20_000, Made::default()), EVERY);
        assert_eq!(status(&setup).await, unconfirmed(tx));
        assert_eq!(acceptance_records(merchant, invoice, &merchant.key_relays[0]), vec![CAME]);
    }

    #[tokio::test(start_paused = true)]
    async fn asks_the_whole_rest_of_one_of_more_than_what_came() {
        let setup = setup().await;
        let Setup { merchant, invoice, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, 35_000, Made::default()), EVERY);
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        assert!(acceptance_records(merchant, invoice, &merchant.key_relays[0]).is_empty());
    }
}

mod a_merchant_acceptance_only_a_minority_of_the_relays_holds {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn never_counts_whichever_relays_answer_the_rest_asked_then_expired() {
        let setup = setup().await;
        let Setup { merchant, invoice, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), &[0]);
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        // The relay that holds it and one that does not answer: still a minority's.
        mute_read(merchant, invoice, &[2]);
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        mute_read(merchant, invoice, &[]);
        merchant.set_now(invoice.expires_at + 60);
        let status_now = setup.client.get_status(invoice).await.unwrap();
        assert!(matches!(status_now, PaymentStatus::Open { rest: None, .. }), "{status_now:?}");
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(
            status(&setup).await,
            serde_json::json!({ "state": "expired", "received": CAME.to_string() })
        );
        assert!(acceptance_records(merchant, invoice, &merchant.key_relays[0]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn is_what_remains_when_a_relay_that_holds_it_fails_and_the_others_that_do_are_a_minority() {
        // SPEC.md §27: that check does not count it; a later one, which that relay answers, does.
        let setup = setup().await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), &[0, 1]);
        mute_read(merchant, invoice, &[0]);
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        mute_read(merchant, invoice, &[]);
        assert_eq!(status(&setup).await, unconfirmed(tx));
    }

    #[tokio::test(start_paused = true)]
    async fn counts_a_relay_once_whatever_copies_of_it_it_sends() {
        let setup = setup().await;
        let Setup { merchant, invoice, .. } = &setup;
        let event = acceptance(merchant, invoice, CAME, Made::default());
        // The same event under another signature (BIP-340: any of them verifies): the same record.
        let sig =
            crate::secp::sign(&from_hex32(&event.id).unwrap(), merchant.team_secret.expose(), &bytes(77))
                .unwrap();
        let resigned = Event { sig: to_hex(&sig), ..event.clone() };
        assert_ne!(resigned.sig, event.sig);
        let relay = merchant.net.get(&merchant.key_relays[0]);
        relay.store_event(&event);
        relay.store_event(&event);
        relay.store_event(&resigned);
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        // The count itself, of what the relays sent (the pool already reads a relay's copies of one
        // id once): one relay, whatever copies it sent; then a second one, a majority.
        let keys = MerchantAcceptanceKeys::of(
            &merchant.integration_key,
            &merchant.team,
            &sale_author(merchant, &invoice.reference),
            &address(),
            invoice.expires_at,
        );
        let terms = AcceptedInvoice { sats: SATS, expires_at: invoice.expires_at };
        let mixed = Event { sig: resigned.sig.clone(), ..event.clone() };
        let mut answers: Answers<Event> = vec![
            ("a".to_owned(), vec![event.clone(), event.clone(), resigned.clone(), mixed]),
            ("b".to_owned(), Vec::new()),
            ("c".to_owned(), Vec::new()),
        ];
        assert_eq!(merchant_acceptance_of(&answers, &keys, terms, 3), MerchantAcceptance::default());
        answers[1].1.push(resigned);
        assert_eq!(
            merchant_acceptance_of(&answers, &keys, terms, 3),
            MerchantAcceptance { received: Some(CAME), newer: false }
        );
    }
}

mod a_record_that_is_not_this_invoice_merchant_acceptance {
    use super::*;

    /// Held by every relay, made as `made` says: not counted, nothing warned of.
    async fn not_counted(made: impl FnOnce(&Invoice) -> Made) {
        let setup = setup().await;
        let Setup { merchant, warnings, invoice, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, made(invoice)), EVERY);
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        assert_eq!(warnings.all(), Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_of_another_invoice_of_the_order_another_expires_at() {
        not_counted(|invoice| Made {
            of: Of { expires_at: Some(invoice.expires_at + 3600), ..Of::default() },
            ..Made::default()
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_of_another_order() {
        not_counted(|_| Made { of: Of { reference: Some("R-2"), ..Of::default() }, ..Made::default() }).await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_of_another_address() {
        not_counted(|_| Made {
            of: Of { address: Some(deposit_address(2)), ..Of::default() },
            ..Made::default()
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_of_another_team() {
        not_counted(|_| Made { signer: Some(Secret::new(bytes(9))), ..Made::default() }).await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_of_the_whole_amount() {
        not_counted(|_| Made {
            value: Some(Json::object([("version", Json::unsigned(1)), ("received", Json::unsigned(SATS))])),
            ..Made::default()
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_of_0_sats() {
        not_counted(|_| Made {
            value: Some(Json::object([("version", Json::unsigned(1)), ("received", Json::unsigned(0))])),
            ..Made::default()
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_without_a_version() {
        not_counted(|_| Made {
            value: Some(Json::object([("received", Json::unsigned(CAME))])),
            ..Made::default()
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn is_not_counted_with_a_damaged_signature() {
        let setup = setup().await;
        let Setup { merchant, invoice, .. } = &setup;
        let event = acceptance(merchant, invoice, CAME, Made::default());
        let last = if event.sig.ends_with('0') { "1" } else { "0" };
        let damaged = Event { sig: format!("{}{last}", &event.sig[..event.sig.len() - 1]), ..event };
        for url in &merchant.key_relays {
            merchant.net.get(url).store_event(&damaged);
        }
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
    }

    /// Dated `after` seconds after the invoice's end (after now: its `created_at` is never compared
    /// with now, only with the lease's end).
    async fn dated(after: i64, counted: bool) {
        let setup = setup().await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        let made = Made { created_at: Some(invoice.expires_at + after), ..Made::default() };
        hold(merchant, &acceptance(merchant, invoice, CAME, made), EVERY);
        let actual = status(&setup).await;
        assert_eq!(actual, if counted { unconfirmed(tx) } else { underpaid(merchant, invoice) });
    }

    #[tokio::test(start_paused = true)]
    async fn dated_at_the_lease_end_counted() {
        dated(120, true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn dated_a_second_after_the_lease_end_not_counted() {
        dated(121, false).await;
    }
}

mod a_merchant_acceptance_of_a_newer_format {
    use super::*;

    /// A record of version 2, dated `created_at`, on every relay with a valid one dated
    /// `valid_at` (relays send both); then the check, and how many times it warned of it.
    async fn newer_with(
        created_at: impl FnOnce(&Setup) -> i64,
        valid_at: impl FnOnce(&Setup) -> i64,
    ) -> Setup {
        let setup = setup().await;
        let Setup { merchant, invoice, .. } = &setup;
        let valid = Made { created_at: Some(valid_at(&setup)), ..Made::default() };
        let valid = acceptance(merchant, invoice, CAME, valid);
        let newer = Made {
            created_at: Some(created_at(&setup)),
            value: Some(Json::object([("version", Json::unsigned(2))])),
            ..Made::default()
        };
        let newer = acceptance(merchant, invoice, CAME, newer);
        for url in &merchant.key_relays {
            for event in [&valid, &newer] {
                merchant.net.get(url).store_event(event);
            }
        }
        setup
    }

    fn warned(setup: &Setup) -> usize {
        setup
            .warnings
            .all()
            .iter()
            .filter(|warning| warning.contains("a merchant's acceptance of this order has a newer format"))
            .count()
    }

    #[tokio::test(start_paused = true)]
    async fn newer_than_a_valid_one_leaves_the_order_without_one_and_is_warned_of() {
        let setup = newer_with(|setup| setup.merchant.now() - 30, |setup| setup.merchant.now() - 60).await;
        assert_eq!(status(&setup).await, underpaid(&setup.merchant, &setup.invoice));
        assert_eq!(warned(&setup), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn older_than_a_valid_one_leaves_it_counted_and_is_warned_of() {
        let setup = newer_with(|setup| setup.merchant.now() - 90, |setup| setup.merchant.now() - 60).await;
        assert_eq!(status(&setup).await, unconfirmed(&setup.tx));
        assert_eq!(warned(&setup), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dated_after_the_lease_end_is_set_aside_and_warned_of() {
        let setup =
            newer_with(|setup| setup.invoice.expires_at + 121, |setup| setup.merchant.now() - 60).await;
        assert_eq!(status(&setup).await, unconfirmed(&setup.tx));
        assert_eq!(warned(&setup), 1);
    }
}

mod a_merchant_acceptance_with_rest_invoices_the_tolerance_the_lightning_part {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn takes_what_rest_invoices_paid_from_it_once_unconfirmed_then_paid_mixed() {
        let setup = setup().await;
        let Setup { merchant, client, invoice, tx, .. } = &setup;
        let address = address();
        // 40 000 on-chain: a rest invoice of 9 000, paid; then the transaction replaced (RBF) by
        // one paying 21 000: 30 000 in all, 19 000 asked.
        merchant.chain.drop_tx(&address, &tx.txid);
        let first = payment(&txid("first"), &address, 40_000);
        merchant.chain.add(&address, first.clone());
        client.get_status(invoice).await.unwrap();
        let rest = made_of(merchant, 9000).into_iter().next().expect("an invoice of the rest");
        merchant.pay_invoice(&rest.payment_hash);
        merchant.advance(1);
        merchant.chain.drop_tx(&address, &first.txid);
        let bump = payment_with(
            &txid("bump"),
            &address,
            21_000,
            Paying { coins: Some(first.coins()), ..Paying::default() },
        );
        merchant.chain.add(&address, bump.clone());
        let status_now = client.get_status(invoice).await.unwrap();
        assert!(
            matches!(&status_now, PaymentStatus::Open { received: 30_000, rest: Some(rest), .. } if rest.sats == 19_000),
            "{status_now:?}"
        );
        // The merchant accepts what came: 21 000 due on-chain (30 000 less the 9 000 of the rest).
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), EVERY);
        assert_eq!(
            status(&setup).await,
            serde_json::json!({ "state": "unconfirmed", "received": "30000", "confirmations": 0, "txids": [bump.txid] })
        );
        assert_eq!(acceptance_records(merchant, invoice, &merchant.key_relays[0]), vec![30_000]);
        merchant.chain.confirm(&address, &bump.txid, merchant.chain.height() - 2);
        merchant.set_now(invoice.expires_at + 3600);
        assert_eq!(
            status(&setup).await,
            serde_json::json!({ "state": "paid", "method": "mixed", "received": "30000", "txids": [bump.txid], "preimages": [rest.preimage] })
        );
    }

    /// With a tolerance of 5 % (46 550 of 49 000), the merchant's acceptance of `accepted` and
    /// `came` on-chain: the lower of the two judges.
    async fn judges_with_the_lower(accepted: u64, came: u64) {
        let setup = setup_with(Some(500), came).await;
        let Setup { merchant, invoice, tx, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, accepted, Made::default()), EVERY);
        assert_eq!(
            status(&setup).await,
            serde_json::json!({ "state": "unconfirmed", "received": came.to_string(), "confirmations": 0, "txids": [tx.txid] })
        );
        assert_eq!(acceptance_records(merchant, invoice, &merchant.key_relays[0]), vec![came]);
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_tolerance_judges_with_the_lower_the_merchant_acceptance() {
        judges_with_the_lower(CAME, CAME).await;
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_tolerance_judges_with_the_lower_the_tolerance() {
        judges_with_the_lower(48_000, 46_550).await;
    }

    #[tokio::test(start_paused = true)]
    async fn changes_nothing_once_the_lightning_invoice_is_paid() {
        let setup = setup().await;
        let Setup { merchant, client, invoice, .. } = &setup;
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), EVERY);
        merchant.pay_invoice(invoice.payment_hash.as_deref().unwrap());
        let status_now = client.get_status(invoice).await.unwrap();
        assert_eq!(json(&status_now)["method"], "lightning", "{status_now:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn is_network_when_fewer_than_a_majority_answer_its_read() {
        let setup = setup().await;
        let Setup { merchant, client, invoice, .. } = &setup;
        // A first check published the witness and asked the rest: the next one publishes nothing
        // before it reads (the relays that fail its read fail every later read on every relay too).
        assert_eq!(status(&setup).await, underpaid(merchant, invoice));
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), EVERY);
        mute_read(merchant, invoice, &[1, 2]);
        assert_eq!(client.get_status(invoice).await.unwrap_err().code(), ErrorCode::Network);
        // Its Lightning invoice paid: paid all the same.
        merchant.pay_invoice(invoice.payment_hash.as_deref().unwrap());
        let status_now = client.get_status(invoice).await.unwrap();
        assert_eq!(json(&status_now)["method"], "lightning", "{status_now:?}");
    }

    async fn until(condition: impl Fn() -> bool) {
        for _ in 0..300 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(condition());
    }

    #[tokio::test(start_paused = true)]
    async fn is_seen_by_wait_for_payment_at_its_next_check_of_the_onchain_part_the_rest_given_till_then() {
        let setup = setup().await;
        let Setup { merchant, client, invoice, tx, .. } = &setup;
        let address = address();
        let socket = merchant.start_explorer_socket();
        let statuses: Arc<Mutex<Vec<PaymentStatus>>> = Arc::new(Mutex::new(Vec::new()));
        // The full checks so far: each asks the explorer for the address's transactions once.
        let asked = merchant.chain.asked().len();
        let full_checks =
            || merchant.chain.asked()[asked..].iter().filter(|url| url.ends_with("/txs")).count();
        let waiting = {
            let (client, invoice, recorded) = (client.clone(), invoice.clone(), statuses.clone());
            let options = WaitOptions::default()
                .interval_ms(250)
                .on_status(move |status| recorded.lock().unwrap().push(status.clone()));
            tokio::spawn(async move { client.wait_for_payment(&invoice, options).await })
        };
        let last = || statuses.lock().unwrap().last().map(json);
        // The first full check, and the one the socket's connection starts, ended.
        until(|| socket.messages().len() == 2 && full_checks() == 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(last(), Some(underpaid(merchant, invoice)));
        // The merchant accepts: no message of the explorer, no check of the on-chain part; the
        // checks of the Lightning invoices give the status with its rest still.
        hold(merchant, &acceptance(merchant, invoice, CAME, Made::default()), EVERY);
        let seen = statuses.lock().unwrap().len();
        until(|| statuses.lock().unwrap().len() > seen + 1).await;
        assert_eq!(full_checks(), 2);
        let since: Vec<serde_json::Value> = statuses.lock().unwrap()[seen..].iter().map(json).collect();
        assert!(since.iter().all(|status| *status == underpaid(merchant, invoice)), "{since:?}");
        // The next check of the on-chain part (a block here; every 60 s at least) counts it.
        let block =
            |height: u64| Json::object([("block", Json::object([("height", Json::unsigned(height))]))]);
        socket.push(&block(merchant.chain.height()));
        until(|| statuses.lock().unwrap().last().is_some_and(|status| status.state() == "unconfirmed")).await;
        assert_eq!(last(), Some(unconfirmed(tx)));
        merchant.chain.confirm(&address, &tx.txid, merchant.chain.height() - 2);
        socket.push(&block(merchant.chain.height()));
        assert_eq!(
            json(&waiting.await.unwrap().unwrap()),
            serde_json::json!({ "state": "paid", "method": "onchain", "received": CAME.to_string(), "txids": [tx.txid] })
        );
        assert_eq!(acceptance_records(merchant, invoice, &merchant.key_relays[0]), vec![CAME]);
    }
}
