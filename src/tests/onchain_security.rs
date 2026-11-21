//! Attacks on on-chain payments (S1 to S6; SPEC.md §13, §21, §31), end to end against local relays
//! and fakes of the explorers. Each test states what must hold.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use super::support::chain::{deposit_address, payment, txid};
use super::support::merchant::TestMerchant;
use super::support::relay::{LocalRelay, RelayBehaviour, pool};
use crate::client::Client;
use crate::declaration::{DeclaredPrice, registry_of};
use crate::derive::{Sale, channel_keys, lease_address, sale_of, sha256};
use crate::error::ErrorCode;
use crate::json::Json;
use crate::model::{Invoice, PaymentStatus};
use crate::nostr::event::{Event, EventTemplate, event_hash, sign_event};
use crate::nostr::record::records_that_open;
use crate::onchain::lease::{HoldRecord, LeaseTerms, is_leased, lease_event, read_leases};
use crate::order::Order;
use crate::runtime::{OsRandom, Random};
use crate::secret::Secret;
use crate::text::to_hex;

fn lot() -> Vec<String> {
    (1..=3).map(deposit_address).collect()
}

fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    let relays = Json::array(merchant.key_relays.iter().map(|relay| Json::from(relay.as_str())).collect());
    merchant.publish_channel(&merchant.channel_value(100, Json::object([("relays", relays)])), 100);
    merchant
}

fn client(merchant: &TestMerchant) -> Client {
    merchant.client().build().unwrap()
}

fn sale_of_ref(merchant: &TestMerchant, reference: &str) -> Sale {
    sale_of(
        &merchant.integration_key,
        &registry_of(&to_hex(merchant.registry_key.expose()), &merchant.reader),
        reference,
    )
}

/// Reproducible random bytes: SHA-256 of `<seed>/<counter>`, 32 bytes at a time.
struct Seeded {
    seed: u32,
    counter: AtomicU32,
}

fn seeded(seed: u32) -> Seeded {
    Seeded { seed, counter: AtomicU32::new(0) }
}

impl Random for Seeded {
    fn fill(&self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(32) {
            let counter = self.counter.fetch_add(1, Ordering::SeqCst);
            let block = sha256(format!("{}/{counter}", self.seed).as_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

/// Zeros: the auxiliary data of a throwaway signature.
struct Zeros;

impl Random for Zeros {
    fn fill(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

/// The lease of `address` by the sale of `reference`, from `created_at` for `seconds`.
fn lease_by(
    merchant: &TestMerchant,
    reference: &str,
    address: &str,
    created_at: i64,
    seconds: i64,
    random: &dyn Random,
) -> Event {
    let terms = LeaseTerms {
        address: address.to_owned(),
        sats: 1000,
        invoice: None,
        verify_url: None,
        created_at,
        expires_at: created_at + seconds,
        price: DeclaredPrice { minor: 1000, digits: 0, currency: "SAT".to_owned() },
        note: reference.to_owned(),
        tolerance: 0,
        confirmed: None,
    };
    lease_event(&sale_of_ref(merchant, reference), &terms, created_at, random).unwrap()
}

/// A record anybody writes at a registry address (it is public): a throwaway key signs it.
fn junk(d: &str, created_at: i64, seed: u32, content: &str) -> Event {
    let secret = Secret::new(sha256(format!("throwaway {seed}").as_bytes()));
    sign_event(
        EventTemplate {
            kind: 30078.0,
            created_at,
            tags: vec![vec!["d".to_owned(), d.to_owned()]],
            content: content.to_owned(),
        },
        &secret,
        &Zeros,
    )
}

fn relays(merchant: &TestMerchant) -> Vec<LocalRelay> {
    merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect()
}

/// Every relay of the key takes `event`.
fn everywhere(merchant: &TestMerchant, event: &Event) {
    for relay in relays(merchant) {
        relay.take(event);
    }
}

fn capped(cap: usize) -> RelayBehaviour {
    RelayBehaviour { cap: Some(cap), ..RelayBehaviour::default() }
}

mod s5_a_paged_read_of_the_leases_misses_a_lease_every_relay_holds {
    use super::*;

    fn setup() -> (TestMerchant, String) {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let d = lease_address(&merchant.registry_key, &lot[0]);
        (merchant, d)
    }

    #[tokio::test(start_paused = true)]
    async fn control_another_order_lease_keeps_the_address() {
        let (merchant, _) = setup();
        everywhere(&merchant, &lease_by(&merchant, "HOLDER", &lot()[0], merchant.now(), 900, &OsRandom));
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S5-0", 49_000)).await.unwrap().onchain_address,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ties_a_page_of_records_of_the_lease_very_second_with_lower_ids() {
        let (merchant, d) = setup();
        for relay in relays(&merchant) {
            relay.set_behaviour(capped(500));
        }
        // At equal created_at, the lowest id first (NIP-01; strfry: the last stored first).
        let mut seed = 0;
        let lease = loop {
            let lease = lease_by(&merchant, "HOLDER", &lot()[0], merchant.now(), 900, &seeded(seed));
            seed += 1;
            if lease.id.as_str() >= "c" {
                break lease;
            }
        };
        everywhere(&merchant, &lease);
        let (mut i, mut made) = (0, 0);
        while made < 500 {
            let record = junk(&d, lease.created_at, i, "x");
            if record.id < lease.id {
                everywhere(&merchant, &record);
                made += 1;
            }
            i += 1;
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S5-1", 49_000)).await.unwrap().onchain_address,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unusable_dates_a_page_of_records_dated_beyond_2_53() {
        let (merchant, d) = setup();
        for relay in relays(&merchant) {
            relay.set_behaviour(capped(500));
        }
        everywhere(&merchant, &lease_by(&merchant, "HOLDER", &lot()[0], merchant.now(), 900, &OsRandom));
        for i in 0..500u32 {
            // As a relay that keeps any date stores it (strfry refuses one more than 900 s ahead).
            let record = junk(&d, 0, i, "x");
            let mut value = record.to_json();
            // A created_at beyond 2^53, which no event of the crate holds: written as a relay sends it.
            if let Json::Object(object) = &mut value {
                let members: Vec<(crate::json::JsonString, Json)> = object
                    .iter()
                    .map(|(name, member)| {
                        let member = if name.as_str() == Some("created_at") {
                            Json::Number(2f64.powi(53) + 2.0 * f64::from(i + 1))
                        } else {
                            member.clone()
                        };
                        (name.clone(), member)
                    })
                    .collect();
                *object = crate::json::JsonObject::new(members);
            }
            for relay in relays(&merchant) {
                relay.store(value.clone());
            }
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S5-2", 49_000)).await.unwrap().onchain_address,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn volume_more_than_20_pages_of_records_newer_than_the_lease() {
        let (merchant, d) = setup();
        for relay in relays(&merchant) {
            relay.set_behaviour(capped(100));
        }
        everywhere(
            &merchant,
            &lease_by(&merchant, "HOLDER", &lot()[0], merchant.now() - 600, 900, &OsRandom),
        );
        for i in 0..2001u32 {
            everywhere(&merchant, &junk(&d, merchant.now() - 599 + i64::from(i % 500), i, "x"));
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S5-3", 49_000)).await.unwrap().onchain_address,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn order_a_relay_that_answers_a_filter_without_a_limit_oldest_first() {
        let (merchant, d) = setup();
        for relay in relays(&merchant) {
            relay.set_behaviour(RelayBehaviour {
                oldest_first_without_limit: true,
                ..RelayBehaviour::default()
            });
        }
        everywhere(&merchant, &lease_by(&merchant, "HOLDER", &lot()[0], merchant.now(), 900, &OsRandom));
        for i in 0..1000u32 {
            everywhere(&merchant, &junk(&d, merchant.now() - 7000 + i64::from(i), i, "x"));
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S5-4", 49_000)).await.unwrap().onchain_address,
            None
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_read_of_leases_among_many_large_records_ends_incomplete_never_failed() {
    let merchant = merchant();
    let lot = lot();
    let d = lease_address(&merchant.registry_key, &lot[0]);
    let filler = "z".repeat(100);
    // More than 20 pages of anybody's records (large ones: hardening.rs): nothing piles up, the
    // read gives up at its 20th page.
    for i in 0..2050u32 {
        everywhere(&merchant, &junk(&d, merchant.now() - i64::from(i), 30_000 + i, &filler));
    }
    let pool = pool(&merchant.net, 2000);
    let read = read_leases(
        &pool,
        &merchant.registry_key,
        &lot[..1],
        &merchant.key_relays,
        merchant.now(),
        &OsRandom,
        false,
    )
    .await;
    assert!(read.answered, "answered: a read that cannot be complete is no failure");
    assert!(!read.complete);
    // Nothing of them kept: none opens as a record of the registry.
    assert!(read.of(&lot[0]).is_empty());
}

mod s4_records_of_a_newer_format_signed_by_any_key_hold_every_address {
    use super::super::support::merchant::Warnings;
    use super::*;
    use crate::derive::{outer_key, public_key_of};
    use crate::nostr::record::{Seal, seal_record};
    use crate::protocol::LEASE_RECORD_TYPE;

    #[tokio::test(start_paused = true)]
    async fn an_empty_content_at_each_registry_address_takes_onchain_away_never() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot, 91);
        for (i, address) in lot.iter().enumerate() {
            everywhere(
                &merchant,
                &junk(&lease_address(&merchant.registry_key, address), merchant.now(), 10_000 + i as u32, ""),
            );
        }
        assert!(
            client(&merchant)
                .create_invoice(&Order::sats("S4-1", 49_000))
                .await
                .unwrap()
                .onchain_address
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_lease_of_a_newer_format_sealed_with_the_registry_key_holds_its_address_and_is_warned_of() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let secret = Secret::new(sha256(b"a sale of a newer version"));
        let newer = seal_record(
            Seal {
                record_type: LEASE_RECORD_TYPE,
                value: Json::object([("version", Json::unsigned(2))]),
                signer: &secret,
                encryption_key: &outer_key(&merchant.registry_key, &d, &public_key_of(&secret)),
                address: &d,
                created_at: merchant.now() - 60,
                tags: Vec::new(),
            },
            &OsRandom,
        )
        .unwrap();
        everywhere(&merchant, &newer);
        let warnings = Warnings::default();
        let client = merchant.client().logger(warnings.clone()).build().unwrap();
        let invoice = client.create_invoice(&Order::sats("S4-3", 49_000)).await.unwrap();
        assert_eq!(invoice.onchain_address, None);
        assert!(
            warnings
                .all()
                .iter()
                .any(|warning| warning.contains("a lease of the integration's addresses has a newer format")),
            "{:?}",
            warnings.all()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn each_such_record_costs_no_signature_check() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let d = lease_address(&merchant.registry_key, &lot[0]);
        for i in 0..1000u32 {
            everywhere(&merchant, &junk(&d, merchant.now() - i64::from(i), 20_000 + i, "#"));
        }
        let before = crate::secp::verifications::total();
        client(&merchant).create_invoice(&Order::sats("S4-2", 49_000)).await.unwrap();
        // The channel, the lot, the order's own records: a handful. Never one per junk record.
        assert!(
            crate::secp::verifications::total() - before < 50,
            "{}",
            crate::secp::verifications::total() - before
        );
    }
}

/// What an order was handed out: an address, or none.
fn handed_out(result: &Result<Invoice, crate::Error>) -> Option<String> {
    match result {
        Ok(invoice) => invoice.onchain_address.clone(),
        Err(error) if error.code() == ErrorCode::InvoicePending => {
            error.invoice().and_then(|invoice| invoice.onchain_address.clone())
        }
        Err(_) => None,
    }
}

fn refusing(test: impl Fn(&Event) -> bool + Send + Sync + 'static) -> RelayBehaviour {
    RelayBehaviour {
        refuse_event: Some(Arc::new(move |event: &Event| test(event).then(|| "error: down".to_owned()))),
        ..RelayBehaviour::default()
    }
}

mod s1_an_earlier_invoice_whose_lease_was_never_confirmed_is_handed_out_again {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn an_order_paid_onchain_only_whose_lease_reached_one_relay() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let relays = relays(&merchant);
        let author = sale_of_ref(&merchant, "S1-R").author;
        let start = merchant.now();
        // r1 takes the order's lease and nothing after it (its withdrawal is lost); r2 and r3 refuse.
        let mine = author.clone();
        relays[0].set_behaviour(refusing(move |event| event.pubkey == mine && event.created_at > start));
        for relay in &relays[1..] {
            let mine = author.clone();
            relay.set_behaviour(refusing(move |event| event.pubkey == mine));
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S1-R", 49_000)).await.unwrap_err().code(),
            ErrorCode::Network
        );

        // Another order while r1 is slow: r2 and r3, which never got that lease, answer first.
        relays[0].set_behaviour(RelayBehaviour::delayed(500));
        relays[1].set_behaviour(RelayBehaviour::default());
        relays[2].set_behaviour(RelayBehaviour::default());
        let x = client(&merchant).create_invoice(&Order::sats("S1-X", 49_000)).await;
        let x_holds =
            x.as_ref().ok().and_then(|invoice| invoice.onchain_address.as_deref()) == Some(lot[0].as_str());

        // The first order again while r2 is slow: r1, which holds its lease, answers.
        relays[0].set_behaviour(RelayBehaviour::default());
        relays[1].set_behaviour(RelayBehaviour::delayed(500));
        let again = client(&merchant).create_invoice(&Order::sats("S1-R", 49_000)).await;
        // Never both: the address handed out to this order while the other holds it.
        assert!(!(x_holds && handed_out(&again).as_deref() == Some(lot[0].as_str())));
    }

    #[tokio::test(start_paused = true)]
    async fn an_invoice_with_lightning_whose_declaration_failed_its_withdrawal_on_one_relay() {
        let merchant = merchant();
        let lot = lot();
        merchant.publish_lot(&lot[..1], 91);
        let relays = relays(&merchant);
        let author = sale_of_ref(&merchant, "S1-L").author;
        let d = lease_address(&merchant.registry_key, &lot[0]);
        let start = merchant.now();
        let is_lease_record = move |event: &Event| {
            event
                .tags
                .iter()
                .any(|tag| tag.first().map(String::as_str) == Some("d") && tag.get(1) == Some(&d))
        };
        let is_lease_record = Arc::new(is_lease_record);
        // r1: the lease and the declaration, not the withdrawal. r2: the lease and the withdrawal,
        // not the declaration. r3: the lease only.
        {
            let (mine, lease) = (author.clone(), is_lease_record.clone());
            relays[0].set_behaviour(refusing(move |event| {
                event.pubkey == mine && lease(event) && event.created_at > start
            }));
        }
        {
            let (mine, lease) = (author.clone(), is_lease_record.clone());
            relays[1].set_behaviour(refusing(move |event| event.pubkey == mine && !lease(event)));
        }
        {
            let (mine, lease) = (author.clone(), is_lease_record.clone());
            relays[2].set_behaviour(refusing(move |event| {
                event.pubkey == mine && (!lease(event) || event.created_at > start)
            }));
        }
        assert_eq!(
            client(&merchant).create_invoice(&Order::sats("S1-L", 49_000)).await.unwrap_err().code(),
            ErrorCode::Network
        );

        // Another order while r1 is slow: r2's withdrawal frees the address.
        relays[0].set_behaviour(RelayBehaviour::delayed(500));
        relays[1].set_behaviour(RelayBehaviour::default());
        relays[2].set_behaviour(RelayBehaviour::default());
        let x = client(&merchant).create_invoice(&Order::sats("S1-X", 49_000)).await.unwrap();
        let x_holds = x.onchain_address.as_deref() == Some(lot[0].as_str());

        // The first order again while r2 is slow.
        relays[0].set_behaviour(RelayBehaviour::default());
        relays[1].set_behaviour(RelayBehaviour::delayed(500));
        let again = client(&merchant).create_invoice(&Order::sats("S1-L", 49_000)).await;
        assert!(!(x_holds && handed_out(&again).as_deref() == Some(lot[0].as_str())));
    }
}

/// An RFC 3339 date of Unix seconds, as `toISOString` writes it.
pub(crate) fn iso(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

mod s2_a_transaction_evicted_then_broadcast_again_during_a_later_lease_pays_two_orders {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_first_order_witness_names_it() {
        let merchant = merchant();
        merchant.publish_lot(&lot()[..1], 91);
        let client = client(&merchant);
        let p = client.create_invoice(&Order::sats("S2-P", 49_000).duration_seconds(600)).await.unwrap();
        let address = p.onchain_address.clone().unwrap();
        // Paid with a very low fee, seen while P's lease runs: P's witness.
        let t = payment(&txid("S2 low fee"), &address, 49_000);
        merchant.chain.add(&address, t.clone());
        assert_eq!(client.get_status(&p).await.unwrap().state(), "unconfirmed");
        // Evicted from the mempools: the explorer lists nothing for the address.
        merchant.chain.drop_tx(&address, &t.txid);
        merchant.set_now(p.expires_at + 120 + 301);
        assert_eq!(client.get_status(&p).await.unwrap(), PaymentStatus::Expired { received: 0 });

        let n = client.create_invoice(&Order::sats("S2-N", 49_000).duration_seconds(600)).await.unwrap();
        // The payer's wallet broadcasts T again during N's lease; it is mined.
        merchant.chain.add(&address, t.clone());
        if n.onchain_address.as_deref() == Some(address.as_str()) {
            client.get_status(&n).await.unwrap();
        }
        merchant.chain.confirm(&address, &t.txid, merchant.chain.height() - 5);
        // The payer asks for P again: the shop checks P's earlier invoice.
        let p_again = client.create_invoice(&Order::sats("S2-P", 49_000)).await;
        let n_paid = n.onchain_address.as_deref() == Some(address.as_str())
            && client.get_status(&n).await.unwrap().is_paid();
        let p_paid = p_again.as_ref().is_err_and(|error| error.code() == ErrorCode::OrderPaid);
        // One transaction, one order.
        assert!(!(n_paid && p_paid));
    }

    #[tokio::test(start_paused = true)]
    async fn no_check_saw_it_while_the_first_lease_ran_blockcypher_time() {
        let merchant = merchant();
        merchant.publish_lot(&lot()[..1], 91);
        let client = client(&merchant);
        let p = client.create_invoice(&Order::sats("S2-Q", 49_000).duration_seconds(600)).await.unwrap();
        let address = p.onchain_address.clone().unwrap();
        let t = payment(&txid("S2 unseen"), &address, 49_000);
        // BlockCypher received it while P's lease ran; no check of P saw it; it is evicted.
        merchant.chain.set_received(&t.txid, &iso(p.created_at + 10));
        merchant.set_now(p.expires_at + 120 + 301);
        assert_eq!(client.get_status(&p).await.unwrap(), PaymentStatus::Expired { received: 0 });

        let n = client.create_invoice(&Order::sats("S2-M", 49_000).duration_seconds(600)).await.unwrap();
        assert_eq!(n.onchain_address.as_deref(), Some(address.as_str()));
        merchant.chain.add(&address, t.clone());
        let status = client.get_status(&n).await.unwrap();
        assert!(matches!(status, PaymentStatus::Unconfirmed { received: 49_000, .. }), "{status:?}");
        merchant.chain.confirm(&address, &t.txid, merchant.chain.height() - 5);
        let p_again = client.create_invoice(&Order::sats("S2-Q", 49_000)).await;
        let n_paid = client.get_status(&n).await.unwrap().is_paid();
        let p_paid = p_again.as_ref().is_err_and(|error| error.code() == ErrorCode::OrderPaid);
        assert!(!(n_paid && p_paid));
    }
}

mod s3_the_witness_of_an_earlier_invoice_of_the_order_counts_for_a_later_one {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn an_underpayment_of_an_expired_invoice_counts_again_for_the_next_one() {
        let merchant = merchant();
        merchant.publish_lot(&lot()[..1], 91);
        // On-chain only: no rest invoice is asked.
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let client = client(&merchant);
        let first = client.create_invoice(&Order::sats("S3-R", 49_000).duration_seconds(600)).await.unwrap();
        let address = first.onchain_address.clone().unwrap();
        let t = payment(&txid("S3 part"), &address, 30_000);
        merchant.chain.add(&address, t.clone());
        let status = client.get_status(&first).await.unwrap();
        assert!(matches!(status, PaymentStatus::Open { received: 30_000, .. }), "{status:?}");
        merchant.set_now(first.expires_at + 121);
        // Underpaid for good: the merchant settles the 30 000 sats with the customer.
        assert_eq!(client.get_status(&first).await.unwrap(), PaymentStatus::Expired { received: 30_000 });
        // T leaves the mempool (evicted).
        merchant.chain.drop_tx(&address, &t.txid);
        merchant.set_now(first.expires_at + 120 + 301);
        let second = match client.create_invoice(&Order::sats("S3-R", 49_000).duration_seconds(600)).await {
            // No address for it (the fix): nothing can count twice.
            Err(error) => {
                assert_eq!(error.code(), ErrorCode::OnchainUnavailable);
                return;
            }
            Ok(second) => second,
        };
        assert_eq!(second.onchain_address.as_deref(), Some(address.as_str()));
        // T broadcast again after the second invoice's end: late, whatever its witness.
        merchant.set_now(second.expires_at + 3600);
        merchant.chain.add(&address, t);
        assert_eq!(client.get_status(&second).await.unwrap(), PaymentStatus::Expired { received: 0 });
    }

    #[tokio::test(start_paused = true)]
    async fn a_witness_of_the_earlier_invoice_made_after_the_later_one_leased_the_address() {
        let merchant = merchant();
        merchant.publish_lot(&lot()[..1], 91);
        merchant.set_pay_field("maxSendable", Some(Json::unsigned(1_000_000)));
        let client = client(&merchant);
        let first = client.create_invoice(&Order::sats("S3-Q", 49_000).duration_seconds(600)).await.unwrap();
        let address = first.onchain_address.clone().unwrap();
        let t = payment(&txid("S3 unseen part"), &address, 30_000);
        // Received by BlockCypher while the first lease ran; no check saw it; then evicted.
        merchant.chain.set_received(&t.txid, &iso(first.created_at + 10));
        // Beyond the reads of leases (7200 s), where the order's own records keep it off the address.
        merchant.set_now(first.created_at + 7300);
        assert_eq!(client.get_status(&first).await.unwrap(), PaymentStatus::Expired { received: 0 });
        let second = client.create_invoice(&Order::sats("S3-Q", 49_000).duration_seconds(600)).await.unwrap();
        assert_eq!(second.onchain_address.as_deref(), Some(address.as_str()));
        // T comes back after the second invoice's end; the first invoice is checked first.
        merchant.set_now(second.expires_at + 3600);
        merchant.chain.add(&address, t);
        let first_status = client.get_status(&first).await.unwrap();
        let second_status = client.get_status(&second).await.unwrap();
        let received = |status: &PaymentStatus| match status {
            PaymentStatus::Open { received, .. }
            | PaymentStatus::Unconfirmed { received, .. }
            | PaymentStatus::Expired { received } => Some(*received),
            PaymentStatus::Paid(_) => None,
        };
        let counted =
            [first_status, second_status].iter().filter(|status| received(status) == Some(30_000)).count();
        // T was received once: it counts for one invoice at most.
        assert!(counted <= 1);
    }
}

#[tokio::test(start_paused = true)]
async fn s6_a_hostile_relay_hides_a_lease_from_the_majority_that_reads() {
    // The confirmation reads on every relay (SPEC.md §13): r2, late but in time, shows the lease.
    let merchant = merchant();
    merchant.publish_lot(&lot()[..1], 91);
    let relays = relays(&merchant);
    let (h, r2) = (&relays[1], &relays[2]);
    let lease = lease_by(&merchant, "S6-A", &lot()[0], merchant.now(), 900, &OsRandom);
    // r1 refused it.
    h.take(&lease);
    r2.take(&lease);
    let hidden = lease.id.clone();
    h.set_behaviour(RelayBehaviour {
        hide: Some(Arc::new(move |value: &Json| {
            value.get("id").and_then(Json::as_str) == Some(hidden.as_str())
        })),
        ..RelayBehaviour::default()
    });
    // r2 answers its reads 1.5 s late, within the timeout (4 s): H and r1 answer first.
    r2.set_behaviour(RelayBehaviour::delayed(1500));
    let invoice = merchant
        .client()
        .relay_timeout_ms(4000)
        .build()
        .unwrap()
        .create_invoice(&Order::sats("S6-B", 49_000))
        .await
        .unwrap();
    assert_eq!(invoice.onchain_address, None);
}

mod copies_of_a_record_under_ids_of_their_own_a_read_keeps_none_of_them_whole {
    use super::*;

    /// `event` with another tag and date, its id recomputed, its signature left as it is.
    fn copy_of(event: &Event, index: i64, filler: &str) -> Event {
        let mut tags = event.tags.clone();
        tags.push(vec!["x".to_owned(), filler.to_owned()]);
        let created_at = event.created_at - 1 - index;
        let id = to_hex(&event_hash(&event.pubkey, created_at, event.kind, &tags, &event.content));
        Event {
            id,
            pubkey: event.pubkey.clone(),
            created_at,
            kind: event.kind,
            tags,
            content: event.content.clone(),
            sig: event.sig.clone(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_lease_of_each_copy_only_its_id_author_date_and_signature_are_kept() {
        let merchant = merchant();
        let lot = lot();
        let lease = lease_by(&merchant, "OTHER", &lot[0], merchant.now() - 60, 900, &OsRandom);
        everywhere(&merchant, &lease);
        let filler = "y".repeat(50_000);
        // Relays that keep them all (anybody can write at a lease's address): read on any majority.
        let copies: Vec<Event> = (0..200).map(|i| copy_of(&lease, i, &filler)).collect();
        for relay in relays(&merchant) {
            for copy in &copies {
                relay.store_event(copy);
            }
        }
        let pool = pool(&merchant.net, 2000);
        let read = read_leases(
            &pool,
            &merchant.registry_key,
            &lot[..1],
            &merchant.key_relays,
            merchant.now(),
            &seeded(1),
            false,
        )
        .await;
        let records = read.of(&lot[0]);
        // Every copy opens as the lease does (its id is its hash, its content decrypts).
        assert_eq!(records.len(), 201);
        // Of each, its id, author, date and signature: never its tags nor its content.
        let kept: usize = records
            .iter()
            .map(|record| record.event.id.len() + record.event.pubkey.len() + record.event.sig.len() + 8)
            .sum();
        assert!(kept < 201 * 400, "{kept}");
        // Only the lease is signed: the walk still finds the address leased.
        let signed: Vec<&str> =
            records.iter().filter(|record| record.signed()).map(|record| record.event.id.as_str()).collect();
        assert_eq!(signed, vec![lease.id.as_str()]);
        assert!(is_leased(&records, merchant.now()));
    }

    #[test]
    fn a_signed_record_a_copy_is_not_kept_its_signature_does_not_check_out() {
        let merchant = TestMerchant::new();
        let keys = channel_keys(&merchant.integration_key);
        let team = merchant.team.clone();
        let key = keys.encryption_key.clone();
        let keep = records_that_open(Arc::new(move |_, author| (author == team).then(|| key.clone())));
        let channel = merchant.channel_event(&merchant.channel_value(100, Json::object([])), 100, None);
        assert_eq!(keep(&channel.to_json()), Some(channel.clone()));
        assert_eq!(keep(&copy_of(&channel, 0, &"z".repeat(1000)).to_json()), None);
        let mut unsigned = channel.clone();
        unsigned.sig = "00".repeat(64);
        assert_eq!(keep(&unsigned.to_json()), None);
        // Another key's: not opened, not kept.
        let mut other = channel;
        other.pubkey = "ab".repeat(32);
        assert_eq!(keep(&other.to_json()), None);
    }
}
