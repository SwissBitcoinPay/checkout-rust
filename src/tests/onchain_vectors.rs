//! The crate against the on-chain conformance vectors (SPEC.md §31) of the pinned copy of the
//! specification: the app's lot, deposit addresses, the methods of an order, leases, witnesses,
//! replacements, the statuses of an invoice with an address (with the merchant's acceptances, end to
//! end too), complete reads, tolerances, the merchant's acceptances and an order's earlier invoices.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::conformance::{every_case, expect_same};
use super::support::http::{Answer, FakeHttp};
use super::support::merchant::{Quiet, Warnings};
use super::support::relay::{LocalRelay, RelayBehaviour, RelayNet, pool};
use super::support::vectors::{Field, error_json, spec, text};
use crate::declaration::{DeclaredPrice, OpenedDeclaration, registry_of};
use crate::derive::{
    RestKeys, channel_keys, lot_address, merchant_acceptance_address, outer_key, public_key_of, rest_keys,
    sale_keys, sale_of, seen_keys,
};
use crate::error::{Error, ErrorCode};
use crate::json::{self, Json};
use crate::key::parse_integration_key;
use crate::lightning::bolt11::{self, Bolt11};
use crate::lnurl::LightningPart;
use crate::model::{Payment, PaymentStatus};
use crate::nostr::event::{Event, signature_checks, valid_event};
use crate::nostr::nip44::{conversation_key, decrypt};
use crate::nostr::record::{Expected, Opened, Seal, open_record, seal_record};
use crate::nostr::relay::{
    Answers, CompleteRead, Filter, Keep, PageEnd, PoolConfig, ReadOf, ReadOutcome, RelayPool, RelayState,
    after_complete_page, complete_read_of, entry_in_answer, majority,
};
use crate::onchain::acceptance::{
    AcceptanceOf, acceptance_record_event, open_acceptance_event, publish_acceptance,
};
use crate::onchain::address::{btc_amount, is_deposit_address, payment_uri};
use crate::onchain::lease::{
    HoldRecord, LeaseEvent, LeaseHold, LeaseOutside, LeaseTerms, OpenedLease, SaleLeaseRecord, is_confirmed,
    is_leased, lease_event, open_lease_inside, open_lease_outside, open_lease_record,
};
use crate::onchain::lot::parse_lot;
use crate::onchain::merchant_acceptance::{
    AcceptedInvoice, MerchantAcceptance, MerchantAcceptanceKeys, OpenedMerchantAcceptance,
    merchant_acceptance_keep, merchant_acceptance_of, open_merchant_acceptance, read_merchant_acceptance,
};
use crate::onchain::methods::{LeaseOutcome, methods_with, payment_methods};
use crate::onchain::payment::{
    InvoiceTerms, OnchainCheck, RestPart, Settled, Witnesses, check_onchain_part, combine_parts, rest_summary,
};
use crate::onchain::replacements::{PaymentTx, payment_parts};
use crate::onchain::rest::{RestInvoice, RestReaderKeys};
use crate::onchain::tolerance::{due_onchain, least_accepted, tolerance_of};
use crate::onchain::witness::{
    OpenedWitness, OrderWitnesses, Witness, address_tag, addresses_named, open_witness, order_tag,
    order_witnesses_of, seen_of, witness_address, witness_event,
};
use crate::order::{Order, check_order};
use crate::protocol::{
    COMPLETE_READ_LIMIT, MAX_PAGES, MEMPOOL_URL, MERCHANT_ACCEPTANCE_RECORD_TYPE,
    MERCHANT_ACCEPTANCE_VERSION, ORDER_TAG, RECORD_KIND, WITNESS_RECORD_TYPE, WITNESS_VERSION,
};
use crate::runtime::OsRandom;
use crate::sales::{
    Pending, SaleDeclaration, invoices_of, may_still_be_paid, newest_records, pending_outcome,
};
use crate::text::to_hex;
use crate::transport::BoxFuture;

fn app() -> Json {
    spec("vectors/app/app.json")
}

#[test]
fn onchain_lot_json_opens_the_lot_the_merchant_app_made_with_the_integration_key_alone() {
    let vector = spec("vectors/app/onchain-lot.json");
    let access = parse_integration_key(vector.text("secretKey")).unwrap();
    let keys = channel_keys(&access.key);
    assert_eq!(access.team, vector.text("team"));
    assert_eq!(lot_address(&access.key), vector.text("lotAddress"));
    assert_eq!(to_hex(keys.encryption_key.expose()), vector.text("channelEncryptionKey"));
    let lot = vector.field("lot");
    let lot_address = lot_address(&access.key);
    let expected = Expected {
        record_type: lot.field("value").text("t"),
        encryption_key: &keys.encryption_key,
        address: &lot_address,
        author: vector.text("team"),
    };
    match open_record(lot.field("event"), &expected, |value, event| parse_lot(value, event.created_at)) {
        Some(Opened::Valid { value, .. }) => {
            assert_eq!(value, lot.field("value").field("v").texts("addresses"))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn onchain_addresses_json() {
    let vectors = spec("vectors/onchain-addresses.json");
    every_case("onchain-addresses.json addresses", vectors.list("addresses"), |case| {
        let valid = case.field("valid").as_bool().unwrap();
        let address = case.field("address").as_str().unwrap_or("");
        if is_deposit_address(address) == valid { Ok(()) } else { Err(format!("expected {valid}")) }
    });
    let registry = vectors.field("registry");
    let key = registry.secret("registryKey");
    every_case("onchain-addresses.json registry", registry.list("cases"), |case| {
        expect_same(
            &text(&crate::derive::lease_address(&key, case.text("address"))),
            case.field("registryAddress"),
        )
    });
    every_case("onchain-addresses.json uris", vectors.list("uris"), |case| {
        let uri = payment_uri(case.opt_text("address"), case.digits("sats"), case.opt_text("bolt11"));
        expect_same(&text(&uri), case.field("uri"))
    });
    every_case("onchain-addresses.json amounts", vectors.list("amounts"), |case| {
        expect_same(&text(&btc_amount(case.digits("sats"))), case.field("btc"))
    });
}

#[test]
fn payment_methods_json() {
    let vectors = spec("vectors/payment-methods.json");
    every_case("payment-methods.json", vectors.list("cases"), |case| {
        let sendable = case.field("sendable");
        let outcome = match case.text("address") {
            "leased" => LeaseOutcome::Leased,
            "none" => LeaseOutcome::None,
            _ => LeaseOutcome::ExplorerFailed(Error::network("The explorer did not answer")),
        };
        let result = check_order(&Order::sats("A-1", case.digits("sats")), &[]).and_then(|order| {
            let methods = payment_methods(
                order.sats.unwrap(),
                (sendable.digits("min"), sendable.digits("max")),
                "sats",
            )?;
            methods_with(methods, outcome)
        });
        let actual = match result {
            Ok(methods) => {
                let mut names = Vec::new();
                if methods.lightning {
                    names.push(text("lightning"));
                }
                if methods.onchain {
                    names.push(text("onchain"));
                }
                Json::object([("methods", Json::array(names))])
            }
            Err(error) => error_json(&error),
        };
        expect_same(&actual, case.field("expected"))
    });
}

mod onchain_leases_json {
    use super::*;

    fn vectors() -> Json {
        spec("vectors/onchain-leases.json")
    }

    /// The sale of vectors/app/app.json's declaration, in this registry.
    fn sale(vectors: &Json) -> crate::derive::Sale {
        let app = app();
        sale_of(
            &app.field("parsed").secret("integrationKey"),
            &registry_of(vectors.text("registryKey"), vectors.text("registryReader")),
            app.field("declaration").text("ref"),
        )
    }

    #[test]
    fn is_the_sale_of_the_app_declaration() {
        let vectors = vectors();
        let sale = sale(&vectors);
        assert_eq!(sale.author, vectors.text("saleAuthor"));
        assert_eq!(to_hex(sale.secret_key.expose()), vectors.text("saleSecret"));
        assert_eq!(to_hex(sale.inner_key.expose()), vectors.text("innerConversationKey"));
    }

    #[test]
    fn derives_the_keys_of_each_address() {
        let vectors = vectors();
        let sale = sale(&vectors);
        let key = vectors.secret("registryKey");
        every_case("onchain-leases.json derived", vectors.list("derived"), |case| {
            let d = crate::derive::lease_address(&key, case.text("address"));
            let actual = Json::object([
                ("registryAddress", text(&d)),
                ("outerKey", text(&to_hex(outer_key(&key, &d, &sale.author).expose()))),
            ]);
            expect_same(
                &actual,
                &Json::object([
                    ("registryAddress", case.field("registryAddress").clone()),
                    ("outerKey", case.field("outerKey").clone()),
                ]),
            )
        });
    }

    fn outside_json(outside: &LeaseOutside) -> Json {
        match outside {
            LeaseOutside::Newer => text("newer"),
            LeaseOutside::Withdrawn => {
                Json::object([("version", Json::unsigned(1)), ("withdrawn", Json::Bool(true))])
            }
            LeaseOutside::Lease { end, sealed } => Json::object([
                ("version", Json::unsigned(1)),
                ("end", Json::integer(*end)),
                ("sealed", text(sealed)),
            ]),
        }
    }

    #[test]
    fn opens_each_event() {
        let vectors = vectors();
        let sale = sale(&vectors);
        let key = vectors.secret("registryKey");
        every_case("onchain-leases.json events", vectors.list("events"), |case| {
            let event = case.field("event");
            let d = crate::derive::lease_address(&key, case.text("address"));
            let record = open_lease_record(event, &key, &d);
            let whole = open_lease_outside(event, &key, &d);
            expect_same(
                &whole.as_ref().map_or(Json::Null, |(_, outside)| outside_json(outside)),
                case.field("outside"),
            )?;
            // A read keeps of it only its id, author, date and signature, and its outside's end.
            let kept = whole.as_ref().map(|_| LeaseEvent {
                id: event.text("id").to_owned(),
                pubkey: event.text("pubkey").to_owned(),
                created_at: event.int("created_at"),
                sig: event.text("sig").to_owned(),
            });
            if record.as_ref().map(|record| record.event.clone()) != kept {
                return Err("the record's event".to_owned());
            }
            // Opening it checks no signature; the record checks it when asked.
            let signature = case.get("signature").and_then(Json::as_bool).unwrap_or(true);
            if signature_checks(event.text("id"), event.text("pubkey"), event.text("sig")) != signature {
                return Err("its signature".to_owned());
            }
            if record.as_ref().is_some_and(|record| record.signed() != signature) {
                return Err("the record's signature".to_owned());
            }
            let opened = match &whole {
                Some((_, LeaseOutside::Lease { end, sealed })) => {
                    open_lease_inside(sealed, *end, &d, &sale).ok().flatten()
                }
                _ => None,
            };
            expect_same(
                &opened.as_ref().map_or(Json::Null, |(_, inside)| inside.clone()),
                case.field("inside"),
            )?;
            let inside = !case.field("inside").is_null();
            // The order's tolerance it gives: absent, or not one, none.
            let tolerance = opened.as_ref().map(|(terms, _)| terms.tolerance);
            let expected =
                inside.then(|| case.get("tolerance").and_then(Json::as_safe_integer).unwrap_or(0) as u64);
            if tolerance != expected {
                return Err(format!("tolerance {tolerance:?}, expected {expected:?}"));
            }
            // Confirmed: `confirmed` true alone (the vector's field, absent: true).
            let confirmed = opened.as_ref().map(|(terms, _)| terms.is_confirmed());
            let expected = inside.then(|| case.get("confirmed").and_then(Json::as_bool).unwrap_or(true));
            if confirmed != expected {
                return Err(format!("confirmed {confirmed:?}, expected {expected:?}"));
            }
            Ok(())
        });
    }

    #[test]
    fn makes_each_lease_again() {
        // A lease the crate makes for the same sale and terms opens with the vector's keys into the
        // vector's inside, byte for byte.
        let vectors = vectors();
        let sale = sale(&vectors);
        let key = vectors.secret("registryKey");
        // A lease the crate writes holds a tolerance of its type (a natural number of basis
        // points): an inside holding another one (a fraction) is opened above, never written.
        let events: Vec<Json> = vectors
            .list("events")
            .iter()
            .filter(|case| !case.field("inside").is_null())
            .filter(|case| {
                case.field("inside")
                    .get("tolerance")
                    .is_none_or(|tolerance| tolerance.as_safe_integer().is_some_and(|value| value >= 0))
            })
            .cloned()
            .collect();
        assert_eq!(
            events.len() + 1,
            vectors.list("events").iter().filter(|case| !case.field("inside").is_null()).count()
        );
        every_case("onchain-leases.json events made again", &events, |case| {
            let v = case.field("inside");
            let fiat = v.field("sale").field("fiat");
            let terms = LeaseTerms {
                address: case.text("address").to_owned(),
                sats: v.int("sats") as u64,
                invoice: v.opt_text("invoice").map(str::to_owned),
                verify_url: v.opt_text("verifyUrl").map(str::to_owned),
                created_at: v.int("createdAt"),
                expires_at: v.int("expiresAt"),
                price: DeclaredPrice {
                    minor: fiat.int("minor") as u64,
                    digits: fiat.int("digits") as u32,
                    currency: fiat.text("currency").to_owned(),
                },
                note: v.field("sale").text("note").to_owned(),
                tolerance: v.get("tolerance").and_then(Json::as_safe_integer).unwrap_or(0) as u64,
                confirmed: v.get("confirmed").and_then(Json::as_bool),
            };
            let made = lease_event(&sale, &terms, case.field("event").int("created_at"), &OsRandom).unwrap();
            let d = crate::derive::lease_address(&key, case.text("address"));
            if made.tags != vec![vec!["d".to_owned(), d.clone()]] || made.pubkey != vectors.text("saleAuthor")
            {
                return Err("its tags or author".to_owned());
            }
            let derived = vectors
                .list("derived")
                .iter()
                .find(|derived| derived.text("address") == case.text("address"))
                .unwrap();
            let plaintext =
                decrypt(&made.content, &derived.secret("outerKey")).map_err(|error| format!("{error:?}"))?;
            if plaintext.len() % 256 != 0 {
                return Err("its padding".to_owned());
            }
            let record = json::parse(&plaintext).unwrap();
            if record.get("t").and_then(Json::as_str) != Some("registry-onchain") {
                return Err("its type".to_owned());
            }
            let outside = record.get("v").unwrap();
            if outside.get("end") != case.field("outside").get("end") {
                return Err("its end".to_owned());
            }
            let sealed = decrypt(
                outside.get("sealed").and_then(Json::as_str).unwrap(),
                &vectors.secret("innerConversationKey"),
            )
            .unwrap();
            if sealed != json::stringify(v) {
                return Err(format!("its inside:\n  {sealed}\n  {}", json::stringify(v)));
            }
            let inner = conversation_key(&sale.secret_key, vectors.text("registryReader")).unwrap();
            if to_hex(inner.expose()) != vectors.text("innerConversationKey") {
                return Err("the inner conversation key".to_owned());
            }
            Ok(())
        });
    }

    /// A record of a vector: what it holds, its signature as the vector says, which the walk
    /// records when it checks it.
    struct VectorRecord<'a> {
        event: LeaseEvent,
        hold: LeaseHold,
        valid: bool,
        index: usize,
        checked: &'a Mutex<Vec<usize>>,
    }

    impl HoldRecord for VectorRecord<'_> {
        fn lease_event(&self) -> &LeaseEvent {
            &self.event
        }

        fn hold(&self) -> LeaseHold {
            self.hold
        }

        fn signed(&self) -> bool {
            self.checked.lock().unwrap().push(self.index);
            self.valid
        }
    }

    /// The records of a vector, as opened (one whose id is not its hash never is).
    fn records_of<'a>(records: &[Json], checked: &'a Mutex<Vec<usize>>) -> Vec<VectorRecord<'a>> {
        records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.get("id") != Some(&Json::Bool(false)))
            .map(|(index, record)| {
                let outside = record.field("outside");
                let hold = if outside.as_str() == Some("newer") {
                    LeaseHold::Newer
                } else if outside.get("withdrawn") == Some(&Json::Bool(true)) {
                    LeaseHold::Withdrawn
                } else {
                    LeaseHold::Lease { end: outside.int("end") }
                };
                VectorRecord {
                    event: LeaseEvent {
                        id: record.opt_text("eventId").map_or_else(|| format!("{index:0>64}"), str::to_owned),
                        pubkey: record.text("author").to_owned(),
                        created_at: record.int("createdAt"),
                        sig: String::new(),
                    },
                    hold,
                    valid: record.get("signature") != Some(&Json::Bool(false)),
                    index,
                    checked,
                }
            })
            .collect()
    }

    #[test]
    fn leased() {
        let vectors = vectors();
        every_case("onchain-leases.json leased", vectors.list("leased"), |case| {
            let checked = Mutex::new(Vec::new());
            let records = records_of(case.list("records"), &checked);
            let refs: Vec<&VectorRecord<'_>> = records.iter().collect();
            let leased = is_leased(&refs, case.int("t"));
            if leased != case.field("expected").as_bool().unwrap() {
                return Err(format!("leased: {leased}"));
            }
            // The signatures checked: those of the records that would end an older one's hold.
            let mut asked = checked.lock().unwrap().clone();
            asked.sort_unstable();
            let expected: Vec<usize> =
                case.list("checked").iter().map(|index| index.as_safe_integer().unwrap() as usize).collect();
            if asked != expected { Err(format!("checked {asked:?}, expected {expected:?}")) } else { Ok(()) }
        });
    }

    #[test]
    fn confirmed() {
        let vectors = vectors();
        every_case("onchain-leases.json confirmed", vectors.list("confirmed"), |case| {
            let checked = Mutex::new(Vec::new());
            let read = records_of(case.list("records"), &checked);
            // This lease, or one that is not among the records read.
            let own = match case.field("lease").as_safe_integer() {
                None => LeaseEvent {
                    id: "f".repeat(64),
                    pubkey: case.text("sale").to_owned(),
                    created_at: case.int("t"),
                    sig: String::new(),
                },
                Some(index) => {
                    let id = format!("{index:0>64}");
                    read.iter().find(|record| record.event.id == id).unwrap().event.clone()
                }
            };
            let refs: Vec<&VectorRecord<'_>> = read.iter().collect();
            let complete = case.field("complete").as_bool().unwrap();
            let actual = complete && is_confirmed(&refs, &own, case.int("t"));
            if actual == case.field("expected").as_bool().unwrap() {
                Ok(())
            } else {
                Err(format!("{actual}"))
            }
        });
    }
}

mod onchain_witnesses_json {
    use super::*;

    fn vectors() -> Json {
        spec("vectors/onchain-witnesses.json")
    }

    #[test]
    fn derives_the_seen_keys_and_the_witness_addresses_and_tags() {
        let vectors = vectors();
        let key = vectors.secret("integrationKey");
        let keys = seen_keys(&key);
        let derived = vectors.field("derived");
        assert_eq!(to_hex(keys.secret_key.expose()), derived.text("seenSecret"));
        assert_eq!(keys.author, derived.text("seenAuthor"));
        assert_eq!(to_hex(keys.address_key.expose()), derived.text("seenAddressKey"));
        let seen = seen_of(&key);
        assert_eq!(to_hex(seen.encryption_key.expose()), vectors.text("channelEncryptionKey"));
        every_case("onchain-witnesses.json addresses", vectors.list("addresses"), |case| {
            let address = witness_address(
                &seen.address_key,
                case.text("address"),
                case.text("txid"),
                case.opt_text("sale"),
            );
            expect_same(&text(&address), case.field("witnessAddress"))
        });
        every_case("onchain-witnesses.json orderTags", vectors.list("orderTags"), |case| {
            expect_same(
                &text(&order_tag(&seen.address_key, case.text("address"), case.opt_text("sale"))),
                case.field("orderTag"),
            )
        });
        every_case("onchain-witnesses.json addressTags", vectors.list("addressTags"), |case| {
            expect_same(
                &text(&address_tag(&seen.address_key, case.text("address"))),
                case.field("addressTag"),
            )
        });
    }

    fn witness_json(witness: &Witness) -> Json {
        Json::object([
            ("version", Json::unsigned(1)),
            ("address", text(&witness.address)),
            ("txid", text(&witness.txid)),
            ("sale", Json::optional_str(witness.sale.as_deref())),
            ("sats", Json::unsigned(witness.sats)),
            ("inputs", Json::array(witness.inputs.iter().map(|coin| text(coin)).collect())),
            ("replacement", Json::Bool(witness.replacement)),
            ("expiresAt", witness.expires_at.map_or(Json::Null, Json::integer)),
        ])
    }

    fn value_of(event: &Json, seen: &crate::onchain::witness::SeenKeys) -> Json {
        match valid_event(event).and_then(|event| open_witness(&event, seen)) {
            None => Json::Null,
            Some(OpenedWitness::Newer { .. }) => text("newer"),
            Some(OpenedWitness::Valid { witness, .. }) => witness_json(&witness),
        }
    }

    #[test]
    fn opens_each_event() {
        let vectors = vectors();
        let seen = seen_of(&vectors.secret("integrationKey"));
        every_case("onchain-witnesses.json events", vectors.list("events"), |case| {
            expect_same(&value_of(case.field("event"), &seen), case.field("value"))
        });
    }

    /// The addresses each event names when leasing (SPEC.md §31, Leasing an address, step 3), as
    /// `read_named_addresses` keeps them: of the vector's address tags, with the seen author.
    #[test]
    fn names_the_addresses_of_each_event() {
        let vectors = vectors();
        let seen = seen_of(&vectors.secret("integrationKey"));
        let by_tag: HashMap<String, String> = vectors
            .list("addressTags")
            .iter()
            .map(|case| {
                (address_tag(&seen.address_key, case.text("address")), case.text("address").to_owned())
            })
            .collect();
        let author = vectors.field("derived").text("seenAuthor").to_owned();
        let checks = |event: &Event| signature_checks(&event.id, &event.pubkey, &event.sig);
        every_case("onchain-witnesses.json names", vectors.list("events"), |case| {
            let mut named = addresses_named(case.field("event"), &author, &by_tag, &checks);
            named.sort();
            let mut expected = case.texts("names");
            expected.sort();
            if named == expected { Ok(()) } else { Err(format!("got {named:?}, expected {expected:?}")) }
        });
    }

    #[test]
    fn makes_each_witness_again() {
        // A witness the crate makes for the same value has the vector's `d` and `o` tags (a
        // vector's other tags are ignored), and opens to it.
        let vectors = vectors();
        let seen = seen_of(&vectors.secret("integrationKey"));
        let cases: Vec<Json> =
            vectors.list("events").iter().filter(|case| case.field("value").is_object()).cloned().collect();
        every_case("onchain-witnesses.json events made again", &cases, |case| {
            let v = case.field("value");
            let witness = Witness {
                address: v.text("address").to_owned(),
                txid: v.text("txid").to_owned(),
                sale: v.opt_text("sale").map(str::to_owned),
                sats: v.int("sats") as u64,
                inputs: v.texts("inputs"),
                replacement: v.field("replacement").as_bool().unwrap(),
                expires_at: v.get("expiresAt").and_then(Json::as_safe_integer),
            };
            let event = case.field("event");
            let made = witness_event(&seen, &witness, event.int("created_at"), &OsRandom);
            if made.pubkey != vectors.field("derived").text("seenAuthor") {
                return Err("its author".to_owned());
            }
            let tags: Vec<Vec<String>> = event
                .list("tags")
                .iter()
                .filter_map(|tag| {
                    let tag: Vec<String> = tag
                        .as_array()?
                        .iter()
                        .map(|item| item.as_str().map(str::to_owned))
                        .collect::<Option<_>>()?;
                    (tag.first().map(String::as_str) == Some("d")
                        || tag.first().map(String::as_str) == Some("o"))
                    .then_some(tag)
                })
                .collect();
            if made.tags != tags {
                return Err(format!("its tags {:?}", made.tags));
            }
            expect_same(&value_of(&made.to_json(), &seen), v)
        });
    }
}

#[test]
fn onchain_replacements_json() {
    let vectors = spec("vectors/onchain-replacements.json");
    every_case("onchain-replacements.json", vectors.list("cases"), |case| {
        let txs: Vec<PaymentTx> = case
            .list("txs")
            .iter()
            .map(|tx| PaymentTx {
                txid: tx.text("txid").to_owned(),
                sats: tx.digits("sats"),
                inputs: tx.texts("inputs"),
                order: tx.get("order").and_then(Json::as_safe_integer),
                listed: tx.field("listed").as_bool().unwrap(),
            })
            .collect();
        let made = payment_parts(&txs);
        let actual = Json::object_of(
            made.iter()
                .map(|(txid, parts)| {
                    (
                        txid.as_str(),
                        Json::array(
                            parts
                                .iter()
                                .map(|part| {
                                    Json::object([
                                        ("sats", text(&part.sats.to_string())),
                                        ("root", text(&part.root)),
                                    ])
                                })
                                .collect(),
                        ),
                    )
                })
                .collect(),
        );
        expect_same(&actual, case.field("parts"))
    });
}

/// vectors/app/merchant-acceptance.json (SPEC.md §31, The merchant's acceptance): the addresses of
/// the merchant's acceptances of invoices of the app's integration, and records made by the app
/// (`records`, read with `secretKey`) or by the specification's own code for a team of its own
/// (`made.records`, read with `made.secretKey`: the same integration key), each read as a check
/// reads it for its invoice: through the opening of one record (`open_merchant_acceptance`), and
/// through the count of a read on every relay where each of 3 relays sent it (what the read keeps
/// of it, `merchant_acceptance_keep`, then `merchant_acceptance_of`).
mod merchant_acceptance_json {
    use super::*;

    fn vector() -> Json {
        spec("vectors/app/merchant-acceptance.json")
    }

    #[test]
    fn derives_the_team_the_channel_key_and_each_invoice_address() {
        let vector = vector();
        let app = parse_integration_key(vector.text("secretKey")).unwrap();
        assert_eq!(app.team, vector.text("team"));
        assert_eq!(
            to_hex(channel_keys(&app.key).encryption_key.expose()),
            vector.text("channelEncryptionKey")
        );
        // `made`: a team of its own, for the same integration key.
        let made = vector.field("made");
        let made_key = parse_integration_key(made.text("secretKey")).unwrap();
        assert_eq!(made_key.team, made.text("team"));
        assert_eq!(public_key_of(&made.secret("teamSecret")), made.text("team"));
        assert_eq!(made_key.key.expose(), app.key.expose());
        let invoices = vector.list("invoices");
        assert!(!invoices.is_empty());
        every_case("merchant-acceptance.json invoices", invoices, |invoice| {
            let sale = sale_keys(&app.key, invoice.text("ref"));
            let actual = Json::object([
                ("saleKey", text(&to_hex(sale.key.expose()))),
                ("sale", text(&sale.author)),
                (
                    "acceptanceAddress",
                    text(&merchant_acceptance_address(
                        &app.key,
                        &sale.author,
                        invoice.text("onchainAddress"),
                        invoice.int("expiresAt"),
                    )),
                ),
            ]);
            expect_same(
                &actual,
                &Json::object([
                    ("saleKey", invoice.field("saleKey").clone()),
                    ("sale", invoice.field("sale").clone()),
                    ("acceptanceAddress", invoice.field("acceptanceAddress").clone()),
                ]),
            )
        });
    }

    /// Reads each record of `records` with the integration key `secret_key`, for its invoice.
    fn reads_each_record(name: &str, records: &[Json], secret_key: &str) {
        let vector = vector();
        let key = parse_integration_key(secret_key).unwrap();
        let invoices = vector.list("invoices");
        assert!(!records.is_empty());
        every_case(name, records, |record| {
            let invoice = &invoices[record.int("invoice") as usize];
            let keys = MerchantAcceptanceKeys::of(
                &key.key,
                &key.team,
                invoice.text("sale"),
                invoice.text("onchainAddress"),
                invoice.int("expiresAt"),
            );
            let terms =
                AcceptedInvoice { sats: invoice.digits("sats"), expires_at: invoice.int("expiresAt") };
            let event = record.field("event");
            let opened = open_merchant_acceptance(event, &keys, terms);
            let actual = match &opened {
                Some(OpenedMerchantAcceptance::Valid { event, received }) => Json::object([
                    ("received", Json::unsigned(*received)),
                    ("createdAt", Json::integer(event.created_at)),
                ]),
                Some(OpenedMerchantAcceptance::Newer { .. }) => text("newer"),
                Some(OpenedMerchantAcceptance::NewerSetAside { .. }) | None => Json::Null,
            };
            let expected = record.field("expected");
            expect_same(&actual, expected).map_err(|why| format!("opened: {why}"))?;
            // Every relay of 3 sent it: what the read keeps of it, counted.
            let keep = merchant_acceptance_keep(&keys);
            let answers: Answers<Event> = (1..=3)
                .map(|n| (format!("wss://relay-{n}.test"), keep(event).into_iter().collect()))
                .collect();
            let counted = merchant_acceptance_of(&answers, &keys, terms, 3);
            let received =
                expected.get("received").and_then(Json::as_safe_integer).map(|received| received as u64);
            // A newer format is told whatever its date: logged.
            let newer = matches!(
                opened,
                Some(OpenedMerchantAcceptance::Newer { .. } | OpenedMerchantAcceptance::NewerSetAside { .. })
            );
            if counted != (MerchantAcceptance { received, newer }) {
                return Err(format!("counted {counted:?}"));
            }
            Ok(())
        });
    }

    #[test]
    fn reads_each_record_the_app_made() {
        let vector = vector();
        reads_each_record(
            "merchant-acceptance.json records",
            vector.list("records"),
            vector.text("secretKey"),
        );
    }

    #[test]
    fn reads_each_record_made_for_a_team_of_the_vector() {
        let vector = vector();
        let made = vector.field("made");
        reads_each_record("merchant-acceptance.json made", made.list("records"), made.text("secretKey"));
    }
}

mod onchain_payments_json {
    use super::*;

    fn error_of(code: &str) -> Error {
        match code {
            "network" => Error::network("The Lightning address did not answer"),
            "invalid_invoice" => Error::invalid_invoice("Not this invoice"),
            other => panic!("no error {other} in these vectors"),
        }
    }

    fn lightning_of(value: &Json) -> Settled<LightningPart> {
        if let Some(error) = value.opt_text("error") {
            return Err(error_of(error));
        }
        Ok(match value.text("state") {
            "open" => LightningPart::Open,
            "expired" => LightningPart::Expired,
            "paid" => LightningPart::Paid(value.text("preimage").to_owned()),
            other => panic!("no state {other}"),
        })
    }

    /// Another order's deposit address: a witness there is of no invoice of the vector's read.
    const OTHER_ADDRESS: &str = "bc1p4gmh64rd4m5y5nn8hwfnvtz2mm6lngpmwys5a257klyg03ju0pyqu65xe8";

    /// The witnesses of a vector, as the relays send them to the check's reads, read as
    /// `read_order_witnesses` reads them (`order_witnesses_of`): the first read, then those after
    /// publishing (the same and the ones the check published, unless the vector says); what the
    /// check publishes.
    struct VectorWitnesses<'a> {
        case: &'a Json,
        reads: AtomicUsize,
        published: Mutex<Vec<Json>>,
        /// The events of the witnesses the check published, as the relays then hold them.
        published_events: Mutex<Vec<Event>>,
        seen: crate::onchain::witness::SeenKeys,
        address: String,
        sale: String,
        /// The author of another sale of the integration.
        other_sale: String,
        expires_at: i64,
        now: i64,
        problems: Mutex<Vec<String>>,
        /// The check's read of the merchant's acceptance, and whether it read it.
        merchant: MerchantRead<'a>,
        team: &'a Team,
        merchant_read: AtomicBool,
    }

    impl VectorWitnesses<'_> {
        /// The event of a witness of the vector, as a relay sends it: made by the seen secret as
        /// the client makes witnesses (`witness_event`), at the invoice's address or, `address`
        /// "other", at another order's; for the order's sale ("this", with the `expiresAt` of the
        /// invoice it is of), another sale (with the invoice's `expiresAt`: nothing here depends on
        /// it) or none. One of a newer format: a record of the seen secret at the witness address
        /// of its txid and the order's sale ("newer") or none ("newer none"), with that address's
        /// `o` tags, dated `newer_at` (the vector gives no date of it).
        fn event_of(&self, w: &Json, newer_at: i64) -> Event {
            let at =
                if w.opt_text("address") == Some("other") { OTHER_ADDRESS } else { self.address.as_str() };
            let txid = w.text("txid");
            let seen = &self.seen;
            match w.field("sale").as_str() {
                Some(newer @ ("newer" | "newer none")) => {
                    let of = (newer == "newer").then_some(self.sale.as_str());
                    seal_record(
                        Seal {
                            record_type: WITNESS_RECORD_TYPE,
                            value: Json::object([("version", Json::Number(WITNESS_VERSION + 1.0))]),
                            signer: &seen.secret_key,
                            encryption_key: &seen.encryption_key,
                            address: &witness_address(&seen.address_key, at, txid, of),
                            created_at: newer_at,
                            tags: vec![
                                vec![ORDER_TAG.to_owned(), order_tag(&seen.address_key, at, of)],
                                vec![ORDER_TAG.to_owned(), address_tag(&seen.address_key, at)],
                            ],
                        },
                        &OsRandom,
                    )
                    .unwrap()
                }
                sale => {
                    let of = match sale {
                        Some("this") => Some(self.sale.clone()),
                        Some("other") => Some(self.other_sale.clone()),
                        None => None,
                        Some(other) => panic!("no sale {other} in these vectors"),
                    };
                    let expires_at = of.as_ref().map(|_| {
                        w.get("expiresAt").and_then(Json::as_safe_integer).unwrap_or(self.expires_at)
                    });
                    let witness = Witness {
                        address: at.to_owned(),
                        txid: txid.to_owned(),
                        sale: of,
                        sats: w.int("sats") as u64,
                        inputs: w.texts("inputs"),
                        replacement: w.field("replacement").as_bool().unwrap(),
                        expires_at,
                    };
                    witness_event(seen, &witness, w.int("seenAt"), &OsRandom)
                }
            }
        }
    }

    impl Witnesses for VectorWitnesses<'_> {
        fn read(&self, _every_relay: bool) -> BoxFuture<'_, Result<OrderWitnesses, Error>> {
            let again = self.reads.fetch_add(1, Ordering::SeqCst) > 0;
            let held = if again {
                self.case.get("witnessesAgain").unwrap_or(self.case.field("witnesses"))
            } else {
                self.case.field("witnesses")
            };
            let result = if held.as_str() == Some("unreadable") {
                Err(Error::network("Fewer than a majority of the merchant's relays answered"))
            } else {
                // What the relays sent to the read (`address` "other": of no invoice of the read,
                // which a relay sent anyway).
                let mut sent: Vec<Event> =
                    held.as_array().unwrap().iter().map(|w| self.event_of(w, self.now - 1)).collect();
                if again && self.case.get("witnessesAgain").is_none() {
                    sent.extend(self.published_events.lock().unwrap().iter().cloned());
                }
                Ok(order_witnesses_of(sent.iter(), &self.seen, &self.address, &self.sale, self.expires_at))
            };
            Box::pin(async move { result })
        }

        fn merchant_acceptance(&self) -> BoxFuture<'_, Result<MerchantAcceptance, Error>> {
            self.merchant_read.store(true, Ordering::SeqCst);
            let Team { keys, terms, .. } = self.team;
            match &self.merchant {
                MerchantRead::Unreadable => Box::pin(async {
                    Err(Error::network("Fewer than a majority of the merchant's relays answered"))
                }),
                MerchantRead::Counted(answers) => {
                    let counted = merchant_acceptance_of(answers, keys, *terms, MERCHANT_RELAYS);
                    Box::pin(async move { Ok(counted) })
                }
                MerchantRead::Relays { pool, urls } => {
                    Box::pin(read_merchant_acceptance(pool, keys, *terms, urls, &OsRandom))
                }
            }
        }

        fn witness_address(&self, txid: &str, sale: Option<&str>) -> String {
            witness_address(&self.seen.address_key, &self.address, txid, sale)
        }

        fn publish<'a>(&'a self, witness: &'a Witness) -> BoxFuture<'a, Result<(), Error>> {
            let result = if self.case.field("publishFails").as_bool().unwrap() {
                Err(Error::network("Fewer than a majority took the witness"))
            } else {
                if witness.address != self.address {
                    self.problems.lock().unwrap().push(format!("a witness of {}", witness.address));
                }
                // Of this invoice: its expiresAt; of none: none.
                let expected = witness.sale.is_some().then_some(self.expires_at);
                if witness.expires_at != expected {
                    self.problems
                        .lock()
                        .unwrap()
                        .push(format!("a witness's expiresAt {:?}", witness.expires_at));
                }
                self.published.lock().unwrap().push(Json::object([
                    ("txid", text(&witness.txid)),
                    ("sale", if witness.sale.is_some() { text("this") } else { Json::Null }),
                    ("replacement", Json::Bool(witness.replacement)),
                ]));
                self.published_events
                    .lock()
                    .unwrap()
                    .push(witness_event(&self.seen, witness, self.now, &OsRandom));
                Ok(())
            };
            Box::pin(async move { result })
        }
    }

    /// The merchant's relays of the vector: 3, of which 2 are a majority.
    const MERCHANT_RELAYS: usize = 3;

    /// The merchant's acceptances of the vector (the team's records, SPEC.md §31, The merchant's
    /// acceptance), made by a team of merchant-acceptance.json's own (`made`: its secret is in the
    /// vector) for the app's integration key, so that they check out: at the merchant's acceptance
    /// address of the vector's invoice for the app's sale, sealed with the channel's key; read with
    /// that team's keys (PORTING.md, step 4).
    struct Team {
        secret: crate::secret::Secret,
        keys: MerchantAcceptanceKeys,
        terms: AcceptedInvoice,
    }

    impl Team {
        fn of(invoice: &Json, sale: &str) -> Self {
            let made = spec("vectors/app/merchant-acceptance.json").field("made").clone();
            let key = parse_integration_key(made.text("secretKey")).unwrap();
            assert_eq!(
                key.key.expose(),
                app().field("parsed").secret("integrationKey").expose(),
                "made: another integration"
            );
            let expires_at = invoice.int("expiresAt");
            Team {
                secret: made.secret("teamSecret"),
                keys: MerchantAcceptanceKeys::of(
                    &key.key,
                    &key.team,
                    sale,
                    invoice.text("onchainAddress"),
                    expires_at,
                ),
                terms: AcceptedInvoice { sats: invoice.digits("sats"), expires_at },
            }
        }

        /// The events of a case's merchant's acceptances, sealed and signed by the team as the
        /// merchant's app makes them: of `{"version": 1, "received": <received>}` (a JSON number),
        /// or of version 2 for one of a newer format, dated `createdAt`. Where the vector gives two
        /// of one date ids, made again until their ids sort as the vector's (the lowest counts).
        fn events(&self, records: &[Json]) -> Vec<Event> {
            loop {
                let events: Vec<Event> = records
                    .iter()
                    .map(|record| {
                        let value = match record.opt_text("received") {
                            Some(received) => Json::object([
                                ("version", Json::Number(MERCHANT_ACCEPTANCE_VERSION)),
                                ("received", Json::Number(received.parse().unwrap())),
                            ]),
                            None => {
                                Json::object([("version", Json::Number(MERCHANT_ACCEPTANCE_VERSION + 1.0))])
                            }
                        };
                        seal_record(
                            Seal {
                                record_type: MERCHANT_ACCEPTANCE_RECORD_TYPE,
                                value,
                                signer: &self.secret,
                                encryption_key: &self.keys.encryption_key,
                                address: &self.keys.address,
                                created_at: record.int("createdAt"),
                                tags: Vec::new(),
                            },
                            &OsRandom,
                        )
                        .unwrap()
                    })
                    .collect();
                let ids = |index: usize| (records[index].opt_text("id"), events[index].id.as_str());
                let sorted = (0..records.len()).all(|a| {
                    (0..records.len()).all(|b| match (ids(a), ids(b)) {
                        ((Some(vector_a), made_a), (Some(vector_b), made_b)) => {
                            (vector_a < vector_b) == (made_a < made_b)
                        }
                        _ => true,
                    })
                });
                if sorted {
                    return events;
                }
            }
        }

        /// What each of the merchant's 3 relays holds of a case's merchant's acceptances (absent:
        /// none): each record on the first `sentBy` of them (absent: all 3).
        fn held(&self, case: &Json) -> Vec<Vec<Event>> {
            let records = case.get("merchantAccepted").and_then(Json::as_array).unwrap_or_default();
            let events = self.events(records);
            (0..MERCHANT_RELAYS)
                .map(|index| {
                    records
                        .iter()
                        .zip(&events)
                        .filter(|(record, _)| {
                            let sent_by = record.get("sentBy").and_then(Json::as_safe_integer);
                            index < sent_by.map_or(MERCHANT_RELAYS, |sent_by| sent_by as usize)
                        })
                        .map(|(_, event)| event.clone())
                        .collect()
                })
                .collect()
        }
    }

    /// How the check reads the merchant's acceptance of a case.
    enum MerchantRead<'a> {
        /// Fewer than a majority answer (`"unreadable"`): `network`, as `read_merchant_acceptance`
        /// fails.
        Unreadable,
        /// What each relay sent, as the read keeps it, counted (`merchant_acceptance_of`).
        Counted(Answers<Event>),
        /// Read on local relays (`read_merchant_acceptance`).
        Relays { pool: &'a RelayPool, urls: &'a [String] },
    }

    /// The check's read of a case's merchant's acceptances without the relays: each of the 3
    /// answers with the records it holds, kept as the read keeps them (`merchant_acceptance_keep`).
    fn counted(case: &Json, team: &Team) -> MerchantRead<'static> {
        if case.get("merchantAccepted").and_then(Json::as_str) == Some("unreadable") {
            return MerchantRead::Unreadable;
        }
        let keep = merchant_acceptance_keep(&team.keys);
        MerchantRead::Counted(
            team.held(case)
                .iter()
                .enumerate()
                .map(|(index, events)| {
                    let kept = events.iter().filter_map(|event| keep(&event.to_json())).collect();
                    (format!("wss://merchant-{}.test", index + 1), kept)
                })
                .collect(),
        )
    }

    #[test]
    fn makes_witnesses_of_another_order_at_a_deposit_address_of_its_own() {
        let address =
            spec("vectors/onchain-payments.json").field("invoice").text("onchainAddress").to_owned();
        assert!(is_deposit_address(OTHER_ADDRESS) && OTHER_ADDRESS != address);
    }

    /// The explorer and BlockCypher of a vector.
    fn http_of(
        case: &Json,
        address: &str,
        asked: std::sync::Arc<Mutex<Vec<String>>>,
        unexpected: std::sync::Arc<Mutex<Vec<String>>>,
    ) -> FakeHttp {
        let case = case.clone();
        let address = address.to_owned();
        FakeHttp::new(move |call| {
            let path = call.url.as_str();
            let explorer = case.field("explorer");
            if path == format!("{MEMPOOL_URL}/address/{address}/txs") {
                return Some(if explorer.has("error") {
                    Answer::text(500, "down")
                } else {
                    Answer::json(explorer.field("txs"))
                });
            }
            if path == format!("{MEMPOOL_URL}/blocks/tip/height") {
                return Some(if explorer.has("error") {
                    Answer::text(500, "down")
                } else {
                    Answer::text(200, &explorer.int("height").to_string())
                });
            }
            if call.host() == "api.blockcypher.com" {
                let txid = call.path().rsplit('/').next().unwrap().to_owned();
                asked.lock().unwrap().push(txid.clone());
                let blockcypher = case.field("blockcypher");
                if blockcypher.has("error") {
                    return Some(Answer::status_json(500, &Json::object([("error", text("down"))])));
                }
                // As the vector writes it: a date, or anything else BlockCypher could send.
                return Some(match blockcypher.get(&txid) {
                    None => Answer::status_json(
                        404,
                        &Json::object([("error", text(&format!("Transaction {txid} not found.")))]),
                    ),
                    Some(received) => Answer::json(&Json::object([
                        ("hash", text(&txid)),
                        ("received", received.clone()),
                        ("confirmations", Json::unsigned(0)),
                    ])),
                });
            }
            unexpected.lock().unwrap().push(format!("Not asked in this vector: {path}"));
            None
        })
    }

    /// What every case runs with: the vector's invoice, the app's sale (its author) and another
    /// sale of the integration, the seen keys, the invoice's rest keys, and the team of the
    /// merchant's acceptances.
    struct Setup {
        invoice: Json,
        sale: String,
        other_sale: String,
        seen: crate::onchain::witness::SeenKeys,
        rest: RestKeys,
        team: Team,
    }

    fn setup() -> Setup {
        let vectors = spec("vectors/onchain-payments.json");
        let invoice = vectors.field("invoice").clone();
        let app = app();
        let sale = app.field("declaration").text("saleAuthor").to_owned();
        let integration_key = app.field("parsed").secret("integrationKey");
        // The rest keys of the invoice, for an order of the app's sale.
        let rest = rest_keys(
            &integration_key,
            app.field("declaration").text("ref"),
            invoice.text("onchainAddress"),
            invoice.int("expiresAt"),
        );
        Setup {
            seen: seen_of(&integration_key),
            other_sale: sale_keys(&integration_key, "ANOTHER-ORDER").author,
            rest,
            team: Team::of(&invoice, &sale),
            sale,
            invoice,
        }
    }

    /// Runs a case through the crate's payment check (`check_onchain_part`, `combine_parts`), its
    /// merchant's acceptance read as `merchant` says; then the acceptance record it publishes.
    async fn run(case: &Json, setup: &Setup, merchant: MerchantRead<'_>) -> Result<(), String> {
        let Setup { invoice, sale, other_sale, seen, rest, team } = setup;
        let address = invoice.text("onchainAddress");
        let sats = invoice.digits("sats");
        let expires_at = invoice.int("expiresAt");
        let asked = std::sync::Arc::new(Mutex::new(Vec::new()));
        let unexpected = std::sync::Arc::new(Mutex::new(Vec::new()));
        let http = http_of(case, address, asked.clone(), unexpected.clone()).http(1000);
        let witnesses = VectorWitnesses {
            case,
            reads: AtomicUsize::new(0),
            published: Mutex::new(Vec::new()),
            published_events: Mutex::new(Vec::new()),
            seen: seen.clone(),
            address: address.to_owned(),
            sale: sale.to_owned(),
            other_sale: other_sale.to_owned(),
            expires_at,
            now: case.int("now"),
            problems: Mutex::new(Vec::new()),
            merchant,
            team,
            merchant_read: AtomicBool::new(false),
        };
        // The rest part: the invoices of the rest the relays hold, and the Lightning part of each.
        let rests = match case.get("rests") {
            None => None,
            Some(list) => {
                let mut part = RestPart::default();
                for rest in list.as_array().unwrap() {
                    let decoded = bolt11::decode(rest.text("invoice")).unwrap();
                    let msat = decoded.amount_msat.unwrap();
                    // What the vector writes of it is the invoice's own.
                    let own = (
                        decoded.payment_hash.as_str(),
                        (msat / 1000).to_string(),
                        decoded.timestamp,
                        decoded.expires_at(),
                    );
                    if own
                        != (
                            rest.text("paymentHash"),
                            rest.text("sats").to_owned(),
                            rest.int("createdAt"),
                            rest.int("expiresAt"),
                        )
                    {
                        return Err("a rest's fields".to_owned());
                    }
                    part.invoices.push(RestInvoice {
                        bolt11: rest.text("invoice").to_owned(),
                        payment_hash: decoded.payment_hash.clone(),
                        verify_url: format!("https://breez.tips/lnurlp/verify/{}", decoded.payment_hash),
                        sats: msat / 1000,
                        created_at: decoded.timestamp,
                        expires_at: decoded.expires_at(),
                    });
                    part.results.push(lightning_of(rest.field("lightning")));
                }
                Some(part)
            }
        };
        let now = case.int("now");
        let logger = Warnings::default();
        let clock = crate::tests::support::random::TestClock::new(now);
        // mempool.space: no node.
        let explorer = crate::onchain::explorer::Explorer::new(
            None,
            Default::default(),
            std::sync::Arc::new(clock.clone()),
        );
        let check = OnchainCheck {
            address,
            sats,
            expires_at,
            sale,
            clock: &clock,
            explorer: &explorer,
            http: &http,
            witnesses: &witnesses,
            logger: &logger,
        };
        let paid = rest_summary(rests.as_ref()).paid;
        let tolerance = tolerance_of(case.get("tolerance"));
        let onchain = check_onchain_part(&check, async move { paid }, async move { tolerance }).await;
        let lightning = case.opt("lightning").map(lightning_of);
        let status = combine_parts(
            InvoiceTerms { sats, expires_at, address: Some(address) },
            now,
            lightning.as_ref(),
            Some(&onchain),
            rests.as_ref(),
        );
        let actual = match &status {
            Ok(status) => crate::tests::support::js(serde_json::to_value(status).unwrap()),
            Err(error) => Json::object([("error", text(error.code().as_str()))]),
        };
        expect_same(&actual, case.field("expected"))?;
        let expected_error = case.field("expected").has("error");
        if !expected_error {
            expect_same(&Json::array(witnesses.published.lock().unwrap().clone()), case.field("published"))
                .map_err(|why| format!("published: {why}"))?;
        }
        expect_same(
            &Json::array(asked.lock().unwrap().iter().map(|txid| text(txid)).collect()),
            case.field("asked"),
        )
        .map_err(|why| format!("asked: {why}"))?;
        let problems: Vec<String> = witnesses
            .problems
            .lock()
            .unwrap()
            .iter()
            .chain(unexpected.lock().unwrap().iter())
            .cloned()
            .collect();
        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        // The acceptance record the check publishes, unless the relays hold one of what it
        // received or less (SPEC.md, "Acceptance records"); none when the status is an error.
        let acceptance = match &status {
            Ok(status) => {
                acceptance_published(status, case.opt_text("accepted"), sats, expires_at, now, rest).await?
            }
            Err(_) => None,
        };
        expect_same(
            &Json::optional_str(acceptance.as_deref()),
            case.get("acceptance").unwrap_or(&Json::Null),
        )
        .map_err(|why| format!("acceptance: {why}"))?;
        // A merchant's acceptance of a newer format is logged once when the check read it, whatever
        // its date and however many relays sent it.
        let newer = case
            .get("merchantAccepted")
            .and_then(Json::as_array)
            .is_some_and(|records| records.iter().any(|record| record.has("newer")));
        let expected = usize::from(newer && witnesses.merchant_read.load(Ordering::SeqCst));
        let warned = logger
            .all()
            .iter()
            .filter(|warning| warning.contains("a merchant's acceptance of this order has a newer format"))
            .count();
        if warned != expected {
            return Err(format!("warned {warned} times of a merchant's acceptance of a newer format"));
        }
        Ok(())
    }

    /// What the check publishes of an acceptance record of the invoice of `rest` (its rest keys)
    /// when its status is `status` (SPEC.md §31, "Acceptance records"), as the client does
    /// (`publish_acceptance`), on three local relays each of which holds one of `accepted` (absent:
    /// none holds one), so that every majority that answers reads it: the `received` of the
    /// records the relays took, `None` when none.
    async fn acceptance_published(
        status: &PaymentStatus,
        accepted: Option<&str>,
        sats: u64,
        expires_at: i64,
        now: i64,
        rest: &RestKeys,
    ) -> Result<Option<String>, String> {
        let net = RelayNet::default();
        let urls: Vec<String> = (1..=3).map(|n| format!("wss://acceptance-{n}.test")).collect();
        let relays: Vec<LocalRelay> =
            urls.iter().map(|url| net.add(url, RelayBehaviour::default())).collect();
        if let Some(accepted) = accepted {
            let held =
                acceptance_record_event(rest, accepted.parse().unwrap(), expires_at, now - 60, &OsRandom);
            for relay in &relays {
                relay.store_event(&held);
            }
        }
        let pool = pool(&net, 2000);
        let invoice = AcceptanceOf { sats, expires_at, keys: rest };
        let published = publish_acceptance(&pool, status, invoice, &urls, now, &OsRandom, &Quiet).await;
        drop(pool);
        let readers = RestReaderKeys::of(rest);
        let took: HashSet<String> = relays
            .iter()
            .flat_map(LocalRelay::received)
            .map(|event| match open_acceptance_event(&event, &readers, sats) {
                Some(Opened::Valid { value, .. }) => value.to_string(),
                Some(Opened::Newer { .. }) => "newer".to_owned(),
                None => "none".to_owned(),
            })
            .collect();
        if took.len() > 1 {
            return Err(format!("acceptance: the relays took {took:?}"));
        }
        let took = took.into_iter().next();
        // What the function says it published is what a majority took.
        if took != published.map(|received| received.to_string()) {
            return Err(format!("acceptance: published {published:?}, the relays took {took:?}"));
        }
        Ok(took)
    }

    #[tokio::test(start_paused = true)]
    async fn checks_every_case() {
        let vectors = spec("vectors/onchain-payments.json");
        let setup = setup();
        let cases = vectors.list("cases");
        assert!(!cases.is_empty());
        let mut failures = Vec::new();
        for case in cases {
            if let Err(why) = run(case, &setup, counted(case, &setup.team)).await {
                failures.push(format!("{}: {why}", case.name()));
            }
        }
        assert!(
            failures.is_empty(),
            "onchain-payments.json: {} of {} cases failed:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// The `merchantAccepted` cases again, end to end (PORTING.md, step 4): the merchant's 3
    /// relays local, each storing the events it holds as they are (several at one address
    /// included), the check reading them on every relay (`read_merchant_acceptance` on a relay
    /// pool). The first, which holds every record, answers 150 ms late: a read that went on with
    /// the first majority to answer would miss what it holds. `"unreadable"`: the 2 others never
    /// answer. Each relay is asked once, by the team and the address alone, and sent nothing.
    #[tokio::test(start_paused = true)]
    async fn checks_the_merchant_acceptance_cases_end_to_end_on_local_relays() {
        let vectors = spec("vectors/onchain-payments.json");
        let setup = setup();
        let cases: Vec<&Json> =
            vectors.list("cases").iter().filter(|case| case.has("merchantAccepted")).collect();
        assert!(!cases.is_empty());
        let mut failures = Vec::new();
        for case in &cases {
            if let Err(why) = on_local_relays(case, &setup).await {
                failures.push(format!("{}: {why}", case.name()));
            }
        }
        assert!(
            failures.is_empty(),
            "onchain-payments.json end to end: {} of {} cases failed:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    async fn on_local_relays(case: &Json, setup: &Setup) -> Result<(), String> {
        let unreadable = case.field("merchantAccepted").as_str() == Some("unreadable");
        let held = if unreadable { vec![Vec::new(); MERCHANT_RELAYS] } else { setup.team.held(case) };
        let net = RelayNet::default();
        let urls: Vec<String> = (1..=MERCHANT_RELAYS).map(|n| format!("wss://merchant-{n}.test")).collect();
        let relays: Vec<LocalRelay> = urls
            .iter()
            .zip(&held)
            .enumerate()
            .map(|(index, (url, events))| {
                let behaviour = match index {
                    0 => RelayBehaviour::delayed(150),
                    _ if unreadable => RelayBehaviour::mute(),
                    _ => RelayBehaviour::default(),
                };
                let relay = net.add(url, behaviour);
                for event in events {
                    relay.store_event(event);
                }
                relay
            })
            .collect();
        let pool = pool(&net, 2000);
        let result = run(case, setup, MerchantRead::Relays { pool: &pool, urls: &urls }).await;
        drop(pool);
        result?;
        // Nothing published there: a check never publishes a merchant's acceptance, nor again.
        if relays.iter().any(|relay| !relay.received().is_empty()) {
            return Err("a relay received an event".to_owned());
        }
        // Read on every relay, as the check reads it: each relay asked once, by its address alone
        // (none asked when no transaction pays the address).
        let keys = &setup.team.keys;
        let filter = Json::object([
            ("kinds", Json::array(vec![Json::Number(RECORD_KIND)])),
            ("authors", Json::array(vec![text(&keys.team)])),
            ("#d", Json::array(vec![text(&keys.address)])),
        ]);
        let queries: Vec<Vec<Json>> = relays.iter().map(LocalRelay::queries).collect();
        let read = queries.iter().any(|asked| !asked.is_empty());
        if read && !unreadable && queries.iter().any(|asked| *asked != [filter.clone()]) {
            return Err(format!("the relays were asked {queries:?}"));
        }
        Ok(())
    }
}

mod relay_reads_json {
    use std::sync::Arc;

    use super::super::support::random::TestClock;
    use super::super::support::relay::{MemorySocket, Peer};
    use super::*;
    use crate::transport::TransportError;
    use crate::websocket::{WebSocketClient, WebSocketConnection, WebSocketRequest};

    #[test]
    fn has_the_page_limit_and_the_pages_of_a_read() {
        let vectors = spec("vectors/relay-reads.json");
        assert_eq!(
            (vectors.int("limit") as usize, vectors.int("pages") as usize),
            (COMPLETE_READ_LIMIT, MAX_PAGES)
        );
    }

    #[test]
    fn reads_each_relay_page_after_page() {
        // What the pool reads of one relay: each page through after_complete_page; a page that
        // fails ends the read incomplete, the first one the relay's failure.
        let vectors = spec("vectors/relay-reads.json");
        every_case("relay-reads.json cases", vectors.list("cases"), |case| {
            let pages = case.list("pages");
            let mut seen = HashSet::new();
            let mut kept: Vec<Json> = Vec::new();
            let mut untils = vec![Json::Null];
            let mut end: Option<(bool, bool)> = None;
            let mut page = 1;
            while end.is_none() {
                let answer = &pages[page - 1];
                if answer.as_str() == Some("fails") {
                    end = Some((page > 1, false));
                    break;
                }
                // Every event kept: the vector counts each id once, whatever opens. The page is the
                // answer of one query, read as the pool reads it.
                let mut read = HashSet::new();
                let entries = answer
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pair| {
                        let pair = pair.as_array().unwrap();
                        let value = Json::object([("id", pair[0].clone()), ("created_at", pair[1].clone())]);
                        entry_in_answer(&value, &|value: &Json| Some(value.clone()), &mut read)
                    })
                    .collect();
                match after_complete_page(entries, &mut seen, &mut kept, page) {
                    PageEnd::Complete(complete) => end = Some((true, complete)),
                    PageEnd::Until(until) => untils.push(Json::integer(until)),
                }
                page += 1;
            }
            let (answered, complete) = end.unwrap();
            let actual = Json::object([
                ("untils", Json::array(untils)),
                ("answered", Json::Bool(answered)),
                ("complete", Json::Bool(complete)),
                ("kept", Json::unsigned(kept.len() as u64)),
            ]);
            expect_same(&actual, case.field("expected"))
        });
    }

    /// Where each relay's part of a read is when the read goes on, as a vector names it, each
    /// relay with one event of its own (`index`).
    fn state_of(state: &str, index: usize) -> RelayState<usize> {
        match state {
            "complete" => RelayState::Ended { events: vec![index], complete: true },
            "incomplete" => RelayState::Ended { events: vec![index], complete: false },
            "failed" => RelayState::Failed,
            "reading" => RelayState::Reading(vec![index]),
            other => panic!("{other}"),
        }
    }

    /// What a read of a list gives from where each relay's read was, as the pool decides it: the
    /// relays' states (`complete_read_of`), then the majorities of the list (`outcome`), the
    /// functions every read of the client ends with.
    fn read_of(relays: &[String]) -> (CompleteRead<usize>, ReadOutcome) {
        let states = relays
            .iter()
            .enumerate()
            .map(|(index, state)| (format!("wss://relay{index}.example.com"), state_of(state, index)))
            .collect();
        let read = complete_read_of(states);
        let outcome = read.outcome(relays.len());
        (read, outcome)
    }

    #[test]
    fn needs_a_majority_of_complete_relays() {
        let vectors = spec("vectors/relay-reads.json");
        every_case("relay-reads.json lists", vectors.list("lists"), |case| {
            let (_, outcome) = read_of(&case.texts("relays"));
            expect_same(&Json::Bool(outcome.complete), case.field("expected"))
        });
    }

    /// A relay that answers each query of a read with the next page of a vector: its events as
    /// the vector wrote them (`{"id", "created_at"}`, nothing else), or `CLOSED` for "fails". It
    /// records each query's filter.
    #[derive(Clone, Default)]
    struct ScriptedRelay {
        pages: Arc<Vec<Json>>,
        filters: Arc<Mutex<Vec<Json>>>,
    }

    impl WebSocketClient for ScriptedRelay {
        fn connect(
            &self,
            _request: WebSocketRequest,
        ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
            let peer = Arc::new(Peer::default());
            let (socket, sender) = MemorySocket::new(peer.clone());
            peer.open(sender);
            let relay = self.clone();
            let socket = socket.on_message(move |text| {
                let Some(Json::Array(message)) = json::parse(&text) else { return };
                let message = message.as_slice();
                if message.first().and_then(Json::as_str) != Some("REQ") {
                    return;
                }
                let id = message.get(1).cloned().unwrap_or(Json::Null);
                let page = {
                    let mut filters = relay.filters.lock().unwrap();
                    filters.push(message.get(2).cloned().unwrap_or(Json::Null));
                    filters.len() - 1
                };
                let send = |message: Vec<Json>| {
                    peer.send(json::stringify(&Json::array(message)));
                };
                match relay.pages.get(page) {
                    Some(answer) if answer.as_str() == Some("fails") => {
                        send(vec![Json::from("CLOSED"), id, Json::from("error: this page fails")]);
                    }
                    Some(answer) => {
                        for pair in answer.as_array().unwrap() {
                            let pair = pair.as_array().unwrap();
                            let event =
                                Json::object([("id", pair[0].clone()), ("created_at", pair[1].clone())]);
                            send(vec![Json::from("EVENT"), id.clone(), event]);
                        }
                        send(vec![Json::from("EOSE"), id]);
                    }
                    // A page the vector does not have: an empty one (its filter recorded).
                    None => send(vec![Json::from("EOSE"), id]),
                }
            });
            Box::pin(async move { Ok(Box::new(socket) as Box<dyn WebSocketConnection>) })
        }
    }

    /// Paged reads (a sale's declarations), through the pool itself: one relay answering each
    /// page as the vector says, every event kept (the vector counts each id once, whatever opens).
    #[tokio::test(start_paused = true)]
    async fn pages_a_read_on_a_relay() {
        let vectors = spec("vectors/relay-reads.json");
        let cases = vectors.list("paged");
        assert!(!cases.is_empty());
        let mut failures = Vec::new();
        for case in cases {
            let relay =
                ScriptedRelay { pages: Arc::new(case.list("pages").to_vec()), ..ScriptedRelay::default() };
            let pool = RelayPool::new(PoolConfig {
                websocket: Arc::new(relay.clone()),
                timeout: std::time::Duration::from_millis(1000),
                random: Arc::new(OsRandom),
                clock: Arc::new(TestClock::new(1_791_378_000)),
                call: crate::nostr::relay::CallTasks::default(),
            });
            let keep: Keep<Json> = Arc::new(|value: &Json| Some(value.clone()));
            let filter = Filter { kinds: Some(vec![30078.0]), ..Filter::default() };
            let read = pool
                .query_relays(
                    &["wss://relay.example.com".to_owned()],
                    &filter,
                    &crate::secret::Secret::new([1; 32]),
                    &keep,
                    ReadOf { needed: 1, paged: true, every_relay: false },
                )
                .await;
            let untils = relay
                .filters
                .lock()
                .unwrap()
                .iter()
                .map(|filter| filter.get("until").cloned().unwrap_or(Json::Null))
                .collect();
            let actual = Json::object([
                ("untils", Json::array(untils)),
                ("answered", Json::Bool(read.answered() == 1)),
                ("kept", Json::unsigned(read.events().count() as u64)),
            ]);
            if let Err(why) = expect_same(&actual, case.field("expected")) {
                failures.push(format!("{}: {why}", case.name()));
            }
        }
        assert!(failures.is_empty(), "relay-reads.json paged:\n{}", failures.join("\n"));
    }

    /// Reads on every relay: what the pool's reads end with, from where each relay's read was
    /// when the read went on, as the pool decides it (`read_of`).
    #[test]
    fn counts_only_the_relays_whose_read_ended_on_every_relay() {
        let vectors = spec("vectors/relay-reads.json");
        every_case("relay-reads.json onEveryRelay", vectors.list("onEveryRelay"), |case| {
            let relays = case.texts("relays");
            // Each relay sent one event, whatever its state: only the pages of one still reading
            // are kept besides the answers.
            let (read, outcome) = read_of(&relays);
            let kept: Vec<usize> = read.read.events().copied().collect();
            let expected_kept: Vec<usize> = relays
                .iter()
                .enumerate()
                .filter(|(_, state)| *state != "failed")
                .map(|(index, _)| index)
                .collect();
            if kept != expected_kept {
                return Err(format!("kept {kept:?}, not {expected_kept:?}"));
            }
            let actual = Json::object([
                ("answered", Json::Bool(outcome.answered)),
                ("complete", Json::Bool(outcome.complete)),
            ]);
            expect_same(&actual, case.field("expected"))
        });
    }
}

#[test]
fn onchain_tolerances_json() {
    let vectors = spec("vectors/onchain-tolerances.json");
    every_case("onchain-tolerances.json values", vectors.list("values"), |case| {
        expect_same(&Json::unsigned(tolerance_of(case.get("value"))), case.field("expected"))
    });
    every_case("onchain-tolerances.json accepted", vectors.list("accepted"), |case| {
        let tolerance = case.int("tolerance") as u64;
        expect_same(
            &text(&least_accepted(case.digits("sats"), tolerance).to_string()),
            case.field("expected"),
        )
    });
    every_case("onchain-tolerances.json due", vectors.list("due"), |case| {
        // With the merchant's acceptance that counts (absent: none).
        let accepted = case.get("merchantAccepted").map(|_| case.digits("merchantAccepted"));
        let due = due_onchain(
            case.digits("sats"),
            case.int("tolerance") as u64,
            case.digits("paidByRests"),
            accepted,
        );
        expect_same(&text(&due.to_string()), case.field("expected"))
    });
}

mod earlier_invoices_json {
    use super::*;

    const SATS: u64 = 49_000;

    fn price() -> DeclaredPrice {
        DeclaredPrice { minor: 49_000, digits: 0, currency: "SAT".to_owned() }
    }

    /// An event of a vector: its date and its id, nothing else read.
    fn event_of(value: &Json) -> Event {
        Event {
            id: value.text("id").to_owned(),
            pubkey: String::new(),
            created_at: value.int("createdAt"),
            kind: 30078.0,
            tags: Vec::new(),
            content: String::new(),
            sig: String::new(),
        }
    }

    fn declaration_of(d: &Json) -> OpenedDeclaration {
        let created_at = d.int("createdAt");
        OpenedDeclaration {
            event: event_of(&Json::object([
                ("createdAt", Json::integer(d.int("declaredAt"))),
                ("id", d.field("paymentHash").clone()),
            ])),
            invoice: d.text("invoice").to_owned(),
            decoded: Bolt11 {
                network: "bc".to_owned(),
                amount_msat: Some(SATS * 1000),
                timestamp: created_at,
                expiry_seconds: d.int("expiresAt") - created_at,
                payment_hash: d.text("paymentHash").to_owned(),
                description_hash: None,
            },
            sats: SATS,
            verify_url: "https://example.com/verify".to_owned(),
            price: price(),
            note: "order".to_owned(),
            declared_at: d.int("declaredAt"),
            rest: d.has("rest").then(|| crate::declaration::RestOf { address: String::new(), expires_at: 0 }),
        }
    }

    fn record_of(r: &Json) -> SaleLeaseRecord {
        let event = event_of(r.field("event"));
        let d = r.text("address").to_owned();
        if r.has("withdrawn") {
            return SaleLeaseRecord::Withdrawn { event, d };
        }
        if r.has("newer") {
            return SaleLeaseRecord::Newer { event, d };
        }
        let invoice = r.opt_text("invoice").map(str::to_owned);
        SaleLeaseRecord::Lease(Box::new(OpenedLease {
            event,
            d: d.clone(),
            terms: LeaseTerms {
                address: d,
                sats: SATS,
                verify_url: invoice.as_ref().map(|_| "https://example.com/verify".to_owned()),
                invoice,
                created_at: r.int("createdAt"),
                expires_at: r.int("expiresAt"),
                price: price(),
                note: "order".to_owned(),
                tolerance: 0,
                confirmed: r.get("confirmed").and_then(Json::as_bool),
            },
        }))
    }

    fn status_of(status: &Json) -> Result<PaymentStatus, Error> {
        if let Some(code) = status.opt_text("error") {
            return Err(match code {
                "network" => Error::network("No answer"),
                "invalid_invoice" => Error::invalid_invoice("Not this invoice"),
                other => panic!("no error {other}"),
            });
        }
        let received = status.opt_text("received").map_or(0, |received| received.parse().unwrap());
        Ok(match status.text("state") {
            "open" => PaymentStatus::Open { expires_at: 0, received, rest: None },
            "unconfirmed" => PaymentStatus::Unconfirmed { received, confirmations: 0, txids: Vec::new() },
            "paid" => PaymentStatus::Paid(Payment::Lightning { preimage: String::new() }),
            other => panic!("no state {other}"),
        })
    }

    #[test]
    fn checks_every_case() {
        let vectors = spec("vectors/earlier-invoices.json");
        let default_relays = vectors.int("relays") as usize;
        every_case("earlier-invoices.json", vectors.list("cases"), |case| {
            let list = case
                .get("relays")
                .and_then(Json::as_safe_integer)
                .map_or(default_relays, |relays| relays as usize);
            let now = case.int("now");
            let declarations: Vec<OpenedDeclaration> =
                case.list("declarations").iter().map(declaration_of).collect();
            let records: Vec<SaleLeaseRecord> = case.list("records").iter().map(record_of).collect();
            let declared: Vec<SaleDeclaration> =
                invoices_of("order", &declarations, &newest_records(records));
            let invoices: Vec<crate::model::DeclaredInvoice> =
                declared.iter().map(|declared| declared.invoice.clone()).collect();
            let expected = case.field("expected");
            let shown = Json::array(
                invoices
                    .iter()
                    .map(|invoice| {
                        Json::object([
                            ("paymentHash", Json::optional_str(invoice.payment_hash.as_deref())),
                            ("onchainAddress", Json::optional_str(invoice.onchain_address.as_deref())),
                            ("createdAt", Json::integer(invoice.created_at)),
                            ("declaredAt", Json::integer(invoice.declared_at)),
                        ])
                    })
                    .collect(),
            );
            expect_same(&shown, expected.field("invoices")).map_err(|why| format!("invoices: {why}"))?;
            let may_be_paid = may_still_be_paid(&invoices, now);
            let indices = |list: &[usize]| {
                Json::array(list.iter().map(|index| Json::unsigned(*index as u64)).collect())
            };
            expect_same(&indices(&may_be_paid), expected.field("mayBePaid"))
                .map_err(|why| format!("mayBePaid: {why}"))?;
            // Every one that may still be paid is checked, even alone.
            expect_same(&indices(&may_be_paid), expected.field("checked"))
                .map_err(|why| format!("checked: {why}"))?;
            if may_be_paid.is_empty() {
                if case.has("statuses") || !expected.field("outcome").is_null() {
                    return Err("an outcome without an invoice to check".to_owned());
                }
                return Ok(());
            }
            // What a read on every relay sent: each event's sentBy, all the relays when absent;
            // nothing when fewer than a majority answered it.
            let mut sent_by: HashMap<String, usize> = HashMap::new();
            for d in case.list("declarations") {
                sent_by.insert(
                    d.text("paymentHash").to_owned(),
                    d.get("sentBy").and_then(Json::as_safe_integer).map_or(list, |n| n as usize),
                );
            }
            for r in case.list("records") {
                sent_by.insert(
                    r.field("event").text("id").to_owned(),
                    r.get("sentBy").and_then(Json::as_safe_integer).map_or(list, |n| n as usize),
                );
            }
            let held: Option<Vec<bool>> = (!case.has("readFails")).then(|| {
                may_be_paid
                    .iter()
                    .map(|&index| {
                        sent_by.get(&declared[index].last_record().id).copied().unwrap_or(0) >= majority(list)
                    })
                    .collect()
            });
            let statuses: Vec<Result<PaymentStatus, Error>> =
                may_be_paid.iter().map(|&index| status_of(&case.list("statuses")[index])).collect();
            let outcome = match pending_outcome(&statuses, held.as_deref()) {
                Pending::Paid(paid) => {
                    Json::object([("orderPaid", Json::unsigned(may_be_paid[paid] as u64))])
                }
                Pending::Failed(failed) => {
                    Json::object([("error", text(statuses[failed].as_ref().unwrap_err().code().as_str()))])
                }
                Pending::Unread => Json::object([("error", text(ErrorCode::Network.as_str()))]),
                Pending::HandOut(index) => {
                    Json::object([("handOut", Json::unsigned(may_be_paid[index] as u64))])
                }
            };
            expect_same(&outcome, expected.field("outcome")).map_err(|why| format!("outcome: {why}"))
        });
    }
}
