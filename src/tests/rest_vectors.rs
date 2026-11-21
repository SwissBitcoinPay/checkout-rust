//! The crate against vectors/onchain-rests.json (SPEC.md §31, The rest of an underpayment): the
//! rest keys of an order's invoice, rest records and acceptance records as the pages read them,
//! declarations with `rest` opened as the sale, and when a check asks for an invoice of the rest.

use std::collections::HashSet;

use super::conformance::{every_case, expect_same};
use super::support::vectors::{Field, spec, text};
use crate::declaration::{open_declaration, registry_of};
use crate::derive::{acceptance_record_address, rest_keys, rest_record_address, sale_of};
use crate::json::Json;
use crate::nostr::event::valid_event;
use crate::nostr::record::Opened;
use crate::onchain::acceptance::open_acceptance_record;
use crate::onchain::rest::{
    RestInvoice, RestLinkTerms, RestReaderKeys, open_rest_record, rest_of, rest_to_ask, sendable,
};
use crate::text::to_hex;

fn vectors() -> Json {
    spec("vectors/onchain-rests.json")
}

#[test]
fn the_rest_keys_of_each_invoice() {
    let vectors = vectors();
    let key = vectors.secret("integrationKey");
    every_case("onchain-rests.json keys", vectors.list("keys"), |case| {
        let keys = rest_keys(&key, case.text("ref"), case.text("address"), case.int("expiresAt"));
        let records: Vec<Json> = case
            .list("records")
            .iter()
            .map(|record| {
                let hash = record.text("paymentHash");
                Json::object([
                    ("paymentHash", text(hash)),
                    ("address", text(&rest_record_address(&keys.key, hash))),
                ])
            })
            .collect();
        let actual = Json::object([
            ("restKey", text(&to_hex(keys.key.expose()))),
            ("restSecret", text(&to_hex(keys.secret_key.expose()))),
            ("restAuthor", text(&keys.author)),
            ("restEncryptionKey", text(&to_hex(keys.encryption_key.expose()))),
            ("records", Json::array(records)),
            ("acceptanceAddress", text(&acceptance_record_address(&keys.key))),
        ]);
        let expected = Json::object(
            ["restKey", "restSecret", "restAuthor", "restEncryptionKey", "records", "acceptanceAddress"]
                .map(|name| (name, case.field(name).clone())),
        );
        expect_same(&actual, &expected)
    });
}

/// The rest keys of the vectors' records: of ORD-1042's invoice at the first address.
fn reader_keys(vectors: &Json, expires_at: i64) -> RestReaderKeys {
    let keys = rest_keys(
        &vectors.secret("integrationKey"),
        "ORD-1042",
        vectors.list("keys")[0].text("address"),
        expires_at,
    );
    RestReaderKeys::of(&keys)
}

#[test]
fn opens_each_rest_record_as_the_page_does() {
    let vectors = vectors();
    let records = vectors.field("records");
    let link = records.field("link");
    let keys = reader_keys(&vectors, link.int("expiresAt"));
    assert_eq!(to_hex(keys.key.expose()), records.text("restKey"));
    assert_eq!(keys.author, records.text("restAuthor"));
    let reader = RestReaderKeys::new(records.secret("restKey"), records.text("restAuthor").to_owned());
    let terms = RestLinkTerms {
        sats: link.digits("sats"),
        created_at: link.int("createdAt"),
        expires_at: link.int("expiresAt"),
    };
    every_case("onchain-rests.json records", records.list("cases"), |case| {
        let actual = match open_rest_record(case.field("event"), &reader, &terms) {
            None => Json::Null,
            Some(Err(_)) => text("newer"),
            Some(Ok(invoice)) => Json::object([
                ("invoice", text(&invoice.bolt11)),
                ("paymentHash", text(&invoice.payment_hash)),
                ("verifyUrl", text(&invoice.verify_url)),
                ("sats", text(&invoice.sats.to_string())),
            ]),
        };
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn opens_each_acceptance_record_as_the_page_does() {
    let vectors = vectors();
    let acceptances = vectors.field("acceptances");
    let records = vectors.field("records");
    let keys = reader_keys(&vectors, records.field("link").int("expiresAt"));
    assert_eq!(to_hex(keys.key.expose()), acceptances.text("restKey"));
    assert_eq!(keys.author, acceptances.text("restAuthor"));
    let sats = acceptances.field("link").digits("sats");
    every_case("onchain-rests.json acceptances", acceptances.list("cases"), |case| {
        let actual = match open_acceptance_record(case.field("event"), &keys, sats) {
            None => Json::Null,
            Some(Opened::Newer { .. }) => text("newer"),
            Some(Opened::Valid { value, .. }) => Json::object([("received", text(&value.to_string()))]),
        };
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn opens_each_declaration_as_the_sale() {
    let vectors = vectors();
    let declarations = vectors.field("declarations");
    let sale = sale_of(
        &vectors.secret("integrationKey"),
        &registry_of(declarations.text("registryKey"), declarations.text("registryReader")),
        declarations.text("ref"),
    );
    every_case("onchain-rests.json declarations", declarations.list("cases"), |case| {
        let opened = valid_event(case.field("event")).and_then(|event| open_declaration(&event, &sale));
        let actual = match opened {
            None | Some(Opened::Newer { .. }) => Json::Null,
            Some(Opened::Valid { value, .. }) => Json::object([
                ("invoice", text(&value.invoice)),
                ("note", text(&value.note)),
                ("rest", value.rest.as_ref().map_or(Json::Null, crate::declaration::RestOf::to_json)),
            ]),
        };
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn asks_an_invoice_of_the_rest_when_the_specification_says() {
    let vectors = vectors();
    let address = vectors.list("keys")[0].text("address").to_owned();
    every_case("onchain-rests.json asking", vectors.list("asking"), |case| {
        let rests: Vec<Json> = case.list("rests").to_vec();
        let invoices: Vec<RestInvoice> = rests
            .iter()
            .map(|rest| RestInvoice {
                bolt11: rest.text("id").to_owned(),
                payment_hash: rest.text("paymentHash").to_owned(),
                verify_url: "https://breez.tips/verify".to_owned(),
                sats: rest.digits("sats"),
                created_at: rest.int("createdAt"),
                expires_at: rest.int("expiresAt"),
            })
            .collect();
        let paid: HashSet<String> = rests
            .iter()
            .zip(&invoices)
            .filter(|(rest, _)| rest.field("paid").as_bool().unwrap())
            .map(|(_, invoice)| invoice.payment_hash.clone())
            .collect();
        let sats = case.digits("sats");
        let expires_at = case.int("expiresAt");
        let now = case.int("now");
        let shown: Vec<&RestInvoice> = invoices.iter().collect();
        let rest = rest_of(sats, expires_at, &address, case.digits("received"), now, &shown, &paid);
        let lease = case.opt("lease").map(|lease| (lease.digits("sats"), lease.int("expiresAt")));
        let sendable_sats = case.field("sendable");
        let ask = rest_to_ask(rest.as_ref(), sats, expires_at, now, lease)
            .filter(|ask| sendable(ask.sats, (sendable_sats.digits("min"), sendable_sats.digits("max"))));
        let actual = Json::object([
            (
                "rest",
                rest.as_ref().map_or(Json::Null, |rest| {
                    Json::object([
                        ("sats", text(&rest.sats.to_string())),
                        ("invoice", Json::optional_str(rest.bolt11.as_deref())),
                    ])
                }),
            ),
            (
                "ask",
                ask.map_or(Json::Null, |ask| {
                    Json::object([
                        ("sats", text(&ask.sats.to_string())),
                        ("expirySeconds", Json::integer(ask.expiry_seconds)),
                    ])
                }),
            ),
        ]);
        expect_same(&actual, case.field("expected"))
    });
}
