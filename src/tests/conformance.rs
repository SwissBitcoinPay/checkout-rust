//! The crate against the conformance vectors every implementation shares (the pinned copy of the
//! specification, spec/vectors/): every file, every case.

use std::sync::Mutex;

use super::support::http::{Answer, FakeHttp};
use super::support::vectors::{Field, assert_same, error_json, same, spec, text};
use crate::channel::{Channel, parse_channel};
use crate::checkout::{
    CheckoutFragment, checkout_keys, checkout_origin_of, checkout_url, parse_checkout_fragment,
    parse_checkout_value, redirect_shown,
};
use crate::currencies::CURRENCY_DIGITS;
// The crate's public function (SPEC.md §4, Functions), as an application calls it.
use crate::currency_digits;
use crate::error::{Error, ErrorCode};
use crate::json::{self, Json};
use crate::key::parse_integration_key;
use crate::lightning::bolt11;
use crate::lnurl::{
    InvoiceAnswer, LightningInvoice, PayRequest, check_invoice, description_hash_of, fetch_pay_request,
    lightning_address_url, request_invoice, sendable_sats, verify_payment,
};
use crate::model::InvoiceToCheck;
use crate::nostr::event::{has_valid_id, serialized_event};
use crate::nostr::record::Newer;
use crate::onchain::payment::{InvoiceTerms, combine_parts};
use crate::order::{Order, check_order, check_ref, check_stored_invoice};
use crate::rates::{
    AskRate, Quote, Rate, RateSource, check_quote, fetch_first_rate, fiat_to_sats, format_decimal,
    number_text, parse_decimal, parse_fiat,
};
use crate::relays::is_relay_url;
use crate::runtime::Logger;
use crate::text::to_hex;
use crate::transport::BoxFuture;
use crate::urls::{parse_https_url, same_host};

/// Runs `check` on every case, and fails with every case that failed.
#[track_caller]
pub(crate) fn every_case(file: &str, cases: &[Json], mut check: impl FnMut(&Json) -> Result<(), String>) {
    assert!(!cases.is_empty(), "{file}: no case");
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| check(case).err().map(|why| format!("{}: {why}", case.name())))
        .collect();
    assert!(
        failures.is_empty(),
        "{file}: {} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// `Ok` when `actual` is `expected`, else why not.
pub(crate) fn expect_same(actual: &Json, expected: &Json) -> Result<(), String> {
    if same(actual, expected) {
        Ok(())
    } else {
        Err(format!("got {}, expected {}", json::stringify(actual), json::stringify(expected)))
    }
}

fn outcome(result: Result<Json, Error>) -> Json {
    result.unwrap_or_else(|error| error_json(&error))
}

#[test]
fn currencies_json_is_the_crate_table() {
    let table = spec("currencies.json");
    let currencies = table.field("currencies").as_object().unwrap();
    assert_eq!(currencies.len(), CURRENCY_DIGITS.len());
    for (code, digits) in currencies.iter() {
        let code = code.as_str().unwrap();
        assert_eq!(currency_digits(code).map(f64::from), digits.as_f64(), "{code}");
    }
    assert!(CURRENCY_DIGITS.windows(2).all(|pair| pair[0].0 < pair[1].0), "sorted, for its binary search");
}

#[test]
fn integration_keys_json() {
    let vectors = spec("vectors/integration-keys.json");
    let cases = vectors.list("cases");
    // The case of the pin's version: a byte order mark before the relays is kept (SPEC.md §6).
    assert!(
        cases.iter().any(|case| case.name() == "relays after a byte order mark (kept: U+FEFF is no host)")
    );
    every_case("integration-keys.json", cases, |case| {
        let actual = outcome(parse_integration_key(case.text("key")).map(|key| {
            Json::object([
                ("teamPublicKey", text(&key.team)),
                ("integrationKey", text(&to_hex(key.key.expose()))),
                ("relays", Json::array(key.relays.iter().map(|relay| text(relay)).collect())),
            ])
        }));
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn relay_urls_json() {
    let vectors = spec("vectors/relay-urls.json");
    every_case("relay-urls.json", vectors.list("cases"), |case| {
        let url = case.field("url").as_str().unwrap_or("");
        let valid = case.field("valid").as_bool().unwrap();
        if is_relay_url(url) == valid { Ok(()) } else { Err(format!("{url}: expected {valid}")) }
    });
}

#[test]
fn relay_addresses_beyond_relay_urls_json() {
    // A path holding a lone surrogate (SPEC.md §6) is no text: a JSON escape makes one, which a
    // relay list read from JSON refuses; a pair of them is a character.
    let lone = json::parse(r#"["wss://relay.example/\ud800"]"#).unwrap();
    assert_eq!(crate::relays::relay_list_of(&lone), None);
    let inside = json::parse(r#"["wss://relay.example/a\udc00b"]"#).unwrap();
    assert_eq!(crate::relays::relay_list_of(&inside), None);
    let pair = json::parse(r#"["wss://relay.example/😀"]"#).unwrap();
    assert_eq!(crate::relays::relay_list_of(&pair), Some(vec!["wss://relay.example/\u{1f600}".to_owned()]));
    assert!(is_relay_url("wss://relay.example/\u{1f600}"));
}

/// Event ids (SPEC.md §11): each event, as a relay would send it with the vector's id (and a
/// signature, not checked here), through the check of an event's id every read uses
/// (`has_valid_id`), its serialization through the one that check hashes (`serialized_event`).
#[test]
fn nostr_events_json() {
    let vectors = spec("vectors/nostr-events.json");
    every_case("nostr-events.json", vectors.list("cases"), |case| {
        let event = case.field("event");
        let mut members: Vec<(&str, Json)> =
            vec![("id", case.field("id").clone()), ("sig", text(&"00".repeat(64)))];
        for name in ["pubkey", "created_at", "kind", "tags", "content"] {
            members.push((name, event.field(name).clone()));
        }
        let sent = Json::object_of(members);
        let Some(checked) = has_valid_id(&sent) else {
            return Err(format!("its id is not {}", case.text("id")));
        };
        let serialized = serialized_event(
            &checked.pubkey,
            checked.created_at,
            checked.kind,
            &checked.tags,
            &checked.content,
        );
        if serialized != case.text("serialized") {
            return Err(format!("serialized {serialized}"));
        }
        // Another id is refused: the check compares.
        let mut other = case.text("id").to_owned();
        let last = if other.ends_with('0') { "1" } else { "0" };
        other.replace_range(63.., last);
        let forged = Json::object_of(
            sent.as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| {
                    let value = if name.as_str() == Some("id") { text(&other) } else { value.clone() };
                    (name.as_str().unwrap(), value)
                })
                .collect(),
        );
        if has_valid_id(&forged).is_some() {
            return Err("an id that is not its hash checks out".to_owned());
        }
        Ok(())
    });
}

#[test]
fn https_urls_json() {
    let vectors = spec("vectors/https-urls.json");
    every_case("https-urls.json urls", vectors.list("urls"), |case| {
        let actual = match parse_https_url(case.text("url")) {
            Some(url) => {
                Json::object([("host", text(&url.host)), ("port", Json::unsigned(u64::from(url.port)))])
            }
            None => Json::Null,
        };
        expect_same(&actual, case.field("expected"))
    });
    every_case("https-urls.json sameHost", vectors.list("sameHost"), |case| {
        let a = parse_https_url(case.text("a")).expect("an https URL");
        let b = parse_https_url(case.text("b")).expect("an https URL");
        expect_same(&Json::Bool(same_host(&a, &b)), case.field("expected"))
    });
    every_case("https-urls.json lightningAddresses", vectors.list("lightningAddresses"), |case| {
        let actual = Json::optional_str(lightning_address_url(case.text("address")).as_deref());
        expect_same(&actual, case.field("payUrl"))
    });
}

/// A decoded invoice as the vectors write it.
pub(crate) fn bolt11_json(decoded: &bolt11::Bolt11) -> Json {
    Json::object([
        ("network", text(&decoded.network)),
        ("amountMsat", decoded.amount_msat.map_or(Json::Null, |msat| text(&msat.to_string()))),
        ("timestamp", Json::integer(decoded.timestamp)),
        ("expirySeconds", Json::integer(decoded.expiry_seconds)),
        ("paymentHash", text(&decoded.payment_hash)),
        ("descriptionHash", Json::optional_str(decoded.description_hash.as_deref())),
    ])
}

#[test]
fn bolt11_json_vectors() {
    let vectors = spec("vectors/bolt11.json");
    every_case("bolt11.json", vectors.list("cases"), |case| {
        let actual = bolt11::decode(case.text("invoice")).map_or(Json::Null, |decoded| bolt11_json(&decoded));
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn fiat_json() {
    let vectors = spec("vectors/fiat.json");
    every_case("fiat.json", vectors.list("cases"), |case| {
        let input = case.field("input");
        let actual = outcome(parse_fiat(input.text("amount"), input.text("currency")).map(|fiat| {
            Json::object([
                ("amount", text(&fiat.amount)),
                ("minor", text(&fiat.minor.to_string())),
                ("digits", Json::unsigned(u64::from(fiat.digits))),
                ("currency", text(&fiat.currency)),
            ])
        }));
        expect_same(&actual, case.field("expected"))
    });
    // currency_digits, through the crate's public function (SPEC.md §4, Functions).
    every_case("fiat.json digits", vectors.list("digits"), |case| {
        let actual =
            currency_digits(case.text("code")).map_or(Json::Null, |digits| Json::unsigned(u64::from(digits)));
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn prices_json() {
    let vectors = spec("vectors/prices.json");
    let read = |price: &str| parse_decimal(price).map(|decimal| format_decimal(&decimal));
    every_case("prices.json text", vectors.list("text"), |case| {
        expect_same(&Json::optional_str(read(case.text("price")).as_deref()), case.field("expected"))
    });
    every_case("prices.json numbers", vectors.list("numbers"), |case| {
        let number = json::parse(case.text("json")).and_then(|value| value.as_f64()).expect("a JSON number");
        let actual = number_text(number).and_then(|text| read(&text));
        expect_same(&Json::optional_str(actual.as_deref()), case.field("expected"))
    });
}

#[test]
fn conversions_json() {
    let vectors = spec("vectors/conversions.json");
    every_case("conversions.json", vectors.list("cases"), |case| {
        let fiat = case.field("fiat");
        let sats = fiat_to_sats(fiat.text("amount"), fiat.text("currency"), case.text("price"))
            .map_err(|error| error.to_string())?;
        expect_same(&text(&sats.to_string()), case.field("sats"))
    });
}

#[test]
fn order_text_json_refs() {
    let vectors = spec("vectors/order-text.json");
    every_case("order-text.json refs", vectors.list("refs"), |case| {
        let reference = case.text("ref");
        let valid = case.field("valid").as_bool().unwrap();
        let actual = match check_ref(reference) {
            Ok(()) => text(reference),
            Err(error) => error_json(&error),
        };
        let expected = if valid {
            text(reference)
        } else {
            json::parse(r#"{"error":"invalid_order","param":"ref"}"#).unwrap()
        };
        expect_same(&actual, &expected)
    });
}

#[test]
fn order_text_json_notes() {
    let vectors = spec("vectors/order-text.json");
    every_case("order-text.json notes", vectors.list("notes"), |case| {
        let reference = case.text("ref");
        let expected = case.field("expected");
        let actual = match case.field("note") {
            Json::Null => outcome(
                check_order(&Order::sats(reference, 1), &[])
                    .map(|order| Json::object([("label", text(&order.label))])),
            ),
            note => match note.as_str() {
                Some(note) => outcome(
                    check_order(&Order::sats(reference, 1).note(note), &[])
                        .map(|order| Json::object([("label", text(&order.label))])),
                ),
                // A note holding a lone surrogate: no Rust string can hold one, so no order can
                // carry it (the type refuses what the vector refuses).
                None => json::parse(r#"{"error":"invalid_order","param":"note"}"#).unwrap(),
            },
        };
        expect_same(&actual, expected)
    });
}

#[tokio::test]
async fn order_text_json_comments() {
    let vectors = spec("vectors/order-text.json");
    let mut failures = Vec::new();
    let cases = vectors.list("comments");
    for case in cases {
        let http = FakeHttp::new(|_| {
            Some(Answer::json(&json::parse(r#"{"pr":"lnbc1","verify":"https://x.example/v"}"#).unwrap()))
        });
        let pay = PayRequest {
            callback: "https://x.example/cb".to_owned(),
            min_sendable_msat: 1000,
            max_sendable_msat: 1_000_000,
            metadata: "[]".to_owned(),
            comment_allowed: case.int("commentAllowed") as u64,
        };
        let label = case.text("label");
        request_invoice(&pay, 1, 60, Some(label), &http.http(1000)).await.unwrap();
        let sent = case.field("sent").as_bool().unwrap();
        let comment = http.calls()[0].param("comment");
        if comment.as_deref() != sent.then_some(label) {
            failures.push(format!("{}: comment {comment:?}", case.name()));
        }
    }
    assert!(failures.is_empty() && !cases.is_empty(), "{failures:?}");
}

#[test]
fn invoice_checks_json() {
    let vectors = spec("vectors/invoice-checks.json");
    let request = vectors.field("payRequest");
    let pay = PayRequest {
        callback: request.text("callback").to_owned(),
        min_sendable_msat: 1000,
        max_sendable_msat: 100_000_000,
        metadata: request.text("metadata").to_owned(),
        comment_allowed: 0,
    };
    every_case("invoice-checks.json", vectors.list("cases"), |case| {
        let answer = case.field("answer");
        let answer =
            InvoiceAnswer { pr: answer.text("pr").to_owned(), verify: answer.text("verify").to_owned() };
        let actual = match check_invoice(
            &answer,
            &pay,
            case.digits("sats"),
            case.int("durationSeconds"),
            case.int("now"),
        ) {
            Ok(_) => Json::object([("valid", Json::Bool(true))]),
            Err(check) => {
                let error = Error::from(check);
                assert_eq!(error.code(), ErrorCode::InvalidInvoice);
                Json::object([("error", text("invalid_invoice")), ("check", text(check.name()))])
            }
        };
        expect_same(&actual, case.field("expected"))
    });
}

/// The fake HTTP answer of a vector's `http`: `body` as JSON, or `bodyText` as it is.
pub(crate) fn http_answer(http: &Json) -> Answer {
    let status = http.int("status") as u16;
    match http.opt_text("bodyText") {
        Some(body) => Answer::text(status, body),
        None => Answer::status_json(status, http.field("body")),
    }
}

/// Pay requests (SPEC.md §16): each read from the answer of its pay URL, served as the vector
/// says, by the function every call reads them with (`fetch_pay_request`); its sendable sats and
/// the description hash of its invoices by those the invoice check uses (`sendable_sats`,
/// `description_hash_of`); or its error. A metadata holding a lone surrogate (a JSON escape) has
/// no UTF-8 to hash: `invalid_invoice`.
#[tokio::test(start_paused = true)]
async fn pay_requests_json() {
    let vectors = spec("vectors/pay-requests.json");
    let cases = vectors.list("cases");
    assert!(!cases.is_empty());
    let mut failures = Vec::new();
    for case in cases {
        let http = case.field("http");
        let status = http.int("status") as u16;
        let body = match http.get("bodyText") {
            Some(sent) => sent.as_str().unwrap().to_owned(),
            None => json::stringify(http.field("body")),
        };
        let fake = FakeHttp::new(move |_| Some(Answer { status, body: body.clone().into_bytes() }));
        let actual = match fetch_pay_request("shop@breez.tips", &fake.http(1000)).await {
            Ok(pay) => {
                let (min, max) = sendable_sats(&pay);
                Json::object([
                    ("callback", text(&pay.callback)),
                    (
                        "sendable",
                        Json::object([("min", text(&min.to_string())), ("max", text(&max.to_string()))]),
                    ),
                    ("commentAllowed", Json::unsigned(pay.comment_allowed)),
                    ("descriptionHash", text(&description_hash_of(&pay))),
                ])
            }
            Err(error) => error_json(&error),
        };
        if let Err(why) = expect_same(&actual, case.field("expected")) {
            failures.push(format!("{}: {why}", case.text("name")));
        }
        // Asked once, at the pay URL of the address.
        let calls = fake.calls();
        if calls.len() != 1 || calls[0].url != "https://breez.tips/.well-known/lnurlp/shop" {
            failures.push(format!(
                "{}: asked {:?}",
                case.text("name"),
                calls.iter().map(|call| &call.url).collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "pay-requests.json: {} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn payments_json() {
    let vectors = spec("vectors/payments.json");
    let invoice = vectors.field("invoice");
    let lightning = LightningInvoice {
        bolt11: invoice.text("bolt11").to_owned(),
        payment_hash: invoice.text("paymentHash").to_owned(),
        verify_url: invoice.text("verifyUrl").to_owned(),
        expires_at: invoice.int("expiresAt"),
    };
    let mut failures = Vec::new();
    let cases = vectors.list("cases");
    for case in cases {
        let answer = http_answer(case.field("http"));
        let http = FakeHttp::new(move |_| Some(answer.clone()));
        let now = case.int("now");
        // An invoice without an address: its status is its Lightning part's.
        let actual = match verify_payment(&lightning, &http.http(1000), now).await {
            Ok(part) => {
                let terms = InvoiceTerms { sats: 1, expires_at: lightning.expires_at, address: None };
                outcome(
                    combine_parts(terms, now, Some(&Ok(part)), None, None).map(|status| status.to_value()),
                )
            }
            Err(error) => Json::object([("error", text(error.code().as_str()))]),
        };
        if let Err(why) = expect_same(&actual, case.field("expected")) {
            failures.push(format!("{}: {why}", case.name()));
        }
    }
    assert!(failures.is_empty() && !cases.is_empty(), "payments.json:\n{}", failures.join("\n"));
}

/// A stored invoice checked as `get_status` checks it before asking anything (SPEC.md §22): read
/// from its JSON as a shop stored it, then its rules. Through serde (`serde_json`) as well: the
/// same verdict.
#[test]
fn payments_json_stored_invoices() {
    let vectors = spec("vectors/payments.json");
    every_case("payments.json stored", vectors.list("stored"), |case| {
        let text = json::stringify(case.field("invoice"));
        let checked = InvoiceToCheck::from_json(&text).and_then(|invoice| check_stored_invoice(&invoice));
        let actual = match &checked {
            Ok(_) => Json::object([("valid", Json::Bool(true))]),
            Err(error) => error_json(error),
        };
        expect_same(&actual, case.field("expected"))?;
        let through_serde = serde_json::from_str::<InvoiceToCheck>(&text)
            .map_err(|_| ())
            .and_then(|invoice| check_stored_invoice(&invoice).map_err(|_| ()));
        if through_serde.is_ok() != checked.is_ok() {
            return Err(format!(
                "through serde: {}",
                if through_serde.is_ok() { "valid" } else { "refused" }
            ));
        }
        Ok(())
    });
}

/// A source's answer of each HTTP status but 2xx (SPEC.md §26, §15: a redirect is no answer):
/// `network` or `rate`, whatever the source.
/// The data model with serde (SPEC.md §3): every type an integrator holds writes, through
/// `serde_json`, the JSON its own `to_json` writes, and reads it back as itself; each status as
/// itself, and in what an integrator stores it in (a list, a member of its own). `Payment`, what a
/// paid status holds, has no JSON of its own and no serde: a status writes it.
#[test]
fn serde_writes_each_type_as_spec_3_does_and_reads_it_back() {
    use crate::model::{
        DeclaredInvoice, Fiat, Invoice, InvoiceToCheck, Merchant, Payment, PaymentStatus, RateInfo, Rest,
    };

    #[track_caller]
    fn same<T>(value: &T, own: &str, what: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let written = serde_json::to_value(value).unwrap();
        assert_eq!(written, serde_json::from_str::<serde_json::Value>(own).unwrap(), "{what}");
        assert_eq!(&serde_json::from_value::<T>(written).unwrap(), value, "{what}: read back");
    }

    let fiat = Fiat { amount: "24.50".into(), currency: "CHF".into(), minor: 2450, digits: 2 };
    let rate = RateInfo {
        source: "coingecko".into(),
        currency: "CHF".into(),
        price: "69012.5".into(),
        fetched_at: 1_791_378_000,
        time: Some(1_791_377_990),
    };
    let address = super::support::chain::deposit_address(1);
    let invoice = Invoice {
        reference: "R-1".into(),
        bolt11: Some("lnbc1".into()),
        payment_hash: Some("ab".repeat(32)),
        verify_url: Some("https://breez.tips/lnurlp/verify/ab".into()),
        onchain_address: Some(address.clone()),
        payment_uri: format!("bitcoin:{address}?amount=0.00049&lightning=lnbc1"),
        sats: 49_000,
        fiat: Some(fiat.clone()),
        rate: Some(rate.clone()),
        note: "Order 1".into(),
        created_at: 1_791_378_000,
        expires_at: 1_791_378_900,
        checkout_url: Some("https://pay.example/pay#c.x".into()),
        redirect_url: Some("https://shop.example/thanks".into()),
    };
    let declared = DeclaredInvoice {
        reference: "R-2".into(),
        bolt11: None,
        payment_hash: None,
        verify_url: None,
        onchain_address: Some(address.clone()),
        payment_uri: format!("bitcoin:{address}?amount=0.02"),
        sats: 2_000_000,
        fiat: None,
        note: "R-2".into(),
        created_at: 1_791_378_000,
        expires_at: 1_791_378_900,
        declared_at: 1_791_378_001,
    };
    let rest = Rest {
        sats: 29_000,
        bolt11: Some("lnbc290u1".into()),
        payment_uri: Some("lightning:lnbc290u1".into()),
    };
    let merchant = Merchant {
        business_name: "Sunrise Bakery".into(),
        min_sats: 1,
        max_sats: 5_000_000,
        onchain_addresses: 3,
    };
    same(&fiat, &fiat.to_json(), "Fiat");
    same(&rate, &rate.to_json(), "RateInfo");
    same(&invoice, &invoice.to_json(), "Invoice");
    same(&declared, &declared.to_json(), "DeclaredInvoice");
    let to_check = InvoiceToCheck::from(&invoice);
    same(&to_check, &to_check.to_json(), "InvoiceToCheck");
    same(&rest, &rest.to_json(), "Rest");
    same(&merchant, &merchant.to_json(), "Merchant");
    let statuses = [
        PaymentStatus::Open { expires_at: 1_791_378_900, received: 0, rest: None },
        PaymentStatus::Open { expires_at: 1_791_378_900, received: 20_000, rest: Some(rest.clone()) },
        PaymentStatus::Unconfirmed { received: 49_000, confirmations: 1, txids: vec!["cd".repeat(32)] },
        PaymentStatus::Paid(Payment::Lightning { preimage: "ef".repeat(32) }),
        PaymentStatus::Paid(Payment::Onchain { received: 49_000, txids: vec!["cd".repeat(32)] }),
        PaymentStatus::Paid(Payment::Mixed {
            received: 49_000,
            txids: vec!["cd".repeat(32)],
            preimages: vec!["ef".repeat(32)],
        }),
        PaymentStatus::Expired { received: 0 },
        PaymentStatus::Expired { received: 20_000 },
    ];
    for status in &statuses {
        same(status, &status.to_json(), &format!("PaymentStatus {}", status.to_json()));
    }
    // In what an integrator stores them in: a pair, the members of a map.
    let pair = (invoice.clone(), statuses.to_vec());
    let own = format!(
        "[{},[{}]]",
        invoice.to_json(),
        statuses.iter().map(PaymentStatus::to_json).collect::<Vec<_>>().join(",")
    );
    same(&pair, &own, "an Invoice and its statuses");
    let by_order: std::collections::BTreeMap<String, PaymentStatus> =
        [("R-1".to_owned(), statuses[3].clone()), ("R-2".to_owned(), statuses[1].clone())].into();
    let own = format!("{{\"R-1\":{},\"R-2\":{}}}", statuses[3].to_json(), statuses[1].to_json());
    same(&by_order, &own, "statuses by order");
    // A payment alone: never a JSON of its own (a compile error, never a wrong JSON).
    assert!(!super::support::serializes!(Payment));
    assert!(super::support::serializes!(PaymentStatus));
    same(&vec![declared.clone()], &format!("[{}]", declared.to_json()), "find_invoices' list");
}

#[tokio::test(start_paused = true)]
async fn rate_sources_json_statuses() {
    let vectors = spec("vectors/rate-sources.json");
    let statuses = vectors.list("statuses");
    assert!(!statuses.is_empty());
    let mut failures = Vec::new();
    for case in statuses {
        let status = case.int("status") as u16;
        for source in [
            RateSource::Coingecko,
            RateSource::Mempool,
            RateSource::Opennode,
            RateSource::Coinbase,
            RateSource::Kraken,
        ] {
            let http = FakeHttp::new(move |_| Some(Answer::status_json(status, &Json::object([]))));
            let client = http.http(1000);
            let context = crate::rates::RateContext { http: &client, coingecko_api_key: None };
            let actual = match crate::rates::fetch_rate(&source, "CHF", &context, 1_791_378_000).await {
                Ok(_) => Json::object([("ok", Json::Bool(true))]),
                Err(error) => error_json(&error),
            };
            if let Err(why) = expect_same(&actual, case.field("expected")) {
                failures.push(format!("HTTP {status}, {}: {why}", source.name()));
            }
        }
    }
    assert!(failures.is_empty(), "rate-sources.json statuses:\n{}", failures.join("\n"));
}

#[test]
fn rate_sources_json_default_list() {
    let vectors = spec("vectors/rate-sources.json");
    let names: Vec<&str> = RateSource::defaults().iter().map(RateSource::name).collect();
    assert_same(
        &Json::array(names.iter().map(|name| text(name)).collect()),
        vectors.field("default"),
        "the default list",
    );
}

/// The sources a vector's `rateSource` names, as the crate takes them: a name (`FromStr`), or a
/// list of names; anything else cannot be a `RateSource` (an empty string, a number, `null`, an
/// object, a list inside a list).
fn sources_of(value: &Json) -> Option<Vec<RateSource>> {
    match value {
        Json::String(name) => Some(vec![name.as_str()?.parse().ok()?]),
        Json::Array(items) => items.as_slice().iter().map(|item| item.as_str()?.parse().ok()).collect(),
        _ => None,
    }
}

#[test]
fn rate_sources_json_values() {
    let vectors = spec("vectors/rate-sources.json");
    every_case("rate-sources.json values", vectors.list("values"), |case| {
        let expected = case.field("expected");
        let given = case.get("rateSource");
        // The client's: the default list when absent.
        let sources = match given {
            None => Some(RateSource::defaults()),
            Some(value) => sources_of(value).and_then(crate::rates::rate_source_list),
        };
        let client = match &sources {
            Some(sources) => Json::object([(
                "sources",
                Json::array(sources.iter().map(|source| text(source.name())).collect()),
            )]),
            None => error_json(&Error::invalid_option("rateSource", "invalid")),
        };
        expect_same(&client, expected)?;
        // An order: invalid_order, and the client's sources when it has none.
        let order = Order::fiat("A-1", "1", "CHF");
        let order = match given {
            None => Some(order),
            Some(value) => sources_of(value).map(|sources| order.rate_sources(sources)),
        };
        let checked = match order {
            Some(order) => {
                check_order(&order, &[RateSource::Kraken]).map(|order| order.rate_sources.unwrap())
            }
            // Not representable as a list of sources: what an order refuses.
            None => Err(Error::invalid_order("rateSource", "invalid")),
        };
        match (checked, expected.get("error")) {
            (Err(error), Some(_))
                if error.code() == ErrorCode::InvalidOrder && error.param() == Some("rateSource") =>
            {
                Ok(())
            }
            (Ok(sources), None) => {
                let names: Vec<&str> = sources.iter().map(RateSource::name).collect();
                let expected: Vec<String> =
                    if given.is_none() { vec!["kraken".to_owned()] } else { expected.texts("sources") };
                if names == expected { Ok(()) } else { Err(format!("the order's sources {names:?}")) }
            }
            (other, _) => Err(format!("the order: {other:?}")),
        }
    });
}

/// What the vector's sources answer: an error, or a price checked as a source's.
struct VectorSources {
    answers: Json,
    asked: Mutex<Vec<String>>,
}

impl AskRate for VectorSources {
    fn ask<'a>(
        &'a self,
        source: &'a RateSource,
        currency: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Rate, Error>> {
        let name = source.name();
        self.asked.lock().unwrap().push(name.to_owned());
        let answer = self.answers.field(name).clone();
        Box::pin(async move {
            match answer.as_str() {
                Some("network") => Err(Error::network(format!("{name} is down"))),
                Some("rate") => Err(Error::rate(format!("{name} gave no price"))),
                Some("unsupported_currency") => Err(Error::unsupported_currency_of(currency, name)),
                _ => {
                    // The price, checked as a source's (SPEC.md §25).
                    let quote = Quote {
                        price: answer.text("price").to_owned(),
                        time: answer.opt("time").and_then(Json::as_f64),
                    };
                    check_quote(name, currency, quote, now)
                }
            }
        })
    }
}

#[derive(Default)]
struct Warnings(Mutex<Vec<String>>);

impl Logger for Warnings {
    fn warn(&self, message: &str) {
        self.0.lock().unwrap().push(message.to_owned());
    }
}

#[tokio::test]
async fn rate_sources_json_lists() {
    let vectors = spec("vectors/rate-sources.json");
    let lists = vectors.field("lists");
    let currency = lists.text("currency");
    let now = lists.int("now");
    let mut failures = Vec::new();
    let cases = lists.list("cases");
    for case in cases {
        let sources: Vec<RateSource> =
            case.texts("sources").iter().map(|name| name.parse().unwrap()).collect();
        let ask = VectorSources { answers: case.field("answers").clone(), asked: Mutex::new(Vec::new()) };
        let warnings = Warnings::default();
        let result = fetch_first_rate(&sources, currency, &|| now, &warnings, &ask).await;
        let asked: Vec<Json> = ask.asked.lock().unwrap().iter().map(|name| text(name)).collect();
        let actual = match &result {
            Ok(rate) => Json::object([
                ("source", text(&rate.info.source)),
                ("price", text(&rate.info.price)),
                ("asked", Json::array(asked.clone())),
            ]),
            Err(error) => {
                Json::object([("error", text(error.code().as_str())), ("asked", Json::array(asked.clone()))])
            }
        };
        if let Err(why) = expect_same(&actual, case.field("expected")) {
            failures.push(format!("{}: {why}", case.name()));
        }
        // Each failure the next source replaces is logged, never the last one.
        if warnings.0.lock().unwrap().len() != asked.len() - 1 {
            failures.push(format!(
                "{}: {} warnings for {} sources asked",
                case.name(),
                warnings.0.lock().unwrap().len(),
                asked.len()
            ));
        }
    }
    assert!(failures.is_empty() && !cases.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn redirect_urls_json() {
    let vectors = spec("vectors/redirect-urls.json");
    every_case("redirect-urls.json", vectors.list("cases"), |case| {
        let url = case.text("url");
        let expected = case.field("expected");
        let order = Order::sats("A-1", 1).checkout(true).redirect_url(url);
        match (check_order(&order, &[]), expected.get("error")) {
            (Err(error), Some(_)) => {
                expect_same(&error_json(&error), expected)?;
                if redirect_shown(url).is_some() { Err("shown".to_owned()) } else { Ok(()) }
            }
            (Ok(checked), None) => {
                if checked.redirect_url.as_deref() != Some(url) {
                    return Err("not kept".to_owned());
                }
                expect_same(
                    &Json::object([("shown", Json::optional_str(redirect_shown(url).as_deref()))]),
                    expected,
                )
            }
            (other, _) => Err(format!("{other:?}")),
        }
    });
}

#[test]
fn checkout_links_json_origins() {
    let vectors = spec("vectors/checkout-links.json");
    every_case("checkout-links.json origins", vectors.list("origins"), |case| {
        let checkout = case.field("checkout");
        let expected = case.field("expected");
        expect_same(&Json::optional_str(checkout_origin_of(Some(checkout)).as_deref()), expected)?;
        // Whatever it holds, the channel stays valid.
        let mut channel = json::parse(&format!(
            r#"{{"version":1,"status":"active","role":"integration","profile":{{"businessName":"Sunrise Bakery","lightningAddress":"a@breez.tips"}},"registryKey":"{}","registryReader":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","updatedAt":100}}"#,
            "11".repeat(32)
        ))
        .unwrap();
        if let Json::Object(members) = &mut channel {
            let mut list: Vec<(json::JsonString, Json)> =
                members.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
            list.push((json::JsonString::Text("checkout".to_owned()), checkout.clone()));
            channel = Json::Object(json::JsonObject::new(list));
        }
        match parse_channel(&channel, 100) {
            Ok(Some(Channel::Active(active))) => {
                expect_same(&Json::optional_str(active.checkout_origin.as_deref()), expected)
            }
            other => Err(format!("the channel: {other:?}")),
        }
    });
}

#[test]
fn checkout_links_json_derivations_and_urls() {
    let vectors = spec("vectors/checkout-links.json");
    every_case("checkout-links.json derivations", vectors.list("derivations"), |case| {
        let keys = checkout_keys(&case.secret("linkKey"));
        let actual = Json::object([
            ("address", text(&keys.address)),
            ("encryptionKey", text(&to_hex(keys.encryption_key.expose()))),
        ]);
        expect_same(
            &actual,
            &Json::object([
                ("address", case.field("address").clone()),
                ("encryptionKey", case.field("encryptionKey").clone()),
            ]),
        )
    });
    every_case("checkout-links.json urls", vectors.list("urls"), |case| {
        let url = checkout_url(
            case.text("origin"),
            case.text("author"),
            &case.secret("linkKey"),
            &case.texts("relays"),
        );
        expect_same(&text(&url), case.field("url"))
    });
}

#[test]
fn checkout_links_json_fragments() {
    let vectors = spec("vectors/checkout-links.json");
    every_case("checkout-links.json fragments", vectors.list("fragments"), |case| {
        let actual = match parse_checkout_fragment(case.text("fragment")) {
            CheckoutFragment::Link { author, link_key, relays } => Json::object([
                ("author", text(&author)),
                ("linkKey", text(&to_hex(link_key.expose()))),
                ("relays", Json::array(relays.iter().map(|relay| text(relay)).collect())),
            ]),
            CheckoutFragment::Newer => text("newer"),
            CheckoutFragment::Invalid => text("invalid"),
            CheckoutFragment::Other => text("other"),
        };
        expect_same(&actual, case.field("expected"))
    });
}

#[test]
fn checkout_links_json_records() {
    let vectors = spec("vectors/checkout-links.json");
    every_case("checkout-links.json records", vectors.list("records"), |case| {
        let actual = match parse_checkout_value(case.field("value")) {
            Err(Newer) => text("newer"),
            Ok(None) => text("invalid"),
            Ok(Some(record)) => Json::object([
                ("sats", text(&record.sats.to_string())),
                ("paymentHash", Json::optional_str(record.payment_hash.as_deref())),
                ("onchainAddress", Json::optional_str(record.onchain_address.as_deref())),
                ("expiresAt", Json::integer(record.expires_at)),
                ("redirect", Json::optional_str(record.redirect_shown.as_deref())),
                (
                    "rest",
                    record.rest.as_ref().map_or(Json::Null, |rest| {
                        Json::object([("author", text(&rest.author)), ("key", text(&rest.key))])
                    }),
                ),
            ]),
        };
        expect_same(&actual, case.field("expected"))
    });
}
