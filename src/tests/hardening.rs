//! What the crate refuses or bounds beyond the conformance vectors: options, HTTP answers, a custom
//! rate source that fails, a channel whose reading key is off the curve, the fan-out of payment
//! checks, what a relay sends, the witnesses a read keeps.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::support::chain::{deposit_address, txid};
use super::support::http::{Answer, FakeHttp};
use super::support::j;
use super::support::merchant::TestMerchant;
use super::support::relay::{RelayBehaviour, pool};
use crate::client::{Client, WaitOptions};
use crate::derive::channel_keys;
use crate::error::{Error, ErrorCode};
use crate::http::{HttpBody, HttpClient, HttpRequest, HttpResponse};
use crate::json::{self, Json, JsonObject, JsonString};
use crate::nostr::event::{Event, EventTemplate, sign_event};
use crate::nostr::record::records_that_open;
use crate::nostr::relay::{Filter, Keep, ReadOf};
use crate::onchain::witness::{
    OrderWitnesses, SeenKeys, Witness, address_tag, order_witnesses_of, seen_of, witness_address,
    witness_event,
};
use crate::order::Order;
use crate::rates::{CustomPrice, CustomRateError, CustomRateSource, RateContext, RateSource, fetch_rate};
use crate::runtime::OsRandom;
use crate::secret::Secret;
use crate::transport::{BoxFuture, TransportError};

fn merchant() -> TestMerchant {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    merchant
}

fn client(merchant: &TestMerchant) -> Client {
    merchant.client().build().unwrap()
}

mod options {
    use super::*;

    #[test]
    fn refuses_an_invalid_option_as_invalid_option_naming_it() {
        // The options of another type (a key that is no text, a clock that is no clock…): the
        // types refuse them.
        let merchant = TestMerchant::new();
        assert_eq!("bitstamp".parse::<RateSource>().unwrap_err().param(), Some("rateSource"));
        let cases: Vec<(&str, crate::client::ClientBuilder)> = vec![
            // 1 or more visible ASCII characters (SPEC.md §4): empty is invalid, not absent.
            ("coingeckoApiKey", merchant.client().coingecko_api_key("")),
            ("coingeckoApiKey", merchant.client().coingecko_api_key("CG-key with a space")),
            ("coingeckoApiKey", merchant.client().coingecko_api_key("CG-clé")),
            ("relayTimeoutMs", merchant.client().relay_timeout_ms(3_000_000_000)),
            ("relayTimeoutMs", merchant.client().relay_timeout_ms(0)),
            ("relayTimeoutMs", merchant.client().relay_timeout_ms(99)),
            ("httpTimeoutMs", merchant.client().http_timeout_ms(60_001)),
            ("httpTimeoutMs", merchant.client().http_timeout_ms(1)),
            ("rateSource", merchant.client().rate_sources([])),
        ];
        for (param, builder) in cases {
            let error = builder.build().unwrap_err();
            assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOption, Some(param)), "{error}");
            assert!(!error.retryable());
        }
        // The edges.
        merchant
            .client()
            .relay_timeout_ms(100)
            .http_timeout_ms(60_000)
            .coingecko_api_key("CG-x")
            .build()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_wait_for_payment_interval() {
        let merchant = merchant();
        let invoice = client(&merchant).create_invoice(&Order::sats("O-1", 1)).await.unwrap();
        for interval in [100, 249, 60_001, 3_000_000_000] {
            let error = client(&merchant)
                .wait_for_payment(&invoice, WaitOptions::default().interval_ms(interval))
                .await
                .unwrap_err();
            assert_eq!(
                (error.code(), error.param()),
                (ErrorCode::InvalidOption, Some("intervalMs")),
                "{interval}"
            );
        }
    }
}

mod notes {
    use super::*;

    // A note holding a lone surrogate, which JavaScript can hold: no Rust string holds one.

    #[tokio::test(start_paused = true)]
    async fn counts_a_note_in_code_points_100_emojis_fit() {
        let merchant = merchant();
        let note = "😀".repeat(100);
        let invoice =
            client(&merchant).create_invoice(&Order::sats("N-2", 1).note(note.clone())).await.unwrap();
        assert_eq!(invoice.note, note);
        // 400 bytes in UTF-8: more than breez.tips's 255, so not sent as the comment.
        assert_eq!(merchant.invoices()[0].comment, None);
        let error = client(&merchant)
            .create_invoice(&Order::sats("N-3", 1).note("😀".repeat(101)))
            .await
            .unwrap_err();
        assert_eq!(error.param(), Some("note"));
    }
}

mod http_answers {
    use super::*;

    /// An injected client that answers every request with what `answer` gives.
    struct Answering<F>(F);

    impl<F: Fn() -> HttpResponse + Send + Sync> HttpClient for Answering<F> {
        fn get(&self, _: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
            let response = (self.0)();
            Box::pin(async move { Ok(response) })
        }
    }

    fn http(client: impl HttpClient + 'static) -> crate::http::Http {
        crate::http::Http { client: Arc::new(client), timeout: Duration::from_millis(1000) }
    }

    #[tokio::test(start_paused = true)]
    async fn follows_no_redirect_an_injected_client_hands_over() {
        let http = http(Answering(|| HttpResponse::from_bytes(302, "{}")));
        let error = http.get_json("https://breez.tips/x", &[]).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
        assert!(error.message().contains("redirect (HTTP 302)"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn drops_a_body_larger_than_1_mib() {
        let big = format!("\"{}\"", "a".repeat(1 << 20));
        let http = FakeHttp::new(move |_| Some(Answer::text(200, &big))).http(1000);
        let error = http.get_json("https://breez.tips/x", &[]).await.unwrap_err();
        assert!(error.message().contains("more than 1048576 bytes"), "{error}");
        let small = format!("\"{}\"", "a".repeat(1000));
        let http = FakeHttp::new(move |_| Some(Answer::text(200, &small))).http(1000);
        assert_eq!(
            http.get_json("https://breez.tips/x", &[]).await.unwrap().body,
            Some(Json::from("a".repeat(1000)))
        );
    }

    /// A body that comes in chunks.
    struct Chunks(VecDeque<Vec<u8>>);

    impl HttpBody for Chunks {
        fn chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
            let chunk = self.0.pop_front();
            Box::pin(async move { Ok(chunk) })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reads_a_body_in_chunks_bounded_as_well() {
        let chunked = |text: String| {
            move || {
                let bytes = text.as_bytes();
                HttpResponse::new(200, Chunks(VecDeque::from([bytes[..5].to_vec(), bytes[5..].to_vec()])))
            }
        };
        let answer = http(Answering(chunked(r#"{"tag":"payRequest"}"#.to_owned())))
            .get_json("https://breez.tips/x", &[])
            .await
            .unwrap();
        assert_eq!((answer.status, answer.body), (200, Some(j!({ "tag": "payRequest" }))));
        let error = http(Answering(chunked(format!("\"{}\"", "a".repeat(1 << 20)))))
            .get_json("https://breez.tips/x", &[])
            .await
            .unwrap_err();
        assert!(error.message().contains("more than 1048576 bytes"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn reads_a_body_that_is_not_utf8_as_no_json() {
        let answer = http(Answering(|| HttpResponse::from_bytes(200, vec![0x22, 0xff, 0x22])))
            .get_json("https://breez.tips/x", &[])
            .await
            .unwrap();
        assert_eq!(answer.body, None);
    }

    #[tokio::test(start_paused = true)]
    async fn reads_a_body_after_one_byte_order_mark_and_no_second() {
        let answer = http(Answering(|| HttpResponse::from_bytes(200, b"\xef\xbb\xbf{\"a\":1}".to_vec())))
            .get_json("https://breez.tips/x", &[])
            .await
            .unwrap();
        assert_eq!(answer.body, Some(j!({ "a": 1 })));
        let answer =
            http(Answering(|| HttpResponse::from_bytes(200, b"\xef\xbb\xbf\xef\xbb\xbf{}".to_vec())))
                .get_json("https://breez.tips/x", &[])
                .await
                .unwrap();
        assert_eq!(answer.body, None);
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_the_whole_request_by_its_timeout() {
        /// A body that never ends.
        struct Endless;
        impl HttpBody for Endless {
            fn chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
                Box::pin(std::future::pending())
            }
        }
        let error = http(Answering(|| HttpResponse::new(200, Endless)))
            .get_json("https://breez.tips/x", &[])
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
    }
}

mod a_custom_rate_source {
    use super::*;

    struct Fails(fn() -> CustomRateError);

    impl CustomRateSource for Fails {
        fn price<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>> {
            let error = (self.0)();
            Box::pin(async move { Err(error) })
        }
    }

    async fn rate_of(source: RateSource, currency: &str) -> Result<crate::rates::Rate, Error> {
        let http = FakeHttp::new(|_| Some(Answer::status_json(404, &j!({})))).http(1000);
        fetch_rate(&source, currency, &RateContext { http: &http, coingecko_api_key: None }, 1_791_378_000)
            .await
    }

    #[derive(Debug)]
    struct Broken;

    impl std::fmt::Display for Broken {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("fetch failed")
        }
    }

    impl std::error::Error for Broken {}

    #[tokio::test(start_paused = true)]
    async fn turns_its_own_errors_into_a_rate_error_with_the_cause() {
        let error = rate_of(RateSource::custom(Fails(|| Box::new(Broken))), "CHF").await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Rate);
        let cause = std::error::Error::source(&error).expect("the cause");
        assert!(cause.downcast_ref::<Broken>().is_some(), "{cause:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_the_crate_errors_it_raises() {
        let error =
            rate_of(RateSource::custom(Fails(|| Box::new(Error::unsupported_currency("XOF")))), "XOF")
                .await
                .unwrap_err();
        assert_eq!(
            (error.code(), error.message()),
            (ErrorCode::UnsupportedCurrency, Error::unsupported_currency("XOF").message())
        );
        let error =
            rate_of(RateSource::custom(Fails(|| Box::new(Error::network("down")))), "XOF").await.unwrap_err();
        assert_eq!((error.code(), error.message()), (ErrorCode::Network, "down"));
    }
}

#[tokio::test(start_paused = true)]
async fn the_channel_is_ignored_when_its_reading_key_is_off_the_curve() {
    let merchant = merchant();
    merchant.publish_channel(&merchant.channel_value(200, j!({ "registryReader": "00".repeat(32) })), 200);
    // The newest valid copy stands: the one of 100.
    assert_eq!(client(&merchant).merchant().await.unwrap().business_name, "Sunrise Bakery");
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({ "registryReader": "00".repeat(32) })), 100);
    assert_eq!(client(&merchant).merchant().await.unwrap_err().code(), ErrorCode::ChannelNotFound);
}

/// The merchant's HTTP, each payment check 20 ms long, counting the checks made at once.
struct Counting {
    inner: FakeHttp,
    running: Arc<AtomicUsize>,
    most: Arc<AtomicUsize>,
}

impl HttpClient for Counting {
    fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let verify = request.url.contains("/verify/");
            if verify {
                let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
                self.most.fetch_max(running, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let response = self.inner.get(request).await;
            if verify {
                self.running.fetch_sub(1, Ordering::SeqCst);
            }
            response
        })
    }
}

#[tokio::test(start_paused = true)]
async fn the_earlier_invoices_of_an_order_are_checked_four_at_a_time() {
    let merchant = merchant();
    let client = client(&merchant);
    for _ in 0..6 {
        client.create_invoice(&Order::sats("E-1", 1).duration_seconds(60)).await.unwrap();
        merchant.advance(60 + 120);
    }
    let most = Arc::new(AtomicUsize::new(0));
    let counting =
        Counting { inner: merchant.http.clone(), running: Arc::new(AtomicUsize::new(0)), most: most.clone() };
    merchant
        .client()
        .http_client(counting)
        .build()
        .unwrap()
        .create_invoice(&Order::sats("E-1", 1))
        .await
        .unwrap();
    assert_eq!(most.load(Ordering::SeqCst), 4);
    assert_eq!(merchant.invoices().len(), 7);
}

#[tokio::test(start_paused = true)]
async fn relays_keep_of_what_a_relay_sends_only_what_the_read_keeps_and_still_page_through_the_rest() {
    let merchant = merchant();
    let relay = merchant.net.get(&merchant.key_relays[0]);
    let filler = "x".repeat(60_000);
    for i in 0..300 {
        relay.store(Json::object([
            ("id", Json::from(format!("{i:064x}"))),
            ("pubkey", Json::from("ab".repeat(32))),
            ("created_at", Json::integer(1_000_000 - i)),
            ("kind", Json::unsigned(30078)),
            ("tags", Json::array(vec![Json::array(vec![Json::from("d"), Json::from("cd".repeat(32))])])),
            ("content", Json::from(filler.as_str())),
            ("sig", Json::from("00".repeat(64))),
        ]));
    }
    let wanted = format!("{}ff", "0".repeat(62));
    let keep: Keep<Json> = {
        let wanted = wanted.clone();
        Arc::new(move |value: &Json| {
            (value.get("id").and_then(Json::as_str) == Some(wanted.as_str())).then(|| value.clone())
        })
    };
    let filter = Filter { kinds: Some(vec![30078.0]), ..Filter::default() };
    let one = vec![merchant.key_relays[0].clone()];
    for paged in [false, true] {
        let pool = pool(&merchant.net, 2000);
        let read = pool
            .query_relays(
                &one,
                &filter,
                &Secret::new([1; 32]),
                &keep,
                ReadOf { needed: 1, paged, every_relay: false },
            )
            .await;
        assert_eq!(read.answered(), 1);
        let kept = &read.answers[0].1;
        assert_eq!(kept.len(), 1, "paged: {paged}");
        assert_eq!(kept[0].get("id").and_then(Json::as_str), Some(wanted.as_str()));
        assert_eq!(kept[0].get("content").and_then(Json::as_str), Some(filler.as_str()));
    }
    // A complete read: 300 events in pages of 100, one kept; the read complete.
    let pool = pool(&merchant.net, 2000);
    let complete = pool.query_complete(&one, &filter, &Secret::new([1; 32]), 1, &keep, false).await;
    assert_eq!(complete.complete, 1);
    assert_eq!(complete.read.answers[0].1.len(), 1);
    let pages =
        relay.queries().iter().filter(|query| query.get("limit") == Some(&Json::unsigned(100))).count();
    assert_eq!(pages, 4);
}

#[tokio::test(start_paused = true)]
async fn reads_a_relay_copies_of_one_event_once_and_keeps_nothing_a_relay_adds_to_it() {
    let merchant = TestMerchant::new();
    let url = "wss://copies.test".to_owned();
    let relay = merchant.net.add(&url, RelayBehaviour::default());
    let event = merchant.channel_event(&merchant.channel_value(100, j!({})), 100, None);
    // Copies that check out: the id and the signature cover none of what a relay adds.
    for _ in 0..50 {
        let mut members: Vec<(JsonString, Json)> = event
            .to_json()
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        members.push((JsonString::Text("padding".to_owned()), Json::from("x".repeat(100_000))));
        relay.store(Json::Object(JsonObject::new(members)));
    }
    let encryption_key = channel_keys(&merchant.integration_key).encryption_key;
    let open = records_that_open(Arc::new(move |_, _| Some(encryption_key.clone())));
    let opened = Arc::new(AtomicUsize::new(0));
    let keep: Keep<Event> = {
        let opened = opened.clone();
        Arc::new(move |value: &Json| {
            opened.fetch_add(1, Ordering::SeqCst);
            open(value)
        })
    };
    let filter = Filter { kinds: Some(vec![30078.0]), ..Filter::default() };
    let one = vec![url.clone()];
    for read in ["query", "paged", "complete"] {
        opened.store(0, Ordering::SeqCst);
        let asked = relay.queries().len();
        let pool = pool(&merchant.net, 2000);
        let key = Secret::new([1; 32]);
        let answers = if read == "complete" {
            let complete = pool.query_complete(&one, &filter, &key, 1, &keep, false).await;
            assert_eq!(complete.complete, 1, "{read}");
            complete.read.answers
        } else {
            let of = ReadOf { needed: 1, paged: read == "paged", every_relay: false };
            pool.query_relays(&one, &filter, &key, &keep, of).await.answers
        };
        assert_eq!(answers.len(), 1, "{read}");
        // One copy kept, exactly its NIP-01 members.
        assert_eq!(answers[0].1.len(), 1, "{read}: copies kept");
        assert!(json::stringify(&answers[0].1[0].to_json()) == json::stringify(&event.to_json()), "{read}");
        // One opening per query that sent the copies (a paged read asks their second again).
        let sent = relay.queries()[asked..]
            .iter()
            .filter(|query| {
                query.get("until").and_then(Json::as_f64).is_none_or(|until| until >= event.created_at as f64)
            })
            .count();
        assert!(sent >= 1, "{read}");
        assert_eq!(opened.load(Ordering::SeqCst), sent, "{read}");
    }
}

mod the_witnesses_of_an_invoice {
    use super::*;

    const EXPIRES_AT: i64 = 1_791_379_180;

    fn seen() -> SeenKeys {
        seen_of(&Secret::new([2; 32]))
    }

    fn sale() -> String {
        "ab".repeat(32)
    }

    fn witness(seen: &SeenKeys, of: &str, tx: &str, sale: Option<&str>) -> Event {
        witness_event(
            seen,
            &Witness {
                address: of.to_owned(),
                txid: txid(tx),
                sale: sale.map(str::to_owned),
                sats: 1000,
                inputs: Vec::new(),
                replacement: false,
                expires_at: sale.map(|_| EXPIRES_AT),
            },
            1_791_378_400,
            &OsRandom,
        )
    }

    /// A record of a newer format (its content `#`) at the witness address of `tx` at `of`.
    fn newer(seen: &SeenKeys, of: &str, tx: &str, tags: Vec<Vec<String>>, signed: bool) -> Event {
        let mut all =
            vec![vec!["d".to_owned(), witness_address(&seen.address_key, of, &txid(tx), Some(&sale()))]];
        all.extend(tags);
        let mut event = sign_event(
            EventTemplate { kind: 30078.0, created_at: 1_791_378_400, tags: all, content: "#".to_owned() },
            &seen.secret_key,
            &OsRandom,
        );
        if !signed {
            event.sig = "00".repeat(64);
        }
        event
    }

    /// What a read of the invoice's witnesses keeps of `events` (as relays send them), then reads.
    fn read(seen: &SeenKeys, events: &[Event]) -> OrderWitnesses {
        let (author, key) = (seen.author.clone(), seen.encryption_key.clone());
        let keep = records_that_open(Arc::new(move |_, pubkey| (pubkey == author).then(|| key.clone())));
        let kept: Vec<Event> = events.iter().filter_map(|event| keep(&event.to_json())).collect();
        order_witnesses_of(&kept, seen, &deposit_address("this"), &sale(), EXPIRES_AT)
    }

    #[test]
    fn reads_those_of_this_read_of_the_sale_of_none_of_another_sale_at_the_address() {
        let seen = seen();
        let address = deposit_address("this");
        let witnesses = read(
            &seen,
            &[
                witness(&seen, &address, "mine", Some(&sale())),
                witness(&seen, &address, "none", None),
                witness(&seen, &address, "another's", Some(&"cd".repeat(32))),
            ],
        );
        assert_eq!(
            witnesses.sale.iter().map(|(txid, _)| txid.clone()).collect::<Vec<_>>(),
            vec![txid("mine")]
        );
        assert_eq!(witnesses.none.iter().cloned().collect::<Vec<_>>(), vec![txid("none")]);
        assert_eq!(
            witnesses.others.iter().map(|(txid, _)| txid.clone()).collect::<Vec<_>>(),
            vec![txid("another's")]
        );
    }

    #[test]
    fn ignores_a_witness_at_another_address_a_transaction_paying_two_orders_pays_each_its_part() {
        let seen = seen();
        let witnesses =
            read(&seen, &[witness(&seen, &deposit_address("elsewhere"), "batch", Some(&"cd".repeat(32)))]);
        assert_eq!((witnesses.sale.len(), witnesses.others.len(), witnesses.none.len()), (0, 0, 0));
    }

    #[test]
    fn keeps_a_witness_of_a_newer_format_only_with_the_read_tags_and_the_author_signature() {
        let seen = seen();
        let address = deposit_address("this");
        let tag = vec![vec!["o".to_owned(), address_tag(&seen.address_key, &address)]];
        let other_tag =
            vec![vec!["o".to_owned(), address_tag(&seen.address_key, &deposit_address("elsewhere"))]];
        assert_eq!(read(&seen, &[newer(&seen, &address, "t", tag.clone(), true)]).newer.len(), 1);
        // Another address's, which a relay sends against the filter: of no invoice of this read.
        assert_eq!(read(&seen, &[newer(&seen, &address, "t", other_tag, true)]).newer.len(), 0);
        // Without the seen secret's signature: nothing (SPEC.md §12), not an undecided payment.
        assert_eq!(read(&seen, &[newer(&seen, &address, "t", tag, false)]).newer.len(), 0);
    }
}

mod absent_is_not_null {
    //! Where the specification says null, an absent member is no null.

    use super::*;
    use crate::declaration::{DeclaredPrice, registry_of};
    use crate::derive::sale_of;
    use crate::json;
    use crate::model::{DeclaredInvoice, Fiat, Invoice, InvoiceToCheck, RateInfo};
    use crate::nostr::nip44;
    use crate::nostr::record::{Seal, seal_record};
    use crate::onchain::explorer::parse_transaction;
    use crate::onchain::lease::{LeaseTerms, lease_inside, open_lease_inside};
    use crate::onchain::witness::{OpenedWitness, open_witness, order_tag, witness_value};
    use crate::order::check_stored_invoice;
    use crate::protocol::WITNESS_RECORD_TYPE;

    /// `value` without its member `name`.
    fn without(value: &Json, name: &str) -> Json {
        Json::object_of(
            value
                .as_object()
                .unwrap()
                .iter()
                .filter(|(member, _)| member.as_str() != Some(name))
                .map(|(member, value)| (member.as_str().unwrap(), value.clone()))
                .collect(),
        )
    }

    #[test]
    fn a_stored_invoice_may_lack_its_onchain_address_alone() {
        let stored = j!({
            "ref": "N-1",
            "bolt11": null,
            "paymentHash": null,
            "verifyUrl": null,
            "onchainAddress": deposit_address(1),
            "sats": "49000",
            "expiresAt": 1_791_379_180
        });
        assert!(InvoiceToCheck::from_json(&json::stringify(&stored)).is_ok());
        let lightning_only = json::stringify(&without(&stored, "onchainAddress"));
        assert_eq!(InvoiceToCheck::from_json(&lightning_only).unwrap().onchain_address, None);
        for name in ["bolt11", "paymentHash", "verifyUrl"] {
            let text = json::stringify(&without(&stored, name));
            let error = InvoiceToCheck::from_json(&text).unwrap_err();
            assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("invoice")), "{name}");
            assert!(serde_json::from_str::<InvoiceToCheck>(&text).is_err(), "{name}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stored_invoice_without_its_bolt11_is_refused_by_get_status_before_any_request() {
        let merchant = merchant();
        let client = client(&merchant);
        let stored = j!({
            "ref": "N-1",
            "paymentHash": null,
            "verifyUrl": null,
            "onchainAddress": deposit_address(1),
            "sats": "49000",
            "expiresAt": 1_791_379_180
        });
        let error = InvoiceToCheck::from_json(&json::stringify(&stored)).unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("invoice")));
        assert!(merchant.http.calls().is_empty());
        let _ = client;
    }

    #[test]
    fn an_explorer_output_address_is_a_string_when_present_null_is_a_failure() {
        let tx = |output: Json| {
            j!({
                "txid": txid("t"),
                "vin": [{ "txid": txid("coin"), "vout": 0, "is_coinbase": false }],
                "vout": [output],
                "status": { "confirmed": false }
            })
        };
        assert!(
            parse_transaction(&tx(j!({ "value": 1000, "scriptpubkey_address": deposit_address(1) })))
                .is_some()
        );
        // An output to no address (OP_RETURN): it pays nothing.
        let none = parse_transaction(&tx(j!({ "value": 0 }))).unwrap();
        assert_eq!(none.outputs, vec![(0, None)]);
        assert_eq!(parse_transaction(&tx(j!({ "value": 1000, "scriptpubkey_address": null }))), None);
        assert_eq!(parse_transaction(&tx(j!({ "value": 1000, "scriptpubkey_address": 7 }))), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_whose_explorer_writes_a_null_address_fails_network() {
        let merchant = merchant();
        merchant.publish_lot(&[deposit_address(1)], 90);
        let client = client(&merchant);
        let invoice = client.create_invoice(&Order::sats("N-2", 49_000)).await.unwrap();
        let address = invoice.onchain_address.clone().unwrap();
        let answer = Json::array(vec![j!({
            "txid": txid("null"),
            "vin": [{ "txid": txid("coin"), "vout": 0, "is_coinbase": false }],
            "vout": [{ "value": 49_000, "scriptpubkey_address": null }],
            "status": { "confirmed": false }
        })]);
        let path = format!("https://mempool.space/api/address/{address}/txs");
        merchant.set_override(Some(move |call: &super::super::support::http::Call| {
            (call.url == path).then(|| Answer::json(&answer))
        }));
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
    }

    #[test]
    fn a_lease_inside_without_its_invoice_and_verify_url_does_not_open_as_the_sale() {
        let merchant = TestMerchant::new();
        let sale = sale_of(
            &merchant.integration_key,
            &registry_of(&crate::text::to_hex(merchant.registry_key.expose()), &merchant.reader),
            "N-3",
        );
        let address = deposit_address(1);
        let terms = LeaseTerms {
            address: address.clone(),
            sats: 49_000,
            invoice: None,
            verify_url: None,
            created_at: 1_791_378_280,
            expires_at: 1_791_379_180,
            price: DeclaredPrice { minor: 49_000, digits: 0, currency: "SAT".to_owned() },
            note: "N-3".to_owned(),
            tolerance: 0,
            confirmed: Some(true),
        };
        let d = crate::derive::lease_address(&merchant.registry_key, &address);
        let end = terms.expires_at + 120;
        let open = |inside: &Json| {
            let sealed = nip44::encrypt(&json::stringify(inside), &sale.inner_key, &[7; 32]).unwrap();
            open_lease_inside(&sealed, end, &d, &sale).unwrap().map(|(terms, _)| terms)
        };
        let inside = lease_inside(&sale, &terms);
        assert_eq!(open(&inside), Some(terms.clone()));
        assert_eq!(open(&without(&inside, "invoice")), None);
        assert_eq!(open(&without(&inside, "verifyUrl")), None);
        assert_eq!(open(&without(&without(&inside, "invoice"), "verifyUrl")), None);
    }

    #[test]
    fn a_witness_without_its_sale_does_not_open() {
        let seen = seen_of(&Secret::new([2; 32]));
        let address = deposit_address(1);
        let witness = Witness {
            address: address.clone(),
            txid: txid("w"),
            sale: None,
            sats: 1000,
            inputs: Vec::new(),
            replacement: false,
            expires_at: None,
        };
        let sealed = |value: Json| {
            seal_record(
                Seal {
                    record_type: WITNESS_RECORD_TYPE,
                    value,
                    signer: &seen.secret_key,
                    encryption_key: &seen.encryption_key,
                    address: &witness_address(&seen.address_key, &address, &witness.txid, None),
                    created_at: 1_791_378_400,
                    tags: vec![
                        vec!["o".to_owned(), order_tag(&seen.address_key, &address, None)],
                        vec!["o".to_owned(), address_tag(&seen.address_key, &address)],
                    ],
                },
                &OsRandom,
            )
            .unwrap()
        };
        let value = witness_value(&witness);
        assert!(matches!(open_witness(&sealed(value.clone()), &seen), Some(OpenedWitness::Valid { .. })));
        assert!(open_witness(&sealed(without(&value, "sale")), &seen).is_none());
        assert!(open_witness(&sealed(without(&value, "expiresAt")), &seen).is_none());
    }

    /// `value` with its member `name` set to `item` (in place, or added at the end).
    fn with(value: &Json, name: &str, item: Json) -> Json {
        super::super::support::merged(value, &Json::object([(name, item)]))
    }

    #[test]
    fn an_invoice_read_back_has_each_member_its_null_included_but_its_onchain_address() {
        let address = deposit_address(1);
        let invoice = Invoice {
            reference: "N-4".to_owned(),
            bolt11: None,
            payment_hash: None,
            verify_url: None,
            onchain_address: Some(address.clone()),
            payment_uri: format!("bitcoin:{address}?amount=0.00049"),
            sats: 49_000,
            fiat: Some(Fiat {
                amount: "24.50".to_owned(),
                currency: "CHF".to_owned(),
                minor: 2450,
                digits: 2,
            }),
            rate: Some(RateInfo {
                source: "kraken".to_owned(),
                currency: "CHF".to_owned(),
                price: "69012".to_owned(),
                fetched_at: 1_791_378_280,
                time: None,
            }),
            note: "N-4".to_owned(),
            created_at: 1_791_378_280,
            expires_at: 1_791_379_180,
            checkout_url: None,
            redirect_url: None,
        };
        let value = invoice.to_value();
        assert_eq!(Invoice::from_json(&json::stringify(&value)).unwrap(), invoice);
        // Without its address it reads as one without (SPEC.md §3, InvoiceToCheck): Lightning only.
        let lightning_only =
            Invoice::from_json(&json::stringify(&without(&value, "onchainAddress"))).unwrap();
        assert_eq!(lightning_only.onchain_address, None);
        let refused = |value: &Json, what: &str| {
            let text = json::stringify(value);
            let error = Invoice::from_json(&text).unwrap_err();
            assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("invoice")), "{what}");
            assert!(serde_json::from_str::<Invoice>(&text).is_err(), "{what}");
        };
        for name in ["bolt11", "paymentHash", "verifyUrl", "fiat", "rate", "checkoutUrl", "redirectUrl"] {
            refused(&without(&value, name), name);
        }
        // An undated rate's time is null, never left out.
        let rate = value.get("rate").unwrap().clone();
        refused(&with(&value, "rate", without(&rate, "time")), "rate.time");

        let declared = DeclaredInvoice {
            reference: invoice.reference.clone(),
            bolt11: None,
            payment_hash: None,
            verify_url: None,
            onchain_address: Some(address),
            payment_uri: invoice.payment_uri.clone(),
            sats: invoice.sats,
            fiat: None,
            note: invoice.note.clone(),
            created_at: invoice.created_at,
            expires_at: invoice.expires_at,
            declared_at: 1_791_378_281,
        };
        let value = declared.to_value();
        assert_eq!(DeclaredInvoice::from_json(&json::stringify(&value)).unwrap(), declared);
        let without_address = json::stringify(&without(&value, "onchainAddress"));
        assert_eq!(DeclaredInvoice::from_json(&without_address).unwrap().onchain_address, None);
        for name in ["bolt11", "paymentHash", "verifyUrl", "fiat"] {
            let text = json::stringify(&without(&value, name));
            let error = DeclaredInvoice::from_json(&text).unwrap_err();
            assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("invoice")), "{name}");
            assert!(serde_json::from_str::<DeclaredInvoice>(&text).is_err(), "{name}");
        }
    }

    #[test]
    fn a_stored_invoice_without_an_address_is_checked_without_its_ref() {
        // As createInvoice made it, Lightning only: `ref` is read only with an address (SPEC.md §22,
        // "the others are not read"), whatever it holds otherwise.
        let vectors = super::super::support::vectors::spec("vectors/payments.json");
        let stored =
            vectors.get("stored").and_then(Json::as_array).unwrap()[0].get("invoice").unwrap().clone();
        assert!(stored.get("onchainAddress").unwrap().is_null());
        let checked = |value: &Json| {
            InvoiceToCheck::from_json(&json::stringify(value))
                .and_then(|invoice| check_stored_invoice(&invoice))
        };
        for reference in [Json::Null, Json::unsigned(5), Json::from("ORD 1"), Json::Bool(true)] {
            let value = with(&stored, "ref", reference.clone());
            assert!(checked(&value).is_ok(), "{}", json::stringify(&reference));
            assert!(serde_json::from_str::<InvoiceToCheck>(&json::stringify(&value)).is_ok());
        }
        assert!(checked(&without(&stored, "ref")).is_ok());
        // With an address, a reference (payments.json: absent, null, not one): never a number.
        let with_address = with(&stored, "onchainAddress", Json::from(deposit_address(1).as_str()));
        assert!(checked(&with_address).is_ok());
        let error = checked(&with(&with_address, "ref", Json::unsigned(5))).unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("invoice")));
    }
}

mod reads_on_every_relay {
    use super::*;
    use crate::nostr::relay::Read;

    /// A record of anybody at `d`, at `created_at`: what any relay may hold.
    fn anybody(d: &str, created_at: i64, seed: usize) -> Json {
        Json::object([
            ("id", Json::from(format!("{seed:064x}"))),
            ("pubkey", Json::from("ab".repeat(32))),
            ("created_at", Json::integer(created_at)),
            ("kind", Json::unsigned(30078)),
            ("tags", Json::array(vec![Json::array(vec![Json::from("d"), Json::from(d)])])),
            ("content", Json::from("x")),
            ("sig", Json::from("00".repeat(64))),
        ])
    }

    fn everything() -> Keep<Json> {
        Arc::new(|value: &Json| Some(value.clone()))
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_whose_authentication_runs_out_of_time_failed_for_the_rest_of_the_call() {
        let merchant = TestMerchant::new().start();
        let urls = merchant.key_relays.clone();
        // r1 asks to authenticate, and never answers the authentication.
        let stalling = merchant.net.get(&urls[0]);
        stalling.set_behaviour(RelayBehaviour {
            require_auth: true,
            mute_auth: true,
            ..RelayBehaviour::default()
        });
        let pool = pool(&merchant.net, 1000);
        let filter = Filter { kinds: Some(vec![30078.0]), ..Filter::default() };
        let key = Secret::new([1; 32]);
        let one = vec![urls[0].clone()];
        let started = tokio::time::Instant::now();
        let read = pool.query_relays(&one, &filter, &key, &everything(), ReadOf::query(&one)).await;
        // Its request ran out of time while it waited for the OK of its authentication (SPEC.md
        // §13): no answer, a relay that failed, never a refusal asked again.
        assert_eq!(read.answered(), 0);
        assert_eq!(started.elapsed(), Duration::from_millis(1000));
        assert!(pool.has_failed(&urls[0]));
        assert_eq!(stalling.queries().len(), 1);
        // A read on every relay of the call does not wait for it again, nor asks it.
        let started = tokio::time::Instant::now();
        let read = pool
            .query_relays(
                &urls,
                &filter,
                &key,
                &everything(),
                ReadOf { needed: 2, paged: false, every_relay: true },
            )
            .await;
        assert_eq!(read.answered(), 2);
        assert!(started.elapsed() < Duration::from_millis(100), "{:?}", started.elapsed());
        assert_eq!(stalling.queries().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_still_reading_when_a_complete_read_goes_on_is_no_answer_its_pages_events_only() {
        let merchant = TestMerchant::new().start();
        let d = "cd".repeat(32);
        let relays: Vec<_> = merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect();
        // r1: more than a page of one second: its read ends incomplete at once.
        for seed in 0..150 {
            relays[0].store(anybody(&d, 1_000_000, seed));
        }
        // r2 never answers: it fails at its timeout.
        relays[1].set_behaviour(RelayBehaviour::mute());
        // r3 sends its first page late, never its second: still reading when r2 fails.
        for seed in 0..150 {
            relays[2].store(anybody(&d, 1_000_000 - seed as i64, 1000 + seed));
        }
        relays[2].set_behaviour(RelayBehaviour {
            query_delay_ms: Some(500),
            mute_query: Some(Arc::new(|filter: &Json| filter.has("until"))),
            ..RelayBehaviour::default()
        });
        let pool = pool(&merchant.net, 1000);
        let filter = Filter { kinds: Some(vec![30078.0]), d: Some(vec![d.clone()]), ..Filter::default() };
        let read = pool
            .query_complete(&merchant.key_relays, &filter, &Secret::new([1; 32]), 2, &everything(), true)
            .await;
        // A majority can no longer read completely: the read goes on, r3 still reading.
        assert_eq!(read.complete, 0);
        let Read { answers, pages } = &read.read;
        assert_eq!(
            answers.iter().map(|(relay, _)| relay.as_str()).collect::<Vec<_>>(),
            vec![merchant.key_relays[0].as_str()]
        );
        assert_eq!(read.read.answered(), 1);
        // Its first page kept as events, and that is all.
        assert_eq!(pages.len(), 1);
        assert_eq!((pages[0].0.as_str(), pages[0].1.len()), (merchant.key_relays[2].as_str(), 100));
        assert_eq!(read.read.events().count(), 200);
    }

    #[tokio::test(start_paused = true)]
    async fn a_paged_read_on_every_relay_counts_the_relays_whose_read_ended_alone() {
        let merchant = TestMerchant::new().start();
        let d = "cd".repeat(32);
        let relays: Vec<_> = merchant.key_relays.iter().map(|url| merchant.net.get(url)).collect();
        for relay in &relays {
            relay.store(anybody(&d, 1_000_000, 1));
            relay.update(|behaviour| behaviour.cap = Some(1));
        }
        relays[2].store(anybody(&d, 999_999, 2));
        // r3 pages one event at a time, its first page 300 ms late, its second never answered:
        // still reading one timeout after a majority answered.
        relays[2].update(|behaviour| {
            behaviour.query_delay_ms = Some(300);
            behaviour.mute_query = Some(Arc::new(|filter: &Json| filter.has("until")));
        });
        let pool = pool(&merchant.net, 1000);
        let filter = Filter { kinds: Some(vec![30078.0]), ..Filter::default() };
        let read = pool
            .query_relays(
                &merchant.key_relays,
                &filter,
                &Secret::new([1; 32]),
                &everything(),
                ReadOf { needed: 2, paged: true, every_relay: true },
            )
            .await;
        assert_eq!(read.answered(), 2);
        assert_eq!(
            read.pages.iter().map(|(relay, events)| (relay.as_str(), events.len())).collect::<Vec<_>>(),
            vec![(merchant.key_relays[2].as_str(), 1)]
        );
    }
}

mod paged_reads {
    use super::*;

    /// An event of `author` at `created_at` that does not check out (its signature), or does.
    fn event(secret: &Secret, created_at: i64, valid: bool) -> Json {
        let mut event = sign_event(
            EventTemplate {
                kind: 30078.0,
                created_at,
                tags: vec![vec!["d".to_owned(), "cd".repeat(32)]],
                content: format!("{created_at}"),
            },
            secret,
            &OsRandom,
        );
        if !valid {
            event.sig = "00".repeat(64);
        }
        event.to_json()
    }

    /// `value` with its member `name` set to `to`.
    fn with(value: &Json, name: &str, to: Json) -> Json {
        let members: Vec<_> = value
            .as_object()
            .unwrap()
            .iter()
            .map(|(member, item)| {
                let item = if member.as_str() == Some(name) { to.clone() } else { item.clone() };
                (member.clone(), item)
            })
            .collect();
        Json::Object(JsonObject::new(members))
    }

    async fn read(merchant: &TestMerchant, relay: &str) -> Vec<Event> {
        let keep: Keep<Event> = Arc::new(crate::nostr::event::valid_event);
        let pool = pool(&merchant.net, 1000);
        let filter = Filter { kinds: Some(vec![30078.0]), ..Filter::default() };
        let read = pool
            .query_relays(
                &[relay.to_owned()],
                &filter,
                &Secret::new([1; 32]),
                &keep,
                ReadOf { needed: 1, paged: true, every_relay: false },
            )
            .await;
        read.events().cloned().collect()
    }

    fn untils(relay: &super::super::support::relay::LocalRelay) -> Vec<Option<i64>> {
        relay.queries().iter().map(|query| query.get("until").and_then(Json::as_safe_integer)).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn go_on_while_a_page_held_an_event_with_a_string_id_and_a_safe_integer_date_valid_or_not() {
        let merchant = TestMerchant::new().start();
        let relay = merchant.net.get(&merchant.key_relays[0]);
        let secret = Secret::new([9; 32]);
        // Pages of 2: four events that do not check out, one whose date is no safe integer, then
        // the one that checks out.
        for created_at in [500, 499, 498, 497] {
            relay.store(event(&secret, created_at, false));
        }
        relay.store(with(&event(&secret, 450, false), "created_at", Json::Number(450.5)));
        let wanted = event(&secret, 400, true);
        relay.store(wanted.clone());
        relay.update(|behaviour| behaviour.cap = Some(2));
        let kept = read(&merchant, &merchant.key_relays[0]).await;
        assert_eq!(kept.iter().map(Event::to_json).collect::<Vec<_>>(), vec![wanted]);
        // Each page from the oldest date of the last one's events with a string id and a safe
        // integer date, valid or not (minus 1 when none was new).
        assert_eq!(
            untils(&relay),
            vec![None, Some(499), Some(498), Some(497), Some(496), Some(400), Some(399)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stop_at_a_page_without_an_event_with_a_string_id_and_a_safe_integer_date() {
        let merchant = TestMerchant::new().start();
        let relay = merchant.net.get(&merchant.key_relays[0]);
        let secret = Secret::new([9; 32]);
        relay.store(with(&event(&secret, 600, false), "id", Json::Number(7.0)));
        relay.store(event(&secret, 400, true));
        relay.update(|behaviour| behaviour.cap = Some(1));
        assert!(read(&merchant, &merchant.key_relays[0]).await.is_empty());
        assert_eq!(untils(&relay), vec![None]);
    }
}

mod records_of_a_newer_format {
    use super::super::support::merchant::Warnings;
    use super::*;
    use crate::declaration::registry_of;
    use crate::derive::{channel_keys, lot_address, sale_of};
    use crate::nostr::record::{Seal, seal_record};

    #[tokio::test(start_paused = true)]
    async fn a_lot_of_a_newer_format_logs_a_warning_and_takes_no_onchain_payment() {
        let merchant = merchant();
        merchant.publish_lot(&[deposit_address(1)], 90);
        let keys = channel_keys(&merchant.integration_key);
        let newer = seal_record(
            Seal {
                record_type: "integration-onchain-lot",
                value: j!({ "version": 2, "addresses": [], "updatedAt": 95 }),
                signer: &merchant.team_secret,
                encryption_key: &keys.encryption_key,
                address: &lot_address(&merchant.integration_key),
                created_at: 95,
                tags: Vec::new(),
            },
            &OsRandom,
        )
        .unwrap();
        for relay in &merchant.key_relays {
            merchant.net.get(relay).store_event(&newer);
        }
        let warnings = Warnings::default();
        let client = merchant.client().logger(warnings.clone()).build().unwrap();
        assert_eq!(client.merchant().await.unwrap().onchain_addresses, 0);
        assert_eq!(warnings.all().len(), 1, "{:?}", warnings.all());
        assert!(warnings.all()[0].contains("lot of addresses has a newer format"), "{:?}", warnings.all());
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_of_the_sale_of_a_newer_format_logs_a_warning() {
        let merchant = merchant();
        let sale = sale_of(
            &merchant.integration_key,
            &registry_of(&crate::text::to_hex(merchant.registry_key.expose()), &merchant.reader),
            "N-4",
        );
        let newer = sign_event(
            EventTemplate {
                kind: 30078.0,
                created_at: merchant.now() - 10,
                tags: vec![vec!["d".to_owned(), "ab".repeat(32)]],
                content: "#".to_owned(),
            },
            &sale.secret_key,
            &OsRandom,
        );
        for relay in &merchant.key_relays {
            merchant.net.get(relay).store_event(&newer);
        }
        let warnings = Warnings::default();
        let client = merchant.client().logger(warnings.clone()).build().unwrap();
        assert!(client.find_invoices("N-4").await.unwrap().is_empty());
        assert_eq!(warnings.all().len(), 1, "{:?}", warnings.all());
        assert!(warnings.all()[0].contains("has a newer format"), "{:?}", warnings.all());
    }
}

mod case_of_bech32 {
    //! Only ASCII letters change case (SPEC.md §6): a BOLT11 invoice is all lowercase or all
    //! uppercase (§19), never a mix, and no other character reads as a letter of it.

    use super::super::support::vectors::{Field, spec};
    use crate::lightning::bolt11;
    use crate::onchain::address::is_deposit_address;

    #[test]
    fn an_invoice_in_upper_case_is_the_same_invoice_one_holding_a_kelvin_sign_for_its_k_is_none() {
        let vectors = spec("vectors/bolt11.json");
        let invoice = vectors
            .list("cases")
            .iter()
            .filter(|case| !case.field("expected").is_null())
            .map(|case| case.text("invoice"))
            .find(|invoice| invoice.contains('k'))
            .expect("a valid invoice holding a k");
        let upper = invoice.to_ascii_uppercase();
        assert!(bolt11::decode(invoice).is_some());
        assert_eq!(bolt11::decode(&upper), bolt11::decode(invoice));
        // U+212A KELVIN SIGN, which Unicode case mapping (JavaScript's toLowerCase) lowers to `k`.
        let at = upper.rfind('K').expect("a K");
        let kelvin = format!("{}\u{212a}{}", &upper[..at], &upper[at + 1..]);
        assert_eq!(bolt11::decode(&kelvin), None);
        let mixed = format!("{}k{}", &upper[..at], &upper[at + 1..]);
        assert_eq!(bolt11::decode(&mixed), None);
    }

    #[test]
    fn a_deposit_address_is_in_lower_case_alone() {
        let vectors = spec("vectors/onchain-addresses.json");
        let address = vectors
            .list("addresses")
            .iter()
            .filter(|case| case.field("valid").as_bool() == Some(true))
            .map(|case| case.text("address"))
            .find(|address| address.contains('k'))
            .expect("a deposit address holding a k");
        assert!(is_deposit_address(address));
        assert!(!is_deposit_address(&address.to_ascii_uppercase()));
        let at = address.rfind('k').expect("a k");
        assert!(!is_deposit_address(&format!("{}\u{212a}{}", &address[..at], &address[at + 1..])));
    }
}

mod every_bitcoin_there_will_ever_be {
    //! SPEC.md §31, Explorers: a transaction whose outputs together hold more than 2 100 000 000
    //! 000 000 sats is no transaction, and the explorer's answer a failure (`network`): each output
    //! a safe integer, two of them paying an address could sum past every bitcoin. So the sums of
    //! what an answer pays the address fit a u64 whatever an explorer sends.

    use super::*;
    use crate::onchain::explorer::{parse_transaction, pays_to};
    use crate::onchain::payment::{OnchainCheck, OnchainPart, Witnesses, check_onchain_part};
    use crate::onchain::witness::{OrderWitnesses, Witness, witness_address};
    use crate::protocol::{MAX_HTTP_BODY_BYTES, MAX_SATS, MEMPOOL_URL};

    /// A transaction paying `values` to `address`, as an explorer writes it, its values spelled as
    /// given (a JSON number of any spelling).
    fn tx(seed: &str, values: &[&str], address: &str) -> String {
        let outputs: Vec<String> = values
            .iter()
            .map(|value| format!(r#"{{"value":{value},"scriptpubkey_address":"{address}"}}"#))
            .collect();
        format!(
            r#"{{"txid":"{}","vin":[],"vout":[{}],"status":{{"confirmed":false}}}}"#,
            txid(seed),
            outputs.join(",")
        )
    }

    fn parsed(text: &str) -> Option<crate::onchain::explorer::ExplorerTx> {
        parse_transaction(&json::parse(text).unwrap())
    }

    #[test]
    fn a_transaction_whose_outputs_hold_more_than_every_bitcoin_is_none() {
        let address = deposit_address(1);
        // Every bitcoin, in one output or in two: a transaction.
        let all = parsed(&tx("all", &["2100000000000000"], &address)).unwrap();
        assert_eq!(pays_to(&all, &address), MAX_SATS);
        let halves = parsed(&tx("halves", &["1050000000000000", "1050000000000000"], &address)).unwrap();
        assert_eq!(pays_to(&halves, &address), MAX_SATS);
        // A sat more, or each output a safe integer above it: none.
        assert!(parsed(&tx("more", &["2100000000000001"], &address)).is_none());
        assert!(parsed(&tx("two", &["1050000000000000", "1050000000000001"], &address)).is_none());
        assert!(parsed(&tx("safe", &["9007199254740991", "9007199254740991"], &address)).is_none());
        // Outputs to other addresses count too.
        let elsewhere = format!(
            r#"{{"txid":"{}","vin":[],"vout":[{{"value":2100000000000000,"scriptpubkey_address":"{address}"}},{{"value":1}}],"status":{{"confirmed":false}}}}"#,
            txid("elsewhere")
        );
        assert!(parsed(&elsewhere).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_whose_explorer_lists_one_fails_network() {
        let merchant = TestMerchant::new().start();
        merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
        merchant.publish_lot(&[deposit_address(1)], 90);
        let client = merchant.client().build().unwrap();
        let invoice = client.create_invoice(&Order::sats("B-1", 49_000)).await.unwrap();
        let address = invoice.onchain_address.clone().unwrap();
        let answer = format!("[{}]", tx("more", &["1050000000000000", "1050000000000001"], &address));
        let path = format!("{MEMPOOL_URL}/address/{address}/txs");
        merchant.set_override(Some(move |call: &super::super::support::http::Call| {
            (call.url == path).then(|| Answer { status: 200, body: answer.clone().into_bytes() })
        }));
        let received =
            || merchant.key_relays.iter().map(|url| merchant.net.get(url).received().len()).sum::<usize>();
        let before = received();
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        // Nothing witnessed of it.
        assert_eq!(received(), before);
    }

    /// Witnesses of nobody, published nowhere; no merchant's acceptance.
    struct NoWitnesses {
        address: String,
    }

    impl Witnesses for NoWitnesses {
        fn read(&self, _every_relay: bool) -> BoxFuture<'_, Result<OrderWitnesses, Error>> {
            Box::pin(async { Ok(OrderWitnesses::default()) })
        }

        fn merchant_acceptance(
            &self,
        ) -> BoxFuture<'_, Result<crate::onchain::merchant_acceptance::MerchantAcceptance, Error>> {
            Box::pin(async { Ok(crate::onchain::merchant_acceptance::MerchantAcceptance::default()) })
        }

        fn witness_address(&self, txid: &str, sale: Option<&str>) -> String {
            witness_address(&Secret::new([3; 32]), &self.address, txid, sale)
        }

        fn publish<'a>(&'a self, _witness: &'a Witness) -> BoxFuture<'a, Result<(), Error>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// The on-chain part of an invoice of `address` whose explorer answers `answer`.
    async fn onchain_part(address: &str, answer: String) -> Result<OnchainPart, Error> {
        let (txs_path, height_path) =
            (format!("{MEMPOOL_URL}/address/{address}/txs"), format!("{MEMPOOL_URL}/blocks/tip/height"));
        let http = FakeHttp::new(move |call| {
            if call.url == txs_path {
                return Some(Answer { status: 200, body: answer.clone().into_bytes() });
            }
            (call.url == height_path).then(|| Answer::text(200, "970000"))
        })
        .http(10_000);
        let clock = super::super::support::random::TestClock::new(1_791_378_000);
        let witnesses = NoWitnesses { address: address.to_owned() };
        let logger = super::super::support::merchant::Quiet;
        let sale = "ab".repeat(32);
        // mempool.space: no node.
        let explorer =
            crate::onchain::explorer::Explorer::new(None, Default::default(), Arc::new(clock.clone()));
        let check = OnchainCheck {
            address,
            sats: 49_000,
            expires_at: 1_791_378_900,
            sale: &sale,
            clock: &clock,
            explorer: &explorer,
            http: &http,
            witnesses: &witnesses,
            logger: &logger,
        };
        check_onchain_part(&check, async { 0 }, async { 0 }).await
    }

    /// The most an explorer's answer can pay an address: as many transactions as 1 MiB holds, of
    /// the fewest bytes (no input, one output to the address, every bitcoin spelled `21e14`), each
    /// paying it every bitcoin there will ever be. Received exactly: below u64::MAX, nothing wraps.
    /// Without the bound, the same answer of outputs of the largest safe integer would sum past it.
    #[tokio::test(start_paused = true)]
    async fn the_most_an_answer_pays_an_address_is_received_without_wrapping() {
        let address = deposit_address(1);
        let answer_of = |value: &str| {
            let count = (MAX_HTTP_BODY_BYTES - 1) / (tx("0", &[value], &address).len() + 1);
            let answer = format!(
                "[{}]",
                (0..count)
                    .map(|index| tx(&index.to_string(), &[value], &address))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            assert!(answer.len() <= MAX_HTTP_BODY_BYTES, "{}", answer.len());
            (count, answer)
        };
        let (count, answer) = answer_of("21e14");
        assert!(u128::from(MAX_SATS) * count as u128 <= u128::from(u64::MAX), "{count} transactions");
        let part = onchain_part(&address, answer).await.unwrap();
        let OnchainPart::Unconfirmed { received, txids, .. } = part else { panic!("{part:?}") };
        assert_eq!(txids.len(), count);
        assert_eq!(u128::from(received), u128::from(MAX_SATS) * count as u128);
        // Each a safe integer, together past u64::MAX: no answer, never a sum that wraps.
        let (count, answer) = answer_of("9007199254740991");
        assert!(9_007_199_254_740_991u128 * count as u128 > u128::from(u64::MAX));
        assert_eq!(onchain_part(&address, answer).await.unwrap_err().code(), ErrorCode::Network);
    }
}

mod the_relays_a_read_went_on_without {
    //! SPEC.md §13, Reads: the relays a read drops when it goes on end their requests and ask
    //! nothing more: no page, no authentication, no subscription id drawn. The reads of a relay
    //! are futures of the read itself, dropped when it goes on: none starts anything after.

    use std::sync::Mutex;

    use super::*;
    use crate::nostr::relay::{PoolConfig, RelayPool};
    use crate::runtime::{Clock, Random};
    use crate::tests::support::relay::{LocalRelay, RelayNet};

    /// The CSPRNG and the test's clock, each call recorded with when it came.
    #[derive(Clone, Default)]
    struct Recorded(Arc<Mutex<Vec<tokio::time::Instant>>>);

    impl Recorded {
        fn since(&self, instant: tokio::time::Instant) -> usize {
            self.0.lock().unwrap().iter().filter(|at| **at > instant).count()
        }
    }

    impl Random for Recorded {
        fn fill(&self, bytes: &mut [u8]) {
            self.0.lock().unwrap().push(tokio::time::Instant::now());
            OsRandom.fill(bytes);
        }
    }

    impl Clock for Recorded {
        fn now_ms(&self) -> i64 {
            self.0.lock().unwrap().push(tokio::time::Instant::now());
            1_791_378_000_000
        }
    }

    /// A record of anybody at `d`, at `created_at`.
    fn anybody(d: &str, created_at: i64, seed: usize) -> Json {
        Json::object([
            ("id", Json::from(format!("{seed:064x}"))),
            ("pubkey", Json::from("ab".repeat(32))),
            ("created_at", Json::integer(created_at)),
            ("kind", Json::unsigned(30078)),
            ("tags", Json::array(vec![Json::array(vec![Json::from("d"), Json::from(d)])])),
            ("content", Json::from("x")),
            ("sig", Json::from("00".repeat(64))),
        ])
    }

    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Query,
        Paged,
        Complete,
    }

    /// A read of five relays: three answer 150 ms late (a majority: the read goes on then);
    /// `late` answers its first page 300 ms late, a full page that would page on; `auth` asks for
    /// authentication and answers it 600 ms late. Nothing reaches `late` and `auth` after the read
    /// went on but the CLOSE of `late`'s query, and the client's random source and clock are not
    /// called after it went on.
    async fn read(kind: Kind) {
        let net = RelayNet::default();
        let d = "cd".repeat(32);
        let urls: Vec<String> = ["answers-1", "answers-2", "answers-3", "late", "auth"]
            .map(|name| format!("wss://{name}.test"))
            .to_vec();
        let relays: Vec<LocalRelay> = urls
            .iter()
            .map(|url| {
                let behaviour = match url.as_str() {
                    "wss://late.test" => RelayBehaviour::delayed(300),
                    "wss://auth.test" => RelayBehaviour {
                        require_auth: true,
                        auth_delay_ms: Some(600),
                        ..RelayBehaviour::default()
                    },
                    _ => RelayBehaviour::delayed(150),
                };
                net.add(url, behaviour)
            })
            .collect();
        // A full page, at distinct seconds: a paged or complete read asks the next one.
        for seed in 0..100 {
            relays[3].store(anybody(&d, 1_000_000 - seed as i64, seed));
            relays[4].store(anybody(&d, 1_000_000 - seed as i64, seed));
        }
        let recorded = Recorded::default();
        let pool = RelayPool::new(PoolConfig {
            websocket: Arc::new(net.clone()),
            timeout: Duration::from_millis(2000),
            random: Arc::new(recorded.clone()),
            clock: Arc::new(recorded.clone()),
            call: crate::nostr::relay::CallTasks::default(),
        });
        let filter = Filter { kinds: Some(vec![30078.0]), d: Some(vec![d.clone()]), ..Filter::default() };
        let key = Secret::new([7; 32]);
        let keep: Keep<Json> = Arc::new(|value: &Json| Some(value.clone()));
        let started = tokio::time::Instant::now();
        let answered = match kind {
            Kind::Query => {
                pool.query_relays(&urls, &filter, &key, &keep, ReadOf::query(&urls)).await.answered()
            }
            Kind::Paged => {
                let read = ReadOf { needed: 3, paged: true, every_relay: false };
                pool.query_relays(&urls, &filter, &key, &keep, read).await.answered()
            }
            Kind::Complete => pool.query_complete(&urls, &filter, &key, 3, &keep, false).await.complete,
        };
        let returned = tokio::time::Instant::now();
        // It went on when the majority answered.
        let went_on = started + Duration::from_millis(150);
        assert_eq!(answered, 3, "{kind:?}");
        // The late relay answers, the other's authentication is answered, meanwhile.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(relays[4].authenticated().len(), 1, "{kind:?}");
        let heard = |relay: &LocalRelay| -> (Vec<String>, Vec<String>) {
            let messages = relay.messages();
            let before = messages.iter().filter(|(at, _)| *at < went_on).map(|(_, m)| m.clone()).collect();
            let after = messages.iter().filter(|(at, _)| *at >= went_on).map(|(_, m)| m.clone()).collect();
            (before, after)
        };
        let (before, after) = heard(&relays[3]);
        assert_eq!(before.len(), 1, "{kind:?}: {before:?}");
        assert!(before[0].starts_with("REQ "), "{kind:?}: {before:?}");
        // Its query ended: closed, and nothing asked again.
        assert_eq!(after, vec![before[0].replacen("REQ", "CLOSE", 1)], "{kind:?}");
        // Asked, refused until it authenticates, authenticated: then nothing more, though its
        // authentication was answered.
        let (before, after) = heard(&relays[4]);
        assert_eq!(before.iter().map(|m| &m[..4]).collect::<Vec<_>>(), vec!["REQ ", "AUTH"], "{kind:?}");
        assert!(after.is_empty(), "{kind:?}: {after:?}");
        assert_eq!(recorded.since(went_on), 0, "{kind:?}");
        // And returned then: its readers had ended.
        assert_eq!(returned, went_on, "{kind:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn ask_nothing_more_once_it_went_on_a_query() {
        read(Kind::Query).await;
    }

    #[tokio::test(start_paused = true)]
    async fn ask_nothing_more_once_it_went_on_a_paged_read() {
        read(Kind::Paged).await;
    }

    #[tokio::test(start_paused = true)]
    async fn ask_nothing_more_once_it_went_on_a_complete_read() {
        read(Kind::Complete).await;
    }
}

/// SPEC.md §13 (NIP-42): an authentication is `["AUTH", <event>]`, never an `EVENT`. The local relay
/// of the tests takes it only so, as NIP-42 has it (kind 22242, the connection's challenge, the
/// relay's URL, an empty content): a client that sent it any other way would fail every test
/// whose relay asks for authentication.
#[tokio::test(start_paused = true)]
async fn the_local_relay_takes_an_authentication_as_an_auth_message_alone() {
    use crate::websocket::{WebSocketClient, request_for};

    let merchant = TestMerchant::new().start();
    let url = merchant.key_relays[0].clone();
    let relay = merchant.net.get(&url);
    relay.set_behaviour(RelayBehaviour { require_auth: true, ..RelayBehaviour::default() });
    let mut socket = merchant.net.connect(request_for(&url)).await.unwrap();
    async fn next(socket: &mut Box<dyn crate::websocket::WebSocketConnection>) -> Json {
        json::parse(&socket.receive().await.unwrap().unwrap()).unwrap()
    }
    let challenge = next(&mut socket).await;
    let challenge = challenge.as_array().unwrap()[1].as_str().unwrap().to_owned();
    let key = Secret::new([5; 32]);
    let auth = |relay_url: &str, content: &str| {
        sign_event(
            EventTemplate {
                created_at: 1_791_378_000,
                kind: 22242.0,
                tags: vec![
                    vec!["relay".to_owned(), relay_url.to_owned()],
                    vec!["challenge".to_owned(), challenge.clone()],
                ],
                content: content.to_owned(),
            },
            &key,
            &OsRandom,
        )
    };
    let mut answers = Vec::new();
    // Sent as an EVENT, then with another relay's URL, then with a content: each refused, and
    // nothing authenticated.
    for (kind, event) in
        [("EVENT", auth(&url, "")), ("AUTH", auth("wss://another.test", "")), ("AUTH", auth(&url, "hi"))]
    {
        socket.send(json::stringify(&Json::array(vec![Json::from(kind), event.to_json()]))).await.unwrap();
        answers.push(next(&mut socket).await);
    }
    for answer in &answers {
        let answer = answer.as_array().unwrap();
        assert_eq!((answer[0].as_str(), &answer[2]), (Some("OK"), &Json::Bool(false)), "{answers:?}");
    }
    assert!(relay.authenticated().is_empty());
    assert!(relay.events().is_empty(), "an authentication kept as an event");
    // As NIP-42 has it: taken.
    let event = auth(&url, "");
    socket.send(json::stringify(&Json::array(vec![Json::from("AUTH"), event.to_json()]))).await.unwrap();
    let taken = next(&mut socket).await;
    assert_eq!(
        taken,
        Json::array(vec![Json::from("OK"), Json::from(event.id.as_str()), Json::Bool(true), Json::from("")])
    );
    assert_eq!(relay.authenticated(), vec![event.pubkey.clone()]);
}

/// SPEC.md §13 (Publication): only the relays past a publication's majority may finish their own
/// request. A publication that failed (a majority can no longer take it) ends its other relays'
/// requests at once: none authenticates, nor writes the event again, though the call goes on.
#[tokio::test(start_paused = true)]
async fn a_failed_publication_ends_its_other_relays_requests_at_once() {
    let merchant = TestMerchant::new().start();
    let urls = merchant.key_relays.clone();
    for url in &urls[..2] {
        merchant.net.get(url).set_behaviour(RelayBehaviour::refusing("blocked: not on this relay"));
    }
    // The third takes it only once authenticated, and answers the authentication 600 ms late.
    let third = merchant.net.get(&urls[2]);
    third.set_behaviour(RelayBehaviour {
        require_auth: true,
        auth_delay_ms: Some(600),
        ..RelayBehaviour::default()
    });
    let key = Secret::new([5; 32]);
    let event = sign_event(
        EventTemplate { created_at: 1_791_378_000, kind: 30078.0, tags: Vec::new(), content: "x".to_owned() },
        &key,
        &OsRandom,
    );
    let pool = pool(&merchant.net, 2000);
    let started = tokio::time::Instant::now();
    assert!(pool.publish_to_quorum(&urls, &event, &key, 2).await.is_err());
    let failed = tokio::time::Instant::now();
    assert!(failed - started < Duration::from_millis(100), "{:?}", failed - started);
    // The call goes on (its pool alive): the authentication is answered meanwhile.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let events = third.messages().iter().filter(|(_, message)| message == "EVENT").count();
    assert_eq!(events, 1, "{:?}", third.messages());
    let after: Vec<String> =
        third.messages().into_iter().filter(|(at, _)| *at > failed).map(|(_, message)| message).collect();
    assert!(after.is_empty(), "{after:?}");
    drop(pool);
}
