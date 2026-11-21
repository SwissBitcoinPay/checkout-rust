//! Prices in a currency (SPEC.md §25, §26): exact conversion, the currencies' decimals, each rate
//! source's answers and failures, custom sources, lists of sources.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use num_bigint::BigUint;

use super::support::http::{Answer, Call, FakeHttp};
use super::support::j;
use super::support::merchant::{Quiet, Warnings};
use crate::currencies::currency_digits;
use crate::error::{Error, ErrorCode};
use crate::json::Json;
use crate::model::RateInfo;
use crate::rates::{
    CustomPrice, CustomRateError, CustomRateSource, Decimal, RateContext, RateSource, Sources,
    fetch_first_rate, fetch_rate, fiat_to_sats, format_decimal, parse_decimal, parse_fiat, rate_source_list,
};
use crate::transport::BoxFuture;

const NOW: i64 = 1_791_385_300;

/// A custom source answering what `answer` gives, recording that it was asked under `name`.
struct Custom<F> {
    answer: F,
    asked: Arc<Mutex<Vec<String>>>,
    name: &'static str,
}

impl<F> CustomRateSource for Custom<F>
where
    F: Fn(&str) -> Result<CustomPrice, CustomRateError> + Send + Sync,
{
    fn price<'a>(&'a self, currency: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>> {
        self.asked.lock().unwrap().push(self.name.to_owned());
        let answer = (self.answer)(currency);
        Box::pin(async move { answer })
    }
}

fn custom(
    answer: impl Fn(&str) -> Result<CustomPrice, CustomRateError> + Send + Sync + 'static,
) -> RateSource {
    RateSource::custom(Custom { answer, asked: Arc::new(Mutex::new(Vec::new())), name: "custom" })
}

fn named(
    name: &'static str,
    asked: &Arc<Mutex<Vec<String>>>,
    answer: impl Fn(&str) -> Result<CustomPrice, CustomRateError> + Send + Sync + 'static,
) -> RateSource {
    RateSource::custom(Custom { answer, asked: asked.clone(), name })
}

/// The price `source` gives in `currency`, its HTTP answered by `route`; and the requests made.
async fn price_of(
    source: &RateSource,
    currency: &str,
    route: impl Fn(&Call) -> Option<Answer> + Send + Sync + 'static,
    coingecko_api_key: Option<&str>,
) -> (Result<RateInfo, Error>, Vec<Call>) {
    let http = FakeHttp::new(route);
    let client = http.http(1000);
    let rate = fetch_rate(source, currency, &RateContext { http: &client, coingecko_api_key }, NOW).await;
    (rate.map(|rate| rate.info), http.calls())
}

fn answer(value: Json) -> impl Fn(&Call) -> Option<Answer> + Send + Sync + 'static {
    move |_| Some(Answer::json(&value))
}

fn code<T: std::fmt::Debug>(result: Result<T, Error>) -> ErrorCode {
    result.expect_err("an error").code()
}

mod exact_conversion {
    use super::*;

    #[test]
    fn rounds_up_to_the_next_whole_sat() {
        // ⌈2450 × 10^8 / 6 901 200⌉: the exact quotient is 35 501.07…
        assert_eq!(2450u64 * 100_000_000 / 6_901_200, 35_501);
        assert_ne!(2450u64 * 100_000_000 % 6_901_200, 0);
        assert_eq!(fiat_to_sats("24.50", "CHF", "69012").unwrap(), BigUint::from(35_502u32));
        assert_eq!(fiat_to_sats("24.5", "CHF", "69012.000").unwrap(), BigUint::from(35_502u32));
    }

    #[test]
    fn gives_exactly_the_quotient_when_it_is_whole() {
        // 1 CHF at 100 000 CHF/BTC: 1000 sats exactly.
        assert_eq!(fiat_to_sats("1.00", "CHF", "100000").unwrap(), BigUint::from(1000u32));
    }

    #[test]
    fn reads_a_price_as_its_exact_decimal_a_coinbase_string_with_16_decimals_included() {
        let price = "69025.1084416666694295";
        assert_eq!(format_decimal(&parse_decimal(price).unwrap()), price);
        // ⌈2450 × 10^8 × 10^16 / (690251084416666694295 × 10^2)⌉, on integers.
        let dividend = BigUint::from(2450u32) * BigUint::from(100_000_000u32) * BigUint::from(10u32).pow(16);
        let divisor: BigUint = "690251084416666694295".parse::<BigUint>().unwrap() * BigUint::from(100u32);
        let expected = (dividend + &divisor - BigUint::from(1u32)) / divisor;
        assert_eq!(fiat_to_sats("24.50", "CHF", price).unwrap(), expected);
    }

    #[test]
    fn reads_exponent_notation() {
        let decimal = |units: &str, scale: u32| Decimal { units: units.parse().unwrap(), scale };
        assert_eq!(parse_decimal("8e-8"), Some(decimal("8", 8)));
        assert_eq!(format_decimal(&parse_decimal("8e-8").unwrap()), "0.00000008");
        assert_eq!(parse_decimal("1.5e+21"), Some(decimal("1500000000000000000000", 0)));
        assert_eq!(parse_decimal("6.9012e4"), Some(decimal("69012", 0)));
        assert_eq!(parse_decimal("69012.50"), Some(decimal("690125", 1)));
    }

    #[test]
    fn refuses_an_invalid_price() {
        // A price is a text (never a number, which may have lost digits): the type refuses one.
        let long = "1".repeat(65);
        for price in [
            "0",
            "0.000",
            "-69012",
            "",
            "abc",
            "1,5",
            " ",
            " 69012",
            "69012\n",
            "0x10",
            "1e65",
            long.as_str(),
            "NaN",
        ] {
            assert_eq!(parse_decimal(price), None, "{price:?}");
            assert_eq!(code(fiat_to_sats("1", "CHF", price)), ErrorCode::Rate, "{price:?}");
        }
    }

    #[test]
    fn takes_the_currency_decimals_from_its_table() {
        assert_eq!(currency_digits("CHF"), Some(2));
        assert_eq!(currency_digits("JPY"), Some(0));
        assert_eq!(currency_digits("BHD"), Some(3));
        // The app's decimals (Intl), not ISO 4217's 2: the app leaves out sales of other decimals.
        assert_eq!(currency_digits("RSD"), Some(0));
        // Not currencies an order is priced in: any three letters, a fund, gold, bitcoin, lower case.
        for code in ["ABC", "CHE", "XAU", "XXX", "BTC", "SAT", "chf", "hasOwnProperty"] {
            assert_eq!(currency_digits(code), None, "{code}");
        }
        let jpy = parse_fiat("1500", "JPY").unwrap();
        assert_eq!(
            (jpy.amount.as_str(), jpy.currency.as_str(), jpy.minor, jpy.digits),
            ("1500", "JPY", 1500, 0)
        );
        let chf = parse_fiat("24.500", "CHF").unwrap();
        assert_eq!((chf.amount.as_str(), chf.currency.as_str(), chf.minor), ("24.50", "CHF", 2450));
    }

    #[test]
    fn refuses_an_invalid_price_in_a_currency() {
        // An amount that is a number: the type refuses it.
        for (amount, currency) in [
            ("24.505", "CHF"),
            ("1.5", "JPY"),
            ("0", "CHF"),
            ("0.00", "CHF"),
            ("-1", "CHF"),
            ("1e3", "CHF"),
            ("24.50", "SAT"),
            ("24.50", "CHFX"),
            ("99999999999999999", "CHF"),
        ] {
            let error = parse_fiat(amount, currency).unwrap_err();
            assert_eq!(
                (error.code(), error.param()),
                (ErrorCode::InvalidOrder, Some("fiat")),
                "{amount} {currency}"
            );
        }
    }
}

mod rate_sources {
    use super::*;

    #[test]
    fn knows_its_sources_by_name() {
        let names: Vec<&str> = ["coingecko", "mempool", "opennode", "coinbase", "kraken"]
            .iter()
            .map(|name| name.parse::<RateSource>().unwrap().name())
            .collect();
        assert_eq!(names, vec!["coingecko", "mempool", "opennode", "coinbase", "kraken"]);
        assert_eq!(code("custom".parse::<RateSource>()), ErrorCode::InvalidOption);
        assert_eq!(code("Kraken".parse::<RateSource>()), ErrorCode::InvalidOption);
    }

    #[tokio::test(start_paused = true)]
    async fn coingecko_dated_with_or_without_a_demo_key() {
        let route = |call: &Call| {
            Some(if call.path().ends_with("/simple/price") {
                Answer::json(&j!({ "bitcoin": { "chf": 69012, "last_updated_at": NOW - 30 } }))
            } else {
                Answer::status_json(404, &j!({}))
            })
        };
        let (info, calls) = price_of(&RateSource::Coingecko, "CHF", route, None).await;
        assert_eq!(
            info.unwrap(),
            RateInfo {
                source: "coingecko".to_owned(),
                currency: "CHF".to_owned(),
                price: "69012".to_owned(),
                fetched_at: NOW,
                time: Some(NOW - 30)
            }
        );
        assert_eq!(
            calls[0].url,
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=chf&include_last_updated_at=true"
        );
        assert_eq!(calls[0].header("x-cg-demo-api-key"), None);
        // CoinGecko answers HTTP 403 to a request without a User-Agent (SPEC.md §15).
        assert_eq!(calls[0].header("User-Agent"), Some("sattleme-Checkout/1"));
        let (_, calls) = price_of(&RateSource::Coingecko, "CHF", route, Some("demo")).await;
        assert_eq!(calls[0].header("x-cg-demo-api-key"), Some("demo"));
        assert_eq!(calls[0].header("User-Agent"), Some("sattleme-Checkout/1"));
        let (info, _) = price_of(&RateSource::Coingecko, "XYZ", answer(j!({ "bitcoin": {} })), None).await;
        assert_eq!(code(info), ErrorCode::UnsupportedCurrency);
        let (info, _) = price_of(&RateSource::Coingecko, "CHF", answer(j!({ "nope": 1 })), None).await;
        assert_eq!(code(info), ErrorCode::Rate);
    }

    #[tokio::test(start_paused = true)]
    async fn mempool_space_dated_its_7_currencies() {
        let body = j!({
            "time": NOW - 60, "USD": 82977, "EUR": 74000, "GBP": 63000, "CAD": 118000, "CHF": 69080, "AUD": 119000, "JPY": 13187638
        });
        let (info, calls) = price_of(&RateSource::Mempool, "CHF", answer(body.clone()), None).await;
        let info = info.unwrap();
        assert_eq!(
            (info.source.as_str(), info.price.as_str(), info.time),
            ("mempool", "69080", Some(NOW - 60))
        );
        assert_eq!(calls[0].url, "https://mempool.space/api/v1/prices");
        let (info, _) = price_of(&RateSource::Mempool, "SEK", answer(body.clone()), None).await;
        assert_eq!(code(info), ErrorCode::UnsupportedCurrency);
        let undated = j!({ "USD": 82977, "CHF": 69080 });
        let (info, _) = price_of(&RateSource::Mempool, "CHF", answer(undated), None).await;
        assert_eq!(code(info), ErrorCode::Rate);
    }

    #[tokio::test(start_paused = true)]
    async fn opennode() {
        let body = j!({
            "data": {
                "BTCCHF": { "CHF": 68991.16, "BTC": 0.00001449 },
                "BTCJPY": { "JPY": 13185808.44, "BTC": 8e-8 }
            }
        });
        let (info, calls) = price_of(&RateSource::Opennode, "CHF", answer(body.clone()), None).await;
        assert_eq!(info.unwrap().price, "68991.16");
        assert_eq!(calls[0].url, "https://api.opennode.com/v1/rates");
        let (info, _) = price_of(&RateSource::Opennode, "SEK", answer(body), None).await;
        assert_eq!(code(info), ErrorCode::UnsupportedCurrency);
        let (info, _) = price_of(&RateSource::Opennode, "CHF", answer(j!({ "data": [] })), None).await;
        assert_eq!(code(info), ErrorCode::Rate);
    }

    #[tokio::test(start_paused = true)]
    async fn coinbase_its_decimal_strings_kept_as_written() {
        let body = j!({ "data": { "currency": "BTC", "rates": { "CHF": "69025.1084416666694295", "USD": "83000.1" } } });
        let (info, calls) = price_of(&RateSource::Coinbase, "CHF", answer(body.clone()), None).await;
        assert_eq!(info.unwrap().price, "69025.1084416666694295");
        assert_eq!(calls[0].url, "https://api.coinbase.com/v2/exchange-rates?currency=BTC");
        let (info, _) = price_of(&RateSource::Coinbase, "SEK", answer(body), None).await;
        assert_eq!(code(info), ErrorCode::UnsupportedCurrency);
        let other = j!({ "data": { "currency": "ETH", "rates": { "CHF": "69025.1084416666694295", "USD": "83000.1" } } });
        let (info, _) = price_of(&RateSource::Coinbase, "CHF", answer(other), None).await;
        assert_eq!(code(info), ErrorCode::Rate);
    }

    #[tokio::test(start_paused = true)]
    async fn kraken_whatever_the_result_key_its_errors_read() {
        let ticker = |key: &str| {
            answer(Json::object([
                ("error", Json::array(vec![])),
                ("result", Json::object_of(vec![(key, j!({ "c": ["69050.00000", "0.1"], "a": ["1"] }))])),
            ]))
        };
        let (info, calls) = price_of(&RateSource::Kraken, "CHF", ticker("XBTCHF"), None).await;
        assert_eq!(info.unwrap().price, "69050");
        assert_eq!(calls[0].url, "https://api.kraken.com/0/public/Ticker?pair=XBTCHF");
        let (info, _) = price_of(&RateSource::Kraken, "USD", ticker("XXBTZUSD"), None).await;
        assert_eq!(info.unwrap().price, "69050");
        let (info, _) = price_of(
            &RateSource::Kraken,
            "ZZZ",
            answer(j!({ "error": ["EQuery:Unknown asset pair"] })),
            None,
        )
        .await;
        assert_eq!(code(info), ErrorCode::UnsupportedCurrency);
        let (info, _) =
            price_of(&RateSource::Kraken, "CHF", answer(j!({ "error": ["EService:Unavailable"] })), None)
                .await;
        assert_eq!(code(info), ErrorCode::Rate);
        let (info, _) = price_of(
            &RateSource::Kraken,
            "CHF",
            answer(j!({ "error": [], "result": { "A": { "c": ["1"] }, "B": { "c": ["2"] } } })),
            None,
        )
        .await;
        assert_eq!(code(info), ErrorCode::Rate);
    }

    #[test]
    fn refuses_a_name_it_does_not_know() {
        assert_eq!(code("bitstamp".parse::<RateSource>()), ErrorCode::InvalidOption);
    }

    #[tokio::test(start_paused = true)]
    async fn a_custom_source_a_decimal_string_dated_or_not() {
        let none = |_: &Call| Some(Answer::status_json(404, &j!({})));
        let (info, _) = price_of(&custom(|_| Ok("70000.5".into())), "CHF", none, None).await;
        assert_eq!(
            info.unwrap(),
            RateInfo {
                source: "custom".to_owned(),
                currency: "CHF".to_owned(),
                price: "70000.5".to_owned(),
                fetched_at: NOW,
                time: None
            }
        );
        let (info, _) = price_of(
            &custom(|_| Ok(CustomPrice { price: "70000".to_owned(), time: Some(NOW - 5) })),
            "CHF",
            none,
            None,
        )
        .await;
        assert_eq!(info.unwrap().time, Some(NOW - 5));
        // A number is no price of a custom source (its type is a string): what is not a decimal is
        // refused.
        for bad in ["0", "-5", "abc", "Infinity", ""] {
            let (info, _) = price_of(&custom(move |_| Ok(bad.into())), "CHF", none, None).await;
            assert_eq!(code(info), ErrorCode::Rate, "{bad}");
        }
        let (info, _) = price_of(
            &custom(|currency| Err(Box::new(Error::unsupported_currency(currency)))),
            "CHF",
            none,
            None,
        )
        .await;
        assert_eq!(code(info), ErrorCode::UnsupportedCurrency);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_price_older_than_an_hour_or_dated_in_the_future() {
        let none = |_: &Call| Some(Answer::status_json(404, &j!({})));
        let dated =
            |time: i64| custom(move |_| Ok(CustomPrice { price: "69000".to_owned(), time: Some(time) }));
        let (info, _) = price_of(&dated(NOW - 3600), "CHF", none, None).await;
        assert_eq!(info.unwrap().time, Some(NOW - 3600));
        let (info, _) = price_of(&dated(NOW - 3601), "CHF", none, None).await;
        assert_eq!(code(info), ErrorCode::Rate);
        let (info, _) = price_of(&dated(NOW + 3600), "CHF", none, None).await;
        assert_eq!(code(info), ErrorCode::Rate);
    }

    #[tokio::test(start_paused = true)]
    async fn an_http_failure_is_a_network_error_retryable() {
        let (info, _) =
            price_of(&RateSource::Coinbase, "CHF", |_| Some(Answer::status_json(503, &j!({}))), None).await;
        let error = info.unwrap_err();
        assert_eq!(error.code(), ErrorCode::Network);
        assert!(error.retryable());
        let (info, _) = price_of(&RateSource::Coinbase, "CHF", |_| None, None).await;
        assert_eq!(code(info), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn an_http_status_is_network_from_500_to_599_408_429_and_a_redirect_else_rate() {
        let cases: [(u16, ErrorCode); 12] = [
            (500, ErrorCode::Network),
            (503, ErrorCode::Network),
            (599, ErrorCode::Network),
            (408, ErrorCode::Network),
            (429, ErrorCode::Network),
            // A redirect is no answer (SPEC.md §15).
            (301, ErrorCode::Network),
            (308, ErrorCode::Network),
            (600, ErrorCode::Rate),
            (999, ErrorCode::Rate),
            (404, ErrorCode::Rate),
            (403, ErrorCode::Rate),
            (499, ErrorCode::Rate),
        ];
        for (status, expected) in cases {
            for source in [RateSource::Coinbase, RateSource::Coingecko, RateSource::Kraken] {
                let route = move |_: &Call| Some(Answer::status_json(status, &j!({})));
                let (info, _) = price_of(&source, "CHF", route, None).await;
                let error = info.expect_err("no price");
                assert_eq!(error.code(), expected, "HTTP {status} of {source:?}");
                assert!(error.retryable(), "HTTP {status}");
            }
        }
    }
}

mod lists_of_rate_sources {
    use super::*;

    fn ask() -> (FakeHttp, crate::http::Http) {
        let http = FakeHttp::new(|_| None);
        let client = http.http(1000);
        (http, client)
    }

    #[test]
    fn keeps_a_list_of_custom_sources_and_names_in_its_order_a_custom_one_alone_too() {
        let mine = || custom(|_| Ok("1".into()));
        let names = |list: Option<Vec<RateSource>>| {
            list.map(|list| list.iter().map(RateSource::name).collect::<Vec<_>>())
        };
        assert_eq!(names(rate_source_list(vec![mine()])), Some(vec!["custom"]));
        assert_eq!(
            names(rate_source_list(vec![mine(), RateSource::Kraken, mine()])),
            Some(vec!["custom", "kraken", "custom"])
        );
        assert_eq!(names(rate_source_list(vec![RateSource::Kraken, mine(), RateSource::Kraken])), None);
    }

    #[tokio::test(start_paused = true)]
    async fn asks_custom_sources_one_at_a_time_and_logs_each_failure_replaced() {
        #[derive(Debug)]
        struct Broken;
        impl std::fmt::Display for Broken {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("broken")
            }
        }
        impl std::error::Error for Broken {}
        let asked = Arc::new(Mutex::new(Vec::new()));
        let sources = vec![
            named("a", &asked, |_| Err(Box::new(Error::network("down")))),
            named("b", &asked, |_| Err(Box::new(Broken))),
            named("c", &asked, |_| Ok("69012.50".into())),
            named("d", &asked, |_| Ok("1".into())),
        ];
        let warnings = Warnings::default();
        let (_, http) = ask();
        let context = Sources { context: RateContext { http: &http, coingecko_api_key: None } };
        let rate = fetch_first_rate(&sources, "CHF", &|| NOW, &warnings, &context).await.unwrap();
        assert_eq!((rate.info.source.as_str(), rate.info.price.as_str()), ("custom", "69012.5"));
        assert_eq!(*asked.lock().unwrap(), vec!["a", "b", "c"]);
        assert_eq!(
            warnings.all(),
            vec![
                "Rate source custom failed (network): down; trying custom".to_owned(),
                "Rate source custom failed (rate): The custom rate source failed; trying custom".to_owned()
            ]
        );
    }

    /// A custom source that never answers.
    struct Stalls(Arc<Mutex<Vec<String>>>);

    impl CustomRateSource for Stalls {
        fn price<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>> {
            self.0.lock().unwrap().push("stalls".to_owned());
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_a_cancellation_and_at_an_error_of_another_kind() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let second = named("second", &asked, |_| Ok("1".into()));
        let (_, http) = ask();
        let context = Sources { context: RateContext { http: &http, coingecko_api_key: None } };
        // The call dropped while the first source runs: the second is never asked.
        let list = vec![RateSource::custom(Stalls(asked.clone())), second.clone()];
        let read = fetch_first_rate(&list, "CHF", &|| NOW, &Quiet, &context);
        assert!(tokio::time::timeout(Duration::from_millis(100), read).await.is_err());
        assert_eq!(*asked.lock().unwrap(), vec!["stalls"]);
        // An error of another kind stops the list, as it is.
        let invalid =
            named("invalid", &asked, |_| Err(Box::new(Error::invalid_order("fiat", "not for this shop"))));
        let error = fetch_first_rate(&[invalid, second], "CHF", &|| NOW, &Quiet, &context).await.unwrap_err();
        assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("fiat")));
        assert_eq!(*asked.lock().unwrap(), vec!["stalls", "invalid"]);
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_a_single_source_own_error() {
        let (_, http) = ask();
        let context = Sources { context: RateContext { http: &http, coingecko_api_key: None } };
        let own = custom(|currency| Err(Box::new(Error::unsupported_currency(currency))));
        let error = fetch_first_rate(&[own], "XAF", &|| NOW, &Quiet, &context).await.unwrap_err();
        assert_eq!((error.code(), error.currency()), (ErrorCode::UnsupportedCurrency, Some("XAF")));
        assert_eq!(error.message(), Error::unsupported_currency("XAF").message());
    }
}
