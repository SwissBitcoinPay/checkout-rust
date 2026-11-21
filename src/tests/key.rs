//! The integration's secret key (SPEC.md §8): read as the app made it, refused damaged, never shown.

use super::support::merchant::Quiet;
use super::support::serializes;
use super::support::vectors::{Field, spec};
use crate::client::Client;
use crate::encoding::{from_base64url, to_base64url};
use crate::error::ErrorCode;
use crate::key::parse_integration_key;
use crate::text::to_hex;

fn app() -> crate::json::Json {
    spec("vectors/app/app.json")
}

#[test]
fn reads_the_key_the_app_made() {
    let app = app();
    let parsed = parse_integration_key(app.text("secretKey")).unwrap();
    let expected = app.field("parsed");
    assert_eq!(parsed.team, expected.text("team"));
    assert_eq!(to_hex(parsed.key.expose()), expected.text("integrationKey"));
    assert_eq!(parsed.relays, expected.texts("relays"));
}

#[test]
fn keeps_the_key_out_of_debug_output_and_of_the_client() {
    let app = app();
    let key = app.text("secretKey");
    let part = key.split('.').nth(1).unwrap();
    let hex = app.field("parsed").text("integrationKey");
    let parsed = parse_integration_key(key).unwrap();
    for shown in [format!("{parsed:?}"), format!("{:#?}", parsed)] {
        assert!(!shown.contains(part) && !shown.contains(hex), "{shown}");
    }
    let client = Client::builder(key).logger(Quiet).build().unwrap();
    for shown in [format!("{client:?}"), format!("{client:#?}")] {
        assert!(!shown.contains(part) && !shown.contains(hex), "{shown}");
    }
    let builder = Client::builder(key);
    let shown = format!("{builder:?}");
    assert!(!shown.contains(part) && !shown.contains(hex), "{shown}");
}

/// SPEC.md §27: nothing that holds the key, a key derived from it or the CoinGecko key gives any
/// of them to what an application logs or returns: `Debug` (`{:?}`, `{:#?}`), `Display`, serde.
#[test]
fn gives_no_key_to_debug_display_or_serde() {
    let app = app();
    let key = app.text("secretKey");
    let secrets = [
        key,
        key.split('.').nth(1).unwrap(),
        app.field("parsed").text("integrationKey"),
        "CG-secretdemokey123",
    ];
    let builder = Client::builder(key).coingecko_api_key("CG-secretdemokey123").logger(Quiet);
    let builder_shown = format!("{builder:?} {builder:#?}");
    let client = builder.build().unwrap();
    let client_shown = format!("{client:?} {client:#?}");
    let error = Client::new(format!("{key}x")).unwrap_err();
    let error_shown = format!("{error:?} {error:#?} {error}");
    let options = crate::client::WaitOptions::default().interval_ms(1000);
    let options_shown = format!("{options:?} {options:#?}");
    for (what, shown) in [
        ("ClientBuilder", builder_shown),
        ("Client", client_shown),
        ("Error", error_shown),
        ("WaitOptions", options_shown),
    ] {
        for secret in secrets {
            assert!(!shown.contains(secret), "{what} shows a secret: {shown}");
        }
    }
    // None of them serializes; the data model does (it holds no key).
    assert!(!serializes!(Client));
    assert!(!serializes!(crate::client::ClientBuilder));
    assert!(!serializes!(crate::Error));
    assert!(!serializes!(crate::client::WaitOptions));
    assert!(serializes!(crate::model::Invoice));
}

/// `part` (base64url of UTF-8) with a byte order mark before its text.
fn with_bom(part: &str) -> String {
    let mut bytes = vec![0xef, 0xbb, 0xbf];
    bytes.extend(from_base64url(part).unwrap());
    to_base64url(&bytes)
}

#[test]
fn refuses_a_damaged_key_without_the_key_in_the_message() {
    let app = app();
    let key = app.text("secretKey").to_owned();
    let hex = app.field("parsed").text("integrationKey").to_owned();
    let parts: Vec<&str> = key["sattleme_ck_".len()..].split('.').collect();
    let (team, secret, relays) = (parts[0], parts[1], parts[2]);
    let damaged: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("another prefix", key.replace("sattleme_ck_", "sattleme_other_")),
        ("a later format's prefix", key.replace("sattleme_ck_", "sattleme_ck2_")),
        ("the prefix sattleme_ without ck_", key.replace("sattleme_ck_", "sattleme_")),
        ("no prefix", key["sattleme_ck_".len()..].to_owned()),
        ("a link holding its parts", format!("https://pay.example/pay#{team}.{secret}.{relays}")),
        ("a part missing", format!("sattleme_ck_{team}.{secret}")),
        ("a part too many", format!("{key}.{relays}")),
        ("a key cut short", key[..key.len() - 3].to_owned()),
        ("a team cut short", format!("sattleme_ck_{}.{secret}.{relays}", &team[1..])),
        ("a key too long", format!("sattleme_ck_{team}.{secret}AA.{relays}")),
        ("padding", format!("sattleme_ck_{team}=.{secret}.{relays}")),
        ("standard base64", format!("sattleme_ck_+{}.{secret}.{relays}", &team[1..])),
        ("unused bits set", format!("sattleme_ck_{}b.{secret}.{relays}", &team[..team.len() - 1])),
        ("no relay", format!("sattleme_ck_{team}.{secret}.")),
        ("a relay that is not one", format!("sattleme_ck_{team}.{secret}.bG9jYWxob3N0")),
        ("spaces", format!(" {key}")),
        // Strict UTF-8 keeps it: "\u{feff}relay…" is no relay's host (SPEC.md §8, step 5).
        (
            "a relays part starting with a byte order mark",
            format!("sattleme_ck_{team}.{secret}.{}", with_bom(relays)),
        ),
    ];
    for (name, text) in damaged {
        let error = parse_integration_key(&text).expect_err(name);
        assert_eq!(error.code(), ErrorCode::InvalidKey, "{name}");
        for shown in [error.to_string(), format!("{error:?}")] {
            assert!(!shown.contains(secret) && !shown.contains(&hex), "{name}: {shown}");
        }
    }
}

#[test]
fn refuses_a_key_at_construction() {
    let error = Client::new("nope").unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidKey);
    let error = Client::builder("nope").build().unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidKey);
}
