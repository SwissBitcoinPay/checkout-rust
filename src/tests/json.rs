//! JSON as every implementation reads it (SPEC.md §2): `JSON.parse`'s reading, and no more than 64
//! arrays and objects nested one in another.

use super::support::chain::deposit_address;
use crate::error::ErrorCode;
use crate::json::{self, Json};
use crate::model::InvoiceToCheck;
use crate::protocol::MAX_JSON_DEPTH;

/// `depth` arrays, one in another, around `1`.
fn nested(depth: usize) -> String {
    format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
}

/// `depth` levels, objects outside and arrays inside, half and half.
fn mixed(depth: usize) -> String {
    format!("{}{}{}", r#"{"a":"#.repeat(depth / 2), nested(depth / 2), "}".repeat(depth / 2))
}

/// A stored invoice with a member nobody reads, `extra`.
fn stored_with(extra: &str) -> String {
    format!(
        r#"{{"ref":"J-1","bolt11":null,"paymentHash":null,"verifyUrl":null,"onchainAddress":"{}","sats":"49000","expiresAt":1791379180,"extra":{extra}}}"#,
        deposit_address(1)
    )
}

#[test]
fn reads_64_arrays_and_objects_nested_and_refuses_65() {
    assert_eq!(MAX_JSON_DEPTH, 64);
    let mut expected = Json::Number(1.0);
    for _ in 0..64 {
        expected = Json::array(vec![expected]);
    }
    assert_eq!(json::parse(&nested(64)), Some(expected));
    assert_eq!(json::parse(&nested(65)), None);
    // Objects and arrays count together.
    assert!(json::parse(&mixed(64)).is_some());
    assert_eq!(json::parse(&mixed(66)), None);
    assert!(json::parse(&format!("{}{}", "[".repeat(64), "]".repeat(64))).is_some());
    assert_eq!(json::parse(&format!("{}{}", r#"{"a":"#.repeat(65), "}".repeat(65))), None);
    // Read by the crate or through serde, a stored invoice 65 deep in a member nobody reads is no
    // JSON; 64 deep, it is.
    let deep = stored_with(&nested(64));
    let error = InvoiceToCheck::from_json(&deep).unwrap_err();
    assert_eq!((error.code(), error.param()), (ErrorCode::InvalidOrder, Some("invoice")));
    assert!(serde_json::from_str::<InvoiceToCheck>(&deep).is_err());
    let fits = stored_with(&nested(63));
    assert!(InvoiceToCheck::from_json(&fits).is_ok());
    assert!(serde_json::from_str::<InvoiceToCheck>(&fits).is_ok());
}

#[test]
fn counts_no_bracket_inside_a_string_an_escaped_quote_included() {
    let inner = format!(r#"[[[[{}\"]]]"#, "{".repeat(100));
    let text = format!(r#"["{inner}"]"#);
    assert_eq!(
        json::parse(&text),
        Some(Json::array(vec![Json::from(format!("[[[[{}\"]]]", "{".repeat(100)))]))
    );
    let text = format!(r#"{{"a\"[[[":{}}}"#, nested(63));
    let value = json::parse(&text).expect("63 arrays in an object");
    assert!(value.get("a\"[[[").and_then(Json::as_array).is_some());
    // A backslash before the quote that ends a string.
    let text = format!(r#"["{}\"\\{}"]"#, "[".repeat(100), "{".repeat(100));
    assert!(json::parse(&text).is_some());
}

#[test]
fn reads_what_json_parse_reads_as_spec_2_says() {
    // Of members with one name, the last; numbers as doubles, whatever their length.
    assert_eq!(json::parse(r#"{"a":1,"a":2}"#), Some(Json::object([("a", Json::Number(2.0))])));
    assert_eq!(
        json::parse(&format!("[{}]", "9".repeat(5000))),
        Some(Json::array(vec![Json::Number(f64::INFINITY)]))
    );
    assert_eq!(
        json::parse("[1e400, -1e400, 5e2, 500.0]"),
        Some(Json::array(vec![
            Json::Number(f64::INFINITY),
            Json::Number(f64::NEG_INFINITY),
            Json::Number(500.0),
            Json::Number(500.0),
        ]))
    );
    // A name holding U+0000 is a name like any other.
    assert_eq!(json::parse(r#"{"\u0000a":1}"#), Some(Json::object([("\u{0}a", Json::Number(1.0))])));
}

#[test]
fn refuses_what_is_not_json() {
    for text in ["[01]", "[1,]", "[1]\u{a0}", "\u{feff}[1]", "", "[", "]"] {
        assert_eq!(json::parse(text), None, "{text:?}");
    }
}

#[test]
fn a_number_of_any_length_is_a_double() {
    let long = format!("1{}", "0".repeat(4999));
    assert_eq!(json::parse(&long), Some(Json::Number(f64::INFINITY)));
    assert_eq!(json::parse(&format!("-{long}")), Some(Json::Number(f64::NEG_INFINITY)));
    assert_eq!(json::parse("1e-400"), Some(Json::Number(0.0)));
    // An infinity is no integer (Number.isInteger).
    assert_eq!(json::parse("1e400").unwrap().as_integer(), None);
    // 300 digits: a finite double, an integer, not a safe one.
    let big = json::parse(&format!("1{}", "0".repeat(299))).unwrap();
    assert_eq!(big.as_f64(), Some(1e299));
    assert!(big.as_integer().is_some() && big.as_safe_integer().is_none());
    // A long spelling of 500 is 500.
    let spelled = json::parse(&format!("5{}e-400", "0".repeat(402))).unwrap();
    assert_eq!(spelled.as_safe_integer(), Some(500));
    // As a member nobody reads, a stored invoice holding one is read.
    assert!(InvoiceToCheck::from_json(&stored_with(&long)).is_ok());
    assert!(InvoiceToCheck::from_json(&stored_with("1e400")).is_ok());
}

/// The doubles of 100 000 random bit patterns whose shortest decimal has two spellings of one
/// length as near to it, and the spelling Node.js's `Number.prototype.toString` gives them (bit
/// patterns, then Node's text): of two as near, the one whose last digit is even.
const TIES: [(&str, &str); 50] = [
    ("431efb16cdb5cc97", "2180081165103909.8"),
    ("c310be96a6370a17", "-1178288467591813.8"),
    ("c31ca8fc7d98eb85", "-2016775435074273.2"),
    ("c31390e27645bc73", "-1376831719698204.8"),
    ("c31078c43e6753ad", "-1159095970813163.2"),
    ("431f494287b07d53", "2201568592797524.8"),
    ("431e77201f04a8d9", "2143807286094390.2"),
    ("431ec9ee91b6ae8f", "2166568946346915.8"),
    ("43153926e0d71967", "1493453413664345.8"),
    ("c31f2caa495e009b", "-2193708541247526.8"),
    ("c31582a2c9422b33", "-1513652545948364.8"),
    ("431026a80797d5c1", "1136525687780720.2"),
    ("4310e8e235f43473", "1189914473205020.8"),
    ("c3172df49f97191d", "-1631113284273735.2"),
    ("431b6bfaeaef55ab", "1929637449684330.8"),
    ("4319621844424471", "1786182695424284.2"),
    ("4313216a254fb65b", "1346191083433366.8"),
    ("c310c09cbd79baa5", "-1178844763418281.2"),
    ("431ded2c4e0993f5", "2105887217050877.2"),
    ("c31acd56e37dd1d7", "-1886030615508085.8"),
    ("4313c522afc77bb3", "1391194331537132.8"),
    ("c3126f1cb85c0725", "-1297179680899529.2"),
    ("431dfceabdd02bdb", "2110214865423094.8"),
    ("431a423277059b83", "1847783476782816.8"),
    ("431f39c205f0e3d3", "2197307441035508.8"),
    ("c317cbf403fe5f1d", "-1674543340951495.2"),
    ("4310fb925fcdc963", "1195051429622360.8"),
    ("c31bf4d64b04a357", "-1967256397490389.8"),
    ("c31b238ee53797af", "-1909730252285419.8"),
    ("431d61807037b3b9", "2067494647753966.2"),
    ("431d0aa8528ce9c1", "2043623095089776.2"),
    ("431ffa52c04ec123", "2250239399669832.8"),
    ("c318048c72e4c7d5", "-1690100177646069.2"),
    ("4317fa3ca5dc03c5", "1687265712996593.2"),
    ("c3127f9a7cdd70cb", "-1301712769342514.8"),
    ("c31bcf7e0583ecdf", "-1956991134137143.8"),
    ("c31ff96eabb0e80f", "-2249994500061699.8"),
    ("431b5a28cb0dc341", "1924738905764048.2"),
    ("c310097e462c9edf", "-1128509393807287.8"),
    ("431ff306cd4a7dc7", "2248233704398705.8"),
    ("431b3d12ad20ace3", "1916743698623288.8"),
    ("4316977811953e51", "1589747858624404.2"),
    ("43171398585bd7f1", "1623867375678972.2"),
    ("4313aaa2a8a93333", "1383910037146828.8"),
    ("4313237ace51772b", "1346758727982538.8"),
    ("c31c747c52839105", "-2002344164254785.2"),
    ("c3141e22210b60b3", "-1415657866582060.8"),
    ("c314b3f2fdd08a43", "-1456838938993296.8"),
    ("431e5bde3f9ef1bf", "2136314852392047.8"),
    ("431b34d20919a9a3", "1914475267910248.8"),
];

#[test]
fn writes_a_double_as_its_shortest_decimal_of_two_as_near_the_even() {
    // SPEC.md §25: the double 1660867710597813.25 reads back from both …813.2 and …813.3.
    for (text, written) in [
        ("1660867710597813.25", "1660867710597813.2"),
        ("-1660867710597813.25", "-1660867710597813.2"),
        ("1660867710597813.3", "1660867710597813.2"),
    ] {
        let Some(Json::Number(value)) = json::parse(text) else { panic!("{text}") };
        assert_eq!(json::number_to_string(value), written, "{text}");
    }
    for (bits, node) in TIES {
        let value = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
        assert_eq!(json::number_to_string(value), node, "{bits}");
    }
    // From 2^50 to 2^51 a double is a multiple of 0.25: each one of .25 or .75 is such a tie.
    let first: u64 = 1 << 50;
    for step in 0..2000u64 {
        let whole = first + step * ((1 << 50) / 2000) + step % 7;
        assert_eq!(json::number_to_string(whole as f64 + 0.25), format!("{whole}.2"));
        assert_eq!(json::number_to_string(whole as f64 + 0.75), format!("{whole}.8"));
        // No tie: one spelling nearer than any other.
        assert_eq!(json::number_to_string(whole as f64 + 0.5), format!("{whole}.5"));
        assert_eq!(json::number_to_string(whole as f64), format!("{whole}"));
    }
    // What has no tie is written as before: the nearest shortest decimal.
    for (value, text) in [
        (0.1, "0.1"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (1e21, "1e+21"),
        (123_456_789_012_345_680_000.0, "123456789012345680000"),
        (0.000_001, "0.000001"),
        (1e-7, "1e-7"),
        (69_012.5, "69012.5"),
        (9_007_199_254_740_993.0, "9007199254740992"),
    ] {
        assert_eq!(json::number_to_string(value), text);
    }
}

/// Reading costs time linear in what is read (SPEC.md §13, Limits): a reader whose cost grew with
/// the square of a string's escapes (one that indexes characters from the string's start at each
/// escape) would let anybody who writes events at a lease's `d` tag make every read of leases run
/// out of time. Each text of about 1 MiB is read in well under a second: within 2 s, a debug build
/// on a busy machine included (a quadratic reader takes minutes).
#[test]
fn reads_a_text_in_time_linear_in_its_size() {
    const MIB: usize = 1 << 20;
    let texts = [
        ("1 MiB of \\u0000 escapes in one string", format!("\"{}\"", "\\u0000".repeat(MIB / 6))),
        ("1 MiB of \\u0000 escapes with an é between each", format!("\"{}\"", "\\u0000é".repeat(MIB / 8))),
        (
            "a lone surrogate, then 1 MiB of \\u0000 escapes with an é between each",
            format!("\"\\ud800{}\"", "\\u0000é".repeat(MIB / 8)),
        ),
        (
            "an object of 65 536 members",
            format!(
                "{{{}\"z\":0}}",
                (0..MIB / 16).map(|index| format!("\"{index:010}\":0,")).collect::<String>()
            ),
        ),
        ("an object of 174 762 members of one name", format!("{{{}\"a\":1}}", "\"a\":0,".repeat(MIB / 6))),
        ("a number of 1 MiB of digits", "9".repeat(MIB)),
        ("an array of 209 716 arrays", format!("[{}]", "[[]],".repeat(MIB / 5) + "[]")),
        (
            "arrays nested 64 deep, 8 192 times",
            format!("[{}]", vec![format!("{}{}", "[".repeat(63), "]".repeat(63)); 8192].join(",")),
        ),
    ];
    for (what, text) in &texts {
        let started = std::time::Instant::now();
        let read = json::parse(text);
        let elapsed = started.elapsed();
        assert!(read.is_some(), "{what}: not read");
        assert!(elapsed < std::time::Duration::from_secs(2), "{what}: read in {elapsed:?}");
    }
    // What they read to.
    let Some(Json::String(units)) = json::parse(&texts[2].1) else { panic!("a string") };
    assert_eq!(units.utf16_len(), 1 + 2 * (MIB / 8));
}

#[test]
fn a_member_name_holding_u0000_is_an_ordinary_name() {
    let value = json::parse(r#"{"\u0000":1,"a\u0000":2,"a":3,"\u0000":4}"#).unwrap();
    assert_eq!(value.get("\u{0}"), Some(&Json::Number(4.0)));
    assert_eq!(value.get("a\u{0}"), Some(&Json::Number(2.0)));
    assert_eq!(value.get("a"), Some(&Json::Number(3.0)));
    assert!(InvoiceToCheck::from_json(&stored_with(r#"{"\u0000":"x"}"#)).is_ok());
    let named = stored_with("0").replacen(r#""extra""#, r#""\u0000""#, 1);
    assert!(InvoiceToCheck::from_json(&named).is_ok());
}

#[test]
fn refuses_a_leading_zero_a_trailing_comma_and_whitespace_beyond_space_tab_lf_cr() {
    for text in [
        "01",
        "-01",
        "00",
        r#"{"a":01}"#,
        r#"{"a":1,}"#,
        "[1,,2]",
        "[,1]",
        "\u{a0}1",
        "1\u{a0}",
        "[1,\u{a0}2]",
        "\u{feff}1",
        "[1,\u{feff}2]",
        "\u{b}1",
        "\u{c}1",
        "[1\u{2028}]",
        "[1\u{3000}]",
    ] {
        assert_eq!(json::parse(text), None, "{text:?}");
    }
    for text in ["0", "-0", "0.5", "10", "1E2", " \t\n\r[ 1 , 2 ]\r\n\t ", r#"{ "a" : 1 }"#] {
        assert!(json::parse(text).is_some(), "{text:?}");
    }
}
