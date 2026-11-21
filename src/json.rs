//! JSON as every implementation reads and writes it (SPEC.md §2): RFC 8259, read as JavaScript's
//! `JSON.parse` reads it, written as `JSON.stringify` writes it.
//!
//! - Of members with one name, the last counts (names that differ in case are different names).
//! - A number is its value as an IEEE 754 double, whatever its spelling: `500`, `500.0` and `5e2`
//!   are all 500. A boolean is never a number.
//! - A string keeps a lone surrogate escape (`"\ud800"`) as it is, so that a text holding one stays
//!   detectable wherever the specification checks a text (SPEC.md §6). `serde_json` refuses the
//!   whole document instead (a member nobody reads would then hide every other one): this reader
//!   is the crate's own, for everything a relay, a service or a vector file sends.
//! - A number of any length is a double: an integer of 5 000 digits, `1e400` (`Infinity`) and
//!   `-1e400` are numbers (none an integer: `Number.isInteger` refuses an infinity). RFC 8259's
//!   grammar holds: no leading zero, no trailing comma, no whitespace but space, tab, line feed and
//!   carriage return (neither U+00A0 nor U+FEFF), a member name any string (U+0000 included).
//! - A text nested more than 64 deep, arrays and objects counted together, is no JSON: a scan of
//!   the text tells, before it is read ([`MAX_JSON_DEPTH`]), the same in every implementation
//!   whatever its platform's reader takes (V8 reads a document a million levels deep).

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;

use num_bigint::BigUint;

use crate::protocol::{MAX_JSON_DEPTH, MAX_SAFE_INTEGER};

/// A JSON value, as `JSON.parse` gives it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(JsonString),
    Array(JsonArray),
    Object(JsonObject),
}

/// A JSON string: text, or UTF-16 code units when it holds a lone surrogate (which no Rust
/// `String` can hold). One string has one representation, so `==` is JavaScript's `===`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum JsonString {
    /// Well-formed: every code point a Unicode scalar value.
    Text(String),
    /// Holds at least one lone surrogate (SPEC.md §6): never a text.
    Units(Vec<u16>),
}

/// The elements of a JSON array. Dropped without recursion, however deep.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct JsonArray(Vec<Json>);

/// The members of a JSON object, in the order their names first appear, each name once with
/// the last value written for it (`JSON.parse`). Dropped without recursion, however deep.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct JsonObject(Vec<(JsonString, Json)>);

impl JsonString {
    /// The text, unless it holds a lone surrogate.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Units(_) => None,
        }
    }

    /// The text, a lone surrogate written U+FFFD: for messages and for what is only shown.
    pub(crate) fn to_string_lossy(&self) -> Cow<'_, str> {
        match self {
            Self::Text(text) => Cow::Borrowed(text),
            Self::Units(units) => Cow::Owned(String::from_utf16_lossy(units)),
        }
    }

    /// Its length in UTF-16 code units, as JavaScript's `length` counts it.
    pub(crate) fn utf16_len(&self) -> usize {
        match self {
            Self::Text(text) => text.encode_utf16().count(),
            Self::Units(units) => units.len(),
        }
    }
}

impl JsonArray {
    pub(crate) fn new(items: Vec<Json>) -> Self {
        Self(items)
    }

    pub(crate) fn as_slice(&self) -> &[Json] {
        &self.0
    }
}

impl JsonObject {
    /// An object of `members`, which have distinct names.
    pub(crate) fn new(members: Vec<(JsonString, Json)>) -> Self {
        Self(members)
    }

    /// The value of the member `name`, if any.
    pub(crate) fn get(&self, name: &str) -> Option<&Json> {
        self.0.iter().find(|(key, _)| key.as_str() == Some(name)).map(|(_, value)| value)
    }

    /// The members, in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&JsonString, &Json)> {
        self.0.iter().map(|(key, value)| (key, value))
    }

    /// How many members (distinct names) it has.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

/// Moves the children of the values of `stack` into it until none is left, so that a deep
/// value is freed with a heap stack rather than a recursion of the thread's stack.
fn drop_iteratively(mut stack: Vec<Json>) {
    while let Some(value) = stack.pop() {
        match value {
            Json::Array(mut array) => stack.append(&mut array.0),
            Json::Object(mut object) => stack.extend(object.0.drain(..).map(|(_, value)| value)),
            _ => {}
        }
    }
}

impl Drop for JsonArray {
    fn drop(&mut self) {
        if self.0.iter().any(is_container) {
            drop_iteratively(std::mem::take(&mut self.0));
        }
    }
}

impl Drop for JsonObject {
    fn drop(&mut self) {
        if self.0.iter().any(|(_, value)| is_container(value)) {
            drop_iteratively(self.0.drain(..).map(|(_, value)| value).collect());
        }
    }
}

fn is_container(value: &Json) -> bool {
    matches!(value, Json::Array(_) | Json::Object(_))
}

impl Json {
    /// The member `name` of an object; `None` for another value or an absent member.
    pub(crate) fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Self::Object(object) => object.get(name),
            _ => None,
        }
    }

    /// Whether this is an object holding a member `name` (whatever its value): JavaScript's `in`.
    pub(crate) fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub(crate) fn as_object(&self) -> Option<&JsonObject> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    pub(crate) fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub(crate) fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(array) => Some(array.as_slice()),
            _ => None,
        }
    }

    /// The string, well-formed or not (JavaScript's `typeof value === "string"`).
    pub(crate) fn as_json_string(&self) -> Option<&JsonString> {
        match self {
            Self::String(string) => Some(string),
            _ => None,
        }
    }

    /// Whether it is a string, well-formed or not.
    #[cfg(test)]
    pub(crate) fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// The text of a string that holds no lone surrogate.
    pub(crate) fn as_str(&self) -> Option<&str> {
        self.as_json_string().and_then(JsonString::as_str)
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The number (a boolean is never one).
    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// The value of a number that is an integer, however large (`Number.isInteger`).
    pub(crate) fn as_integer(&self) -> Option<f64> {
        self.as_f64().filter(|value| value.is_finite() && value.fract() == 0.0)
    }

    /// The value of a number that is a safe integer, ±(2^53 − 1) at most (`Number.isSafeInteger`).
    pub(crate) fn as_safe_integer(&self) -> Option<i64> {
        self.as_integer()
            .filter(|value| value.abs() <= MAX_SAFE_INTEGER as f64)
            // Exact: a safe integer is a double without a fraction.
            .map(|value| value as i64)
    }

    /// Whether this is the number `value` (JavaScript's `===` with a number).
    pub(crate) fn is_number(&self, value: f64) -> bool {
        self.as_f64() == Some(value)
    }

    /// An object of `members` (distinct names), in their order.
    pub(crate) fn object<const N: usize>(members: [(&str, Json); N]) -> Json {
        Json::Object(JsonObject::new(
            members.into_iter().map(|(name, value)| (JsonString::Text(name.to_owned()), value)).collect(),
        ))
    }

    /// An object of `members` (distinct names), in their order.
    pub(crate) fn object_of(members: Vec<(&str, Json)>) -> Json {
        Json::Object(JsonObject::new(
            members.into_iter().map(|(name, value)| (JsonString::Text(name.to_owned()), value)).collect(),
        ))
    }

    pub(crate) fn array(items: Vec<Json>) -> Json {
        Json::Array(JsonArray::new(items))
    }

    /// The number of an integer the JSON writes exactly (|value| ≤ 2^53 − 1).
    pub(crate) fn integer(value: i64) -> Json {
        debug_assert!(value.unsigned_abs() <= MAX_SAFE_INTEGER as u64);
        Json::Number(value as f64)
    }

    /// The number of a count the JSON writes exactly (≤ 2^53 − 1).
    pub(crate) fn unsigned(value: u64) -> Json {
        debug_assert!(value <= MAX_SAFE_INTEGER as u64);
        Json::Number(value as f64)
    }

    /// A string, or null.
    pub(crate) fn optional_str(value: Option<&str>) -> Json {
        value.map_or(Json::Null, Json::from)
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Json::String(JsonString::Text(value.to_owned()))
    }
}

impl From<String> for Json {
    fn from(value: String) -> Self {
        Json::String(JsonString::Text(value))
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Json::Bool(value)
    }
}

impl From<Vec<Json>> for Json {
    fn from(items: Vec<Json>) -> Self {
        Json::array(items)
    }
}

/// The value of a JSON text (RFC 8259, as `JSON.parse` reads it); `None` when it is not JSON,
/// one nested more than 64 deep included.
pub(crate) fn parse(text: &str) -> Option<Json> {
    if !nests_within(text.as_bytes(), MAX_JSON_DEPTH) {
        return None;
    }
    Parser { bytes: text.as_bytes(), text, pos: 0 }.document()
}

/// Whether `text` nests at most `depth` deep (SPEC.md §2): outside strings, each `[` and `{`
/// opens a level and each `]` and `}` closes one. A scan before the text is read, so that the
/// depth is told the same whatever the reader; of a text that is no JSON anyway, it tells nothing
/// that matters.
pub(crate) fn nests_within(text: &[u8], depth: usize) -> bool {
    let mut level = 0usize;
    let mut index = 0;
    while index < text.len() {
        match text[index] {
            b'"' => {
                // A string: to its closing quote, an escape's character skipped.
                index += 1;
                while index < text.len() && text[index] != b'"' {
                    index += if text[index] == b'\\' { 2 } else { 1 };
                }
            }
            b'[' | b'{' => {
                level += 1;
                if level > depth {
                    return false;
                }
            }
            b']' | b'}' => level = level.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    true
}

/// An array or an object being read: the reader's stack, on the heap.
enum Frame {
    Array(Vec<Json>),
    Object { members: Vec<(JsonString, Json)>, index: HashMap<JsonString, usize>, name: JsonString },
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn document(&mut self) -> Option<Json> {
        let mut stack: Vec<Frame> = Vec::new();
        'value: loop {
            self.whitespace();
            let mut value = match *self.bytes.get(self.pos)? {
                b'[' => {
                    self.pos += 1;
                    self.whitespace();
                    if self.eat(b']') {
                        Json::Array(JsonArray::default())
                    } else {
                        stack.push(Frame::Array(Vec::new()));
                        continue 'value;
                    }
                }
                b'{' => {
                    self.pos += 1;
                    self.whitespace();
                    if self.eat(b'}') {
                        Json::Object(JsonObject::default())
                    } else {
                        let name = self.member_name()?;
                        stack.push(Frame::Object { members: Vec::new(), index: HashMap::new(), name });
                        continue 'value;
                    }
                }
                b'"' => Json::String(self.string()?),
                b't' => self.literal("true", Json::Bool(true))?,
                b'f' => self.literal("false", Json::Bool(false))?,
                b'n' => self.literal("null", Json::Null)?,
                b'-' | b'0'..=b'9' => Json::Number(self.number()?),
                _ => return None,
            };
            // The value is complete: into its array or object, which may be complete in turn.
            loop {
                let Some(frame) = stack.last_mut() else {
                    self.whitespace();
                    return (self.pos == self.bytes.len()).then_some(value);
                };
                self.whitespace();
                match frame {
                    Frame::Array(items) => {
                        items.push(value);
                        if self.eat(b',') {
                            continue 'value;
                        }
                        if !self.eat(b']') {
                            return None;
                        }
                        let Some(Frame::Array(items)) = stack.pop() else { unreachable!() };
                        value = Json::Array(JsonArray::new(items));
                    }
                    Frame::Object { members, index, name } => {
                        let name = std::mem::replace(name, JsonString::Text(String::new()));
                        // Of members with one name, the last value counts, at the first one's place.
                        match index.get(&name) {
                            Some(&at) => members[at].1 = value,
                            None => {
                                index.insert(name.clone(), members.len());
                                members.push((name, value));
                            }
                        }
                        if self.eat(b',') {
                            self.whitespace();
                            let next = self.member_name()?;
                            if let Some(Frame::Object { name, .. }) = stack.last_mut() {
                                *name = next;
                            }
                            continue 'value;
                        }
                        if !self.eat(b'}') {
                            return None;
                        }
                        let Some(Frame::Object { members, .. }) = stack.pop() else { unreachable!() };
                        value = Json::Object(JsonObject::new(members));
                    }
                }
            }
        }
    }

    /// A member's name and its `:`.
    fn member_name(&mut self) -> Option<JsonString> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return None;
        }
        let name = self.string()?;
        self.whitespace();
        self.eat(b':').then_some(name)
    }

    fn whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Option<Json> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Some(value)
        } else {
            None
        }
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, as the nearest double (correctly
    /// rounded, as every JSON reader of JavaScript rounds it).
    fn number(&mut self) -> Option<f64> {
        let start = self.pos;
        self.eat(b'-');
        match self.bytes.get(self.pos)? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => self.digits(),
            _ => return None,
        }
        if self.eat(b'.') {
            if !self.bytes.get(self.pos)?.is_ascii_digit() {
                return None;
            }
            self.digits();
        }
        if let Some(b'e' | b'E') = self.bytes.get(self.pos) {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.bytes.get(self.pos) {
                self.pos += 1;
            }
            if !self.bytes.get(self.pos)?.is_ascii_digit() {
                return None;
            }
            self.digits();
        }
        self.text[start..self.pos].parse::<f64>().ok()
    }

    fn digits(&mut self) {
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
    }

    /// A string, from its opening quote: escapes read as UTF-16 code units, a pair of
    /// surrogates as its character, a lone one kept (`Units`).
    fn string(&mut self) -> Option<JsonString> {
        self.pos += 1;
        let mut text = String::new();
        let mut units: Option<Vec<u16>> = None;
        loop {
            let run = self.pos;
            while let Some(&byte) = self.bytes.get(self.pos) {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            let raw = &self.text[run..self.pos];
            match &mut units {
                Some(units) => units.extend(raw.encode_utf16()),
                None => text.push_str(raw),
            }
            match *self.bytes.get(self.pos)? {
                b'"' => {
                    self.pos += 1;
                    return Some(match units {
                        Some(units) => JsonString::Units(units),
                        None => JsonString::Text(text),
                    });
                }
                b'\\' => {
                    self.pos += 1;
                    let escaped = *self.bytes.get(self.pos)?;
                    self.pos += 1;
                    let unit = match escaped {
                        b'"' => u16::from(b'"'),
                        b'\\' => u16::from(b'\\'),
                        b'/' => u16::from(b'/'),
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => u16::from(b'\n'),
                        b'r' => u16::from(b'\r'),
                        b't' => u16::from(b'\t'),
                        b'u' => self.hex_unit()?,
                        _ => return None,
                    };
                    let character = if (0xd800..0xdc00).contains(&unit) {
                        // A high surrogate: a pair with the escape of a low one right after it.
                        let pair = self.bytes[self.pos..].starts_with(b"\\u").then(|| {
                            let save = self.pos;
                            self.pos += 2;
                            match self.hex_unit() {
                                Some(low) if (0xdc00..0xe000).contains(&low) => Some(low),
                                _ => {
                                    self.pos = save;
                                    None
                                }
                            }
                        });
                        pair.flatten().map(|low| {
                            let code =
                                0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                            char::from_u32(code).expect("a pair of surrogates is a character")
                        })
                    } else {
                        char::from_u32(u32::from(unit))
                    };
                    match (character, &mut units) {
                        (Some(character), Some(units)) => {
                            let mut buffer = [0u16; 2];
                            units.extend_from_slice(character.encode_utf16(&mut buffer));
                        }
                        (Some(character), None) => text.push(character),
                        (None, Some(units)) => units.push(unit),
                        (None, None) => {
                            // The first lone surrogate: the string is code units from now on.
                            let mut all: Vec<u16> = text.encode_utf16().collect();
                            all.push(unit);
                            units = Some(all);
                        }
                    }
                }
                // A control character must be escaped.
                _ => return None,
            }
        }
    }

    /// Four hex digits (either case) after `\u`.
    fn hex_unit(&mut self) -> Option<u16> {
        let digits = self.bytes.get(self.pos..self.pos + 4)?;
        let mut unit: u16 = 0;
        for &digit in digits {
            unit = unit * 16 + char::from(digit).to_digit(16)? as u16;
        }
        self.pos += 4;
        Some(unit)
    }
}

/// `value` as `JSON.stringify` writes it: no whitespace, members in their order, strings with
/// JSON's escapes only (`"`, `\`, control characters, lone surrogates), numbers as JavaScript
/// writes them. Values given to it are the crate's own or checked events: shallow.
pub(crate) fn stringify(value: &Json) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Json) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        // JSON has no NaN nor infinity: `JSON.stringify` writes null.
        Json::Number(number) if !number.is_finite() => out.push_str("null"),
        Json::Number(number) => out.push_str(&number_to_string(*number)),
        Json::String(string) => write_string(out, string),
        Json::Array(array) => {
            out.push('[');
            for (index, item) in array.as_slice().iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Json::Object(object) => {
            out.push('{');
            for (index, (name, item)) in object.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, name);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

/// A string as `JSON.stringify` quotes it (ECMAScript QuoteJSONString).
pub(crate) fn write_string(out: &mut String, string: &JsonString) {
    out.push('"');
    match string {
        JsonString::Text(text) => {
            for character in text.chars() {
                write_character(out, character);
            }
        }
        JsonString::Units(units) => {
            for decoded in char::decode_utf16(units.iter().copied()) {
                match decoded {
                    Ok(character) => write_character(out, character),
                    Err(lone) => {
                        let _ = write!(out, "\\u{:04x}", lone.unpaired_surrogate());
                    }
                }
            }
        }
    }
    out.push('"');
}

fn write_character(out: &mut String, character: char) {
    match character {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        control if u32::from(control) < 0x20 => {
            let _ = write!(out, "\\u{:04x}", u32::from(control));
        }
        other => out.push(other),
    }
}

/// A number as JavaScript writes it (ECMAScript `Number::toString`): the shortest decimal that
/// reads back as the same double, of two such the nearer to it, of two as near the one whose last
/// digit is even; plain from 10^-7 to below 10^21, with an exponent otherwise (`1e+21`, `1e-7`).
/// Also what a price given as a JSON number is read as (SPEC.md §25).
pub(crate) fn number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if value < 0.0 {
        return format!("-{}", number_to_string(-value));
    }
    // Rust writes the shortest digits that read back as the same double, the nearest to it; of two
    // as near, the upper one.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("a finite double has an exponent");
    let digits: String = mantissa.chars().filter(|&c| c != '.').collect();
    let exponent: i64 = exponent.parse().expect("an exponent is an integer");
    let digits = even_of_a_tie(value, digits, exponent);
    let k = digits.len() as i64;
    let n = exponent + 1;
    if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e >= 0 { '+' } else { '-' };
        if k == 1 {
            format!("{digits}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    }
}

/// Of the shortest `digits` of the positive finite `value` (the first of them at the power of ten
/// `exponent`), the spelling whose last digit is even when another of their length is exactly as
/// near to `value` and reads back as it too (ECMA-262 Number::toString, step 5:
/// `1660867710597813.25` is `…813.2`, never `…813.3`); `digits` otherwise.
fn even_of_a_tie(value: f64, digits: String, exponent: i64) -> String {
    // An integer below 2^53 is its own shortest decimal, at no distance: no tie.
    let last = digits.as_bytes()[digits.len() - 1] - b'0';
    if last.is_multiple_of(2) || (value.fract() == 0.0 && value < 9_007_199_254_740_992.0) {
        return digits;
    }
    let shortest: u64 = digits.parse().expect("at most 17 digits");
    // The power of ten of the last digit.
    let power = exponent - (digits.len() as i64 - 1);
    // `value` is exactly m × 2^q.
    let bits = value.to_bits();
    let biased = ((bits >> 52) & 0x7ff) as i64;
    let fraction = bits & ((1 << 52) - 1);
    let (m, q) = if biased == 0 { (fraction, -1074) } else { (fraction | (1 << 52), biased - 1075) };
    for other in [shortest - 1, shortest + 1] {
        // At the middle of the two: m × 2^(q+1) = (shortest + other) × 10^power.
        let mut left = BigUint::from(m);
        let mut right = BigUint::from(shortest + other);
        if q + 1 >= 0 {
            left <<= (q + 1) as u64;
        } else {
            right <<= (-(q + 1)) as u64;
        }
        let ten = BigUint::from(10u32);
        if power >= 0 {
            right *= ten.pow(power as u32);
        } else {
            left *= ten.pow((-power) as u32);
        }
        if left != right {
            continue;
        }
        let spelled = other.to_string();
        // One of the same length that reads back as `value` (a shorter one would have been given).
        if spelled.len() == digits.len()
            && !spelled.ends_with('0')
            && format!("{spelled}e{power}").parse::<f64>() == Ok(value)
        {
            return spelled;
        }
    }
    digits
}

impl<'de> serde::Deserialize<'de> for Json {
    /// A value of another format serde reads (a stored invoice in `serde_json`), as `JSON.parse`
    /// would: numbers as doubles, the last member of a name, 64 levels of arrays and objects at
    /// most. The reader of that format decides the rest: `serde_json` refuses a lone surrogate
    /// escape anywhere in the document, and a number beyond a double (`1e400`), which `JSON.parse`
    /// reads as `Infinity` (the crate's own reader, `from_json`, as well).
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::DeserializeSeed::deserialize(JsonSeed { depth: 0 }, deserializer)
    }
}

/// A value inside `depth` levels of arrays and objects: one more than 64 is no JSON (SPEC.md §2).
#[derive(Clone, Copy)]
struct JsonSeed {
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for JsonSeed {
    type Value = Json;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(JsonVisitor { depth: self.depth })
    }
}

struct JsonVisitor {
    depth: usize,
}

impl JsonVisitor {
    /// The depth of an array or an object read here: an error past 64.
    fn level<E: serde::de::Error>(&self) -> Result<JsonSeed, E> {
        let depth = self.depth + 1;
        if depth > MAX_JSON_DEPTH {
            return Err(E::custom(format_args!("nested more than {MAX_JSON_DEPTH} deep: not JSON")));
        }
        Ok(JsonSeed { depth })
    }
}

impl<'de> serde::de::Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Number(value as f64))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(Json::Number(value as f64))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Json, E> {
        Ok(Json::Number(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(Json::from(value))
    }

    fn visit_string<E>(self, value: String) -> Result<Json, E> {
        Ok(Json::from(value))
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        serde::de::DeserializeSeed::deserialize(JsonSeed { depth: self.depth }, deserializer)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let seed = self.level()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(seed)? {
            items.push(item);
        }
        Ok(Json::array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let seed = self.level()?;
        let mut members: Vec<(JsonString, Json)> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        while let Some(name) = map.next_key::<String>()? {
            let value = map.next_value_seed(seed)?;
            // Of members with one name, the last value counts, at the first one's place.
            match index.get(&name) {
                Some(&at) => members[at].1 = value,
                None => {
                    index.insert(name.clone(), members.len());
                    members.push((JsonString::Text(name), value));
                }
            }
        }
        Ok(Json::Object(JsonObject::new(members)))
    }
}

impl serde::Serialize for Json {
    /// The value in another format serde writes (`serde_json`), as `JSON.stringify` would: an
    /// integer as an integer (`1791378280`, never `1791378280.0`), the members in their order.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Json::Null => serializer.serialize_unit(),
            Json::Bool(value) => serializer.serialize_bool(*value),
            Json::Number(value)
                if value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_SAFE_INTEGER as f64 =>
            {
                serializer.serialize_i64(*value as i64)
            }
            Json::Number(value) if value.is_finite() => serializer.serialize_f64(*value),
            // JSON has no NaN nor infinity: `JSON.stringify` writes null.
            Json::Number(_) => serializer.serialize_unit(),
            Json::String(string) => serializer.serialize_str(&string.to_string_lossy()),
            Json::Array(array) => {
                let mut sequence = serializer.serialize_seq(Some(array.as_slice().len()))?;
                for item in array.as_slice() {
                    sequence.serialize_element(item)?;
                }
                sequence.end()
            }
            Json::Object(object) => {
                let mut map = serializer.serialize_map(Some(object.len()))?;
                for (name, value) in object.iter() {
                    map.serialize_entry(&*name.to_string_lossy(), value)?;
                }
                map.end()
            }
        }
    }
}
