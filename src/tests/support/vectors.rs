//! The pinned copy of the specification (spec/, PIN.json): its vectors, read with the crate's own
//! JSON reader (so that a lone surrogate escape stays one), never edited here (spec_pin.rs).

use std::path::PathBuf;

use crate::json::{self, Json, JsonString};
use crate::secret::Secret;
use crate::text::from_hex32;

/// The repository's root.
pub(crate) fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A file of the pinned copy of the specification, as JSON (`path` relative to spec/).
pub(crate) fn spec(path: &str) -> Json {
    let full = root().join("spec").join(path);
    let text = std::fs::read_to_string(&full).unwrap_or_else(|error| panic!("{}: {error}", full.display()));
    json::parse(&text).unwrap_or_else(|| panic!("{}: not JSON", full.display()))
}

/// What a test reads of a vector's JSON, failing loudly when a field is not there.
pub(crate) trait Field {
    fn field(&self, name: &str) -> &Json;
    fn text(&self, name: &str) -> &str;
    fn int(&self, name: &str) -> i64;
    fn list(&self, name: &str) -> &[Json];
    fn opt(&self, name: &str) -> Option<&Json>;
    fn opt_text(&self, name: &str) -> Option<&str>;
    fn texts(&self, name: &str) -> Vec<String>;
    fn hex32(&self, name: &str) -> [u8; 32];
    fn secret(&self, name: &str) -> Secret;
    fn digits(&self, name: &str) -> u64;
    fn name(&self) -> String;
}

impl Field for Json {
    fn field(&self, name: &str) -> &Json {
        self.get(name).unwrap_or_else(|| {
            panic!("no {name} in {}", json::stringify(self).chars().take(300).collect::<String>())
        })
    }

    fn text(&self, name: &str) -> &str {
        self.field(name).as_str().unwrap_or_else(|| panic!("{name} is not a text"))
    }

    fn int(&self, name: &str) -> i64 {
        self.field(name).as_safe_integer().unwrap_or_else(|| panic!("{name} is not an integer"))
    }

    fn list(&self, name: &str) -> &[Json] {
        self.field(name).as_array().unwrap_or_else(|| panic!("{name} is not an array"))
    }

    fn opt(&self, name: &str) -> Option<&Json> {
        self.get(name).filter(|value| !value.is_null())
    }

    fn opt_text(&self, name: &str) -> Option<&str> {
        self.opt(name).map(|value| value.as_str().unwrap_or_else(|| panic!("{name} is not a text")))
    }

    fn texts(&self, name: &str) -> Vec<String> {
        self.list(name).iter().map(|item| item.as_str().expect("a text").to_owned()).collect()
    }

    fn hex32(&self, name: &str) -> [u8; 32] {
        from_hex32(self.text(name)).unwrap_or_else(|| panic!("{name} is not hex32"))
    }

    fn secret(&self, name: &str) -> Secret {
        Secret::new(self.hex32(name))
    }

    fn digits(&self, name: &str) -> u64 {
        self.text(name).parse().unwrap_or_else(|_| panic!("{name} is not a string of digits"))
    }

    fn name(&self) -> String {
        self.get("name")
            .and_then(Json::as_str)
            .map_or_else(|| json::stringify(self).chars().take(120).collect(), str::to_owned)
    }
}

/// Whether two JSON values are equal as JavaScript's `toEqual` compares them: objects by their
/// members whatever their order, arrays element by element, numbers by value.
pub(crate) fn same(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Object(a), Json::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(name, value)| b.iter().any(|(other, item)| other == name && same(value, item)))
        }
        (Json::Array(a), Json::Array(b)) => {
            a.as_slice().len() == b.as_slice().len()
                && a.as_slice().iter().zip(b.as_slice()).all(|(a, b)| same(a, b))
        }
        _ => a == b,
    }
}

/// Asserts that `actual` is `expected` (as `same` compares them), showing both.
#[track_caller]
pub(crate) fn assert_same(actual: &Json, expected: &Json, what: &str) {
    assert!(
        same(actual, expected),
        "{what}:\n  actual   {}\n  expected {}",
        json::stringify(actual),
        json::stringify(expected)
    );
}

/// A JSON string.
pub(crate) fn text(value: &str) -> Json {
    Json::String(JsonString::Text(value.to_owned()))
}

/// The JSON of an error as the vectors write it: `{"error": <code>}`, with `param` when it has
/// one.
pub(crate) fn error_json(error: &crate::Error) -> Json {
    match error.param() {
        Some(param) => Json::object([("error", text(error.code().as_str())), ("param", text(param))]),
        None => Json::object([("error", text(error.code().as_str()))]),
    }
}
