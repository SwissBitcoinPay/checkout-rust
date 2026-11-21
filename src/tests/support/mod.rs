//! What the tests share: the vectors, and fakes of everything the client reaches (relays, the
//! Lightning address, the rate sources, the explorers), reached through the injected HTTP and
//! WebSocket clients with their real host names, never the network.

pub(crate) mod chain;
pub(crate) mod http;
pub(crate) mod lightning;
pub(crate) mod merchant;
pub(crate) mod owner;
pub(crate) mod random;
pub(crate) mod relay;
pub(crate) mod vectors;

use crate::json::Json;

/// The crate's JSON of a `serde_json` value (an object's members in the order of serde_json's
/// map: by name).
pub(crate) fn js(value: serde_json::Value) -> Json {
    serde_json::from_value(value).expect("serde_json's values are JSON")
}

/// The crate's JSON of a JSON literal, as `serde_json::json!` writes it.
macro_rules! j {
    ($($json:tt)+) => {
        $crate::tests::support::js(::serde_json::json!($($json)+))
    };
}
pub(crate) use j;

/// Whether a type implements serde's `Serialize`, told by the compiler ([`serializes!`]): the
/// inherent method exists only where its bound holds, and is then found before the trait's.
pub(crate) struct Probe<T>(pub(crate) std::marker::PhantomData<T>);

pub(crate) trait Unserializable {
    fn serializes(&self) -> bool {
        false
    }
}

impl<T> Unserializable for Probe<T> {}

impl<T: serde::Serialize> Probe<T> {
    pub(crate) fn serializes(&self) -> bool {
        true
    }
}

/// Whether the type `$type` implements serde's `Serialize`.
macro_rules! serializes {
    ($type:ty) => {{
        #[allow(unused_imports)]
        use $crate::tests::support::Unserializable as _;
        $crate::tests::support::Probe::<$type>(::std::marker::PhantomData).serializes()
    }};
}
pub(crate) use serializes;

/// `base` with the members of `extra` (an object): each in place of the member of its name, the
/// others after, as JavaScript's `{ ...base, ...extra }`.
pub(crate) fn merged(base: &Json, extra: &Json) -> Json {
    let mut members: Vec<(crate::json::JsonString, Json)> = base
        .as_object()
        .map(|object| object.iter().map(|(name, value)| (name.clone(), value.clone())).collect())
        .unwrap_or_default();
    if let Some(extra) = extra.as_object() {
        for (name, value) in extra.iter() {
            match members.iter().position(|(member, _)| member == name) {
                Some(index) => members[index].1 = value.clone(),
                None => members.push((name.clone(), value.clone())),
            }
        }
    }
    Json::Object(crate::json::JsonObject::new(members))
}

pub(crate) mod rates {
    //! Custom rate sources for tests.

    use crate::error::Error;
    use crate::rates::{CustomPrice, CustomRateError, CustomRateSource, RateSource};
    use crate::transport::BoxFuture;

    /// A source that always gives `price`, undated.
    pub(crate) struct Price(pub(crate) String);

    impl CustomRateSource for Price {
        fn price<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>> {
            Box::pin(async move { Ok(CustomPrice::from(self.0.as_str())) })
        }
    }

    /// The custom source of a fixed price.
    pub(crate) fn price(price: &str) -> RateSource {
        RateSource::custom(Price(price.to_owned()))
    }

    /// A source that fails with `error`.
    pub(crate) struct Failing(pub(crate) Error);

    impl CustomRateSource for Failing {
        fn price<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>> {
            Box::pin(async move { Err(Box::new(self.0.clone()) as CustomRateError) })
        }
    }
}
