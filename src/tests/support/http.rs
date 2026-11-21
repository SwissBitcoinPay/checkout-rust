//! A fake HTTP client: each URL goes to a route, which answers (or does not: no answer). Every
//! request is recorded with its headers.

use std::sync::{Arc, Mutex};

use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::json::{self, Json};
use crate::transport::{BoxFuture, TransportError};

/// What a route answers.
#[derive(Clone, Debug)]
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl Answer {
    /// A 200 with `value` as JSON.
    pub(crate) fn json(value: &Json) -> Self {
        Self { status: 200, body: json::stringify(value).into_bytes() }
    }

    /// `status` with `value` as JSON.
    pub(crate) fn status_json(status: u16, value: &Json) -> Self {
        Self { status, body: json::stringify(value).into_bytes() }
    }

    /// `status` with `text` as it is.
    pub(crate) fn text(status: u16, text: &str) -> Self {
        Self { status, body: text.as_bytes().to_vec() }
    }
}

/// A request the client made.
#[derive(Clone, Debug)]
pub(crate) struct Call {
    pub(crate) url: String,
    pub(crate) headers: Vec<(String, String)>,
}

impl Call {
    /// The URL without its query.
    pub(crate) fn path(&self) -> &str {
        self.url.split_once('?').map_or(self.url.as_str(), |(path, _)| path)
    }

    /// Every query parameter, in order.
    pub(crate) fn params(&self) -> Vec<(String, String)> {
        crate::web::query_parameters(&self.url)
    }

    /// The host of the URL.
    pub(crate) fn host(&self) -> String {
        crate::urls::parse_https_url(&self.url).map(|url| url.host).unwrap_or_default()
    }

    /// The value of the header `name` (its case ignored).
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The value of the query parameter `name`, as `URLSearchParams.get` reads it.
    pub(crate) fn param(&self, name: &str) -> Option<String> {
        crate::web::query_parameter(&self.url, name)
    }
}

type Route = dyn Fn(&Call) -> Option<Answer> + Send + Sync;

/// The fake: `route` answers each request; `None` is no answer (a failed connection).
#[derive(Clone)]
pub(crate) struct FakeHttp {
    route: Arc<Route>,
    pub(crate) calls: Arc<Mutex<Vec<Call>>>,
}

impl FakeHttp {
    pub(crate) fn new(route: impl Fn(&Call) -> Option<Answer> + Send + Sync + 'static) -> Self {
        Self { route: Arc::new(route), calls: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Every request so far.
    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// The `Http` of the crate over this client.
    pub(crate) fn http(&self, timeout_ms: u64) -> crate::http::Http {
        crate::http::Http {
            client: Arc::new(self.clone()),
            timeout: std::time::Duration::from_millis(timeout_ms),
        }
    }
}

impl HttpClient for FakeHttp {
    fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        let call = Call { url: request.url, headers: request.headers };
        self.calls.lock().unwrap().push(call.clone());
        let answer = (self.route)(&call);
        Box::pin(async move {
            match answer {
                Some(answer) => Ok(HttpResponse::from_bytes(answer.status, answer.body)),
                None => Err(TransportError::new(format!("fetch failed: {}", call.url))),
            }
        })
    }
}
