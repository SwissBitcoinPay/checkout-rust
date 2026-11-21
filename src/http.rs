//! HTTP (SPEC.md §15): every request a GET with `Accept: application/json` and the User-Agent
//! `sattleme-Checkout/1`, to a checked https URL (or, when the explorer reads a merchant's Bitcoin
//! node, to a URL under its node URL, whose own rule allows `http` to a local host and an IPv4
//! address: SPEC.md §31); no redirect followed (a redirect is no answer);
//! the whole request, body included, bounded by `httpTimeoutMs`; the body read up to 1 MiB, one
//! leading byte order mark ignored; the head (status line, headers, a chunked body's size lines and
//! trailers) bounded too; no answer, `network`.
//!
//! The client is injectable ([`HttpClient`]): for tests, proxies, or to restrict what the server
//! reaches. The default one is hyper's HTTP/1.1 client over rustls (crate::transport), one
//! connection per request, nothing spawned: a request dropped (its call cancelled) is over; in
//! clear HTTP/1.1, over the same hyper client, to a merchant's Bitcoin node on a local network
//! only.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Error;
use crate::json::{self, Json};
use crate::protocol::{MAX_HTTP_ANSWER_BYTES, MAX_HTTP_BODY_BYTES, USER_AGENT};
use crate::transport::{BoxFuture, Stream, Transport, TransportError};
use crate::urls::parse_https_url;
use crate::web::Target;

/// One HTTP GET request of the crate.
#[derive(Clone)]
pub struct HttpRequest {
    /// The URL: a checked `https://` URL, as the WHATWG URL standard writes it (no fragment, no
    /// default port). One exception, a request of the explorer to the merchant's Bitcoin node
    /// (SPEC.md §31), whose URL follows a rule of its own: `https://` to an IPv4 address too, and
    /// `http://` (default port 80) to a host of a local network (10.0.0.0/8, 172.16.0.0/12,
    /// 192.168.0.0/16, 100.64.0.0/10, a name under `.local`), never another one. A client that
    /// cannot reach such a host fails the request: the node's `fallback` then applies.
    pub url: String,
    /// The headers to send, as they are: `Accept: application/json`, `User-Agent:
    /// sattleme-Checkout/1` and, to CoinGecko with a key, `x-cg-demo-api-key`. An injected client
    /// sends them in place of its own.
    pub headers: Vec<(String, String)>,
}

impl fmt::Debug for HttpRequest {
    /// The URL and the headers, but the value of CoinGecko's key header.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let shown = if name.eq_ignore_ascii_case(crate::rates::COINGECKO_KEY_HEADER) {
                    "<redacted>"
                } else {
                    value.as_str()
                };
                (name.as_str(), shown)
            })
            .collect();
        formatter.debug_struct("HttpRequest").field("url", &self.url).field("headers", &headers).finish()
    }
}

/// The body of an answer, read chunk after chunk: the crate stops reading at 1 MiB.
pub trait HttpBody: Send {
    /// The next chunk of the body; `None` at its end.
    fn chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;
}

/// A body held whole.
struct WholeBody(Option<Vec<u8>>);

impl HttpBody for WholeBody {
    fn chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        let chunk = self.0.take();
        Box::pin(async move { Ok(chunk) })
    }
}

/// An answer: its status and its body.
pub struct HttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body.
    pub body: Box<dyn HttpBody>,
}

impl HttpResponse {
    /// An answer whose body comes as `body` reads it.
    pub fn new(status: u16, body: impl HttpBody + 'static) -> Self {
        Self { status, body: Box::new(body) }
    }

    /// An answer whose body is `body`, whole.
    pub fn from_bytes(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(status, WholeBody(Some(body.into())))
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HttpResponse").field("status", &self.status).finish_non_exhaustive()
    }
}

/// How the crate makes HTTP requests: GET only. An implementation follows no redirect (it hands
/// a 3xx answer over as it is, or fails), sends the request's headers in place of its own, and
/// verifies TLS. It sends a request whose URL is `http://` (to a merchant's Bitcoin node on a local
/// network, [`HttpRequest::url`]) in clear HTTP/1.1, or fails it. The crate bounds the whole request by `httpTimeoutMs` (dropping the future when
/// it runs out) and reads at most 1 MiB of the body. Dropping the returned future, or the body,
/// must stop the request.
pub trait HttpClient: Send + Sync {
    /// Sends `request`: its answer once its status and headers came, its body to be read.
    fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>>;
}

/// The default client: hyper's HTTP/1.1, over a TLS connection of its own per request (in clear to
/// a merchant's Bitcoin node on a local network, the one `http` URL the crate asks).
#[derive(Debug, Clone)]
pub(crate) struct DefaultHttpClient {
    transport: Transport,
}

impl DefaultHttpClient {
    pub(crate) fn new(transport: Transport) -> Self {
        Self { transport }
    }

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        // An https URL; or one under a merchant's Bitcoin node's, `http` to a local host only.
        let target = Target::of(&request.url)
            .or_else(|| Target::of_node(&request.url))
            .filter(|target| matches!(target.scheme, "https" | "http"))
            .ok_or_else(|| TransportError::new("Not an https URL"))?;
        let stream = self.transport.open(&target).await.map_err(|error| {
            TransportError::with_source(format!("No connection to {}", target.host), error)
        })?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(Bounded::new(stream)))
                .await
                .map_err(|error| TransportError::with_source("HTTP/1.1 handshake failed", error))?;
        let mut builder =
            hyper::Request::get(target.path_and_query()).header(hyper::header::HOST, target.authority());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let http_request = builder
            .body(Empty::new())
            .map_err(|error| TransportError::with_source("Invalid request", error))?;
        let mut connection = Box::pin(connection);
        let mut answer = std::pin::pin!(sender.send_request(http_request));
        let response = tokio::select! {
            biased;
            response = &mut answer => response,
            result = &mut connection => match result {
                // Closed once it brought the answer (a server that closes after answering), or
                // before it: the answer, or the request's failure.
                Ok(()) => answer.await,
                Err(error) => return Err(TransportError::with_source("The connection failed", error)),
            },
        }
        .map_err(|error| TransportError::with_source("No answer", error))?;
        let status = response.status().as_u16();
        Ok(HttpResponse::new(status, HyperBody { body: response.into_body(), connection: Some(connection) }))
    }
}

type HyperConnection = hyper::client::conn::http1::Connection<TokioIo<Bounded<Stream>>, Empty<Bytes>>;

/// A connection that reads at most [`MAX_HTTP_ANSWER_BYTES`] of the answer: hyper bounds the
/// status line and the headers (some 400 KiB), a chunked body's trailers and chunk extensions (16
/// KiB each), not the rest of its size lines, which it reads byte after byte whatever their length
/// (leading zeros, whitespace after the size). Past the bound the connection fails, and the answer
/// with it (SPEC.md §15, Head).
pub(crate) struct Bounded<S> {
    inner: S,
    read: usize,
}

impl<S> Bounded<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self { inner, read: 0 }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Bounded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(context, buf))?;
        self.read += buf.filled().len() - before;
        if self.read > MAX_HTTP_ANSWER_BYTES {
            return Poll::Ready(Err(io::Error::other("An answer of more than 10 MiB")));
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Bounded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// The body of a hyper answer, with the connection that brings it: polled as the body is read,
/// so that nothing runs once the body is dropped.
struct HyperBody {
    body: Incoming,
    connection: Option<Pin<Box<HyperConnection>>>,
}

impl HttpBody for HyperBody {
    fn chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            loop {
                let Self { body, connection } = self;
                let driving = async {
                    match connection.as_mut() {
                        Some(connection) => connection.await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    frame = body.frame() => {
                        return match frame {
                            None => Ok(None),
                            Some(Err(error)) => Err(TransportError::with_source("The body broke off", error)),
                            Some(Ok(frame)) => match frame.into_data() {
                                Ok(data) => Ok(Some(data.to_vec())),
                                // Trailers: no data.
                                Err(_) => continue,
                            },
                        };
                    }
                    _ = driving => {
                        // Over: what it brought is in the body (or the body fails next).
                        self.connection = None;
                    }
                }
            }
        })
    }
}

impl HttpClient for DefaultHttpClient {
    fn get(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(self.send(request))
    }
}

/// How the crate asks: the client, the timeout of each request (body included).
#[derive(Clone)]
pub(crate) struct Http {
    pub(crate) client: std::sync::Arc<dyn HttpClient>,
    pub(crate) timeout: Duration,
}

/// The host of `url`, for messages: never its path (a Lightning address's name is in it). A
/// merchant's Bitcoin node's host too (its IPv4 address, or a name of its own rule).
pub(crate) fn host_of(url: &str) -> String {
    parse_https_url(url)
        .map(|url| url.host)
        .or_else(|| Target::of_node(url).map(|target| target.host))
        .unwrap_or_else(|| "(invalid URL)".to_owned())
}

/// Which rule the URL of a request follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// An https URL (SPEC.md §15): every request but the explorer's to a merchant's Bitcoin node.
    Https,
    /// A URL under a merchant's Bitcoin node's (SPEC.md §31, A node URL), which the explorer
    /// built from a parsed node URL: `https` to an IPv4 address too, and `http` to a local host.
    Node,
}

/// An answer, its body read.
#[derive(Debug)]
pub(crate) struct Answer<T> {
    pub(crate) status: u16,
    pub(crate) body: T,
}

impl<T> Answer<T> {
    /// A 2xx status.
    pub(crate) fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The text of an HTTP body (SPEC.md §15): UTF-8, one leading byte order mark (EF BB BF) ignored,
/// as WHATWG's UTF-8 decode does; `None` when it is not UTF-8.
pub(crate) fn body_text(bytes: &[u8]) -> Option<&str> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    crate::text::decode_utf8(bytes)
}

impl Http {
    /// GET `url` with `headers` added: the status and the body. `network` when there is no
    /// answer in time, a redirect, or a body larger than 1 MiB. `reach`: the rule of `url`, an
    /// https URL but for the explorer's reads of a merchant's Bitcoin node; a URL that is not of
    /// it is never asked.
    async fn get_bytes(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        reach: Reach,
    ) -> Result<Answer<Vec<u8>>, Error> {
        let host = host_of(url);
        let target = match reach {
            Reach::Https => Target::of(url).filter(|target| target.scheme == "https"),
            Reach::Node => Target::of_node(url).filter(|target| matches!(target.scheme, "https" | "http")),
        }
        .ok_or_else(|| Error::network(format!("No answer from {host}")))?;
        let mut all: Vec<(String, String)> =
            headers.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
        all.push(("Accept".to_owned(), "application/json".to_owned()));
        all.push(("User-Agent".to_owned(), USER_AGENT.to_owned()));
        let request = HttpRequest { url: target.url(), headers: all };
        let read = async {
            let response = self
                .client
                .get(request)
                .await
                .map_err(|error| Error::network(format!("No answer from {host}")).with_source(error))?;
            // An injected client may hand a redirect over: no answer.
            if (300..400).contains(&response.status) {
                return Err(Error::network(format!("{host} answered a redirect (HTTP {})", response.status)));
            }
            let status = response.status;
            let mut body = response.body;
            let mut bytes = Vec::new();
            while let Some(chunk) = body
                .chunk()
                .await
                .map_err(|error| Error::network(format!("No answer from {host}")).with_source(error))?
            {
                if bytes.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
                    return Err(Error::network(format!(
                        "{host} answered more than {MAX_HTTP_BODY_BYTES} bytes"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(Answer { status, body: bytes })
        };
        tokio::time::timeout(self.timeout, read)
            .await
            .unwrap_or_else(|_| Err(Error::network(format!("No answer from {host} in time"))))
    }

    /// GET `url` asking for JSON: the status and the body's value (`None` when it is not JSON in
    /// UTF-8).
    pub(crate) async fn get_json(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<Answer<Option<Json>>, Error> {
        self.get_json_at(url, headers, Reach::Https).await
    }

    /// [`Http::get_json`] of a URL of the rule `reach`.
    pub(crate) async fn get_json_at(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        reach: Reach,
    ) -> Result<Answer<Option<Json>>, Error> {
        let answer = self.get_bytes(url, headers, reach).await?;
        let body = body_text(&answer.body).and_then(json::parse);
        Ok(Answer { status: answer.status, body })
    }

    /// GET `url` (of the rule `reach`) for the one plain-text answer (an explorer's height): the
    /// body as text (`None` when it is not UTF-8).
    pub(crate) async fn get_text(&self, url: &str, reach: Reach) -> Result<Answer<Option<String>>, Error> {
        let answer = self.get_bytes(url, &[], reach).await?;
        let body = body_text(&answer.body).map(str::to_owned);
        Ok(Answer { status: answer.status, body })
    }
}
