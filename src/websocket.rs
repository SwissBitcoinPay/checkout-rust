//! WebSockets: to the relays (SPEC.md §13) and to the explorer (SPEC.md §31: mempool.space's, or
//! the merchant's Bitcoin node's, `ws://` in clear to a node on a local network). The opening
//! handshake follows no redirect (a redirect is a failed connection: it would skip the checks of
//! the URL), carries the User-Agent `sattleme-Checkout/1` (some relays refuse a handshake without
//! one, HTTP 403) and offers no compression (permessage-deflate: a few compressed bytes would
//! unpack into many large messages, and sealed records do not compress); a message is at most
//! 1 MiB; the handshake is bounded by `relayTimeoutMs`.
//!
//! The client is injectable ([`WebSocketClient`]). The default one is tokio-tungstenite over
//! rustls (crate::transport).

use std::fmt;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::protocol::{MAX_RELAY_MESSAGE_BYTES, USER_AGENT};
use crate::transport::{BoxFuture, Transport, TransportError};
use crate::web::Target;

/// What the crate opens a WebSocket to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketRequest {
    /// The URL: a checked relay address (`wss://`, SPEC.md §9) or the explorer's WebSocket:
    /// mempool.space's, or the merchant's Bitcoin node's (SPEC.md §31), whose URL follows a rule of
    /// its own: `wss://` to an IPv4 address too, and `ws://` (default port 80) to a host of a
    /// local network (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, a name under
    /// `.local`), never another one. A client that cannot reach such a host fails the connection:
    /// the node's `fallback` then applies.
    pub url: String,
    /// The headers of the opening handshake, sent in place of the client's own:
    /// `User-Agent: sattleme-Checkout/1`.
    pub headers: Vec<(String, String)>,
}

/// An open WebSocket: text messages, in and out. Binary messages a peer sends are read as UTF-8
/// text (dropped when they are not); control frames are the client's.
pub trait WebSocketConnection: Send {
    /// Sends one text message.
    fn send(&mut self, message: String) -> BoxFuture<'_, Result<(), TransportError>>;

    /// The next text message; `None` once the connection is closed. Cancel-safe: dropping the
    /// future before it completes loses no message (the crate waits for a message and for one to
    /// send at once).
    fn receive(&mut self) -> BoxFuture<'_, Option<Result<String, TransportError>>>;
}

/// How the crate opens WebSockets. An implementation follows no redirect, sends the request's
/// headers in its handshake in place of its own, offers no compression, verifies TLS (opens a
/// `ws://` URL, to a merchant's Bitcoin node on a local network, in clear, or fails it), SHOULD
/// refuse a message larger than 1 MiB and bound its handshake. Dropping the returned future must
/// stop the attempt, dropping the connection close it.
pub trait WebSocketClient: Send + Sync {
    /// Opens a WebSocket for `request`.
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>>;
}

/// The request the crate makes for `url`: the User-Agent of every implementation.
pub(crate) fn request_for(url: &str) -> WebSocketRequest {
    WebSocketRequest { url: url.to_owned(), headers: vec![("User-Agent".to_owned(), USER_AGENT.to_owned())] }
}

/// The default client: tokio-tungstenite, over rustls (in clear to a merchant's Bitcoin node on a
/// local network, the one `ws` URL the crate opens).
#[derive(Clone)]
pub(crate) struct DefaultWebSocketClient {
    transport: Transport,
    /// Bounds the whole opening: TCP, TLS and the handshake.
    timeout: Duration,
}

impl fmt::Debug for DefaultWebSocketClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DefaultWebSocketClient").field("timeout", &self.timeout).finish()
    }
}

/// The configuration of every WebSocket: a message and a frame of 1 MiB at most (tungstenite
/// offers no compression: it has no permessage-deflate).
pub(crate) fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_RELAY_MESSAGE_BYTES))
}

impl DefaultWebSocketClient {
    pub(crate) fn new(transport: Transport, timeout: Duration) -> Self {
        Self { transport, timeout }
    }

    async fn open(&self, request: WebSocketRequest) -> Result<Box<dyn WebSocketConnection>, TransportError> {
        // A wss URL; or a merchant's Bitcoin node's WebSocket, `ws` to a local host only.
        let target = Target::of(&request.url)
            .or_else(|| Target::of_node(&request.url))
            .filter(|target| matches!(target.scheme, "wss" | "ws"))
            .ok_or_else(|| TransportError::new("Not a wss URL"))?;
        let mut handshake = target
            .url()
            .into_client_request()
            .map_err(|error| TransportError::with_source("Not a WebSocket URL", error))?;
        for (name, value) in &request.headers {
            let name = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| TransportError::with_source("Invalid header", error))?;
            let value = http::HeaderValue::from_str(value)
                .map_err(|error| TransportError::with_source("Invalid header", error))?;
            handshake.headers_mut().insert(name, value);
        }
        let stream = self.transport.open(&target).await.map_err(|error| {
            TransportError::with_source(format!("No connection to {}", target.host), error)
        })?;
        // A status other than 101 (a redirect included) fails the handshake: never followed.
        let (socket, _) =
            tokio_tungstenite::client_async_with_config(handshake, stream, Some(websocket_config()))
                .await
                .map_err(|error| {
                    TransportError::with_source(format!("No WebSocket from {}", target.host), error)
                })?;
        Ok(Box::new(Tungstenite(socket)))
    }
}

impl WebSocketClient for DefaultWebSocketClient {
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.open(request))
                .await
                .unwrap_or_else(|_| Err(TransportError::new("The WebSocket handshake ran out of time")))
        })
    }
}

/// A tungstenite WebSocket, as text messages.
struct Tungstenite<S>(WebSocketStream<S>);

impl<S> WebSocketConnection for Tungstenite<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    fn send(&mut self, message: String) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            self.0
                .send(Message::text(message))
                .await
                .map_err(|error| TransportError::with_source("The WebSocket failed", error))
        })
    }

    fn receive(&mut self) -> BoxFuture<'_, Option<Result<String, TransportError>>> {
        Box::pin(async move {
            loop {
                match self.0.next().await? {
                    Ok(Message::Text(text)) => return Some(Ok(text.as_str().to_owned())),
                    Ok(Message::Binary(bytes)) => {
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            return Some(Ok(text.to_owned()));
                        }
                    }
                    Ok(Message::Close(_)) => return None,
                    // Pings are answered by tungstenite; pongs and raw frames carry nothing.
                    Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
                    Err(error) => {
                        return Some(Err(TransportError::with_source("The WebSocket failed", error)));
                    }
                }
            }
        })
    }
}
