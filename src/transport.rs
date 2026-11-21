//! What the default HTTP and WebSocket clients share (SPEC.md §15, §13): a TCP connection to a
//! host and a port, then TLS, before any request; in clear only to a merchant's Bitcoin node on a
//! local network (SPEC.md §31: an `http` node URL, [`crate::web::Target::of_node`]), the one URL
//! whose rule allows it. TLS is rustls with its `ring` provider, the
//! Mozilla root certificates of `webpki-roots` (the same on every machine: a minimal container
//! has no system store to rely on) and the default protocol versions (TLS 1.2 and 1.3): a host
//! whose certificate does not chain to one of them gets no request. Names are resolved by the
//! system (`getaddrinfo`), never refused here by address (SPEC.md §27: a check before the
//! request is bypassed by a name that resolves again): an integrator who needs to restrict what
//! the server reaches injects its own clients.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// A future of the crate's injectable clients.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a request of an injected HTTP or WebSocket client failed: no connection, no TLS, no
/// answer, a broken stream. The crate reports it as `network`, this error as its source.
pub struct TransportError {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl TransportError {
    /// A failure, said in a sentence (no secret: it may be logged).
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), source: None }
    }

    /// A failure caused by `source`.
    pub fn with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self { message: message.into(), source: Some(source.into()) }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TransportError");
        debug.field("message", &self.message);
        if let Some(source) = &self.source {
            debug.field("source", source);
        }
        debug.finish()
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| &**source as &(dyn std::error::Error + 'static))
    }
}

/// Opens the TCP connection to a host and a port: the system's, or a test's.
pub(crate) trait Dial: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<TcpStream>>;
}

/// The system's: `getaddrinfo`, then the first address that connects.
struct SystemDial;

impl Dial for SystemDial {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<TcpStream>> {
        Box::pin(TcpStream::connect((host, port)))
    }
}

/// TCP then TLS, to the hosts of checked URLs.
#[derive(Clone)]
pub(crate) struct Transport {
    dial: Arc<dyn Dial>,
    tls: TlsConnector,
}

impl fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Transport")
    }
}

/// The TLS configuration of the default clients, made once.
fn default_tls() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            Arc::new(tls_config(roots))
        })
        .clone()
}

/// A client configuration trusting `roots`: rustls's `ring` provider, its default protocol
/// versions, HTTP/1.1 (the WebSocket handshake is one too).
pub(crate) fn tls_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

impl Transport {
    /// The system's resolver and the default TLS configuration.
    pub(crate) fn system() -> Self {
        Self { dial: Arc::new(SystemDial), tls: TlsConnector::from(default_tls()) }
    }

    /// Another dialer and TLS configuration: the tests' (a local server for a real host name).
    #[cfg(test)]
    pub(crate) fn with(dial: Arc<dyn Dial>, tls: Arc<rustls::ClientConfig>) -> Self {
        Self { dial, tls: TlsConnector::from(tls) }
    }

    /// A TLS connection to `host:port`, its certificate checked for `host` (a name, or the IPv4
    /// address of a merchant's Bitcoin node).
    pub(crate) async fn connect(&self, host: &str, port: u16) -> io::Result<TlsStream<TcpStream>> {
        let name = ServerName::try_from(host.to_owned())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let tcp = self.tcp(host, port).await?;
        self.tls.connect(name, tcp).await
    }

    /// The TCP connection to `host:port`.
    async fn tcp(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let tcp = self.dial.dial(host, port).await?;
        // No delay: requests are small, and answers awaited one at a time.
        tcp.set_nodelay(true)?;
        Ok(tcp)
    }

    /// The connection a request to `target` goes over: TLS for `https` and `wss`; in clear for
    /// `http` and `ws`, which only a merchant's Bitcoin node on a local network has (a target of
    /// [`crate::web::Target::of_node`], whose host is then local).
    pub(crate) async fn open(&self, target: &crate::web::Target) -> io::Result<Stream> {
        if target.is_secure() {
            Ok(Stream::Tls(Box::new(self.connect(&target.host, target.port).await?)))
        } else {
            Ok(Stream::Plain(self.tcp(&target.host, target.port).await?))
        }
    }
}

/// A connection of the default clients: TLS, or in clear to a merchant's Bitcoin node on a local
/// network.
pub(crate) enum Stream {
    Tls(Box<TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buf),
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, bytes),
            Self::Plain(stream) => Pin::new(stream).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}
