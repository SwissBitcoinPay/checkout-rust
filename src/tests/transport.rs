//! The default HTTP and WebSocket clients over real sockets (SPEC.md §13, §15): local TLS servers
//! of a test certificate authority, reached under the real host names through a test dialer.
//! Every WebSocket handshake carries the User-Agent (relays and the explorer's WebSocket), offers
//! no compression and follows no redirect; a message above 1 MiB is refused; the handshake is
//! bounded; TLS is verified. Every HTTP request carries the crate's headers alone, follows no
//! redirect, and its body is bounded. A merchant's Bitcoin node (SPEC.md §31) is asked under the
//! same rules, in clear HTTP/1.1 and WebSocket to a host of a local network only, never to another
//! host, and over TLS verified for its IPv4 address.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use super::support::j;
use super::support::merchant::TestMerchant;
use crate::http::{DefaultHttpClient, Http, HttpClient, HttpRequest, Reach};
use crate::order::Order;
use crate::protocol::{MEMPOOL_WEBSOCKET_URL, USER_AGENT};
use crate::transport::{BoxFuture, Dial, Transport, tls_config};
use crate::websocket::{DefaultWebSocketClient, WebSocketClient, request_for};

/// A test certificate authority and a server certificate it signed for the hosts the tests reach.
struct TestTls {
    roots: rustls::RootCertStore,
    server: Arc<rustls::ServerConfig>,
}

fn test_tls() -> TestTls {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    // The IPv4 address of a merchant's Bitcoin node of the Internet too (SPEC.md §31).
    let names = ["relay.test", "mempool.space", "breez.tips", "203.0.113.5"].map(str::to_owned).to_vec();
    let leaf = CertificateParams::new(names).unwrap().signed_by(&leaf_key, &ca).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let server =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], key)
            .unwrap();
    TestTls { roots, server: Arc::new(server) }
}

/// Every host to the local port of the test's server.
struct ToLocal(u16);

impl Dial for ToLocal {
    fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<TcpStream>> {
        Box::pin(TcpStream::connect(("127.0.0.1", self.0)))
    }
}

/// A transport to `port`, trusting the test authority alone.
fn transport(port: u16, tls: &TestTls) -> Transport {
    Transport::with(Arc::new(ToLocal(port)), Arc::new(tls_config(tls.roots.clone())))
}

/// A transport to `port`, trusting the Mozilla roots of the default clients.
fn default_roots(port: u16) -> Transport {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    Transport::with(Arc::new(ToLocal(port)), Arc::new(tls_config(roots)))
}

async fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// What a WebSocket server heard of the handshake: its path and headers.
type Heard = (String, Vec<(String, String)>);

/// A WebSocket server that accepts one connection, tells what its handshake said, then sends
/// `messages` and waits.
async fn websocket_server(tls: &TestTls, messages: Vec<String>) -> (u16, oneshot::Receiver<Heard>) {
    let (listener, port) = listener().await;
    let acceptor = TlsAcceptor::from(tls.server.clone());
    let (heard, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(tcp).await.unwrap();
        #[expect(
            clippy::result_large_err,
            reason = "tungstenite's handshake callback: its error is an answer"
        )]
        let callback = move |request: &Request, response: Response| {
            let headers = request
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or("").to_owned()))
                .collect();
            let _ = heard.send((request.uri().to_string(), headers));
            Ok(response)
        };
        let mut socket = tokio_tungstenite::accept_hdr_async(stream, callback).await.unwrap();
        for message in messages {
            if socket.send(Message::text(message)).await.is_err() {
                return;
            }
        }
        // Until the client leaves.
        while let Some(Ok(_)) = socket.next().await {}
    });
    (port, receiver)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn a_websocket_handshake_carries_the_user_agent_to_a_relay_and_to_the_explorer_and_offers_no_compression()
 {
    let tls = test_tls();
    for url in ["wss://relay.test", MEMPOOL_WEBSOCKET_URL] {
        let (port, heard) = websocket_server(&tls, vec!["[\"NOTICE\",\"hello\"]".to_owned()]).await;
        let client = DefaultWebSocketClient::new(transport(port, &tls), Duration::from_secs(5));
        let mut socket = client.connect(request_for(url)).await.unwrap();
        assert_eq!(socket.receive().await.unwrap().unwrap(), "[\"NOTICE\",\"hello\"]");
        let (path, headers) = heard.await.unwrap();
        // Relays behind a bot protection (Cloudflare's, nostr.wine's) refuse a handshake without
        // one, HTTP 403.
        assert_eq!(header(&headers, "user-agent"), Some(USER_AGENT), "{url}");
        assert_eq!(header(&headers, "sec-websocket-extensions"), None, "{url}: no permessage-deflate");
        let expected_path = if url == MEMPOOL_WEBSOCKET_URL { "/api/v1/ws" } else { "/" };
        assert_eq!(path, expected_path);
        let host = url.strip_prefix("wss://").unwrap().split('/').next().unwrap();
        assert_eq!(header(&headers, "host"), Some(host));
    }
}

#[tokio::test(start_paused = true)]
async fn every_websocket_handshake_of_a_client_carries_the_user_agent() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    let lot = vec![super::support::chain::deposit_address(1)];
    merchant.publish_lot(&lot, 90);
    let _socket = merchant.start_explorer_socket();
    let client = merchant.client().build().unwrap();
    let invoice = client.create_invoice(&Order::sats("U-1", 49_000)).await.unwrap();
    assert!(invoice.onchain_address.is_some());
    let wait = client.wait_for_payment(&invoice, crate::client::WaitOptions::default());
    assert!(tokio::time::timeout(Duration::from_millis(100), wait).await.is_err());
    let handshakes = merchant.net.handshakes();
    assert!(handshakes.iter().any(|request| request.url == MEMPOOL_WEBSOCKET_URL));
    assert!(handshakes.iter().filter(|request| request.url.starts_with("wss://relay-")).count() >= 3);
    for request in handshakes {
        assert_eq!(
            request.headers,
            vec![("User-Agent".to_owned(), USER_AGENT.to_owned())],
            "{}",
            request.url
        );
    }
}

#[tokio::test]
async fn a_websocket_handshake_follows_no_redirect() {
    let tls = test_tls();
    let (listener, port) = listener().await;
    let acceptor = TlsAcceptor::from(tls.server.clone());
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.unwrap();
        let mut buffer = vec![0u8; 4096];
        let _ = stream.read(&mut buffer).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: wss://relay.test/elsewhere\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        let _ = stream.flush().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let client = DefaultWebSocketClient::new(transport(port, &tls), Duration::from_secs(5));
    let started = Instant::now();
    let error = client.connect(request_for("wss://relay.test")).await.err().expect("a failed connection");
    // Failed at the redirect, not at the timeout.
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert!(error.to_string().contains("No WebSocket"), "{error}");
}

#[tokio::test]
async fn a_websocket_message_above_1_mib_is_refused() {
    let tls = test_tls();
    let at_most = "a".repeat(1 << 20);
    let above = "a".repeat((1 << 20) + 1);
    let (port, _) = websocket_server(&tls, vec![at_most.clone(), above]).await;
    let client = DefaultWebSocketClient::new(transport(port, &tls), Duration::from_secs(5));
    let mut socket = client.connect(request_for("wss://relay.test")).await.unwrap();
    assert_eq!(socket.receive().await.unwrap().unwrap().len(), at_most.len());
    assert!(socket.receive().await.unwrap().is_err());
}

#[tokio::test]
async fn a_websocket_handshake_is_bounded_by_its_timeout() {
    let tls = test_tls();
    let (listener, port) = listener().await;
    let acceptor = TlsAcceptor::from(tls.server.clone());
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // The TLS connection, then nothing: the handshake is never answered.
        let _stream = acceptor.accept(tcp).await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let client = DefaultWebSocketClient::new(transport(port, &tls), Duration::from_millis(300));
    let started = Instant::now();
    let error = client.connect(request_for("wss://relay.test")).await.err().expect("no connection");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert!(error.to_string().contains("ran out of time"), "{error}");
}

#[tokio::test]
async fn a_websocket_to_a_host_whose_certificate_chains_to_no_trusted_root_is_refused() {
    let tls = test_tls();
    let (port, _) = websocket_server(&tls, Vec::new()).await;
    let client = DefaultWebSocketClient::new(default_roots(port), Duration::from_secs(5));
    let error = client.connect(request_for("wss://relay.test")).await.err().expect("refused");
    assert!(error.to_string().contains("No connection"), "{error}");
}

#[tokio::test]
async fn a_websocket_url_that_is_not_wss_is_refused() {
    let tls = test_tls();
    let client = DefaultWebSocketClient::new(transport(9, &tls), Duration::from_secs(5));
    assert!(client.connect(request_for("ws://relay.test")).await.is_err());
}

/// An HTTP server that answers one request with `answer`, and tells what the request said.
async fn http_server(tls: &TestTls, answer: Vec<u8>) -> (u16, oneshot::Receiver<String>) {
    let (listener, port) = listener().await;
    let acceptor = TlsAcceptor::from(tls.server.clone());
    let (heard, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
        let _ = heard.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream.write_all(&answer).await;
        let _ = stream.shutdown().await;
    });
    (port, receiver)
}

fn crate_http(transport: Transport) -> Http {
    Http { client: Arc::new(DefaultHttpClient::new(transport)), timeout: Duration::from_secs(5) }
}

#[tokio::test]
async fn an_http_request_carries_the_crate_headers_alone_and_reads_the_answer() {
    let tls = test_tls();
    let body = r#"{"tag":"payRequest"}"#;
    let answer = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (port, heard) = http_server(&tls, answer.into_bytes()).await;
    let http = crate_http(transport(port, &tls));
    let answer =
        http.get_json("https://breez.tips/.well-known/lnurlp/sattleme02c6047f94?a=1", &[]).await.unwrap();
    assert_eq!((answer.status, answer.body), (200, Some(j!({ "tag": "payRequest" }))));
    let request = heard.await.unwrap();
    let lines: Vec<&str> = request.split("\r\n").filter(|line| !line.is_empty()).collect();
    assert_eq!(lines[0], "GET /.well-known/lnurlp/sattleme02c6047f94?a=1 HTTP/1.1");
    let mut headers: Vec<String> = lines[1..].iter().map(|line| line.to_ascii_lowercase()).collect();
    headers.sort();
    // No compression asked, no cookie, nothing but what every implementation sends.
    assert_eq!(
        headers,
        vec![
            "accept: application/json",
            "host: breez.tips",
            &format!("user-agent: {}", USER_AGENT.to_ascii_lowercase())
        ]
    );
}

#[tokio::test]
async fn an_http_redirect_is_no_answer() {
    let tls = test_tls();
    let answer =
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n".to_vec();
    let (port, _) = http_server(&tls, answer).await;
    // The default client hands the 302 over as it is…
    let client = DefaultHttpClient::new(transport(port, &tls));
    let response = client
        .get(HttpRequest { url: "https://breez.tips/x".to_owned(), headers: Vec::new() })
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    // …and the crate takes it as no answer.
    let (port, _) = http_server(
        &tls,
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
    let error = crate_http(transport(port, &tls)).get_json("https://breez.tips/x", &[]).await.unwrap_err();
    assert!(error.message().contains("redirect (HTTP 302)"), "{error}");
}

#[tokio::test]
async fn an_http_body_above_1_mib_is_dropped() {
    let tls = test_tls();
    let body = format!("\"{}\"", "a".repeat(1 << 20));
    let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (port, _) = http_server(&tls, answer.into_bytes()).await;
    let error = crate_http(transport(port, &tls)).get_json("https://breez.tips/x", &[]).await.unwrap_err();
    assert!(error.message().contains("more than 1048576 bytes"), "{error}");
}

/// An answer's head is bounded (SPEC.md §15): what the client holds of its status line, its
/// headers, and a chunked body's size lines and trailers, 10 MiB at most in all; a larger one is no
/// answer (`network`). hyper bounds the status line and headers far lower (some 400 KiB), a chunked
/// body's trailers and its chunk extensions at 16 KiB each; what it reads of a size line without
/// holding it (leading zeros, whitespace after the size), the crate's client bounds: it reads at
/// most 10 MiB of an answer in all. An answer below it is read, its trailers too.
#[tokio::test]
async fn an_http_answer_whose_head_is_larger_than_10_mib_is_no_answer() {
    const MIB: usize = 1 << 20;
    let tls = test_tls();
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("a header line of 11 MiB", {
            let mut answer = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
            answer.extend(std::iter::repeat_n(b'a', 11 * MIB));
            answer.extend_from_slice(b"\r\nContent-Length: 2\r\n\r\n{}");
            answer
        }),
        ("a chunk size of 11 MiB of leading zeros", {
            let mut answer = head.as_bytes().to_vec();
            answer.extend(std::iter::repeat_n(b'0', 11 * MIB));
            answer.extend_from_slice(b"2\r\n{}\r\n0\r\n\r\n");
            answer
        }),
        ("11 MiB of whitespace after a chunk size", {
            let mut answer = head.as_bytes().to_vec();
            answer.push(b'2');
            answer.extend(std::iter::repeat_n(b' ', 11 * MIB));
            answer.extend_from_slice(b"\r\n{}\r\n0\r\n\r\n");
            answer
        }),
        ("a chunk extension of 11 MiB", {
            let mut answer = head.as_bytes().to_vec();
            answer.extend_from_slice(b"2;x=");
            answer.extend(std::iter::repeat_n(b'a', 11 * MIB));
            answer.extend_from_slice(b"\r\n{}\r\n0\r\n\r\n");
            answer
        }),
        ("11 MiB of trailers", {
            let mut answer = head.as_bytes().to_vec();
            answer.extend_from_slice(b"2\r\n{}\r\n0\r\nX-Trailer: ");
            answer.extend(std::iter::repeat_n(b'a', 11 * MIB));
            answer.extend_from_slice(b"\r\n\r\n");
            answer
        }),
    ];
    for (what, answer) in cases {
        let (port, _) = http_server(&tls, answer).await;
        let http = Http {
            client: Arc::new(DefaultHttpClient::new(transport(port, &tls))),
            timeout: Duration::from_secs(30),
        };
        let started = Instant::now();
        let result = http.get_json("https://breez.tips/x", &[]).await;
        let elapsed = started.elapsed();
        assert_eq!(
            result.as_ref().err().map(crate::Error::code),
            Some(crate::ErrorCode::Network),
            "{what}: {result:?}"
        );
        // Refused once read that far, never at the request's timeout.
        assert!(elapsed < Duration::from_secs(10), "{what}: {elapsed:?}");
    }
    // Below the bound: 1 MiB of body in 4 096 chunks whose size lines take 2 100 spaces each,
    // some 9.2 MiB of answer in all, read.
    let mut answer = head.as_bytes().to_vec();
    let body = format!("\"{}\"", "a".repeat(MIB - 2));
    for chunk in body.as_bytes().chunks(256) {
        answer.extend_from_slice(format!("{:x}{}\r\n", chunk.len(), " ".repeat(2100)).as_bytes());
        answer.extend_from_slice(chunk);
        answer.extend_from_slice(b"\r\n");
    }
    answer.extend_from_slice(b"0\r\n\r\n");
    assert!(answer.len() > 9 * MIB && answer.len() < 10 * MIB, "{}", answer.len());
    let (port, _) = http_server(&tls, answer).await;
    let http = Http {
        client: Arc::new(DefaultHttpClient::new(transport(port, &tls))),
        timeout: Duration::from_secs(30),
    };
    let read = http.get_json("https://breez.tips/x", &[]).await.unwrap();
    assert_eq!(read.body.and_then(|body| body.as_str().map(str::len)), Some(MIB - 2));
    // A trailer of 1 000 bytes: read to its end, the body given.
    let mut answer = head.as_bytes().to_vec();
    answer.extend_from_slice(format!("2\r\n{{}}\r\n0\r\nX-Trailer: {}\r\n\r\n", "a".repeat(1000)).as_bytes());
    let (port, _) = http_server(&tls, answer).await;
    let read = crate_http(transport(port, &tls)).get_json("https://breez.tips/x", &[]).await.unwrap();
    assert_eq!(read.body, Some(j!({})));
}

/// The answer to a WebSocket's opening handshake is bounded too (SPEC.md §15, Head): tungstenite
/// holds at most 64 KiB of it. A header of 11 MiB fails the connection, and a read of that relay
/// with it (`network`); one of 1 KiB opens.
#[tokio::test]
async fn a_websocket_handshake_whose_answer_holds_a_header_of_11_mib_is_a_failed_connection() {
    for (size, opens) in [(1024, true), (11 << 20, false)] {
        let tls = test_tls();
        let (listener, port) = listener().await;
        let acceptor = TlsAcceptor::from(tls.server.clone());
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(tcp).await.unwrap();
            #[expect(
                clippy::result_large_err,
                reason = "tungstenite's handshake callback: its error is an answer"
            )]
            let callback = move |_: &Request, mut response: Response| {
                let large = http::HeaderValue::from_str(&"a".repeat(size)).unwrap();
                response.headers_mut().insert("x-large", large);
                Ok(response)
            };
            if let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(stream, callback).await {
                while let Some(Ok(_)) = socket.next().await {}
            }
        });
        let client = DefaultWebSocketClient::new(transport(port, &tls), Duration::from_secs(30));
        let started = Instant::now();
        let result = client.connect(request_for("wss://relay.test")).await;
        assert_eq!(result.is_ok(), opens, "{size}: {:?}", result.err());
        // Refused once read that far, never at the handshake's timeout.
        assert!(started.elapsed() < Duration::from_secs(10), "{size}: {:?}", started.elapsed());
    }
    // A relay whose handshake answers so: no answer to a read.
    let tls = test_tls();
    let (listener, port) = listener().await;
    let acceptor = TlsAcceptor::from(tls.server.clone());
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(tcp).await.unwrap();
        #[expect(
            clippy::result_large_err,
            reason = "tungstenite's handshake callback: its error is an answer"
        )]
        let callback = |_: &Request, mut response: Response| {
            response
                .headers_mut()
                .insert("x-large", http::HeaderValue::from_str(&"a".repeat(11 << 20)).unwrap());
            Ok(response)
        };
        let _ = tokio_tungstenite::accept_hdr_async(stream, callback).await;
    });
    let pool = crate::nostr::relay::RelayPool::new(crate::nostr::relay::PoolConfig {
        websocket: Arc::new(DefaultWebSocketClient::new(transport(port, &tls), Duration::from_secs(30))),
        timeout: Duration::from_secs(30),
        random: Arc::new(crate::runtime::OsRandom),
        clock: Arc::new(crate::runtime::SystemClock),
        call: crate::nostr::relay::CallTasks::default(),
    });
    let relays = vec!["wss://relay.test".to_owned()];
    let filter = crate::nostr::relay::Filter { kinds: Some(vec![30078.0]), ..Default::default() };
    let keep: crate::nostr::relay::Keep<crate::json::Json> = Arc::new(|value| Some(value.clone()));
    let started = Instant::now();
    let read = pool
        .query_relays(
            &relays,
            &filter,
            &crate::secret::Secret::new([1; 32]),
            &keep,
            crate::nostr::relay::ReadOf::query(&relays),
        )
        .await;
    assert!(!read.majority_answered(1));
    assert!(pool.has_failed("wss://relay.test"));
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
}

#[tokio::test]
async fn an_http_host_whose_certificate_chains_to_no_trusted_root_gets_no_request() {
    let tls = test_tls();
    let (port, heard) = http_server(&tls, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec()).await;
    let error = crate_http(default_roots(port)).get_json("https://breez.tips/x", &[]).await.unwrap_err();
    assert_eq!(error.code(), crate::ErrorCode::Network);
    // The server heard nothing of the request: TLS failed first.
    assert!(heard.await.map_or(true, |request| request.is_empty()));
}

/// A resolver that holds a thread of the blocking pool (as `getaddrinfo` does) until it is
/// released, then finds nothing: what the system's dialer does for a name slow to resolve.
#[derive(Clone, Default)]
struct SlowResolver(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

impl SlowResolver {
    /// Ends every resolution, so that the blocking pool stops at the test's end.
    fn release(&self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }

    fn transport(&self, tls: &TestTls) -> Transport {
        Transport::with(Arc::new(self.clone()), Arc::new(tls_config(tls.roots.clone())))
    }
}

impl Dial for SlowResolver {
    fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<TcpStream>> {
        let gate = self.0.clone();
        Box::pin(async move {
            let _ = tokio::task::spawn_blocking(move || {
                let (released, signal) = &*gate;
                let mut released = released.lock().unwrap();
                while !*released {
                    released = signal.wait_timeout(released, Duration::from_secs(10)).unwrap().0;
                }
            })
            .await;
            Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
        })
    }
}

#[tokio::test]
async fn the_resolution_of_a_name_counts_in_the_timeouts_of_a_request_and_of_a_handshake() {
    let tls = test_tls();
    let resolver = SlowResolver::default();
    let http = Http {
        client: Arc::new(DefaultHttpClient::new(resolver.transport(&tls))),
        timeout: Duration::from_millis(300),
    };
    let started = Instant::now();
    let error = http.get_json("https://mempool.space/api/blocks/tip/height", &[]).await.unwrap_err();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert_eq!(error.code(), crate::ErrorCode::Network);
    let client = DefaultWebSocketClient::new(resolver.transport(&tls), Duration::from_millis(300));
    let started = Instant::now();
    let error = client.connect(request_for("wss://relay.test")).await.err().expect("no connection");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert!(error.to_string().contains("ran out of time"), "{error}");
    resolver.release();
}

#[tokio::test]
async fn a_call_cancelled_while_a_name_resolves_ends_at_once_with_the_cancellation() {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    let tls = test_tls();
    let resolver = SlowResolver::default();
    // The Lightning address's name resolves slowly (the relays are local).
    let client = merchant
        .client()
        .http_client(DefaultHttpClient::new(resolver.transport(&tls)))
        .http_timeout_ms(10_000)
        .build()
        .unwrap();
    let started = Instant::now();
    let result =
        tokio::time::timeout(Duration::from_millis(200), client.create_invoice(&Order::sats("C-1", 1000)))
            .await;
    let elapsed = started.elapsed();
    // The caller's cancellation (its deadline), at once: neither the call's own error nor a wait
    // for the resolution's thread.
    assert!(result.is_err(), "{result:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    // A call dropped while the resolution runs (its task aborted) ends at once too.
    let started = Instant::now();
    let call = tokio::spawn({
        let client = client.clone();
        async move { client.create_invoice(&Order::sats("C-2", 1000)).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    assert!(started.elapsed() < Duration::from_secs(2));
    resolver.release();
}

/// A dialer that connects nowhere, counting the attempts.
#[derive(Clone, Default)]
struct Nowhere(Arc<std::sync::atomic::AtomicUsize>);

impl Dial for Nowhere {
    fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<TcpStream>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(io::Error::new(io::ErrorKind::ConnectionRefused, "nowhere")) })
    }
}

/// An HTTP server in clear (a merchant's Bitcoin node on its local network) that answers one
/// request with `answer`, and tells what the request said.
async fn plain_http_server(answer: Vec<u8>) -> (u16, oneshot::Receiver<String>) {
    let (listener, port) = listener().await;
    let (heard, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
        let _ = heard.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream.write_all(&answer).await;
        let _ = stream.shutdown().await;
    });
    (port, receiver)
}

#[tokio::test]
async fn a_node_on_a_local_network_is_asked_in_clear_http_1_1_with_the_crate_headers_alone() {
    let tls = test_tls();
    let answer = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\n970000".to_vec();
    let (port, heard) = plain_http_server(answer).await;
    let http = crate_http(transport(port, &tls));
    let answer = http.get_text("http://192.168.1.10:3006/api/blocks/tip/height", Reach::Node).await.unwrap();
    assert_eq!((answer.status, answer.body.as_deref()), (200, Some("970000")));
    let request = heard.await.unwrap();
    let lines: Vec<&str> = request.split("\r\n").filter(|line| !line.is_empty()).collect();
    assert_eq!(lines[0], "GET /api/blocks/tip/height HTTP/1.1");
    let mut headers: Vec<String> = lines[1..].iter().map(|line| line.to_ascii_lowercase()).collect();
    headers.sort();
    assert_eq!(
        headers,
        vec![
            "accept: application/json",
            "host: 192.168.1.10:3006",
            &format!("user-agent: {}", USER_AGENT.to_ascii_lowercase())
        ]
    );
    // Port 80, the default of http, is left out of the Host header, as WHATWG writes the URL.
    let (port, heard) = plain_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1".to_vec()).await;
    crate_http(transport(port, &tls))
        .get_text("http://umbrel.local:80/api/blocks/tip/height", Reach::Node)
        .await
        .unwrap();
    assert!(heard.await.unwrap().to_ascii_lowercase().contains("\r\nhost: umbrel.local\r\n"));
}

#[tokio::test]
async fn a_redirect_of_a_node_is_no_answer() {
    let tls = test_tls();
    let answer =
        b"HTTP/1.1 302 Found\r\nLocation: https://mempool.space/api/x\r\nContent-Length: 0\r\n\r\n".to_vec();
    let (port, _) = plain_http_server(answer).await;
    let error = crate_http(transport(port, &tls))
        .get_json_at("http://192.168.1.10:3006/api/address/x/txs", &[], Reach::Node)
        .await
        .unwrap_err();
    assert!(error.message().contains("redirect (HTTP 302)"), "{error}");
}

#[tokio::test]
async fn a_node_of_the_internet_at_an_ipv4_address_is_asked_over_tls_verified_for_that_address() {
    let tls = test_tls();
    let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n970000".to_vec();
    let (port, _) = http_server(&tls, answer).await;
    let height = crate_http(transport(port, &tls))
        .get_text("https://203.0.113.5:8443/api/blocks/tip/height", Reach::Node)
        .await
        .unwrap();
    assert_eq!(height.body.as_deref(), Some("970000"));
    // Its certificate is for another address: no request.
    let (port, heard) = http_server(&tls, b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1".to_vec()).await;
    let error = crate_http(transport(port, &tls))
        .get_text("https://203.0.113.6:8443/api/blocks/tip/height", Reach::Node)
        .await
        .unwrap_err();
    assert_eq!(error.code(), crate::ErrorCode::Network);
    assert!(heard.await.map_or(true, |request| request.is_empty()));
}

#[tokio::test]
async fn plain_http_goes_to_a_node_on_a_local_network_only_never_to_another_url() {
    let tls = test_tls();
    let nowhere = Nowhere::default();
    let http =
        crate_http(Transport::with(Arc::new(nowhere.clone()), Arc::new(tls_config(tls.roots.clone()))));
    // http to a public host, to the machine itself, an https URL's rule for an IP address, and a
    // node's URL asked as an https URL (a callback, a verify URL, a rate source): never dialled.
    for (url, reach) in [
        ("http://node.example/api/blocks/tip/height", Reach::Node),
        ("http://8.8.8.8/api/blocks/tip/height", Reach::Node),
        ("http://127.0.0.1:3006/api/blocks/tip/height", Reach::Node),
        ("http://localhost:3006/api/blocks/tip/height", Reach::Node),
        ("https://0.0.0.1/api/blocks/tip/height", Reach::Node),
        ("http://192.168.1.10:3006/api/blocks/tip/height", Reach::Https),
        ("https://192.168.1.10:3006/api/blocks/tip/height", Reach::Https),
        ("http://umbrel.local/api/blocks/tip/height", Reach::Https),
    ] {
        let error = http.get_text(url, reach).await.unwrap_err();
        assert_eq!(error.code(), crate::ErrorCode::Network, "{url}");
    }
    // Nor the default client given such a URL itself (an http request to a public host).
    let client = DefaultHttpClient::new(Transport::with(
        Arc::new(nowhere.clone()),
        Arc::new(tls_config(tls.roots.clone())),
    ));
    for url in ["http://node.example/x", "http://8.8.8.8/x", "http://breez.tips/x"] {
        assert!(client.get(HttpRequest { url: url.to_owned(), headers: Vec::new() }).await.is_err(), "{url}");
    }
    assert_eq!(nowhere.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_node_on_a_local_network_s_websocket_is_opened_in_clear_with_the_user_agent() {
    let tls = test_tls();
    let (listener, port) = listener().await;
    let (heard, receiver) = oneshot::channel::<Heard>();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        #[expect(
            clippy::result_large_err,
            reason = "tungstenite's handshake callback: its error is an answer"
        )]
        let callback = move |request: &Request, response: Response| {
            let headers = request
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or("").to_owned()))
                .collect();
            let _ = heard.send((request.uri().to_string(), headers));
            Ok(response)
        };
        let mut socket = tokio_tungstenite::accept_hdr_async(tcp, callback).await.unwrap();
        let _ = socket.send(Message::text("{\"block\":{}}")).await;
        while let Some(Ok(_)) = socket.next().await {}
    });
    let client = DefaultWebSocketClient::new(transport(port, &tls), Duration::from_secs(5));
    let mut socket =
        client.connect(request_for("ws://192.168.1.10:3006/api/v1/ws")).await.expect("connected");
    assert_eq!(socket.receive().await.unwrap().unwrap(), "{\"block\":{}}");
    let (path, headers) = receiver.await.unwrap();
    assert_eq!(path, "/api/v1/ws");
    assert_eq!(header(&headers, "user-agent"), Some(USER_AGENT));
    assert_eq!(header(&headers, "host"), Some("192.168.1.10:3006"));
    assert_eq!(header(&headers, "sec-websocket-extensions"), None);
    // ws to a host that is not local: never dialled.
    let nowhere = Nowhere::default();
    let client = DefaultWebSocketClient::new(
        Transport::with(Arc::new(nowhere.clone()), Arc::new(tls_config(tls.roots.clone()))),
        Duration::from_secs(5),
    );
    for url in ["ws://node.example/api/v1/ws", "ws://8.8.8.8/api/v1/ws", "ws://127.0.0.1/api/v1/ws"] {
        assert!(client.connect(request_for(url)).await.is_err(), "{url}");
    }
    assert_eq!(nowhere.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}
