//! The README's Rust examples, compiled (`cargo xtask readme`): each ```` ```rust ```` block of
//! README.md, as it is written, in a function of a crate of its own that gives it what the README
//! leaves to the reader (a client, the key, a stored invoice, the shop's orders and database, the
//! clients and logger of the options), built against the crate of the working tree. A block that
//! does not compile, or names something the README never gives, fails the check: add it below
//! when a new example needs it.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What every block may use.
const PRELUDE: &str = r#"#![allow(unused, unreachable_code)]
use sattleme_checkout::{Client, Error, ErrorCode, InvoiceToCheck, Order, PaymentStatus, RateSource};

pub struct ShopOrder {
    pub invoice: Option<String>,
    pub reference: String,
    pub number: u32,
}

pub struct Db;

impl Db {
    pub async fn save(&self, _order: &mut ShopOrder) {}
    pub async fn mark_paid(&self, _order: &mut ShopOrder, _payment: &sattleme_checkout::Payment) {}
}

#[allow(non_upper_case_globals)]
pub static db: Db = Db;

/// The HTTP client of the README's own rate source: a stand-in of reqwest's API.
pub mod reqwest {
    pub struct Client;
    pub struct Request;
    pub struct Response;
    #[derive(Debug)]
    pub struct ReqwestError;
    impl std::fmt::Display for ReqwestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an HTTP error")
        }
    }
    impl std::error::Error for ReqwestError {}
    impl Client {
        pub fn get(&self, _url: String) -> Request {
            Request
        }
    }
    impl Request {
        pub async fn send(self) -> Result<Response, ReqwestError> {
            Ok(Response)
        }
    }
    impl Response {
        pub fn status(&self) -> u16 {
            200
        }
        pub async fn json<T: Default>(self) -> Result<T, ReqwestError> {
            Ok(T::default())
        }
    }
}

#[derive(Default)]
pub struct Answer {
    pub price: String,
    pub time: i64,
}

pub struct MyHttp;
impl sattleme_checkout::HttpClient for MyHttp {
    fn get(
        &self,
        _request: sattleme_checkout::HttpRequest,
    ) -> sattleme_checkout::BoxFuture<'_, Result<sattleme_checkout::HttpResponse, sattleme_checkout::TransportError>> {
        unimplemented!()
    }
}

pub struct MyWebSocket;
impl sattleme_checkout::WebSocketClient for MyWebSocket {
    fn connect(
        &self,
        _request: sattleme_checkout::WebSocketRequest,
    ) -> sattleme_checkout::BoxFuture<
        '_,
        Result<Box<dyn sattleme_checkout::WebSocketConnection>, sattleme_checkout::TransportError>,
    > {
        unimplemented!()
    }
}

pub struct MyLogger;
impl sattleme_checkout::Logger for MyLogger {
    fn warn(&self, _message: &str) {}
}
"#;

/// The text of each ```` ```rust ```` block of `readme`, in order.
pub fn blocks(readme: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = readme;
    while let Some(start) = rest.find("```rust\n") {
        let body = &rest[start + "```rust\n".len()..];
        let Some(end) = body.find("```") else { break };
        found.push(&body[..end]);
        rest = &body[end + 3..];
    }
    found
}

fn indented(text: &str, by: usize) -> String {
    let margin = " ".repeat(by);
    text.lines().map(|line| format!("{margin}{line}\n")).collect()
}

/// The crate's main.rs: the prelude, then each block in a module of its own. A block that defines
/// types (a `struct` or an `impl` at its start of line) has them at the module's level, and its
/// last paragraph, its statements, in the function.
pub fn source(readme: &str) -> String {
    let mut out = String::from(PRELUDE);
    for (index, block) in blocks(readme).iter().enumerate() {
        let defines = block.lines().any(|line| line.starts_with("struct ") || line.starts_with("impl "));
        let (items, statements) = match block.trim_end().rsplit_once("\n\n") {
            Some((items, statements)) if defines => (items, statements),
            _ => ("", *block),
        };
        writeln!(out, "\nmod block{index} {{\n    use super::*;\n")
            .expect("writing to a String does not fail");
        out.push_str(&indented(items, 4));
        out.push_str(
            "    pub async fn run(\n        client: Client,\n        key: String,\n        stored: String,\n        \
             demo_key: String,\n        http: reqwest::Client,\n    ) -> Result<(), Box<dyn std::error::Error>> {\n        \
             let (my_http_client, my_websocket_client, my_logger) = (MyHttp, MyWebSocket, MyLogger);\n",
        );
        out.push_str(&indented(statements, 8));
        out.push_str("        Ok(())\n    }\n}\n");
    }
    out.push_str("\nfn main() {}\n");
    out
}

/// Builds the README's blocks in `<target>/readme-examples`, offline, with the repository's
/// Cargo.lock: whether every block compiles.
pub fn check(root: &Path) -> Result<usize, String> {
    let readme = fs::read_to_string(root.join("README.md")).map_err(|error| format!("README.md: {error}"))?;
    let count = blocks(&readme).len();
    if count == 0 {
        return Err("README.md holds no Rust block".to_owned());
    }
    let target = env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let dir = target.join("readme-examples");
    let write = |path: &Path, text: &str| {
        fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
    };
    fs::create_dir_all(dir.join("src")).map_err(|error| format!("{}: {error}", dir.display()))?;
    let manifest = format!(
        "[package]\nname = \"readme-examples\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n\
         [workspace]\n\n[dependencies]\nsattleme-checkout = {{ path = {:?} }}\n",
        root.display().to_string()
    );
    write(&dir.join("Cargo.toml"), &manifest)?;
    let lock = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| format!("Cargo.lock: {error}"))?;
    write(&dir.join("Cargo.lock"), &lock)?;
    write(&dir.join("src").join("main.rs"), &source(&readme))?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("> cargo build (the {count} Rust blocks of README.md, in {})", dir.display());
    let status = Command::new(cargo)
        .current_dir(&dir)
        .args(["build", "--offline", "--quiet", "--target-dir"])
        .arg(&target)
        .status()
        .map_err(|error| format!("cargo: {error}"))?;
    if status.success() { Ok(count) } else { Err("A Rust block of README.md does not compile".to_owned()) }
}
