//! Local Nostr relays for tests (NIP-01, NIP-42), in memory: the crate reaches them under their
//! `wss://` names through the injected WebSocket client ([`RelayNet`]). A relay keeps the newest
//! event of each address, as strfry does, and can refuse writes, ask for authentication, cap its
//! answers, answer late or never answer at all. Time is tokio's (paused in the tests): a mute
//! relay costs a test nothing but the virtual time of a timeout.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use super::chain::FakeExplorerSocket;
use crate::json::{self, Json};
use crate::nostr::event::{Event, valid_event};
use crate::transport::{BoxFuture, TransportError};
use crate::websocket::{WebSocketClient, WebSocketConnection, WebSocketRequest};

/// The server's end of an in-memory WebSocket: what it sends reaches the client.
#[derive(Default)]
pub(crate) struct Peer {
    sender: Mutex<Option<mpsc::UnboundedSender<String>>>,
}

impl Peer {
    pub(crate) fn open(&self, sender: mpsc::UnboundedSender<String>) {
        *self.sender.lock().unwrap() = Some(sender);
    }

    /// Sends `text` to the client; `false` once the connection is closed.
    pub(crate) fn send(&self, text: String) -> bool {
        self.sender.lock().unwrap().as_ref().is_some_and(|sender| sender.send(text).is_ok())
    }

    /// Closes the connection: the client reads its end.
    pub(crate) fn close(&self) {
        self.sender.lock().unwrap().take();
    }

    pub(crate) fn is_open(&self) -> bool {
        self.sender.lock().unwrap().as_ref().is_some_and(|sender| !sender.is_closed())
    }
}

type Handler = Box<dyn FnMut(String) + Send>;

/// The client's end of an in-memory WebSocket: what it sends goes to its server's handler, at
/// once.
pub(crate) struct MemorySocket {
    incoming: mpsc::UnboundedReceiver<String>,
    peer: Arc<Peer>,
    handler: Handler,
}

impl MemorySocket {
    /// A socket to `peer`, and the sender of what reaches the client.
    pub(crate) fn new(peer: Arc<Peer>) -> (Self, mpsc::UnboundedSender<String>) {
        let (sender, incoming) = mpsc::unbounded_channel();
        (Self { incoming, peer, handler: Box::new(|_| {}) }, sender)
    }

    pub(crate) fn on_message(mut self, handler: impl FnMut(String) + Send + 'static) -> Self {
        self.handler = Box::new(handler);
        self
    }
}

impl WebSocketConnection for MemorySocket {
    fn send(&mut self, message: String) -> BoxFuture<'_, Result<(), TransportError>> {
        let result = if self.peer.is_open() {
            (self.handler)(message);
            Ok(())
        } else {
            Err(TransportError::new("The WebSocket is closed"))
        };
        Box::pin(async move { result })
    }

    fn receive(&mut self) -> BoxFuture<'_, Option<Result<String, TransportError>>> {
        Box::pin(async move { self.incoming.recv().await.map(Ok) })
    }
}

impl Drop for MemorySocket {
    fn drop(&mut self) {
        self.peer.close();
    }
}

/// What a relay gives a filter (`REQ`), an event (`EVENT`), a stored value.
pub(crate) type OnFilter = Arc<dyn Fn(&Json) -> bool + Send + Sync>;
pub(crate) type OnValue = Arc<dyn Fn(&Json) -> bool + Send + Sync>;
pub(crate) type OnRefuse = Arc<dyn Fn(&Event) -> Option<String> + Send + Sync>;
pub(crate) type OnEvent = Arc<dyn Fn(&Event, &LocalRelay) + Send + Sync>;

/// How a relay behaves (all off by default: a relay that keeps and answers everything).
#[derive(Clone, Default)]
pub(crate) struct RelayBehaviour {
    /// Refuses every event with this reason.
    pub(crate) refuse: Option<String>,
    /// Refuses the events it gives a reason for (a checkout link and not a declaration…).
    pub(crate) refuse_event: Option<OnRefuse>,
    /// Accepts connections and never sends anything.
    pub(crate) mute: bool,
    /// Asks every connection to authenticate (NIP-42) before reading or writing.
    pub(crate) require_auth: bool,
    /// Never answers an authentication (no `OK`): a relay that stalls there.
    pub(crate) mute_auth: bool,
    /// Answers each authentication this many milliseconds late.
    pub(crate) auth_delay_ms: Option<u64>,
    /// Sends at most this many events per query, the newest first (strfry: 500).
    pub(crate) cap: Option<usize>,
    /// Never answers the queries it gives true for (no event, no EOSE): a relay that stalls there.
    pub(crate) mute_query: Option<OnFilter>,
    /// Answers each query this many milliseconds late (writes at once).
    pub(crate) query_delay_ms: Option<u64>,
    /// Answers a filter without `limit` oldest first, as nostr-rs-relay does.
    pub(crate) oldest_first_without_limit: bool,
    /// Leaves out of its answers the values it gives true for: a hostile relay.
    pub(crate) hide: Option<OnValue>,
    /// Hears each event the relay took, once it keeps it (another server writing meanwhile…).
    pub(crate) on_event: Option<OnEvent>,
}

impl RelayBehaviour {
    pub(crate) fn mute() -> Self {
        Self { mute: true, ..Self::default() }
    }

    pub(crate) fn refusing(reason: &str) -> Self {
        Self { refuse: Some(reason.to_owned()), ..Self::default() }
    }

    pub(crate) fn delayed(milliseconds: u64) -> Self {
        Self { query_delay_ms: Some(milliseconds), ..Self::default() }
    }
}

/// What an address is made of, as a relay keeps one event of it: its kind, author and `d` tag.
type AddressKey = (Option<f64>, Option<String>, String);

fn address_key(value: &Json) -> AddressKey {
    (
        value.get("kind").and_then(Json::as_f64),
        value.get("pubkey").and_then(Json::as_str).map(str::to_owned),
        first_tag(value, "d").to_owned(),
    )
}

#[derive(Default)]
struct RelayData {
    events: Vec<Json>,
    /// The address of each event, in the order of `events`.
    keys: Vec<AddressKey>,
    received: Vec<Event>,
    queries: Vec<Json>,
    authenticated: Vec<String>,
    closed_subscriptions: Vec<String>,
    /// Every message a client sent, when it came: its type, and the subscription of a `REQ` or a
    /// `CLOSE`.
    messages: Vec<(tokio::time::Instant, String)>,
    behaviour: RelayBehaviour,
    clients: Vec<Arc<Peer>>,
}

/// One connection's state: the relay's URL, its challenge, who authenticated.
struct Session {
    url: String,
    challenge: String,
    authed: Mutex<Option<String>>,
    peer: Arc<Peer>,
}

static CHALLENGES: AtomicUsize = AtomicUsize::new(0);

/// A local relay (a handle: clones are the same relay).
#[derive(Clone, Default)]
pub(crate) struct LocalRelay(Arc<Mutex<RelayData>>);

/// The `created_at` of a stored value, as JavaScript reads `value.created_at ?? 0`.
fn created_at_of(value: &Json) -> f64 {
    match value.get("created_at") {
        None | Some(Json::Null) => 0.0,
        Some(other) => other.as_f64().unwrap_or(f64::NAN),
    }
}

/// `String(value.id)`.
fn id_text(value: &Json) -> String {
    match value.get("id") {
        None => "undefined".to_owned(),
        Some(id) => id.as_str().map_or_else(|| json::stringify(id), str::to_owned),
    }
}

/// The value of the first tag of a stored value named `name`, `""` without one.
fn first_tag<'a>(value: &'a Json, name: &str) -> &'a str {
    value
        .get("tags")
        .and_then(Json::as_array)
        .and_then(|tags| {
            tags.iter()
                .find(|tag| tag.as_array().and_then(|tag| tag.first()).and_then(Json::as_str) == Some(name))
        })
        .and_then(|tag| tag.as_array()?.get(1)?.as_str())
        .unwrap_or("")
}

fn includes(list: Option<&Json>, value: Option<&Json>) -> bool {
    match list.and_then(Json::as_array) {
        None => true,
        Some(list) => value.is_some_and(|value| list.contains(value)),
    }
}

fn matches(filter: &Json, value: &Json) -> bool {
    includes(filter.get("ids"), value.get("id"))
        && includes(filter.get("kinds"), value.get("kind"))
        && includes(filter.get("authors"), value.get("pubkey"))
        && ["d", "o"].iter().all(|name| match filter.get(&format!("#{name}")).and_then(Json::as_array) {
            None => true,
            Some(values) => value.get("tags").and_then(Json::as_array).is_some_and(|tags| {
                tags.iter().any(|tag| {
                    tag.as_array().is_some_and(|tag| {
                        tag.first().and_then(Json::as_str) == Some(name)
                            && tag.get(1).is_some_and(|item| values.contains(item))
                    })
                })
            }),
        })
        && filter.get("since").and_then(Json::as_f64).is_none_or(|since| created_at_of(value) >= since)
        && filter.get("until").and_then(Json::as_f64).is_none_or(|until| created_at_of(value) <= until)
}

impl LocalRelay {
    fn data(&self) -> std::sync::MutexGuard<'_, RelayData> {
        self.0.lock().unwrap()
    }

    /// Stores `value` as it is (an invalid event too: a relay is never trusted).
    pub(crate) fn store(&self, value: Json) {
        let mut data = self.data();
        data.keys.push(address_key(&value));
        data.events.push(value);
    }

    /// Stores an event as it is.
    pub(crate) fn store_event(&self, event: &Event) {
        self.store(event.to_json());
    }

    /// Takes `event` as a client's write: the newest of its address is kept.
    pub(crate) fn take(&self, event: &Event) {
        self.keep(event);
    }

    /// Every value it holds.
    pub(crate) fn events(&self) -> Vec<Json> {
        self.data().events.clone()
    }

    /// Every valid event a client sent, taken or not.
    pub(crate) fn received(&self) -> Vec<Event> {
        self.data().received.clone()
    }

    /// Every filter a client asked.
    pub(crate) fn queries(&self) -> Vec<Json> {
        self.data().queries.clone()
    }

    /// The public keys that authenticated.
    pub(crate) fn authenticated(&self) -> Vec<String> {
        self.data().authenticated.clone()
    }

    /// Every message a client sent, in order, with when it came: `"REQ <subscription>"`,
    /// `"CLOSE <subscription>"`, `"AUTH"`, `"EVENT"`.
    pub(crate) fn messages(&self) -> Vec<(tokio::time::Instant, String)> {
        self.data().messages.clone()
    }

    /// The subscriptions a client closed (NIP-01 CLOSE).
    pub(crate) fn closed_subscriptions(&self) -> Vec<String> {
        self.data().closed_subscriptions.clone()
    }

    pub(crate) fn behaviour(&self) -> RelayBehaviour {
        self.data().behaviour.clone()
    }

    pub(crate) fn set_behaviour(&self, behaviour: RelayBehaviour) {
        self.data().behaviour = behaviour;
    }

    /// Changes its behaviour.
    pub(crate) fn update(&self, change: impl FnOnce(&mut RelayBehaviour)) {
        change(&mut self.data().behaviour);
    }

    /// Forgets every value it holds.
    pub(crate) fn clear_events(&self) {
        let mut data = self.data();
        data.events.clear();
        data.keys.clear();
    }

    /// How many connections are open.
    pub(crate) fn open_connections(&self) -> usize {
        self.data().clients.iter().filter(|client| client.is_open()).count()
    }

    /// Closes every connection.
    fn terminate(&self) {
        let clients = std::mem::take(&mut self.data().clients);
        for client in clients {
            client.close();
        }
    }

    /// A connection; with `slow_writes`, what the client writes as events (`["EVENT"…`) reaches
    /// the relay that late (or never, when the connection closed meanwhile).
    fn accept_with(&self, url: &str, slow_writes: Option<Duration>) -> MemorySocket {
        let peer = Arc::new(Peer::default());
        let (socket, sender) = MemorySocket::new(peer.clone());
        peer.open(sender);
        let n = CHALLENGES.fetch_add(1, AtomicOrdering::SeqCst);
        let session = Arc::new(Session {
            url: url.to_owned(),
            challenge: format!("challenge-{n}"),
            authed: Mutex::new(None),
            peer: peer.clone(),
        });
        let behaviour = {
            let mut data = self.data();
            data.clients.push(peer);
            data.behaviour.clone()
        };
        if behaviour.require_auth && !behaviour.mute {
            session.peer.send(json::stringify(&Json::array(vec![
                Json::from("AUTH"),
                Json::from(session.challenge.as_str()),
            ])));
        }
        let relay = self.clone();
        socket.on_message(move |text| match slow_writes {
            Some(delay) if text.starts_with("[\"EVENT\"") => {
                let (relay, session) = (relay.clone(), session.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if session.peer.is_open() {
                        relay.handle(&session, &text);
                    }
                });
            }
            _ => relay.handle(&session, &text),
        })
    }

    fn send(session: &Session, message: Vec<Json>) {
        session.peer.send(json::stringify(&Json::array(message)));
    }

    fn handle(&self, session: &Arc<Session>, text: &str) {
        let behaviour = self.behaviour();
        let Some(message) = json::parse(text) else { return };
        let Some(items) = message.as_array() else { return };
        let kind = items.first().and_then(Json::as_str);
        let heard = match (kind, items.get(1).and_then(Json::as_str)) {
            (Some(kind @ ("REQ" | "CLOSE")), Some(id)) => format!("{kind} {id}"),
            (kind, _) => kind.unwrap_or("?").to_owned(),
        };
        self.data().messages.push((tokio::time::Instant::now(), heard));
        if behaviour.mute {
            return;
        }
        match kind {
            Some("AUTH") if behaviour.mute_auth => {}
            Some("AUTH") => {
                let auth = items.get(1);
                let event = auth.and_then(valid_event);
                // As NIP-42 has it: kind 22242, signed, the connection's challenge, the relay's URL,
                // an empty content.
                let tag = |event: &Event, name: &str, value: &str| {
                    event.tags.iter().any(|tag| tag.len() >= 2 && tag[0] == name && tag[1] == value)
                };
                let ok = event.as_ref().is_some_and(|event| {
                    event.kind == 22242.0
                        && tag(event, "challenge", &session.challenge)
                        && tag(event, "relay", &session.url)
                        && event.content.is_empty()
                });
                if ok {
                    let pubkey = event.as_ref().map(|event| event.pubkey.clone()).unwrap_or_default();
                    *session.authed.lock().unwrap() = Some(pubkey.clone());
                    self.data().authenticated.push(pubkey);
                }
                let id = auth.and_then(|auth| auth.get("id")).cloned().unwrap_or(Json::Null);
                let answer = vec![
                    Json::from("OK"),
                    id,
                    Json::Bool(ok),
                    Json::from(if ok { "" } else { "invalid: bad auth" }),
                ];
                match behaviour.auth_delay_ms {
                    Some(delay) if delay > 0 => {
                        let session = session.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            Self::send(&session, answer);
                        });
                    }
                    _ => Self::send(session, answer),
                }
            }
            Some("EVENT") => {
                let value = items.get(1).cloned().unwrap_or(Json::Null);
                let id = value.get("id").cloned().unwrap_or(Json::Null);
                let pubkey = value.get("pubkey").and_then(Json::as_str).map(str::to_owned);
                let event = valid_event(&value);
                if let Some(event) = &event {
                    self.data().received.push(event.clone());
                }
                let authed = session.authed.lock().unwrap().clone();
                // An authentication is an AUTH message (NIP-42), never an EVENT: refused, kept
                // nowhere, authenticating nothing.
                let refusal = if event.as_ref().is_some_and(|event| event.kind == 22242.0) {
                    Some("invalid: an authentication is sent as [\"AUTH\", <event>]".to_owned())
                } else if behaviour.require_auth && (authed.is_none() || authed != pubkey) {
                    Some("auth-required: sign in first".to_owned())
                } else if let Some(reason) = &behaviour.refuse {
                    Some(reason.clone())
                } else if let Some(reason) = event
                    .as_ref()
                    .and_then(|event| behaviour.refuse_event.as_ref().and_then(|refuse| refuse(event)))
                {
                    Some(reason)
                } else if event.is_none() {
                    Some("invalid: bad event".to_owned())
                } else {
                    None
                };
                match (refusal, event) {
                    (Some(reason), _) => {
                        Self::send(session, vec![Json::from("OK"), id, Json::Bool(false), Json::from(reason)])
                    }
                    (None, Some(event)) => {
                        self.keep(&event);
                        if let Some(on_event) = &behaviour.on_event {
                            on_event(&event, self);
                        }
                        Self::send(
                            session,
                            vec![
                                Json::from("OK"),
                                Json::from(event.id.as_str()),
                                Json::Bool(true),
                                Json::from(""),
                            ],
                        );
                    }
                    (None, None) => unreachable!("an invalid event is refused"),
                }
            }
            Some("REQ") => {
                let id = items.get(1).cloned().unwrap_or(Json::Null);
                let filters: Vec<Json> = items.iter().skip(2).cloned().collect();
                self.data().queries.extend(filters.iter().cloned());
                if behaviour.require_auth && session.authed.lock().unwrap().is_none() {
                    Self::send(
                        session,
                        vec![Json::from("CLOSED"), id, Json::from("auth-required: sign in first")],
                    );
                    return;
                }
                if behaviour.mute_query.as_ref().is_some_and(|mute| filters.iter().any(|filter| mute(filter)))
                {
                    return;
                }
                let relay = self.clone();
                let session = session.clone();
                let answer = move || {
                    if !session.peer.is_open() {
                        return;
                    }
                    for event in relay.find(&filters) {
                        Self::send(&session, vec![Json::from("EVENT"), id.clone(), event]);
                    }
                    Self::send(&session, vec![Json::from("EOSE"), id.clone()]);
                };
                match behaviour.query_delay_ms {
                    Some(delay) if delay > 0 => {
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            answer();
                        });
                    }
                    _ => answer(),
                }
            }
            Some("CLOSE") => {
                let id = items.get(1).map_or_else(
                    || "undefined".to_owned(),
                    |id| id.as_str().map_or_else(|| json::stringify(id), str::to_owned),
                );
                self.data().closed_subscriptions.push(id);
            }
            _ => {}
        }
    }

    /// Keeps the newest event of an address (kind 30000–39999), as relays do (NIP-01).
    fn keep(&self, event: &Event) {
        let mut data = self.data();
        if (30000.0..40000.0).contains(&event.kind) {
            let d = event.tag("d").unwrap_or("");
            let index = data.keys.iter().position(|(kind, pubkey, other_d)| {
                *kind == Some(event.kind) && pubkey.as_deref() == Some(event.pubkey.as_str()) && other_d == d
            });
            if let Some(index) = index {
                let old = &data.events[index];
                let old_created_at = old.get("created_at").and_then(Json::as_f64).unwrap_or(f64::NAN);
                let old_id = old.get("id").and_then(Json::as_str);
                // The newest kept; of one second, the lowest id (NIP-01).
                let created_at = event.created_at as f64;
                if old_created_at > created_at
                    || (old_created_at == created_at && old_id.is_some_and(|old| old <= event.id.as_str()))
                {
                    return;
                }
                data.events.remove(index);
                data.keys.remove(index);
            }
        }
        let value = event.to_json();
        data.keys.push(address_key(&value));
        data.events.push(value);
    }

    /// What the relay answers `filters`: the newest first (of one second, the lowest id), capped.
    fn find(&self, filters: &[Json]) -> Vec<Json> {
        let data = self.data();
        let behaviour = &data.behaviour;
        let mut found: Vec<(f64, String, &Json)> = data
            .events
            .iter()
            .filter(|value| !behaviour.hide.as_ref().is_some_and(|hide| hide(value)))
            .filter(|value| filters.iter().any(|filter| matches(filter, value)))
            .map(|value| (created_at_of(value), id_text(value), value))
            .collect();
        found.sort_by(|a, b| {
            let difference = b.0 - a.0;
            if difference > 0.0 {
                Ordering::Greater
            } else if difference < 0.0 {
                Ordering::Less
            } else {
                a.1.cmp(&b.1)
            }
        });
        if behaviour.oldest_first_without_limit && filters.iter().all(|filter| filter.get("limit").is_none())
        {
            found.reverse();
        }
        let limit = filters
            .iter()
            .map(|filter| {
                filter.get("limit").and_then(Json::as_f64).map_or(usize::MAX, |limit| limit.max(0.0) as usize)
            })
            .chain(std::iter::once(behaviour.cap.unwrap_or(usize::MAX)))
            .min()
            .unwrap_or(usize::MAX);
        found.truncate(limit);
        found.into_iter().map(|(_, _, value)| value.clone()).collect()
    }
}

#[derive(Default)]
struct NetState {
    relays: HashMap<String, LocalRelay>,
    servers: HashMap<String, FakeExplorerSocket>,
    blackholes: HashSet<String>,
    connections: HashMap<String, usize>,
    handshakes: Vec<WebSocketRequest>,
}

/// The relays (and the explorer's WebSocket) of a test, by their `wss://` name: the WebSocket
/// client the crate gets. A name nothing serves refuses connections.
#[derive(Clone, Default)]
pub(crate) struct RelayNet(Arc<Mutex<NetState>>);

impl RelayNet {
    fn state(&self) -> std::sync::MutexGuard<'_, NetState> {
        self.0.lock().unwrap()
    }

    /// Starts a relay at `url`.
    pub(crate) fn add(&self, url: &str, behaviour: RelayBehaviour) -> LocalRelay {
        let relay = LocalRelay::default();
        relay.set_behaviour(behaviour);
        self.state().relays.insert(url.to_owned(), relay.clone());
        relay
    }

    /// A WebSocket server of a test at `url`: the explorer's.
    pub(crate) fn add_server(&self, url: &str) -> FakeExplorerSocket {
        let server = FakeExplorerSocket::default();
        self.state().servers.insert(url.to_owned(), server.clone());
        server
    }

    /// Stops the WebSocket server of `url`: its name refuses connections from now on.
    pub(crate) fn remove_server(&self, url: &str) {
        let server = self.state().servers.remove(url).unwrap_or_else(|| panic!("No server {url}"));
        server.drop_clients();
    }

    /// A name whose server takes the connection and never answers the handshake.
    pub(crate) fn add_blackhole(&self, url: &str) {
        self.state().blackholes.insert(url.to_owned());
    }

    /// Stops the relay of `url`: its connections end, its name refuses connections from now on.
    pub(crate) fn remove(&self, url: &str) {
        let relay = self.state().relays.remove(url).unwrap_or_else(|| panic!("No relay {url}"));
        relay.terminate();
    }

    pub(crate) fn get(&self, url: &str) -> LocalRelay {
        self.state().relays.get(url).cloned().unwrap_or_else(|| panic!("No relay {url}"))
    }

    /// How many connections `url` got (refused ones too).
    pub(crate) fn connections(&self, url: &str) -> usize {
        self.state().connections.get(url).copied().unwrap_or(0)
    }

    /// Every opening handshake, in order.
    pub(crate) fn handshakes(&self) -> Vec<WebSocketRequest> {
        self.state().handshakes.clone()
    }
}

/// A pool of the crate over `net`: requests bounded by `timeout_ms`, the OS's randomness.
pub(crate) fn pool(net: &RelayNet, timeout_ms: u64) -> crate::nostr::relay::RelayPool {
    crate::nostr::relay::RelayPool::new(crate::nostr::relay::PoolConfig {
        websocket: Arc::new(net.clone()),
        timeout: Duration::from_millis(timeout_ms),
        random: Arc::new(crate::runtime::OsRandom),
        clock: Arc::new(super::random::TestClock::new(1_791_378_000)),
        call: crate::nostr::relay::CallTasks::default(),
    })
}

/// The relays of a net, whose writes (events) reach them `delay` late: a slow client.
#[derive(Clone)]
pub(crate) struct SlowWrites {
    pub(crate) net: RelayNet,
    pub(crate) delay: Duration,
}

impl WebSocketClient for SlowWrites {
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
        self.net.connect_with(request, Some(self.delay))
    }
}

impl RelayNet {
    fn connect_with(
        &self,
        request: WebSocketRequest,
        slow_writes: Option<Duration>,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
        let mut state = self.state();
        *state.connections.entry(request.url.clone()).or_default() += 1;
        state.handshakes.push(request.clone());
        if let Some(relay) = state.relays.get(&request.url).cloned() {
            drop(state);
            let socket = relay.accept_with(&request.url, slow_writes);
            return Box::pin(async move { Ok(Box::new(socket) as Box<dyn WebSocketConnection>) });
        }
        if let Some(server) = state.servers.get(&request.url).cloned() {
            drop(state);
            let socket = server.accept(request);
            return Box::pin(async move { Ok(Box::new(socket) as Box<dyn WebSocketConnection>) });
        }
        if state.blackholes.contains(&request.url) {
            return Box::pin(std::future::pending());
        }
        Box::pin(async move { Err(TransportError::new("Connection refused")) })
    }
}

impl WebSocketClient for RelayNet {
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> BoxFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>> {
        self.connect_with(request, None)
    }
}
