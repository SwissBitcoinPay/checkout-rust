//! The relay client (NIP-01, NIP-42; SPEC.md §13).
//!
//! An integration's server may live for one call: a [`RelayPool`] opens one connection per relay
//! for that call, every read and write of the call goes over it, and it is closed when the call
//! is done (the pool dropped). Every relay of a list at once; a read goes on as soon as a
//! majority answered (any two majorities of one list share a relay), but the reads on every
//! relay. Subscription ids are random: what a relay receives names nothing of the integration.
//!
//! Cancellation: the pool owns every task it starts (each connection's, and each publication's
//! past the call's quorum) in a [`JoinSet`]; dropping the pool aborts them and hands them to its
//! call's [`CallTasks`], which the call ends before it returns: once it returned, nothing it
//! started runs, nor writes, its connections closed. A call dropped (cancelled) drops them with
//! it, aborted. Reads run in the call's own future: dropped when the read goes on, or with the
//! call, they send nothing more.
//!
//! What a relay sends is never trusted, nor kept whole: each event of a read is reduced, as it
//! comes, to its id, its date and what the read's [`Keep`] keeps of it (SPEC.md §13, Limits).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::derive::sha256;
use crate::json::{self, Json, JsonString};
use crate::nostr::event::{Event, EventTemplate, sign_event};
use crate::protocol::{
    AUTH_KIND, COMPLETE_READ_LIMIT, MAX_EVENTS_PER_QUERY, MAX_PAGES, MAX_RELAY_MESSAGE_BYTES,
};
use crate::runtime::{Clock, Random, seconds};
use crate::secret::Secret;
use crate::text::to_hex;
use crate::websocket::{WebSocketClient, request_for};

/// NIP-42 prefix of a refusal that authentication may lift.
const AUTH_REQUIRED: &str = "auth-required:";

/// More than half of `count` relays: any two majorities of one list share a relay.
pub(crate) fn majority(count: usize) -> usize {
    count / 2 + 1
}

/// Locks a mutex, whatever a panic elsewhere left in it (its data stays consistent: every
/// critical section here is a single update).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A NIP-01 subscription filter, as far as the crate uses it.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Filter {
    pub(crate) kinds: Option<Vec<f64>>,
    pub(crate) authors: Option<Vec<String>>,
    /// `#d`.
    pub(crate) d: Option<Vec<String>>,
    /// `#o`: a witness's order and address tags (SPEC.md §31, Witnesses).
    pub(crate) o: Option<Vec<String>>,
    pub(crate) since: Option<i64>,
    pub(crate) until: Option<i64>,
    pub(crate) limit: Option<usize>,
}

impl Filter {
    pub(crate) fn to_json(&self) -> Json {
        let texts =
            |values: &[String]| Json::array(values.iter().map(|value| Json::from(value.as_str())).collect());
        let mut members: Vec<(&str, Json)> = Vec::new();
        if let Some(kinds) = &self.kinds {
            members.push(("kinds", Json::array(kinds.iter().map(|&kind| Json::Number(kind)).collect())));
        }
        if let Some(authors) = &self.authors {
            members.push(("authors", texts(authors)));
        }
        if let Some(d) = &self.d {
            members.push(("#d", texts(d)));
        }
        if let Some(o) = &self.o {
            members.push(("#o", texts(o)));
        }
        if let Some(since) = self.since {
            members.push(("since", Json::integer(since)));
        }
        if let Some(until) = self.until {
            members.push(("until", Json::integer(until)));
        }
        if let Some(limit) = self.limit {
            members.push(("limit", Json::unsigned(limit as u64)));
        }
        Json::object_of(members)
    }
}

/// How a read of a list goes (SPEC.md §13): how many relays must answer, page after page or one
/// query, and whether on every relay.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadOf {
    /// How many relays must answer: a majority of the list.
    pub(crate) needed: usize,
    /// Page after page (`until`): a sale's declarations.
    pub(crate) paged: bool,
    /// On every relay: it does not go on as soon as `needed` answered.
    pub(crate) every_relay: bool,
}

impl ReadOf {
    /// One query on a majority of `relays`.
    pub(crate) fn query(relays: &[String]) -> Self {
        Self { needed: majority(relays.len()), paged: false, every_relay: false }
    }
}

/// What a read keeps of an event a relay sent (SPEC.md §13), as it comes: what it opens to, or
/// the checked event itself, when it opens; `None` drops it. Its id and its date are kept anyway,
/// to page the read and count each event once; so what a relay sends never piles up.
pub(crate) type Keep<K> = Arc<dyn Fn(&Json) -> Option<K> + Send + Sync>;

/// What a read keeps of an event, as it comes: its id and its date, and what its `Keep` kept.
#[derive(Debug)]
pub(crate) struct Entry<K> {
    /// Its `id` when it is a string (a JSON string, well-formed or not), one longer than 64
    /// characters by its SHA-256 (`#` and the hex: an id is 64 characters).
    pub(crate) id: Option<JsonString>,
    /// Its `created_at` when it is a safe integer.
    pub(crate) created_at: Option<i64>,
    pub(crate) value: Option<K>,
}

/// The `id` of `value` as an entry keeps it: when it is a string, one longer than 64 characters
/// by its SHA-256.
fn entry_id(value: &Json) -> Option<JsonString> {
    value.get("id").and_then(Json::as_json_string).map(|id| {
        if id.utf16_len() <= 64 {
            id.clone()
        } else {
            // The UTF-8 of the id, a lone surrogate as U+FFFD (as TextEncoder writes it).
            JsonString::Text(format!("#{}", to_hex(&sha256(id.to_string_lossy().as_bytes()))))
        }
    })
}

/// The entry of `value`, an event of one relay's answer to a query, of which `read` holds the ids
/// so far: the first event of each `id` is the one read; a later one of that `id` (a copy, or a
/// forgery: an id is its event's hash) only counts toward the query's 1000 events, its id and
/// date paging the read, nothing of it kept, opened or checked (SPEC.md §13, Limits).
pub(crate) fn entry_in_answer<K>(
    value: &Json,
    keep: &(dyn Fn(&Json) -> Option<K> + Send + Sync),
    read: &mut HashSet<JsonString>,
) -> Entry<K> {
    let id = entry_id(value);
    let created_at = value.get("created_at").and_then(Json::as_safe_integer);
    let first = id.as_ref().is_none_or(|id| read.insert(id.clone()));
    Entry { id, created_at, value: if first { keep(value) } else { None } }
}

/// How one page of a complete read ends (SPEC.md §13, Complete reads): the next page's `until`,
/// or the end of the relay's read, complete or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageEnd {
    Until(i64),
    Complete(bool),
}

/// One page of a complete read, read: what the read asks next, or how it ends. `seen` holds the
/// ids of the read so far; the page's new ones are added to it, and the events kept of them to
/// `kept`.
pub(crate) fn after_complete_page<K>(
    answer: Vec<Entry<K>>,
    seen: &mut HashSet<JsonString>,
    kept: &mut Vec<K>,
    pages_read: usize,
) -> PageEnd {
    let length = answer.len();
    let mut oldest: Option<i64> = None;
    let mut fresh = false;
    for entry in answer {
        let Some(id) = entry.id else { continue };
        if let Some(created_at) = entry.created_at {
            oldest = Some(oldest.map_or(created_at, |oldest| oldest.min(created_at)));
        }
        if !seen.insert(id) {
            continue;
        }
        if let Some(value) = entry.value {
            kept.push(value);
        }
        // New, dated or not ("no event not seen before"): the next page may hold more.
        fresh = true;
    }
    // More than asked: the relay ignored the limit, and what it left out cannot be told.
    if length > COMPLETE_READ_LIMIT {
        return PageEnd::Complete(false);
    }
    if length < COMPLETE_READ_LIMIT {
        return PageEnd::Complete(true);
    }
    // Full: the next page from its oldest second, unless it cannot move on.
    match oldest {
        Some(oldest) if fresh && pages_read < MAX_PAGES => PageEnd::Until(oldest),
        _ => PageEnd::Complete(false),
    }
}

/// One page of a paged read (SPEC.md §13, Paged reads), read: the `until` of the next page, or
/// `None` when the read ends there. Only an event's string `id` and safe integer `created_at` page
/// the read, whatever else it holds (one that does not check out pages it all the same); one
/// without them is not kept. The next page goes on from the oldest of those dates, one second
/// earlier when none of those events was new to the read. `seen` holds the ids of the read so far;
/// the page's new ones are added to it, and the events kept of them to `kept`.
pub(crate) fn after_paged_page<K>(
    answer: Vec<Entry<K>>,
    seen: &mut HashSet<JsonString>,
    kept: &mut Vec<K>,
) -> Option<i64> {
    let mut oldest: Option<i64> = None;
    let mut fresh = false;
    for entry in answer {
        let (Some(id), Some(created_at)) = (entry.id, entry.created_at) else { continue };
        oldest = Some(oldest.map_or(created_at, |oldest| oldest.min(created_at)));
        if !seen.insert(id) {
            continue;
        }
        if let Some(value) = entry.value {
            kept.push(value);
        }
        fresh = true;
    }
    // Nothing new: the oldest second again would bring the same page.
    oldest.map(|oldest| if fresh { oldest } else { oldest - 1 })
}

/// The events of each relay that answered a read, in the order they answered.
pub(crate) type Answers<K> = Vec<(String, Vec<K>)>;

/// Where one relay's part of a read is when the read goes on (SPEC.md §13).
pub(crate) enum RelayState<K> {
    /// Its read ended, complete or not: it answered, with these events.
    Ended { events: Vec<K>, complete: bool },
    /// Its read failed (its first page, or earlier in the call): no answer.
    Failed,
    /// Still reading, on every relay: the pages it sent by then, and no answer.
    Reading(Vec<K>),
}

/// What a read of a list gives, from where each relay's part of it is when it goes on: the relays
/// whose read ended answered; those still reading only gave their pages.
pub(crate) fn complete_read_of<K>(states: Vec<(String, RelayState<K>)>) -> CompleteRead<K> {
    let mut answers: Answers<K> = Vec::new();
    let mut pages: Answers<K> = Vec::new();
    let mut complete = 0;
    for (relay, state) in states {
        match state {
            RelayState::Ended { events, complete: read_completely } => {
                if read_completely {
                    complete += 1;
                }
                answers.push((relay, events));
            }
            RelayState::Failed => {}
            RelayState::Reading(events) => {
                if !events.is_empty() {
                    pages.push((relay, events));
                }
            }
        }
    }
    CompleteRead { read: Read { answers, pages }, complete }
}

/// What a read of a list gives (SPEC.md §13): the relays that answered, each with its events, and
/// on every relay the pages of those still reading.
pub(crate) struct Read<K> {
    /// The events kept of each relay whose read ended (complete or not), in the order they ended:
    /// these relays, and only these, answered.
    pub(crate) answers: Answers<K>,
    /// On every relay, the pages that each relay still reading had sent when the read went on:
    /// their events count as any relay's, but such a relay never counts as answered.
    pub(crate) pages: Answers<K>,
}

impl<K> Read<K> {
    /// How many relays answered: those whose read ended, never one still reading.
    pub(crate) fn answered(&self) -> usize {
        self.answers.len()
    }

    /// Whether a majority of the list, of `relays` relays, answered: else the read is no answer
    /// (`network`), never an absence (SPEC.md §13). A relay still reading never answered, whatever
    /// pages it sent, nor one that failed earlier in the call.
    pub(crate) fn majority_answered(&self, relays: usize) -> bool {
        self.answered() >= majority(relays)
    }

    /// Every event kept: of the relays that answered, then the pages of those still reading.
    pub(crate) fn events(&self) -> impl Iterator<Item = &K> {
        self.answers.iter().chain(self.pages.iter()).flat_map(|(_, events)| events.iter())
    }
}

/// What a complete read of a list gives: the read, and how many relays read completely.
pub(crate) struct CompleteRead<K> {
    pub(crate) read: Read<K>,
    /// How many relays read completely.
    pub(crate) complete: usize,
}

/// What a read of a list gives once it goes on (SPEC.md §13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadOutcome {
    /// Whether a majority of the list answered (their reads ended, complete or not): else the read
    /// is no answer (`network`).
    pub(crate) answered: bool,
    /// Whether a majority of the list read completely: only then is a complete read complete.
    pub(crate) complete: bool,
}

impl<K> CompleteRead<K> {
    /// What the read of a list of `relays` relays gives, from what each relay's read was when it
    /// went on ([`complete_read_of`]).
    pub(crate) fn outcome(&self, relays: usize) -> ReadOutcome {
        ReadOutcome {
            answered: self.read.majority_answered(relays),
            complete: self.complete >= majority(relays),
        }
    }
}

/// Fewer relays than needed took an event.
#[derive(Debug)]
pub(crate) struct NotTaken;

/// Why a request to one relay failed.
#[derive(Debug)]
enum RequestError {
    /// No answer in time, or the connection failed: the relay counts as failed for the rest of
    /// the call (reads on every relay do not wait for it again).
    Failed,
    /// The relay answered: a query `CLOSED`, an event refused (`OK` false), with its reason.
    Refused,
}

/// What a connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Connecting,
    Open,
    Dead,
}

/// What a listener does after a message: keeps listening, or stops.
#[derive(PartialEq, Eq)]
enum Control {
    Keep,
    Stop,
}

type Listener = Box<dyn FnMut(&[Json]) -> Control + Send>;

#[derive(Default)]
struct Listeners {
    next: u64,
    entries: Vec<(u64, Listener)>,
}

/// One connection to one relay, shared by every request of a pool.
struct Connection {
    url: String,
    state: watch::Sender<State>,
    outgoing: mpsc::UnboundedSender<String>,
    listeners: Mutex<Listeners>,
    /// The last NIP-42 challenge the relay sent.
    challenge: Mutex<Option<String>>,
    /// NIP-42 answers, by public key and challenge: one AUTH per key and challenge.
    auths: Mutex<HashMap<String, watch::Receiver<Option<bool>>>>,
}

impl Connection {
    /// Hears every message of the relay until it says it stops, or `unlisten`.
    fn listen(&self, listener: Listener) -> u64 {
        let mut listeners = lock(&self.listeners);
        let id = listeners.next;
        listeners.next += 1;
        listeners.entries.push((id, listener));
        id
    }

    /// Stops a listener: whether it was still listening.
    fn unlisten(&self, id: u64) -> bool {
        let mut listeners = lock(&self.listeners);
        let before = listeners.entries.len();
        listeners.entries.retain(|(entry, _)| *entry != id);
        listeners.entries.len() != before
    }

    fn send(&self, message: &Json) {
        if *self.state.borrow() != State::Dead {
            // Read by the connection's task; gone once it ended, as the connection.
            let _ = self.outgoing.send(json::stringify(message));
        }
    }

    /// A message of the relay: a JSON array, handed to every listener.
    fn dispatch(&self, text: &str) {
        let Some(Json::Array(message)) = json::parse(text) else {
            return;
        };
        let items = message.as_slice();
        if items.first().and_then(Json::as_str) == Some("AUTH")
            && let Some(challenge) = items.get(1).and_then(Json::as_str)
        {
            *lock(&self.challenge) = Some(challenge.to_owned());
        }
        lock(&self.listeners).entries.retain_mut(|(_, listener)| listener(items) == Control::Keep);
    }

    /// Ends the connection: every request still on it fails.
    fn die(&self) {
        self.state.send_replace(State::Dead);
        lock(&self.listeners).entries.clear();
    }

    /// Once the connection is open: `false` when it failed instead.
    async fn opened(&self) -> bool {
        let mut state = self.state.subscribe();
        match state.wait_for(|state| *state != State::Connecting).await {
            Ok(state) => *state == State::Open,
            Err(_) => false,
        }
    }

    /// Once the connection is over.
    async fn dead(&self) {
        let mut state = self.state.subscribe();
        let _ = state.wait_for(|state| *state == State::Dead).await;
    }

    /// Answers the relay's NIP-42 challenge with `key`: whether the relay took it. One AUTH per
    /// key and challenge, shared by the requests that ask for it.
    async fn authenticate(&self, key: &Secret, created_at: i64, random: &dyn Random) -> bool {
        let Some(challenge) = lock(&self.challenge).clone() else {
            return false;
        };
        if *self.state.borrow() == State::Dead {
            return false;
        }
        let mut answer = {
            let mut auths = lock(&self.auths);
            let public = crate::derive::public_key_of(key);
            let id = format!("{public}:{challenge}");
            match auths.get(&id) {
                Some(answer) => answer.clone(),
                None => {
                    let auth = sign_event(
                        EventTemplate {
                            created_at,
                            kind: AUTH_KIND,
                            tags: vec![
                                vec!["relay".to_owned(), self.url.clone()],
                                vec!["challenge".to_owned(), challenge],
                            ],
                            content: String::new(),
                        },
                        key,
                        random,
                    );
                    let (sender, receiver) = watch::channel(None);
                    let auth_id = auth.id.clone();
                    self.listen(Box::new(move |message| {
                        if message.first().and_then(Json::as_str) != Some("OK")
                            || message.get(1).and_then(Json::as_str) != Some(auth_id.as_str())
                        {
                            return Control::Keep;
                        }
                        sender.send_replace(Some(message.get(2) == Some(&Json::Bool(true))));
                        Control::Stop
                    }));
                    auths.insert(id, receiver.clone());
                    self.send(&Json::array(vec![Json::from("AUTH"), auth.to_json()]));
                    receiver
                }
            }
        };
        tokio::select! {
            taken = answer.wait_for(Option::is_some) => taken.is_ok_and(|taken| *taken == Some(true)),
            () = self.dead() => false,
        }
    }
}

/// Reads and writes the relay's messages until the connection ends: what requests send, what the
/// relay sends to the listeners. A message larger than 1 MiB ends it, as the default WebSocket
/// client refuses one.
async fn drive(
    connection: Arc<Connection>,
    client: Arc<dyn WebSocketClient>,
    mut outgoing: mpsc::UnboundedReceiver<String>,
) {
    let Ok(mut socket) = client.connect(request_for(&connection.url)).await else {
        connection.die();
        return;
    };
    connection.state.send_replace(State::Open);
    loop {
        tokio::select! {
            message = outgoing.recv() => match message {
                Some(text) => {
                    if socket.send(text).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            incoming = socket.receive() => match incoming {
                Some(Ok(text)) if text.len() <= MAX_RELAY_MESSAGE_BYTES => connection.dispatch(&text),
                _ => break,
            },
        }
    }
    connection.die();
}

/// What a request needs besides its connection.
#[derive(Clone)]
struct Context {
    timeout: Duration,
    failed: Arc<Mutex<HashSet<String>>>,
    random: Arc<dyn Random>,
    clock: Arc<dyn Clock>,
}

impl Context {
    /// Runs `operation` over `connection` once it is open, within the timeout (the wait for the
    /// connection included). A timeout or a connection that fails counts the relay as failed.
    async fn request<T, Fut>(
        &self,
        connection: &Arc<Connection>,
        operation: impl FnOnce(Arc<Connection>) -> Fut,
    ) -> Result<T, RequestError>
    where
        Fut: Future<Output = Result<T, RequestError>>,
    {
        let work = async {
            if !connection.opened().await {
                return Err(RequestError::Failed);
            }
            tokio::select! {
                result = operation(connection.clone()) => result,
                () = connection.dead() => Err(RequestError::Failed),
            }
        };
        let result = tokio::time::timeout(self.timeout, work).await.unwrap_or(Err(RequestError::Failed));
        if matches!(result, Err(RequestError::Failed)) {
            lock(&self.failed).insert(connection.url.clone());
        }
        result
    }

    fn now(&self) -> i64 {
        seconds(&*self.clock)
    }
}

/// What a query was answered: its entries, and the reason of a `CLOSED`.
struct QueryOutcome<K> {
    entries: Vec<Entry<K>>,
    closed: Option<String>,
}

/// Stops a query's listener when the query is dropped before its end, and closes its
/// subscription.
struct Subscription<'a> {
    connection: &'a Connection,
    listener: u64,
    id: String,
}

impl Drop for Subscription<'_> {
    fn drop(&mut self) {
        if self.connection.unlisten(self.listener) {
            self.connection.send(&Json::array(vec![Json::from("CLOSE"), Json::from(self.id.as_str())]));
        }
    }
}

/// Stops a publication's listener when it is dropped before its answer.
struct Publication<'a> {
    connection: &'a Connection,
    listener: u64,
}

impl Drop for Publication<'_> {
    fn drop(&mut self) {
        self.connection.unlisten(self.listener);
    }
}

/// Asks `filter` once over `connection`: its events until `EOSE` (then `CLOSE`), at most 1000
/// (the 1000th ends it, then `CLOSE`), or its `CLOSED`. Of each `id`, the first event alone is
/// kept: a copy only counts.
async fn ask<K: Send + 'static>(
    connection: &Connection,
    filter: &Json,
    keep: &Keep<K>,
    random: &dyn Random,
) -> Result<QueryOutcome<K>, RequestError> {
    let mut bytes = [0u8; 8];
    random.fill(&mut bytes);
    let subscription = to_hex(&bytes);
    let (done, outcome) = oneshot::channel();
    let mut done = Some(done);
    let mut entries: Vec<Entry<K>> = Vec::new();
    // The ids of this answer's events so far: the first event of each is the one read.
    let mut read: HashSet<JsonString> = HashSet::new();
    let id = subscription.clone();
    let keep = keep.clone();
    let outgoing = connection.outgoing.clone();
    let listener = connection.listen(Box::new(move |message| {
        if message.get(1).and_then(Json::as_str) != Some(id.as_str()) {
            return Control::Keep;
        }
        let close = |entries: Vec<Entry<K>>,
                     closed: Option<String>,
                     done: &mut Option<oneshot::Sender<QueryOutcome<K>>>| {
            if let Some(done) = done.take() {
                let _ = done.send(QueryOutcome { entries, closed });
            }
            Control::Stop
        };
        match message.first().and_then(Json::as_str) {
            Some("EVENT") => {
                entries.push(entry_in_answer(message.get(2).unwrap_or(&Json::Null), &*keep, &mut read));
                if entries.len() >= MAX_EVENTS_PER_QUERY {
                    let _ = outgoing.send(json::stringify(&Json::array(vec![
                        Json::from("CLOSE"),
                        Json::from(id.as_str()),
                    ])));
                    return close(std::mem::take(&mut entries), None, &mut done);
                }
                Control::Keep
            }
            Some("EOSE") => {
                let _ = outgoing
                    .send(json::stringify(&Json::array(vec![Json::from("CLOSE"), Json::from(id.as_str())])));
                close(std::mem::take(&mut entries), None, &mut done)
            }
            Some("CLOSED") => {
                let reason = message.get(2).and_then(Json::as_str).unwrap_or_default().to_owned();
                close(std::mem::take(&mut entries), Some(reason), &mut done)
            }
            _ => Control::Keep,
        }
    }));
    let guard = Subscription { connection, listener, id: subscription.clone() };
    connection.send(&Json::array(vec![Json::from("REQ"), Json::from(subscription.as_str()), filter.clone()]));
    // The sender gone without an answer: the connection died (the request fails on it).
    let result = outcome.await.map_err(|_| RequestError::Failed);
    drop(guard);
    result
}

/// The stored events of a relay that match `filter`, as it sent them (each reduced to its entry),
/// unchecked: the caller checks them. Authenticates when the relay asks (NIP-42).
async fn query<K: Send + 'static>(
    context: &Context,
    connection: &Arc<Connection>,
    filter: &Json,
    key: &Secret,
    keep: &Keep<K>,
) -> Result<Vec<Entry<K>>, RequestError> {
    context
        .request(connection, |connection| async move {
            let mut outcome = ask(&connection, filter, keep, &*context.random).await?;
            if outcome.closed.as_deref().is_some_and(|reason| reason.starts_with(AUTH_REQUIRED))
                && connection.authenticate(key, context.now(), &*context.random).await
            {
                outcome = ask(&connection, filter, keep, &*context.random).await?;
            }
            match outcome.closed {
                Some(_) => Err(RequestError::Refused),
                None => Ok(outcome.entries),
            }
        })
        .await
}

/// Sends `event` once over `connection`: whether the relay took it, and its reason.
async fn write(connection: &Connection, event: &Json, id: &str) -> Result<(bool, String), RequestError> {
    let (done, answer) = oneshot::channel();
    let mut done = Some(done);
    let event_id = id.to_owned();
    let listener = connection.listen(Box::new(move |message| {
        if message.first().and_then(Json::as_str) != Some("OK")
            || message.get(1).and_then(Json::as_str) != Some(event_id.as_str())
        {
            return Control::Keep;
        }
        if let Some(done) = done.take() {
            let accepted = message.get(2) == Some(&Json::Bool(true));
            let reason = message.get(3).and_then(Json::as_str).unwrap_or_default().to_owned();
            let _ = done.send((accepted, reason));
        }
        Control::Stop
    }));
    let guard = Publication { connection, listener };
    connection.send(&Json::array(vec![Json::from("EVENT"), event.clone()]));
    let result = answer.await.map_err(|_| RequestError::Failed);
    drop(guard);
    result
}

/// Publishes `event` to one relay, authenticating when it asks (NIP-42): taken, or not.
async fn publish(
    context: &Context,
    connection: &Arc<Connection>,
    event: &Event,
    key: &Secret,
) -> Result<(), RequestError> {
    let json = event.to_json();
    context
        .request(connection, |connection| async move {
            let mut answer = write(&connection, &json, &event.id).await?;
            if !answer.0
                && answer.1.starts_with(AUTH_REQUIRED)
                && connection.authenticate(key, context.now(), &*context.random).await
            {
                answer = write(&connection, &json, &event.id).await?;
            }
            if answer.0 { Ok(()) } else { Err(RequestError::Refused) }
        })
        .await
}

/// What the pools of one call started (SPEC.md §4, §13): a pool dropped hands its tasks here,
/// aborted, and the call ends them all ([`CallTasks::end`]) before it returns, so that nothing it
/// started runs on once it returned, a publication's relays past its majority included (their
/// requests end with the call). A call dropped (cancelled) drops them with it, aborted: none runs
/// again.
#[derive(Clone, Default)]
pub(crate) struct CallTasks(Arc<Mutex<Vec<JoinSet<()>>>>);

impl CallTasks {
    /// Once every task of the call's dropped pools has ended: each aborted, and waited for.
    pub(crate) async fn end(&self) {
        loop {
            let sets = std::mem::take(&mut *lock(&self.0));
            if sets.is_empty() {
                return;
            }
            for mut set in sets {
                set.shutdown().await;
            }
        }
    }
}

/// The configuration of a pool.
#[derive(Clone)]
pub(crate) struct PoolConfig {
    pub(crate) websocket: Arc<dyn WebSocketClient>,
    /// Per request (a page of a read, a write), the wait for the connection included.
    pub(crate) timeout: Duration,
    pub(crate) random: Arc<dyn Random>,
    /// The date of NIP-42 authentication events.
    pub(crate) clock: Arc<dyn Clock>,
    /// The call whose relays these are: it ends the pool's tasks before it returns.
    pub(crate) call: CallTasks,
}

/// The relays of one call: one connection per relay, opened at its first request, kept for the
/// call's next requests, closed when the pool is dropped and its call ends its tasks. Requests are
/// bounded by the timeout each.
pub(crate) struct RelayPool {
    config: PoolConfig,
    connections: Mutex<HashMap<String, Arc<Connection>>>,
    /// Relays a request to which ran out of time or lost its connection in this call: a read on
    /// every relay counts them as failed at once (SPEC.md §13).
    failed: Arc<Mutex<HashSet<String>>>,
    /// Every task of the pool: aborted when it is dropped, and ended by its call.
    tasks: Mutex<JoinSet<()>>,
}

impl Drop for RelayPool {
    fn drop(&mut self) {
        let mut tasks =
            std::mem::take(self.tasks.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner));
        tasks.abort_all();
        let mut sets = lock(&self.config.call.0);
        // Those of the call's earlier pools that ended are forgotten: a long wait for a payment
        // drops a pool at each check.
        sets.retain_mut(|set| {
            while set.try_join_next().is_some() {}
            !set.is_empty()
        });
        sets.push(tasks);
    }
}

impl RelayPool {
    pub(crate) fn new(config: PoolConfig) -> Self {
        Self {
            config,
            connections: Mutex::new(HashMap::new()),
            failed: Arc::new(Mutex::new(HashSet::new())),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    fn context(&self) -> Context {
        Context {
            timeout: self.config.timeout,
            failed: self.failed.clone(),
            random: self.config.random.clone(),
            clock: self.config.clock.clone(),
        }
    }

    /// The pool's connection to `url`, opened at its first request.
    fn connection(&self, url: &str) -> Arc<Connection> {
        let mut connections = lock(&self.connections);
        if let Some(connection) = connections.get(url) {
            return connection.clone();
        }
        let (outgoing, receiver) = mpsc::unbounded_channel();
        let connection = Arc::new(Connection {
            url: url.to_owned(),
            state: watch::Sender::new(State::Connecting),
            outgoing,
            listeners: Mutex::new(Listeners::default()),
            challenge: Mutex::new(None),
            auths: Mutex::new(HashMap::new()),
        });
        let mut tasks = lock(&self.tasks);
        // Finished tasks are dropped as new ones come.
        while tasks.try_join_next().is_some() {}
        tasks.spawn(drive(connection.clone(), self.config.websocket.clone(), receiver));
        connections.insert(url.to_owned(), connection.clone());
        connection
    }

    /// The call whose relays these are.
    pub(crate) fn call(&self) -> &CallTasks {
        &self.config.call
    }

    /// Whether a request to `url` failed (ran out of time, or lost its connection) in this call.
    pub(crate) fn has_failed(&self, url: &str) -> bool {
        lock(&self.failed).contains(url)
    }

    /// The events of one relay that match `filter`, page after page (`until`): the first page
    /// fails, the relay fails; a later one ends the read with what came. `pages` receives each
    /// page's events as they come (what a read on every relay keeps of a relay cut short).
    async fn pages<K: Send + 'static>(
        &self,
        context: &Context,
        url: &str,
        filter: &Filter,
        key: &Secret,
        keep: &Keep<K>,
        pages: &Mutex<Vec<K>>,
    ) -> Result<(), RequestError> {
        let connection = self.connection(url);
        let mut seen: HashSet<JsonString> = HashSet::new();
        let mut until = filter.until;
        for page in 0..MAX_PAGES {
            let asked = Filter { until, ..filter.clone() }.to_json();
            let answer = match query(context, &connection, &asked, key, keep).await {
                Ok(answer) => answer,
                // A relay that stops answering after its first page keeps what it sent.
                Err(error) if page == 0 => return Err(error),
                Err(_) => break,
            };
            let mut kept = Vec::new();
            let next = after_paged_page(answer, &mut seen, &mut kept);
            lock(pages).extend(kept);
            match next {
                Some(next) => until = Some(next),
                None => break,
            }
        }
        Ok(())
    }

    /// The events of one relay that match `filter`, read completely if it can be: whether it was.
    /// Fails when its first page fails (the relay failed); a later failure ends the read
    /// incomplete.
    async fn complete_pages<K: Send + 'static>(
        &self,
        context: &Context,
        url: &str,
        filter: &Filter,
        key: &Secret,
        keep: &Keep<K>,
        pages: &Mutex<Vec<K>>,
    ) -> Result<bool, RequestError> {
        let connection = self.connection(url);
        let mut seen: HashSet<JsonString> = HashSet::new();
        let mut until = filter.until;
        for page in 1.. {
            let asked = Filter { limit: Some(COMPLETE_READ_LIMIT), until, ..filter.clone() }.to_json();
            let answer = match query(context, &connection, &asked, key, keep).await {
                Ok(answer) => answer,
                Err(error) if page == 1 => return Err(error),
                Err(_) => return Ok(false),
            };
            let mut kept = Vec::new();
            let next = after_complete_page(answer, &mut seen, &mut kept, page);
            lock(pages).extend(kept);
            match next {
                PageEnd::Complete(complete) => return Ok(complete),
                PageEnd::Until(oldest) => until = Some(oldest),
            }
        }
        unreachable!("a read ends at its 20th page at the latest")
    }

    /// What every relay of `relays` holds that matches `filter`, at once, page after page when
    /// `read.paged`. Goes on as soon as `read.needed` relays answered (the others' reads dropped),
    /// or once every relay answered or failed; on every relay (`read.every_relay`), once every
    /// relay did, or one timeout after `read.needed` did, and the relays that failed earlier in the
    /// call count as failed at once. The events kept of each relay that answered, unchecked; on
    /// every relay, the pages of those still reading too (which never count as answers).
    pub(crate) async fn query_relays<K: Send + 'static>(
        &self,
        relays: &[String],
        filter: &Filter,
        key: &Secret,
        keep: &Keep<K>,
        read: ReadOf,
    ) -> Read<K> {
        let ReadOf { needed, paged, every_relay } = read;
        let context = self.context();
        let asked: Vec<&String> =
            relays.iter().filter(|relay| !every_relay || !self.has_failed(relay)).collect();
        let mut failed = relays.len() - asked.len();
        let sent: Vec<Mutex<Vec<K>>> = asked.iter().map(|_| Mutex::new(Vec::new())).collect();
        let mut reads = FuturesUnordered::new();
        for (index, relay) in asked.iter().enumerate() {
            let context = &context;
            let sent = &sent[index];
            reads.push(async move {
                let result = if paged {
                    self.pages(context, relay, filter, key, keep, sent).await
                } else {
                    let connection = self.connection(relay);
                    query(context, &connection, &filter.to_json(), key, keep).await.map(|entries| {
                        lock(sent).extend(entries.into_iter().filter_map(|entry| entry.value));
                    })
                };
                (index, result)
            });
        }
        let mut answered: Vec<usize> = Vec::new();
        let mut failed_reads: HashSet<usize> = HashSet::new();
        let mut grace: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            if answered.len() + failed >= relays.len() {
                break;
            }
            if answered.len() >= needed {
                if !every_relay {
                    break;
                }
                // On every relay, the others are waited for one timeout more at most.
                grace.get_or_insert_with(|| Box::pin(tokio::time::sleep(self.config.timeout)));
            }
            tokio::select! {
                Some((index, result)) = reads.next() => match result {
                    Ok(()) => answered.push(index),
                    Err(_) => {
                        failed_reads.insert(index);
                        failed += 1;
                    }
                },
                () = async { grace.as_mut().expect("guarded").await }, if grace.is_some() => break,
            }
        }
        drop(reads);
        let mut sent: Vec<Option<Vec<K>>> = sent
            .into_iter()
            .map(|events| Some(events.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner)))
            .collect();
        // The relays that answered, in the order they did; then the others: failed, or still
        // reading (on every relay, their pages kept; else their reads dropped).
        let mut states: Vec<(String, RelayState<K>)> = Vec::new();
        for &index in &answered {
            let events = sent[index].take().unwrap_or_default();
            states.push((asked[index].clone(), RelayState::Ended { events, complete: false }));
        }
        for (index, relay) in asked.iter().enumerate() {
            let Some(events) = sent[index].take() else { continue };
            let state = if failed_reads.contains(&index) {
                RelayState::Failed
            } else if every_relay && paged {
                RelayState::Reading(events)
            } else {
                RelayState::Reading(Vec::new())
            };
            states.push(((*relay).clone(), state));
        }
        complete_read_of(states).read
    }

    /// A complete read of `filter` on every relay of `relays` at once (SPEC.md §13, Complete
    /// reads): pages of 100 events, the next one from the oldest second of the last, until a page
    /// is not full. Goes on as soon as `needed` relays read completely (the others' reads
    /// dropped), or once every relay's read ended or failed; on every relay (`every_relay`), once
    /// every relay's did, or one timeout after `needed` read completely, or as soon as `needed`
    /// can no longer read completely, and the relays that failed earlier in the call count as
    /// failed at once.
    pub(crate) async fn query_complete<K: Send + 'static>(
        &self,
        relays: &[String],
        filter: &Filter,
        key: &Secret,
        needed: usize,
        keep: &Keep<K>,
        every_relay: bool,
    ) -> CompleteRead<K> {
        let context = self.context();
        let asked: Vec<&String> =
            relays.iter().filter(|relay| !every_relay || !self.has_failed(relay)).collect();
        let mut settled = relays.len() - asked.len();
        let mut complete = 0;
        let sent: Vec<Mutex<Vec<K>>> = asked.iter().map(|_| Mutex::new(Vec::new())).collect();
        let mut reads = FuturesUnordered::new();
        for (index, relay) in asked.iter().enumerate() {
            let context = &context;
            let sent = &sent[index];
            reads.push(
                async move { (index, self.complete_pages(context, relay, filter, key, keep, sent).await) },
            );
        }
        // Each relay whose read ended, in order: whether it read completely, or `None` (failed).
        let mut ended: Vec<(usize, Option<bool>)> = Vec::new();
        let mut grace: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            if settled >= relays.len() {
                break;
            }
            // On every relay, no wait once a majority can no longer read completely.
            if every_relay && complete + (relays.len() - settled) < needed {
                break;
            }
            if complete >= needed {
                if !every_relay {
                    break;
                }
                grace.get_or_insert_with(|| Box::pin(tokio::time::sleep(self.config.timeout)));
            }
            tokio::select! {
                Some((index, result)) = reads.next() => {
                    settled += 1;
                    match result {
                        Ok(read_complete) => {
                            if read_complete {
                                complete += 1;
                            }
                            ended.push((index, Some(read_complete)));
                        }
                        Err(_) => ended.push((index, None)),
                    }
                }
                () = async { grace.as_mut().expect("guarded").await }, if grace.is_some() => break,
            }
        }
        drop(reads);
        let mut sent: Vec<Option<Vec<K>>> = sent
            .into_iter()
            .map(|events| Some(events.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner)))
            .collect();
        let mut states: Vec<(String, RelayState<K>)> = Vec::new();
        for &(index, read_complete) in &ended {
            let events = sent[index].take().unwrap_or_default();
            let state = match read_complete {
                Some(complete) => RelayState::Ended { events, complete },
                None => RelayState::Failed,
            };
            states.push((asked[index].clone(), state));
        }
        // Still reading: on every relay its pages are kept, but it did not answer (SPEC.md §13).
        for (index, relay) in asked.iter().enumerate() {
            let Some(events) = sent[index].take() else { continue };
            let state = RelayState::Reading(if every_relay { events } else { Vec::new() });
            states.push(((*relay).clone(), state));
        }
        let read = complete_read_of(states);
        debug_assert_eq!(read.complete, complete);
        read
    }

    /// Publishes `event` to every relay of `relays` at once, signed and authenticated with `key`.
    /// Succeeds once `quorum` relays took it (the others go on until the call ends, each bounded by
    /// its timeout), fails as soon as they no longer can (the others' requests ended then).
    pub(crate) async fn publish_to_quorum(
        &self,
        relays: &[String],
        event: &Event,
        key: &Secret,
        quorum: usize,
    ) -> Result<(), NotTaken> {
        let (taken_sender, mut answers) = mpsc::unbounded_channel::<bool>();
        let mut requests = Vec::new();
        for relay in relays {
            let connection = self.connection(relay);
            let context = self.context();
            let event = event.clone();
            let key = key.clone();
            let taken_sender = taken_sender.clone();
            let mut tasks = lock(&self.tasks);
            while tasks.try_join_next().is_some() {}
            requests.push(tasks.spawn(async move {
                let taken = publish(&context, &connection, &event, &key).await.is_ok();
                let _ = taken_sender.send(taken);
            }));
        }
        drop(taken_sender);
        let (mut taken, mut failures) = (0, 0);
        loop {
            if taken >= quorum {
                return Ok(());
            }
            if relays.len() - failures < quorum {
                // Failed: only a publication's relays past its majority may finish their own
                // request (SPEC.md §13); the others' end now, none authenticates nor writes again.
                for request in &requests {
                    request.abort();
                }
                return Err(NotTaken);
            }
            match answers.recv().await {
                Some(true) => taken += 1,
                Some(false) => failures += 1,
                None => return Err(NotTaken),
            }
        }
    }
}

/// A key of one read alone, for NIP-42 (SPEC.md §13): 32 fresh random bytes, drawn again in the
/// negligible case they are no secret key of the curve.
pub(crate) fn read_key(random: &dyn Random) -> Secret {
    loop {
        let bytes = crate::runtime::random32(random);
        if crate::secp::is_secret_key(&bytes) {
            return Secret::new(bytes);
        }
    }
}
