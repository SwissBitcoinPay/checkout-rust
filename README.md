# sattleme-checkout

Take Lightning and on-chain payments for a sattle.me merchant from an online shop's
**server**, in Rust: the invoice of each order (a Lightning invoice, a deposit address of the
merchant's wallet, or both), its declaration in the merchant's registry, and the check of its
payment.

- Everything runs on your server, which holds the integration's secret key. The customer's
  browser only ever gets the invoice and its address: on your page, or on the merchant's web app
  through a [checkout link](#checkout-links), if you ask for one.
- Payments go straight to the merchant's wallet. sattle.me runs no server and no API for
  integrations: this crate talks to the merchant's Lightning address (breez.tips), to the
  merchant's Nostr relays and, for [on-chain payments](#on-chain-payments), to one block explorer
  (mempool.space, or [the merchant's own Bitcoin node](#the-merchants-bitcoin-node) when its app
  names one) and BlockCypher; nothing else (and to the rate source you choose, for prices in a
  currency).
- Amounts are exact: integers (sats, a currency's minor units), strings of digits in JSON, never
  floating-point.

The protocol is specified, for implementations in other languages, in
[sattleme/checkout-spec](https://github.com/sattleme/checkout-spec) (`SPEC.md`), with
conformance vectors every implementation passes. This version implements its version 1.0.0
(`spec/PIN.json`).

## Requirements

- Rust 1.88 or later (`rust-version`), on a **server**, with the [Tokio](https://tokio.rs)
  runtime: call the client from a Tokio runtime with its I/O and time drivers enabled
  (`#[tokio::main]`, or `Builder::enable_all()`), multi-threaded or not.
- A clock synchronized by NTP: invoices more than 5 minutes off the server's clock are refused.
- An integration's secret key: the merchant creates the integration in the sattle.me app
  ("Integrations") and gives you its key, `sattleme_ck_…`.

```sh
cargo add sattleme-checkout
```

or, in your `Cargo.toml`:

```toml
[dependencies]
sattleme-checkout = "1.0.0"
```

## The key is a secret

Keep the integration's key on the server only: in an environment variable or a secrets vault,
never in a web page, an app, a code repository or a log. With it, anyone can make invoices that
pay the merchant and mark sales as the integration's. It can never spend the merchant's funds nor
read their wallet.

The crate never writes it anywhere: no message, no log, no error, no `Debug` of its types holds it
or a key derived from it. The crate's own copies of the key and of the keys derived from it are
overwritten in memory when they are dropped: a best effort, since what the hash, cipher and curve
libraries copy of them (on the stack, in their state), and the keys of each NIP-44 message, are
not.

If it leaks, the merchant removes the integration in the app ("Remove the integration") and
creates another one: the old key then makes no invoice, finds none and reads no merchant
(`ErrorCode::Revoked`). A check of an invoice it made still finds its Lightning payment: an invoice
without an address is checked as before, and one with an address is `ErrorCode::Revoked` unless
its Lightning invoice was paid (SPEC.md §14). The merchant settles by hand the orders still being
paid on-chain.

**One key, one shop.** The merchant creates one integration for each shop (each system with its
own orders' references), and two shops never share a key: the sale of an order is derived from the
key and the order's reference, so two shops with one key would share their references, and an
order of one would be found paid, or pending, with an invoice of the other. The servers of one
shop share its key.

## Quick start

```rust
use sattleme_checkout::{Client, Error, ErrorCode, InvoiceToCheck, Order, PaymentStatus};

// Nothing to connect nor to close: each call reads the merchant, opens one connection per relay
// and closes it when it is done. Cheap to clone: clones share their configuration.
let client = Client::new(std::env::var("SATTLEME_INTEGRATION_KEY")?)?;

// When the customer checks out, or when the payment page asks again: the order's invoice, kept
// with the order as JSON.
async fn invoice_of(client: &Client, order: &mut ShopOrder) -> Result<String, Error> {
    if let Some(invoice) = &order.invoice {
        return Ok(invoice.clone()); // one order, one invoice at a time
    }
    let new = Order::sats(order.reference.as_str(), 49_000) // "ORD-1042": its sale in the merchant's app
        // or: Order::fiat(order.reference.as_str(), "24.50", "CHF")
        .duration_seconds(900) // 60 to 3600
        .note(format!("Order {}", order.number)); // shown to the merchant, 100 characters at most
    let invoice = match client.create_invoice(&new).await {
        Ok(invoice) => invoice.to_json(),
        // An invoice of this order may still be paid (say, after a crash): keep that one. It is the
        // registry's copy: the same fields, without `rate`.
        Err(error) if error.code() == ErrorCode::InvoicePending => {
            error.invoice().expect("invoice_pending carries the invoice").to_json()
        }
        Err(error) => return Err(error),
    };
    order.invoice = Some(invoice.clone());
    db.save(order).await;
    Ok(invoice)
}

// The payment page gets the invoice alone: its paymentUri ("bitcoin:bc1p…?amount=…&lightning=
// lnbc…") and expiresAt. When it asks for the order's status (every 1 to 2 seconds):
async fn status_of(client: &Client, order: &mut ShopOrder) -> Result<&'static str, Error> {
    let stored = InvoiceToCheck::from_json(order.invoice.as_deref().expect("an invoice"))?;
    let status = client.get_status(stored).await?;
    match &status {
        // In Lightning: keep the preimage, the proof of payment. On-chain: the transactions. Mixed
        // (on-chain, its rest in Lightning): both.
        PaymentStatus::Paid(payment) => db.mark_paid(order, payment).await,
        // Never paid: the order may get a new invoice. `received` above 0: an on-chain
        // underpayment the merchant received, to settle with the customer.
        PaymentStatus::Expired { .. } => {
            order.invoice = None;
            db.save(order).await;
        }
        PaymentStatus::Open { .. } | PaymentStatus::Unconfirmed { .. } => {}
    }
    Ok(status.state()) // "open" | "unconfirmed" | "paid" | "expired"
}
```

`create_invoice` gives an `Invoice`, whose JSON (`invoice.to_json()`, or serde) is what you
store with the order:

```json
{
  "ref": "ORD-1042",
  "bolt11": "lnbc490u1p…",
  "paymentHash": "9c41…",
  "verifyUrl": "https://breez.tips/lnurlp/verify/9c41…",
  "onchainAddress": "bc1p…",
  "paymentUri": "bitcoin:bc1p…?amount=0.00049&lightning=lnbc490u1p…",
  "sats": "49000",
  "fiat": null,
  "rate": null,
  "note": "Order 1042",
  "createdAt": 1791378000,
  "expiresAt": 1791378900,
  "checkoutUrl": null,
  "redirectUrl": null
}
```

`bolt11` is null for an order paid on-chain only, `onchainAddress` null without an address
(Lightning only); `fiat` is `{ "amount": "24.50", "currency": "CHF", "minor": "2450", "digits":
2 }` for a price in a currency, with its `rate` (`{ "source": "coingecko", "currency": "CHF",
"price": "69012", "fetchedAt": …, "time": … }`); `checkoutUrl` a checkout link, with
`checkout(true)`. Every amount is a string of digits, every date an integer of Unix seconds, an
absent value `null`: an implementation in another language reads it, and this crate reads theirs
(`InvoiceToCheck::from_json`, or serde with `serde_json`).

**Stored invoices are your shop's.** Check only the invoices your shop stored itself with their
orders, where only it writes (its database), never one that comes from the customer (a form field,
a URL, a cookie): `get_status` checks that a stored invoice is well formed (SPEC.md §22), never that
this integration made it. An invoice someone else wrote, with a Lightning invoice of their own that
they paid, reads as `paid` (SPEC.md §27).

Instead of polling from your page's requests, a background task may wait for the payment:

```rust
use sattleme_checkout::WaitOptions;

let options = WaitOptions::default()
    .interval_ms(2000)
    .on_status(|status| println!("{}", status.state()));
// Dropping the future stops waiting (a timeout, a select!, an aborted task).
let last = client.wait_for_payment(InvoiceToCheck::from_json(&stored)?, options).await?;
// last: PaymentStatus::Paid(Payment::Lightning { preimage }) | Paid(Payment::Onchain { received,
// txids }) | Paid(Payment::Mixed { received, txids, preimages }) | PaymentStatus::Expired { received }
```

A network failure only delays the next check. One that each check meets again (an explorer or the
Lightning address that does not answer…) is reported to your `logger` once, and again only after
it stopped.

### One order, one invoice at a time

- An order keeps its invoice until it has **expired**: `get_status` says `expired` 120 seconds
  after the invoice's end (a payment of its last seconds may be reported that late). Only then may
  the order get a new invoice. `create_invoice` checks it in the merchant's registry and fails with
  `ErrorCode::InvoicePending` (with that invoice, `error.invoice()`) while an earlier invoice of
  the same reference may still be paid (or its on-chain payment is being confirmed), or
  `ErrorCode::OrderPaid` (with its `error.status()`, and the `error.preimage()` of a Lightning
  payment) when one was paid.
- Only the order that holds an invoice is marked paid with it, in the database transaction that
  marks it paid. Keep the preimage (the proof of a Lightning payment) or the txids (of an on-chain
  one) and the `rate` the amount was converted at, to answer a customer or an audit. The paid
  status holds them: store its JSON, `status.to_json()` (`{"state": "paid", "method":
  "lightning", "preimage": …}`, as every implementation writes it), or the `PaymentStatus` with
  serde, which reads it back too. A `Payment` alone has no JSON (SPEC.md §3 writes it only as a
  paid status) and no serde: store the status it came in, or its fields.
- Invoices of the same reference are one sale in the merchant's app. One order, one reference:
  never reused for another order by anything that holds the key (a test copy of the shop, a
  restored database included), and never taken from what the customer sends (make it on your
  server).
- After a failure, `find_invoices(reference)` lists the invoices declared for an order, from the
  merchant's registry.
- "One at a time" holds within one `Client` (and its clones) and against the registry: when several
  processes may make the invoice of the same order at once, lock the order (in your database)
  around `create_invoice`. In a store whose reads may lag behind its writes (an eventually
  consistent one, as some hosted platforms give), read the lock and the order's invoice with reads
  that see the latest writes (consistent reads).

### Showing the invoice

This crate is for servers only. The shop's page shows the invoice with its own code:

- a QR code of `payment_uri`, with any QR library: `bitcoin:<address>?amount=…&lightning=<bolt11>`
  with an address (BIP-21, the "unified QR" wallets read: they pay in Lightning or on-chain),
  `lightning:<bolt11>` without one;
- an "Open in wallet" link to the same URI;
- the time left until `expires_at`, then the status your server gives (`open`, `unconfirmed`,
  `paid`, `expired`). With an on-chain underpayment, `Open` carries what was `received` and its
  `rest`: show its `payment_uri` as the QR code (the rest in Lightning, and on-chain to the same
  address from 1 000 sats), until `expires_at`.

The page talks to your server only: never give it the key, nor ask it to reach breez.tips or the
relays. Or send the customer to a checkout link instead (below).

## Checkout links

Instead of showing the invoice on your page, you may send the customer to a page of the merchant's
sattle.me web app made for this invoice: its QR code, a button that opens the customer's wallet,
the time left, then "Paid" or "Expired". Once the invoice is paid, the page sends the customer back
to your redirect URL, 7 seconds later or at once with a tap.

```rust
let invoice = client
    .create_invoice(
        &Order::fiat("ORD-1042", "24.50", "CHF")
            .note("Order 1042") // shown to the customer too
            .checkout(true)
            .redirect_url("https://shop.example/orders/1042/thanks"), // or "myshop://orders/1042"
    )
    .await?;
// Store it with the order, then redirect the customer's browser to invoice.checkout_url:
// "https://…/pay#c.…" (nothing after "#" is ever sent to the web app's host).
```

- **Optional, per order.** Without `checkout(true)`, nothing changes. A redirect URL alone is
  refused (`ErrorCode::InvalidOrder`, `error.param()` `"redirectUrl"`); without one, the page shows
  the receipt and sends the customer nowhere.
- **Not a proof of payment.** Anyone can open your redirect URL. When the customer arrives there,
  check the order with `get_status` (or `wait_for_payment`) on your server, and mark it paid only
  then, as without checkout.
- **What the page gets**: a record the crate publishes on a majority of the merchant's relays,
  before the invoice is declared: the invoice, its verify URL, its deposit address (with its amount
  and dates), the business's name, the price, the note and your redirect URL. Never the key, the
  merchant's Lightning address nor its registry. It is signed by a key of that link alone,
  forgotten once it is published: nobody, you included, can change a link afterwards. Relays that
  honor NIP-40 drop it a week after the invoice's end.
- **The rest of an underpayment**: with an address, the record also carries the key and the public
  key with which the page reads the invoices of the rest your server asks for
  ([On-chain payments](#on-chain-payments)): the page shows the rest's invoice as soon as a check
  of your server published it, so keep checking the payment while the customer pays
  (`wait_for_payment`, or `get_status` from your page's polling). Only the integration key signs
  them.
- **Who sees the customer**: the customer's browser loads the web app, reads the record from the
  merchant's relays and checks the payment with the merchant's Lightning address (breez.tips):
  they see its IP address, which they never do when your page shows the invoice.
- **Redirect URLs**: `https://` with a lowercase host name (no IP address, no `localhost` nor a
  name under it, no `user:password@`), or an app's link (`myshop://…`), 2048 characters at most,
  every character of RFC 3986 (anything else percent-encoded, host names in punycode). Refused:
  `http:`, browser and file schemes, other browsers' schemes (`x-safari-https:`, `googlechrome:`,
  `firefox:`…, which would open a web page whose host the page cannot show: a web page is an
  `https` URL), `intent:`, payment schemes (`lightning:`, `bitcoin:`…), calls and messages. The
  page shows "Redirecting to shop.example" (or "myshop://") on its button. Prefer universal links
  (iOS) and App Links (Android), which are `https` URLs: browsers do not open an app on their own
  after a delay (Chrome on Android refuses it), so for an app's link the customer taps the button.
- **One order, one invoice at a time** holds with checkout links too. When an invoice of the order
  may still be paid, `ErrorCode::InvoicePending` carries, with `checkout(true)`, a new link to it:
  `error.checkout_url()`. Send the customer there.
- **Availability**: the merchant's app says in the integration's channel where its web app is. An
  app without a web app gives none: `create_invoice` with `checkout(true)` fails with
  `ErrorCode::CheckoutUnavailable`; show the invoice on your page instead.

## On-chain payments

From 1 000 sats, an order may also be paid on-chain, to a deposit address of the merchant's
wallet. Nothing to ask for: `create_invoice` leases an address when the amount allows it, and the
Invoice's `payment_uri` shows both methods in one QR code.

| Amount                                          | Methods                                                           |
| ----------------------------------------------- | ----------------------------------------------------------------- |
| below 1 000 sats                                | Lightning (outside its bounds: `InvalidOrder`)                    |
| 1 000 sats or more, within the Lightning bounds | Lightning and on-chain (Lightning only without an address)        |
| 1 000 sats or more, outside them                | on-chain only (`OnchainUnavailable` without an address)           |

- **The lot**: your server has no wallet and makes no address. The merchant's app gives the
  integration a lot of up to 100 taproot addresses (`bc1p…`) of its wallet, and fills it again
  whenever the merchant opens the app. `merchant().await?.onchain_addresses` says how many it holds
  (0: no on-chain payment yet).
- **One address, one order**: an order leases an address in the merchant's registry until its
  invoice's end plus 120 seconds; two servers never keep the same one. The lease is published, read
  again on every relay of the merchant (it is confirmed when no other order holds the address),
  then marked confirmed: only then is the address the order's. An address the explorer shows paid
  already, or that a witness (below) names, is skipped.
- **Unconfirmed, then paid**: `get_status` says `unconfirmed` once enough was sent in time, then
  `paid` (`Payment::Onchain`) at 3 confirmations on the explorer (mempool.space, or the merchant's
  Bitcoin node): about 30 minutes. Ship the order only once it is `paid`. `wait_for_payment` watches
  the address on the explorer's WebSocket meanwhile; a server that cannot wait that long checks
  again later with `get_status` (`create_invoice` for the same reference fails with `InvoicePending`
  while it is being confirmed).
- **In time**: a transaction counts for the order when it came while the lease ran. The crate
  records each transaction it sees in the merchant's registry (a witness), so that the merchant's
  app tells the same order paid: check the payment while the customer pays (your page's polling,
  or `wait_for_payment`), until the invoice's end and its 120 seconds. A transaction no check saw
  by then is told by BlockCypher's time; one received after the end is late: it reaches the
  merchant, but pays no order. A replacement (RBF, a fee bump) of a payment in time counts for it.
  A transaction counts for one invoice at most: one that a witness of another invoice names counts
  for nothing here.
- **Underpaid**: `received` is what came in time. Below the amount (and unless the merchant's
  tolerance or acceptance, below, accepted it), the invoice stays `open` until its end, then
  `expired` with `received` above 0: the merchant received it, settle it with the customer. An
  overpayment is `paid`.
- **The merchant's tolerance**: the merchant may accept, in its app, an on-chain payment a little
  short of the amount (up to 10 %) as paying the order in full. An order keeps the tolerance of its
  creation, whatever the merchant sets later. A payment short by no more than it is
  `unconfirmed`, then `paid`, with `received` below the amount: ship the order as for any `paid`
  status. One short by more is underpaid: its whole rest is asked. The tolerance is the
  merchant's: the crate never gives it to your server, nor to your customer; the page of a checkout
  link learns only that this payment counts (an acceptance record), and sends the customer back to
  your shop.
- **The merchant's acceptance**: the merchant may also accept, by hand in its app, what an order
  underpaid on-chain received as paying it in full: one short by more than its tolerance, which
  the merchant would rather settle at what came. Nothing to configure, nothing to call: every
  check (`get_status`, `wait_for_payment`, and `create_invoice`'s check of an order's earlier
  invoices) reads it on every relay of the merchant with the order's witnesses, and counts it only
  when a majority of those relays hold it. The order is then `unconfirmed`, then `paid`
  (`Payment::Onchain`, or `Payment::Mixed` with invoices of the rest), with `received` below the
  amount, as with the tolerance: ship it as for any `paid` status. `wait_for_payment` sees it at
  its next check of the on-chain part (within 60 s), the `rest` still given until then. Only the
  merchant's team can make one: neither your server's key nor a customer can. The page of a
  checkout link learns of it as of the tolerance, through an acceptance record. One exception to
  `expired` being final (SPEC.md §3): when a relay that holds the acceptance fails at a check after
  the lease's end, that check may give `expired`, and a later one, which the relay answers,
  `unconfirmed`, then `paid`. If you cancelled the order on `expired`, settle it by hand.
- **The rest, in Lightning**: the check that sees an underpayment (`get_status`,
  `wait_for_payment`) asks the merchant's Lightning address for an invoice of the rest, until the
  invoice's end, declares it in the merchant's registry and publishes it for the order's checkout
  links, whose page shows it at once. `PaymentStatus::Open` carries it in `rest`:

  ```json
  {
    "state": "open",
    "expiresAt": 1791378900,
    "received": "20000",
    "rest": {
      "sats": "29000",
      "bolt11": "lnbc290u1p…",
      "paymentUri": "bitcoin:bc1p…?amount=0.00029&lightning=lnbc290u1p…"
    }
  }
  ```

  `received` is what came in time, `rest.sats` all that is left (whatever the tolerance or the
  merchant's acceptance), `rest.bolt11` its invoice (null while there is none: asked at the next
  check). From 1 000 sats the rest is payable on-chain to the same address too; below, in Lightning
  only (`paymentUri` is `lightning:…`, or null while its invoice is asked). No invoice of the rest
  is asked with less than a minute left, nor outside the Lightning address's bounds; a failure is
  logged as a warning, never returned: the next check asks again. Once the rest is paid, the order
  is `unconfirmed` until its on-chain part is 3 confirmations deep, then `paid` with
  `Payment::Mixed`: keep its `txids` and the `preimages` of the invoices of the rest.

- **Who sees what**: the explorer (mempool.space, or the merchant's Bitcoin node, and
  mempool.space too when the node fails and its fallback allows it) sees your server's IP address
  and the addresses and transactions it asks about or watches; BlockCypher, a transaction no check
  saw in time. Never a key. A payment counts as made on what that one explorer shows.

### The merchant's Bitcoin node

The merchant may have the blockchain read from a node of its own that serves mempool.space's API
(an Umbrel, a server of its own) rather than from mempool.space. It sets it in its app, which
writes it in the integration's channel: nothing to configure on your server. Every call reads it
with the channel; every read of an address and of the chain's height (when an address is leased,
at each check), and `wait_for_payment`'s WebSocket, then go to the node: `http://192.168.1.10:3006`
is read at `http://192.168.1.10:3006/api` and `ws://192.168.1.10:3006/api/v1/ws` (`wss://` for an
`https://` node). BlockCypher and the `mempool` rate source stay BlockCypher's and mempool.space's.

- **Its URL** follows a rule of its own (SPEC.md §31): `https`, or `http` for a host of a local
  network only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, a name under `.local`);
  an IPv4 address or a name, never `localhost`, 127.0.0.0/8 nor 0.0.0.0/8; no user name, query nor
  fragment. A node the channel names in any other way, or with an invalid `fallback` or `payers`,
  is none: mempool.space is read, and the channel stays valid.
- **Its `fallback`**, when the node does not answer a read (no answer, an error status, a redirect,
  an answer out of format):
  - `"mempool"`: the same read of mempool.space, `ErrorCode::Network` when both fail. A node that
    failed less than 60 s ago in the same call (`create_invoice`, `get_status`, one
    `wait_for_payment`) is asked after mempool.space, so that a node that is down does not make
    each read wait for its timeout. The WebSocket goes to mempool.space's when the node's fails, or
    is lost before any message.
  - `"none"`: mempool.space is never asked. While the node does not answer, no address is leased
    (`create_invoice` gives a Lightning invoice only, or fails with `ErrorCode::Network` for an
    order paid on-chain only) and every check of an order with an address fails with
    `ErrorCode::Network`: never `expired` nor final underpaid for want of an answer. The order
    waits until the node answers again.

  A check's two reads (the address's transactions and the chain's height) always come from one
  explorer: when the node fails either, both are asked of mempool.space.

- **A node on the merchant's network** (`http://192.168.1.10:3006`, `http://umbrel.local`) is
  reachable only by a server on that network: a shop the merchant hosts itself, or one that
  joined it (by Tailscale, for one). Any other server fails every read of it, and its fallback
  applies: with `"none"`, no on-chain payment at all.
- **`payers`**: with `true` (only for a node of the Internet: `https` and a name, not under
  `.local`), the checkout links' records name the node (its `url` and `fallback`, never `payers`),
  and their page reads the chain from it too, with the same fallback; the node then sees the
  customer's IP address and the address the page follows, and whoever holds a link reads the
  node's URL. With `false`, only your server reads the node, and the page reads mempool.space.
- **Your HTTP and WebSocket clients**: the default ones ask a node on a local network in clear
  HTTP/1.1 and WebSocket, with the same hyper and tokio-tungstenite as every other request (over a
  plain TCP connection in place of rustls's), and an `https`/`wss` node over TLS, verified for its
  name or its IPv4 address. An `HttpClient` you give gets an `http://` URL (`HttpRequest::url`),
  and a `WebSocketClient` a `ws://` one, only for a node on a local network: send it in clear, or
  fail it, and the node's fallback applies. Never for any other request.
- **Security**: a node's URL is the merchant's choice, and the crate follows a valid one: GET
  requests at the paths of mempool.space's API under `/api`, and the WebSocket's two messages, in
  clear HTTP too to a host of a local network, and to an IPv4 address. Nothing is sent but deposit
  addresses, no redirect is followed, and every answer is bounded and checked. But if your server
  holds the keys of several merchants (a shared host), one merchant could so have it ask machines
  of your own network: restrict what your server can reach to public addresses (see
  [Outbound requests](#outbound-requests)); such a merchant's node is then unreachable, and its
  fallback applies. The node is trusted as mempool.space is: what it shows decides whether an
  order is paid. Over `http`, whoever is on the network between your server and the node can
  change its answers: it is as safe as that network.

## Prices in a currency

Give a price instead of sats (`Order::fiat`): the crate converts it to sats on your server, at the
rate of a price source, and declares the price to the merchant's app, which shows it. Nothing to
set up: without a rate source, it asks the default list of sources (below).

```rust
let invoice = client.create_invoice(&Order::fiat("ORD-1043", "24.50", "CHF")).await?; // a string: never a float
// 24.50 CHF at 69 012 CHF/BTC: ⌈2450 × 10^8 / 6 901 200⌉ = 35 502 sats
```

- The currency is an ISO 4217 code in upper case, of the ISO 4217 currencies (List One, without
  funds, metals and test codes). The amount is a string of digits with at most the currency's
  decimals (2 for CHF, 0 for JPY, 3 for KWD): those the merchant's app uses, from the crate's own
  table, never from the platform's locale data.
- `sattleme_checkout::currency_digits(code)` gives them: the decimals of the currency whose code
  is exactly `code` (`Some(2)` for `"CHF"`), `None` for any other text (`"chf"`, `" CHF"`, a fund,
  a metal, `"BTC"`). It needs no client, no key and no request: ask it whether your shop may offer
  its customers to pay in its currency, and in how many decimals its prices go to
  `create_invoice`.
- The conversion is exact, on integers: the price of one bitcoin is read as the decimal its source
  wrote, and the sats are **rounded up** to the next whole sat, so that the merchant never receives
  less than the price.
- The sats must fit the bounds of the merchant's Lightning address (`merchant()`), as for an amount
  in sats.

### Rate sources

A rate source is optional. Without one, the crate asks these sources **one after the other**, the
next one only when the previous one does not answer, gives no usable price, or has no price in the
currency (`RateSource::defaults()`):

`coingecko`, then `mempool`, `coinbase`, `kraken` and `opennode`.

The dated sources come first (a dated price is checked for its age), then the undated ones. The
first usable price is the rate, and `invoice.rate`'s `source` names the source that gave it. Each
source that failed before it is reported to your `logger` as a warning.

To choose, give sources to the client or to an order (an order's win):

```rust
use sattleme_checkout::RateSource;

Client::builder(key.as_str()).rate_source(RateSource::Kraken).build()?; // this source only: no other is asked
Client::builder(key.as_str()).rate_sources([RateSource::Kraken, RateSource::Coingecko]).build()?; // in this order
let order = Order::fiat("ORD-1044", "24.50", "CHF").rate_sources([RateSource::Mempool, RateSource::Coinbase]);
let named: RateSource = "kraken".parse()?; // a name, as the specification writes it
```

A list holds sources (names or your own), at least one, no name twice; anything else fails with
`ErrorCode::InvalidOption` (`InvalidOrder` for an order, `error.param()` `"rateSource"`). Each
source asked may take up to the HTTP timeout: a list of 5 sources that all fail to answer may take
5 times as long.

| Source                  | Currencies                  | Dated | Notes                                                                                                         |
| ----------------------- | --------------------------- | ----- | ------------------------------------------------------------------------------------------------------------- |
| `RateSource::Coingecko` | many                        | yes   | No key needed. Optional: a Demo key (`coingecko_api_key`), sent to CoinGecko only. Without one, limited by IP. |
| `RateSource::Mempool`   | USD EUR GBP CAD CHF AUD JPY | yes   |                                                                                                               |
| `RateSource::Coinbase`  | many                        | no    | Prices are decimal strings, read as written.                                                                  |
| `RateSource::Kraken`    | Kraken's pairs              | no    | The last trade's price.                                                                                       |
| `RateSource::Opennode`  | ~140                        | no    |                                                                                                               |
| `RateSource::custom`    | yours                       | maybe | A `CustomRateSource`: `"69012.5"`, or `{ price, time }`. Never a number. Its `rate.source` is `"custom"`.      |

Any other source (a CoinGecko Pro key, your own mempool instance, several sources checked against
each other) is your own: it gives the price as a **string**, as its source wrote it: a number may
already have lost digits.

```rust
use sattleme_checkout::{BoxFuture, CustomPrice, CustomRateError, CustomRateSource, Error, RateSource};

struct MyRates {
    http: reqwest::Client, // whatever client you use
}

impl CustomRateSource for MyRates {
    fn price<'a>(&'a self, currency: &'a str) -> BoxFuture<'a, Result<CustomPrice, CustomRateError>> {
        Box::pin(async move {
            // Your service answers { "price": "69012.50", "time": 1791378000 }: the price as a string.
            let response = self.http.get(format!("https://rates.example.ch/btc/{currency}")).send().await?;
            if response.status() == 404 {
                return Err(Error::unsupported_currency(currency).into());
            }
            let answer: Answer = response.json().await?;
            Ok(CustomPrice { price: answer.price, time: Some(answer.time) })
        })
    }
}

let client = Client::builder(key).rate_source(RateSource::custom(MyRates { http })).build()?;
```

A price its source dates is refused when it is more than an hour old, or more than 5 minutes
ahead: the next source of the list is then asked. When no source gives a price, `create_invoice`
fails with `UnsupportedCurrency` if none of them has the currency, else the last `Rate` error (no
usable price) or `Network` error (no answer), both retryable. Your source fails with
`Error::unsupported_currency(currency)` when it has no price in a currency, or with a `Network` or
`Rate` error of the crate when it cannot give one now: the next source is then asked. Any other
error of yours becomes a `Rate` error (your error as its `source()`); an error of the crate of
another kind stops the list and goes through as it is.

## Errors

Every failure is an `Error` with a stable `code()` (`ErrorCode`, whose text is the code every
implementation uses) and `retryable()`. A call cancelled (its future dropped) gives none. None ever
holds a secret: neither the key, nor a sale's key, nor any key derived from them, in its message,
its `Debug` or its `source()`.

| `ErrorCode`           | Code                   | When                                                                                                                                      | Retry?           |
| --------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| `InvalidKey`          | `invalid_key`          | The key is not an integration key (another prefix, damaged, an old `https://…/pay#…` link).                                               | no               |
| `InvalidOption`       | `invalid_option`       | An option of the client or of `wait_for_payment` is invalid: `param()` names it.                                                          | no               |
| `InvalidOrder`        | `invalid_order`        | A parameter is invalid: `param()` names it (`ref`, `sats`, `fiat`, `rateSource`, `durationSeconds`, `note`, `checkout`, `redirectUrl`, `invoice`). | no |
| `Revoked`             | `revoked`              | The merchant removed the integration.                                                                                                     | no               |
| `ChannelNotFound`     | `channel_not_found`    | The relays answered without the integration's channel (`newer_format()`: update the crate).                                               | when not newer   |
| `Network`             | `network`              | A relay, breez.tips, a rate source or an explorer did not answer, or fewer than a majority of the merchant's relays took a record.        | yes              |
| `InvalidInvoice`      | `invalid_invoice`      | An invoice or a payment answer failed the checks. Never show such an invoice.                                                             | no               |
| `InvoicePending`      | `invoice_pending`      | An earlier invoice of this order may still be paid, or is being confirmed on-chain: `invoice()` (and `checkout_url()` with a link).       | after it expires |
| `OrderPaid`           | `order_paid`           | An earlier invoice of this order was paid: `invoice()`, `status()`, `preimage()` (`None` on-chain).                                       | no               |
| `UnsupportedCurrency` | `unsupported_currency` | The rate source has no price in this currency: `currency()`.                                                                              | no               |
| `Rate`                | `rate`                 | No usable price: invalid, too old, or your rate source failed.                                                                            | yes              |
| `CheckoutUnavailable` | `checkout_unavailable` | `checkout(true)`, and the merchant's app gives no web app for checkout links.                                                             | no               |
| `OnchainUnavailable`  | `onchain_unavailable`  | The order can only be paid on-chain, and no address of the integration's lot could be leased.                                             | yes              |

## Cancellation

A call is cancelled the Rust way: drop its future (`tokio::time::timeout`, a `select!`, an aborted
task). It stops at once, whatever it was waiting for (a relay, an HTTP answer, the resolution of a
name on a thread of Tokio's blocking pool: that thread finishes on its own, unwaited), nothing it
started runs on, and it gives no `Error`. Every call's future is `Send`, and `'static` once it owns
what it borrows: spawn it on any task.

## What `create_invoice` does

1. Reads the integration's channel on the Nostr relays of the key (signed by the merchant's team,
   following up to 3 moves of the merchant's relays): the merchant's Lightning address, registry
   and relays, or `removed`. At every call: a removal stops the next invoice.
2. Checks that no earlier invoice of the order may still be paid (its payment checked: one already
   paid is never handed out again, `OrderPaid`; one underpaid on-chain gets the invoice of its
   rest, as with `get_status`, before `InvoicePending`). Meanwhile, reads the Lightning address
   and, for a price in a currency, the rate.
3. Converts the price to sats, when it is in a currency; its methods follow from the amount.
4. With Lightning, asks the merchant's Lightning address for the invoice (LUD-06/16), and checks
   it: Bitcoin mainnet, exactly the amount, the merchant's description hash, a verify URL (LUD-21)
   on the same host and port, no longer than asked, dated within 5 minutes.
5. With on-chain, leases an address of the integration's lot: publishes the lease on a majority of
   the merchant's relays, reads the address's leases again on every relay to confirm it, then marks
   it confirmed. A lease that was not confirmed is withdrawn, and the next address is tried.
   Without an address, Lightning only (or `OnchainUnavailable`).
6. With `checkout(true)`, publishes its checkout link on a majority of the merchant's relays.
   Without a majority, no invoice (nothing is declared).
7. With Lightning, declares it in the merchant's registry, on a majority of the merchant's relays:
   so that its payment counts for this order's sale and for no other. Without a majority, no
   invoice.

A confirmed lease is never withdrawn, whatever fails after it (its mark, the link, the
declaration): it holds its address until its end, and the order's next `create_invoice` may hand
its invoice out (`InvoicePending`).

`get_status` asks the invoice's verify URL (LUD-21) and accepts a Lightning payment only with the
preimage of its payment hash, in an answer about this very invoice; with an address, it asks the
explorer at the same time and reads the witnesses of the order and the merchant's acceptance of
the invoice (see [On-chain payments](#on-chain-payments)).

A call opens one connection per relay, used for all it reads and writes there, and closes them
when it is done. Reads and writes go on as soon as a majority of the relays answered (each
declaration is on a majority of them, and any two majorities share a relay): a slow or down relay
slows nothing. Three reads decide that a record is nobody else's and wait for every relay instead,
up to the relay timeout after a majority answered: a lease's confirmation, the witnesses read again
after one is published, and the choice among several invoices of an order that may still be paid.
So does the read of the merchant's acceptance, which counts only what a majority of them sent.
A relay that failed earlier in the call is not waited for again; one still reading when such a
read goes on gives its pages as records, never as an answer. A write to the relays past the
majority goes on in the background until the call is done, then its connection closes.

HTTP requests (the merchant's Bitcoin node's included) follow no redirect, read at most 1 MiB of an
answer's body (and of the default client, 10 MiB of the answer in all: its head, and a chunked
body's size lines and trailers, bounded too), and carry `User-Agent: sattleme-Checkout/1`, the same
in every implementation of the specification. The WebSocket handshake (of the relays and of the
explorer) follows no redirect either, carries the same User-Agent (relays behind a bot protection
refuse a handshake without one), and offers no compression. Of what a relay sends, a read keeps only
what opens with its keys and, for a signed record, whose signature checks out, once per event and
without the members a relay may add to it (of a lease, only its id, author, date, signature and end;
of any other event, its id and its date): a relay that sends one event many times has its first copy
read, the others only counted, and cannot make the server's memory grow. JSON is read as JavaScript
reads it, by the crate's own reader: a text nested more than 64 deep is no JSON.

## Outbound requests

Besides fixed hosts (the rate sources, mempool.space, BlockCypher), your server asks hosts that
others choose: the merchant's Lightning address and its provider (breez.tips), the merchant's
relays, and the merchant's Bitcoin node when its app names one. Their URLs are checked first:
`https` or `wss` only, no IP address, no `localhost` nor a name under it, no redirect followed; but
for the node, whose URL allows `http` to a host of a local network and an IPv4 address ([The
merchant's Bitcoin node](#the-merchants-bitcoin-node)), never `localhost`. A name may still lead
into your own network (an internal name, a public name resolving to a private address), and the
crate does not resolve names itself (a name that resolves again would bypass such a check): the
system resolves them, within each request's timeout. If your server holds the keys of several
merchants, or sits in a network with services of its own, restrict what it can reach to public
addresses: in your network (an egress proxy, a firewall), or in the HTTP and WebSocket clients you
give the client (a merchant's node on a private address is then unreachable, and its fallback
applies).

TLS is verified against the Mozilla root certificates of `webpki-roots`, the same on every machine,
whatever the system's store (a minimal container has none): a host whose certificate does not
chain to one of them gets no request. Behind a TLS-intercepting proxy, inject clients that trust
its authority.

## Limits

- One hour at most per invoice; on-chain, about 30 minutes more to be `paid` (3 confirmations).
- Not measured: the limits of breez.tips, of the explorer and of the relays for a shop that makes
  many invoices from one IP address. BlockCypher takes 100 requests an hour from an IP address
  without a token: it is asked only about a transaction no check saw while its lease ran.

Not in this version: refunds, webhooks, and showing open (unpaid) invoices in the merchant's app.

## Cryptography

Keys, BIP-340 signatures and the ECDH of NIP-44 are computed by libsecp256k1, Bitcoin Core's C
library, through rust-bitcoin's `secp256k1` 0.33.1 (its `secp256k1-sys` 0.14.1 builds the copy of
the library it vendors, libsecp256k1 at commit 6e2c8bc4, with your C compiler); HKDF, HMAC-SHA256
and SHA-256 by RustCrypto's `hkdf`, `hmac` and `sha2`, ChaCha20 by its `chacha20`. Never curve
code of this crate's own.

libsecp256k1 signs and computes ECDH in constant time, as its README says ("Constant time,
constant memory access signing and public key generation"): the point of a signature's nonce, and
a public key, by `secp256k1_ecmult_gen`, a comb over precomputed tables that reads every entry of
a table with conditional moves (no branch, no memory address depends on the secret scalar), its
scalar blinded by a value of the context; ECDH's point by `secp256k1_ecmult_const`, constant time
in the secret scalar (the point is public). The library checks these paths for branches and
memory accesses that depend on secrets, under Valgrind or MemorySanitizer (`src/ctime_tests.c`);
nothing checks the machine code your compiler makes of it. `secp256k1` blinds its thread's context
again after each signature, from the secret key (its `rand` feature, which would mix in random
bytes, is off). Verifying a signature handles nothing secret and takes a variable time. MACs are
compared in constant time (`hmac`'s `verify_slice`, SPEC.md §27), and random bytes come from the
operating system's CSPRNG (`getrandom`).

## Options

```rust
let client = Client::builder(key) // required
    .rate_sources(RateSource::defaults()) // optional: a source or a list of them; the default list
    .coingecko_api_key(demo_key) // optional: CoinGecko's Demo key (visible ASCII), sent to CoinGecko only
    .relay_timeout_ms(10_000) // per relay request, connection included: 100 to 60 000
    .http_timeout_ms(10_000) // per HTTP request, body included: 100 to 60 000
    .http_client(my_http_client) // an HttpClient: hyper over rustls by default
    .websocket_client(my_websocket_client) // a WebSocketClient: tokio-tungstenite over rustls by default
    .logger(my_logger) // a Logger, warnings only, never a secret: the `log` crate's warn! by default
    .build()?; // an invalid option: ErrorCode::InvalidOption, at once
```

`Client::new(key)` is `Client::builder(key).build()`. `clock` and `random` are for reproducible
tests only. `wait_for_payment` takes `WaitOptions` (`interval_ms`: 250 to 60 000, 2000 by default;
`on_status`).

Within one call, the crate calls what you give it (the HTTP and WebSocket clients, the logger,
the clock and the randomness) from several tasks at once, on several threads of a multi-threaded
runtime, and so do calls that run at the same time: each must be safe to call so (the traits
require `Send + Sync`). A call returns only once everything it started ended: its relays'
connections closed, and the relays past a publication's majority not awaited (their requests end
with the call; SPEC.md §13). Once it returned, nothing it started calls what you gave it, but for
the system's resolution of a host name by the default clients (`getaddrinfo`, on a thread of
Tokio's blocking pool), which cannot be stopped: it ends on its own, its result unused.

An `HttpClient` you give follows no redirect (it hands a 3xx answer over, or fails) and sends the
request's headers in place of its own; a `WebSocketClient` sends the request's headers in its
handshake, follows no redirect and offers no compression; both verify TLS, and send an `http://` or
`ws://` URL (a merchant's Bitcoin node on a local network, the only one the crate gives them) in
clear, or fail it. The crate bounds every
request by its timeout and reads at most 1 MiB of an answer's body; bound what your clients hold of
an answer's head (status line, headers, a chunked body's size lines and trailers) and of the answer
to a WebSocket's opening handshake at 10 MiB at most, as HTTP libraries do, most far lower
(SPEC.md §15).

## Other languages

The crate's public API is `Client`, its builder, its types, its `Error` and `currency_digits`:
everything else is internal. Implementations in other languages follow
[`SPEC.md`](https://github.com/sattleme/checkout-spec/blob/main/SPEC.md) and pass its conformance
vectors; the invoices they store are the same JSON.

## Dependencies

Few, maintained, each for what the standard library does not do. `Cargo.toml` requires each as
Rust crates do, from the version below (any later compatible one, by semver); `Cargo.lock` pins
every package of this repository's build exactly, with its checksum: what the CI builds and
tests, as it is (`--locked`). Your application resolves the requirements into its own
`Cargo.lock` (Cargo ignores a dependency's): `cargo update` takes newer compatible versions than
the CI tested, and `cargo deny`, or `cargo audit`, checks them against RustSec's advisories.

| Crate                    | Version  | Why                                                                                                                                                     |
| ------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secp256k1`              | 0.33.1   | Bitcoin Core's libsecp256k1: BIP-340 signatures (32 fresh random bytes of auxiliary data each) and their verification, x-only keys, `lift_x`, the ECDH of NIP-44. Never curve code of our own. |
| `chacha20`               | 0.10.2   | NIP-44 v2's ChaCha20 (RustCrypto), checked against NIP-44's official vectors.                                                                            |
| `hkdf`, `hmac`, `sha2`   | 0.13.0, 0.13.0, 0.11.1 | HKDF-SHA256 (every key derivation), HMAC-SHA256 (NIP-44's MAC, compared in constant time; the addresses of witnesses), SHA-256 (event ids, preimages). |
| `num-bigint`             | 0.5.1    | The exact conversion of a price to sats: integers beyond 64 bits.                                                                                        |
| `getrandom`              | 0.4.3    | The operating system's CSPRNG: every nonce, signature randomness and key of a read.                                                                      |
| `zeroize`                | 1.9.1    | Secrets overwritten in memory when they are dropped.                                                                                                     |
| `tokio`                  | 1.54.1   | The runtime's sockets, timers, tasks and locks (`net`, `time`, `rt`, `sync`, `macros`).                                                                  |
| `futures-util`           | 0.3.34   | Many futures at once (the relays of a read, the checks of an order), the WebSocket's sink and stream.                                                    |
| `hyper`, `hyper-util`    | 1.12.0, 0.1.21 | The default HTTP/1.1 client, one connection per request: it follows no redirect by itself; the body read chunk by chunk, up to 1 MiB; its head bounded at some 400 KiB, a chunked body's trailers and chunk extensions at 16 KiB, the answer by the crate at 10 MiB in all (hyper reads a size line's leading zeros and whitespace without a bound). |
| `http`, `http-body-util`, `bytes` | 1.5.0, 0.1.5, 1.12.1 | The request and body types hyper and the WebSocket handshake take.                                                                   |
| `tokio-tungstenite`      | 0.30.0   | The default WebSocket client: no permessage-deflate (no compression offered), messages and frames bounded at 1 MiB, the answer to its handshake at 64 KiB, the handshake's headers ours. |
| `rustls`, `tokio-rustls` | 0.23.46, 0.26.6 | TLS 1.2 and 1.3, verified, with the `ring` provider (no C toolchain beyond a C compiler, no CMake), for HTTP and WebSockets.                 |
| `webpki-roots`           | 1.0.12   | Mozilla's root certificates, the same on every machine (from 1.0.11: without the distrusted emSign roots, RUSTSEC-2026-0381).                           |
| `serde`                  | 1.0.229  | `Serialize` and `Deserialize` of the data model, as the JSON of SPEC.md §3 (the crate reads JSON with its own reader, as JavaScript does).               |
| `log`                    | 0.4.35   | The default logger: warnings to whatever `log` backend the server uses.                                                                                  |

For the tests only: `rcgen` 0.14.10 (a test certificate authority, made at each run: no key in the
repository), `serde_json` 1.0.154 (JSON literals, serde round trips) and Tokio's `test-util`
(virtual time). The CI checks the RustSec advisories, the licenses and the sources of every
dependency with `cargo-deny` (`deny.toml`).

Why its own JSON reader: SPEC.md §2 reads JSON as JavaScript's `JSON.parse` does, and
`serde_json` differs where it matters: it refuses a whole document for a lone surrogate escape
(`"\ud800"`) in a member nobody reads, and a number beyond a double (`1e400`, which JavaScript
reads as `Infinity`). The data model's serde implementations still read through your serde format
(and so do as it does).

## Development

```sh
cargo xtask check # the pinned specification, cargo fmt, clippy, tests, the README's examples, docs, the package
```

The toolchain of the checks is pinned (`rust-toolchain.toml`: Rust 1.100.0, with clippy and
rustfmt); the CI runs them, the tests on Rust 1.88.0 (`rust-version`) too, and `cargo deny
--locked check` (cargo-deny 0.20.2). The tests run local Nostr relays and fakes of breez.tips, of
the rate sources, of the explorers (mempool.space and a merchant's Bitcoin node, REST and
WebSocket) and of BlockCypher, reached under their
real host names through injected clients: no network. A few run real TLS sockets on localhost, with
a test certificate authority made at each run. The Rust blocks of this README are compiled against
the crate (`cargo xtask readme`), each in a function that gives it what the README leaves to you (a
client, the key, your orders and database: `xtask/src/readme.rs`).

`spec/` is a copy of [sattleme/checkout-spec](https://github.com/sattleme/checkout-spec) pinned to
one commit (`spec/PIN.json`, checked file by file by `cargo xtask spec check` and the tests), never
edited here. Its vectors are what the tests check the crate against: the conformance vectors, the
merchant's app's vectors (`spec/vectors/app/app.json`) and the vectors an implementation makes for
the app (`spec/vectors/app/implementation-declaration.json`, `checkout-link.json`,
`checkout-rest.json`). To take a new version: clone checkout-spec, check out the commit (a tagged
version when there is one), then `cargo xtask spec import <clone>`, and change the crate and its
tests until `cargo xtask check` passes, in one pull request.

The toolchain (`rust-toolchain.toml`), rustup in the CI (`.github/actions/install-rust`, its
version and SHA-256) and cargo-deny (`.github/workflows/ci.yml`) are updated by hand, each at its
latest release at least 7 days old; Dependabot proposes the dependencies and the actions, one
pull request per ecosystem grouping all its updates, each a week after its release (`cooldown`,
`.github/dependabot.yml`).

## Releasing

Releases are the maintainers'. A maintainer pushes a tag `vX.Y.Z` on a commit of `main`, equal to
`Cargo.toml`'s `version` (with its `CHANGELOG.md` entry). `.github/workflows/release.yml` then runs
the CI again, checks the tag and that its commit is on `main`, builds the package
(`cargo publish --dry-run`), and publishes it on crates.io in a job bound to the protected
environment `crates-io`, with crates.io's trusted publishing: a token of 30 minutes, exchanged for
the job's OIDC token and revoked when it ends, no stored secret. To set it up, once:

1. On crates.io, the first version: trusted publishing applies to a crate that exists. A
   maintainer publishes 1.0.0 from a clean checkout of its tag (`cargo publish --locked`) with an
   API token scoped to `publish-new` for `sattleme-checkout` alone, then revokes the token, and
   adds the other maintainers as owners.
2. On crates.io, the crate's Settings, Trusted Publishing: GitHub, owner `sattleme`, repository
   `checkout-rust`, workflow `release.yml`, environment `crates-io`.
3. On GitHub, the repository's environment `crates-io`: required reviewers (a maintainer approves
   each release), deployment tags `v*`. Protect the `v*` tags with a ruleset, so that only
   maintainers create them.

## License

[MIT](LICENSE)
