# Changelog

All notable changes to `sattleme-checkout`. Versions follow
[Semantic Versioning](https://semver.org/); tags are `vX.Y.Z`.

Released versions are published on crates.io by CI, once a maintainer approves the release job
(README.md, "Releasing").

## 1.0.0 - 2026-11-21

First version. Follows version 1.0.0 of the specification
([sattleme/checkout-spec](https://github.com/sattleme/checkout-spec)) and passes its
conformance vectors.

- **The client**, `Client`: reads the integration key and the merchant (`merchant()`), makes the
  invoice of an order and declares it in the merchant's registry (`create_invoice()`), checks its
  payment (`get_status()`, `wait_for_payment()`), finds the invoices of an order again
  (`find_invoices()`). Made for a server that lives for one call: nothing is kept between calls.
  Async on Tokio; a call is cancelled by dropping its future, and every call can be spawned.
- **One order, one invoice at a time**, checked against the registry (`invoice_pending`,
  `order_paid`): the payment of an invoice that may still be paid is checked first, even when it is
  the only one, so that an invoice already paid is never handed out again; of several, the one a
  majority of the relays holds is handed out.
- **Orders in sats or in a currency** (the ISO 4217 currencies), converted exactly and rounded up
  to the sat, at the price of a list of rate sources asked in turn: CoinGecko, mempool.space,
  Coinbase, Kraken, OpenNode, or your own (`CustomRateSource`). `currency_digits(code)` gives
  the decimals of a currency whose code is exactly `code`, `None` for any other text, with no
  client: whether a shop may offer its currency, and in how many decimals.
- **Lightning payments**: an invoice from the merchant's Lightning address (LUD-16, LUD-21 verify
  URL).
- **On-chain payments**: from 1 000 sats, a taproot deposit address of the merchant's wallet leased
  for the order, with a single `bitcoin:` QR code (`payment_uri`). A lease is published
  unconfirmed, read again on every relay of the merchant, then marked confirmed: only a confirmed
  lease gives the order its address, and no order leases an address another order holds or a
  witness names. Payment checked on one explorer (paid at 3 confirmations), with fee bumps (RBF)
  and the `unconfirmed` state; `wait_for_payment` watches the address on the explorer's WebSocket.
- **The merchant's Bitcoin node**: the explorer is mempool.space, or the node the integration's
  channel names (`bitcoinNode`: its URL, `http` allowed for a local network, its `fallback`
  `"mempool"` or `"none"`, and `payers`), read over REST and WebSocket with its fallback, a node
  that failed less than 60 s ago in the same call being asked after mempool.space; with `"none"`,
  mempool.space is never asked, and a node that does not answer leases no address and gives
  `network`, never `expired`. With `payers` true, the checkout links' records name the node, whose
  page then reads it too. An invalid `bitcoinNode` is none. The default clients ask a node on a
  local network in clear HTTP/1.1 and WebSocket; an injected client gets an `http://` or `ws://`
  URL for such a node only.
- **Witnesses** of the transactions each check sees, which name the invoice they are of: a
  transaction a witness of another invoice names counts for nothing.
- **The rest of an on-chain underpayment**, payable in Lightning (and on-chain from 1 000 sats),
  shown on the order's checkout links; an order paid both ways is `paid` with `Payment::Mixed`.
- **The merchant's tolerance of on-chain underpayments** (0 to 10 %), read in the integration's
  channel and kept in the lease of each order's address.
- **The merchant's acceptance** of an order underpaid on-chain at what it received, made by the
  merchant in its app: read by every check on every relay of the merchant, and counted only when a
  majority of them hold it; the order is then paid with `received` below its amount. A relay that
  holds it and fails at a check after the invoice's end may make that check give `expired`, and a
  later one `paid` (SPEC.md §3).
- **Checkout links**: `Order::checkout(true)` and `redirect_url` give a `checkout_url`, a page of
  the merchant's web app where the customer pays, then is sent to the redirect URL.
- **The data model** of the specification, as its JSON (`to_json`, `from_json`, serde): an invoice
  stored by another implementation is checked here, and the other way round.
- **JSON as every implementation reads it**: HTTP answers, relay messages, records, stored invoices
  and the explorer's WebSocket go through the crate's own reader, which reads as JavaScript's
  `JSON.parse` does (a number of any length is a double, a string keeps a lone surrogate) and
  takes no text nested more than 64 deep.
- **Records of a newer format**, written by a newer version, are never written over: a lease, a
  witness, a rest record or an acceptance record of a newer format holds what it is of, and each
  one met is logged as a warning to update the crate.
- **Outbound requests**: https URLs only (a lowercase host name, no IP address, no host under
  `localhost`), but for the merchant's Bitcoin node (`http` to a local network, an IPv4 address,
  never `localhost`), no redirect followed, at most 1 MiB read of an answer's body (10 MiB of the
  answer in all, its head and a chunked body's size lines and trailers included), and `User-Agent:
  sattleme-Checkout/1`. The relays' WebSocket handshake follows no redirect, carries the same
  User-Agent, offers no compression and reads at most 64 KiB of its answer; a read keeps only what
  opens with its keys, once per event, so a relay cannot make the server's memory grow. TLS with
  rustls and Mozilla's root certificates.
- **Errors** with a stable `code()` and whether they are `retryable()`; none holds a secret.
