# Security

`sattleme-checkout` makes and checks Lightning invoices and on-chain payments for a sattle.me
merchant on an online shop's server. A flaw here could let an attacker be paid instead of the
merchant, mark an order paid that is not, or learn an integration's key: please report it
**privately**, never in a public issue, pull request or discussion.

## How to report

- On GitHub: **Security** tab of this repository → **Report a vulnerability** (private
  vulnerability reporting).
- Or by email: security@sattle.me, subject starting with `[security] checkout-rust`.

Please include what you found, the version of the crate, and, when you can, the steps or the
input that show it. Do not test against real merchants' funds or keys.

## What is in scope

- This crate: anything that, used as its README says, accepts a wrong invoice or payment,
  publishes a record others could alter, or leaks a key.
- A rule of the specification itself goes to
  [sattleme/checkout-spec](https://github.com/sattleme/checkout-spec/blob/main/SECURITY.md).

We will acknowledge your report, keep you informed, and credit you when the fix is published,
unless you prefer otherwise.
