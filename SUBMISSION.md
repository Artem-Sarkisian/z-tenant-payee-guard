# T3N Agent Build Challenge — submission

**Project:** z-tenant-payee-guard — payee-substitution defence for accounts payable
**Repo:** https://github.com/Artem-Sarkisian/z-tenant-payee-guard
**DID:** did:t3n:b5665866494eb7c4605cbce6ea39833db028d7da
**Deployed:** T3N testnet, contract id **765**, tail `payee-guard`, v0.1.0
**Built with:** Claude Code · Rust 1.98.0 → wasm32-wasip2 · @terminal3/t3n-sdk 5.2.0

---

## What it does

Business-email-compromise fraud does not break cryptography. It edits a bank
account number on an otherwise genuine invoice from a supplier the company
really does owe money to, and the payment goes out because nothing in the
process ever asks the one useful question:

**Have we ever paid this vendor at this account before?**

`z-tenant-payee-guard` answers exactly that, and nothing else.

| Function | Purpose |
| --- | --- |
| `enroll-payee` | Register or rotate a vendor's known-good account. Rotation is counted and timestamped, never silent. |
| `verify-payee` | Check one payment instruction. Returns verdict, risk band, reasons, and whether an out-of-band check is required. |
| `vendor-status` | Non-sensitive register status for dashboards. Never returns account data. |

Verdicts: `match` (low), `mismatch` (high — the BEC shape), `unknown_vendor`
(elevated — a first payment cannot be checked against history, so it is not
"safe", it is un-vouched).

## Why this belongs on Terminal 3

The register of known-good payees is the whole asset. It is the complete list of
who a company pays and where — exactly what an attacker wants, and exactly what
a breached vendor database hands over. Running the check in an ordinary service
means holding that list in a place a breach can reach.

Three properties come from the platform rather than from discipline:

1. **No enumeration.** A lookup requires supplying a candidate account. A wrong
   candidate returns `mismatch` without revealing the right one, so a caller
   with full API access still cannot extract the payment book.
2. **No plaintext at rest.** Accounts are stored as tenant-salted SHA-256
   fingerprints; the salt lives in `z:<tid>:secrets`, written by the tenant SDK
   and never compiled into the artifact.
3. **No network, structurally.** `world.wit` imports `kv-store`, `logging`,
   `tenant-context` and `clock` — and deliberately no `http`. Capabilities on
   T3N come from WIT imports, so this contract has no route to make an outbound
   call at all.

Point 3 is the one worth dwelling on. The usual mitigation for "the agent
reading this invoice might be tricked by text inside it" is a policy asking the
agent not to be. Here the egress channel does not exist in the contract's
capability set, so an agent authorised for `verify-payee` cannot send the
register anywhere even if it is fully compromised by a prompt injection in the
document it was asked to process.

## Verified behaviour

Live run against contract 765 on testnet. Full transcript: `RUN_OUTPUT.txt` in
the repo; screenshots below.

| # | Scenario | Result |
| --- | --- | --- |
| 1 | Enrol genuine payee for "ACME GmbH" | `enrolled`, change_count 0 |
| 2 | Legitimate invoice, IBAN reformatted `de89-3704-0044-0532-013000` | `match` / `low` — normalisation defeats formatting noise |
| 3 | **BEC attempt: same vendor, attacker's IBAN** | **`mismatch` / `high` / `requires_out_of_band_check: true`** |
| 4 | Never-seen vendor | `unknown_vendor` / `elevated` |
| 5 | Dashboard status | Returns enrolment state and beneficiary name, **no account identifier** |

Plus 6 native unit tests covering vendor/account normalisation, salt-dependence
of fingerprints, format-insensitivity, and constant-time comparison.

### Screenshots

1. Build and tests — https://raw.githubusercontent.com/Artem-Sarkisian/z-tenant-payee-guard/main/screenshots/01-build-and-tests.png
2. Live run, part 1 — https://raw.githubusercontent.com/Artem-Sarkisian/z-tenant-payee-guard/main/screenshots/02-live-run-part1.png
3. Live run, BEC detection — https://raw.githubusercontent.com/Artem-Sarkisian/z-tenant-payee-guard/main/screenshots/03-live-run-part2.png

## Bugs faced

Four, each with a reproduction and the workaround used. Full write-up in
`BUGS.md` in the repo.

1. **Docs describe SDK 3.x; npm installs 5.2.0.** Two major versions of drift,
   and issues 2 and 3 are both consequences of it.
2. **`getContractVersion()` 404s for a contract registered seconds earlier.**
   `Failed to fetch current version for 765: 404 Not Found`. Registration
   succeeded and the contract is invocable; only the lookup fails. Combined with
   the documented absence of an API to fetch a tail's current `contract_id`, a
   deploy script has no programmatic way to discover what it just deployed.
   Workaround: pass `contract_version` explicitly.
3. **The reference table puts `executeAndDecode` on the wrong object.** It is
   listed as `tenant.contracts.execute(...)/executeAndDecode(...)`, but
   `tenant.contracts` has no `executeAndDecode` — it is on `T3nClient`. The
   Agent Auth page uses it correctly, so the reference contradicts the
   walkthrough. Workaround: `t3n.executeAndDecode({...})`.
4. **SDK errors print the entire minified bundle to stderr** — 2.24 MB across 17
   lines, with the real message buried after it, because `dist/index.esm.js` is
   one minified line and Node prints the offending source line. Suggested fix: a
   sourcemap, or an unminified build alongside.

Things that worked exactly as documented are listed at the end of `BUGS.md` —
a bug list without a control group is not very informative.

## Maintenance after the challenge

Built to keep running, so the moving parts are deliberately few:

- **No outbound dependency.** Nothing breaks when a third-party API changes,
  rate-limits or goes down. The only runtime inputs are the KV maps.
- **No model.** Verdicts are deterministic string and hash comparisons, so the
  same instruction always produces the same answer and the logic is auditable by
  reading it.
- **Natively testable.** `crate-type = ["cdylib", "lib"]` keeps `cargo test`
  working on the host target with no WASM harness.
- **One operational secret.** The fingerprint salt is write-once per tenant;
  rotating it invalidates every fingerprint, and that is stated in `lib.rs`
  rather than left as folklore.

Happy either way on handover: I can keep running it, or hand it to Terminal 3 to
maintain. If handing over, the only state to migrate is the `payees` map and the
salt in `secrets`, and the only thing to preserve is `contract_id` 765 — the map
ACLs are scoped to it, and re-registering the tail allocates a new id.
