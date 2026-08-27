# z-tenant-payee-guard

**Payee-substitution defence for accounts payable, as a Terminal 3 TEE contract.**

Deployed and exercised on T3N testnet: `z:b5665866…:payee-guard`, contract id `765`, v0.1.0.

---

## The problem

Business-email-compromise fraud does not break cryptography. It edits a bank
account number on an otherwise genuine invoice from a supplier you really do owe
money to, and the payment goes out because nothing in the process ever asks the
one useful question:

> Have we ever paid this vendor at **this** account before?

Answering it needs a register of known-good payees. That register is the problem:
it is the complete list of who a company pays and where, which is exactly what an
attacker wants and exactly what a breached vendor database hands over.

## Why this is a TEE contract and not a service

The register stays inside the enclave and only a verdict comes out.

- **No enumeration.** A lookup requires supplying a candidate account. A wrong
  candidate returns `mismatch` without revealing the right one, so a caller with
  full API access still cannot extract the payment book.
- **No plaintext at rest.** Account identifiers are stored as salted SHA-256
  fingerprints. The salt is tenant-scoped and lives in `z:<tid>:secrets`, written
  by the tenant SDK, never compiled into the artifact. A future contract bug or an
  over-broad grant still cannot surface an IBAN.
- **No network.** `world.wit` imports `kv-store`, `logging`, `tenant-context` and
  `clock` — and no `http`. Capabilities on T3N come from WIT imports, so this
  contract has no route to make an outbound call at all. An agent authorised for
  `verify-payee` cannot send the register anywhere, even if the agent itself is
  compromised by a prompt injection in the invoice it is reading.

That last point is the argument for the platform. The usual mitigation for
"the agent might be tricked" is a policy telling the agent not to be. Here the
egress simply does not exist in the contract's capability set.

## Interface

| Function | Purpose |
| --- | --- |
| `enroll-payee` | Register or rotate a vendor's known-good account. Rotation is counted and timestamped, never silent. |
| `verify-payee` | Check one payment instruction. Returns verdict, risk band, reasons, and whether an out-of-band check is required. |
| `vendor-status` | Non-sensitive register status for dashboards. Never returns account data. |

### Verdicts

| Verdict | Risk | Meaning |
| --- | --- | --- |
| `match` | `low` | The account is the enrolled one. Escalates to `elevated` if the beneficiary name differs. |
| `mismatch` | `high` | Vendor is enrolled, account is not the one on file. **This is the BEC shape.** |
| `unknown_vendor` | `elevated` | Never enrolled. A first payment cannot be checked against history, so this is not "safe" — it is un-vouched. |

Rotation history feeds the risk signal: an account that has never changed makes a
new one more surprising, and a recent change is itself worth reporting.

## Verified behaviour

Full transcript in [`RUN_OUTPUT.txt`](RUN_OUTPUT.txt), produced by
[`invoke.ts`](invoke.ts) against the live testnet contract.

```
2. legitimate invoice, IBAN reformatted "de89-3704-0044-0532-013000"
   → verdict "match", risk "low"          (normalisation defeats formatting noise)

3. BEC attempt: same vendor, attacker's IBAN
   → verdict "mismatch", risk "high",
     requires_out_of_band_check: true

4. never-seen vendor
   → verdict "unknown_vendor", risk "elevated"

5. dashboard status
   → enrolled: true, beneficiary_name_on_file: "ACME GmbH"
     (no account identifier in the response, by construction)
```

## Running it

```bash
# contract
cargo test                                        # 6 unit tests, native target
cargo build --release --target wasm32-wasip2      # 179 KB component

# deployment (from the sibling Node project)
export T3N_API_KEY=...
npx tsx deploy.ts     # register, create maps scoped to contract_id, seed salt
npx tsx invoke.ts     # exercise all three functions
```

`deploy.ts` is one-shot on purpose. Re-registering the same tail allocates a new
`contract_id` and leaves the map ACLs pointing at the old one — the docs warn
about this and there is no API to recover the current id, so re-running
registration is the one thing that will quietly break a working deployment.

## Maintaining it after the challenge

This was built to keep running, so the moving parts are deliberately few:

- **No outbound dependency.** Nothing to break when a third-party API changes its
  contract, rate-limits, or goes down. The only runtime inputs are the KV maps.
- **No model.** Verdicts are deterministic string and hash comparisons, so the
  same instruction always produces the same answer and the logic is auditable by
  reading it.
- **Business logic is unit-testable natively.** `crate-type = ["cdylib", "lib"]`
  keeps `cargo test` working on the host target without a WASM harness.
- **The only operational secret is the salt.** Rotating it invalidates every
  fingerprint, so it is write-once per tenant; that is stated in `lib.rs` rather
  than left as folklore.

Happy to hand this over for Terminal 3 to maintain, or keep running it — either
works. Issues encountered while building are written up in [`BUGS.md`](BUGS.md).

## Layout

```
src/lib.rs      wit-bindgen entry point, Guest impl, capability docs
src/store.rs    register schema, normalisation, salted fingerprints, KV access
src/verify.rs   verify-payee — verdict, risk band, reasons (+ unit tests)
src/enroll.rs   enroll-payee and vendor-status
wit/world.wit   exported interface and the four host imports
```

MIT.
