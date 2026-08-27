# Issues hit while building on the T3N ADK

Four issues, each with the exact reproduction and the workaround used. Reported
in the order they were hit. Environment: macOS 15 arm64, Node v25.9.0,
`@terminal3/t3n-sdk@5.2.0`, Rust 1.98.0, target `wasm32-wasip2`, testnet.

---

## 1. Docs describe SDK 3.x; npm installs 5.2.0

**Where:** `/developers/adk/changelog` and every code sample in the walkthrough.

The changelog says hackathon integrations "referenced `@terminal3/t3n-sdk`
versions `3.5.2`, `3.9.0`, and `3.11.0`". A clean `npm install @terminal3/t3n-sdk`
today resolves **5.2.0** — two major versions on. Issues 2 and 3 below are both
places where the documented surface and the shipped surface differ, so this is
not a cosmetic gap.

**Suggested fix:** pin the version each doc page was written against at the top
of the walkthrough, or state the minimum supported version explicitly. A reader
currently has no way to tell whether a sample that fails is their mistake or a
version drift.

---

## 2. `getContractVersion()` returns 404 for a contract registered seconds earlier

**Where:** `/developers/adk/reference` — listed as "Looks up the currently
registered version of a contract", and used in the invoke walkthrough.

**Reproduce:**

```ts
const reg = await tenant.contracts.register({ tail: "payee-guard", version: "0.1.0", wasm });
// reg.contract_id === 765, registration succeeded
const version = await getContractVersion(getNodeUrl(), reg.contract_id);
```

**Actual:**

```
Error: Failed to fetch current version for 765: 404 Not Found
    at fetchCurrentContractVersion (index.esm.js:2:993108)
    at async getContractVersion (index.esm.js:2:993665)
```

Registration reported success and the contract is invocable — passing the
version string explicitly works fine. Only the lookup 404s.

**Why it matters beyond this call:** the register-contract page warns that
"there is currently no API to fetch a tail's current `contract_id` after
re-registering". If `getContractVersion` is also unreliable immediately after
registration, a deploy script has no programmatic way to discover what it just
deployed, and every pipeline has to hard-code the version string it passed in.

**Workaround:** pass `contract_version` explicitly from the same constant used
at registration.

---

## 3. Reference table puts `executeAndDecode` on the wrong object

**Where:** `/developers/adk/reference`, SDK method table:

> `tenant.contracts.execute(...)` / `executeAndDecode(...)` — Invokes a registered contract.

**Actual on 5.2.0:**

```
tenant.contracts → publish, register, setDescriptor, list, listDetailed,
                   disable, enable, unregister, logs, execute, contractStateChange
T3nClient        → ..., execute, executeWithBlob, executeAndDecode, ...
```

`tenant.contracts.executeAndDecode` does not exist; calling it fails with
`tenant.contracts.executeAndDecode is not a function`. The method is on
`T3nClient`. The Agent Auth page uses it correctly as
`agentClient.executeAndDecode({...})`, so the reference table contradicts the
walkthrough rather than the SDK being inconsistent.

**Workaround:** call `t3n.executeAndDecode({...})`.

**Suggested fix:** split the table row — `tenant.contracts.execute` and
`T3nClient.executeAndDecode` are different objects and it currently reads as if
both live on the same one.

---

## 4. SDK errors print the entire minified bundle to stderr

**Reproduce:** trigger any thrown SDK error from a plain `npx tsx` script — for
example issue 2 above.

**Actual:** Node's uncaught-exception handler prints the offending source line.
Because `dist/index.esm.js` is a single minified, name-mangled line, the whole
bundle is emitted: **2.24 MB across 17 lines**, with the real message
(`Failed to fetch current version for 765`) buried after it. In a terminal it
scrolls the actual error out of view; in CI it is 2 MB of log per failure.

**Workaround:** wrap every SDK call in `try/catch` and print only `e.message`.
That is good practice anyway, but a first-time user following the quickstart
verbatim gets the full dump on their first error, which is a rough first
impression of an otherwise clean SDK.

**Suggested fix:** ship a sourcemap, or at minimum publish an unminified build
alongside the minified one so the frame resolves to a short line.

---

## Not bugs — things that worked exactly as documented

Worth recording, since a bug list without a control group is not very
informative:

- `readers: { only: [contractId] }` really is required on `maps.create` — the
  documented deny-by-default behaviour matched observation.
- `map-entry-set` did bypass the `writers` ACL as described, seeding the salt
  into a contract-only map.
- The `wasm32-wasip2` build, the `cdylib` + `lib` crate-type trick, and the
  vendored `wit/deps` all worked first try from the reference repo.
- Vendor normalisation, salted fingerprints and the KV round-trip behaved
  identically in native `cargo test` and inside the enclave.
