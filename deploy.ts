/**
 * Deploy + end-to-end exercise for z-tenant-payee-guard.
 *
 * Order matters: register first (the contract_id is needed for the map ACLs),
 * then create the maps scoped to that id, then seed the salt, then invoke.
 */
import { readFile } from "fs/promises";
import {
  T3nClient, TenantClient, setEnvironment, loadWasmComponent, eth_get_address,
  metamask_sign, createEthAuthInput, fetchTrustedManifest, getNodeUrl, getContractVersion,
} from "@terminal3/t3n-sdk";

setEnvironment("testnet");
const KEY = process.env.T3N_API_KEY!;
const WASM_PATH = "../z-tenant-payee-guard/target/wasm32-wasip2/release/z_tenant_payee_guard.wasm";
const TAIL = "payee-guard";
const VERSION = process.env.CONTRACT_VERSION ?? "0.1.0";

const wasmComponent = await loadWasmComponent();
const address = eth_get_address(KEY);
const t3n = new T3nClient({
  trustAnchor: await fetchTrustedManifest("testnet"),
  wasmComponent,
  handlers: { EthSign: metamask_sign(address, undefined, KEY) },
});
await t3n.handshake();
const tenantDid = (await t3n.authenticate(createEthAuthInput(address))).value;
const tenant = new TenantClient({ t3n, baseUrl: getNodeUrl(), tenantDid });
await tenant.tenant.me();
console.log("tenant ready:", tenantDid);

// 1. Register
const wasm = await readFile(WASM_PATH);
console.log(`registering ${TAIL} v${VERSION} (${wasm.length} bytes)`);
const reg = await tenant.contracts.register({ tail: TAIL, version: VERSION, wasm });
const contractId = reg.contract_id;
const tenantId = tenantDid.slice("did:t3n:".length);
const script = `z:${tenantId}:${TAIL}`;
console.log(`registered ${script} -> contract_id ${contractId}`);

// 2. Maps, scoped to this contract only
for (const tail of ["secrets", "payees"]) {
  try {
    await tenant.maps.create({
      tail, visibility: "private",
      writers: { only: [contractId] },
      readers: { only: [contractId] },
    });
    console.log(`map created: ${tail}`);
  } catch (e: any) {
    console.log(`map ${tail}: ${e?.message ?? e}`);
  }
}

// 3. Seed the fingerprint salt (control-plane write; bypasses the writers ACL)
const salt = process.env.PAYEE_SALT ?? "0f3c9a1d7e5b48c2a6f0d93b7c1e5a84f2b6d0c93e7a1548b2c6f0d93b7c1e5a8";
await tenant.executeControl("map-entry-set", {
  map_name: tenant.canonicalName("secrets"),
  key: "payee_fingerprint_salt",
  value: salt,
});
console.log("salt sealed in secrets map");

// 4. Exercise the contract
const version = await getContractVersion(getNodeUrl(), contractId);
const call = (fn: string, input: unknown) =>
  tenant.contracts.executeAndDecode({
    contract_id: script, contract_version: version, function_name: fn, input,
  });

const IBAN_REAL = "DE89 3704 0044 0532 0130 00";
const IBAN_FRAUD = "DE21 1005 0000 0123 4567 89";

console.log("\n--- 1. enrol the genuine payee ---");
console.log(await call("enroll-payee", {
  vendor_ref: "ACME GmbH", account_id: IBAN_REAL,
  beneficiary_name: "ACME GmbH", actor: "ap-controller",
}));

console.log("\n--- 2. legitimate invoice, same account, reformatted ---");
console.log(await call("verify-payee", {
  vendor_ref: "acme gmbh", account_id: "de89-3704-0044-0532-013000",
  beneficiary_name: "ACME GmbH",
}));

console.log("\n--- 3. BEC attempt: real vendor, attacker's account ---");
console.log(await call("verify-payee", {
  vendor_ref: "ACME GmbH", account_id: IBAN_FRAUD,
  beneficiary_name: "ACME GmbH",
}));

console.log("\n--- 4. never-seen vendor ---");
console.log(await call("verify-payee", {
  vendor_ref: "Unknown Supplier Ltd", account_id: IBAN_FRAUD,
  beneficiary_name: "Unknown Supplier Ltd",
}));

console.log("\n--- 5. dashboard status (no account data returned) ---");
console.log(await call("vendor-status", { vendor_ref: "ACME GmbH" }));
