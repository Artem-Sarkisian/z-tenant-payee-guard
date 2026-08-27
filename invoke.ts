/** Exercise the already-registered payee-guard contract (id 765, v0.1.0). */
import {
  T3nClient, TenantClient, setEnvironment, loadWasmComponent, eth_get_address,
  metamask_sign, createEthAuthInput, fetchTrustedManifest, getNodeUrl,
} from "@terminal3/t3n-sdk";

setEnvironment("testnet");
const KEY = process.env.T3N_API_KEY!;
const TAIL = "payee-guard";
const VERSION = "0.1.0";   // passed explicitly: getContractVersion() 404s (see BUGS.md #2)

const wasmComponent = await loadWasmComponent();
const address = eth_get_address(KEY);
const t3n = new T3nClient({
  trustAnchor: await fetchTrustedManifest("testnet"), wasmComponent,
  handlers: { EthSign: metamask_sign(address, undefined, KEY) },
});
await t3n.handshake();
const tenantDid = (await t3n.authenticate(createEthAuthInput(address))).value;
const tenant = new TenantClient({ t3n, baseUrl: getNodeUrl(), tenantDid });
const script = `z:${tenantDid.slice("did:t3n:".length)}:${TAIL}`;

const call = async (fn: string, input: unknown) => {
  try {
    return await t3n.executeAndDecode({
      contract_id: script, contract_version: VERSION, function_name: fn, input,
    });
  } catch (e: any) {
    return { ERROR: e?.message ?? String(e) };   // never let the SDK dump its bundle
  }
};

const IBAN_REAL  = "DE89 3704 0044 0532 0130 00";
const IBAN_FRAUD = "DE21 1005 0000 0123 4567 89";
const show = (t: string, v: unknown) => console.log(`\n--- ${t}\n` + JSON.stringify(v, null, 2));

show("1. enrol genuine payee", await call("enroll-payee", {
  vendor_ref: "ACME GmbH", account_id: IBAN_REAL, beneficiary_name: "ACME GmbH", actor: "ap-controller" }));
show("2. legitimate invoice, same account reformatted", await call("verify-payee", {
  vendor_ref: "acme gmbh", account_id: "de89-3704-0044-0532-013000", beneficiary_name: "ACME GmbH" }));
show("3. BEC attempt: real vendor, attacker account", await call("verify-payee", {
  vendor_ref: "ACME GmbH", account_id: IBAN_FRAUD, beneficiary_name: "ACME GmbH" }));
show("4. never-seen vendor", await call("verify-payee", {
  vendor_ref: "Unknown Supplier Ltd", account_id: IBAN_FRAUD, beneficiary_name: "Unknown Supplier Ltd" }));
show("5. dashboard status (no account data)", await call("vendor-status", { vendor_ref: "ACME GmbH" }));
