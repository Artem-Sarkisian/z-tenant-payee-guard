//! Shared storage layer: the payee register and the fingerprinting scheme.
//!
//! Two rules hold everywhere in this module:
//!   1. An account identifier is fingerprinted before it is stored, and the
//!      plaintext is dropped immediately afterwards.
//!   2. No function here ever returns a fingerprint to a caller. Fingerprints
//!      are compared inside the enclave; only verdicts cross the boundary.

extern crate alloc;
use alloc::{format, string::String, vec::Vec};

/// One vendor's known-good payee. Stored as JSON under `z:<tid>:payees`,
/// keyed by the normalised vendor reference.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct PayeeRecord {
    /// Salted SHA-256 of the normalised account identifier, hex-encoded.
    pub account_fp: String,
    /// Beneficiary name as enrolled. Not a secret — it is printed on the
    /// invoice the caller already holds — and a name mismatch is a signal
    /// worth surfacing, so it is stored in the clear.
    pub beneficiary_name: String,
    pub enrolled_at_ms: u64,
    pub last_changed_ms: u64,
    /// Number of times the account has been rotated since first enrolment.
    /// A vendor whose account changes often is itself a risk signal.
    pub change_count: u32,
    /// Who performed the last write, for the audit trail.
    pub last_actor: String,
}

/// Vendor references arrive from invoices and from humans; normalise so that
/// "ACME GmbH", "acme gmbh" and " Acme  GmbH " are one vendor and not three.
pub fn normalise_vendor(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_space = true;
    for ch in raw.trim().chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
            prev_space = false;
        }
    }
    out
}

/// IBANs and account numbers are quoted with spaces, dashes and mixed case.
/// Strip everything that is not alphanumeric so formatting differences cannot
/// masquerade as a different account — or hide that it is the same one.
pub fn normalise_account(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Salted fingerprint. The salt is tenant-scoped and lives in the `secrets`
/// map, so two tenants holding the same IBAN do not produce the same digest
/// and the register cannot be attacked with a precomputed table.
pub fn fingerprint(salt: &str, account: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"|");
    h.update(normalise_account(account).as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time comparison. Fingerprint checking is not a timing-sensitive
/// operation in the classic sense, but a short-circuiting `==` on a secret
/// digest is the kind of detail that ages badly, so it is avoided here.
pub fn fp_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub const MAP_PAYEES: &str = "payees";
pub const MAP_SECRETS: &str = "secrets";
pub const KEY_SALT: &[u8] = b"payee_fingerprint_salt";

#[cfg(target_arch = "wasm32")]
use crate::host::{
    interfaces::{clock, kv_store},
    tenant::tenant_context,
};

/// Fully-qualified z-namespace map name for this tenant.
#[cfg(target_arch = "wasm32")]
pub fn map_name(short: &str) -> Result<String, String> {
    // tenant-did returns the raw 20-byte CompactDid; the z-namespace map name
    // uses its hex encoding.
    let tid = tenant_context::tenant_did();
    Ok(format!("z:{}:{}", hex::encode(&tid), short))
}

#[cfg(target_arch = "wasm32")]
pub fn load_salt() -> Result<String, String> {
    let map = map_name(MAP_SECRETS)?;
    let bytes = kv_store::get(&map, KEY_SALT)
        .map_err(|e| format!("kv read {map}: {e}"))?
        .ok_or(
            "payee_fingerprint_salt missing from the secrets map — write one \
             (32+ random bytes) via the tenant SDK before first use",
        )?;
    String::from_utf8(bytes).map_err(|e| format!("salt is not utf-8: {e}"))
}

#[cfg(target_arch = "wasm32")]
pub fn load_record(vendor: &str) -> Result<Option<PayeeRecord>, String> {
    let map = map_name(MAP_PAYEES)?;
    match kv_store::get(&map, vendor.as_bytes()).map_err(|e| format!("kv read {map}: {e}"))? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("corrupt payee record for '{vendor}': {e}")),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn save_record(vendor: &str, rec: &PayeeRecord) -> Result<(), String> {
    let map = map_name(MAP_PAYEES)?;
    let bytes: Vec<u8> = serde_json::to_vec(rec).map_err(|e| e.to_string())?;
    kv_store::put(&map, vendor.as_bytes(), &bytes).map_err(|e| format!("kv write {map}: {e}"))
}

#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> Result<u64, String> {
    clock::now_ms().map_err(|e| format!("clock: {e:?}"))
}

pub const MS_PER_DAY: u64 = 86_400_000;
