//! z-tenant-payee-guard v0.1.0 — payee-substitution defence for accounts payable.
//!
//! Business-email-compromise fraud does not break cryptography; it edits a bank
//! account number on an otherwise genuine invoice. The defence is a register of
//! known-good payees and one check at payment time. The reason to run that check
//! inside a TEE rather than in an ordinary service is the register itself: it is
//! the complete list of who your company pays and where, which is exactly what an
//! attacker wants and exactly what a breached vendor database gives away.
//!
//! This contract keeps the register inside the enclave and exposes only a verdict.
//!   - `enroll-payee`  — register or rotate a vendor's known-good account.
//!   - `verify-payee`  — check one payment instruction. Returns a verdict, never
//!                       the enrolled account.
//!   - `vendor-status` — non-sensitive register status for dashboards.
//!
//! Account identifiers are stored as salted SHA-256 fingerprints, so the register
//! does not contain a recoverable IBAN even inside the enclave. The caller cannot
//! enumerate: a lookup requires a candidate, and a wrong candidate yields
//! `mismatch` without revealing the right one.
//!
//! # Host-capability requirements
//! ```json
//! { "host_capabilities": ["kv_store", "logging", "tenant_context", "clock"] }
//! ```
//! Deliberately no `http`: this contract never makes an outbound call, so a
//! tenant can grant it without also granting network egress. An agent authorised
//! for `verify-payee` has no route to send the register anywhere.
//!
//! # Setup
//! Before first use the tenant SDK must write a fingerprint salt:
//! ```text
//! z_sdk.kv("secrets").set("payee_fingerprint_salt", <32+ random bytes, hex>)
//! ```
#![warn(clippy::style, missing_debug_implementations)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

pub const CONTRACT_VERSION: &str = "0.1.0";

wit_bindgen::generate!({
    world: "tenant-payee-guard",
    path: "wit",
    additional_derives: [
        serde::Deserialize,
        serde::Serialize,
    ],
    generate_all,
});

mod enroll;
mod store;
mod verify;

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::tenant_payee_guard::contracts::Guest for Component {
    fn enroll_payee(
        req: exports::z::tenant_payee_guard::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("enroll-payee: missing input")?;
        enroll::enroll_payee(&input)
    }

    fn verify_payee(
        req: exports::z::tenant_payee_guard::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("verify-payee: missing input")?;
        verify::verify_payee(&input)
    }

    fn vendor_status(
        req: exports::z::tenant_payee_guard::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("vendor-status: missing input")?;
        enroll::vendor_status(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;

    #[test]
    fn contract_version_is_semver() {
        let parts: alloc::vec::Vec<&str> = CONTRACT_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        for p in parts {
            assert!(p.parse::<u32>().is_ok());
        }
    }
}
