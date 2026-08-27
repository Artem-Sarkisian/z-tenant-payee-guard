//! verify-payee — the hot path. Answers one question: have we paid this
//! vendor at this account before?
//!
//! The caller learns a verdict, a risk band and the reasons behind it. It
//! never learns the enrolled account, and it cannot enumerate the register:
//! a lookup requires supplying a candidate, and a wrong candidate returns
//! `mismatch` without disclosing what the right one is.

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};
use crate::store;

#[derive(serde::Deserialize)]
pub struct VerifyReq {
    pub vendor_ref: String,
    pub account_id: String,
    #[serde(default)]
    pub beneficiary_name: String,
}

#[derive(serde::Serialize)]
pub struct VerifyResp {
    /// `match` | `mismatch` | `unknown_vendor`
    pub verdict: String,
    /// `low` | `elevated` | `high`
    pub risk: String,
    pub reasons: Vec<String>,
    /// The actionable bit: stop and confirm through a channel that did not
    /// deliver this invoice.
    pub requires_out_of_band_check: bool,
    pub vendor_known: bool,
    pub change_count: u32,
    pub days_since_last_change: Option<u64>,
}

/// A payee that changed recently is more suspicious than a long-stable one:
/// the attacker's rotation and the legitimate one look identical except in
/// how much history sits behind them.
const RECENT_CHANGE_DAYS: u64 = 30;

pub fn verify_payee(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: VerifyReq =
        serde_json::from_slice(input).map_err(|e| format!("verify-payee: bad input: {e}"))?;
    if req.vendor_ref.trim().is_empty() {
        return Err("verify-payee: vendor_ref is required".to_string());
    }
    if req.account_id.trim().is_empty() {
        return Err("verify-payee: account_id is required".to_string());
    }

    #[cfg(target_arch = "wasm32")]
    {
        let resp = verify_wasm(req)?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("verify_payee runs only on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
fn verify_wasm(req: VerifyReq) -> Result<VerifyResp, String> {
    use crate::host::interfaces::logging;

    let vendor = store::normalise_vendor(&req.vendor_ref);
    let salt = store::load_salt()?;
    let candidate_fp = store::fingerprint(&salt, &req.account_id);
    let now = store::now_ms()?;

    let Some(rec) = store::load_record(&vendor)? else {
        // An unknown vendor is not "safe" — it is simply un-vouched. First
        // payments are a common fraud entry point, so this is elevated, not low.
        let _ = logging::info(&format!("verify-payee: unknown vendor '{vendor}'"));
        return Ok(VerifyResp {
            verdict: "unknown_vendor".to_string(),
            risk: "elevated".to_string(),
            reasons: alloc::vec![
                "No payee has ever been enrolled for this vendor.".to_string(),
                "A first payment cannot be checked against history.".to_string(),
            ],
            requires_out_of_band_check: true,
            vendor_known: false,
            change_count: 0,
            days_since_last_change: None,
        });
    };

    let days_since = now.saturating_sub(rec.last_changed_ms) / store::MS_PER_DAY;
    let mut reasons: Vec<String> = Vec::new();

    if store::fp_eq(&candidate_fp, &rec.account_fp) {
        // Account matches. The only remaining signal is the beneficiary name:
        // a right account under a wrong name is worth a look, but it is not
        // the fraud pattern this contract exists to catch.
        let name_differs = !req.beneficiary_name.trim().is_empty()
            && store::normalise_vendor(&req.beneficiary_name)
                != store::normalise_vendor(&rec.beneficiary_name);
        if name_differs {
            reasons.push(
                "Account matches the enrolled payee, but the beneficiary name on \
                 this instruction differs from the one on file."
                    .to_string(),
            );
        }
        if days_since < RECENT_CHANGE_DAYS {
            reasons.push(format!(
                "The enrolled account for this vendor was changed {days_since} day(s) ago."
            ));
        }
        if reasons.is_empty() {
            reasons.push("Account matches the payee enrolled for this vendor.".to_string());
        }
        let risk = if name_differs { "elevated" } else { "low" };
        let _ = logging::info(&format!("verify-payee: match vendor='{vendor}' risk={risk}"));
        return Ok(VerifyResp {
            verdict: "match".to_string(),
            risk: risk.to_string(),
            reasons,
            requires_out_of_band_check: name_differs,
            vendor_known: true,
            change_count: rec.change_count,
            days_since_last_change: Some(days_since),
        });
    }

    // Mismatch on a known vendor. This is the business-email-compromise shape:
    // a supplier you really do owe money to, asking to be paid somewhere new.
    reasons.push(
        "This vendor is enrolled, but the account on this instruction is not the \
         one on file."
            .to_string(),
    );
    reasons.push(
        "Payee substitution on a genuine invoice is the most common form of \
         invoice fraud."
            .to_string(),
    );
    if rec.change_count == 0 {
        reasons.push(
            "The enrolled account has never been changed since enrolment, so a \
             new account is unexpected."
                .to_string(),
        );
    } else {
        reasons.push(format!(
            "The enrolled account has already been changed {} time(s); the last \
             change was {days_since} day(s) ago.",
            rec.change_count
        ));
    }
    let _ = logging::error(&format!(
        "verify-payee: MISMATCH vendor='{vendor}' change_count={}",
        rec.change_count
    ));
    Ok(VerifyResp {
        verdict: "mismatch".to_string(),
        risk: "high".to_string(),
        reasons,
        requires_out_of_band_check: true,
        vendor_known: true,
        change_count: rec.change_count,
        days_since_last_change: Some(days_since),
    })
}

#[cfg(test)]
mod tests {
    use crate::store;

    #[test]
    fn account_normalisation_ignores_formatting() {
        assert_eq!(
            store::normalise_account("DE89 3704 0044 0532 0130 00"),
            store::normalise_account("de89-3704-0044-0532-013000")
        );
    }

    #[test]
    fn vendor_normalisation_collapses_whitespace_and_case() {
        assert_eq!(store::normalise_vendor("  ACME   GmbH "), "acme gmbh");
    }

    #[test]
    fn fingerprint_is_salt_dependent() {
        let a = store::fingerprint("salt-a", "DE89370400440532013000");
        let b = store::fingerprint("salt-b", "DE89370400440532013000");
        assert_ne!(a, b, "same account under different tenants must not collide");
    }

    #[test]
    fn fingerprint_is_format_insensitive() {
        let a = store::fingerprint("s", "DE89 3704 0044 0532 0130 00");
        let b = store::fingerprint("s", "de89370400440532013000");
        assert_eq!(a, b, "formatting must not change the fingerprint");
    }

    #[test]
    fn fp_eq_rejects_different_lengths_and_values() {
        assert!(store::fp_eq("abc", "abc"));
        assert!(!store::fp_eq("abc", "abd"));
        assert!(!store::fp_eq("abc", "abcd"));
    }
}
