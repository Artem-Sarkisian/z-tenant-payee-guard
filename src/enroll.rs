//! enroll-payee and vendor-status — the write path and the dashboard read.
//!
//! Rotation is deliberately not silent. An attacker's goal is to get the
//! register itself updated, so every change increments a counter and stamps a
//! time that `verify-payee` then reports back as a risk signal.

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};
use crate::store::{self, PayeeRecord};

#[derive(serde::Deserialize)]
pub struct EnrollReq {
    pub vendor_ref: String,
    pub account_id: String,
    pub beneficiary_name: String,
    /// Who authorised this enrolment. Recorded for the audit trail; the
    /// contract does not interpret it.
    #[serde(default)]
    pub actor: String,
}

#[derive(serde::Serialize)]
pub struct EnrollResp {
    pub vendor_ref: String,
    /// `enrolled` | `rotated` | `unchanged`
    pub action: String,
    pub change_count: u32,
    pub enrolled_at_ms: u64,
    pub last_changed_ms: u64,
}

#[derive(serde::Deserialize)]
pub struct StatusReq {
    pub vendor_ref: String,
}

#[derive(serde::Serialize)]
pub struct StatusResp {
    pub vendor_ref: String,
    pub enrolled: bool,
    pub change_count: u32,
    pub days_since_last_change: Option<u64>,
    /// Present so a dashboard can show who is on file. The account identifier
    /// is never included in this or any other response.
    pub beneficiary_name_on_file: Option<String>,
}

pub fn enroll_payee(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: EnrollReq =
        serde_json::from_slice(input).map_err(|e| format!("enroll-payee: bad input: {e}"))?;
    if req.vendor_ref.trim().is_empty() {
        return Err("enroll-payee: vendor_ref is required".to_string());
    }
    if req.account_id.trim().is_empty() {
        return Err("enroll-payee: account_id is required".to_string());
    }
    #[cfg(target_arch = "wasm32")]
    {
        let resp = enroll_wasm(req)?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("enroll_payee runs only on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
fn enroll_wasm(req: EnrollReq) -> Result<EnrollResp, String> {
    use crate::host::interfaces::logging;

    let vendor = store::normalise_vendor(&req.vendor_ref);
    let salt = store::load_salt()?;
    let fp = store::fingerprint(&salt, &req.account_id);
    let now = store::now_ms()?;
    let actor = if req.actor.trim().is_empty() {
        "unspecified".to_string()
    } else {
        req.actor.clone()
    };

    let (rec, action) = match store::load_record(&vendor)? {
        None => (
            PayeeRecord {
                account_fp: fp,
                beneficiary_name: req.beneficiary_name.clone(),
                enrolled_at_ms: now,
                last_changed_ms: now,
                change_count: 0,
                last_actor: actor,
            },
            "enrolled",
        ),
        Some(prev) if store::fp_eq(&prev.account_fp, &fp) => {
            // Re-enrolling the same account is a no-op for risk purposes. It
            // must not bump the counter, or routine re-syncs would erode the
            // signal that makes a real rotation stand out.
            let name = if req.beneficiary_name.trim().is_empty() {
                prev.beneficiary_name.clone()
            } else {
                req.beneficiary_name.clone()
            };
            (
                PayeeRecord {
                    account_fp: prev.account_fp,
                    beneficiary_name: name,
                    enrolled_at_ms: prev.enrolled_at_ms,
                    last_changed_ms: prev.last_changed_ms,
                    change_count: prev.change_count,
                    last_actor: actor,
                },
                "unchanged",
            )
        }
        Some(prev) => (
            PayeeRecord {
                account_fp: fp,
                beneficiary_name: req.beneficiary_name.clone(),
                enrolled_at_ms: prev.enrolled_at_ms,
                last_changed_ms: now,
                change_count: prev.change_count.saturating_add(1),
                last_actor: actor,
            },
            "rotated",
        ),
    };

    store::save_record(&vendor, &rec)?;
    let _ = logging::info(&format!(
        "enroll-payee: vendor='{vendor}' action={action} change_count={}",
        rec.change_count
    ));
    Ok(EnrollResp {
        vendor_ref: vendor,
        action: action.to_string(),
        change_count: rec.change_count,
        enrolled_at_ms: rec.enrolled_at_ms,
        last_changed_ms: rec.last_changed_ms,
    })
}

pub fn vendor_status(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: StatusReq =
        serde_json::from_slice(input).map_err(|e| format!("vendor-status: bad input: {e}"))?;
    #[cfg(target_arch = "wasm32")]
    {
        let resp = status_wasm(req)?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("vendor_status runs only on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
fn status_wasm(req: StatusReq) -> Result<StatusResp, String> {
    let vendor = store::normalise_vendor(&req.vendor_ref);
    let now = store::now_ms()?;
    match store::load_record(&vendor)? {
        None => Ok(StatusResp {
            vendor_ref: vendor,
            enrolled: false,
            change_count: 0,
            days_since_last_change: None,
            beneficiary_name_on_file: None,
        }),
        Some(rec) => Ok(StatusResp {
            vendor_ref: vendor,
            enrolled: true,
            change_count: rec.change_count,
            days_since_last_change: Some(
                now.saturating_sub(rec.last_changed_ms) / store::MS_PER_DAY,
            ),
            beneficiary_name_on_file: Some(rec.beneficiary_name),
        }),
    }
}
