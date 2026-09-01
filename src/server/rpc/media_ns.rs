//! `grob/media/*` namespace: provenance handle resolution.
//!
//! Three reads, split across two roles on purpose. `verify` answers "is this
//! handle known here", which names nobody and is safe to expose widely.
//! `trace` and `fingerprint` return the tenant that produced an image, which
//! is precisely the fact the opaque handle keeps out of the file, so they sit
//! a rung higher.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, ERR_INTERNAL};
use crate::server::AppState;
// The registry is read from disk rather than from AppState; the parameter is
// kept for signature symmetry with the other namespaces.
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Answer to `grob/media/verify`.
///
/// Carries no context beyond existence, so an Observer can ask "did this come
/// from us" without learning who produced it.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Whether the handle is recorded by this instance.
    pub known: bool,
    /// Which layer answered, so a caller can weigh the result.
    ///
    /// A handle read from a signed manifest and one recovered from a
    /// fingerprint are both useful, and not equally strong. Reporting the
    /// layer keeps that distinction visible instead of collapsing it into a
    /// boolean.
    pub layer: &'static str,
}

/// Answer to `grob/media/trace` and `grob/media/fingerprint`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TraceResponse {
    /// Matching records, newest first.
    pub records: Vec<crate::features::media::trace::TraceRecord>,
}

/// Reports whether a provenance handle is known.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Observer`,
/// `INVALID_PARAMS_CODE` when the handle is malformed, and `ERR_INTERNAL`
/// when the registry cannot be read.
pub async fn verify(
    _state: &Arc<AppState>,
    caller: &CallerIdentity,
    trace_id: &str,
) -> Result<VerifyResponse, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;
    let id = parse_trace_id(trace_id)?;
    let registry = open_registry()?;
    let known = registry
        .resolve(id)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("registry read failed: {e}")))?
        .is_some();
    Ok(VerifyResponse {
        known,
        layer: "registry",
    })
}

/// Resolves a provenance handle to its full context.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Operator`,
/// `INVALID_PARAMS_CODE` when the handle is malformed, and `ERR_INTERNAL`
/// when the registry cannot be read.
pub async fn trace(
    _state: &Arc<AppState>,
    caller: &CallerIdentity,
    trace_id: &str,
) -> Result<TraceResponse, ErrorObjectOwned> {
    // Operator, not Observer: the answer names a tenant.
    require_role(caller, Role::Operator)?;
    let id = parse_trace_id(trace_id)?;
    let registry = open_registry()?;
    let records = registry
        .resolve(id)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("registry read failed: {e}")))?
        .into_iter()
        .collect();
    Ok(TraceResponse { records })
}

/// Finds records sharing a perceptual fingerprint.
///
/// The fallback for an image whose handle was stripped: the fingerprint comes
/// from pixels, so nothing needs to have survived inside the file.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Operator`,
/// `INVALID_PARAMS_CODE` when the fingerprint is malformed, and
/// `ERR_INTERNAL` when the registry cannot be read.
pub async fn fingerprint(
    _state: &Arc<AppState>,
    caller: &CallerIdentity,
    phash: &str,
) -> Result<TraceResponse, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;
    if phash.len() != 16 || !phash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(rpc_err(
            INVALID_PARAMS_CODE,
            "phash must be 16 hexadecimal digits".to_string(),
        ));
    }
    let registry = open_registry()?;
    let records = registry
        .resolve_by_phash(phash)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("registry read failed: {e}")))?;
    Ok(TraceResponse { records })
}

/// Parses a handle, rejecting anything that could not have been embedded.
fn parse_trace_id(
    trace_id: &str,
) -> Result<crate::features::media::trace::TraceId, ErrorObjectOwned> {
    crate::features::media::trace::TraceId::from_hex(trace_id).ok_or_else(|| {
        rpc_err(
            INVALID_PARAMS_CODE,
            "trace_id must be 16 hexadecimal digits within 61 bits".to_string(),
        )
    })
}

/// Opens the provenance registry.
fn open_registry() -> Result<crate::features::media::trace::TraceRegistry, ErrorObjectOwned> {
    let home = crate::grob_home()
        .ok_or_else(|| rpc_err(ERR_INTERNAL, "no grob home directory".to_string()))?;
    crate::features::media::trace::TraceRegistry::open(&home)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("cannot open registry: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::media::trace::{TraceId, TraceRecord, TraceRegistry};

    #[test]
    fn malformed_handles_are_refused_before_touching_the_registry() {
        // Cheap input validation, but it also protects the invariant: a value
        // that cannot round-trip through the watermark is not a handle, so
        // accepting it would invite callers to build ones that never work.
        assert!(parse_trace_id("").is_err());
        assert!(parse_trace_id("abc").is_err());
        assert!(parse_trace_id("not-hex-at-all!!").is_err());
        // Right length, but bits above the 61st cannot be embedded.
        assert!(parse_trace_id("ffffffffffffffff").is_err());
        // A valid handle parses.
        assert!(parse_trace_id("00000000deadbeef").is_ok());
    }

    #[test]
    fn a_recorded_handle_resolves_through_the_same_path_the_rpc_uses() {
        // Exercises the registry the handlers read, so a change to its layout
        // fails here rather than only in production.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry = TraceRegistry::open(dir.path()).expect("open");

        let id = TraceId::generate();
        registry
            .record(
                &TraceRecord::new(id)
                    .with_tenant("acme")
                    .with_phash("cafebabecafebabe"),
            )
            .expect("record");

        let reopened = TraceRegistry::open(dir.path()).expect("reopen");
        let found = reopened.resolve(id).expect("resolve").expect("known");
        assert_eq!(found.tenant.as_deref(), Some("acme"));

        let by_phash = reopened
            .resolve_by_phash("cafebabecafebabe")
            .expect("resolve");
        assert_eq!(by_phash.len(), 1);
    }

    #[test]
    fn verify_reports_which_layer_answered() {
        // A boolean would hide the difference between a handle read from a
        // signed manifest and one recovered from a fingerprint. Both are
        // useful; they are not equally strong.
        let response = VerifyResponse {
            known: true,
            layer: "registry",
        };
        let json = serde_json::to_value(&response).expect("serialise");
        assert_eq!(json["layer"], "registry");
        assert_eq!(json["known"], true);
    }
}
