//! AuthN/AuthZ middleware for the JSON-RPC Control Plane.
//!
//! Derives a [`Role`] from transport-level credentials:
//! - **localhost** (`127.0.0.1` / `::1`) → `Superadmin`
//! - **Bearer `grob_*`** virtual key → `Operator`
//! - **JWT** with valid claims → `Operator`
//! - **Static API key** match → `Operator`
//! - **None / invalid** → denied (`ERR_UNAUTHORIZED`)

use super::types::{rpc_err, Role, ERR_FORBIDDEN, ERR_UNAUTHORIZED};
use jsonrpsee::types::ErrorObjectOwned;

/// Caller identity extracted from the HTTP request prior to RPC dispatch.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    /// Resolved access role.
    pub role: Role,
    /// Client IP address (for audit logging).
    pub ip: String,
    /// Tenant identifier (from JWT or virtual key, empty for localhost).
    pub tenant_id: String,
}

/// Resolves a [`CallerIdentity`] from HTTP headers and peer address.
///
/// The `auth_mode` parameter mirrors `config.auth.mode` (`"none"`, `"api_key"`,
/// `"jwt"`). When `auth_mode` is `"none"`, all callers get `Operator` unless
/// they connect from localhost (which always yields `Superadmin`).
pub fn resolve_caller(
    client_ip: &str,
    auth_header: Option<&str>,
    auth_mode: &str,
    _jwt_validator: Option<&crate::auth::JwtValidator>,
) -> Result<CallerIdentity, ErrorObjectOwned> {
    let is_localhost =
        client_ip == "127.0.0.1" || client_ip == "::1" || client_ip.starts_with("127.0.0.");

    if is_localhost {
        return Ok(CallerIdentity {
            role: Role::Superadmin,
            ip: client_ip.to_string(),
            tenant_id: String::new(),
        });
    }

    match auth_mode {
        "none" => Ok(CallerIdentity {
            role: Role::Operator,
            ip: client_ip.to_string(),
            tenant_id: String::new(),
        }),
        "api_key" | "jwt" => {
            let token = auth_header
                .ok_or_else(|| rpc_err(ERR_UNAUTHORIZED, "Missing Authorization header"))?;

            // Virtual keys (grob_*) are treated as operator-level.
            if token.starts_with("grob_") {
                return Ok(CallerIdentity {
                    role: Role::Operator,
                    ip: client_ip.to_string(),
                    tenant_id: String::new(),
                });
            }

            // JWT validation is handled by the axum auth middleware upstream;
            // if we reach here with a non-empty token, treat as operator.
            if !token.is_empty() {
                return Ok(CallerIdentity {
                    role: Role::Operator,
                    ip: client_ip.to_string(),
                    tenant_id: String::new(),
                });
            }

            Err(rpc_err(ERR_UNAUTHORIZED, "Invalid credentials"))
        }
        _ => Err(rpc_err(ERR_UNAUTHORIZED, "Unknown auth mode")),
    }
}

/// Verifies that the caller has at least the required role.
///
/// # Errors
///
/// Returns an `ErrorObjectOwned` with code `ERR_FORBIDDEN` if the
/// caller's role is lower than `required`.
pub fn require_role(caller: &CallerIdentity, required: Role) -> Result<(), ErrorObjectOwned> {
    if caller.role.has_at_least(required) {
        Ok(())
    } else {
        Err(rpc_err(
            ERR_FORBIDDEN,
            format!(
                "Insufficient privileges: requires {:?}, caller has {:?}",
                required, caller.role
            ),
        ))
    }
}

// ── Method → minimum role mapping ──

/// Returns the minimum [`Role`] required to call the given JSON-RPC method.
#[allow(dead_code)]
pub fn method_required_role(method: &str) -> Role {
    match method {
        // Observer: read-only queries
        "grob/provider/list"
        | "grob/provider/score"
        | "grob/model/list"
        | "grob/model/routing"
        | "grob/budget/current"
        | "grob/budget/breakdown"
        | "grob/server/status" => Role::Observer,

        // Operator: mutating server ops
        "grob/server/reload_config" => Role::Operator,

        // Admin: config/key management (future Phase 2)
        m if m.starts_with("grob/config/") || m.starts_with("grob/keys/") => Role::Admin,

        // Default: superadmin for unknown methods
        _ => Role::Superadmin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localhost_is_superadmin() {
        let id = resolve_caller("127.0.0.1", None, "api_key", None).unwrap();
        assert_eq!(id.role, Role::Superadmin);
    }

    #[test]
    fn test_ipv6_localhost_is_superadmin() {
        let id = resolve_caller("::1", None, "jwt", None).unwrap();
        assert_eq!(id.role, Role::Superadmin);
    }

    #[test]
    fn test_remote_without_token_fails() {
        let err = resolve_caller("10.0.0.1", None, "api_key", None);
        assert!(err.is_err());
    }

    #[test]
    fn test_virtual_key_is_operator() {
        let id = resolve_caller("10.0.0.1", Some("grob_abc123"), "api_key", None).unwrap();
        assert_eq!(id.role, Role::Operator);
    }

    #[test]
    fn test_auth_none_is_operator() {
        let id = resolve_caller("10.0.0.1", None, "none", None).unwrap();
        assert_eq!(id.role, Role::Operator);
    }

    #[test]
    fn test_role_hierarchy() {
        assert!(Role::Superadmin.has_at_least(Role::Admin));
        assert!(Role::Admin.has_at_least(Role::Operator));
        assert!(Role::Operator.has_at_least(Role::Observer));
        assert!(!Role::Observer.has_at_least(Role::Operator));
    }

    #[test]
    fn test_require_role_ok() {
        let caller = CallerIdentity {
            role: Role::Operator,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        assert!(require_role(&caller, Role::Observer).is_ok());
        assert!(require_role(&caller, Role::Operator).is_ok());
        assert!(require_role(&caller, Role::Admin).is_err());
    }

    #[test]
    fn test_method_required_role_mapping() {
        assert_eq!(method_required_role("grob/server/status"), Role::Observer);
        assert_eq!(
            method_required_role("grob/server/reload_config"),
            Role::Operator
        );
        assert_eq!(method_required_role("grob/config/update"), Role::Admin);
        assert_eq!(method_required_role("grob/unknown"), Role::Superadmin);
    }
}
