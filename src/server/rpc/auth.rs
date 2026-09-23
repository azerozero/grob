//! Authorization for the verified identity supplied by HTTP authentication.

use super::types::{rpc_err, Role, ERR_FORBIDDEN};
use jsonrpsee::types::ErrorObjectOwned;

/// Caller identity extracted from the HTTP request prior to RPC dispatch.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    /// Resolved access role.
    pub role: Role,
    /// Client IP address (for audit logging).
    pub ip: String,
    /// Tenant identifier (from JWT or virtual key, empty for administrative credentials or unauthenticated local access).
    pub tenant_id: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operators_cannot_manage_keys() {
        let caller = CallerIdentity {
            role: Role::Operator,
            ip: "127.0.0.1".into(),
            tenant_id: "tenant".into(),
        };
        assert!(require_role(&caller, Role::Observer).is_ok());
        assert!(require_role(&caller, Role::Admin).is_err());
    }
}
