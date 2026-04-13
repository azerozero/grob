//! Unified JSON-RPC 2.0 Control Plane for Grob.
//!
//! Exposes server management, model routing, provider scoring, budget
//! tracking, key management, config inspection, tool layer, HIT policies,
//! and pledge profiles through a single `POST /rpc` endpoint.
//! Authentication and authorization are resolved per-request from
//! transport credentials.

pub mod auth;
pub(crate) mod budget_ns;
pub(crate) mod config_ns;
pub(crate) mod hit_ns;
pub(crate) mod keys_ns;
pub(crate) mod model_ns;
pub(crate) mod pledge_ns;
pub(crate) mod provider_ns;
pub(crate) mod server_ns;
pub(crate) mod tools_ns;
pub mod types;

use crate::control::engine::{self, Action};
use crate::server::AppState;
use auth::CallerIdentity;
use std::sync::Arc;

/// Dispatches a JSON-RPC method call to the appropriate namespace handler.
///
/// Parses the method name into an [`Action`] via the control engine, checks
/// role authorization, then delegates to the namespace handler. Returns a
/// `serde_json::Value` result or an `ErrorObjectOwned` on failure.
pub async fn dispatch(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    method: &str,
    params: Option<&serde_json::Value>,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    let action = match engine::parse_method(method, params) {
        Some(a) => a,
        None => {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                jsonrpsee::types::error::METHOD_NOT_FOUND_CODE,
                format!("Method not found: {method}"),
                None::<()>,
            ));
        }
    };

    let required = engine::required_role(&action);
    auth::require_role(caller, required)?;

    dispatch_action(state, caller, &action).await
}

/// Routes a parsed [`Action`] to the appropriate namespace handler.
async fn dispatch_action(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    action: &Action,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    use crate::control::engine::*;

    match action {
        // ── grob/server/* ──
        Action::Server(ServerAction::Status) => server_ns::status(state, caller).await,
        Action::Server(ServerAction::Reload) => {
            let r = server_ns::reload_config(state, caller).await?;
            to_json(r)
        }

        // ── grob/model/* ──
        Action::Model(ModelAction::List) => model_ns::list(state, caller).await,
        Action::Model(ModelAction::Routing) => model_ns::routing(state, caller).await,

        // ── grob/provider/* ──
        Action::Provider(ProviderAction::List) => {
            let r = provider_ns::list(state, caller).await?;
            to_json(r)
        }
        Action::Provider(ProviderAction::Score) => provider_ns::score(state, caller).await,

        // ── grob/budget/* ──
        Action::Budget(BudgetAction::Current) => {
            let r = budget_ns::current(state, caller).await?;
            to_json(r)
        }
        Action::Budget(BudgetAction::Breakdown) => {
            let r = budget_ns::breakdown(state, caller).await?;
            to_json(r)
        }

        // ── grob/keys/* ──
        Action::Keys(KeysAction::Create { name }) => keys_ns::create(state, caller, name).await,
        Action::Keys(KeysAction::List) => {
            let r = keys_ns::list(state, caller).await?;
            to_json(r)
        }
        Action::Keys(KeysAction::Revoke { key_id }) => {
            let r = keys_ns::revoke(state, caller, key_id).await?;
            to_json(r)
        }
        Action::Keys(KeysAction::Rotate { key_id }) => keys_ns::rotate(state, caller, key_id).await,

        // ── grob/config/* ──
        Action::Config(ConfigAction::Get { key }) => {
            config_ns::get(state, caller, key.as_deref()).await
        }
        Action::Config(ConfigAction::Set { key, value }) => {
            let r = config_ns::set(state, caller, key, value).await?;
            to_json(r)
        }
        Action::Config(ConfigAction::Reload) => {
            let r = config_ns::reload(state, caller).await?;
            to_json(r)
        }
        Action::Config(ConfigAction::Diff) => config_ns::diff(state, caller).await,

        // ── grob/tools/* ──
        Action::Tools(ToolsAction::List) => {
            let r = tools_ns::list(state, caller).await?;
            to_json(r)
        }
        Action::Tools(ToolsAction::Enable { tool }) => {
            let r = tools_ns::enable(state, caller, tool).await?;
            to_json(r)
        }
        Action::Tools(ToolsAction::Disable { tool }) => {
            let r = tools_ns::disable(state, caller, tool).await?;
            to_json(r)
        }
        Action::Tools(ToolsAction::Catalog) => tools_ns::catalog(state, caller).await,

        // ── grob/hit/* ──
        Action::Hit(HitAction::ListPolicies) => {
            let r = hit_ns::list_policies(state, caller).await?;
            to_json(r)
        }
        Action::Hit(HitAction::SetPolicy { name, policy }) => {
            hit_ns::set_policy(state, caller, name, policy).await
        }
        Action::Hit(HitAction::GetPolicy { name }) => hit_ns::get_policy(state, caller, name).await,
        Action::Hit(HitAction::Resolve { context }) => {
            hit_ns::resolve(state, caller, context).await
        }

        // ── grob/pledge/* ──
        Action::Pledge(PledgeAction::Set { profile, source }) => {
            let r = pledge_ns::set(state, caller, profile, source.as_deref()).await?;
            to_json(r)
        }
        Action::Pledge(PledgeAction::Clear) => {
            let r = pledge_ns::clear(state, caller).await?;
            to_json(r)
        }
        Action::Pledge(PledgeAction::Status) => pledge_ns::status(state, caller).await,
        Action::Pledge(PledgeAction::ListProfiles) => {
            let r = pledge_ns::list_profiles(state, caller).await?;
            to_json(r)
        }
    }
}

/// Serializes a value to JSON, mapping errors to RPC internal errors.
fn to_json(
    value: impl serde::Serialize,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    serde_json::to_value(value).map_err(|e| types::rpc_err(types::ERR_INTERNAL, e.to_string()))
}

/// All registered JSON-RPC method names (for introspection).
pub use crate::control::engine::ALL_METHODS as METHODS;
