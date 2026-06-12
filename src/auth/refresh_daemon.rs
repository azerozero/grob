//! Background daemon that proactively refreshes OAuth tokens before they expire.
//!
//! Wakes every [`DEFAULT_TICK_INTERVAL`] and, for each token in the
//! [`TokenStore`], triggers a refresh if the token expires within
//! [`DEFAULT_REFRESH_WINDOW`]. On refresh failure (e.g. revoked
//! `refresh_token`), the token is marked as needing manual re-authentication.
//!
//! The daemon listens on a [`CancellationToken`] for graceful shutdown.

use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::auth::oauth::{OAuthClient, OAuthConfig};
use crate::auth::token_store::{OAuthToken, TokenStore};

/// Default interval between proactive refresh sweeps.
pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Default window ahead of `expires_at` at which a token is eligible for refresh.
pub const DEFAULT_REFRESH_WINDOW: chrono::Duration = chrono::Duration::minutes(15);

/// Maps an `oauth_provider_id` to the corresponding [`OAuthConfig`] factory.
///
/// Kept in sync with [`crate::auth::auto_flow`] mappings.
fn config_for_provider_id(provider_id: &str) -> Option<OAuthConfig> {
    match provider_id {
        "anthropic-max" | "claude-max" | "anthropic-oauth" => Some(OAuthConfig::anthropic()),
        "openai-codex" => Some(OAuthConfig::openai_codex()),
        "gemini" => Some(OAuthConfig::gemini()),
        _ => None,
    }
}

/// Returns `true` when `now + window >= expires_at`.
///
/// Pure function extracted for unit testing.
pub(crate) fn should_refresh(
    token: &OAuthToken,
    now: DateTime<Utc>,
    window: chrono::Duration,
) -> bool {
    if token.needs_reauth.unwrap_or(false) {
        return false;
    }
    now + window >= token.expires_at
}

/// Classification of an OAuth refresh error, derived from the error message.
///
/// Replaces the ad-hoc `msg.contains("401")` heuristic with a typed verdict
/// so callers can decide terminal vs transient without touching strings.
/// The heuristic stays in one place and is unit-tested.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum OAuthRefreshError {
    /// `invalid_grant` / `invalid_token` / `unauthorized_client` — the
    /// refresh token is permanently rejected. Requires user re-auth.
    InvalidGrant,
    /// HTTP 401 without a specific OAuth error body — treat as terminal.
    Unauthorized,
    /// Transient network error, rate limit, or 5xx from the authorization server.
    Transient,
}

impl OAuthRefreshError {
    /// Returns `true` when the token must be marked `needs_reauth`.
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::InvalidGrant | Self::Unauthorized)
    }
}

/// Classifies an OAuth refresh error message.
///
/// # Examples
///
/// ```ignore
/// use crate::auth::refresh_daemon::{classify_refresh_error, OAuthRefreshError};
/// assert!(classify_refresh_error("invalid_grant").is_terminal());
/// assert!(!classify_refresh_error("connection reset by peer").is_terminal());
/// ```
pub(crate) fn classify_refresh_error(msg: &str) -> OAuthRefreshError {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("invalid_grant")
        || lower.contains("invalid_token")
        || lower.contains("unauthorized_client")
    {
        OAuthRefreshError::InvalidGrant
    } else if lower.contains("401") {
        OAuthRefreshError::Unauthorized
    } else {
        OAuthRefreshError::Transient
    }
}

/// Possible outcomes of a single-token refresh attempt.
///
/// Returned by [`refresh_one`] for ease of unit testing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    /// Token was not eligible (already valid or already flagged needs_reauth).
    Skipped,
    /// Refresh succeeded and the new token was persisted.
    Refreshed,
    /// Token was (re-)mirrored from a co-installed CLI's credential store.
    Adopted,
    /// Refresh failed; the token was marked `needs_reauth`.
    MarkedNeedsReauth,
    /// Refresh failed transiently; the token was left untouched for retry.
    TransientFailure,
}

/// How a token should be serviced on a refresh tick.
///
/// Pure verdict extracted from [`refresh_one`] for unit testing — it performs
/// no I/O, so the adoption / refresh decision can be asserted in isolation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServicePlan {
    /// Not eligible — leave the token untouched.
    Skip,
    /// Mirror the token from its system source instead of an OAuth refresh.
    AdoptFromSystem,
    /// Run grob's own OAuth refresh against the authorization server.
    Refresh,
}

/// Decides how `token` should be serviced this tick.
///
/// With `adopt_from_system` on, a token backed by a co-installed CLI is healed
/// by re-adoption when it is flagged `needs_reauth`, and a Claude token (which
/// grob must not refresh — its keychain item is shared) is always re-adopted
/// rather than refreshed. Otherwise the eligibility rule is [`should_refresh`].
pub(crate) fn plan_service(
    token: &OAuthToken,
    now: DateTime<Utc>,
    window: chrono::Duration,
    adopt_from_system: bool,
) -> ServicePlan {
    let has_system_source =
        adopt_from_system && crate::auth::system_creds::source_for(&token.provider_id).is_some();

    if !should_refresh(token, now, window) {
        // A revoked token is normally stuck until manual re-auth; adoption can
        // heal it by pulling the co-installed CLI's fresh credential.
        if has_system_source && token.needs_reauth.unwrap_or(false) {
            return ServicePlan::AdoptFromSystem;
        }
        return ServicePlan::Skip;
    }

    // Never let grob's own refresh rotate a token it only mirrors read-only
    // (the Claude keychain item is shared by every Claude Code session).
    if has_system_source && !crate::auth::system_creds::grob_may_refresh(&token.provider_id) {
        return ServicePlan::AdoptFromSystem;
    }

    ServicePlan::Refresh
}

/// Mirrors `provider_id`'s system credential into the store.
///
/// On failure the token is flagged `needs_reauth` so the operator is prompted.
fn adopt_one(store: &TokenStore, provider_id: &str) -> RefreshOutcome {
    match crate::auth::system_creds::adopt(store, provider_id) {
        Ok(_) => {
            info!(provider = %provider_id, "adopted OAuth token from co-installed CLI");
            RefreshOutcome::Adopted
        }
        Err(e) => {
            warn!(
                provider = %provider_id,
                error = %e,
                "system credential adoption failed — marking token as needing re-authentication"
            );
            if let Err(store_err) = store.mark_needs_reauth(provider_id) {
                error!(
                    provider = %provider_id,
                    error = %store_err,
                    "Failed to mark token as needs_reauth"
                );
            }
            RefreshOutcome::MarkedNeedsReauth
        }
    }
}

/// Refreshes (or re-adopts) a single token if it is eligible, updating the store.
///
/// With `adopt_from_system`, tokens backed by a co-installed CLI are mirrored
/// from that CLI rather than refreshed when grob must not rotate them, and a
/// terminal refresh failure (revoked token) is healed by re-adoption instead of
/// requiring manual re-authentication.
pub(crate) async fn refresh_one(
    store: &TokenStore,
    token: &OAuthToken,
    now: DateTime<Utc>,
    window: chrono::Duration,
    adopt_from_system: bool,
) -> RefreshOutcome {
    match plan_service(token, now, window, adopt_from_system) {
        ServicePlan::Skip => return RefreshOutcome::Skipped,
        ServicePlan::AdoptFromSystem => return adopt_one(store, &token.provider_id),
        ServicePlan::Refresh => {}
    }

    let Some(config) = config_for_provider_id(&token.provider_id) else {
        debug!(
            provider = %token.provider_id,
            "refresh daemon: no OAuthConfig mapping — skipping"
        );
        return RefreshOutcome::Skipped;
    };

    let client = OAuthClient::new(config, store.clone());
    match client.refresh_token(&token.provider_id).await {
        Ok(_) => {
            info!(
                provider = %token.provider_id,
                "OAuth token refreshed proactively"
            );
            RefreshOutcome::Refreshed
        }
        Err(e) => {
            let msg = e.to_string();
            let classification = classify_refresh_error(&msg);
            if classification.is_terminal() {
                // Self-heal a revoked token from the co-installed CLI before
                // falling back to a manual re-auth prompt.
                if adopt_from_system
                    && crate::auth::system_creds::source_for(&token.provider_id).is_some()
                {
                    info!(
                        provider = %token.provider_id,
                        "OAuth refresh rejected — attempting recovery via system credential adoption"
                    );
                    return adopt_one(store, &token.provider_id);
                }
                warn!(
                    provider = %token.provider_id,
                    error = %msg,
                    "OAuth refresh failed permanently — marking token as needing re-authentication. Run: grob connect --force-reauth"
                );
                if let Err(store_err) = store.mark_needs_reauth(&token.provider_id) {
                    error!(
                        provider = %token.provider_id,
                        error = %store_err,
                        "Failed to mark token as needs_reauth"
                    );
                }
                RefreshOutcome::MarkedNeedsReauth
            } else {
                warn!(
                    provider = %token.provider_id,
                    error = %msg,
                    "OAuth refresh failed transiently — will retry next tick"
                );
                RefreshOutcome::TransientFailure
            }
        }
    }
}

/// Spawns the refresh daemon as a tokio task.
///
/// Returns a [`CancellationToken`] handle that, when cancelled, causes the
/// daemon to terminate at the next tick boundary.
pub fn spawn(store: TokenStore, adopt_from_system: bool) -> CancellationToken {
    spawn_with_config(
        store,
        DEFAULT_TICK_INTERVAL,
        DEFAULT_REFRESH_WINDOW,
        adopt_from_system,
    )
}

/// Spawns the refresh daemon with a custom tick interval and refresh window.
///
/// Primarily useful for tests that need to drive refresh activity faster than
/// the production defaults allow.
pub fn spawn_with_config(
    store: TokenStore,
    tick: Duration,
    window: chrono::Duration,
    adopt_from_system: bool,
) -> CancellationToken {
    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    tokio::spawn(async move {
        info!(
            tick_secs = tick.as_secs(),
            window_secs = window.num_seconds(),
            adopt_from_system,
            "OAuth refresh daemon started"
        );
        loop {
            tokio::select! {
                _ = cancel_child.cancelled() => {
                    info!("OAuth refresh daemon shutting down");
                    break;
                }
                _ = tokio::time::sleep(tick) => {
                    run_tick(&store, window, adopt_from_system).await;
                }
            }
        }
    });
    cancel
}

/// Iterates every stored token and services any that expire within `window`.
pub(crate) async fn run_tick(
    store: &TokenStore,
    window: chrono::Duration,
    adopt_from_system: bool,
) {
    let now = Utc::now();
    let tokens = store.all();
    for (_id, token) in tokens {
        let _ = refresh_one(store, &token, now, window, adopt_from_system).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn make_token(expires_in_minutes: i64, needs_reauth: Option<bool>) -> OAuthToken {
        OAuthToken {
            provider_id: "anthropic-max".to_string(),
            access_token: SecretString::new("access".into()),
            refresh_token: SecretString::new("refresh".into()),
            expires_at: Utc::now() + chrono::Duration::minutes(expires_in_minutes),
            enterprise_url: None,
            project_id: None,
            needs_reauth,
        }
    }

    #[test]
    fn should_refresh_triggers_when_within_window() {
        let token = make_token(10, None);
        assert!(should_refresh(
            &token,
            Utc::now(),
            chrono::Duration::minutes(15)
        ));
    }

    #[test]
    fn should_refresh_skips_when_outside_window() {
        let token = make_token(30, None);
        assert!(!should_refresh(
            &token,
            Utc::now(),
            chrono::Duration::minutes(15)
        ));
    }

    #[test]
    fn should_refresh_skips_when_needs_reauth_flagged() {
        let token = make_token(1, Some(true));
        assert!(!should_refresh(
            &token,
            Utc::now(),
            chrono::Duration::minutes(15)
        ));
    }

    #[test]
    fn should_refresh_triggers_when_already_expired() {
        let token = make_token(-1, None);
        assert!(should_refresh(
            &token,
            Utc::now(),
            chrono::Duration::minutes(15)
        ));
    }

    fn provider_token(
        provider_id: &str,
        expires_in_minutes: i64,
        needs_reauth: Option<bool>,
    ) -> OAuthToken {
        let mut t = make_token(expires_in_minutes, needs_reauth);
        t.provider_id = provider_id.to_string();
        t
    }

    const WINDOW: chrono::Duration = chrono::Duration::minutes(15);

    #[test]
    fn plan_service_skips_valid_token() {
        let token = provider_token("openai-codex", 30, None);
        assert_eq!(
            plan_service(&token, Utc::now(), WINDOW, true),
            ServicePlan::Skip
        );
    }

    #[test]
    fn plan_service_refreshes_eligible_codex_when_adopt_on() {
        // Codex token becomes grob-private once adopted, so grob refreshes it.
        let token = provider_token("openai-codex", 5, None);
        assert_eq!(
            plan_service(&token, Utc::now(), WINDOW, true),
            ServicePlan::Refresh
        );
    }

    #[test]
    fn plan_service_adopts_claude_instead_of_refreshing() {
        // The Claude keychain is shared — grob must mirror it, never rotate it.
        let token = provider_token("anthropic-max", 5, None);
        assert_eq!(
            plan_service(&token, Utc::now(), WINDOW, true),
            ServicePlan::AdoptFromSystem
        );
    }

    #[test]
    fn plan_service_heals_revoked_token_by_adoption() {
        let token = provider_token("openai-codex", 5, Some(true));
        assert_eq!(
            plan_service(&token, Utc::now(), WINDOW, true),
            ServicePlan::AdoptFromSystem
        );
    }

    #[test]
    fn plan_service_without_adopt_falls_back_to_refresh_rules() {
        // Adoption off: eligible token refreshes, revoked token is left alone.
        let eligible = provider_token("anthropic-max", 5, None);
        assert_eq!(
            plan_service(&eligible, Utc::now(), WINDOW, false),
            ServicePlan::Refresh
        );
        let revoked = provider_token("openai-codex", 5, Some(true));
        assert_eq!(
            plan_service(&revoked, Utc::now(), WINDOW, false),
            ServicePlan::Skip
        );
    }

    #[test]
    fn plan_service_refreshes_provider_without_system_source() {
        // No known system source → adoption flag is inert; normal rules apply.
        let token = provider_token("gemini", 5, None);
        assert_eq!(
            plan_service(&token, Utc::now(), WINDOW, true),
            ServicePlan::Refresh
        );
    }

    #[tokio::test]
    async fn refresh_one_skips_when_outside_window() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        let token = make_token(30, None);
        store.save(token.clone()).unwrap();

        let outcome = refresh_one(
            &store,
            &token,
            Utc::now(),
            chrono::Duration::minutes(15),
            false,
        )
        .await;
        assert_eq!(outcome, RefreshOutcome::Skipped);
    }

    #[tokio::test]
    async fn refresh_one_skips_unknown_provider() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        let mut token = make_token(5, None);
        token.provider_id = "unknown-provider".into();
        store.save(token.clone()).unwrap();

        let outcome = refresh_one(
            &store,
            &token,
            Utc::now(),
            chrono::Duration::minutes(15),
            false,
        )
        .await;
        assert_eq!(outcome, RefreshOutcome::Skipped);
    }

    #[tokio::test]
    async fn spawn_with_config_runs_and_shuts_down_on_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();

        let cancel = spawn_with_config(
            store,
            Duration::from_millis(10),
            chrono::Duration::minutes(15),
            false,
        );
        // Let a few ticks run.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        // Give the task a moment to notice cancellation.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[test]
    fn classify_invalid_grant_is_terminal() {
        assert_eq!(
            classify_refresh_error("oauth: invalid_grant"),
            OAuthRefreshError::InvalidGrant
        );
        assert!(classify_refresh_error("invalid_grant").is_terminal());
        assert!(classify_refresh_error("INVALID_TOKEN").is_terminal());
        assert!(classify_refresh_error("unauthorized_client").is_terminal());
    }

    #[test]
    fn classify_bare_401_is_terminal() {
        assert_eq!(
            classify_refresh_error("HTTP 401"),
            OAuthRefreshError::Unauthorized
        );
        assert!(classify_refresh_error("401 Unauthorized").is_terminal());
    }

    #[test]
    fn classify_transient_errors_are_not_terminal() {
        assert_eq!(
            classify_refresh_error("connection reset by peer"),
            OAuthRefreshError::Transient
        );
        assert!(!classify_refresh_error("timeout").is_terminal());
        assert!(!classify_refresh_error("500 Internal Server Error").is_terminal());
        assert!(!classify_refresh_error("rate limited").is_terminal());
    }
}
