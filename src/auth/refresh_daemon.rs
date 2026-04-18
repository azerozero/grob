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

/// Possible outcomes of a single-token refresh attempt.
///
/// Returned by [`refresh_one`] for ease of unit testing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    /// Token was not eligible (already valid or already flagged needs_reauth).
    Skipped,
    /// Refresh succeeded and the new token was persisted.
    Refreshed,
    /// Refresh failed; the token was marked `needs_reauth`.
    MarkedNeedsReauth,
    /// Refresh failed transiently; the token was left untouched for retry.
    TransientFailure,
}

/// Refreshes a single token if it is eligible, updating the store accordingly.
pub(crate) async fn refresh_one(
    store: &TokenStore,
    token: &OAuthToken,
    now: DateTime<Utc>,
    window: chrono::Duration,
) -> RefreshOutcome {
    if !should_refresh(token, now, window) {
        return RefreshOutcome::Skipped;
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
            // Terminal failures: the refresh_token itself was rejected.
            // 401/invalid_grant/invalid_token are all treated as permanent.
            let terminal = msg.contains("401")
                || msg.contains("invalid_grant")
                || msg.contains("invalid_token")
                || msg.contains("unauthorized_client");
            if terminal {
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
pub fn spawn(store: TokenStore) -> CancellationToken {
    spawn_with_config(store, DEFAULT_TICK_INTERVAL, DEFAULT_REFRESH_WINDOW)
}

/// Spawns the refresh daemon with a custom tick interval and refresh window.
///
/// Primarily useful for tests that need to drive refresh activity faster than
/// the production defaults allow.
pub fn spawn_with_config(
    store: TokenStore,
    tick: Duration,
    window: chrono::Duration,
) -> CancellationToken {
    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    tokio::spawn(async move {
        info!(
            tick_secs = tick.as_secs(),
            window_secs = window.num_seconds(),
            "OAuth refresh daemon started"
        );
        loop {
            tokio::select! {
                _ = cancel_child.cancelled() => {
                    info!("OAuth refresh daemon shutting down");
                    break;
                }
                _ = tokio::time::sleep(tick) => {
                    run_tick(&store, window).await;
                }
            }
        }
    });
    cancel
}

/// Runs a single refresh sweep over all tokens in the store.
pub(crate) async fn run_tick(store: &TokenStore, window: chrono::Duration) {
    let now = Utc::now();
    let tokens = store.all();
    for (_id, token) in tokens {
        let _ = refresh_one(store, &token, now, window).await;
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

    #[tokio::test]
    async fn refresh_one_skips_when_outside_window() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        let token = make_token(30, None);
        store.save(token.clone()).unwrap();

        let outcome = refresh_one(&store, &token, Utc::now(), chrono::Duration::minutes(15)).await;
        assert_eq!(outcome, RefreshOutcome::Skipped);
    }

    #[tokio::test]
    async fn refresh_one_skips_unknown_provider() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        let mut token = make_token(5, None);
        token.provider_id = "unknown-provider".into();
        store.save(token.clone()).unwrap();

        let outcome = refresh_one(&store, &token, Utc::now(), chrono::Duration::minutes(15)).await;
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
        );
        // Let a few ticks run.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        // Give the task a moment to notice cancellation.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
