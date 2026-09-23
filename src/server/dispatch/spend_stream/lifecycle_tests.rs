use super::*;
use futures::{stream, StreamExt};

fn context(state: Arc<AppState>) -> SpendStreamContext {
    SpendStreamContext {
        state,
        provider: "synthetic".into(),
        model_name: "alpha".into(),
        actual_model: "gpt-4o".into(),
        route_type: RouteType::Default,
        tenant_id: None,
        agent_id: None,
        is_subscription: false,
        estimated_input_tokens: 0,
        start_time: std::time::Instant::now(),
        trace_id: None,
    }
}

#[tokio::test]
async fn completion_error_and_cancellation_commit_observed_usage_once_before_drain() {
    for mode in [
        crate::cli::TokenCountingMode::Api,
        crate::cli::TokenCountingMode::Estimate,
    ] {
        for end in ["eof", "error", "cancelled"] {
            let (_home, state, _app) = crate::server::credential_boundary_tests::fixture();
            let mut config = state.snapshot().config.clone();
            config.pricing.token_counting = mode;
            *state.inner.write().unwrap() = Arc::new(crate::server::ReloadableState::new(
                config.clone(),
                crate::routing::classify::Router::new(config),
                Arc::new(crate::providers::ProviderRegistry::new()),
            ));
            let pricing = state.observability.pricing_table.read().await;
            let expected = crate::features::token_pricing::TokenCounter::with_pricing(
                "gpt-4o",
                100,
                20,
                0,
                false,
                Some(&pricing),
            )
            .estimated_cost_usd;
            drop(pricing);
            assert!(expected > 0.0);
            // The final usage event lacks a delimiter: terminal paths must flush carry.
            let events = Bytes::from_static(b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":100}}}\n\nevent: message_delta\ndata: {\"usage\":{\"output_tokens\":20}}");
            let mut chunks = vec![Ok(events.clone())];
            if end == "error" {
                chunks.push(Err(crate::providers::error::ProviderError::AuthError(
                    "synthetic".into(),
                )));
            }
            let mut body = SpendStream::new(stream::iter(chunks), context(state.clone()));
            assert_eq!(body.next().await.unwrap().unwrap(), events);
            assert!(
                state
                    .active_requests
                    .load(std::sync::atomic::Ordering::Relaxed)
                    > 0
            );
            // Hold the accounting mutex so drain must wait for the tracked task.
            let tracker = state.observability.spend_tracker.lock().await;
            if end != "cancelled" {
                let terminal = body.next().await;
                assert_eq!(terminal.is_none(), end == "eof");
            }
            drop(body);
            let draining_state = state.clone();
            let drain = tokio::spawn(async move {
                crate::server::lifecycle::drain_in_flight(&draining_state).await
            });
            tokio::task::yield_now().await;
            assert!(!drain.is_finished());
            assert_eq!(tracker.total(), 0.0);
            drop(tracker);
            tokio::time::timeout(std::time::Duration::from_secs(2), drain)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                state.observability.spend_tracker.lock().await.total(),
                expected,
                "{mode:?} {end}"
            );
            state.grob_store.flush_spend();
            let reopened =
                crate::storage::GrobStore::open(&state.grob_store.path().join("grob.db")).unwrap();
            assert_eq!(reopened.load_spend().total, expected);
            assert_eq!(
                state
                    .active_requests
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        }
    }
}
