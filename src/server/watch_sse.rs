//! SSE endpoint for `grob watch` live event streaming.

use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use std::convert::Infallible;
use std::sync::Arc;

use super::AppState;

/// Streams live dispatch events as Server-Sent Events.
///
/// Clients connect to `GET /api/events` and receive a JSON-encoded
/// [`WatchEvent`] per SSE `data:` line. A keep-alive ping is sent
/// every 15 seconds to prevent proxy/load-balancer timeouts.
pub(crate) async fn watch_events_sse(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rx = state.event_bus.subscribe();

    let stream = async_stream::stream! {
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        yield Ok::<_, Infallible>(Event::default().data(json));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!("SSE subscriber lagged, skipped {} events", n);
                    // Continue receiving.
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}
