//! Live event bus for `grob watch` TUI and SSE endpoint.
//!
//! Broadcasts dispatch events (requests, responses, DLP actions, fallbacks)
//! to all connected subscribers without blocking the hot path.

pub mod events;
#[cfg(feature = "watch")]
pub mod tui;

use events::WatchEvent;
use tokio::sync::broadcast;

/// Default broadcast channel capacity (drops oldest if full).
const CHANNEL_CAPACITY: usize = 1024;

/// Broadcast sender for live events. Embed in `AppState`.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<WatchEvent>,
}

impl EventBus {
    /// Creates a new event bus with default capacity.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }

    /// Publishes an event to all subscribers. Non-blocking, never fails.
    pub fn emit(&self, event: WatchEvent) {
        // Ignore send errors (no subscribers).
        let _ = self.tx.send(event);
    }

    /// Creates a new subscriber receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<WatchEvent> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
