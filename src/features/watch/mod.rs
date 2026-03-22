//! Live event bus for `grob watch` TUI and SSE endpoint.
//!
//! Broadcasts dispatch events (requests, responses, DLP actions, fallbacks)
//! to all connected subscribers without blocking the hot path.
//!
//! When the `watch` feature is disabled, [`EventBus`] is a zero-size no-op type
//! with the same interface — no channel is allocated and all calls are inlined.

pub mod events;
#[cfg(feature = "watch")]
pub mod tui;

use events::WatchEvent;

// ── Full EventBus (watch feature enabled) ────────────────────────────────────

/// Broadcast sender for live events. Embed in `AppState`.
#[cfg(feature = "watch")]
#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<WatchEvent>,
}

#[cfg(feature = "watch")]
impl EventBus {
    /// Default broadcast channel capacity (drops oldest when full).
    const CHANNEL_CAPACITY: usize = 1024;

    /// Creates a new event bus.
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(Self::CHANNEL_CAPACITY);
        Self { tx }
    }

    /// Publishes an event to all subscribers. Non-blocking, never fails.
    pub fn emit(&self, event: WatchEvent) {
        let _ = self.tx.send(event);
    }

    /// Creates a new subscriber receiver.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<WatchEvent> {
        self.tx.subscribe()
    }
}

#[cfg(feature = "watch")]
impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ── No-op EventBus stub (watch feature disabled) ─────────────────────────────

/// Zero-cost no-op event bus for builds without the `watch` feature.
///
/// All methods are inlined empty functions. No channel is allocated.
#[cfg(not(feature = "watch"))]
#[derive(Clone, Default)]
pub struct EventBus;

#[cfg(not(feature = "watch"))]
impl EventBus {
    /// Creates a new no-op event bus.
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }

    /// No-op: event is dropped immediately.
    #[inline(always)]
    pub fn emit(&self, _event: WatchEvent) {}
}
