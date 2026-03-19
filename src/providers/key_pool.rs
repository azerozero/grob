//! Multi-account API key pool with rotation strategies.
//!
//! Allows chaining multiple API keys for the same provider so that
//! when one key is exhausted (e.g., rate-limited), the next is used.

use crate::cli::PoolStrategy;
use secrecy::SecretString;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Thread-safe pool of API keys with configurable rotation strategy.
pub struct KeyPool {
    keys: Vec<SecretString>,
    strategy: PoolStrategy,
    cursor: AtomicUsize,
    exhausted: Mutex<HashSet<usize>>,
}

impl KeyPool {
    /// Creates a key pool from a list of keys and a rotation strategy.
    ///
    /// # Panics
    ///
    /// Panics if `keys` is empty.
    pub fn new(keys: Vec<SecretString>, strategy: PoolStrategy) -> Self {
        assert!(!keys.is_empty(), "KeyPool requires at least one key");
        Self {
            keys,
            strategy,
            cursor: AtomicUsize::new(0),
            exhausted: Mutex::new(HashSet::new()),
        }
    }

    /// Returns the number of keys in the pool.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if the pool contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Returns the current active key based on the rotation strategy.
    pub fn current_key(&self) -> &SecretString {
        let idx = self.cursor.load(Ordering::Relaxed) % self.keys.len();
        &self.keys[idx]
    }

    /// Marks the current key as exhausted and advances to the next available key.
    ///
    /// Returns `true` if rotation succeeded (more keys available),
    /// `false` if all keys are exhausted.
    pub fn rotate_on_error(&self) -> bool {
        let mut exhausted = self.exhausted.lock().expect("poisoned lock");
        let current = self.cursor.load(Ordering::Relaxed) % self.keys.len();
        exhausted.insert(current);

        // Find the next non-exhausted key.
        for offset in 1..self.keys.len() {
            let candidate = (current + offset) % self.keys.len();
            if !exhausted.contains(&candidate) {
                self.cursor.store(candidate, Ordering::Relaxed);
                tracing::info!(
                    "Key pool: rotated from key {} to key {} ({} of {} exhausted)",
                    current,
                    candidate,
                    exhausted.len(),
                    self.keys.len()
                );
                return true;
            }
        }

        tracing::warn!("Key pool: all {} keys exhausted", self.keys.len());
        false
    }

    /// Advances the cursor for round-robin strategy (called on every request).
    pub fn advance(&self) {
        // Relaxed is fine: worst case two concurrent requests see the same
        // index, which is harmless for round-robin distribution.
        let _ = self.cursor.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the rotation strategy.
    pub fn strategy(&self) -> &PoolStrategy {
        &self.strategy
    }
}

// NOTE: Debug is intentionally not derived to prevent accidental key logging.
impl std::fmt::Debug for KeyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPool")
            .field("key_count", &self.keys.len())
            .field("strategy", &self.strategy)
            .field("cursor", &self.cursor.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn make_keys(n: usize) -> Vec<SecretString> {
        (0..n)
            .map(|i| SecretString::new(format!("key-{}", i)))
            .collect()
    }

    #[test]
    fn sequential_returns_first_key() {
        let pool = KeyPool::new(make_keys(3), PoolStrategy::Sequential);
        assert_eq!(pool.current_key().expose_secret(), "key-0");
    }

    #[test]
    fn sequential_exhaustion_walks_through_keys() {
        let pool = KeyPool::new(make_keys(3), PoolStrategy::Sequential);

        assert_eq!(pool.current_key().expose_secret(), "key-0");
        assert!(pool.rotate_on_error());
        assert_eq!(pool.current_key().expose_secret(), "key-1");
        assert!(pool.rotate_on_error());
        assert_eq!(pool.current_key().expose_secret(), "key-2");
        // All exhausted after rotating from key-2.
        assert!(!pool.rotate_on_error());
    }

    #[test]
    fn round_robin_wraps_around() {
        let pool = KeyPool::new(make_keys(3), PoolStrategy::RoundRobin);

        assert_eq!(pool.current_key().expose_secret(), "key-0");
        pool.advance();
        assert_eq!(pool.current_key().expose_secret(), "key-1");
        pool.advance();
        assert_eq!(pool.current_key().expose_secret(), "key-2");
        pool.advance();
        // Wraps back to key-0.
        assert_eq!(pool.current_key().expose_secret(), "key-0");
    }

    #[test]
    fn fallback_stays_on_first_until_error() {
        let pool = KeyPool::new(make_keys(3), PoolStrategy::Fallback);

        // Stays on first key without errors.
        assert_eq!(pool.current_key().expose_secret(), "key-0");
        assert_eq!(pool.current_key().expose_secret(), "key-0");

        // Rotates only on error.
        assert!(pool.rotate_on_error());
        assert_eq!(pool.current_key().expose_secret(), "key-1");
    }

    #[test]
    #[should_panic(expected = "KeyPool requires at least one key")]
    fn empty_keys_panics() {
        KeyPool::new(vec![], PoolStrategy::Sequential);
    }

    #[test]
    fn single_key_rotate_returns_false() {
        let pool = KeyPool::new(make_keys(1), PoolStrategy::Sequential);
        assert!(!pool.rotate_on_error());
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let pool = KeyPool::new(make_keys(2), PoolStrategy::Sequential);
        let debug = format!("{:?}", pool);
        assert!(!debug.contains("key-0"));
        assert!(!debug.contains("key-1"));
        assert!(debug.contains("key_count: 2"));
    }
}
