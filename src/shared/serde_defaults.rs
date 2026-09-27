//! Serde `#[serde(default = "...")]` helpers shared by every config struct.
//!
//! Serde only accepts a *path* for `default`, so a literal `true` cannot be
//! written inline. Six modules used to carry their own private copy of this
//! one-liner; they now point here so the intent is defined exactly once.

/// Returns `true`, for `#[serde(default = "crate::shared::serde_defaults::default_true")]`.
pub(crate) fn default_true() -> bool {
    true
}
