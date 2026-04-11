//! Response caching layer for LLM responses.

pub mod response_cache;
pub mod simhash;

pub use response_cache::{CachedResponse, ResponseCache};
pub use simhash::SimHashCache;
