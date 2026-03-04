//! Record & replay sandwich testing harness.
//!
//! Captures raw HTTP traffic (requests + responses) as "tape" files,
//! then replays them through grob with a mock backend to exercise
//! the full pipeline: DLP, routing, cache, rate limiting, streaming, etc.

mod driver;
mod mock_backend;
mod report;
mod tape;

pub use driver::{Driver, DriverConfig};
pub use mock_backend::{MockBackend, MockConfig};
pub use report::HarnessReport;
pub use tape::{load_tape, TapeEntry, TapeRecorderLayer, TapeRequest, TapeResponse, TapeWriter};
