//! Interactive wizard screens.
//!
//! Each screen is a pure user-interaction step: it collects input and
//! returns a fully-formed choice object. Nothing here touches the filesystem.

pub(in crate::commands::setup) mod auth;
pub(in crate::commands::setup) mod budget;
pub(in crate::commands::setup) mod compliance;
pub(in crate::commands::setup) mod endpoints;
pub(in crate::commands::setup) mod fallback;
pub(in crate::commands::setup) mod tools;
