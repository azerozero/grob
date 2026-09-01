//! Stateless sidecar layer for capabilities too heavy to link in.
//!
//! Three capabilities (OCR, watermarking, provenance signing) each need
//! machine-learning runtimes or large cryptographic stacks. Measured costs for
//! linking them directly: `c2pa` adds 7.0 MB and `trustmark` 11.9 MB to a
//! binary of 17.3 MB. Out-of-process is therefore the default rather than a
//! preference, and one protocol serves all three so they cannot drift apart.
//!
//! # Statelessness
//!
//! The contract is bytes in, bytes or text out. A [`proto::SidecarRequest`]
//! carries no tenant, session, policy or trace field, so a sidecar cannot
//! correlate calls even if it wanted to. Everything stateful stays in Grob
//! under `~/.grob/media/`.
//!
//! This keeps sidecars replaceable while running, replicable behind any load
//! balancer, and outside the blast radius: a component that retained payloads
//! would be a second copy of the data this slice exists to protect.
//!
//! # Availability
//!
//! An unconfigured capability is off, not broken. Grob starts and serves
//! whether or not any sidecar exists, and a failing one trips a breaker rather
//! than being retried indefinitely.
//!
//! # Choosing an OCR engine
//!
//! The protocol makes engines interchangeable, which matters because their
//! costs differ by three orders of magnitude:
//!
//! | Engine | Weights | Runs on |
//! |---|---|---|
//! | `ocrs` (default) | ~12 MB | CPU, no system dependency |
//! | macOS Vision | 0, in the OS | Apple platforms |
//! | `deepseek-ocr.rs` | 4.7-9 GB, 9-50 GB RAM | GPU or large-memory hosts |
//!
//! `ocrs` and Vision were each measured feeding 3 of 4 planted secrets to the
//! DLP engine from the same screenshot, with different failure modes. A
//! vision-language model reads what both miss, at a memory budget that rules
//! it out as a default for a proxy that fits in a 6 MB container.
//!
//! One caution worth stating where the code is: a VLM reading
//! attacker-supplied screenshots is the multimodal prompt-injection surface
//! from OWASP LLM01. Its output is data for the DLP engine, never
//! instructions, which is why [`proto::SidecarResponse`] carries text and
//! bytes and nothing that could be interpreted as a command.

pub mod client;
pub mod config;
pub mod proto;
#[cfg(test)]
mod tests;

pub use client::SidecarClient;
pub use config::{Endpoint, SidecarConfig};
pub use proto::{Capability, SidecarError, SidecarRequest, SidecarResponse, PROTOCOL_VERSION};
