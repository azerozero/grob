//! CLI subcommands: start, stop, status, doctor, spend, etc.

/// Shared utilities and helpers used across subcommands.
pub mod common;
/// Shell completion script generation for supported shells.
pub mod completions;
/// Compares running config against the on-disk TOML file.
pub mod config_diff;
/// Establishes a live connection to a running grob instance.
pub mod connect;
/// Diagnoses configuration, connectivity, and provider health.
pub mod doctor;
/// Displays resolved environment variables and config paths.
pub mod env;
/// Executes a one-shot LLM request without starting the server.
pub mod exec;
/// Record and replay sandwich testing harness.
#[cfg(feature = "harness")]
pub mod harness;
/// Initializes a new grob configuration file interactively.
pub mod init;
/// Lists, inspects, and manages available LLM models.
pub mod model;
/// Manages named configuration presets (save, load, delete).
pub mod preset;
/// Stops and restarts the grob server in one operation.
pub mod restart;
/// Starts the server in foreground (non-daemonized) mode.
pub mod run;
/// Installs shell completion scripts to standard locations.
pub mod setup_completions;
/// Displays cumulative spend, budget status, and cost breakdowns.
pub mod spend;
/// Launches the grob server as a background daemon.
pub mod start;
/// Reports whether the grob daemon is running and healthy.
pub mod status;
/// Gracefully shuts down the running grob daemon.
pub mod stop;
/// Checks for and applies grob binary upgrades.
pub mod upgrade;
/// Validates the TOML configuration file for errors.
pub mod validate;
