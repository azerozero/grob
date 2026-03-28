// Validates unikernel build constraints at the code level.
//
// Heavy-weight checks (cargo build, binary size) run in CI via
// .github/workflows/unikernel.yml. These tests verify invariants
// that the Rust type system and feature flags enforce.

use std::path::PathBuf;
use std::process::Command;

/// Verifies that the project compiles with the unikernel feature flag.
#[test]
fn unikernel_feature_compiles() {
    // On Windows, jemalloc (a default feature) cannot build, so use
    // --no-default-features with the unikernel-compatible feature set.
    let args: &[&str] = if cfg!(target_os = "windows") {
        &[
            "check",
            "--no-default-features",
            "--features",
            "dlp,oauth,tap,compliance,mcp,watch,policies,socket-opts,dirs,unikernel",
        ]
    } else {
        &["check", "--features", "unikernel"]
    };
    let status = Command::new("cargo")
        .args(args)
        .status()
        .expect("failed to execute cargo check");
    assert!(status.success(), "cargo check --features unikernel failed");
}

/// Verifies that the minimal unikernel feature set compiles without defaults.
#[test]
fn unikernel_no_default_features_compiles() {
    let status = Command::new("cargo")
        .args([
            "check",
            "--no-default-features",
            "--features",
            "dlp,policies,unikernel",
        ])
        .status()
        .expect("failed to execute cargo check");
    assert!(
        status.success(),
        "cargo check --no-default-features --features dlp,policies,unikernel failed"
    );
}

/// Verifies the release binary stays under the 20 MB size budget.
///
/// Skipped in regular test runs (requires a release build). Runs in CI
/// via the unikernel workflow which builds the binary first.
#[test]
#[ignore = "requires release build — run with --ignored or in CI"]
fn binary_size_under_budget() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = workspace.join("target/release/grob");

    if !binary.exists() {
        panic!(
            "Release binary not found at {}. Run `cargo build --release` first.",
            binary.display()
        );
    }

    let metadata = std::fs::metadata(&binary).expect("failed to read binary metadata");
    let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
    let max_mb = 20.0;

    assert!(
        size_mb < max_mb,
        "Binary size {size_mb:.1} MB exceeds {max_mb:.0} MB budget"
    );
}

/// Verifies `grob_home()` returns `None` when the unikernel feature is active
/// and `GROB_HOME` is not set.
#[test]
#[cfg(feature = "unikernel")]
fn grob_home_returns_none_without_env() {
    // Temporarily clear GROB_HOME if set
    let prev = std::env::var("GROB_HOME").ok();
    std::env::remove_var("GROB_HOME");

    let result = grob::grob_home();
    assert!(
        result.is_none(),
        "grob_home() should return None under unikernel without GROB_HOME"
    );

    // Restore
    if let Some(val) = prev {
        std::env::set_var("GROB_HOME", val);
    }
}

/// Verifies `grob_home()` honours `GROB_HOME` even under the unikernel feature.
#[test]
fn grob_home_honours_env_var() {
    let prev = std::env::var("GROB_HOME").ok();
    std::env::set_var("GROB_HOME", "/tmp/grob-test");

    let result = grob::grob_home();
    assert_eq!(result, Some(PathBuf::from("/tmp/grob-test")));

    // Restore
    match prev {
        Some(val) => std::env::set_var("GROB_HOME", val),
        None => std::env::remove_var("GROB_HOME"),
    }
}
