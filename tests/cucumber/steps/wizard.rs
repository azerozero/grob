use cucumber::{given, then, when};
use std::path::PathBuf;
use tokio::process::Command;

use crate::world::E2eWorld;

fn wizard_home(world: &E2eWorld) -> PathBuf {
    PathBuf::from(&world.wizard_home)
}

fn config_path(world: &E2eWorld) -> PathBuf {
    wizard_home(world).join("config.toml")
}

/// Resolves the grob binary path (built by cargo).
fn grob_bin() -> PathBuf {
    // Use the binary from the cargo target directory.
    let mut path = std::env::current_exe().expect("cannot resolve test binary path");
    // tests/cucumber binary is in target/debug/deps/ — go up to target/debug/
    path.pop(); // deps/
    path.pop(); // debug/
    path.push("grob");
    if !path.exists() {
        // Fallback: rely on PATH
        return PathBuf::from("grob");
    }
    path
}

/// Runs grob with GROB_CONFIG pointing to the wizard home, env vars stripped.
async fn run_grob(world: &mut E2eWorld, args: &[&str]) {
    let output = Command::new(grob_bin())
        .args(args)
        .env(
            "GROB_CONFIG",
            config_path(world).to_string_lossy().to_string(),
        )
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENROUTER_API_KEY")
        .env_remove("GEMINI_API_KEY")
        .env_remove("DEEPSEEK_API_KEY")
        .env_remove("MISTRAL_API_KEY")
        .output()
        .await
        .expect("failed to run grob");

    world.last_exit_code = output.status.code().unwrap_or(-1);
    world.last_stdout = String::from_utf8_lossy(&output.stdout).to_string();
    world.last_stderr = String::from_utf8_lossy(&output.stderr).to_string();
}

// ── Given ──

#[given("a clean grob home directory")]
async fn clean_home(world: &mut E2eWorld) {
    let dir = std::env::temp_dir().join(format!("grob-wizard-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("cleanup failed");
    }
    std::fs::create_dir_all(&dir).expect("mkdir failed");
    world.wizard_home = dir.to_string_lossy().to_string();
    world.wizard_config_snapshot = String::new();
}

#[given("a previous setup was completed")]
async fn previous_setup(world: &mut E2eWorld) {
    run_grob(world, &["setup", "--yes"]).await;
    assert_eq!(
        world.last_exit_code, 0,
        "setup --yes failed: {}",
        world.last_stderr
    );
    // Snapshot the config for later comparison
    world.wizard_config_snapshot = std::fs::read_to_string(config_path(world)).unwrap_or_default();
}

// ── When ──

#[when("I run setup with defaults")]
async fn setup_defaults(world: &mut E2eWorld) {
    run_grob(world, &["setup", "--yes"]).await;
}

#[when("I run setup with defaults and dry run")]
async fn setup_dry_run(world: &mut E2eWorld) {
    run_grob(world, &["setup", "--yes", "--dry-run"]).await;
}

#[when("I run doctor")]
async fn run_doctor(world: &mut E2eWorld) {
    run_grob(world, &["doctor"]).await;
}

#[when(regex = r#"I apply preset "(.+)" with dry run"#)]
async fn preset_dry_run(world: &mut E2eWorld, name: String) {
    // Snapshot before
    world.wizard_config_snapshot = std::fs::read_to_string(config_path(world)).unwrap_or_default();
    run_grob(world, &["preset", "apply", &name, "--dry-run"]).await;
}

// ── Then ──

#[then("a valid config is created")]
async fn valid_config(world: &mut E2eWorld) {
    assert_eq!(
        world.last_exit_code, 0,
        "exit code != 0:\n{}",
        world.last_stderr
    );
    let path = config_path(world);
    assert!(path.exists(), "config.toml not created");
    let content = std::fs::read_to_string(&path).expect("cannot read config");
    let config: toml::Value = toml::from_str(&content).expect("invalid TOML");
    assert!(config.get("router").is_some(), "missing [router]");
    assert!(config.get("providers").is_some(), "missing [[providers]]");
}

#[then("no config is written")]
async fn no_config(world: &mut E2eWorld) {
    assert_eq!(
        world.last_exit_code, 0,
        "exit code != 0:\n{}",
        world.last_stderr
    );
    assert!(!config_path(world).exists(), "config.toml should not exist");
    let combined = format!("{}{}", world.last_stdout, world.last_stderr);
    assert!(combined.contains("Dry run"), "missing 'Dry run' in output");
}

#[then("a backup of the previous config exists")]
async fn backup_exists(world: &mut E2eWorld) {
    assert_eq!(
        world.last_exit_code, 0,
        "exit code != 0:\n{}",
        world.last_stderr
    );
    let backup = wizard_home(world).join("config.toml.backup");
    assert!(backup.exists(), "config.toml.backup not created");
}

#[then("all credentials use environment variable references")]
async fn env_var_refs(world: &mut E2eWorld) {
    let content = std::fs::read_to_string(config_path(world)).expect("cannot read config");
    let config: toml::Value = toml::from_str(&content).expect("invalid TOML");
    if let Some(providers) = config.get("providers").and_then(|p| p.as_array()) {
        for p in providers {
            if let Some(key) = p.get("api_key").and_then(|k| k.as_str()) {
                let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                assert!(
                    key.starts_with('$'),
                    "provider '{}' has raw key: {}",
                    name,
                    key
                );
            }
        }
    }
}

#[then("the doctor reports no errors")]
async fn doctor_ok(world: &mut E2eWorld) {
    assert_eq!(
        world.last_exit_code, 0,
        "doctor should exit 0:\nstdout: {}\nstderr: {}",
        world.last_stdout, world.last_stderr
    );
}

#[then("the config is unchanged")]
async fn config_unchanged(world: &mut E2eWorld) {
    assert_eq!(
        world.last_exit_code, 0,
        "exit code != 0:\n{}",
        world.last_stderr
    );
    let current = std::fs::read_to_string(config_path(world)).expect("cannot read config");
    assert_eq!(current, world.wizard_config_snapshot, "config was modified");
}
