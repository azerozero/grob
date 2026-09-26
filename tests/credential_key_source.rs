//! Exercises external storage keys through independent CLI processes and private stores.
use std::{
    path::Path,
    process::{Command, Output},
};

fn protect(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn run(home: &Path, key: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_grob"));
    command
        .env("GROB_HOME", home)
        .env_remove("GROB_ENCRYPTION_KEY_FILE")
        .arg("--config")
        .arg(home.join("config.toml"))
        .args(args);
    if let Some(key) = key {
        command.env("GROB_ENCRYPTION_KEY_FILE", key);
    }
    command.output().unwrap()
}

#[test]
fn cli_external_key_survives_restart_and_missing_or_wrong_keys_never_write() {
    let home = tempfile::tempdir().unwrap();
    let secret_mount = tempfile::tempdir().unwrap();
    let key = secret_mount.path().join("storage-key");
    std::fs::write(&key, [27u8; 32]).unwrap();
    protect(&key);
    std::fs::write(
        home.path().join("config.toml"),
        r#"
providers = []
models = []
[router]
default = "unused"
[auth]
mode = "api_key"
api_key = "synthetic-admin"
adopt_from_system = false
[pricing]
fetch_openrouter = false
"#,
    )
    .unwrap();
    let created = run(
        home.path(),
        Some(&key),
        &["key", "create", "--name", "fixture", "--tenant", "fixture"],
    );
    assert!(
        created.status.success(),
        "key creation failed without displaying credential output"
    );
    assert!(!home.path().join("encryption.key").exists());
    assert!(home.path().join("encryption.check").exists());
    assert!(run(home.path(), Some(&key), &["key", "list"])
        .status
        .success());
    let check = std::fs::read(home.path().join("encryption.check")).unwrap();
    std::fs::write(&key, [28u8; 32]).unwrap();
    assert!(!run(
        home.path(),
        Some(&key),
        &["key", "create", "--name", "wrong"]
    )
    .status
    .success());
    std::fs::remove_file(&key).unwrap();
    assert!(!run(home.path(), Some(&key), &["key", "list"])
        .status
        .success());
    assert!(!run(home.path(), None, &["key", "list"]).status.success());
    assert!(!home.path().join("encryption.key").exists());
    assert_eq!(
        std::fs::read(home.path().join("encryption.check")).unwrap(),
        check
    );
    std::fs::write(&key, [27u8; 32]).unwrap();
    protect(&key);
    assert!(run(home.path(), Some(&key), &["key", "list"])
        .status
        .success());
}
