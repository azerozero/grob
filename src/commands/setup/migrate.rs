//! Auto-migration for deprecated top-level keys in an existing `grob.toml`.
//!
//! The wizard runs [`detect_schema_drift`](super::detect::detect_schema_drift)
//! on startup. When drift is found, the user is prompted; on confirmation
//! this module rewrites the config atomically (backup → edit → write).

use std::path::Path;

use anyhow::{Context, Result};
use toml::Value;

use super::detect::DriftReport;

/// Applies every supported migration to `value` and returns a summary.
///
/// The returned `Vec` lists the migrations that were performed, in the form
/// `"old_key -> target"`. Unsupported deprecated keys are preserved with a
/// prefix so manual review is still possible.
pub(in crate::commands::setup) fn apply_migrations(
    value: &mut Value,
    report: &DriftReport,
) -> Vec<String> {
    let mut applied = Vec::new();
    let Some(root) = value.as_table_mut() else {
        return applied;
    };

    for (key, _hint) in &report.deprecated {
        match *key {
            "openai_compat" => {
                if let Some(section) = root.remove(*key) {
                    nest_under(root, "server", "openai_compat", section);
                    applied.push(format!("'{}' -> [server.openai_compat]", key));
                }
            }
            "rate_limit" => {
                if let Some(section) = root.remove(*key) {
                    migrate_rate_limit(root, section);
                    applied.push(format!("'{}' -> [security].rate_limit_*", key));
                }
            }
            _ => {
                // Unknown deprecation — keep the key so the user can migrate manually.
            }
        }
    }

    // Unknown keys are removed: they are not valid TOML for any section and
    // cannot be autoloaded, so their only effect is a parse warning.
    for key in &report.unknown {
        if root.remove(key).is_some() {
            applied.push(format!("removed unknown key '{}'", key));
        }
    }

    applied
}

/// Writes `value` to `path` atomically, keeping a `.toml.backup` copy.
///
/// # Errors
///
/// Returns an error if the backup cannot be created, serialization fails,
/// or the final write fails.
pub(in crate::commands::setup) fn write_migrated(path: &Path, value: &Value) -> Result<()> {
    if path.exists() {
        let backup = path.with_extension("toml.backup");
        std::fs::copy(path, &backup).context("failed to back up config before migration")?;
    }
    let serialized = toml::to_string_pretty(value).context("failed to serialize migrated TOML")?;
    std::fs::write(path, serialized).context("failed to write migrated config")?;
    Ok(())
}

/// Nests `value` under `root[parent][child]`, creating the parent table if needed.
fn nest_under(root: &mut toml::map::Map<String, Value>, parent: &str, child: &str, value: Value) {
    let parent_entry = root
        .entry(parent.to_string())
        .or_insert_with(|| Value::Table(toml::map::Map::new()));
    if let Some(parent_table) = parent_entry.as_table_mut() {
        parent_table.insert(child.to_string(), value);
    }
}

/// Maps the legacy `[rate_limit]` section onto `[security].rate_limit_rps` /
/// `[security].rate_limit_burst`.
fn migrate_rate_limit(root: &mut toml::map::Map<String, Value>, legacy: Value) {
    let Some(legacy_table) = legacy.as_table() else {
        return;
    };
    let security = root
        .entry("security".to_string())
        .or_insert_with(|| Value::Table(toml::map::Map::new()));
    let Some(sec) = security.as_table_mut() else {
        return;
    };
    for (old, new) in [("rps", "rate_limit_rps"), ("burst", "rate_limit_burst")] {
        if let Some(v) = legacy_table.get(old) {
            sec.insert(new.to_string(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Value {
        toml::from_str(
            r#"
[openai_compat]
enabled = true

[rate_limit]
rps = 50
burst = 100

[typo_section]
foo = 1

[providers]
"#,
        )
        .unwrap()
    }

    #[test]
    fn migrates_openai_compat_under_server() {
        let mut value = sample_config();
        let report = DriftReport {
            deprecated: vec![("openai_compat", "")],
            unknown: vec![],
        };
        let applied = apply_migrations(&mut value, &report);
        assert!(applied.iter().any(|m| m.contains("openai_compat")));

        let root = value.as_table().unwrap();
        assert!(!root.contains_key("openai_compat"));
        let server = root.get("server").unwrap().as_table().unwrap();
        assert!(server.contains_key("openai_compat"));
    }

    #[test]
    fn migrates_rate_limit_into_security() {
        let mut value = sample_config();
        let report = DriftReport {
            deprecated: vec![("rate_limit", "")],
            unknown: vec![],
        };
        apply_migrations(&mut value, &report);

        let root = value.as_table().unwrap();
        assert!(!root.contains_key("rate_limit"));
        let sec = root.get("security").unwrap().as_table().unwrap();
        assert_eq!(sec.get("rate_limit_rps").unwrap().as_integer(), Some(50));
        assert_eq!(sec.get("rate_limit_burst").unwrap().as_integer(), Some(100));
    }

    #[test]
    fn removes_unknown_keys() {
        let mut value = sample_config();
        let report = DriftReport {
            deprecated: vec![],
            unknown: vec!["typo_section".into()],
        };
        let applied = apply_migrations(&mut value, &report);
        assert!(applied.iter().any(|m| m.contains("typo_section")));
        assert!(!value.as_table().unwrap().contains_key("typo_section"));
    }

    #[test]
    fn preserves_known_sections() {
        let mut value = sample_config();
        let report = DriftReport {
            deprecated: vec![("openai_compat", ""), ("rate_limit", "")],
            unknown: vec!["typo_section".into()],
        };
        apply_migrations(&mut value, &report);
        assert!(value.as_table().unwrap().contains_key("providers"));
    }

    #[test]
    fn no_op_when_drift_empty() {
        let mut value = sample_config();
        let report = DriftReport::default();
        let applied = apply_migrations(&mut value, &report);
        assert!(applied.is_empty());
        assert!(value.as_table().unwrap().contains_key("openai_compat"));
    }
}
