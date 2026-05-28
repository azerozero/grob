//! Verifies that every shipped example config in `docs/examples/` parses
//! into [`AppConfig`] under the current schema.
//!
//! These examples were inherited from a `claude-code-router` fork and used
//! fork-era keys (`api_base_url`, `[providers.transformers]`,
//! `[providers.model_context]`) that the current `#[serde(deny_unknown_fields)]`
//! schema rejects. This test pins them to the live schema so the drift cannot
//! silently return: a malformed example fails CI instead of a user's first run.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use grob::cli::AppConfig;

    /// Returns the absolute path to the repository's `docs/examples` directory.
    fn examples_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/examples")
    }

    /// Collects every `*.toml` file under `docs/examples/`, sorted by name.
    fn example_toml_files() -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(examples_dir())
            .expect("docs/examples directory must exist")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("toml"))
            .collect();
        files.sort();
        files
    }

    /// Every example TOML deserializes into [`AppConfig`] and passes validation.
    ///
    /// Uses `toml::from_str` (schema check) followed by `validate()` (semantic
    /// check: provider references, regex compilation, auth wiring). Env-var
    /// resolution is intentionally skipped so the test stays hermetic — a
    /// literal `"$DEEPSEEK_API_KEY"` placeholder satisfies the api_key
    /// presence check without requiring the variable to be set.
    #[test]
    fn all_example_configs_parse_into_appconfig() {
        let files = example_toml_files();
        assert!(
            !files.is_empty(),
            "expected at least one example TOML in docs/examples"
        );

        for path in files {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

            let config: AppConfig = toml::from_str(&content).unwrap_or_else(|e| {
                panic!(
                    "example config {} does not parse into AppConfig: {e}",
                    path.display()
                )
            });

            config.validate().unwrap_or_else(|e| {
                panic!("example config {} failed validation: {e}", path.display())
            });
        }
    }
}
