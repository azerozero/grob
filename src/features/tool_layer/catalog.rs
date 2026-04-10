//! Embedded tool catalog with static JSON schemas.
//!
//! Schemas are compiled into the binary via `include_str!` so no filesystem
//! access is needed at runtime.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Pre-parsed tool schema from the embedded JSON catalog.
#[derive(Debug, Clone, Deserialize)]
pub struct CatalogEntry {
    /// Canonical tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    pub parameters: serde_json::Value,
}

/// Lazily-initialised catalog keyed by canonical tool name.
static CATALOG: LazyLock<HashMap<String, CatalogEntry>> = LazyLock::new(|| {
    let raw_entries: &[&str] = &[
        include_str!("schemas/bash.json"),
        include_str!("schemas/read_file.json"),
        include_str!("schemas/write_file.json"),
        include_str!("schemas/web_search.json"),
        include_str!("schemas/grep.json"),
    ];

    let mut map = HashMap::with_capacity(raw_entries.len());
    for raw in raw_entries {
        let entry: CatalogEntry =
            serde_json::from_str(raw).expect("embedded tool schema is valid JSON");
        map.insert(entry.name.clone(), entry);
    }
    map
});

/// Returns the catalog entry for `name`, or `None` if unknown.
pub fn lookup(name: &str) -> Option<&'static CatalogEntry> {
    CATALOG.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_loads_all_schemas() {
        assert!(lookup("bash").is_some());
        assert!(lookup("read_file").is_some());
        assert!(lookup("write_file").is_some());
        assert!(lookup("web_search").is_some());
        assert!(lookup("grep").is_some());
        assert!(lookup("nonexistent").is_none());
    }
}
