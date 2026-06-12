//! Inbound tool **well-formedness** validation.
//!
//! Validates that client-supplied tools are structurally sound before they reach
//! a provider: a non-empty `name`, and an `input_schema` that is a well-formed
//! JSON Schema (an object, with sane `type`/`properties`/`required` shapes).
//!
//! IMPORTANT: this is **NOT** catalogue membership. Client tools are arbitrary
//! and legitimate (Claude Code, Codex, MCP servers all ship their own tools);
//! validating them against grob's internal tool catalogue would strip every one
//! of them and break tool use wholesale. The only thing checked here is *shape*.
//!
//! By default a malformed tool is **stripped and logged** (never silently
//! dropped). Setting `reject = true` turns a malformed tool into a `400` instead.

use crate::models::{CanonicalRequest, Tool};
use serde::{Deserialize, Serialize};

/// Configuration for inbound tool well-formedness validation (`[tool_validation]`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolValidationConfig {
    /// Master switch. Enabled by default — malformed tools are stripped + logged.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// When true, a malformed tool aborts the request with `400` instead of being
    /// stripped. Opt-in; the default is the non-fatal strip-and-log behaviour.
    #[serde(default)]
    pub reject: bool,
}

impl Default for ToolValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reject: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Validates the well-formedness of every inbound tool on `request`.
///
/// In the default (strip) mode, malformed tools are removed in place and their
/// labels returned so the caller can log them. In reject mode, the first
/// malformed tool yields `Err(reason)` and the request is left untouched.
///
/// # Errors
///
/// Returns `Err(reason)` only in reject mode, when a tool is malformed.
pub fn validate_inbound_tools(
    request: &mut CanonicalRequest,
    config: &ToolValidationConfig,
) -> Result<Vec<String>, String> {
    if !config.enabled {
        return Ok(Vec::new());
    }
    let Some(tools) = request.tools.as_mut() else {
        return Ok(Vec::new());
    };

    if config.reject {
        for tool in tools.iter() {
            if let Err(reason) = check_well_formed(tool) {
                return Err(format!(
                    "tool '{}' is malformed: {reason}",
                    tool_label(tool)
                ));
            }
        }
        return Ok(Vec::new());
    }

    let mut stripped = Vec::new();
    tools.retain(|tool| match check_well_formed(tool) {
        Ok(()) => true,
        Err(_) => {
            stripped.push(tool_label(tool));
            false
        }
    });
    Ok(stripped)
}

/// Checks a single tool's structural well-formedness (NOT catalogue membership).
fn check_well_formed(tool: &Tool) -> Result<(), &'static str> {
    match tool.name.as_deref() {
        Some(name) if !name.trim().is_empty() => {}
        _ => return Err("missing or empty tool name"),
    }

    // `input_schema` is optional, but when present it must be a well-formed JSON
    // Schema. Tools use object schemas; we accept any object and sanity-check the
    // common keywords rather than running a full meta-schema (no catalogue, no
    // semantic constraints on the client's own parameters).
    if let Some(schema) = &tool.input_schema {
        let Some(obj) = schema.as_object() else {
            return Err("input_schema is not a JSON Schema object");
        };
        // `type`: a valid JSON Schema type keyword, or an array of them.
        if let Some(ty) = obj.get("type") {
            match ty {
                serde_json::Value::String(s) => {
                    if !is_valid_schema_type(s) {
                        return Err("input_schema.type is not a valid JSON Schema type");
                    }
                }
                serde_json::Value::Array(items) => {
                    if !items
                        .iter()
                        .all(|i| i.as_str().is_some_and(is_valid_schema_type))
                    {
                        return Err("input_schema.type array has a non-type element");
                    }
                }
                _ => return Err("input_schema.type must be a string or array"),
            }
        }
        // `properties`: each value must itself be a (sub-)schema object.
        if let Some(props) = obj.get("properties") {
            let Some(props) = props.as_object() else {
                return Err("input_schema.properties must be an object");
            };
            if !props.values().all(|v| v.is_object()) {
                return Err("input_schema.properties has a non-object sub-schema");
            }
        }
        // `required`: an array whose every element is a string.
        if let Some(required) = obj.get("required") {
            let Some(items) = required.as_array() else {
                return Err("input_schema.required must be an array");
            };
            if !items.iter().all(|i| i.is_string()) {
                return Err("input_schema.required has a non-string element");
            }
        }
    }

    Ok(())
}

/// Returns `true` for the seven JSON Schema primitive type keywords.
fn is_valid_schema_type(ty: &str) -> bool {
    matches!(
        ty,
        "object" | "array" | "string" | "number" | "integer" | "boolean" | "null"
    )
}

/// Human-readable label for logging / error messages.
fn tool_label(tool: &Tool) -> String {
    match tool.name.as_deref() {
        Some(name) if !name.trim().is_empty() => name.to_string(),
        _ => "<unnamed>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(name: Option<&str>, schema: Option<serde_json::Value>) -> Tool {
        Tool {
            r#type: Some("function".to_string()),
            name: name.map(|n| n.to_string()),
            description: Some("d".to_string()),
            input_schema: schema,
        }
    }

    fn request_with(tools: Vec<Tool>) -> CanonicalRequest {
        CanonicalRequest {
            model: "m".to_string(),
            messages: vec![],
            max_tokens: 16,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: Some(tools),
            tool_choice: None,
            extensions: Default::default(),
        }
    }

    fn names(req: &CanonicalRequest) -> Vec<String> {
        req.tools
            .as_ref()
            .map(|t| t.iter().filter_map(|t| t.name.clone()).collect())
            .unwrap_or_default()
    }

    // A well-formed CLIENT tool that is NOT in grob's catalogue must be KEPT
    // (anti-regression: validation is well-formedness, not catalogue membership).
    #[test]
    fn well_formed_custom_client_tool_is_kept() {
        let custom = tool(
            Some("my_company_internal_jira_tool"),
            Some(json!({
                "type": "object",
                "properties": { "ticket": { "type": "string" } },
                "required": ["ticket"]
            })),
        );
        let mut req = request_with(vec![custom]);
        let stripped = validate_inbound_tools(&mut req, &ToolValidationConfig::default()).unwrap();
        assert!(
            stripped.is_empty(),
            "well-formed custom tool must not be stripped"
        );
        assert_eq!(names(&req), vec!["my_company_internal_jira_tool"]);
    }

    // Malformed tool (input_schema is not an object) is stripped + reported.
    #[test]
    fn malformed_tool_is_stripped_and_reported() {
        let good = tool(Some("read_file"), Some(json!({ "type": "object" })));
        let bad = tool(Some("broken"), Some(json!("not-a-schema")));
        let nameless = tool(None, Some(json!({ "type": "object" })));
        let mut req = request_with(vec![good, bad, nameless]);

        let stripped = validate_inbound_tools(&mut req, &ToolValidationConfig::default()).unwrap();

        assert_eq!(
            names(&req),
            vec!["read_file"],
            "only the well-formed tool survives"
        );
        assert!(stripped.contains(&"broken".to_string()));
        assert!(stripped.contains(&"<unnamed>".to_string()));
    }

    // Reject mode turns a malformed tool into an error (mapped to 400 upstream),
    // leaving the request untouched.
    #[test]
    fn reject_mode_errors_on_malformed_tool() {
        let bad = tool(Some("broken"), Some(json!(42)));
        let mut req = request_with(vec![bad]);
        let cfg = ToolValidationConfig {
            enabled: true,
            reject: true,
        };
        let err = validate_inbound_tools(&mut req, &cfg).unwrap_err();
        assert!(
            err.contains("broken"),
            "error names the offending tool: {err}"
        );
        assert_eq!(
            names(&req),
            vec!["broken"],
            "reject mode leaves the request unchanged"
        );
    }

    // Disabled validation is a no-op even on malformed tools.
    #[test]
    fn disabled_is_noop() {
        let bad = tool(None, Some(json!("garbage")));
        let mut req = request_with(vec![bad]);
        let cfg = ToolValidationConfig {
            enabled: false,
            reject: false,
        };
        let stripped = validate_inbound_tools(&mut req, &cfg).unwrap();
        assert!(stripped.is_empty());
        assert_eq!(req.tools.as_ref().unwrap().len(), 1);
    }

    // Targeted JSON Schema checks: an invalid `type` keyword, a non-string
    // `required` element, and a non-object `properties` sub-schema are each
    // malformed and must be stripped.
    #[test]
    fn malformed_schemas_are_stripped() {
        let good = tool(
            Some("good"),
            Some(json!({
                "type": "object",
                "properties": { "x": { "type": "string" } },
                "required": ["x"]
            })),
        );
        let bad_type = tool(
            Some("bad_type"),
            Some(json!({ "type": "not_a_json_schema_type" })),
        );
        let bad_type_array = tool(
            Some("bad_type_array"),
            Some(json!({ "type": ["object", 42] })),
        );
        let bad_required = tool(
            Some("bad_required"),
            Some(json!({ "type": "object", "required": [42] })),
        );
        let bad_properties = tool(
            Some("bad_properties"),
            Some(json!({ "type": "object", "properties": { "x": "not-an-object" } })),
        );
        let mut req = request_with(vec![
            good,
            bad_type,
            bad_type_array,
            bad_required,
            bad_properties,
        ]);

        let stripped = validate_inbound_tools(&mut req, &ToolValidationConfig::default()).unwrap();

        assert_eq!(names(&req), vec!["good"], "only the valid schema survives");
        for n in [
            "bad_type",
            "bad_type_array",
            "bad_required",
            "bad_properties",
        ] {
            assert!(stripped.contains(&n.to_string()), "`{n}` must be stripped");
        }
    }
}
