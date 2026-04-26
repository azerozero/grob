//! Built-in MCP tool descriptors injected into the `tools/list` response.
//!
//! The `tools/list` JSON-RPC method returns the full set of tools the MCP
//! server advertises. The tool-matrix engine populates the dynamic portion;
//! this module appends the always-on grob tools (`grob_hint`, `grob_configure`,
//! `grob_autotune`, the control-plane bridges, and the wizard surface) so MCP
//! clients can discover them without a separate registry.

use crate::features::mcp::server::types::JsonRpcResponse;

/// Appends built-in tools to the `tools/list` response.
pub(super) fn inject_builtin_tools(resp: &mut JsonRpcResponse) {
    if let Some(tools) = resp.result.get_mut("tools").and_then(|v| v.as_array_mut()) {
        tools.push(serde_json::json!({
            "name": "grob_hint",
            "description": "Declare task complexity for routing heuristics (trivial/medium/complex). Stateless: consumed by the next request.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "complexity": {
                        "type": "string",
                        "enum": ["trivial", "medium", "complex"],
                        "description": "Task complexity level"
                    }
                },
                "required": ["complexity"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_configure",
            "description": "Read or update safe configuration sections (router, budget, cache, classifier). Credentials and security settings are denied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "update"]
                    },
                    "section": {
                        "type": "string",
                        "enum": ["router", "budget", "dlp", "cache", "classifier"]
                    },
                    "key": { "type": "string" },
                    "value": {}
                },
                "required": ["action", "section"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_autotune",
            "description": "Inspect or batch-apply complexity classifier weight/threshold changes. action=suggest returns current values; action=apply takes a list of {key, value} patches and persists them via the grob_configure pipeline.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["suggest", "apply"]
                    },
                    "patches": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "key": { "type": "string" },
                                "value": { "type": "number" }
                            },
                            "required": ["key", "value"]
                        }
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_keys",
            "description": "Manage virtual API keys: create, list, revoke, or rotate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["create", "list", "revoke", "rotate"],
                        "description": "Key management operation"
                    },
                    "name": {
                        "type": "string",
                        "description": "Human-readable label (required for create)"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key identifier (required for revoke/rotate)"
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_tools",
            "description": "Inspect and toggle the tool layer: list active tools, enable/disable by name, or browse the full catalog.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "enable", "disable", "catalog"],
                        "description": "Tool layer operation"
                    },
                    "tool": {
                        "type": "string",
                        "description": "Tool name (required for enable/disable)"
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_hit",
            "description": "Manage HIT (Human Intent Token) policies: list, get, set, or resolve which policy applies to a context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list_policies", "get_policy", "set_policy", "resolve"],
                        "description": "HIT policy operation"
                    },
                    "name": {
                        "type": "string",
                        "description": "Policy name (required for get_policy/set_policy)"
                    },
                    "policy": {
                        "type": "object",
                        "description": "Policy definition (required for set_policy)"
                    },
                    "context": {
                        "type": "object",
                        "description": "Request context for policy resolution (required for resolve)"
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "wizard_get_config",
            "description": "Read the current config (all known sections or just one) as JSON. No secrets are returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": ["router", "budget", "dlp", "cache"],
                        "description": "Optional section filter; omit to return all safe sections."
                    }
                },
                "required": []
            }
        }));
        tools.push(serde_json::json!({
            "name": "wizard_set_section",
            "description": "Apply one or more key/value updates to a config section and trigger hot-reload. Same safety policy as grob_configure.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": ["router", "budget", "cache"],
                        "description": "Config section to update (DLP is read-only)."
                    },
                    "values": {
                        "type": "object",
                        "description": "Map of key → new value to apply."
                    }
                },
                "required": ["section", "values"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "wizard_run_doctor",
            "description": "Runs programmatic health checks against the running grob (providers, models, storage, credentials). Returns JSON with per-check status and an overall severity.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_pledge",
            "description": "Manage pledge capability restrictions: activate a profile, clear to defaults, check status, or list available profiles.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["set", "clear", "status", "list_profiles"],
                        "description": "Pledge operation"
                    },
                    "profile": {
                        "type": "string",
                        "description": "Profile name (required for set)"
                    },
                    "source": {
                        "type": "string",
                        "description": "Optional source filter (for set)"
                    }
                },
                "required": ["action"]
            }
        }));
    }
}
