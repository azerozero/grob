//! Tool name aliasing: resolves alternative names to their canonical form.

use super::config::AliasRule;
use crate::models::CanonicalRequest;

/// Rewrites tool names in `request.tools` using the alias table.
///
/// For each tool whose name matches an alias `from`, the name is replaced
/// with the canonical `to` value. Tool arguments and other fields are
/// preserved unchanged.
pub fn apply_aliases(aliases: &[AliasRule], request: &mut CanonicalRequest) {
    let tools = match request.tools.as_mut() {
        Some(t) if !t.is_empty() => t,
        _ => return,
    };

    for tool in tools.iter_mut() {
        let name = match tool.name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        if let Some(rule) = aliases.iter().find(|r| r.from == name) {
            tracing::debug!(
                from = name,
                to = %rule.to,
                "Tool layer: aliased tool name"
            );
            tool.name = Some(rule.to.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::tool_layer::tests::make_request;
    use crate::models::Tool;

    fn alias(from: &str, to: &str) -> AliasRule {
        AliasRule {
            from: from.to_string(),
            to: to.to_string(),
        }
    }

    #[test]
    fn resolves_alias() {
        let aliases = vec![alias("execute_command", "bash")];
        let mut req = make_request(&["execute_command"]);

        apply_aliases(&aliases, &mut req);

        let names: Vec<_> = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|t| t.name.as_deref())
            .collect();
        assert_eq!(names, vec!["bash"]);
    }

    #[test]
    fn preserves_tool_args() {
        let aliases = vec![alias("execute_command", "bash")];
        let schema =
            serde_json::json!({"type": "object", "properties": {"cmd": {"type": "string"}}});
        let mut req = make_request(&[]);
        req.tools = Some(vec![Tool {
            r#type: Some("function".to_string()),
            name: Some("execute_command".to_string()),
            description: Some("Run a command".to_string()),
            input_schema: Some(schema.clone()),
        }]);

        apply_aliases(&aliases, &mut req);

        let tool = &req.tools.as_ref().unwrap()[0];
        assert_eq!(tool.name.as_deref(), Some("bash"));
        assert_eq!(tool.description.as_deref(), Some("Run a command"));
        assert_eq!(tool.input_schema, Some(schema));
    }

    #[test]
    fn unknown_tool_passes_through() {
        let aliases = vec![alias("execute_command", "bash")];
        let mut req = make_request(&["some_unknown_tool"]);

        apply_aliases(&aliases, &mut req);

        let names: Vec<_> = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|t| t.name.as_deref())
            .collect();
        assert_eq!(names, vec!["some_unknown_tool"]);
    }
}
