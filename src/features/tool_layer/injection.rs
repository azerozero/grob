//! Tool injection: adds missing tool definitions from the embedded catalog.

use super::catalog;
use super::config::InjectRule;
use crate::models::{CanonicalRequest, Tool};

/// Injects tools from the catalog into the request according to `rules`.
///
/// When `if_absent` is true (the default), a tool is only injected if no tool
/// with that name already exists in the request. This prevents overwriting
/// client-provided schemas.
pub fn inject_tools(rules: &[InjectRule], request: &mut CanonicalRequest) {
    for rule in rules {
        let entry = match catalog::lookup(&rule.tool) {
            Some(e) => e,
            None => {
                tracing::warn!(tool = %rule.tool, "Tool layer: inject rule references unknown catalog entry");
                continue;
            }
        };

        if rule.if_absent && tool_already_present(request, &rule.tool) {
            continue;
        }

        let tool = Tool {
            r#type: Some("function".to_string()),
            name: Some(entry.name.clone()),
            description: Some(entry.description.clone()),
            input_schema: Some(entry.parameters.clone()),
        };

        tracing::debug!(tool = %rule.tool, "Tool layer: injected tool from catalog");

        match request.tools.as_mut() {
            Some(tools) => tools.push(tool),
            None => request.tools = Some(vec![tool]),
        }
    }
}

/// Returns `true` if a tool with the given `name` is already in the request.
fn tool_already_present(request: &CanonicalRequest, name: &str) -> bool {
    request
        .tools
        .as_ref()
        .is_some_and(|tools| tools.iter().any(|t| t.name.as_deref() == Some(name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::tool_layer::tests::make_request;

    fn inject(tool: &str) -> InjectRule {
        InjectRule {
            tool: tool.to_string(),
            if_absent: true,
        }
    }

    #[test]
    fn injects_when_absent() {
        let rules = vec![inject("web_search")];
        let mut req = make_request(&["bash"]);

        inject_tools(&rules, &mut req);

        let names: Vec<_> = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|t| t.name.as_deref())
            .collect();
        assert!(names.contains(&"web_search"));
        assert!(names.contains(&"bash"));
    }

    #[test]
    fn does_not_overwrite_existing() {
        let rules = vec![inject("bash")];
        let mut req = make_request(&["bash"]);
        let original_desc = req.tools.as_ref().unwrap()[0].description.clone();

        inject_tools(&rules, &mut req);

        // Still only one bash tool, not duplicated.
        let bash_count = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter(|t| t.name.as_deref() == Some("bash"))
            .count();
        assert_eq!(bash_count, 1);
        // Description unchanged (client's original preserved).
        assert_eq!(req.tools.as_ref().unwrap()[0].description, original_desc);
    }

    #[test]
    fn injects_into_empty_tools() {
        let rules = vec![inject("grep")];
        let mut req = make_request(&[]);
        req.tools = None;

        inject_tools(&rules, &mut req);

        assert_eq!(req.tools.as_ref().unwrap().len(), 1);
        assert_eq!(req.tools.as_ref().unwrap()[0].name.as_deref(), Some("grep"));
    }
}
