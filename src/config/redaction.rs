//! Shared credential redaction for configuration inspection and revision hashes.

use serde_json::Value;
use zeroize::Zeroize;

/// Redacts credential fields and all custom header values without changing persistence.
pub(crate) fn redact(mut value: Value) -> Value {
    redact_in_place(&mut value, "");
    value
}

fn redact_in_place(value: &mut Value, parent: &str) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if parent == "headers" || (parent == "pool" && lower == "keys") || is_secret(&lower)
                {
                    erase(value);
                } else {
                    redact_in_place(value, &lower);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(|v| redact_in_place(v, parent)),
        Value::String(s) if s.contains("://") => {
            if let Ok(mut url) = reqwest::Url::parse(s) {
                if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
                    let _ = url.set_username("");
                    let _ = url.set_password(None);
                    url.set_query(None);
                    s.zeroize();
                    *s = url.to_string();
                }
            }
        }
        _ => {}
    }
}

fn is_secret(key: &str) -> bool {
    matches!(
        key,
        "token" | "secret" | "password" | "signing_key" | "private_key"
    ) || key.ends_with("_api_key")
        || key == "api_key"
        || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_password")
}

fn erase(value: &mut Value) {
    match value {
        Value::String(s) => {
            s.zeroize();
            s.push_str("<redacted>");
        }
        Value::Array(values) => values.iter_mut().for_each(erase),
        Value::Object(map) => map.values_mut().for_each(erase),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_credentials_are_redacted_without_hiding_policy_numbers() {
        let input = serde_json::json!({
            "auth": {"api_key":"synthetic-master", "jwt":{"hmac_secret":"synthetic-hmac"}},
            "providers":[{"api_key":"é令牌synthetic", "pool":{"keys":["synthetic-pool"]},
                "headers":{"X-Custom":"synthetic-header"}, "base_url":"https://user:synthetic-pass@example.com/v1?key=synthetic-query"}],
            "metrics":{"bearer_token":"synthetic-metrics"}, "max_tokens":123,
            "expected_config_revision":"abc"
        });
        let output = redact(input);
        assert!(!output.to_string().contains("synthetic"));
        assert_eq!(output["max_tokens"], 123);
        assert_eq!(output["expected_config_revision"], "abc");
        assert_eq!(output["providers"][0]["base_url"], "https://example.com/v1");
    }
}
