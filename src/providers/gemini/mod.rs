//! Google Gemini provider implementation (API key, Vertex AI, and OAuth/CodeAssist).

mod retry;
mod transform;
pub(crate) mod types;

use super::{build_provider_client, LlmProvider, ProviderError, ProviderResponse, StreamResponse};
use crate::auth::{OAuthConfig, TokenStore};
use crate::models::CanonicalRequest;
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use types::*;

// NOTE: GeminiProvider does not use ProviderBase because it has a fundamentally
// different auth model (Option<api_key>, HashMap headers, Vertex AI fields).

/// Google Gemini provider supporting three authentication methods:
/// 1. OAuth 2.0 (Google AI Pro/Ultra) - Uses Code Assist API
/// 2. API Key (Google AI Studio) - Uses public Gemini API
/// 3. Vertex AI (Google Cloud) - Uses Vertex AI API
pub struct GeminiProvider {
    api_key: Option<String>,
    base_url: String,
    models: Vec<String>,
    client: Client,
    custom_headers: HashMap<String, String>,
    // Vertex AI fields
    project_id: Option<String>,
    location: Option<String>,
    // OAuth fields
    oauth_provider: Option<String>,
    token_store: Option<TokenStore>,
    /// Per-request timeout from server config
    api_timeout: Duration,
    pass_through: bool,
}

/// Max retries for Gemini 429 rate-limit errors (higher than default because
/// Gemini's retry-after headers give precise delays).
const GEMINI_RATE_LIMIT_RETRIES: u32 = 3;

/// All data needed to send a request to the Gemini API.
struct PreparedRequest {
    url: String,
    body: serde_json::Value,
    auth_header: Option<String>,
    is_oauth: bool,
}

impl GeminiProvider {
    /// Creates a Gemini provider with custom headers and optional Vertex AI fields.
    pub fn new(
        params: super::ProviderParams,
        custom_headers: HashMap<String, String>,
        project_id: Option<String>,
        location: Option<String>,
    ) -> Self {
        let api_key = if params.api_key.is_empty() {
            None
        } else {
            Some(params.api_key)
        };

        let base_url = params.base_url.unwrap_or_else(|| {
            if params.oauth_provider.is_some() {
                "https://cloudcode-pa.googleapis.com/v1internal".to_string()
            } else if project_id.is_some() && location.is_some() {
                format!(
                    "https://{}-aiplatform.googleapis.com/v1",
                    location.as_deref().unwrap_or("us-central1")
                )
            } else {
                "https://generativelanguage.googleapis.com/v1beta".to_string()
            }
        });

        Self {
            api_key,
            base_url,
            models: params.models,
            client: build_provider_client(params.connect_timeout),
            custom_headers,
            project_id,
            location,
            oauth_provider: params.oauth_provider,
            token_store: params.token_store,
            api_timeout: params.api_timeout,
            pass_through: params.pass_through,
        }
    }

    /// Check if this provider uses OAuth (Code Assist API)
    fn is_oauth(&self) -> bool {
        self.oauth_provider.is_some() && self.token_store.is_some()
    }

    /// Check if this provider uses Vertex AI
    fn is_vertex_ai(&self) -> bool {
        self.project_id.is_some() && self.location.is_some()
    }

    /// Check if the model supports tools (function calling)
    /// lite/flash-lite models don't support tools
    fn supports_tools(&self, model: &str) -> bool {
        !model.contains("lite") && !model.contains("flash-lite")
    }

    async fn auth_header(&self) -> Result<Option<String>, ProviderError> {
        if self.oauth_provider.is_some() {
            let token = super::auth::resolve_access_token(
                self.oauth_provider.as_deref(),
                self.token_store.as_ref(),
                OAuthConfig::gemini,
                "",
            )
            .await?;
            Ok(Some(format!("Bearer {}", token)))
        } else {
            Ok(None)
        }
    }

    /// Handle 429 rate limit errors with automatic retry
    async fn handle_rate_limit_retry<F, Fut>(
        &self,
        mut request_fn: F,
        max_retries: u32,
    ) -> Result<reqwest::Response, ProviderError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let mut retries = 0;

        loop {
            let response = request_fn().await?;

            // Check if it's a 429 error
            if response.status().as_u16() == 429 {
                let error_text = response.text().await.unwrap_or_default();

                // Try to extract retry delay
                if let Some(delay) = retry::extract_retry_delay(&error_text) {
                    if retries < max_retries {
                        retries += 1;
                        tracing::warn!(
                            "⏱️  Rate limit hit (attempt {}/{}), retrying after {:?}...",
                            retries,
                            max_retries,
                            delay
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    } else {
                        tracing::error!(
                            "❌ Rate limit retries exhausted after {} attempts",
                            max_retries
                        );
                        return Err(ProviderError::ApiError {
                            status: 429,
                            message: error_text,
                        });
                    }
                } else {
                    // No retry delay found, return error
                    return Err(ProviderError::ApiError {
                        status: 429,
                        message: error_text,
                    });
                }
            }

            return Ok(response);
        }
    }

    /// Prepare request data shared between streaming and non-streaming paths.
    async fn prepare_request(
        &self,
        request: &CanonicalRequest,
        streaming: bool,
    ) -> Result<PreparedRequest, ProviderError> {
        let supports_tools = self.supports_tools(&request.model);
        let gemini_request = transform::transform_request(request, supports_tools)?;

        if self.is_oauth() {
            self.prepare_oauth_request(request, gemini_request, streaming)
                .await
        } else if self.is_vertex_ai() {
            self.prepare_vertex_request(request, gemini_request, streaming)
        } else {
            self.prepare_apikey_request(request, gemini_request, streaming)
        }
    }

    /// Build a Code Assist API request for OAuth-authenticated access.
    async fn prepare_oauth_request(
        &self,
        request: &CanonicalRequest,
        gemini_request: GeminiRequest,
        streaming: bool,
    ) -> Result<PreparedRequest, ProviderError> {
        let bearer_token = self.auth_header().await?.ok_or_else(|| {
            ProviderError::AuthError("OAuth configured but no token available".to_string())
        })?;

        let project_id = self
            .oauth_provider
            .as_ref()
            .zip(self.token_store.as_ref())
            .and_then(|(prov, store)| store.get(prov).and_then(|t| t.project_id.clone()));

        if project_id.is_none() {
            tracing::warn!(
                "⚠️ No project_id found in token for Gemini OAuth. Code Assist API may fail."
            );
        }

        let code_assist_request = CodeAssistRequest {
            model: request.model.clone(),
            project: project_id,
            user_prompt_id: Some(format!("gemini-{}", chrono::Utc::now().timestamp_millis())),
            request: CodeAssistInnerRequest {
                contents: gemini_request.contents,
                system_instruction: gemini_request.system_instruction,
                generation_config: gemini_request.generation_config,
                tools: gemini_request.tools,
                tool_config: gemini_request.tool_config,
                session_id: None,
            },
        };

        let suffix = if streaming {
            ":streamGenerateContent?alt=sse"
        } else {
            ":generateContent"
        };
        let url = format!("{}{}", self.base_url, suffix);

        tracing::debug!(
            "🔐 Using OAuth Code Assist API{}: {}",
            if streaming { " (streaming)" } else { "" },
            url
        );

        if tracing::event_enabled!(tracing::Level::DEBUG) {
            if let Ok(json_str) = serde_json::to_string_pretty(&code_assist_request) {
                tracing::debug!("📤 Code Assist Request:\n{}", json_str);
            }
        }

        let body = serde_json::to_value(&code_assist_request).map_err(|e| {
            ProviderError::ConfigError(format!("Failed to serialize request: {}", e))
        })?;

        Ok(PreparedRequest {
            url,
            body,
            auth_header: Some(bearer_token),
            is_oauth: true,
        })
    }

    /// Build a Vertex AI request (project_id + location based URL).
    fn prepare_vertex_request(
        &self,
        request: &CanonicalRequest,
        gemini_request: GeminiRequest,
        streaming: bool,
    ) -> Result<PreparedRequest, ProviderError> {
        let project = self.project_id.as_deref().ok_or_else(|| {
            ProviderError::ConfigError("Vertex AI requires project_id".to_string())
        })?;
        let location = self
            .location
            .as_deref()
            .ok_or_else(|| ProviderError::ConfigError("Vertex AI requires location".to_string()))?;

        let (action, alt_sse) = Self::url_parts(streaming);
        let url = format!(
            "{}/projects/{}/locations/{}/publishers/google/models/{}:{}{}",
            self.base_url, project, location, request.model, action, alt_sse
        );

        if streaming {
            tracing::debug!("📡 Using Gemini Vertex AI (streaming): {}", url);
        }

        Self::serialize_gemini_body(url, gemini_request)
    }

    /// Build a public Gemini API request (API key based URL).
    fn prepare_apikey_request(
        &self,
        request: &CanonicalRequest,
        gemini_request: GeminiRequest,
        streaming: bool,
    ) -> Result<PreparedRequest, ProviderError> {
        let key = self.api_key.as_ref().ok_or_else(|| {
            ProviderError::ConfigError(
                "Gemini provider requires either api_key, OAuth, or Vertex AI configuration"
                    .to_string(),
            )
        })?;

        let (action, alt_sse) = Self::url_parts(streaming);
        let sep = if streaming { "&" } else { "" };
        let url = format!(
            "{}/models/{}:{}?key={}{}{}",
            self.base_url,
            request.model,
            action,
            key,
            sep,
            alt_sse.trim_start_matches('?')
        );

        if streaming {
            tracing::debug!("📡 Using Gemini API (streaming): {}", url);
        }

        Self::serialize_gemini_body(url, gemini_request)
    }

    /// URL action and SSE suffix for streaming vs non-streaming.
    fn url_parts(streaming: bool) -> (&'static str, &'static str) {
        if streaming {
            ("streamGenerateContent", "?alt=sse")
        } else {
            ("generateContent", "")
        }
    }

    /// Serialize a GeminiRequest body into a PreparedRequest (non-OAuth path).
    fn serialize_gemini_body(
        url: String,
        gemini_request: GeminiRequest,
    ) -> Result<PreparedRequest, ProviderError> {
        let body = serde_json::to_value(&gemini_request).map_err(|e| {
            ProviderError::ConfigError(format!("Failed to serialize request: {}", e))
        })?;
        Ok(PreparedRequest {
            url,
            body,
            auth_header: None,
            is_oauth: false,
        })
    }

    /// Build an HTTP request from prepared data (used for non-retry paths).
    fn build_http_request(&self, prep: &PreparedRequest) -> reqwest::RequestBuilder {
        let mut req_builder = self
            .client
            .post(&prep.url)
            .header("Content-Type", "application/json");

        if let Some(ref auth) = prep.auth_header {
            req_builder = req_builder.header("Authorization", auth);
        }

        for (key, value) in &self.custom_headers {
            req_builder = req_builder.header(key, value);
        }

        req_builder.timeout(self.api_timeout).json(&prep.body)
    }

    /// Checks response status and returns a structured [`ProviderError`] on failure.
    async fn check_response(
        response: reqwest::Response,
        model: &str,
        is_oauth: bool,
    ) -> Result<reqwest::Response, ProviderError> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Gemini: failed to read error body".to_string());
        Err(Self::classify_error(status, &error_text, model, is_oauth))
    }

    /// Classifies an API error with model-not-found handling.
    fn classify_error(status: u16, error_text: &str, model: &str, is_oauth: bool) -> ProviderError {
        if status == 404 {
            let user_friendly_msg = if model.contains("gemini-3") || model.contains("preview") {
                format!(
                    "Model '{}' is not available. This may be a preview model that requires \
                     special access. Try using gemini-2.5-pro or gemini-2.0-flash-exp instead. \
                     Original error: {}",
                    model, error_text
                )
            } else {
                format!(
                    "Model '{}' not found. Original error: {}",
                    model, error_text
                )
            };
            tracing::warn!("⚠️ Model not found (404): {}", user_friendly_msg);
            return ProviderError::ApiError {
                status,
                message: user_friendly_msg,
            };
        }

        let label = if is_oauth {
            "Code Assist API"
        } else {
            "Gemini API"
        };
        tracing::error!("{} error ({}): {}", label, status, error_text);
        ProviderError::ApiError {
            status,
            message: error_text.to_string(),
        }
    }
}

#[async_trait]
impl LlmProvider for GeminiProvider {
    async fn send_message(
        &self,
        request: CanonicalRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let model = request.model.clone();
        let prep = self.prepare_request(&request, false).await?;
        let is_oauth = prep.is_oauth;

        // Clone data for the retry closure
        let client = self.client.clone();
        let custom_headers = self.custom_headers.clone();
        let auth_header = prep.auth_header;
        let body = prep.body;
        let url = prep.url;
        let api_timeout = self.api_timeout;

        let response = self
            .handle_rate_limit_retry(
                move || {
                    let mut req_builder =
                        client.post(&url).header("Content-Type", "application/json");

                    if let Some(ref auth) = auth_header {
                        req_builder = req_builder.header("Authorization", auth);
                    }

                    for (key, value) in &custom_headers {
                        req_builder = req_builder.header(key, value);
                    }

                    req_builder.timeout(api_timeout).json(&body).send()
                },
                GEMINI_RATE_LIMIT_RETRIES,
            )
            .await?;

        let response = Self::check_response(response, &model, is_oauth).await?;

        if is_oauth {
            let code_assist_response: CodeAssistResponse = response.json().await?;
            transform::transform_response(code_assist_response.response, model)
        } else {
            let gemini_response: GeminiResponse = response.json().await?;
            transform::transform_response(gemini_response, model)
        }
    }

    async fn send_message_stream(
        &self,
        request: CanonicalRequest,
    ) -> Result<StreamResponse, ProviderError> {
        use futures::TryStreamExt;

        let model = request.model.clone();
        let prep = self.prepare_request(&request, true).await?;
        let is_oauth = prep.is_oauth;

        let response = self.build_http_request(&prep).send().await?;

        let response = Self::check_response(response, &model, is_oauth).await?;

        let stream = response.bytes_stream().map_err(ProviderError::HttpError);
        Ok(StreamResponse {
            stream: Box::pin(stream),
            headers: HashMap::new(),
        })
    }

    async fn count_tokens(
        &self,
        request: crate::models::CountTokensRequest,
    ) -> Result<crate::models::CountTokensResponse, ProviderError> {
        Ok(super::helpers::estimate_token_count(&request))
    }

    fn supports_model(&self, model: &str) -> bool {
        self.pass_through || self.models.iter().any(|m| m.eq_ignore_ascii_case(model))
    }

    fn base_url(&self) -> Option<&str> {
        Some(&self.base_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ContentBlock, Tool};

    #[test]
    fn test_parse_retry_delay_seconds() {
        let d = retry::parse_retry_delay("3.5s").unwrap();
        assert_eq!(d, Duration::from_millis(3500));
    }

    #[test]
    fn test_parse_retry_delay_milliseconds() {
        let d = retry::parse_retry_delay("900ms").unwrap();
        assert_eq!(d, Duration::from_millis(900));
    }

    #[test]
    fn test_parse_retry_delay_integer_seconds() {
        let d = retry::parse_retry_delay("60s").unwrap();
        assert_eq!(d, Duration::from_secs(60));
    }

    #[test]
    fn test_parse_retry_delay_invalid() {
        assert!(retry::parse_retry_delay("invalid").is_none());
        assert!(retry::parse_retry_delay("").is_none());
    }

    #[test]
    fn test_convert_block_text() {
        let block = ContentBlock::text("hello".to_string(), None);
        let map = HashMap::new();
        let part = transform::convert_block(&block, &map).unwrap();
        match part {
            GeminiPart::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("Expected Text part"),
        }
    }

    #[test]
    fn test_convert_block_tool_use() {
        let block = ContentBlock::tool_use(
            "id-1".to_string(),
            "my_tool".to_string(),
            serde_json::json!({"key": "value"}),
        );
        let map = HashMap::new();
        let part = transform::convert_block(&block, &map).unwrap();
        match part {
            GeminiPart::FunctionCall { function_call } => {
                assert_eq!(function_call.name, "my_tool");
                assert_eq!(function_call.args["key"], "value");
            }
            _ => panic!("Expected FunctionCall part"),
        }
    }

    #[test]
    fn test_convert_tools_websearch() {
        let tools = vec![Tool {
            r#type: None,
            name: Some("WebSearch".to_string()),
            description: None,
            input_schema: None,
        }];
        let gemini_tools = transform::convert_tools(&tools);
        assert_eq!(gemini_tools.len(), 1);
        assert!(matches!(gemini_tools[0], GeminiTool::GoogleSearch { .. }));
    }

    #[test]
    fn test_convert_tools_function() {
        let tools = vec![Tool {
            r#type: None,
            name: Some("get_weather".to_string()),
            description: Some("Get weather data".to_string()),
            input_schema: Some(serde_json::json!({"type": "object"})),
        }];
        let gemini_tools = transform::convert_tools(&tools);
        assert_eq!(gemini_tools.len(), 1);
        match &gemini_tools[0] {
            GeminiTool::FunctionDeclarations {
                function_declarations,
            } => {
                assert_eq!(function_declarations.len(), 1);
                assert_eq!(function_declarations[0].name, "get_weather");
            }
            _ => panic!("Expected FunctionDeclarations"),
        }
    }

    #[test]
    fn test_convert_tool_config_auto() {
        let tc = serde_json::json!({"type": "auto"});
        let config = transform::convert_tool_config(&tc).unwrap();
        assert_eq!(config.function_calling_config.mode, "AUTO");
        assert!(config
            .function_calling_config
            .allowed_function_names
            .is_none());
    }

    #[test]
    fn test_convert_tool_config_specific_tool() {
        let tc = serde_json::json!({"type": "tool", "name": "my_func"});
        let config = transform::convert_tool_config(&tc).unwrap();
        assert_eq!(config.function_calling_config.mode, "ANY");
        assert_eq!(
            config.function_calling_config.allowed_function_names,
            Some(vec!["my_func".to_string()])
        );
    }

    #[test]
    fn test_convert_tool_config_unknown() {
        let tc = serde_json::json!({"type": "unknown"});
        assert!(transform::convert_tool_config(&tc).is_none());
    }
}
