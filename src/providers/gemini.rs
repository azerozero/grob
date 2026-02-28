use super::{
    build_provider_client, AnthropicProvider, ProviderError, ProviderResponse, StreamResponse,
    Usage,
};
use crate::auth::{OAuthConfig, TokenStore};
use crate::models::{AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Google Gemini provider supporting three authentication methods:
/// 1. OAuth 2.0 (Google AI Pro/Ultra) - Uses Code Assist API
/// 2. API Key (Google AI Studio) - Uses public Gemini API
/// 3. Vertex AI (Google Cloud) - Uses Vertex AI API
pub struct GeminiProvider {
    pub api_key: Option<String>,
    pub base_url: String,
    pub models: Vec<String>,
    pub client: Client,
    pub custom_headers: HashMap<String, String>,
    // Vertex AI fields
    pub project_id: Option<String>,
    pub location: Option<String>,
    // OAuth fields
    pub oauth_provider: Option<String>,
    pub token_store: Option<TokenStore>,
    /// Per-request timeout from server config
    pub api_timeout: Duration,
}

/// Remove JSON Schema metadata fields that Gemini API doesn't support
fn clean_json_schema(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Remove JSON Schema metadata fields
            map.remove("$schema");
            map.remove("$id");
            map.remove("$ref");
            map.remove("$comment");
            map.remove("exclusiveMinimum");
            map.remove("exclusiveMaximum");
            map.remove("definitions");
            map.remove("$defs");

            // Recursively clean nested objects
            for (_, v) in map.iter_mut() {
                clean_json_schema(v);
            }
        }
        serde_json::Value::Array(arr) => {
            // Recursively clean array elements
            for item in arr.iter_mut() {
                clean_json_schema(item);
            }
        }
        _ => {}
    }
}

impl GeminiProvider {
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

    async fn get_auth_header(&self) -> Result<Option<String>, ProviderError> {
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

    /// Convert a single Anthropic content block to a Gemini part.
    fn convert_block(
        block: &ContentBlock,
        tool_id_to_name: &HashMap<String, String>,
    ) -> Option<GeminiPart> {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                Some(GeminiPart::Text { text: text.clone() })
            }
            ContentBlock::Known(KnownContentBlock::Image { source }) => {
                let (media_type, data) = (source.media_type.as_ref()?, source.data.as_ref()?);
                Some(GeminiPart::InlineData {
                    inline_data: GeminiInlineData {
                        mime_type: media_type.clone(),
                        data: data.clone(),
                    },
                })
            }
            ContentBlock::Known(KnownContentBlock::Thinking { raw }) => {
                let thinking = raw.get("thinking").and_then(|v| v.as_str())?;
                Some(GeminiPart::Text {
                    text: thinking.to_string(),
                })
            }
            ContentBlock::Known(KnownContentBlock::ToolUse { name, input, .. }) => {
                Some(GeminiPart::FunctionCall {
                    function_call: GeminiFunctionCall {
                        name: name.clone(),
                        args: input.clone(),
                    },
                })
            }
            ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            }) => {
                let fn_name = tool_id_to_name
                    .get(tool_use_id)
                    .cloned()
                    .unwrap_or_else(|| tool_use_id.clone());
                Some(GeminiPart::FunctionResponse {
                    function_response: GeminiFunctionResponse {
                        name: fn_name,
                        response: serde_json::json!({ "content": content.to_string() }),
                    },
                })
            }
            _ => None,
        }
    }

    /// Convert Anthropic tools to Gemini tool format.
    fn convert_tools(tools: &[crate::models::Tool]) -> Vec<GeminiTool> {
        let mut gemini_tools = Vec::new();
        let mut function_declarations = Vec::new();

        for tool in tools {
            match tool.name.as_deref().unwrap_or("") {
                "WebSearch" => gemini_tools.push(GeminiTool::GoogleSearch {
                    google_search: GoogleSearchTool {},
                }),
                "WebFetch" => gemini_tools.push(GeminiTool::UrlContext {
                    url_context: UrlContextTool {},
                }),
                _ => {
                    let mut parameters = tool.input_schema.clone().unwrap_or_default();
                    clean_json_schema(&mut parameters);
                    if let Some(name) = &tool.name {
                        function_declarations.push(GeminiFunctionDeclaration {
                            name: name.clone(),
                            description: tool.description.clone().unwrap_or_default(),
                            parameters,
                        });
                    }
                }
            }
        }

        if !function_declarations.is_empty() {
            gemini_tools.push(GeminiTool::FunctionDeclarations {
                function_declarations,
            });
        }
        gemini_tools
    }

    /// Convert Anthropic tool_choice to Gemini tool_config.
    fn convert_tool_config(tc: &serde_json::Value) -> Option<GeminiToolConfig> {
        let tc_type = tc.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let (mode, names) = match tc_type {
            "auto" => ("AUTO", None),
            "any" => ("ANY", None),
            "tool" => {
                let name = tc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                ("ANY", Some(vec![name.to_string()]))
            }
            _ => return None,
        };
        Some(GeminiToolConfig {
            function_calling_config: GeminiFunctionCallingConfig {
                mode: mode.to_string(),
                allowed_function_names: names,
            },
        })
    }

    /// Transform Anthropic request to Gemini format
    fn transform_request(
        &self,
        request: &AnthropicRequest,
    ) -> Result<GeminiRequest, ProviderError> {
        let system_instruction = request
            .system
            .as_ref()
            .map(|system| GeminiSystemInstruction {
                parts: vec![GeminiPart::Text {
                    text: system.to_text(),
                }],
            });

        // Build tool_use_id → name map for resolving tool_result references
        let tool_id_to_name: HashMap<String, String> = request
            .messages
            .iter()
            .flat_map(|msg| match &msg.content {
                MessageContent::Blocks(blocks) => blocks.as_slice(),
                _ => &[],
            })
            .filter_map(|block| match block {
                ContentBlock::Known(KnownContentBlock::ToolUse { id, name, .. }) => {
                    Some((id.clone(), name.clone()))
                }
                _ => None,
            })
            .collect();

        // Transform messages
        let contents: Vec<GeminiContent> = request
            .messages
            .iter()
            .filter_map(|msg| {
                let role = match msg.role.as_str() {
                    "user" => "user",
                    "assistant" => "model",
                    _ => return None,
                };
                let parts = match &msg.content {
                    MessageContent::Text(text) => vec![GeminiPart::Text { text: text.clone() }],
                    MessageContent::Blocks(blocks) => blocks
                        .iter()
                        .filter_map(|b| Self::convert_block(b, &tool_id_to_name))
                        .collect(),
                };
                if parts.is_empty() {
                    return None;
                }
                Some(GeminiContent {
                    role: role.to_string(),
                    parts,
                })
            })
            .collect();

        let tools = if self.supports_tools(&request.model) {
            request
                .tools
                .as_ref()
                .map(|tools| Self::convert_tools(tools))
        } else {
            None
        };

        Ok(GeminiRequest {
            contents,
            system_instruction,
            generation_config: Some(GeminiGenerationConfig {
                temperature: request.temperature,
                top_p: request.top_p,
                top_k: Some(40),
                max_output_tokens: Some(request.max_tokens as i32),
                stop_sequences: request.stop_sequences.clone(),
            }),
            tools,
            tool_config: request
                .tool_choice
                .as_ref()
                .and_then(Self::convert_tool_config),
        })
    }

    /// Transform Gemini response to Anthropic format
    fn transform_response(
        &self,
        response: GeminiResponse,
        model: String,
    ) -> Result<ProviderResponse, ProviderError> {
        let candidate = response
            .candidates
            .first()
            .ok_or_else(|| ProviderError::ApiError {
                status: 500,
                message: "No candidates in response".to_string(),
            })?;

        let mut has_function_call = false;
        let mut tool_call_counter = 0u32;
        let content: Vec<ContentBlock> = candidate
            .content
            .parts
            .iter()
            .filter_map(|part| match part {
                GeminiPart::Text { text } => Some(ContentBlock::text(text.clone(), None)),
                GeminiPart::FunctionCall { function_call } => {
                    has_function_call = true;
                    tool_call_counter += 1;
                    let id = format!("toolu_{:012x}", tool_call_counter);
                    Some(ContentBlock::tool_use(
                        id,
                        function_call.name.clone(),
                        function_call.args.clone(),
                    ))
                }
                _ => None, // Skip InlineData, FunctionResponse in model output
            })
            .collect();

        let stop_reason = if has_function_call {
            Some("tool_use".to_string())
        } else {
            match candidate.finish_reason.as_deref() {
                Some("STOP") => Some("end_turn".to_string()),
                Some("MAX_TOKENS") => Some("max_tokens".to_string()),
                _ => None,
            }
        };

        let usage = Usage {
            input_tokens: response
                .usage_metadata
                .as_ref()
                .and_then(|u| u.prompt_token_count)
                .unwrap_or(0) as u32,
            output_tokens: response
                .usage_metadata
                .as_ref()
                .and_then(|u| u.candidates_token_count)
                .unwrap_or(0) as u32,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        Ok(ProviderResponse {
            id: format!("gemini-{}", chrono::Utc::now().timestamp_millis()),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content,
            model,
            stop_reason,
            stop_sequence: None,
            usage,
        })
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
                if let Some(delay) = extract_retry_delay(&error_text) {
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
}

#[async_trait]
impl AnthropicProvider for GeminiProvider {
    async fn send_message(
        &self,
        request: AnthropicRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let model = request.model.clone();

        // Check if using OAuth (Code Assist API)
        if self.is_oauth() {
            // Use Code Assist API endpoint
            let gemini_request = self.transform_request(&request)?;

            // Get OAuth bearer token
            let auth_header = self.get_auth_header().await?;
            let bearer_token = auth_header.ok_or_else(|| {
                ProviderError::AuthError("OAuth configured but no token available".to_string())
            })?;

            // Get project_id from token store
            let project_id = if let (Some(oauth_provider), Some(token_store)) =
                (&self.oauth_provider, &self.token_store)
            {
                token_store
                    .get(oauth_provider)
                    .and_then(|token| token.project_id.clone())
            } else {
                None
            };

            if project_id.is_none() {
                tracing::warn!(
                    "⚠️ No project_id found in token for Gemini OAuth. Code Assist API may fail."
                );
            }

            // Generate unique user_prompt_id
            let user_prompt_id = format!("gemini-{}", chrono::Utc::now().timestamp_millis());

            // Wrap in Code Assist API format
            let code_assist_request = CodeAssistRequest {
                model: model.clone(),
                project: project_id,
                user_prompt_id: Some(user_prompt_id),
                request: CodeAssistInnerRequest {
                    contents: gemini_request.contents,
                    system_instruction: gemini_request.system_instruction,
                    generation_config: gemini_request.generation_config,
                    tools: gemini_request.tools,
                    tool_config: gemini_request.tool_config,
                    session_id: None, // Optional
                },
            };

            // Code Assist API endpoint: https://cloudcode-pa.googleapis.com/v1internal:generateContent
            let url = format!("{}:generateContent", self.base_url);

            tracing::debug!("🔐 Using OAuth Code Assist API: {}", url);

            // Debug: Log the request payload
            if let Ok(json_str) = serde_json::to_string_pretty(&code_assist_request) {
                tracing::debug!("📤 Code Assist Request:\n{}", json_str);
            }

            // Clone necessary data for the retry closure
            let client = self.client.clone();
            let custom_headers = self.custom_headers.clone();
            let bearer_token = bearer_token.clone();
            let code_assist_request = code_assist_request.clone();
            let url = url.clone();
            let api_timeout = self.api_timeout;

            // Use retry handler for 429 errors
            let response = self
                .handle_rate_limit_retry(
                    move || {
                        let mut req_builder = client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .header("Authorization", &bearer_token);

                        for (key, value) in &custom_headers {
                            req_builder = req_builder.header(key, value);
                        }

                        req_builder
                            .timeout(api_timeout)
                            .json(&code_assist_request)
                            .send()
                    },
                    3, // max_retries
                )
                .await?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());

                // Special handling for 404 errors (model not found)
                if status == 404 {
                    let model_name = &model;
                    let user_friendly_msg = if model_name.contains("gemini-3")
                        || model_name.contains("preview")
                    {
                        format!(
                            "Model '{}' is not available. This may be a preview model that requires special access. \n                            Try using gemini-2.5-pro or gemini-2.0-flash-exp instead. \n                            Original error: {}",
                            model_name, error_text
                        )
                    } else {
                        format!(
                            "Model '{}' not found. Original error: {}",
                            model_name, error_text
                        )
                    };
                    tracing::warn!("⚠️ Model not found (404): {}", user_friendly_msg);
                    return Err(ProviderError::ApiError {
                        status,
                        message: user_friendly_msg,
                    });
                }

                tracing::error!("Code Assist API error ({}): {}", status, error_text);
                return Err(ProviderError::ApiError {
                    status,
                    message: error_text,
                });
            }

            // Parse Code Assist response
            let code_assist_response: CodeAssistResponse = response.json().await?;
            self.transform_response(code_assist_response.response, model)
        } else {
            // Use public Gemini API or Vertex AI
            let gemini_request = self.transform_request(&request)?;

            // Build URL
            let url = if self.is_vertex_ai() {
                // Vertex AI endpoint (project_id & location guaranteed by is_vertex_ai())
                let project = self.project_id.as_deref().ok_or_else(|| {
                    ProviderError::ConfigError("Vertex AI requires project_id".to_string())
                })?;
                let location = self.location.as_deref().ok_or_else(|| {
                    ProviderError::ConfigError("Vertex AI requires location".to_string())
                })?;
                format!(
                    "{}/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
                    self.base_url, project, location, model
                )
            } else if let Some(ref key) = self.api_key {
                // API Key endpoint (key in query parameter)
                format!(
                    "{}/models/{}:generateContent?key={}",
                    self.base_url, model, key
                )
            } else {
                return Err(ProviderError::ConfigError(
                    "Gemini provider requires either api_key, OAuth, or Vertex AI configuration"
                        .to_string(),
                ));
            };

            // Clone necessary data for the retry closure
            let client = self.client.clone();
            let custom_headers = self.custom_headers.clone();
            let gemini_request = gemini_request.clone();
            let url = url.clone();
            let api_timeout = self.api_timeout;

            // Use retry handler for 429 errors
            let response = self
                .handle_rate_limit_retry(
                    move || {
                        let mut req_builder =
                            client.post(&url).header("Content-Type", "application/json");

                        for (key, value) in &custom_headers {
                            req_builder = req_builder.header(key, value);
                        }

                        req_builder
                            .timeout(api_timeout)
                            .json(&gemini_request)
                            .send()
                    },
                    3, // max_retries
                )
                .await?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::error!("Gemini API error ({}): {}", status, error_text);
                return Err(ProviderError::ApiError {
                    status,
                    message: error_text,
                });
            }

            let gemini_response: GeminiResponse = response.json().await?;
            self.transform_response(gemini_response, model)
        }
    }

    async fn send_message_stream(
        &self,
        request: AnthropicRequest,
    ) -> Result<StreamResponse, ProviderError> {
        use futures::TryStreamExt;

        let model = request.model.clone();

        // Check if using OAuth (Code Assist API)
        if self.is_oauth() {
            // Use Code Assist API streaming endpoint
            let gemini_request = self.transform_request(&request)?;

            // Get OAuth bearer token
            let auth_header = self.get_auth_header().await?;
            let bearer_token = auth_header.ok_or_else(|| {
                ProviderError::AuthError("OAuth configured but no token available".to_string())
            })?;

            // Get project_id from token store
            let project_id = if let (Some(oauth_provider), Some(token_store)) =
                (&self.oauth_provider, &self.token_store)
            {
                token_store
                    .get(oauth_provider)
                    .and_then(|token| token.project_id.clone())
            } else {
                None
            };

            if project_id.is_none() {
                tracing::warn!(
                    "⚠️ No project_id found in token for Gemini OAuth. Code Assist API may fail."
                );
            }

            // Generate unique user_prompt_id
            let user_prompt_id = format!("gemini-{}", chrono::Utc::now().timestamp_millis());

            // Wrap in Code Assist API format
            let code_assist_request = CodeAssistRequest {
                model: model.clone(),
                project: project_id,
                user_prompt_id: Some(user_prompt_id),
                request: CodeAssistInnerRequest {
                    contents: gemini_request.contents,
                    system_instruction: gemini_request.system_instruction,
                    generation_config: gemini_request.generation_config,
                    tools: gemini_request.tools,
                    tool_config: gemini_request.tool_config,
                    session_id: None, // Optional
                },
            };

            // Code Assist API streaming endpoint with alt=sse parameter
            let url = format!("{}:streamGenerateContent?alt=sse", self.base_url);

            tracing::debug!("🔐 Using OAuth Code Assist API (streaming): {}", url);

            // Build request
            let mut req_builder = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", bearer_token);

            for (key, value) in &self.custom_headers {
                req_builder = req_builder.header(key, value);
            }

            let response = req_builder
                .timeout(self.api_timeout)
                .json(&code_assist_request)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::error!(
                    "Code Assist API streaming error ({}): {}",
                    status,
                    error_text
                );
                return Err(ProviderError::ApiError {
                    status,
                    message: error_text,
                });
            }

            // Return the streaming response
            // The Gemini API returns SSE format, just pass through the stream
            let stream = response.bytes_stream().map_err(ProviderError::HttpError);
            Ok(StreamResponse {
                stream: Box::pin(stream),
                headers: HashMap::new(), // Gemini doesn't have rate limit headers to forward
            })
        } else {
            // Use public Gemini API or Vertex AI streaming
            let gemini_request = self.transform_request(&request)?;

            // Build URL
            let url = if self.is_vertex_ai() {
                // Vertex AI streaming endpoint
                let project = self.project_id.as_deref().ok_or_else(|| {
                    ProviderError::ConfigError("Vertex AI requires project_id".to_string())
                })?;
                let location = self.location.as_deref().ok_or_else(|| {
                    ProviderError::ConfigError("Vertex AI requires location".to_string())
                })?;
                format!(
                    "{}/projects/{}/locations/{}/publishers/google/models/{}:streamGenerateContent?alt=sse",
                    self.base_url, project, location, model
                )
            } else if let Some(ref key) = self.api_key {
                // API Key streaming endpoint
                format!(
                    "{}/models/{}:streamGenerateContent?key={}&alt=sse",
                    self.base_url, model, key
                )
            } else {
                return Err(ProviderError::ConfigError(
                    "Gemini provider requires either api_key, OAuth, or Vertex AI configuration"
                        .to_string(),
                ));
            };

            tracing::debug!("📡 Using Gemini API (streaming): {}", url);

            // Build request
            let mut req_builder = self
                .client
                .post(&url)
                .header("Content-Type", "application/json");

            for (key, value) in &self.custom_headers {
                req_builder = req_builder.header(key, value);
            }

            let response = req_builder
                .timeout(self.api_timeout)
                .json(&gemini_request)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::error!("Gemini API streaming error ({}): {}", status, error_text);
                return Err(ProviderError::ApiError {
                    status,
                    message: error_text,
                });
            }

            // Return the streaming response
            let stream = response.bytes_stream().map_err(ProviderError::HttpError);
            Ok(StreamResponse {
                stream: Box::pin(stream),
                headers: HashMap::new(), // Gemini doesn't have rate limit headers to forward
            })
        }
    }

    async fn count_tokens(
        &self,
        request: crate::models::CountTokensRequest,
    ) -> Result<crate::models::CountTokensResponse, ProviderError> {
        Ok(super::helpers::estimate_token_count(&request))
    }

    fn supports_model(&self, model: &str) -> bool {
        self.models.iter().any(|m| m.eq_ignore_ascii_case(model))
    }

    fn base_url(&self) -> Option<&str> {
        Some(&self.base_url)
    }
}

// Gemini API structures

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiSystemInstruction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<GeminiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_config: Option<GeminiToolConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum GeminiPart {
    Text {
        text: String,
    },
    InlineData {
        inline_data: GeminiInlineData,
    },
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: GeminiFunctionCall,
    },
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: GeminiFunctionResponse,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeminiFunctionCall {
    name: String,
    args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeminiFunctionResponse {
    name: String,
    response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiInlineData {
    mime_type: String,
    data: String,
}

#[derive(Debug, Clone, Serialize)]
struct GeminiSystemInstruction {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

/// Gemini Tool supports multiple tool types via protobuf oneof
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum GeminiTool {
    /// Function calling tools
    FunctionDeclarations {
        #[serde(rename = "functionDeclarations")]
        function_declarations: Vec<GeminiFunctionDeclaration>,
    },
    /// Google Search tool
    GoogleSearch {
        #[serde(rename = "googleSearch")]
        google_search: GoogleSearchTool,
    },
    /// URL Context/Fetch tool
    UrlContext {
        #[serde(rename = "urlContext")]
        url_context: UrlContextTool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiToolConfig {
    function_calling_config: GeminiFunctionCallingConfig,
}

#[derive(Debug, Clone, Serialize)]
struct GeminiFunctionCallingConfig {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_function_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct GeminiFunctionDeclaration {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct GoogleSearchTool {}

#[derive(Debug, Clone, Serialize)]
struct UrlContextTool {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiCandidate {
    content: GeminiContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct GeminiUsageMetadata {
    prompt_token_count: Option<i32>,
    candidates_token_count: Option<i32>,
    total_token_count: Option<i32>,
}

// Code Assist API structures (for OAuth)

#[derive(Debug, Clone, Serialize)]
struct CodeAssistRequest {
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_prompt_id: Option<String>,
    request: CodeAssistInnerRequest,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CodeAssistInnerRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiSystemInstruction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<GeminiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_config: Option<GeminiToolConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CodeAssistResponse {
    response: GeminiResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
}

// Error response structures for rate limiting

#[derive(Debug, Deserialize)]
struct GeminiErrorResponse {
    error: GeminiError,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GeminiError {
    code: u16,
    message: String,
    status: String,
    #[serde(default)]
    details: Vec<GeminiErrorDetail>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "@type")]
enum GeminiErrorDetail {
    #[serde(rename = "type.googleapis.com/google.rpc.RetryInfo")]
    RetryInfo {
        #[serde(rename = "retryDelay")]
        retry_delay: String,
    },
    #[serde(rename = "type.googleapis.com/google.rpc.ErrorInfo")]
    ErrorInfo {
        reason: String,
        domain: String,
        #[serde(default)]
        metadata: HashMap<String, String>,
    },
    #[serde(other)]
    Unknown,
}

/// Parse retry delay from Google's duration format (e.g., "3.020317815s", "60s", "900ms")
fn parse_retry_delay(duration: &str) -> Option<std::time::Duration> {
    if let Some(ms_str) = duration.strip_suffix("ms") {
        ms_str
            .parse::<f64>()
            .ok()
            .map(|ms| std::time::Duration::from_millis(ms as u64))
    } else if let Some(s_str) = duration.strip_suffix("s") {
        s_str
            .parse::<f64>()
            .ok()
            .map(std::time::Duration::from_secs_f64)
    } else {
        None
    }
}

/// Extract retry delay from 429 error response
fn extract_retry_delay(error_text: &str) -> Option<std::time::Duration> {
    // Try to parse as JSON error response
    if let Ok(error_response) = serde_json::from_str::<GeminiErrorResponse>(error_text) {
        // Look for RetryInfo in details
        for detail in &error_response.error.details {
            if let GeminiErrorDetail::RetryInfo { retry_delay } = detail {
                if let Some(delay) = parse_retry_delay(retry_delay) {
                    tracing::info!("⏱️  Rate limit hit, will retry after {:?}", delay);
                    return Some(delay);
                }
            }
        }

        // Check for RATE_LIMIT_EXCEEDED in ErrorInfo
        for detail in &error_response.error.details {
            if let GeminiErrorDetail::ErrorInfo {
                reason,
                domain,
                metadata,
            } = detail
            {
                if reason == "RATE_LIMIT_EXCEEDED" && domain.contains("cloudcode-pa.googleapis.com")
                {
                    // Try to get quotaResetDelay from metadata
                    if let Some(quota_reset) = metadata.get("quotaResetDelay") {
                        if let Some(delay) = parse_retry_delay(quota_reset) {
                            tracing::info!(
                                "⏱️  Rate limit hit (RATE_LIMIT_EXCEEDED), will retry after {:?}",
                                delay
                            );
                            return Some(delay);
                        }
                    }
                    // Default to 10 seconds if no delay specified
                    tracing::info!(
                        "⏱️  Rate limit hit (RATE_LIMIT_EXCEEDED), will retry after 10s"
                    );
                    return Some(std::time::Duration::from_secs(10));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tool;

    #[test]
    fn test_parse_retry_delay_seconds() {
        let d = parse_retry_delay("3.5s").unwrap();
        assert_eq!(d, Duration::from_millis(3500));
    }

    #[test]
    fn test_parse_retry_delay_milliseconds() {
        let d = parse_retry_delay("900ms").unwrap();
        assert_eq!(d, Duration::from_millis(900));
    }

    #[test]
    fn test_parse_retry_delay_integer_seconds() {
        let d = parse_retry_delay("60s").unwrap();
        assert_eq!(d, Duration::from_secs(60));
    }

    #[test]
    fn test_parse_retry_delay_invalid() {
        assert!(parse_retry_delay("invalid").is_none());
        assert!(parse_retry_delay("").is_none());
    }

    #[test]
    fn test_convert_block_text() {
        let block = ContentBlock::text("hello".to_string(), None);
        let map = HashMap::new();
        let part = GeminiProvider::convert_block(&block, &map).unwrap();
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
        let part = GeminiProvider::convert_block(&block, &map).unwrap();
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
        let gemini_tools = GeminiProvider::convert_tools(&tools);
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
        let gemini_tools = GeminiProvider::convert_tools(&tools);
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
        let config = GeminiProvider::convert_tool_config(&tc).unwrap();
        assert_eq!(config.function_calling_config.mode, "AUTO");
        assert!(config
            .function_calling_config
            .allowed_function_names
            .is_none());
    }

    #[test]
    fn test_convert_tool_config_specific_tool() {
        let tc = serde_json::json!({"type": "tool", "name": "my_func"});
        let config = GeminiProvider::convert_tool_config(&tc).unwrap();
        assert_eq!(config.function_calling_config.mode, "ANY");
        assert_eq!(
            config.function_calling_config.allowed_function_names,
            Some(vec!["my_func".to_string()])
        );
    }

    #[test]
    fn test_convert_tool_config_unknown() {
        let tc = serde_json::json!({"type": "unknown"});
        assert!(GeminiProvider::convert_tool_config(&tc).is_none());
    }
}
