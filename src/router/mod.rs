//! Request routing engine with regex-based prompt rules and task-type classification.

/// Provider type inference from model name prefixes.
pub mod inference;
/// Message content extraction for routing decisions.
mod message;
/// Regex compilation and capture-group utilities.
mod rules;

use crate::cli::AppConfig;
use crate::models::{CanonicalRequest, RouteDecision, RouteType};
use anyhow::Result;
use regex::Regex;
use tracing::{debug, info};

// Re-export memchr for SIMD-accelerated byte search in pre-filters.
use memchr::memchr2;

/// Compiled prompt rule with pre-compiled regex
#[derive(Clone)]
pub struct CompiledPromptRule {
    /// Pre-compiled regex pattern for matching user prompts.
    pub regex: Regex,
    /// Target model name (may contain capture-group references).
    pub model: String,
    /// Whether to strip the matched text from the prompt.
    pub strip_match: bool,
    /// True if model contains capture group references ($1, $name, etc.)
    pub is_dynamic: bool,
}

/// Optimized model-name matcher.
///
/// Detects simple `^literal` prefix patterns at construction time and uses
/// `str::starts_with` (~2 ns) instead of a full regex match (~30 ns).
#[derive(Clone)]
enum AutoMapper {
    /// Anchored literal prefix, matched via `starts_with`.
    Prefix(String),
    /// General regex pattern.
    Regex(Regex),
}

impl AutoMapper {
    /// Builds a fast `Prefix` matcher for `^literal` patterns; falls back to `Regex`.
    fn new(pattern: &str) -> Option<Self> {
        if let Some(literal) = pattern.strip_prefix('^') {
            if !literal.is_empty()
                && literal.bytes().all(|b| {
                    !matches!(
                        b,
                        b'.' | b'*'
                            | b'+'
                            | b'?'
                            | b'('
                            | b')'
                            | b'['
                            | b']'
                            | b'{'
                            | b'}'
                            | b'|'
                            | b'\\'
                            | b'$'
                            | b'^'
                    )
                })
            {
                return Some(AutoMapper::Prefix(literal.to_string()));
            }
        }
        Regex::new(pattern).ok().map(AutoMapper::Regex)
    }

    #[inline]
    fn is_match(&self, text: &str) -> bool {
        match self {
            AutoMapper::Prefix(p) => text.starts_with(p.as_str()),
            AutoMapper::Regex(r) => r.is_match(text),
        }
    }
}

/// Extracts a pre-filter byte from a regex pattern's trailing required literal.
///
/// Returns the first byte (lowercased) of the last alphabetic run (≥ 3 chars)
/// at the end of the pattern. Only extracts when the literal is certainly
/// required (no alternation, no quantifiers after the literal).
///
/// For `(?i)claude.*haiku` → `Some(b'h')`.
fn extract_trailing_literal_byte(pattern: &str) -> Option<u8> {
    // Alternation makes individual literals optional — bail.
    if pattern.contains('|') {
        return None;
    }

    let bytes = pattern.as_bytes();
    // Saute les ancres '$' de fin via `rposition` plutot qu'un decrement
    // d'index mutable : cargo-mutants transforme `end -= 1` en `end /= 1`,
    // ce qui cree une boucle infinie non tuable par test (timeout systematique).
    // L'expression iterateur n'expose aucun decrement mutable a muter.
    let end = bytes
        .iter()
        .rposition(|&b| b != b'$')
        .map_or(0, |p| p + 1);
    if end == 0 {
        return None;
    }
    // Le caractere avant toute ancre doit etre alphabetique (pas de quantificateur).
    if !bytes[end - 1].is_ascii_alphabetic() {
        return None;
    }
    // Remonte la sequence alphabetique finale, encore via `rposition` pour
    // eviter tout decrement mutable susceptible de devenir une boucle infinie
    // sous mutation cargo-mutants.
    let i = bytes[..end]
        .iter()
        .rposition(|b| !b.is_ascii_alphabetic())
        .map_or(0, |p| p + 1);
    if end - i >= 3 {
        Some(bytes[i].to_ascii_lowercase())
    } else {
        None
    }
}

/// Router for intelligently selecting models based on request characteristics
#[derive(Clone)]
pub struct Router {
    config: AppConfig,
    auto_mapper: Option<AutoMapper>,
    background_regex: Option<Regex>,
    /// Both cases (lower, upper) of the trailing required literal's first byte.
    /// Enables SIMD-accelerated `memchr2` rejection before running the full regex.
    background_prefilter_bytes: Option<(u8, u8)>,
    prompt_rules: Vec<CompiledPromptRule>,
}

impl Router {
    /// Create a new router with configuration
    pub fn new(config: AppConfig) -> Self {
        let auto_mapper = {
            let pattern = config
                .router
                .auto_map_regex
                .as_deref()
                .unwrap_or("^claude-");
            AutoMapper::new(pattern).or_else(|| {
                tracing::warn!(
                    "Invalid auto_map_regex '{}', falling back to default",
                    pattern
                );
                AutoMapper::new("^claude-")
            })
        };

        let bg_pattern = config
            .router
            .background_regex
            .as_deref()
            .unwrap_or("(?i)claude.*haiku");
        let background_prefilter_bytes =
            extract_trailing_literal_byte(bg_pattern).map(|lo| (lo, lo.to_ascii_uppercase()));
        let background_regex = rules::compile_regex_with_fallback(
            config.router.background_regex.as_deref(),
            r"(?i)claude.*haiku",
            "background_regex",
        );

        // Compile prompt rules
        let prompt_rules: Vec<CompiledPromptRule> = config
            .router
            .prompt_rules
            .iter()
            .filter_map(|rule| match Regex::new(&rule.pattern) {
                Ok(regex) => {
                    let is_dynamic = rules::contains_capture_reference(&rule.model);
                    Some(CompiledPromptRule {
                        regex,
                        model: rule.model.clone(),
                        strip_match: rule.strip_match,
                        is_dynamic,
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        "Invalid prompt_rule pattern '{}': {}. Skipping.",
                        rule.pattern,
                        e
                    );
                    None
                }
            })
            .collect();

        if !prompt_rules.is_empty() {
            info!("📝 Loaded {} prompt routing rules", prompt_rules.len());
        }

        Self {
            config,
            auto_mapper,
            background_regex,
            background_prefilter_bytes,
            prompt_rules,
        }
    }

    /// Route an incoming request to the appropriate model
    ///
    /// Priority order (highest to lowest):
    /// 1. WebSearch - tool-based detection (web_search tool present)
    /// 2. Background - model name regex match (e.g., haiku) - checked early to save costs
    /// 3. Subagent - GROB-SUBAGENT-MODEL tag in system prompt
    /// 4. Prompt Rules - regex pattern matching on user prompt (after background for cost savings)
    /// 5. Think - Plan Mode / reasoning enabled
    /// 6. Default - auto-mapped or original model name
    pub fn route(&self, request: &mut CanonicalRequest) -> Result<RouteDecision> {
        // 1. WebSearch (HIGHEST PRIORITY - tool-based detection, no model name needed)
        if let Some(ref websearch_model) = self.config.router.websearch {
            if self.has_web_search_tool(request) {
                debug!("🔍 Routing to websearch model (web_search tool detected)");
                return Ok(RouteDecision {
                    model_name: websearch_model.clone(),
                    route_type: RouteType::WebSearch,
                    matched_prompt: None,
                });
            }
        }

        // 2. Background tasks (checked BEFORE auto-mapping to avoid cloning original model)
        if let Some(ref background_model) = self.config.router.background {
            if self.is_background_task(&request.model) {
                debug!("🔄 Routing to background model");
                return Ok(RouteDecision {
                    model_name: background_model.clone(),
                    route_type: RouteType::Background,
                    matched_prompt: None,
                });
            }
        }

        // 3. Auto-mapping (model name transformation, after background check)
        if let Some(ref mapper) = self.auto_mapper {
            if mapper.is_match(&request.model) {
                debug!(
                    "🔀 Auto-mapped model '{}' → '{}'",
                    request.model, self.config.router.default
                );
                request.model.clone_from(&self.config.router.default);
            }
        }

        // 4. Subagent Model (system prompt tag)
        if let Some(model) = self.extract_subagent_model(request) {
            debug!(
                "🤖 Routing to subagent model (GROB-SUBAGENT-MODEL tag): {}",
                model
            );
            return Ok(RouteDecision {
                model_name: model,
                route_type: RouteType::Default,
                matched_prompt: None,
            });
        }

        // 5. Prompt Rules (pattern matching on user prompt)
        if let Some((model, matched_text)) = self.match_prompt_rule(request) {
            debug!("📝 Routing to model via prompt rule match: {}", model);
            return Ok(RouteDecision {
                model_name: model,
                route_type: RouteType::PromptRule,
                matched_prompt: Some(matched_text),
            });
        }

        // 6. Think mode (Plan Mode / Reasoning)
        if let Some(ref think_model) = self.config.router.think {
            if self.is_plan_mode(request) {
                debug!("🧠 Routing to think model (Plan Mode detected)");
                return Ok(RouteDecision {
                    model_name: think_model.clone(),
                    route_type: RouteType::Think,
                    matched_prompt: None,
                });
            }
        }

        // 7. Default fallback
        debug!("✅ Using model: {}", request.model);
        Ok(RouteDecision {
            model_name: request.model.clone(),
            route_type: RouteType::Default,
            matched_prompt: None,
        })
    }

    /// Check if request has web_search tool (tool-based detection)
    /// Following claude-code-router pattern: checks if tools array contains web_search type
    #[inline]
    fn has_web_search_tool(&self, request: &CanonicalRequest) -> bool {
        if let Some(ref tools) = request.tools {
            tools.iter().any(|tool| {
                tool.r#type
                    .as_ref()
                    .map(|t| t.starts_with("web_search"))
                    .unwrap_or(false)
            })
        } else {
            false
        }
    }

    /// Check if request is Plan Mode by detecting thinking field
    #[inline]
    fn is_plan_mode(&self, request: &CanonicalRequest) -> bool {
        request
            .thinking
            .as_ref()
            .map(|t| t.r#type == "enabled")
            .unwrap_or(false)
    }

    /// Detect background tasks using regex pattern.
    ///
    /// Uses SIMD-accelerated `memchr2` pre-filter to reject non-matching
    /// model names before invoking the full regex (~3 ns vs ~35 ns).
    #[inline]
    fn is_background_task(&self, model: &str) -> bool {
        if let Some(ref regex) = self.background_regex {
            // Fast SIMD pre-filter: reject if trailing literal's first byte is absent.
            if let Some((lo, hi)) = self.background_prefilter_bytes {
                if memchr2(lo, hi, model.as_bytes()).is_none() {
                    return false;
                }
            }
            regex.is_match(model)
        } else {
            false
        }
    }
}

// ── Trait implementation ──

impl crate::traits::RequestRouter for Router {
    fn route(&self, request: &mut CanonicalRequest) -> Result<RouteDecision> {
        self.route(request)
    }
}

#[cfg(test)]
mod tests;
