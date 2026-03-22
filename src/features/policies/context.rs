//! Request context for policy evaluation.

/// Describes the current request for policy matching.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    /// Tenant identifier (from virtual key or JWT claim).
    pub tenant: Option<String>,
    /// Deployment zone (from provider region tag).
    pub zone: Option<String>,
    /// Project name (from `X-Grob-Project` header or `.grob.toml`).
    pub project: Option<String>,
    /// User identifier (from JWT `sub` or virtual key owner).
    pub user: Option<String>,
    /// Agent identifier (from `User-Agent` or `X-Grob-Agent` header).
    pub agent: Option<String>,
    /// Active compliance tags.
    pub compliance: Vec<String>,
    /// Requested model name.
    pub model: String,
    /// Provider selected by router.
    pub provider: String,
    /// Route classification (thinking, web_search, background, default).
    pub route_type: String,
    /// Whether DLP was triggered on this request.
    pub dlp_triggered: bool,
    /// Estimated cost in USD.
    pub estimated_cost: f64,
}
