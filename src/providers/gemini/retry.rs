use super::types::{GeminiErrorDetail, GeminiErrorResponse};

/// Parse retry delay from Google's duration format (e.g., "3.020317815s", "60s", "900ms")
pub(super) fn parse_retry_delay(duration: &str) -> Option<std::time::Duration> {
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
pub(super) fn extract_retry_delay(error_text: &str) -> Option<std::time::Duration> {
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
