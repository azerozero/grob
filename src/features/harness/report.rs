//! Harness report: latency percentiles, throughput, and error breakdown.

use std::collections::HashMap;
use std::fmt;

/// Aggregated results from a harness replay run.
#[derive(Debug, Clone)]
pub struct HarnessReport {
    /// Total requests sent.
    pub total: u64,
    /// Successful requests (2xx).
    pub ok: u64,
    /// Failed requests (non-2xx or connection errors).
    pub failed: u64,
    /// Error breakdown: status code / error kind → count.
    pub errors: HashMap<String, u64>,
    /// Wall-clock duration of the run in seconds.
    pub duration_secs: f64,
    /// Observed requests per second.
    pub rps: f64,
    /// Latency distribution.
    pub latency: LatencyStats,
}

/// Latency percentile statistics (all values in milliseconds).
#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    pub min: u64,
    pub max: u64,
    pub mean: f64,
    pub p50: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
}

impl LatencyStats {
    /// Computes stats from a slice of latency samples (ms).
    pub fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();

        let sum: u64 = sorted.iter().sum();
        let n = sorted.len();

        Self {
            min: sorted[0],
            max: sorted[n - 1],
            mean: sum as f64 / n as f64,
            p50: percentile(&sorted, 50),
            p90: percentile(&sorted, 90),
            p95: percentile(&sorted, 95),
            p99: percentile(&sorted, 99),
        }
    }
}

/// Returns the p-th percentile from a sorted slice.
fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (p * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
}

impl fmt::Display for HarnessReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n=== Grob Harness Report ===")?;
        writeln!(f, "Duration:     {:.1}s", self.duration_secs)?;
        writeln!(
            f,
            "Requests:     {} ({} ok, {} failed)",
            self.total, self.ok, self.failed
        )?;
        writeln!(f, "Throughput:   {:.1} req/s", self.rps)?;
        writeln!(
            f,
            "Latency:      p50={}ms  p90={}ms  p95={}ms  p99={}ms",
            self.latency.p50, self.latency.p90, self.latency.p95, self.latency.p99
        )?;
        writeln!(
            f,
            "              min={}ms  max={}ms  mean={:.1}ms",
            self.latency.min, self.latency.max, self.latency.mean
        )?;

        if !self.errors.is_empty() {
            let mut errs: Vec<_> = self.errors.iter().collect();
            errs.sort_by(|a, b| b.1.cmp(a.1));
            let parts: Vec<String> = errs.iter().map(|(k, v)| format!("{}: {}", k, v)).collect();
            writeln!(f, "Errors:       {}", parts.join(", "))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_basic() {
        let samples = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let stats = LatencyStats::from_samples(&samples);
        assert_eq!(stats.min, 10);
        assert_eq!(stats.max, 100);
        assert!((stats.mean - 55.0).abs() < 0.1);
        assert_eq!(stats.p50, 60);
        assert_eq!(stats.p90, 100);
    }

    #[test]
    fn latency_stats_empty() {
        let stats = LatencyStats::from_samples(&[]);
        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 0);
    }

    #[test]
    fn report_display() {
        let report = HarnessReport {
            total: 100,
            ok: 95,
            failed: 5,
            errors: HashMap::from([("503".into(), 3), ("429".into(), 2)]),
            duration_secs: 10.0,
            rps: 10.0,
            latency: LatencyStats::from_samples(&[10, 20, 30]),
        };
        let output = format!("{}", report);
        assert!(output.contains("Grob Harness Report"));
        assert!(output.contains("100"));
        assert!(output.contains("95 ok"));
    }
}
