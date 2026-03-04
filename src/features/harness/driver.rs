//! Traffic driver that replays recorded requests against a grob instance.
//!
//! Uses a semaphore for concurrency control and an optional rate limiter
//! for QPS throttling, following the same pattern as the MCP bench engine.

use super::report::{HarnessReport, LatencyStats};
use super::tape::TapeEntry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, warn};

/// Configuration for the traffic driver.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// Base URL of the grob instance to test.
    pub target_url: String,
    /// Maximum concurrent in-flight requests.
    pub concurrency: usize,
    /// Target queries per second (0 = unlimited).
    pub qps: f64,
    /// Total requests to send (0 = replay each entry once).
    pub total: usize,
    /// Maximum duration in seconds (0 = no limit).
    pub duration_secs: u64,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            target_url: "http://[::1]:13456".into(),
            concurrency: 10,
            qps: 0.0,
            total: 0,
            duration_secs: 0,
        }
    }
}

/// Replays tape entries against a running grob instance.
pub struct Driver {
    client: reqwest::Client,
    entries: Vec<TapeEntry>,
    config: DriverConfig,
}

impl Driver {
    /// Creates a new driver from tape entries and configuration.
    pub fn new(entries: Vec<TapeEntry>, config: DriverConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(config.concurrency)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            entries,
            config,
        }
    }

    /// Runs the replay and returns the aggregated report.
    pub async fn run(&self) -> HarnessReport {
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let ok = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let errors: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let latencies: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

        let total = if self.config.total > 0 {
            self.config.total
        } else {
            self.entries.len()
        };

        let deadline = if self.config.duration_secs > 0 {
            Some(Instant::now() + Duration::from_secs(self.config.duration_secs))
        } else {
            None
        };

        // QPS throttling interval.
        let interval = if self.config.qps > 0.0 {
            Some(Duration::from_secs_f64(1.0 / self.config.qps))
        } else {
            None
        };

        let start = Instant::now();
        let mut handles = Vec::with_capacity(total);

        for i in 0..total {
            // Check deadline.
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    break;
                }
            }

            // QPS throttling.
            if let Some(iv) = interval {
                let expected = iv * (i as u32);
                let elapsed = start.elapsed();
                if expected > elapsed {
                    tokio::time::sleep(expected - elapsed).await;
                }
            }

            let entry = &self.entries[i % self.entries.len()];
            let sem = semaphore.clone();
            let client = self.client.clone();
            let target = self.config.target_url.clone();
            let req_path = entry.request.path.clone();
            let req_body = entry.request.body.clone();
            let req_headers = entry.request.headers.clone();
            let ok = ok.clone();
            let failed = failed.clone();
            let errors = errors.clone();
            let latencies = latencies.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("Semaphore closed");

                let url = format!("{}{}", target, req_path);
                let mut builder = client.post(&url);

                // Forward non-sensitive headers.
                for (k, v) in &req_headers {
                    if k != "authorization" && k != "x-api-key" && k != "cookie" {
                        builder = builder.header(k.as_str(), v.as_str());
                    }
                }

                // Always set content-type.
                builder = builder.header("content-type", "application/json");
                builder = builder.json(&req_body);

                let t0 = Instant::now();
                match builder.send().await {
                    Ok(resp) => {
                        let latency = t0.elapsed().as_millis() as u64;
                        latencies.lock().await.push(latency);

                        let status = resp.status().as_u16();
                        if (200..300).contains(&(status as usize)) {
                            ok.fetch_add(1, Ordering::Relaxed);
                            debug!(status, latency, "Request OK");
                        } else {
                            failed.fetch_add(1, Ordering::Relaxed);
                            let key = format!("{}", status);
                            *errors.lock().await.entry(key).or_insert(0) += 1;
                        }
                    }
                    Err(e) => {
                        let latency = t0.elapsed().as_millis() as u64;
                        latencies.lock().await.push(latency);
                        failed.fetch_add(1, Ordering::Relaxed);
                        let key = format!(
                            "conn:{}",
                            e.to_string().chars().take(40).collect::<String>()
                        );
                        *errors.lock().await.entry(key).or_insert(0) += 1;
                        warn!(error = %e, "Request failed");
                    }
                }
            });

            handles.push(handle);
        }

        // Collect all tasks.
        for handle in handles {
            handle.await.ok();
        }

        let duration = start.elapsed();
        let total_sent = ok.load(Ordering::Relaxed) + failed.load(Ordering::Relaxed);
        let rps = if duration.as_secs_f64() > 0.0 {
            total_sent as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        let lats = latencies.lock().await;
        let latency = LatencyStats::from_samples(&lats);
        drop(lats);

        let error_map = errors.lock().await.clone();

        HarnessReport {
            total: total_sent,
            ok: ok.load(Ordering::Relaxed),
            failed: failed.load(Ordering::Relaxed),
            errors: error_map,
            duration_secs: duration.as_secs_f64(),
            rps,
            latency,
        }
    }
}
