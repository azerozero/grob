//! Spend-journal persistence for [`GrobStore`].
//!
//! Holds the global and per-tenant append-only JSONL spend journals plus the
//! hot-path in-memory caches. Split out of `storage/mod.rs` so the storage
//! backend's four concerns (spend, OAuth tokens, secrets, virtual keys) each
//! live in a focused module while sharing one `GrobStore` type.

use std::sync::atomic::Ordering;

use super::{journal, sanitize_filename, GrobStore, DEFAULT_TENANT};
use crate::features::token_pricing::spend::SpendData;

impl GrobStore {
    /// Loads spend data (from cache for global, from per-tenant cache for tenants).
    pub(crate) fn load_spend(&self, tenant: Option<&str>) -> SpendData {
        if tenant.is_none() {
            return self
                .spend_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
        }
        let tenant = tenant.unwrap_or("");
        // Prefer the in-memory per-tenant cache; fall back to journal replay
        // when the tenant has not yet been touched in this process (e.g. read
        // before any record_spend call).
        let caches = self.tenant_caches.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(data) = caches.get(tenant) {
            return data.clone();
        }
        drop(caches);
        let journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        journal.replay_for_tenant(tenant)
    }

    /// Records spend for a request. Uses in-memory cache + batched fsync.
    ///
    /// The global in-memory cache and global journal continue to receive
    /// every event so legacy `total()` / Prometheus / monthly export paths
    /// keep working unchanged. When `tenant` is `Some`, the event is also
    /// appended to a per-tenant journal under `spend/<tenant>/<month>.jsonl`
    /// and the per-tenant in-memory cache is updated for budget checks.
    ///
    /// `tenant = None` is treated as the [`DEFAULT_TENANT`] for in-memory
    /// per-tenant accounting, but the journal entry is written without a
    /// `tenant` field to keep on-disk backward compatibility.
    pub(crate) fn record_spend(
        &self,
        tenant: Option<&str>,
        amount: f64,
        provider: &str,
        model: &str,
    ) {
        let ts = chrono::Utc::now().to_rfc3339();

        // Update in-memory global cache. Tenant-tagged events historically
        // also accumulated here; that is now suppressed so a per-tenant
        // overspend cannot trip the global budget. See ADR commentary in
        // SpendTracker::record_tenant.
        if tenant.is_none() {
            let mut cache = self.spend_cache.lock().unwrap_or_else(|e| e.into_inner());
            let now = crate::features::token_pricing::spend::current_month();
            if cache.month != now {
                *cache = SpendData::default();
            }
            cache.total += amount;
            *cache.by_provider.entry(provider.to_string()).or_default() += amount;
            *cache.by_model.entry(model.to_string()).or_default() += amount;
            *cache
                .by_provider_count
                .entry(provider.to_string())
                .or_default() += 1;
        }

        // Update in-memory per-tenant cache. Untagged calls are bucketed
        // under DEFAULT_TENANT so per-tenant budget logic is uniform.
        let tenant_key = tenant.unwrap_or(DEFAULT_TENANT);
        {
            let mut caches = self.tenant_caches.lock().unwrap_or_else(|e| e.into_inner());
            let now = crate::features::token_pricing::spend::current_month();
            let entry = caches.entry(tenant_key.to_string()).or_default();
            if entry.month != now {
                *entry = SpendData::default();
            }
            entry.total += amount;
            *entry.by_provider.entry(provider.to_string()).or_default() += amount;
            *entry.by_model.entry(model.to_string()).or_default() += amount;
            *entry
                .by_provider_count
                .entry(provider.to_string())
                .or_default() += 1;
        }

        // Append to global journal (preserves legacy on-disk layout).
        let event = journal::SpendEvent {
            ts: ts.clone(),
            kind: "spend".to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            cost_usd: amount,
            tenant: tenant.map(String::from),
        };
        if let Ok(mut j) = self.journal.lock() {
            if let Err(e) = j.append(&event) {
                tracing::warn!("failed to append spend event to journal: {e}");
            }
        }

        // Append to the per-tenant journal at `spend/<tenant>/<month>.jsonl`
        // when a tenant is supplied so per-tenant exports do not have to
        // re-scan the entire global journal.
        if let Some(t) = tenant {
            // Tenant ids reach the filesystem here; sanitize the same way as
            // OAuth provider ids so unusual ids cannot escape the spend dir.
            let safe_tenant = sanitize_filename(t);
            let mut tj = self
                .tenant_journals
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Open the per-tenant journal lazily. A disk-full / permission error
            // must NOT crash the spend path: log and skip the per-tenant append.
            // The global journal above already holds a tenant-tagged copy of this
            // event, so per-tenant spend remains recoverable.
            use std::collections::hash_map::Entry;
            let journal_entry = match tj.entry(safe_tenant.clone()) {
                Entry::Occupied(occupied) => Some(occupied.into_mut()),
                Entry::Vacant(vacant) => {
                    let dir = self.base_dir.join("spend").join(&safe_tenant);
                    match journal::SpendJournal::open_in(&dir) {
                        Ok(journal) => Some(vacant.insert(journal)),
                        Err(e) => {
                            tracing::error!(
                                tenant = %safe_tenant,
                                "failed to open per-tenant spend journal; skipping per-tenant \
                                 append (global journal retains a tagged copy): {e}"
                            );
                            None
                        }
                    }
                }
            };
            if let Some(journal_entry) = journal_entry {
                let tenant_event = journal::SpendEvent {
                    ts,
                    kind: "spend".to_string(),
                    provider: provider.to_string(),
                    model: model.to_string(),
                    cost_usd: amount,
                    tenant: Some(t.to_string()),
                };
                if let Err(e) = journal_entry.append(&tenant_event) {
                    tracing::warn!("failed to append per-tenant spend event: {e}");
                }
            }
        }

        // Batch fsync every 10 calls.
        let count = self.save_counter.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(10) {
            self.flush_spend();
        }
    }

    /// Forces journal fsync to disk (global + every per-tenant journal).
    pub(crate) fn flush_spend(&self) {
        if let Ok(mut j) = self.journal.lock() {
            if let Err(e) = j.fsync() {
                tracing::warn!("failed to fsync spend journal: {e}");
            }
        }
        if let Ok(mut tj) = self.tenant_journals.lock() {
            for (tenant, journal) in tj.iter_mut() {
                if let Err(e) = journal.fsync() {
                    tracing::warn!("failed to fsync per-tenant spend journal '{tenant}': {e}");
                }
            }
        }
    }
}
