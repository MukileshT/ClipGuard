// Copyright 2026 Mukilesh
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Protection statistics.
//!
//! Statistics never contain clipboard content — only counts, categories and
//! application names. This keeps the dashboard useful while guaranteeing that
//! no secret is ever written to disk or to a log file.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::model::SecretKind;

/// A point in time snapshot of the protection statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// Number of clipboard payloads that were scanned.
    pub scans: u64,
    /// Number of scans that contained at least one secret.
    pub detections: u64,
    /// Number of secrets that were redacted.
    pub redacted: u64,
    /// Number of secrets that were removed.
    pub removed: u64,
    /// Number of pastes that were blocked.
    pub blocked: u64,
    /// Number of pastes that were allowed through.
    pub allowed: u64,
    /// Number of detections per secret kind.
    pub by_kind: BTreeMap<SecretKind, u64>,
    /// Number of detections per application.
    pub by_app: BTreeMap<String, u64>,
    /// Unix timestamp (seconds) of the moment the daemon started.
    pub started_at: u64,
    /// Unix timestamp (seconds) of the last scan.
    pub last_scan_at: u64,
}

impl StatsSnapshot {
    /// Number of distinct secrets that were detected.
    pub fn total_findings(&self) -> u64 {
        self.by_kind.values().copied().sum()
    }

    /// Detection rate as a percentage of scans that found something.
    pub fn detection_rate(&self) -> f64 {
        if self.scans == 0 {
            0.0
        } else {
            (self.detections as f64 / self.scans as f64) * 100.0
        }
    }
}

/// Thread safe counters backing the statistics.
#[derive(Debug, Default)]
pub struct Stats {
    scans: AtomicU64,
    detections: AtomicU64,
    redacted: AtomicU64,
    removed: AtomicU64,
    blocked: AtomicU64,
    allowed: AtomicU64,
    started_at: AtomicU64,
    last_scan_at: AtomicU64,
    by_kind: Mutex<BTreeMap<SecretKind, u64>>,
    by_app: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    /// Creates a new counter set.
    pub fn new() -> Self {
        Self {
            started_at: AtomicU64::new(now_unix()),
            ..Default::default()
        }
    }

    /// Records a scan.
    pub fn record_scan(&self) {
        self.scans.fetch_add(1, Ordering::Relaxed);
        self.last_scan_at.store(now_unix(), Ordering::Relaxed);
    }

    /// Records detected secrets.
    pub fn record_detection(&self, kinds: &[SecretKind], app: Option<&str>) {
        if kinds.is_empty() {
            return;
        }
        self.detections.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut by_kind) = self.by_kind.lock() {
            for kind in kinds {
                *by_kind.entry(*kind).or_insert(0) += 1;
            }
        }
        if let Some(app) = app
            && let Ok(mut by_app) = self.by_app.lock()
        {
            *by_app.entry(app.to_string()).or_insert(0) += 1;
        }
    }

    /// Records a redaction.
    pub fn record_redacted(&self, count: u64) {
        self.redacted.fetch_add(count, Ordering::Relaxed);
    }

    /// Records a removal.
    pub fn record_removed(&self, count: u64) {
        self.removed.fetch_add(count, Ordering::Relaxed);
    }

    /// Records a blocked paste.
    pub fn record_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an allowed paste.
    pub fn record_allowed(&self) {
        self.allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a consistent snapshot of the counters.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            scans: self.scans.load(Ordering::Relaxed),
            detections: self.detections.load(Ordering::Relaxed),
            redacted: self.redacted.load(Ordering::Relaxed),
            removed: self.removed.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            by_kind: self
                .by_kind
                .lock()
                .map(|map| map.clone())
                .unwrap_or_default(),
            by_app: self
                .by_app
                .lock()
                .map(|map| map.clone())
                .unwrap_or_default(),
            started_at: self.started_at.load(Ordering::Relaxed),
            last_scan_at: self.last_scan_at.load(Ordering::Relaxed),
        }
    }

    /// Resets every counter.
    pub fn reset(&self) {
        self.scans.store(0, Ordering::Relaxed);
        self.detections.store(0, Ordering::Relaxed);
        self.redacted.store(0, Ordering::Relaxed);
        self.removed.store(0, Ordering::Relaxed);
        self.blocked.store(0, Ordering::Relaxed);
        self.allowed.store(0, Ordering::Relaxed);
        self.last_scan_at.store(0, Ordering::Relaxed);
        if let Ok(mut by_kind) = self.by_kind.lock() {
            by_kind.clear();
        }
        if let Ok(mut by_app) = self.by_app.lock() {
            by_app.clear();
        }
    }
}

/// Current unix timestamp in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
