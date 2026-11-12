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

//! The secret detection engine.
//!
//! The engine combines four detection techniques:
//!
//! 1. **Regular expressions** for provider specific signatures.
//! 2. **Entropy analysis** for unknown, high entropy tokens.
//! 3. **Checksum validation** (Luhn, mod-97) to weed out false positives.
//! 4. **Context awareness** so that generic assignments only trigger when the
//!    surrounding text actually talks about a secret.

use std::collections::{BTreeMap, BTreeSet};

use crate::entropy::{self, EntropyConfig, EntropyVerdict};
use crate::model::{Finding, RiskLevel, ScanReport, SecretKind};
use crate::rules::builtin::{ENTROPY_KEYWORDS, builtin_rules};
use crate::rules::{CompiledRule, RuleSpec};

/// Maximum number of bytes that are scanned in one pass.
///
/// Clipboard payloads larger than this are truncated: a 2 MB paste is almost
/// certainly not a credential and scanning it would waste CPU and memory.
pub const DEFAULT_MAX_SCAN_BYTES: usize = 512 * 1024;

/// A detection engine instance.
///
/// Engines are immutable once built; rebuild them when the configuration
/// changes.
#[derive(Debug, Clone)]
pub struct DetectionEngine {
    rules: Vec<CompiledRule>,
    entropy: EntropyConfig,
    fingerprint_key: [u8; 32],
    enabled_kinds: BTreeSet<SecretKind>,
    max_scan_bytes: usize,
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine {
    /// Builds an engine with the built-in rules and default settings.
    pub fn new() -> Self {
        let rules = builtin_rules()
            .iter()
            .filter_map(|spec| spec.compile().ok())
            .collect();
        Self {
            rules,
            entropy: EntropyConfig::default(),
            fingerprint_key: random_key(),
            enabled_kinds: BTreeSet::new(),
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
        }
    }

    /// Builds an engine from an explicit list of rule specifications.
    pub fn from_specs(specs: &[RuleSpec]) -> crate::Result<Self> {
        let rules = specs
            .iter()
            .map(RuleSpec::compile)
            .collect::<crate::Result<Vec<_>>>()?;
        Ok(Self {
            rules,
            entropy: EntropyConfig::default(),
            fingerprint_key: random_key(),
            enabled_kinds: BTreeSet::new(),
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
        })
    }

    /// Replaces the rule set with the built-in rules plus `custom`.
    pub fn with_custom_rules(&mut self, custom: &[RuleSpec]) -> crate::Result<()> {
        let mut rules = builtin_rules()
            .iter()
            .filter_map(|spec| spec.compile().ok())
            .collect::<Vec<_>>();
        rules.extend(
            custom
                .iter()
                .map(RuleSpec::compile)
                .collect::<crate::Result<Vec<_>>>()?,
        );
        self.rules = rules;
        Ok(())
    }

    /// Restricts detection to the given kinds. An empty set means "all kinds".
    pub fn set_enabled_kinds(&mut self, kinds: &[SecretKind]) {
        self.enabled_kinds = kinds.iter().copied().collect();
    }

    /// Overrides the entropy configuration.
    pub fn set_entropy_config(&mut self, config: EntropyConfig) {
        self.entropy = config;
    }

    /// Overrides the maximum number of bytes scanned per pass.
    pub fn set_max_scan_bytes(&mut self, max: usize) {
        self.max_scan_bytes = max;
    }

    /// Returns the compiled rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Scans `text` and returns all findings.
    pub fn scan(&self, text: &str) -> ScanReport {
        let scanned = &text[..text.len().min(self.max_scan_bytes)];
        let mut candidates = self.run_pattern_rules(scanned);
        self.run_entropy_rule(scanned, &mut candidates);

        let findings = merge_candidates(candidates, scanned, &self.fingerprint_key);
        let risk = findings
            .iter()
            .map(|finding| finding.risk)
            .max()
            .unwrap_or(RiskLevel::Low);

        ScanReport {
            findings,
            risk,
            scanned_bytes: scanned.len(),
        }
    }

    /// Runs every enabled pattern rule.
    fn run_pattern_rules(&self, text: &str) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if !self.enabled_kinds.is_empty() && !self.enabled_kinds.contains(&rule.kind) {
                continue;
            }
            for captures in rule.regex.captures_iter(text) {
                let Some(matched) = captures.get(rule.group) else {
                    continue;
                };
                let span = matched.start()..matched.end();
                if span.is_empty() {
                    continue;
                }
                if !rule.context_matches(text, span.start) {
                    continue;
                }
                let value = &text[span.clone()];
                if !rule.validators_accept(value) {
                    continue;
                }
                candidates.push(Candidate {
                    kind: rule.kind,
                    risk: rule.risk,
                    span,
                    rule: rule.name.clone(),
                    priority: rule.kind != SecretKind::EntropySecret,
                });
            }
        }
        candidates
    }

    /// Runs the entropy based detector over tokens that are not already
    /// covered by a pattern rule.
    fn run_entropy_rule(&self, text: &str, candidates: &mut Vec<Candidate>) {
        if !self.enabled_kinds.is_empty()
            && !self.enabled_kinds.contains(&SecretKind::EntropySecret)
        {
            return;
        }
        for (start, end) in token_spans(text) {
            if candidates
                .iter()
                .any(|candidate| candidate.span.start < end && start < candidate.span.end)
            {
                continue;
            }
            let token = &text[start..end];
            let context_start = start.saturating_sub(160);
            let context = &text[context_start..start];
            if entropy::evaluate(token, context, &self.entropy, ENTROPY_KEYWORDS)
                == EntropyVerdict::Secret
            {
                candidates.push(Candidate {
                    kind: SecretKind::EntropySecret,
                    risk: SecretKind::EntropySecret.default_risk(),
                    span: start..end,
                    rule: "entropy-detector".into(),
                    priority: false,
                });
            }
        }
    }

    /// Returns a summary of the active rule set, grouped by kind.
    pub fn coverage(&self) -> BTreeMap<SecretKind, usize> {
        let mut map = BTreeMap::new();
        for rule in &self.rules {
            if rule.enabled {
                *map.entry(rule.kind).or_insert(0) += 1;
            }
        }
        map
    }
}

/// An intermediate detection candidate before de-duplication.
#[derive(Debug, Clone)]
struct Candidate {
    kind: SecretKind,
    risk: RiskLevel,
    span: std::ops::Range<usize>,
    rule: String,
    priority: bool,
}

/// Removes overlapping candidates, keeping the most severe one.
fn merge_candidates(mut candidates: Vec<Candidate>, text: &str, key: &[u8; 32]) -> Vec<Finding> {
    candidates.sort_by(|a, b| {
        a.span
            .start
            .cmp(&b.span.start)
            .then_with(|| b.risk.cmp(&a.risk))
            .then_with(|| {
                b.span
                    .end
                    .saturating_sub(b.span.start)
                    .cmp(&a.span.end.saturating_sub(a.span.start))
            })
            .then_with(|| b.priority.cmp(&a.priority))
    });

    let mut findings: Vec<Finding> = Vec::new();
    let mut last_end = 0usize;
    for candidate in candidates {
        if !findings.is_empty() && candidate.span.start < last_end {
            continue;
        }
        last_end = candidate.span.end;
        // The secret bytes are only used to derive the fingerprint; they are
        // never stored in the finding itself.
        let secret = text
            .get(candidate.span.clone())
            .unwrap_or_default()
            .as_bytes();
        findings.push(Finding::from_slice(
            candidate.kind,
            candidate.risk,
            candidate.span,
            candidate.rule,
            secret,
            key,
        ));
    }
    findings
}

/// Splits `text` into candidate tokens and returns their byte ranges.
fn token_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (index, &byte) in bytes.iter().enumerate() {
        let is_token_char =
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_');
        if is_token_char {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(begin) = start.take() {
            spans.push((begin, index));
        }
    }
    if let Some(begin) = start {
        spans.push((begin, bytes.len()));
    }
    spans
}

/// Generates a random key used for fingerprints.
///
/// The key is created once per process: fingerprints are therefore stable
/// inside a running ClipWarden instance but cannot be correlated across
/// restarts or across machines.
fn random_key() -> [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        if getrandom::fill(&mut key).is_err() {
            // Fall back to a time based seed; fingerprints stay
            // non-reversible because they are only ever compared inside a
            // single session.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            key[..8].copy_from_slice(&nanos.to_le_bytes());
        }
        key
    })
}
