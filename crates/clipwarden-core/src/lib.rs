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

//! # ClipWarden Core
//!
//! The security engine of [ClipWarden](https://github.com/MukileshT/ClipWarden).
//!
//! This crate contains no Windows specific code and no I/O beyond reading and
//! writing the configuration file, which makes it fully unit testable and
//! reusable from any front end.
//!
//! ## Design rules
//!
//! * Secrets are never written to logs, statistics or configuration files.
//! * Findings store byte offsets and a keyed fingerprint, never the secret.
//! * Detection is deterministic: the same input always yields the same
//!   findings.
//! * The engine performs no network access whatsoever.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod engine;
pub mod entropy;
pub mod error;
pub mod model;
pub mod policy;
pub mod redact;
pub mod rules;
pub mod stats;
pub mod templates;

pub use config::{
    CONFIG_DIR_NAME, CONFIG_FILE_NAME, Config, DetectionConfig, GeneralConfig, ProtectionConfig,
    default_config_path,
};
pub use engine::DetectionEngine;
pub use entropy::EntropyConfig;
pub use error::{CoreError, Result};
pub use model::{
    AppIdentity, FailSafe, Finding, GlobalMode, ProtectionMode, RiskLevel, ScanReport,
    SecretFamily, SecretKind,
};
pub use policy::{AppRule, PolicyDecision, PolicyEngine};
pub use redact::{RedactionOptions, RedactionOutcome};
pub use rules::{CompiledRule, RuleSet, RuleSpec, Validator};
pub use stats::{Stats, StatsSnapshot};
pub use templates::{Template, TemplateCategory, all_templates, personal_phone_template};

/// The version of the ClipWarden core crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Detects secrets in `text` using the default engine.
pub fn quick_scan(text: &str) -> ScanReport {
    DetectionEngine::new().scan(text)
}
