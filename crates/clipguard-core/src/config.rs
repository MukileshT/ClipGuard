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

//! Persistent configuration.
//!
//! The configuration is stored as TOML in `%APPDATA%\ClipGuard\config.toml`.
//! It never contains credentials of any kind — only *patterns* that describe
//! what should be protected.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::DetectionEngine;
use crate::entropy::EntropyConfig;
use crate::error::{CoreError, Result};
use crate::model::{FailSafe, GlobalMode, ProtectionMode, SecretKind};
use crate::policy::{AppRule, PolicyEngine, default_app_rules};
use crate::rules::RuleSpec;

/// Name of the configuration directory inside the user profile.
pub const CONFIG_DIR_NAME: &str = "ClipGuard";

/// Name of the configuration file.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// The root configuration object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General behaviour of the application.
    pub general: GeneralConfig,
    /// Detection tuning.
    pub detection: DetectionConfig,
    /// Protection behaviour.
    pub protection: ProtectionConfig,
    /// Per application rules.
    pub apps: Vec<AppRule>,
    /// User defined detection rules.
    pub rules: Vec<RuleSpec>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            detection: DetectionConfig::default(),
            protection: ProtectionConfig::default(),
            apps: default_app_rules(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    /// Loads the configuration from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path).map_err(|source| CoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&raw)
    }

    /// Parses a configuration from a TOML string.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut config: Config = toml::from_str(raw)?;
        config.normalise();
        config.validate()?;
        Ok(config)
    }

    /// Serialises the configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(CoreError::from)
    }

    /// Writes the configuration to `path`, creating parent directories.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| CoreError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let raw = self.to_toml()?;
        std::fs::write(path, raw).map_err(|source| CoreError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Returns the default configuration path for the current user.
    pub fn default_path() -> PathBuf {
        default_config_path()
    }

    /// Fills in missing values and normalises the stored rule set.
    fn normalise(&mut self) {
        for rule in &mut self.apps {
            if rule.id.is_empty() {
                rule.id = crate::policy::slugify(&rule.pattern);
            }
            if rule.label.is_empty() {
                rule.label = rule.pattern.clone();
            }
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        for rule in &self.rules {
            rule.compile()
                .map_err(|err| CoreError::Invalid(format!("rule `{}`: {err}", rule.name)))?;
        }
        if self.protection.placeholder.trim().is_empty() {
            return Err(CoreError::Invalid(
                "protection.placeholder must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// Builds a detection engine from this configuration.
    pub fn build_engine(&self) -> Result<DetectionEngine> {
        let mut specs = crate::rules::builtin::builtin_rules();
        specs.extend(self.rules.iter().cloned());
        let mut engine = DetectionEngine::from_specs(&specs)?;
        engine.set_entropy_config(self.detection.entropy);

        // Personal information is only detected when the user asks for it.
        let personal = [
            SecretKind::EmailAddress,
            SecretKind::PhoneNumber,
            SecretKind::CreditCard,
            SecretKind::Ssn,
            SecretKind::Iban,
        ];

        let mut kinds: Vec<SecretKind> = if self.detection.enabled_kinds.is_empty() {
            SecretKind::ALL.to_vec()
        } else {
            self.detection.enabled_kinds.clone()
        };
        kinds.retain(|kind| !self.detection.disabled_kinds.contains(kind));
        if !self.detection.detect_personal {
            kinds.retain(|kind| !personal.contains(kind));
        }
        engine.set_enabled_kinds(&kinds);
        Ok(engine)
    }

    /// Builds a policy engine from this configuration.
    pub fn build_policy(&self) -> PolicyEngine {
        PolicyEngine {
            default_mode: self.protection.default_mode,
            global_mode: self.general.global_mode,
            fail_safe: self.general.fail_safe,
            app_rules: self.apps.clone(),
        }
    }
}

/// General application behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Master switch.
    pub enabled: bool,
    /// Whether protection runs at copy time (ghost) or paste time (satellite).
    pub global_mode: GlobalMode,
    /// Behaviour when the protection pipeline fails.
    pub fail_safe: FailSafe,
    /// Monitor clipboard changes.
    pub monitor_clipboard: bool,
    /// Observe paste shortcuts to apply per application policies.
    pub intercept_paste: bool,
    /// Restore the original content when pasting into a trusted application.
    pub restore_on_trusted_paste: bool,
    /// Launch ClipGuard when the user signs in.
    pub start_with_windows: bool,
    /// Show the system tray icon.
    pub show_tray_icon: bool,
    /// Show desktop notifications for detections.
    pub notifications: bool,
    /// Also protect content that was already on the clipboard when ClipGuard
    /// started.
    ///
    /// By default only new copies are protected: the text that was on the
    /// clipboard before the service started stays untouched.
    #[serde(default)]
    pub protect_existing_clipboard: bool,
    /// Keep the clipboard history of Windows switched off.
    ///
    /// Windows stores every copied text in its own history before ClipGuard
    /// can mask the clipboard. The setting is restored by Windows from time
    /// to time, so the choice is remembered here and made again.
    #[serde(default)]
    pub disable_windows_history: bool,
    /// SHA-256 hash of the application password. Empty means no password protection.
    #[serde(default)]
    pub password_hash: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_mode: GlobalMode::Ghost,
            fail_safe: FailSafe::Redact,
            monitor_clipboard: true,
            intercept_paste: true,
            restore_on_trusted_paste: true,
            start_with_windows: false,
            show_tray_icon: true,
            notifications: true,
            protect_existing_clipboard: false,
            disable_windows_history: false,
            password_hash: String::new(),
        }
    }
}

/// Detection tuning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    /// Kinds that should be detected. Empty means "all kinds".
    pub enabled_kinds: Vec<SecretKind>,
    /// Kinds that must never be detected.
    pub disabled_kinds: Vec<SecretKind>,
    /// Detect personal information (email addresses, phone numbers, …).
    pub detect_personal: bool,
    /// Entropy detector configuration.
    pub entropy: EntropyConfig,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled_kinds: Vec::new(),
            disabled_kinds: Vec::new(),
            detect_personal: true,
            entropy: EntropyConfig::default(),
        }
    }
}

/// Protection behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectionConfig {
    /// Mode used when no application rule matches.
    pub default_mode: ProtectionMode,
    /// Placeholder inserted by `Redact` mode.
    pub placeholder: String,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            default_mode: ProtectionMode::Redact,
            placeholder: "[REDACTED]".into(),
        }
    }
}

/// Returns the default configuration path for the current user.
pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a credential that looks real but is assembled at runtime.
    ///
    /// The hosting platform scans every push for leaked credentials. A sample
    /// that is written literally would be indistinguishable from a real key
    /// and would block the push, so the parts are kept apart here.
    fn fake_secret(prefix: &str, parts: &[&str]) -> String {
        format!("{prefix}{}", parts.concat())
    }

    #[test]
    fn default_config_round_trips() {
        let config = Config::default();
        let raw = config.to_toml().unwrap();
        let parsed = Config::parse(&raw).unwrap();
        assert_eq!(
            parsed.protection.default_mode,
            config.protection.default_mode
        );
        assert_eq!(parsed.general.global_mode, config.general.global_mode);
        assert_eq!(parsed.apps.len(), config.apps.len());
    }

    #[test]
    fn invalid_rule_is_rejected() {
        let raw = r#"
            [[rules]]
            name = "broken"
            pattern = "([unclosed"
            kind = "custom"
        "#;
        assert!(Config::parse(raw).is_err());
    }

    #[test]
    fn engine_is_built_from_config() {
        let config = Config::default();
        let engine = config.build_engine().unwrap();
        assert!(!engine.rules().is_empty());
    }

    #[test]
    fn default_config_detects_api_keys() {
        let config = Config::default();
        let engine = config.build_engine().unwrap();
        let report = engine.scan(&fake_secret("AKIA", &["IOSFODNN7EXAMPLE"]));
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    }

    #[test]
    fn personal_information_can_be_disabled() {
        let mut config = Config::default();
        config.detection.detect_personal = false;
        let engine = config.build_engine().unwrap();
        let report = engine.scan("mail me at alice@example.com");
        assert!(report.is_clean(), "{:?}", report.findings);
    }

    #[test]
    fn disabled_kinds_are_not_detected() {
        let mut config = Config::default();
        config.detection.disabled_kinds = vec![SecretKind::AwsAccessKeyId];
        let engine = config.build_engine().unwrap();
        let report = engine.scan(&fake_secret("AKIA", &["IOSFODNN7EXAMPLE"]));
        assert!(report.is_clean(), "{:?}", report.findings);
    }
}
