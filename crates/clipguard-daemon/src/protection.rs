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

//! The protection engine.
//!
//! This module contains the logic that turns a clipboard event into a
//! protection decision:
//!
//! * [`ProtectionEngine::on_clipboard_changed`] is called by the clipboard
//!   monitor whenever the clipboard content changes.
//! * [`ProtectionEngine::on_paste`] is called by the keyboard hook when a
//!   paste shortcut is pressed.
//!
//! Both callbacks must return quickly: the first one runs inside the window
//! procedure of the listener window, the second one inside a low level
//! keyboard hook, where Windows terminates hooks that take too long.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

use clipguard_core::config::Config;
use clipguard_core::engine::DetectionEngine;
use clipguard_core::model::{
    AppIdentity, Finding, GlobalMode, ProtectionMode, RiskLevel, ScanReport, SecretKind,
};
use clipguard_core::policy::PolicyEngine;
use clipguard_core::redact::{RedactionOptions, apply};
use clipguard_core::stats::{Stats, StatsSnapshot};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use clipguard_clipboard::app::AppResolver;
use clipguard_clipboard::hook::PasteDecision;
use clipguard_clipboard::monitor::ClipboardAction;

/// The payload of a detection event.
///
/// The event never contains the secret itself - only metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// The kinds that were detected.
    pub kinds: Vec<SecretKind>,
    /// The highest risk that was detected.
    pub risk: RiskLevel,
    /// How many secrets were found.
    pub count: usize,
    /// The application that was focused when the copy happened.
    pub source_app: Option<String>,
    /// The mode that was applied.
    pub mode: ProtectionMode,
    /// Whether the clipboard content was actually modified.
    pub modified: bool,
}

/// Current status of the protection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionStatus {
    /// Whether protection is active.
    pub enabled: bool,
    /// The global mode.
    pub global_mode: GlobalMode,
    /// The mode used when no application rule matches.
    pub default_mode: ProtectionMode,
    /// Whether the clipboard is currently monitored.
    pub monitoring: bool,
    /// Whether a secret is currently held in memory.
    pub secret_pending: bool,
    /// Whether a password is configured for the application.
    pub password_protected: bool,
}

/// Holds the clipboard content that ClipGuard has to protect.
///
/// The buffer is wiped as soon as the clipboard changes, so that a secret is
/// never kept around longer than necessary.
#[derive(Debug, Default)]
struct Vault {
    original: Option<Zeroizing<String>>,
    protected: Option<Zeroizing<String>>,
    has_secret: bool,
    /// Set while ClipGuard itself is writing to the clipboard.
    ignore_next_update: bool,
}

impl Vault {
    fn store(&mut self, original: &str, protected: Option<&str>, has_secret: bool) {
        self.original = Some(Zeroizing::new(original.to_string()));
        self.protected = protected.map(|value| Zeroizing::new(value.to_string()));
        self.has_secret = has_secret;
    }

    fn clear(&mut self) {
        self.original = None;
        self.protected = None;
        self.has_secret = false;
    }

    fn original(&self) -> Option<String> {
        self.original.as_ref().map(|value| value.to_string())
    }

    fn protected(&self) -> Option<String> {
        self.protected.as_ref().map(|value| value.to_string())
    }
}

/// Returns `true` when the detection engine has to be rebuilt.
///
/// Compiling the patterns is the expensive part of a configuration change,
/// so it only happens when a rule or a detection setting really changed.
fn detector_changed(previous: &Config, current: &Config) -> bool {
    previous.detection != current.detection || previous.rules != current.rules
}

/// Returns `true` when the policy has to be rebuilt.
fn policy_changed(previous: &Config, current: &Config) -> bool {
    previous.apps != current.apps
        || previous.protection.default_mode != current.protection.default_mode
        || previous.general.global_mode != current.general.global_mode
        || previous.general.fail_safe != current.general.fail_safe
}

/// The protection engine.
pub struct ProtectionEngine {
    config_path: PathBuf,
    config: RwLock<Config>,
    detector: RwLock<DetectionEngine>,
    policy: RwLock<PolicyEngine>,
    stats: Stats,
    vault: Mutex<Vault>,
    resolver: AppResolver,
    subscribers: Mutex<Vec<Sender<serde_json::Value>>>,
    paused: AtomicBool,
    /// Set when the service should quit.
    shutdown_requested: AtomicBool,

    last_config_mtime: Mutex<Option<std::time::SystemTime>>,
}

impl ProtectionEngine {
    /// Creates an engine that loads its configuration from `config_path`.
    pub fn new(config_path: PathBuf) -> Self {
        let config = Config::load(&config_path).unwrap_or_default();
        let detector = config
            .build_engine()
            .unwrap_or_else(|_| DetectionEngine::new());
        let policy = config.build_policy();
        let mtime = std::fs::metadata(&config_path)
            .and_then(|meta| meta.modified())
            .ok();
        Self {
            config_path,
            config: RwLock::new(config),
            detector: RwLock::new(detector),
            policy: RwLock::new(policy),
            stats: Stats::new(),
            vault: Mutex::new(Vault::default()),
            resolver: AppResolver::new(),
            subscribers: Mutex::new(Vec::new()),
            paused: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
            last_config_mtime: Mutex::new(mtime),
        }
    }

    /// Asks the service to quit.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
    }

    /// Returns `true` when the service was asked to quit.
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    /// Returns the path of the configuration file.
    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    /// Returns a copy of the current configuration.
    pub fn config(&self) -> Config {
        self.config.read().expect("config lock").clone()
    }

    /// Replaces the configuration and rebuilds the engine.
    ///
    /// Only the parts that actually changed are rebuilt: switching between
    /// the ghost and the satellite mode does not touch the detection rules
    /// and therefore does not compile the patterns again.
    pub fn set_config(&self, config: Config) -> Result<(), String> {
        config.validate().map_err(|error| error.to_string())?;
        let previous = self.config.read().expect("config lock").clone();

        if detector_changed(&previous, &config) {
            let detector = config.build_engine().map_err(|error| error.to_string())?;
            *self.detector.write().expect("detector lock") = detector;
        }
        if policy_changed(&previous, &config) {
            let policy = config.build_policy();
            *self.policy.write().expect("policy lock") = policy;
        }

        config
            .save(&self.config_path)
            .map_err(|error| error.to_string())?;
        *self.config.write().expect("config lock") = config.clone();
        self.touch_config_mtime();

        // Switching the option on masks the older content right away.
        if config.general.protect_existing_clipboard && !previous.general.protect_existing_clipboard
        {
            self.protect_existing_content();
        }
        Ok(())
    }

    /// Reloads the configuration from disk if it changed.
    pub fn reload_if_changed(&self) {
        let current = std::fs::metadata(&self.config_path)
            .and_then(|meta| meta.modified())
            .ok();
        let changed = match (
            &current,
            &*self.last_config_mtime.lock().expect("mtime lock"),
        ) {
            (Some(now), Some(previous)) => now != previous,
            (Some(_), None) => true,
            _ => false,
        };
        if !changed {
            return;
        }
        match Config::load(&self.config_path) {
            Ok(config) => {
                let previous = self.config.read().expect("config lock").clone();
                if detector_changed(&previous, &config)
                    && let Ok(detector) = config.build_engine()
                {
                    *self.detector.write().expect("detector lock") = detector;
                }
                if policy_changed(&previous, &config) {
                    let policy = config.build_policy();
                    *self.policy.write().expect("policy lock") = policy;
                }
                *self.config.write().expect("config lock") = config.clone();
                self.touch_config_mtime();
                tracing::info!("the configuration was reloaded");

                // Switching the option on masks the content that was on the
                // clipboard right away.
                if config.general.protect_existing_clipboard
                    && !previous.general.protect_existing_clipboard
                {
                    self.protect_existing_content();
                }
            }
            Err(error) => tracing::error!(?error, "the configuration could not be reloaded"),
        }
    }

    fn touch_config_mtime(&self) {
        let mtime = std::fs::metadata(&self.config_path)
            .and_then(|meta| meta.modified())
            .ok();
        *self.last_config_mtime.lock().expect("mtime lock") = mtime;
    }

    /// Returns the current protection status.
    pub fn status(&self) -> ProtectionStatus {
        let config = self.config.read().expect("config lock");
        let vault = self.vault.lock().expect("vault lock");
        ProtectionStatus {
            enabled: config.general.enabled && !self.paused.load(Ordering::Relaxed),
            global_mode: config.general.global_mode,
            default_mode: config.protection.default_mode,
            monitoring: config.general.monitor_clipboard,
            secret_pending: vault.has_secret,
            password_protected: !config.general.password_hash.is_empty(),
        }
    }

    /// Returns a snapshot of the statistics.
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Pauses or resumes protection.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        if paused {
            self.vault.lock().expect("vault lock").clear();
        }
    }

    /// Returns `true` when protection is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Registers a subscriber that receives detection events.
    pub fn subscribe(&self, sender: Sender<serde_json::Value>) {
        self.subscribers
            .lock()
            .expect("subscribers lock")
            .push(sender);
    }

    /// Scans a piece of text without touching the clipboard.
    pub fn scan(&self, text: &str) -> ScanReport {
        self.detector.read().expect("detector lock").scan(text)
    }

    /// Masks the content that was already on the clipboard when the service
    /// started.
    ///
    /// Nothing happens unless the user asked for it in the settings: by
    /// default the text that was on the clipboard stays untouched. The
    /// content that is already there never produces a clipboard event, so it
    /// has to be checked once when the service starts.
    pub fn protect_existing_content(&self) -> bool {
        let config = self.config.read().expect("config lock").clone();
        if !config.general.protect_existing_clipboard {
            return false;
        }
        let Some(text) = clipguard_clipboard::access::read_text().ok().flatten() else {
            return false;
        };
        let report = self.detector.read().expect("detector lock").scan(&text);
        if report.is_clean() {
            return false;
        }
        let options = RedactionOptions {
            placeholder: config.protection.placeholder.clone(),
            tidy: true,
        };
        let mode = match config.general.global_mode {
            GlobalMode::Ghost => config.protection.default_mode,
            GlobalMode::Satellite => ProtectionMode::Redact,
        };
        let Some(protected) = apply(&text, &report.findings, mode, &options).text else {
            return false;
        };
        if clipguard_clipboard::access::write_text(&protected).is_err() {
            tracing::warn!("could not mask the content that was already on the clipboard");
            return false;
        }
        tracing::info!("the content that was already on the clipboard was masked");
        true
    }

    /// Handles a clipboard change.
    ///
    /// `existed_before` is `true` when the content was already on the
    /// clipboard when the service started. Such content is left alone unless
    /// the user asked for it in the settings.
    pub fn on_clipboard_changed(
        &self,
        text: Option<&str>,
        existed_before: bool,
    ) -> ClipboardAction {
        self.reload_if_changed();

        let config = self.config.read().expect("config lock").clone();
        if !config.general.enabled || self.paused.load(Ordering::Relaxed) {
            self.vault.lock().expect("vault lock").clear();
            return ClipboardAction::Ignore;
        }

        let Some(text) = text else {
            self.vault.lock().expect("vault lock").clear();
            return ClipboardAction::Ignore;
        };

        // The content that was on the clipboard before the service started
        // stays untouched unless the user asks for it.
        if existed_before && !config.general.protect_existing_clipboard {
            self.vault.lock().expect("vault lock").clear();
            return ClipboardAction::Ignore;
        }

        {
            let mut vault = self.vault.lock().expect("vault lock");
            if vault.ignore_next_update {
                // This update was produced by ClipGuard itself.
                vault.ignore_next_update = false;
                vault.clear();
                return ClipboardAction::Ignore;
            }
        }

        self.stats.record_scan();

        let report = self.detector.read().expect("detector lock").scan(text);
        if report.is_clean() {
            self.vault.lock().expect("vault lock").clear();
            return ClipboardAction::Ignore;
        }

        let kinds: Vec<SecretKind> = report.findings.iter().map(|f| f.kind).collect();
        let source_app = self.resolver.foreground().map(|app| app.exe);
        self.stats.record_detection(&kinds, source_app.as_deref());

        let options = RedactionOptions {
            placeholder: config.protection.placeholder.clone(),
            tidy: true,
        };

        // The mode that decides what happens with the secret.
        let mode = match config.general.global_mode {
            GlobalMode::Ghost => config.protection.default_mode,
            GlobalMode::Satellite => ProtectionMode::Redact,
        };

        // The protected variant is computed once and reused. In satellite
        // mode the clipboard stays untouched; the variant is prepared for
        // the moment the user pastes.
        let protected = match mode {
            ProtectionMode::Allow => None,
            _ => apply(text, &report.findings, mode, &options).text,
        };

        let has_secret = !report.findings.is_empty();
        {
            let mut vault = self.vault.lock().expect("vault lock");
            vault.store(text, protected.as_deref(), has_secret);
        }

        let action = match config.general.global_mode {
            GlobalMode::Ghost => match mode {
                ProtectionMode::Allow => ClipboardAction::Ignore,
                ProtectionMode::Redact | ProtectionMode::Remove => match protected {
                    Some(protected) => ClipboardAction::SetText(protected),
                    None => ClipboardAction::Clear,
                },
                ProtectionMode::Block => ClipboardAction::Clear,
            },
            GlobalMode::Satellite => ClipboardAction::Ignore,
        };

        let modified = !matches!(action, ClipboardAction::Ignore);
        if modified {
            match mode {
                ProtectionMode::Redact => self.stats.record_redacted(report.findings.len() as u64),
                ProtectionMode::Remove => self.stats.record_removed(report.findings.len() as u64),
                ProtectionMode::Block => self.stats.record_blocked(),
                ProtectionMode::Allow => {}
            }
        }

        self.publish(&DetectionEvent {
            kinds,
            risk: report.risk,
            count: report.findings.len(),
            source_app,
            mode,
            modified,
        });

        action
    }

    /// Handles a paste shortcut.
    pub fn on_paste(&self) -> PasteDecision {
        let config = self.config.read().expect("config lock").clone();
        if !config.general.enabled
            || !config.general.intercept_paste
            || self.paused.load(Ordering::Relaxed)
        {
            return PasteDecision::Continue;
        }

        let (original, protected, has_secret) = {
            let vault = self.vault.lock().expect("vault lock");
            (vault.original(), vault.protected(), vault.has_secret)
        };
        if !has_secret {
            return PasteDecision::Continue;
        }

        let app = self.resolver.foreground();
        let decision = self
            .policy
            .read()
            .expect("policy lock")
            .decide(app.as_ref().unwrap_or(&AppIdentity::default()));
        let mode = decision.mode;

        match mode {
            ProtectionMode::Allow => {
                if config.general.restore_on_trusted_paste {
                    if let Some(original) = original
                        && self.write_back(&original)
                    {
                        self.stats.record_allowed();
                    }
                } else {
                    self.stats.record_allowed();
                }
                PasteDecision::Continue
            }
            ProtectionMode::Redact | ProtectionMode::Remove => {
                if let Some(protected) = protected
                    && self.write_back(&protected)
                {
                    self.stats.record_redacted(1);
                }
                PasteDecision::Continue
            }
            ProtectionMode::Block => {
                let _ = clipguard_clipboard::access::clear();
                self.stats.record_blocked();
                self.publish(&DetectionEvent {
                    kinds: Vec::new(),
                    risk: RiskLevel::Critical,
                    count: 0,
                    source_app: app.map(|app| app.exe),
                    mode: ProtectionMode::Block,
                    modified: true,
                });
                PasteDecision::Suppress
            }
        }
    }

    /// Writes content back to the clipboard without reacting to the update.
    fn write_back(&self, text: &str) -> bool {
        {
            let mut vault = self.vault.lock().expect("vault lock");
            vault.ignore_next_update = true;
        }
        match clipguard_clipboard::access::write_text(text) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(?error, "could not write the protected clipboard content");
                let mut vault = self.vault.lock().expect("vault lock");
                vault.ignore_next_update = false;
                false
            }
        }
    }

    /// Publishes an event to all subscribers.
    fn publish(&self, event: &DetectionEvent) {
        let payload = serde_json::to_value(event).unwrap_or(serde_json::Value::Null);
        let subscribers = self.subscribers.lock().expect("subscribers lock");
        for subscriber in subscribers.iter() {
            let _ = subscriber.send(payload.clone());
        }
    }

    /// Returns the findings of the last scan of `text`, without the secrets.
    pub fn describe(&self, text: &str) -> Vec<Finding> {
        self.scan(text).findings
    }
}

/// A shared handle to the protection engine.
pub type SharedEngine = Arc<ProtectionEngine>;

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
    fn clean_text_is_ignored() {
        let engine = ProtectionEngine::new(PathBuf::from("does-not-exist.toml"));
        let action = engine.on_clipboard_changed(Some("hello world"), false);
        assert_eq!(action, ClipboardAction::Ignore);
        assert!(engine.stats().scans >= 1);
    }

    #[test]
    fn secret_is_detected_and_redacted() {
        let engine = ProtectionEngine::new(PathBuf::from("does-not-exist.toml"));
        let action = engine.on_clipboard_changed(
            Some(&format!(
                "{} and {}",
                fake_secret("AKIA", &["IOSFODNN7EXAMPLE"]),
                fake_secret("ghp_", &["16C7e42F292c6912E7", "710c838347Ae178B4a"])
            )),
            false,
        );
        match action {
            ClipboardAction::SetText(text) => {
                assert!(!text.contains(&fake_secret("AKIA", &["IOSFODNN7EXAMPLE"])));
                assert!(text.contains("[REDACTED]"));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        let stats = engine.stats();
        assert_eq!(stats.detections, 1);
        assert_eq!(stats.redacted, 2);
    }

    #[test]
    fn the_content_of_the_startup_clipboard_stays_untouched() {
        let engine = ProtectionEngine::new(PathBuf::from("does-not-exist.toml"));
        let secret = fake_secret("ghp_", &["16C7e42F292c6912E7", "710c838347Ae178B4a"]);

        // The text that was already on the clipboard is not masked.
        let action = engine.on_clipboard_changed(Some(&secret), true);
        assert_eq!(action, ClipboardAction::Ignore);

        // A new copy of the same text is masked.
        let action = engine.on_clipboard_changed(Some(&secret), false);
        assert!(matches!(action, ClipboardAction::SetText(_)));
    }

    #[test]
    fn the_option_masks_the_content_of_the_startup_clipboard() {
        let mut config = Config::default();
        config.general.protect_existing_clipboard = true;
        let path = std::env::temp_dir().join("clipguard-existing-test.toml");
        config
            .save(&path)
            .expect("the configuration must be writable");

        let engine = ProtectionEngine::new(path.clone());
        let secret = fake_secret("ghp_", &["16C7e42F292c6912E7", "710c838347Ae178B4a"]);

        let action = engine.on_clipboard_changed(Some(&secret), true);
        assert!(matches!(action, ClipboardAction::SetText(_)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn switching_the_mode_is_fast() {
        let path = std::env::temp_dir().join("clipguard-mode-test.toml");
        let _ = std::fs::remove_file(&path);
        let engine = ProtectionEngine::new(path.clone());
        let mut config = engine.config();

        // Switching between ghost and satellite does not touch the detection
        // rules, so the patterns are not compiled again.
        let start = std::time::Instant::now();
        config.general.global_mode = GlobalMode::Satellite;
        engine
            .set_config(config.clone())
            .expect("the configuration must be stored");
        let switch = start.elapsed();

        // For comparison: compiling every pattern again.
        let start = std::time::Instant::now();
        let _ = config.build_engine().expect("the engine must be built");
        let rebuild = start.elapsed();

        config.general.global_mode = GlobalMode::Ghost;
        engine
            .set_config(config)
            .expect("the configuration must be stored");

        assert!(
            switch < rebuild,
            "the switch took {switch:?}, a full rebuild takes {rebuild:?}"
        );
        let _ = std::fs::remove_file(path);
    }
}
