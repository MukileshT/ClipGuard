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

//! The policy engine.
//!
//! The policy engine maps an *application* to a *protection mode*. It is
//! deliberately independent of any windowing or clipboard API so that it can
//! be unit tested and reused by every front end.

use serde::{Deserialize, Serialize};

use crate::model::{AppIdentity, FailSafe, GlobalMode, ProtectionMode};

/// A rule that applies a protection mode to a set of applications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    /// Stable identifier.
    #[serde(default)]
    pub id: String,
    /// Human readable name shown in the UI.
    #[serde(default)]
    pub label: String,
    /// Wildcard pattern matched against the executable name and full path.
    ///
    /// `*` matches any sequence of characters, `?` matches a single
    /// character. Matching is case insensitive.
    pub pattern: String,
    /// Protection mode applied to matching applications.
    pub mode: ProtectionMode,
    /// Trusted applications are never modified.
    #[serde(default)]
    pub trusted: bool,
    /// Whether the rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl AppRule {
    /// Creates a rule with default identifiers.
    pub fn new(pattern: impl Into<String>, mode: ProtectionMode) -> Self {
        let pattern = pattern.into();
        Self {
            id: slugify(&pattern),
            label: pattern.clone(),
            pattern,
            mode,
            trusted: false,
            enabled: true,
        }
    }

    /// Returns `true` when the rule matches the given application.
    pub fn matches(&self, app: &AppIdentity) -> bool {
        if !self.enabled {
            return false;
        }
        if wildcard_match(&self.pattern, &app.exe) {
            return true;
        }
        if let Some(path) = &app.path {
            if wildcard_match(&self.pattern, path) {
                return true;
            }
            let file_name = path.rsplit(['\\', '/']).next().unwrap_or(path);
            if wildcard_match(&self.pattern, file_name) {
                return true;
            }
        }
        false
    }

    /// Specificity of the match, higher wins.
    fn specificity(&self, app: &AppIdentity) -> u8 {
        let exact_exe = self.pattern.eq_ignore_ascii_case(&app.exe);
        let exact_path = app
            .path
            .as_ref()
            .is_some_and(|path| self.pattern.eq_ignore_ascii_case(path));
        match (exact_exe, exact_path) {
            (true, _) => 3,
            (false, true) => 2,
            _ => 1,
        }
    }
}

/// The outcome of a policy lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// The mode that must be applied.
    pub mode: ProtectionMode,
    /// Name of the rule that produced the decision, if any.
    pub matched_rule: Option<String>,
    /// `true` when the application matched a trusted rule.
    pub trusted: bool,
}

/// Decides how clipboard content must be treated per application.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Mode used when no application rule matches.
    pub default_mode: ProtectionMode,
    /// Determines when the decision is taken (copy time or paste time).
    pub global_mode: GlobalMode,
    /// Behaviour when the protection pipeline fails.
    pub fail_safe: FailSafe,
    /// Application rules, evaluated by specificity.
    pub app_rules: Vec<AppRule>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            default_mode: ProtectionMode::Redact,
            global_mode: GlobalMode::Ghost,
            fail_safe: FailSafe::Redact,
            app_rules: default_app_rules(),
        }
    }
}

impl PolicyEngine {
    /// Creates an engine with the supplied defaults.
    pub fn new(default_mode: ProtectionMode, global_mode: GlobalMode) -> Self {
        Self {
            default_mode,
            global_mode,
            fail_safe: FailSafe::Redact,
            app_rules: default_app_rules(),
        }
    }

    /// Resolves the protection mode for an application.
    pub fn decide(&self, app: &AppIdentity) -> PolicyDecision {
        let mut best: Option<(&AppRule, u8)> = None;
        for rule in &self.app_rules {
            if !rule.matches(app) {
                continue;
            }
            let score = rule.specificity(app);
            let better = match best {
                None => true,
                Some((current, current_score)) => {
                    if score != current_score {
                        score > current_score
                    } else {
                        // A trusted rule always wins a tie: it is an explicit
                        // user decision and must never be overridden by a
                        // generic rule that happens to match as well.
                        rule.trusted && !current.trusted
                    }
                }
            };
            if better {
                best = Some((rule, score));
            }
        }

        match best {
            Some((rule, _)) if rule.trusted => PolicyDecision {
                mode: ProtectionMode::Allow,
                matched_rule: Some(rule.label.clone()),
                trusted: true,
            },
            Some((rule, _)) => PolicyDecision {
                mode: rule.mode,
                matched_rule: Some(rule.label.clone()),
                trusted: false,
            },
            None => PolicyDecision {
                mode: self.default_mode,
                matched_rule: None,
                trusted: false,
            },
        }
    }

    /// Convenience wrapper returning only the protection mode.
    pub fn mode_for(&self, app: &AppIdentity) -> ProtectionMode {
        self.decide(app).mode
    }

    /// Returns `true` when the given application is explicitly trusted.
    pub fn is_trusted(&self, app: &AppIdentity) -> bool {
        self.decide(app).trusted
    }
}

/// The default set of application rules.
///
/// The list is intentionally conservative: only applications that are known to
/// benefit from strict protection are listed, and trusted entries are limited
/// to password managers where the user explicitly asked for an exception.
pub fn default_app_rules() -> Vec<AppRule> {
    vec![
        AppRule {
            id: "trusted-password-managers".into(),
            label: "Password managers".into(),
            pattern: "*1Password.exe".into(),
            mode: ProtectionMode::Allow,
            trusted: true,
            enabled: true,
        },
        AppRule {
            id: "trusted-keepass".into(),
            label: "KeePass".into(),
            pattern: "*KeePassXC.exe".into(),
            mode: ProtectionMode::Allow,
            trusted: true,
            enabled: true,
        },
        AppRule {
            id: "trusted-bitwarden".into(),
            label: "Bitwarden".into(),
            pattern: "*Bitwarden.exe".into(),
            mode: ProtectionMode::Allow,
            trusted: true,
            enabled: true,
        },
        AppRule {
            id: "ai-assistants".into(),
            label: "AI assistants".into(),
            pattern: "{ChatGPT,Claude,Cursor,Copilot,Codeium,Windsurf}.exe".into(),
            mode: ProtectionMode::Block,
            trusted: false,
            enabled: true,
        },
        AppRule {
            id: "terminals".into(),
            label: "Terminals".into(),
            pattern: "{WindowsTerminal,wezterm-gui,alacritty,cmd,Hyper}.exe".into(),
            mode: ProtectionMode::Redact,
            trusted: false,
            enabled: true,
        },
        AppRule {
            id: "browsers".into(),
            label: "Browsers".into(),
            pattern: "{chrome,msedge,firefox,brave,opera}.exe".into(),
            mode: ProtectionMode::Redact,
            trusted: false,
            enabled: true,
        },
        AppRule {
            id: "editors".into(),
            label: "Code editors".into(),
            pattern: "{Code,Code - Insiders,code,devenv,idea64}.exe".into(),
            mode: ProtectionMode::Redact,
            trusted: false,
            enabled: true,
        },
    ]
}

/// Matches `text` against a wildcard `pattern`.
///
/// Supports `*` (any sequence) and `?` (exactly one character) and is case
/// insensitive.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let text: Vec<char> = text.to_ascii_lowercase().chars().collect();

    // Brace expansion: `{a,b,c}` becomes several alternatives.
    if let Some(expanded) = expand_braces(&pattern) {
        return expanded.iter().any(|alt| wildcard_match_chars(alt, &text));
    }
    wildcard_match_chars(&pattern, &text)
}

/// Expands `{a,b}` alternatives into a list of patterns.
fn expand_braces(pattern: &[char]) -> Option<Vec<Vec<char>>> {
    let open = pattern.iter().position(|c| *c == '{')?;
    let close = pattern
        .iter()
        .skip(open + 1)
        .position(|c| *c == '}')
        .map(|index| index + open + 1)?;
    let prefix = &pattern[..open];
    let suffix = &pattern[close + 1..];
    let body: String = pattern[open + 1..close].iter().collect();

    let mut alternatives = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    let mut parts = Vec::new();
    for ch in body.chars() {
        match ch {
            '{' => {
                depth += 1;
                current.push(ch);
            }
            '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    parts.push(current);

    for part in parts {
        let mut combined = prefix.to_vec();
        combined.extend(part.chars());
        combined.extend_from_slice(suffix);
        alternatives.push(combined);
    }
    Some(alternatives)
}

/// Classic iterative wildcard matcher.
fn wildcard_match_chars(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = p;
            mark = t;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Turns an arbitrary string into a stable, URL friendly identifier.
pub fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_dash = true;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "rule".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_star_matches() {
        assert!(wildcard_match("*.exe", "code.exe"));
        assert!(wildcard_match("Code*", "Code.exe"));
        assert!(!wildcard_match("Code*", "NotCode.exe"));
    }

    #[test]
    fn wildcard_question_mark_matches_single_char() {
        assert!(wildcard_match("co?e.exe", "code.exe"));
        assert!(wildcard_match("co?e.exe", "cooe.exe"));
        assert!(!wildcard_match("co?e.exe", "coe.exe"));
    }

    #[test]
    fn brace_expansion_matches_alternatives() {
        assert!(wildcard_match("{a,b}.exe", "a.exe"));
        assert!(wildcard_match("{a,b}.exe", "b.exe"));
        assert!(!wildcard_match("{a,b}.exe", "c.exe"));
    }

    #[test]
    fn trusted_rule_overrides_protective_rule() {
        let engine = PolicyEngine {
            default_mode: ProtectionMode::Redact,
            global_mode: GlobalMode::Satellite,
            fail_safe: FailSafe::Redact,
            app_rules: vec![
                AppRule::new("*secretapp.exe", ProtectionMode::Block),
                AppRule {
                    id: "trusted".into(),
                    label: "trusted".into(),
                    pattern: "*secretapp.exe".into(),
                    mode: ProtectionMode::Allow,
                    trusted: true,
                    enabled: true,
                },
            ],
        };
        let decision = engine.decide(&AppIdentity::from_exe("secretapp.exe"));
        assert_eq!(decision.mode, ProtectionMode::Allow);
        assert!(decision.trusted);
    }

    #[test]
    fn default_is_used_without_matching_rule() {
        let engine = PolicyEngine {
            default_mode: ProtectionMode::Remove,
            global_mode: GlobalMode::Ghost,
            fail_safe: FailSafe::Redact,
            app_rules: vec![],
        };
        assert_eq!(
            engine.mode_for(&AppIdentity::from_exe("unknown.exe")),
            ProtectionMode::Remove
        );
    }
}
