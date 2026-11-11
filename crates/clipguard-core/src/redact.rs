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

//! Applying a protection decision to the clipboard payload.
//!
//! Redaction never copies the secret into a new allocation beyond the
//! replacement itself, and the resulting `String` is the only place where
//! protected content lives.

use zeroize::Zeroize;

use crate::model::{Finding, ProtectionMode, SecretKind};

/// Options controlling how protected content is rewritten.
#[derive(Debug, Clone)]
pub struct RedactionOptions {
    /// Placeholder used in `Redact` mode.
    ///
    /// The template may contain `{kind}`, `{kind_label}` and `{risk}` which are
    /// replaced with the metadata of the finding.
    pub placeholder: String,
    /// Whether `Remove` mode should also clean up dangling separators.
    pub tidy: bool,
}

impl Default for RedactionOptions {
    fn default() -> Self {
        Self {
            placeholder: "[REDACTED]".to_string(),
            tidy: true,
        }
    }
}

/// The result of applying a protection mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutcome {
    /// The rewritten text. `None` when the content was blocked.
    pub text: Option<String>,
    /// `true` when the content was modified.
    pub changed: bool,
    /// `true` when the paste was blocked.
    pub blocked: bool,
    /// Number of findings that were affected.
    pub affected: usize,
}

impl RedactionOutcome {
    fn unchanged(text: &str) -> Self {
        Self {
            text: Some(text.to_string()),
            changed: false,
            blocked: false,
            affected: 0,
        }
    }
}

/// Applies `mode` to `text` for the given `findings`.
pub fn apply(
    text: &str,
    findings: &[Finding],
    mode: ProtectionMode,
    options: &RedactionOptions,
) -> RedactionOutcome {
    match mode {
        ProtectionMode::Allow => RedactionOutcome::unchanged(text),
        ProtectionMode::Block => RedactionOutcome {
            text: None,
            changed: true,
            blocked: true,
            affected: findings.len(),
        },
        ProtectionMode::Redact => {
            if findings.is_empty() {
                return RedactionOutcome::unchanged(text);
            }
            let mut output = String::with_capacity(text.len() + 32);
            let mut cursor = 0usize;
            for finding in findings {
                let start = finding.span.start.min(text.len());
                let end = finding.span.end.min(text.len());
                if start < cursor {
                    continue;
                }
                output.push_str(&text[cursor..start]);
                output.push_str(&render_placeholder(&options.placeholder, finding));
                cursor = end;
            }
            output.push_str(&text[cursor..]);
            let changed = output != text;
            RedactionOutcome {
                text: Some(output),
                changed,
                blocked: false,
                affected: findings.len(),
            }
        }
        ProtectionMode::Remove => {
            if findings.is_empty() {
                return RedactionOutcome::unchanged(text);
            }
            let mut output = String::with_capacity(text.len());
            let mut cursor = 0usize;
            for finding in findings {
                let span = expand_span_for_quotes(text, finding.span.clone());
                let start = span.start.min(text.len());
                let end = span.end.min(text.len());
                if start < cursor {
                    continue;
                }
                output.push_str(&text[cursor..start]);
                cursor = end;
            }
            output.push_str(&text[cursor..]);
            if options.tidy {
                output = tidy_removed_text(&output);
            }
            let changed = output != text;
            RedactionOutcome {
                text: Some(output),
                changed,
                blocked: false,
                affected: findings.len(),
            }
        }
    }
}

/// Grows a span so that it also covers the quotes around it.
///
/// Removing the value of `password = "hunter2"` should leave `password =`
/// and not `password = ""`.
fn expand_span_for_quotes(text: &str, span: std::ops::Range<usize>) -> std::ops::Range<usize> {
    let mut start = span.start;
    let mut end = span.end;
    if start > 0 && end < text.len() {
        let before = text[start - 1..start].chars().next().unwrap_or('\0');
        let after = text[end..end + 1].chars().next().unwrap_or('\0');
        if (before == '"' || before == '\'') && before == after {
            start -= 1;
            end += 1;
        }
    }
    start..end
}

/// Expands the placeholder template for a finding.
fn render_placeholder(template: &str, finding: &Finding) -> String {
    if !template.contains('{') {
        return template.to_string();
    }
    template
        .replace("{kind}", finding.kind.as_str())
        .replace("{kind_label}", finding.kind.label())
        .replace("{risk}", finding.risk.as_str())
}

/// Cleans up artefacts left behind by a removal.
///
/// Removing `hunter2` from `password = "hunter2"` would leave
/// `password = ""`; this helper collapses empty quotes, duplicated separators
/// and dangling assignments.
pub fn tidy_removed_text(text: &str) -> String {
    let mut result = text.to_string();

    for quote in ['"', '\''] {
        let pair = format!("{quote}{quote}");
        while result.contains(&pair) {
            result = result.replace(&pair, "");
        }
    }

    // `key= ,` / `key=;` / `key= ` -> `key=`
    let mut previous = result.clone();
    while previous != result {
        previous = result.clone();
        result = result.replace("= ,", "=");
        result = result.replace("=;", "=");
        result = result.replace("= ,", "=");
    }

    while result.contains(",,") {
        result = result.replace(",,", ",");
    }
    while result.contains(";;") {
        result = result.replace(";;", ";");
    }
    while result.contains("  ") {
        result = result.replace("  ", " ");
    }
    result.trim_end().to_string()
}

/// Clears a buffer that may contain secret material.
pub fn wipe(buffer: &mut String) {
    buffer.zeroize();
}

/// Returns a redacted preview of `text` that is safe to display.
///
/// Only the placeholder and the surrounding context are shown; the secret
/// itself never leaves the engine.
pub fn preview(text: &str, findings: &[Finding], context_chars: usize) -> String {
    let mut preview = String::new();
    for finding in findings {
        let start = finding.span.start.saturating_sub(context_chars);
        let end = finding
            .span
            .end
            .saturating_add(context_chars)
            .min(text.len());
        let before = text.get(start..finding.span.start).unwrap_or("");
        let after = text.get(finding.span.end..end).unwrap_or("");
        preview.push_str(before);
        preview.push_str("[…]");
        preview.push_str(after);
        preview.push('\n');
    }
    preview
}

/// Convenience helper that redacts a single known secret kind.
pub fn redact_kind(
    text: &str,
    findings: &[Finding],
    kind: SecretKind,
    options: &RedactionOptions,
) -> RedactionOutcome {
    let filtered: Vec<Finding> = findings
        .iter()
        .filter(|finding| finding.kind == kind)
        .cloned()
        .collect();
    apply(text, &filtered, ProtectionMode::Redact, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RiskLevel;

    fn finding(start: usize, end: usize, kind: SecretKind) -> Finding {
        Finding {
            kind,
            risk: RiskLevel::High,
            span: start..end,
            rule: "test".into(),
            fingerprint: "deadbeefdeadbeef".into(),
            length: end - start,
        }
    }

    #[test]
    fn redact_replaces_span() {
        let text = "key=sk-abcdef";
        let findings = vec![finding(4, 14, SecretKind::OpenAiApiKey)];
        let outcome = apply(
            text,
            &findings,
            ProtectionMode::Redact,
            &RedactionOptions::default(),
        );
        assert_eq!(outcome.text.as_deref(), Some("key=[REDACTED]"));
        assert!(outcome.changed);
    }

    #[test]
    fn remove_strips_value_and_tidies() {
        let text = "password = \"hunter2\"";
        let findings = vec![finding(12, 19, SecretKind::Password)];
        let outcome = apply(
            text,
            &findings,
            ProtectionMode::Remove,
            &RedactionOptions::default(),
        );
        assert_eq!(outcome.text.as_deref(), Some("password ="));
    }

    #[test]
    fn block_produces_no_text() {
        let text = "secret";
        let findings = vec![finding(0, 6, SecretKind::Password)];
        let outcome = apply(
            text,
            &findings,
            ProtectionMode::Block,
            &RedactionOptions::default(),
        );
        assert!(outcome.blocked);
        assert!(outcome.text.is_none());
    }

    #[test]
    fn placeholder_template_is_expanded() {
        let options = RedactionOptions {
            placeholder: "[{kind}]".into(),
            tidy: true,
        };
        let text = "value";
        let findings = vec![finding(0, 5, SecretKind::Jwt)];
        let outcome = apply(text, &findings, ProtectionMode::Redact, &options);
        assert_eq!(outcome.text.as_deref(), Some("[jwt]"));
    }

    #[test]
    fn preview_never_contains_the_secret() {
        let text = "prefix sk-secretvalue suffix";
        let findings = vec![finding(7, 21, SecretKind::OpenAiApiKey)];
        let preview = preview(text, &findings, 4);
        assert!(!preview.contains("sk-secretvalue"));
    }
}
