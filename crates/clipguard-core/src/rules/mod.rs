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

//! Detection rules: the declarative description of a pattern and its
//! compilation into an executable matcher.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{RiskLevel, SecretKind};

pub mod builtin;

/// Additional validation applied to a candidate match before it is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validator {
    /// Luhn checksum (credit cards, IMEI, some card numbers).
    Luhn,
    /// ISO 13616 mod-97 checksum (IBAN).
    IbanMod97,
    /// Structural validation for US social security numbers.
    UsSsn,
    /// Rejects obvious placeholders such as `changeme` or `your_api_key`.
    NotPlaceholder,
    /// Rejects values that look like code references (`os.environ`, `Foo.Bar`).
    NotCodeReference,
}

impl Validator {
    /// Returns `true` when `value` passes this validator.
    pub fn accepts(&self, value: &str) -> bool {
        match self {
            Validator::Luhn => luhn_valid(value),
            Validator::IbanMod97 => iban_valid(value),
            Validator::UsSsn => ssn_valid(value),
            Validator::NotPlaceholder => !is_placeholder(value),
            Validator::NotCodeReference => !looks_like_code_reference(value),
        }
    }
}

/// Placeholder values that are obviously not real secrets.
const PLACEHOLDERS: &[&str] = &[
    "xxx",
    "xxxx",
    "xxxxxxxx",
    "changeme",
    "change_me",
    "change-me",
    "your_api_key",
    "your-api-key",
    "yourapikey",
    "your_secret",
    "your-password",
    "yourpassword",
    "your_password",
    "placeholder",
    "example",
    "example.com",
    "sample",
    "dummy",
    "redacted",
    "removed",
    "todo",
    "fixme",
    "none",
    "null",
    "nil",
    "undefined",
    "notasecret",
    "not_a_secret",
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "hunter2",
    "test",
    "testing",
    "foo",
    "bar",
    "baz",
    "abcdef",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
];

/// Markers that indicate a value is a template rather than a real secret.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "your_",
    "your-",
    "yourapi",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "example",
    "dummy",
    "sample",
    "xxxx",
    "redacted",
    "notasecret",
    "not_a_secret",
    "insert_",
    "insert-",
    "replace_",
    "replace-",
    "my_secret",
    "my_password",
    "my_token",
    "test_key",
    "test_token",
    "test_secret",
    "some_secret",
    "some_password",
    "fake_key",
    "fake_token",
    "todo",
    "fixme",
];

/// Returns `true` when the value is an obvious placeholder.
pub fn is_placeholder(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return true;
    }
    if PLACEHOLDERS.iter().any(|p| lowered == *p) {
        return true;
    }
    if PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return true;
    }
    // Values made up of a single repeated character.
    let mut chars = lowered.chars();
    if let Some(first) = chars.next()
        && chars.clone().all(|c| c == first)
    {
        return true;
    }
    // `<your-key-here>` style placeholders.
    if lowered.starts_with('<') && lowered.ends_with('>') {
        return true;
    }
    false
}

/// Returns `true` when the value looks like a source code reference rather
/// than a literal secret.
pub fn looks_like_code_reference(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.contains("::") || trimmed.contains("()") {
        return true;
    }
    if trimmed.contains('.') {
        // `os.environ`, `settings.SECRET`, `process.env` …
        let segments: Vec<&str> = trimmed.split('.').collect();
        if segments.len() >= 2
            && segments.iter().all(|segment| {
                segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        {
            return true;
        }
    }
    false
}

/// Computes the Luhn checksum of `value`, ignoring spaces and dashes.
pub fn luhn_valid(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    for (index, digit) in digits.iter().rev().enumerate() {
        let mut value = *digit;
        if index % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum.is_multiple_of(10)
}

/// Validates an IBAN using the ISO 13616 mod-97 algorithm.
pub fn iban_valid(value: &str) -> bool {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        let value = match ch.to_digit(10) {
            Some(digit) => digit,
            None => match ch {
                'A'..='Z' => u32::from(ch as u8 - b'A' + 10),
                _ => return false,
            },
        };
        remainder = (remainder * if value > 9 { 100 } else { 10 }) + value;
        remainder %= 97;
    }
    remainder == 1
}

/// Structurally validates a US social security number.
pub fn ssn_valid(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Declarative description of a detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSpec {
    /// Unique name of the rule.
    pub name: String,
    /// Regular expression source.
    pub pattern: String,
    /// Secret classification produced by this rule.
    #[serde(default = "default_kind")]
    pub kind: SecretKind,
    /// Risk assigned to findings produced by this rule.
    #[serde(default)]
    pub risk: Option<RiskLevel>,
    /// Capture group that contains the secret. `0` means the whole match.
    #[serde(default)]
    pub group: usize,
    /// Match case-insensitively.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Let `.` match newlines.
    #[serde(default)]
    pub dot_all: bool,
    /// Enable multi line mode (`^`/`$` match at line boundaries).
    #[serde(default)]
    pub multiline: bool,
    /// The match must be preceded by one of these keywords.
    #[serde(default)]
    pub context: Vec<String>,
    /// Extra validation applied to the matched value.
    #[serde(default)]
    pub validators: Vec<Validator>,
    /// Whether the rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_kind() -> SecretKind {
    SecretKind::Custom
}

fn default_true() -> bool {
    true
}

impl RuleSpec {
    /// Compiles the rule into an executable matcher.
    pub fn compile(&self) -> Result<CompiledRule> {
        let mut builder = regex::RegexBuilder::new(&self.pattern);
        builder
            .case_insensitive(self.case_insensitive)
            .dot_matches_new_line(self.dot_all)
            .multi_line(self.multiline)
            .size_limit(1 << 22);
        let regex = builder
            .build()
            .map_err(|source| CoreError::InvalidPattern {
                rule: self.name.clone(),
                source,
            })?;
        Ok(CompiledRule {
            name: self.name.clone(),
            kind: self.kind,
            risk: self.risk.unwrap_or_else(|| self.kind.default_risk()),
            regex,
            group: self.group,
            context: self
                .context
                .iter()
                .map(|context| context.to_ascii_lowercase())
                .collect(),
            validators: self.validators.clone(),
            enabled: self.enabled,
        })
    }
}

/// An executable detection rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Unique name of the rule.
    pub name: String,
    /// Secret classification produced by this rule.
    pub kind: SecretKind,
    /// Risk assigned to findings produced by this rule.
    pub risk: RiskLevel,
    /// Compiled regular expression.
    pub regex: regex::Regex,
    /// Capture group that contains the secret. `0` means the whole match.
    pub group: usize,
    /// Lower-cased keywords that must precede the match.
    pub context: Vec<String>,
    /// Extra validation applied to the matched value.
    pub validators: Vec<Validator>,
    /// Whether the rule is active.
    pub enabled: bool,
}

impl CompiledRule {
    /// Returns `true` when the match at `start` satisfies the context
    /// requirement.
    pub fn context_matches(&self, text: &str, start: usize) -> bool {
        if self.context.is_empty() {
            return true;
        }
        let window_start = start.saturating_sub(160);
        let window = text
            .get(window_start..start)
            .unwrap_or("")
            .to_ascii_lowercase();
        self.context.iter().any(|keyword| window.contains(keyword))
    }

    /// Returns `true` when the candidate passes all validators.
    pub fn validators_accept(&self, value: &str) -> bool {
        self.validators
            .iter()
            .all(|validator| validator.accepts(value))
    }
}

/// A named collection of rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSet {
    /// The rules in this set.
    pub rules: Vec<RuleSpec>,
}

impl RuleSet {
    /// Compiles every rule in the set.
    pub fn compile(&self) -> Result<Vec<CompiledRule>> {
        self.rules.iter().map(RuleSpec::compile).collect()
    }

    /// Adds a rule, replacing an existing rule with the same name.
    pub fn upsert(&mut self, spec: RuleSpec) {
        match self.rules.iter_mut().find(|rule| rule.name == spec.name) {
            Some(existing) => *existing = spec,
            None => self.rules.push(spec),
        }
    }

    /// Removes the rule with the given name, returning `true` when a rule was
    /// removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|rule| rule.name != name);
        self.rules.len() != before
    }
}
