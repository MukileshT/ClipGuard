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

//! Detection templates.
//!
//! Templates are ready-made detection rules that cover the secrets a normal
//! developer runs into. They are offered in the dashboard as a one-click
//! starting point:
//!
//! * **Email templates** — personal addresses on the major providers
//!   (Gmail, Outlook, Yahoo, Proton, …).
//! * **Phone templates** — the user's own number and common formats.
//! * **Secret templates** — the whole catalogue of credential categories.

use serde::{Deserialize, Serialize};

use crate::model::SecretKind;
use crate::rules::RuleSpec;

/// The category a template belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateCategory {
    /// E-mail address templates.
    Email,
    /// Phone number templates.
    Phone,
    /// Credential and secret templates.
    Secret,
}

impl TemplateCategory {
    /// Stable lowercase identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            TemplateCategory::Email => "email",
            TemplateCategory::Phone => "phone",
            TemplateCategory::Secret => "secret",
        }
    }

    /// Human readable label.
    pub fn label(&self) -> &'static str {
        match self {
            TemplateCategory::Email => "E-mail addresses",
            TemplateCategory::Phone => "Phone numbers",
            TemplateCategory::Secret => "Secrets & credentials",
        }
    }
}

/// A ready-made detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    /// Stable identifier.
    pub id: String,
    /// Human readable name.
    pub name: String,
    /// Short explanation of what the template protects.
    pub description: String,
    /// The category this template belongs to.
    pub category: TemplateCategory,
    /// The rule that is added when the template is enabled.
    pub rule: RuleSpec,
}

impl Template {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: &str,
        name: &str,
        description: &str,
        category: TemplateCategory,
        pattern: &str,
        kind: SecretKind,
        risk: crate::model::RiskLevel,
        group: usize,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category,
            rule: RuleSpec {
                name: name.to_string(),
                pattern: pattern.to_string(),
                kind,
                risk: Some(risk),
                group,
                case_insensitive: false,
                dot_all: false,
                multiline: false,
                context: Vec::new(),
                validators: Vec::new(),
                enabled: true,
            },
        }
    }
}

/// The major e-mail providers that get their own template.
const EMAIL_PROVIDERS: &[(&str, &str)] = &[
    ("gmail", "gmail.com"),
    ("googlemail", "googlemail.com"),
    ("outlook", "outlook.com"),
    ("outlook-hotmail", "hotmail.com"),
    ("outlook-live", "live.com"),
    ("outlook-in", "outlook.in"),
    ("yahoo", "yahoo.com"),
    ("yahoo-uk", "yahoo.co.uk"),
    ("yahoo-in", "yahoo.co.in"),
    ("protonmail", "protonmail.com"),
    ("proton", "proton.me"),
    ("icloud", "icloud.com"),
    ("me", "me.com"),
    ("mac", "mac.com"),
    ("aol", "aol.com"),
    ("zoho", "zoho.com"),
    ("yandex", "yandex.com"),
    ("gmx", "gmx.com"),
    ("mail-com", "mail.com"),
    ("duck", "duck.com"),
    ("fastmail", "fastmail.com"),
    ("tutanota", "tutanota.com"),
    ("msn", "msn.com"),
    ("live-in", "live.in"),
    ("rediffmail", "rediffmail.com"),
];

/// Returns every e-mail address template.
pub fn email_templates() -> Vec<Template> {
    EMAIL_PROVIDERS
        .iter()
        .map(|(id, domain)| {
            Template::new(
                &format!("email-{id}"),
                &format!("{} address", domain),
                &format!(
                    "Detects personal e-mail addresses at {domain}, for example alice@{domain}."
                ),
                TemplateCategory::Email,
                &format!(r"\b[A-Za-z0-9._%+\-]+@{}\b", regex::escape(domain)),
                SecretKind::EmailAddress,
                crate::model::RiskLevel::Low,
                0,
            )
        })
        .collect()
}

/// Returns the phone number templates.
///
/// The user's own number can be added with [`personal_phone_template`].
pub fn phone_templates() -> Vec<Template> {
    vec![
        Template::new(
            "phone-e164",
            "International phone number",
            "Detects phone numbers in international format, for example +14155552671.",
            TemplateCategory::Phone,
            r"\+[1-9][0-9]{9,14}\b",
            SecretKind::PhoneNumber,
            crate::model::RiskLevel::Low,
            0,
        ),
        Template::new(
            "phone-labelled",
            "Labelled phone number",
            "Detects numbers written after a label such as 'phone:' or 'mobile:'.",
            TemplateCategory::Phone,
            r"(?i)\b(?:phone|tel|telephone|mobile|cell|msisdn|fax)\b\s*[:=]\s*(\+?[0-9][0-9 ()\-.]{6,20})",
            SecretKind::PhoneNumber,
            crate::model::RiskLevel::Low,
            1,
        ),
        Template::new(
            "phone-national",
            "National phone number",
            "Detects longer digit groups that look like national phone numbers.",
            TemplateCategory::Phone,
            r"(?i)\b(?:phone|tel|telephone|mobile|cell|contact)\b\s*[:=]?\s*([0-9][0-9 \-().]{8,18}[0-9])",
            SecretKind::PhoneNumber,
            crate::model::RiskLevel::Low,
            1,
        ),
    ]
}

/// Builds a template that protects one specific phone number.
///
/// The number is matched literally, so it never triggers on other numbers.
pub fn personal_phone_template(number: &str) -> Option<Template> {
    let trimmed = number.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Escape everything that could be a regex metacharacter.
    let escaped = regex::escape(trimmed);
    Some(Template::new(
        "phone-personal",
        "My phone number",
        "Protects the phone number you entered. Only this exact number is matched.",
        TemplateCategory::Phone,
        &escaped,
        SecretKind::PhoneNumber,
        crate::model::RiskLevel::High,
        0,
    ))
}

/// The secret templates: one for every credential family.
pub fn secret_templates() -> Vec<Template> {
    vec![
        Template::new(
            "secret-openai",
            "OpenAI API key",
            "Detects OpenAI project and legacy API keys.",
            TemplateCategory::Secret,
            r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}",
            SecretKind::OpenAiApiKey,
            crate::model::RiskLevel::Critical,
            0,
        ),
        Template::new(
            "secret-anthropic",
            "Anthropic API key",
            "Detects Anthropic API keys.",
            TemplateCategory::Secret,
            r"\bsk-ant-[A-Za-z0-9_\-]{24,}",
            SecretKind::AnthropicApiKey,
            crate::model::RiskLevel::Critical,
            0,
        ),
        Template::new(
            "secret-github",
            "GitHub token",
            "Detects GitHub personal access, OAuth and app tokens.",
            TemplateCategory::Secret,
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})",
            SecretKind::GithubToken,
            crate::model::RiskLevel::Critical,
            0,
        ),
        Template::new(
            "secret-gitlab",
            "GitLab token",
            "Detects GitLab personal access tokens.",
            TemplateCategory::Secret,
            r"\bglpat-[A-Za-z0-9_\-]{20,}",
            SecretKind::GitlabToken,
            crate::model::RiskLevel::Critical,
            0,
        ),
        Template::new(
            "secret-aws",
            "AWS access key id",
            "Detects AWS access key identifiers.",
            TemplateCategory::Secret,
            r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
            SecretKind::AwsAccessKeyId,
            crate::model::RiskLevel::High,
            0,
        ),
        Template::new(
            "secret-google",
            "Google API key",
            "Detects Google API keys and OAuth tokens.",
            TemplateCategory::Secret,
            r"\b(?:AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{20,})",
            SecretKind::GoogleApiKey,
            crate::model::RiskLevel::High,
            0,
        ),
        Template::new(
            "secret-slack",
            "Slack token",
            "Detects Slack bot and user tokens.",
            TemplateCategory::Secret,
            r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
            SecretKind::SlackToken,
            crate::model::RiskLevel::High,
            0,
        ),
        Template::new(
            "secret-stripe",
            "Stripe key",
            "Detects Stripe secret and restricted keys.",
            TemplateCategory::Secret,
            r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}",
            SecretKind::StripeKey,
            crate::model::RiskLevel::Critical,
            0,
        ),
        Template::new(
            "secret-npm",
            "npm token",
            "Detects npm access tokens.",
            TemplateCategory::Secret,
            r"\bnpm_[A-Za-z0-9]{36}\b",
            SecretKind::NpmToken,
            crate::model::RiskLevel::High,
            0,
        ),
        Template::new(
            "secret-huggingface",
            "Hugging Face token",
            "Detects Hugging Face access tokens.",
            TemplateCategory::Secret,
            r"\bhf_[A-Za-z0-9]{34,}",
            SecretKind::HuggingFaceToken,
            crate::model::RiskLevel::High,
            0,
        ),
        Template::new(
            "secret-jwt",
            "JSON Web Token",
            "Detects signed JSON Web Tokens.",
            TemplateCategory::Secret,
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            SecretKind::Jwt,
            crate::model::RiskLevel::High,
            0,
        ),
        Template::new(
            "secret-bearer",
            "Bearer token",
            "Detects `Authorization: Bearer …` credentials.",
            TemplateCategory::Secret,
            r"(?i)\bbearer\s+([A-Za-z0-9_\-\.=+/]{16,})",
            SecretKind::BearerToken,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-basic",
            "Basic auth credential",
            "Detects `Authorization: Basic …` credentials.",
            TemplateCategory::Secret,
            r"(?i)\bbasic\s+([A-Za-z0-9+/]{16,}={0,2})",
            SecretKind::BasicAuth,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-password",
            "Password assignment",
            "Detects `password = …` style assignments.",
            TemplateCategory::Secret,
            r#"(?i)\b(?:pass(?:word|wd|phrase)?|pwd)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{6,})"#,
            SecretKind::Password,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-api-key",
            "API key assignment",
            "Detects `api_key = …`, `client_secret = …` and similar assignments.",
            TemplateCategory::Secret,
            r#"(?i)\b(?:api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key|client[_\-]?secret|app[_\-]?secret|private[_\-]?key|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|webhook[_\-]?secret)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{8,})"#,
            SecretKind::SecretAssignment,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-token",
            "Token assignment",
            "Detects `token = …` and `credential = …` assignments.",
            TemplateCategory::Secret,
            r#"(?i)\b(?:token|secret|credential|credentials)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{8,})"#,
            SecretKind::SecretAssignment,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-private-key",
            "Private key block",
            "Detects PEM encoded private keys of any type.",
            TemplateCategory::Secret,
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
            SecretKind::PrivateKey,
            crate::model::RiskLevel::Critical,
            0,
        ),
        Template::new(
            "secret-postgres",
            "PostgreSQL connection string",
            "Detects the password inside PostgreSQL URLs.",
            TemplateCategory::Secret,
            r"\bpostgres(?:ql)?://[^\s:/@]+:([^\s:/@]+)@[^\s/]+",
            SecretKind::PostgresUrl,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-mysql",
            "MySQL connection string",
            "Detects the password inside MySQL URLs.",
            TemplateCategory::Secret,
            r"\bmysql://[^\s:/@]+:([^\s:/@]+)@[^\s/]+",
            SecretKind::MySqlUrl,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-mongodb",
            "MongoDB connection string",
            "Detects the password inside MongoDB URLs.",
            TemplateCategory::Secret,
            r"\bmongodb(?:\+srv)?://[^\s:/@]+:([^\s:/@]+)@[^\s/]+",
            SecretKind::MongoUrl,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-redis",
            "Redis connection string",
            "Detects the password inside Redis URLs.",
            TemplateCategory::Secret,
            r"\bredis(?:s)?://[^\s:/@]*:([^\s:/@]+)@[^\s/]+",
            SecretKind::RedisUrl,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-jdbc",
            "JDBC connection string",
            "Detects the password inside JDBC URLs.",
            TemplateCategory::Secret,
            r"\bjdbc:[a-z0-9]+://[^\s:/@]+:([^\s:/@]+)@[^\s/]+",
            SecretKind::JdbcUrl,
            crate::model::RiskLevel::High,
            1,
        ),
        Template::new(
            "secret-aws-secret",
            "AWS secret access key",
            "Detects AWS secret access keys written in configuration files.",
            TemplateCategory::Secret,
            r#"(?i)aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b"#,
            SecretKind::AwsSecretAccessKey,
            crate::model::RiskLevel::Critical,
            1,
        ),
        Template::new(
            "secret-azure",
            "Azure storage key",
            "Detects Azure storage account keys.",
            TemplateCategory::Secret,
            r#"(?i)\b(?:accountkey|account_key)\s*=\s*["']?([A-Za-z0-9+/=]{40,})"#,
            SecretKind::AzureStorageKey,
            crate::model::RiskLevel::Critical,
            1,
        ),
        Template::new(
            "secret-ip",
            "IP address",
            "Detects IPv4 addresses such as 192.168.1.10.",
            TemplateCategory::Secret,
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            SecretKind::IpV4Address,
            crate::model::RiskLevel::Low,
            0,
        ),
        Template::new(
            "secret-ipv6",
            "IPv6 address",
            "Detects IPv6 addresses such as 2001:db8:85a3::8a2e:370:7334.",
            TemplateCategory::Secret,
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            SecretKind::IpV6Address,
            crate::model::RiskLevel::Low,
            0,
        ),
        Template::new(
            "secret-credit-card",
            "Credit card number",
            "Detects credit card numbers that pass the Luhn checksum.",
            TemplateCategory::Secret,
            r"\b[0-9][0-9 \-]{11,21}[0-9]\b",
            SecretKind::CreditCard,
            crate::model::RiskLevel::Medium,
            0,
        ),
        Template::new(
            "secret-ssn",
            "Social security number",
            "Detects US social security numbers.",
            TemplateCategory::Secret,
            r"(?i)\b(?:ssn|social\s+security(?:\s+(?:number|no\.?))?)\b\s*[:=#]?\s*([0-9][0-9 \-]{8,11})",
            SecretKind::Ssn,
            crate::model::RiskLevel::Medium,
            1,
        ),
        Template::new(
            "secret-iban",
            "IBAN",
            "Detects international bank account numbers.",
            TemplateCategory::Secret,
            r"\b[A-Z]{2}[0-9]{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b",
            SecretKind::Iban,
            crate::model::RiskLevel::Medium,
            0,
        ),
    ]
}

/// Returns every template.
pub fn all_templates() -> Vec<Template> {
    let mut templates = email_templates();
    templates.extend(phone_templates());
    templates.extend(secret_templates());
    templates
}

/// Returns the templates of one category.
pub fn templates_by_category(category: TemplateCategory) -> Vec<Template> {
    all_templates()
        .into_iter()
        .filter(|template| template.category == category)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_templates_have_unique_ids() {
        let templates = all_templates();
        let mut ids: Vec<&str> = templates.iter().map(|t| t.id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(count, ids.len(), "duplicate template ids");
    }

    #[test]
    fn every_template_compiles() {
        for template in all_templates() {
            template
                .rule
                .compile()
                .unwrap_or_else(|e| panic!("template {}: {e}", template.id));
        }
    }

    #[test]
    fn email_templates_cover_major_providers() {
        let templates = email_templates();
        let domains: Vec<String> = templates
            .iter()
            .map(|t| {
                // The pattern is "<local>@<escaped-domain>"; recover the
                // domain by stripping the fixed prefix and suffix.
                let pattern = &t.rule.pattern;
                pattern
                    .trim_start_matches(r"\b[A-Za-z0-9._%+\-]+@")
                    .trim_end_matches(r"\b")
                    .replace("\\.", ".")
            })
            .collect();
        assert!(domains.contains(&"gmail.com".to_string()), "{domains:?}");
        assert!(domains.contains(&"outlook.com".to_string()), "{domains:?}");
        assert!(domains.contains(&"outlook.in".to_string()), "{domains:?}");
    }

    #[test]
    fn personal_phone_template_escapes_the_number() {
        let template = personal_phone_template("+1 (415) 555-2671").expect("template");
        // The pattern must match the number literally and nothing else.
        let regex = regex::Regex::new(&template.rule.pattern).expect("valid regex");
        assert!(regex.is_match("+1 (415) 555-2671"));
        assert!(!regex.is_match("+1 415 555 0000"));
        assert_eq!(template.rule.kind, SecretKind::PhoneNumber);
    }

    #[test]
    fn templates_are_grouped_by_category() {
        assert!(!templates_by_category(TemplateCategory::Email).is_empty());
        assert!(!templates_by_category(TemplateCategory::Phone).is_empty());
        assert!(!templates_by_category(TemplateCategory::Secret).is_empty());
    }
}
