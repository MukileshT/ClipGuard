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

//! Built-in detection signatures.
//!
//! The rules below are intentionally conservative: a false negative (a secret
//! that slips through) is much more damaging than a false positive, but a
//! flood of false positives destroys trust in the tool. Every rule therefore
//! tries to anchor on a provider specific signature, a context keyword, or a
//! checksum.

use crate::model::{RiskLevel, SecretKind};
use crate::rules::{RuleSpec, Validator};

/// Keyword list shared by the entropy detector.
pub const ENTROPY_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "auth",
    "private_key",
    "access_key",
    "client_secret",
    "bearer",
];

/// Returns the catalogue of built-in rules.
// The rules are pushed one by one so that every entry keeps its comment.
#[allow(clippy::vec_init_then_push)]
pub fn builtin_rules() -> Vec<RuleSpec> {
    let mut rules: Vec<RuleSpec> = Vec::new();

    // ------------------------------------------------------------------ API
    rules.push(RuleSpec {
        name: "anthropic-api-key".into(),
        pattern: r"sk-ant-[A-Za-z0-9_\-]{24,}".into(),
        kind: SecretKind::AnthropicApiKey,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "openai-api-key".into(),
        pattern: r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}".into(),
        kind: SecretKind::OpenAiApiKey,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "google-api-key".into(),
        pattern: r"\bAIza[0-9A-Za-z_\-]{35}\b".into(),
        kind: SecretKind::GoogleApiKey,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "google-oauth-token".into(),
        pattern: r"\bya29\.[0-9A-Za-z_\-]{20,}".into(),
        kind: SecretKind::GoogleOAuthToken,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "aws-access-key-id".into(),
        pattern: r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b".into(),
        kind: SecretKind::AwsAccessKeyId,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "aws-secret-access-key".into(),
        pattern: r#"(?i)aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b"#.into(),
        kind: SecretKind::AwsSecretAccessKey,
        risk: Some(RiskLevel::Critical),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "azure-storage-connection-string".into(),
        pattern: r"DefaultEndpointsProtocol=https;AccountName=[^;\r\n]{1,256};AccountKey=[A-Za-z0-9+/=]{40,}".into(),
        kind: SecretKind::AzureConnectionString,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "azure-storage-key".into(),
        pattern: r#"(?i)\b(?:accountkey|account_key)\s*=\s*["']?([A-Za-z0-9+/=]{40,})"#.into(),
        kind: SecretKind::AzureStorageKey,
        risk: Some(RiskLevel::Critical),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "github-token".into(),
        pattern: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})".into(),
        kind: SecretKind::GithubToken,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "gitlab-token".into(),
        pattern: r"\bglpat-[A-Za-z0-9_\-]{20,}".into(),
        kind: SecretKind::GitlabToken,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "slack-token".into(),
        pattern: r"\bxox[abposr]-[A-Za-z0-9\-]{10,}".into(),
        kind: SecretKind::SlackToken,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "stripe-key".into(),
        pattern: r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}".into(),
        kind: SecretKind::StripeKey,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "twilio-key".into(),
        pattern: r"\b(?:SK[0-9a-fA-F]{32}|AC[0-9a-f]{32})\b".into(),
        kind: SecretKind::TwilioKey,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "sendgrid-key".into(),
        pattern: r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}".into(),
        kind: SecretKind::SendgridKey,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "discord-token".into(),
        pattern: r"\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}".into(),
        kind: SecretKind::DiscordToken,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "npm-token".into(),
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b".into(),
        kind: SecretKind::NpmToken,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "huggingface-token".into(),
        pattern: r"\bhf_[A-Za-z0-9]{34,}".into(),
        kind: SecretKind::HuggingFaceToken,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "firebase-credential".into(),
        pattern: r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}".into(),
        kind: SecretKind::FirebaseCredential,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "gcp-service-account".into(),
        pattern: r#"(?i)"type"\s*:\s*"service_account""#.into(),
        kind: SecretKind::GcpServiceAccount,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec!["service_account".into()],
        validators: vec![],
        enabled: true,
    });

    // ------------------------------------------------------- authentication
    rules.push(RuleSpec {
        name: "json-web-token".into(),
        pattern: r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}".into(),
        kind: SecretKind::Jwt,
        risk: Some(RiskLevel::High),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "bearer-token".into(),
        pattern: r"(?i)\bbearer\s+([A-Za-z0-9_\-\.=+/]{16,})".into(),
        kind: SecretKind::BearerToken,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "basic-auth".into(),
        pattern: r"(?i)\bbasic\s+([A-Za-z0-9+/]{16,}={0,2})".into(),
        kind: SecretKind::BasicAuth,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "oauth-token".into(),
        pattern: r#"(?i)\b(?:access_token|refresh_token|id_token|oauth_token|bearer_token)\b\s*[:=]\s*["']?([A-Za-z0-9_\-\.=+/]{16,})"#.into(),
        kind: SecretKind::OAuthToken,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "session-cookie".into(),
        pattern: r"(?i)\b(?:set-)?cookie\b[^\r\n]{0,60}?\b(?:sess|session|sid|auth|jwt)[a-z0-9_]*=([A-Za-z0-9_\-\.%+/=]{16,})".into(),
        kind: SecretKind::SessionCookie,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });

    // ---------------------------------------------------------- credentials
    rules.push(RuleSpec {
        name: "private-key-pem".into(),
        pattern: r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----".into(),
        kind: SecretKind::PrivateKey,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "ssh-private-key".into(),
        pattern: r"PuTTY-User-Key-File-[0-9]+:[^\n]*\n[\s\S]*?-----END (?:RSA |SSH2 |OPENSSH )?PRIVATE KEY-----".into(),
        kind: SecretKind::SshPrivateKey,
        risk: Some(RiskLevel::Critical),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "certificate-pem".into(),
        pattern: r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----".into(),
        kind: SecretKind::Certificate,
        risk: Some(RiskLevel::Medium),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "password-assignment".into(),
        pattern: r#"(?i)\b(?:pass(?:word|wd|phrase)?|pwd)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{6,})"#
            .into(),
        kind: SecretKind::Password,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![Validator::NotPlaceholder, Validator::NotCodeReference],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "api-key-assignment".into(),
        pattern: r#"(?i)\b(?:api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key|client[_\-]?secret|app[_\-]?secret|private[_\-]?key|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|webhook[_\-]?secret)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{8,})"#.into(),
        kind: SecretKind::SecretAssignment,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![Validator::NotPlaceholder, Validator::NotCodeReference],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "token-assignment".into(),
        pattern: r#"(?i)\b(?:token|secret|credential|credentials)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{8,})"#.into(),
        kind: SecretKind::SecretAssignment,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![Validator::NotPlaceholder, Validator::NotCodeReference],
        enabled: true,
    });

    // ------------------------------------------------------------ databases
    rules.push(RuleSpec {
        name: "postgres-url".into(),
        pattern: r"\bpostgres(?:ql)?://[^\s:/@]+:([^\s:/@]+)@[^\s/]+".into(),
        kind: SecretKind::PostgresUrl,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "mysql-url".into(),
        pattern: r"\bmysql://[^\s:/@]+:([^\s:/@]+)@[^\s/]+".into(),
        kind: SecretKind::MySqlUrl,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "mongodb-url".into(),
        pattern: r"\bmongodb(?:\+srv)?://[^\s:/@]+:([^\s:/@]+)@[^\s/]+".into(),
        kind: SecretKind::MongoUrl,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "redis-url".into(),
        pattern: r"\bredis(?:s)?://[^\s:/@]*:([^\s:/@]+)@[^\s/]+".into(),
        kind: SecretKind::RedisUrl,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "sqlserver-url".into(),
        pattern: r"\b(?:sqlserver|mssql)://[^\s:/@]+:([^\s:/@]+)@[^\s/]+".into(),
        kind: SecretKind::SqlServerUrl,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "jdbc-url".into(),
        pattern: r"\bjdbc:[a-z0-9]+://[^\s:/@]+:([^\s:/@]+)@[^\s/]+".into(),
        kind: SecretKind::JdbcUrl,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "connection-string-password".into(),
        pattern: r#"(?i)\b(?:server|data\s+source|host)\s*=\s*[^;\r\n]{1,128};[^\r\n]{0,160}?\bpassword\s*=\s*([^\s;"',]{3,})"#.into(),
        kind: SecretKind::ConnectionString,
        risk: Some(RiskLevel::High),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });

    // ------------------------------------------------------------ personal
    rules.push(RuleSpec {
        name: "email-address".into(),
        pattern: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}\b".into(),
        kind: SecretKind::EmailAddress,
        risk: Some(RiskLevel::Low),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "phone-number-e164".into(),
        pattern: r"\+[1-9][0-9]{9,14}\b".into(),
        kind: SecretKind::PhoneNumber,
        risk: Some(RiskLevel::Low),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "phone-number-labelled".into(),
        pattern: r"(?i)\b(?:phone|tel|telephone|mobile|cell|msisdn|fax)\b\s*[:=]\s*(\+?[0-9][0-9 ()\-.]{6,20})".into(),
        kind: SecretKind::PhoneNumber,
        risk: Some(RiskLevel::Low),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "credit-card-number".into(),
        pattern: r"\b[0-9][0-9 \-]{11,21}[0-9]\b".into(),
        kind: SecretKind::CreditCard,
        risk: Some(RiskLevel::Medium),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![Validator::Luhn],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "social-security-number".into(),
        pattern: r"(?i)\b(?:ssn|social\s+security(?:\s+(?:number|no\.?))?)\b\s*[:=#]?\s*([0-9][0-9 \-]{8,11})".into(),
        kind: SecretKind::Ssn,
        risk: Some(RiskLevel::Medium),
        group: 1,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![Validator::UsSsn],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "iban".into(),
        pattern: r"\b[A-Z]{2}[0-9]{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b".into(),
        kind: SecretKind::Iban,
        risk: Some(RiskLevel::Medium),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![Validator::IbanMod97],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "ipv4-address".into(),
        pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b".into(),
        kind: SecretKind::IpV4Address,
        risk: Some(RiskLevel::Low),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });
    rules.push(RuleSpec {
        name: "ipv6-address".into(),
        pattern: r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b".into(),
        kind: SecretKind::IpV6Address,
        risk: Some(RiskLevel::Low),
        group: 0,
        case_insensitive: false,
        dot_all: false,
        multiline: false,
        context: vec![],
        validators: vec![],
        enabled: true,
    });

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtin_rules_compile() {
        for rule in builtin_rules() {
            rule.compile()
                .unwrap_or_else(|err| panic!("rule {}: {err}", rule.name));
        }
    }

    #[test]
    fn rule_names_are_unique() {
        let rules = builtin_rules();
        let mut names: Vec<&str> = rules.iter().map(|rule| rule.name.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(count, names.len(), "duplicate built-in rule names");
    }
}
