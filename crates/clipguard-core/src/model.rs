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

//! Core data model: secret kinds, risk levels, findings and protection modes.
//!
//! Nothing in this module is allowed to retain the plaintext of a secret for
//! longer than the duration of a single scan. [`Finding`] deliberately stores
//! only offsets, metadata and a keyed fingerprint so that logs, statistics and
//! UI notifications can never leak the secret itself.

use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Serialize};

/// Classification of the risk posed by a detected secret.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low impact, usually personal data.
    #[default]
    Low,
    /// Moderate impact, e.g. internal identifiers.
    Medium,
    /// High impact, e.g. access tokens and API keys.
    High,
    /// Critical impact, e.g. private keys and production database credentials.
    Critical,
}

impl RiskLevel {
    /// All risk levels, ordered from least to most severe.
    pub const ALL: [RiskLevel; 4] = [
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];

    /// Stable lowercase identifier used in configuration files.
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    /// Human readable label for the UI.
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The category of a detected secret.
///
/// The variants are grouped by family so that the UI can offer coarse
/// toggles (for example "hide personal information") without enumerating
/// every individual provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    // ---- API keys -------------------------------------------------------
    /// OpenAI-style secret key (`sk-...`).
    OpenAiApiKey,
    /// Anthropic API key (`sk-ant-...`).
    AnthropicApiKey,
    /// Google API key (`AIza...`).
    GoogleApiKey,
    /// Google OAuth access token (`ya29....`).
    GoogleOAuthToken,
    /// AWS access key id (`AKIA...`).
    AwsAccessKeyId,
    /// AWS secret access key (context aware, 40 char secret).
    AwsSecretAccessKey,
    /// Azure storage account key.
    AzureStorageKey,
    /// Azure storage connection string.
    AzureConnectionString,
    /// GitHub personal access token / OAuth token.
    GithubToken,
    /// GitLab personal access token.
    GitlabToken,
    /// Slack token.
    SlackToken,
    /// Stripe secret / restricted key.
    StripeKey,
    /// Twilio account SID or API key.
    TwilioKey,
    /// SendGrid API key.
    SendgridKey,
    /// Discord bot token.
    DiscordToken,
    /// npm access token.
    NpmToken,
    /// Hugging Face access token.
    HuggingFaceToken,
    /// Firebase database URL or credential.
    FirebaseCredential,
    /// Google Cloud service account payload.
    GcpServiceAccount,

    // ---- Authentication -------------------------------------------------
    /// JSON Web Token.
    Jwt,
    /// `Authorization: Bearer ...` credential.
    BearerToken,
    /// `Authorization: Basic ...` credential.
    BasicAuth,
    /// Generic OAuth access/refresh token.
    OAuthToken,
    /// Session cookie or `Set-Cookie` value.
    SessionCookie,

    // ---- Credentials ----------------------------------------------------
    /// Password-like assignment (`password = ...`).
    Password,
    /// Generic secret assignment (`api_key = ...`, `secret: ...`).
    SecretAssignment,
    /// Generic credential assignment (`credentials = ...`).
    Credentials,
    /// PEM encoded private key block.
    PrivateKey,
    /// PuTTY/OpenSSH private key file body.
    SshPrivateKey,
    /// X.509 certificate.
    Certificate,
    /// Generic high entropy token without a known signature.
    EntropySecret,

    // ---- Databases and connection strings --------------------------------
    /// PostgreSQL connection URL.
    PostgresUrl,
    /// MySQL / MariaDB connection URL.
    MySqlUrl,
    /// MongoDB connection URL.
    MongoUrl,
    /// Redis connection URL.
    RedisUrl,
    /// Microsoft SQL Server connection URL.
    SqlServerUrl,
    /// JDBC connection URL.
    JdbcUrl,
    /// Generic connection string containing credentials.
    ConnectionString,

    // ---- Personal information -------------------------------------------
    /// Email address.
    EmailAddress,
    /// Phone number.
    PhoneNumber,
    /// Credit card number.
    CreditCard,
    /// US social security number.
    Ssn,
    /// International bank account number.
    Iban,

    // ---- Network --------------------------------------------------------
    /// IPv4 address.
    IpV4Address,
    /// IPv6 address.
    IpV6Address,

    // ---- User defined ----------------------------------------------------
    /// A secret detected by a user supplied custom rule.
    Custom,
}

impl SecretKind {
    /// Every known secret kind.
    pub const ALL: &'static [SecretKind] = &[
        SecretKind::OpenAiApiKey,
        SecretKind::AnthropicApiKey,
        SecretKind::GoogleApiKey,
        SecretKind::GoogleOAuthToken,
        SecretKind::AwsAccessKeyId,
        SecretKind::AwsSecretAccessKey,
        SecretKind::AzureStorageKey,
        SecretKind::AzureConnectionString,
        SecretKind::GithubToken,
        SecretKind::GitlabToken,
        SecretKind::SlackToken,
        SecretKind::StripeKey,
        SecretKind::TwilioKey,
        SecretKind::SendgridKey,
        SecretKind::DiscordToken,
        SecretKind::NpmToken,
        SecretKind::HuggingFaceToken,
        SecretKind::FirebaseCredential,
        SecretKind::GcpServiceAccount,
        SecretKind::Jwt,
        SecretKind::BearerToken,
        SecretKind::BasicAuth,
        SecretKind::OAuthToken,
        SecretKind::SessionCookie,
        SecretKind::Password,
        SecretKind::SecretAssignment,
        SecretKind::Credentials,
        SecretKind::PrivateKey,
        SecretKind::SshPrivateKey,
        SecretKind::Certificate,
        SecretKind::EntropySecret,
        SecretKind::PostgresUrl,
        SecretKind::MySqlUrl,
        SecretKind::MongoUrl,
        SecretKind::RedisUrl,
        SecretKind::SqlServerUrl,
        SecretKind::JdbcUrl,
        SecretKind::ConnectionString,
        SecretKind::EmailAddress,
        SecretKind::PhoneNumber,
        SecretKind::CreditCard,
        SecretKind::Ssn,
        SecretKind::Iban,
        SecretKind::IpV4Address,
        SecretKind::IpV6Address,
        SecretKind::Custom,
    ];

    /// Stable lowercase identifier used in configuration files and the API.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretKind::OpenAiApiKey => "openai_api_key",
            SecretKind::AnthropicApiKey => "anthropic_api_key",
            SecretKind::GoogleApiKey => "google_api_key",
            SecretKind::GoogleOAuthToken => "google_oauth_token",
            SecretKind::AwsAccessKeyId => "aws_access_key_id",
            SecretKind::AwsSecretAccessKey => "aws_secret_access_key",
            SecretKind::AzureStorageKey => "azure_storage_key",
            SecretKind::AzureConnectionString => "azure_connection_string",
            SecretKind::GithubToken => "github_token",
            SecretKind::GitlabToken => "gitlab_token",
            SecretKind::SlackToken => "slack_token",
            SecretKind::StripeKey => "stripe_key",
            SecretKind::TwilioKey => "twilio_key",
            SecretKind::SendgridKey => "sendgrid_key",
            SecretKind::DiscordToken => "discord_token",
            SecretKind::NpmToken => "npm_token",
            SecretKind::HuggingFaceToken => "huggingface_token",
            SecretKind::FirebaseCredential => "firebase_credential",
            SecretKind::GcpServiceAccount => "gcp_service_account",
            SecretKind::Jwt => "jwt",
            SecretKind::BearerToken => "bearer_token",
            SecretKind::BasicAuth => "basic_auth",
            SecretKind::OAuthToken => "oauth_token",
            SecretKind::SessionCookie => "session_cookie",
            SecretKind::Password => "password",
            SecretKind::SecretAssignment => "secret_assignment",
            SecretKind::Credentials => "credentials",
            SecretKind::PrivateKey => "private_key",
            SecretKind::SshPrivateKey => "ssh_private_key",
            SecretKind::Certificate => "certificate",
            SecretKind::EntropySecret => "entropy_secret",
            SecretKind::PostgresUrl => "postgres_url",
            SecretKind::MySqlUrl => "mysql_url",
            SecretKind::MongoUrl => "mongo_url",
            SecretKind::RedisUrl => "redis_url",
            SecretKind::SqlServerUrl => "sqlserver_url",
            SecretKind::JdbcUrl => "jdbc_url",
            SecretKind::ConnectionString => "connection_string",
            SecretKind::EmailAddress => "email_address",
            SecretKind::PhoneNumber => "phone_number",
            SecretKind::CreditCard => "credit_card",
            SecretKind::Ssn => "ssn",
            SecretKind::Iban => "iban",
            SecretKind::IpV4Address => "ipv4_address",
            SecretKind::IpV6Address => "ipv6_address",
            SecretKind::Custom => "custom",
        }
    }

    /// Human readable label used in the user interface.
    pub fn label(&self) -> &'static str {
        match self {
            SecretKind::OpenAiApiKey => "OpenAI API key",
            SecretKind::AnthropicApiKey => "Anthropic API key",
            SecretKind::GoogleApiKey => "Google API key",
            SecretKind::GoogleOAuthToken => "Google OAuth token",
            SecretKind::AwsAccessKeyId => "AWS access key id",
            SecretKind::AwsSecretAccessKey => "AWS secret access key",
            SecretKind::AzureStorageKey => "Azure storage key",
            SecretKind::AzureConnectionString => "Azure connection string",
            SecretKind::GithubToken => "GitHub token",
            SecretKind::GitlabToken => "GitLab token",
            SecretKind::SlackToken => "Slack token",
            SecretKind::StripeKey => "Stripe key",
            SecretKind::TwilioKey => "Twilio key",
            SecretKind::SendgridKey => "SendGrid key",
            SecretKind::DiscordToken => "Discord token",
            SecretKind::NpmToken => "npm token",
            SecretKind::HuggingFaceToken => "Hugging Face token",
            SecretKind::FirebaseCredential => "Firebase credential",
            SecretKind::GcpServiceAccount => "Google Cloud service account",
            SecretKind::Jwt => "JSON Web Token",
            SecretKind::BearerToken => "Bearer token",
            SecretKind::BasicAuth => "Basic auth credential",
            SecretKind::OAuthToken => "OAuth token",
            SecretKind::SessionCookie => "Session cookie",
            SecretKind::Password => "Password",
            SecretKind::SecretAssignment => "Secret assignment",
            SecretKind::Credentials => "Credentials",
            SecretKind::PrivateKey => "Private key",
            SecretKind::SshPrivateKey => "SSH private key",
            SecretKind::Certificate => "Certificate",
            SecretKind::EntropySecret => "High entropy token",
            SecretKind::PostgresUrl => "PostgreSQL URL",
            SecretKind::MySqlUrl => "MySQL URL",
            SecretKind::MongoUrl => "MongoDB URL",
            SecretKind::RedisUrl => "Redis URL",
            SecretKind::SqlServerUrl => "SQL Server URL",
            SecretKind::JdbcUrl => "JDBC URL",
            SecretKind::ConnectionString => "Connection string",
            SecretKind::EmailAddress => "Email address",
            SecretKind::PhoneNumber => "Phone number",
            SecretKind::CreditCard => "Credit card number",
            SecretKind::Ssn => "Social security number",
            SecretKind::Iban => "IBAN",
            SecretKind::IpV4Address => "IPv4 address",
            SecretKind::IpV6Address => "IPv6 address",
            SecretKind::Custom => "Custom rule",
        }
    }

    /// Default risk classification for this kind of secret.
    pub fn default_risk(&self) -> RiskLevel {
        match self {
            SecretKind::PrivateKey | SecretKind::SshPrivateKey => RiskLevel::Critical,
            SecretKind::AwsSecretAccessKey
            | SecretKind::AzureStorageKey
            | SecretKind::AzureConnectionString
            | SecretKind::PostgresUrl
            | SecretKind::MySqlUrl
            | SecretKind::MongoUrl
            | SecretKind::SqlServerUrl
            | SecretKind::JdbcUrl
            | SecretKind::RedisUrl
            | SecretKind::ConnectionString
            | SecretKind::Credentials
            | SecretKind::Password
            | SecretKind::BasicAuth => RiskLevel::High,

            SecretKind::OpenAiApiKey
            | SecretKind::AnthropicApiKey
            | SecretKind::GoogleApiKey
            | SecretKind::GoogleOAuthToken
            | SecretKind::AwsAccessKeyId
            | SecretKind::GithubToken
            | SecretKind::GitlabToken
            | SecretKind::SlackToken
            | SecretKind::StripeKey
            | SecretKind::TwilioKey
            | SecretKind::SendgridKey
            | SecretKind::DiscordToken
            | SecretKind::NpmToken
            | SecretKind::HuggingFaceToken
            | SecretKind::FirebaseCredential
            | SecretKind::GcpServiceAccount
            | SecretKind::Jwt
            | SecretKind::BearerToken
            | SecretKind::OAuthToken
            | SecretKind::SessionCookie
            | SecretKind::SecretAssignment
            | SecretKind::EntropySecret
            | SecretKind::Custom => RiskLevel::High,

            SecretKind::Certificate => RiskLevel::Medium,
            SecretKind::EmailAddress | SecretKind::PhoneNumber => RiskLevel::Low,
            SecretKind::CreditCard | SecretKind::Ssn | SecretKind::Iban => RiskLevel::Medium,
            SecretKind::IpV4Address | SecretKind::IpV6Address => RiskLevel::Low,
        }
    }

    /// Family grouping used by the UI for coarse toggles.
    pub fn family(&self) -> SecretFamily {
        match self {
            SecretKind::OpenAiApiKey
            | SecretKind::AnthropicApiKey
            | SecretKind::GoogleApiKey
            | SecretKind::GoogleOAuthToken
            | SecretKind::AwsAccessKeyId
            | SecretKind::AwsSecretAccessKey
            | SecretKind::AzureStorageKey
            | SecretKind::AzureConnectionString
            | SecretKind::GithubToken
            | SecretKind::GitlabToken
            | SecretKind::SlackToken
            | SecretKind::StripeKey
            | SecretKind::TwilioKey
            | SecretKind::SendgridKey
            | SecretKind::DiscordToken
            | SecretKind::NpmToken
            | SecretKind::HuggingFaceToken
            | SecretKind::FirebaseCredential
            | SecretKind::GcpServiceAccount => SecretFamily::ApiKey,
            SecretKind::Jwt
            | SecretKind::BearerToken
            | SecretKind::BasicAuth
            | SecretKind::OAuthToken
            | SecretKind::SessionCookie => SecretFamily::Authentication,
            SecretKind::Password
            | SecretKind::SecretAssignment
            | SecretKind::Credentials
            | SecretKind::PrivateKey
            | SecretKind::SshPrivateKey
            | SecretKind::Certificate
            | SecretKind::EntropySecret => SecretFamily::Credential,
            SecretKind::PostgresUrl
            | SecretKind::MySqlUrl
            | SecretKind::MongoUrl
            | SecretKind::RedisUrl
            | SecretKind::SqlServerUrl
            | SecretKind::JdbcUrl
            | SecretKind::ConnectionString => SecretFamily::Database,
            SecretKind::EmailAddress
            | SecretKind::PhoneNumber
            | SecretKind::CreditCard
            | SecretKind::Ssn
            | SecretKind::Iban => SecretFamily::Personal,
            SecretKind::IpV4Address | SecretKind::IpV6Address => SecretFamily::Network,
            SecretKind::Custom => SecretFamily::Custom,
        }
    }
}

/// Coarse grouping of secret kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretFamily {
    /// Provider API keys and cloud credentials.
    ApiKey,
    /// Session and protocol authentication material.
    Authentication,
    /// Passwords, assignments and private keys.
    Credential,
    /// Database connection strings.
    Database,
    /// Personal data.
    Personal,
    /// Network addresses.
    Network,
    /// User defined rules.
    Custom,
}

impl SecretFamily {
    /// All families.
    pub const ALL: [SecretFamily; 7] = [
        SecretFamily::ApiKey,
        SecretFamily::Authentication,
        SecretFamily::Credential,
        SecretFamily::Database,
        SecretFamily::Personal,
        SecretFamily::Network,
        SecretFamily::Custom,
    ];

    /// Stable lowercase identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretFamily::ApiKey => "api_key",
            SecretFamily::Authentication => "authentication",
            SecretFamily::Credential => "credential",
            SecretFamily::Database => "database",
            SecretFamily::Personal => "personal",
            SecretFamily::Network => "network",
            SecretFamily::Custom => "custom",
        }
    }

    /// Human readable label.
    pub fn label(&self) -> &'static str {
        match self {
            SecretFamily::ApiKey => "API keys",
            SecretFamily::Authentication => "Authentication",
            SecretFamily::Credential => "Credentials & keys",
            SecretFamily::Database => "Databases",
            SecretFamily::Personal => "Personal information",
            SecretFamily::Network => "Network addresses",
            SecretFamily::Custom => "Custom rules",
        }
    }
}

/// A single detected secret.
///
/// The matched plaintext is intentionally *not* part of this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Classification of the detected secret.
    pub kind: SecretKind,
    /// Risk assigned to the finding.
    pub risk: RiskLevel,
    /// Byte range of the secret inside the scanned text.
    pub span: Range<usize>,
    /// Name of the rule that produced the finding.
    pub rule: String,
    /// Keyed fingerprint of the secret, safe to store and compare.
    pub fingerprint: String,
    /// Length of the secret in bytes.
    pub length: usize,
}

impl Finding {
    /// Creates a finding for the given secret slice.
    ///
    /// The `fingerprint` is computed with a per-session key so that values can
    /// be correlated inside one session but never across sessions or machines.
    pub fn from_slice(
        kind: SecretKind,
        risk: RiskLevel,
        span: Range<usize>,
        rule: impl Into<String>,
        secret: &[u8],
        fingerprint_key: &[u8; 32],
    ) -> Self {
        let length = span.end.saturating_sub(span.start);
        Self {
            kind,
            risk,
            span,
            rule: rule.into(),
            fingerprint: fingerprint(secret, fingerprint_key),
            length,
        }
    }
}

/// Computes a short, keyed fingerprint of `secret`.
///
/// The fingerprint is an HMAC-SHA256 truncated to 16 hex characters. It allows
/// "the same secret was seen again" checks without storing the secret.
pub fn fingerprint(secret: &[u8], key: &[u8; 32]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(secret);
    let digest = mac.finalize().into_bytes();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// What ClipGuard should do when a protected value is encountered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    /// Leave the clipboard untouched.
    Allow,
    /// Replace the secret with a placeholder.
    Redact,
    /// Remove the secret from the text entirely.
    Remove,
    /// Prevent the paste entirely and notify the user.
    Block,
}

impl ProtectionMode {
    /// All modes.
    pub const ALL: [ProtectionMode; 4] = [
        ProtectionMode::Allow,
        ProtectionMode::Redact,
        ProtectionMode::Remove,
        ProtectionMode::Block,
    ];

    /// Stable lowercase identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectionMode::Allow => "allow",
            ProtectionMode::Redact => "redact",
            ProtectionMode::Remove => "remove",
            ProtectionMode::Block => "block",
        }
    }

    /// Human readable label.
    pub fn label(&self) -> &'static str {
        match self {
            ProtectionMode::Allow => "Allow",
            ProtectionMode::Redact => "Redact",
            ProtectionMode::Remove => "Remove",
            ProtectionMode::Block => "Block",
        }
    }

    /// `true` when the mode modifies or prevents the content.
    pub fn is_protective(&self) -> bool {
        !matches!(self, ProtectionMode::Allow)
    }
}

impl std::str::FromStr for ProtectionMode {
    type Err = crate::error::CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow" | "off" | "none" => Ok(ProtectionMode::Allow),
            "redact" | "mask" => Ok(ProtectionMode::Redact),
            "remove" | "strip" => Ok(ProtectionMode::Remove),
            "block" | "deny" => Ok(ProtectionMode::Block),
            other => Err(crate::error::CoreError::Invalid(format!(
                "unknown protection mode `{other}`"
            ))),
        }
    }
}

/// Global strategy that determines *when* protection is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalMode {
    /// Protect the clipboard as soon as content is copied, regardless of where
    /// it is pasted.
    Ghost,
    /// Keep the original content on the clipboard and apply the policy of the
    /// application that receives the paste.
    Satellite,
}

impl GlobalMode {
    /// Both global modes.
    pub const ALL: [GlobalMode; 2] = [GlobalMode::Ghost, GlobalMode::Satellite];

    /// Stable lowercase identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            GlobalMode::Ghost => "ghost",
            GlobalMode::Satellite => "satellite",
        }
    }

    /// Human readable label.
    pub fn label(&self) -> &'static str {
        match self {
            GlobalMode::Ghost => "Ghost mode",
            GlobalMode::Satellite => "Satellite mode",
        }
    }
}

impl std::str::FromStr for GlobalMode {
    type Err = crate::error::CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ghost" => Ok(GlobalMode::Ghost),
            "satellite" => Ok(GlobalMode::Satellite),
            other => Err(crate::error::CoreError::Invalid(format!(
                "unknown global mode `{other}`"
            ))),
        }
    }
}

/// Behaviour when the protection pipeline itself fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailSafe {
    /// Apply the redaction pipeline even if secondary checks failed.
    Redact,
    /// Let the content through untouched.
    Allow,
    /// Strip any detected secret even if the primary check failed.
    Remove,
}

impl FailSafe {
    /// All fail-safe behaviours.
    pub const ALL: [FailSafe; 3] = [FailSafe::Redact, FailSafe::Allow, FailSafe::Remove];

    /// Stable lowercase identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            FailSafe::Redact => "redact",
            FailSafe::Allow => "allow",
            FailSafe::Remove => "remove",
        }
    }
}

impl std::str::FromStr for FailSafe {
    type Err = crate::error::CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "redact" => Ok(FailSafe::Redact),
            "allow" => Ok(FailSafe::Allow),
            "remove" => Ok(FailSafe::Remove),
            other => Err(crate::error::CoreError::Invalid(format!(
                "unknown fail-safe behaviour `{other}`"
            ))),
        }
    }
}

/// The result of scanning a piece of text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Individual findings, ordered by their position in the text.
    pub findings: Vec<Finding>,
    /// Highest risk across all findings.
    pub risk: RiskLevel,
    /// Number of bytes that were scanned.
    pub scanned_bytes: usize,
}

impl ScanReport {
    /// `true` when at least one secret was detected.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Number of findings by kind, for statistics.
    pub fn counts_by_kind(&self) -> std::collections::BTreeMap<SecretKind, u64> {
        let mut map = std::collections::BTreeMap::new();
        for finding in &self.findings {
            *map.entry(finding.kind).or_insert(0) += 1;
        }
        map
    }
}

/// An identified application that receives clipboard content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIdentity {
    /// Executable file name, for example `Code.exe`.
    pub exe: String,
    /// Full path of the executable when it could be resolved.
    pub path: Option<String>,
    /// Window title, if available. Never used for policy decisions by default.
    pub title: Option<String>,
}

impl AppIdentity {
    /// Creates an identity from just an executable name.
    pub fn from_exe(exe: impl Into<String>) -> Self {
        Self {
            exe: exe.into(),
            path: None,
            title: None,
        }
    }

    /// Creates an identity from an executable name and full path.
    pub fn new(exe: impl Into<String>, path: Option<String>) -> Self {
        Self {
            exe: exe.into(),
            path,
            title: None,
        }
    }
}

impl fmt::Display for AppIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.exe)
    }
}
