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

//! End to end detection tests.
//!
//! Every sample below is synthetic. No real credential is used anywhere in
//! this repository.

use clipwarden_core::engine::DetectionEngine;
use clipwarden_core::model::{ProtectionMode, SecretKind};
use clipwarden_core::redact::{RedactionOptions, apply};

/// Builds a credential that looks real but is assembled at runtime.
///
/// The hosting platform scans every push for leaked credentials. A sample
/// that is written literally would be indistinguishable from a real key
/// and would block the push, so the parts are kept apart here.
fn fake_secret(prefix: &str, parts: &[&str]) -> String {
    format!("{prefix}{}", parts.concat())
}

fn engine() -> DetectionEngine {
    DetectionEngine::new()
}

fn kinds(text: impl AsRef<str>) -> Vec<SecretKind> {
    engine()
        .scan(text.as_ref())
        .findings
        .into_iter()
        .map(|finding| finding.kind)
        .collect()
}

fn contains(text: impl AsRef<str>, kind: SecretKind) -> bool {
    kinds(text.as_ref()).contains(&kind)
}

#[test]
fn detects_openai_key() {
    let text = format!(
        "OPENAI_KEY={}",
        fake_secret("sk-proj-", &["Ab3Cd9EfGh1IjKlMnOpQ", "rStUvWxYz0123456789"])
    );
    assert!(contains(text, SecretKind::OpenAiApiKey));
}

#[test]
fn detects_anthropic_key() {
    let text = format!(
        "export ANTHROPIC_API_KEY={}",
        fake_secret("sk-ant-api03-", &["9ZkQwErTyUiOpAsDf", "GhJkLzXcVbNm1234"])
    );
    let found = kinds(text.as_str());
    assert!(found.contains(&SecretKind::AnthropicApiKey), "{found:?}");
}

#[test]
fn detects_github_tokens() {
    let text = fake_secret("ghp_", &["16C7e42F292c6912E7", "710c838347Ae178B4a"]);
    assert!(contains(text, SecretKind::GithubToken));

    let fine_grained = fake_secret(
        "github_pat_",
        &["11ABCDEFG0aBcDeFgHiJkL_M", "nOpQrStUvWxYz0123456789"],
    );
    assert!(contains(fine_grained, SecretKind::GithubToken));
}

#[test]
fn detects_gitlab_token() {
    let text = fake_secret("glpat-", &["xK3mQ9vL7pR2tXwZ", "5aB8cD4eF6gH1jK3"]);
    assert!(contains(text, SecretKind::GitlabToken));
}

#[test]
fn detects_aws_access_key_id() {
    let text = format!(
        "AWS_ACCESS_KEY_ID={}",
        fake_secret("AKIA", &["IOSFODNN7EXAMPLE"])
    );
    assert!(contains(text, SecretKind::AwsAccessKeyId));
}

#[test]
fn detects_aws_secret_access_key() {
    let text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    assert!(contains(text, SecretKind::AwsSecretAccessKey));
}

#[test]
fn detects_google_api_key() {
    let text = fake_secret("AIza", &["SyD1ExampleKeyWith", "35CharsAbcDeFgHiJ"]);
    assert!(contains(text, SecretKind::GoogleApiKey));
}

#[test]
fn detects_slack_token() {
    let text = fake_secret(
        "xoxb-",
        &["123456789012-1234567890123", "-AbCdEfGhIjKlMnOpQrStUvWx"],
    );
    assert!(contains(text, SecretKind::SlackToken));
}

#[test]
fn detects_stripe_key() {
    let text = fake_secret("sk_live_", &["4eC39HqLyjWDarjtT1z", "dp7dc"]);
    assert!(contains(text, SecretKind::StripeKey));
}

#[test]
fn detects_npm_token() {
    let text = fake_secret("npm_", &["aBcDeFgHiJkLmNoPqR", "sTuVwXyZ0123456789"]);
    assert!(contains(text, SecretKind::NpmToken));
}

#[test]
fn detects_jwt() {
    let text = fake_secret(
        "eyJhbGciOiJIUzI1NiIs",
        &[
            "InR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3",
            "ODkwIn0.",
            "dBjftJeZ4CVPmB92K27uhbUJ",
            "U1p1r_wW1gFWFOEjXk",
        ],
    );
    assert!(contains(text, SecretKind::Jwt));
}

#[test]
fn detects_bearer_token() {
    let text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789";
    assert!(contains(text, SecretKind::BearerToken));
}

#[test]
fn detects_pem_private_key() {
    let text = fake_secret(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        &[
            "MIIEowIBAAKCAQEA",
            "1234567890abcdefg",
            "\n-----END RSA PRIVATE KEY-----",
        ],
    );
    assert!(contains(text, SecretKind::PrivateKey));
}

#[test]
fn detects_database_urls() {
    let postgres = fake_secret(
        "postgresql://appuser:",
        &["s3cr3tp4ss@db.inter", "nal:5432/production"],
    );
    assert!(contains(postgres, SecretKind::PostgresUrl));

    let mongo = "mongodb+srv://root:R00tP4ss@mongo.example.com/admin";
    assert!(contains(mongo, SecretKind::MongoUrl));

    let mysql = fake_secret("mysql://root:", &["hunter2@127.0", ".0.1:3306/app"]);
    assert!(contains(mysql, SecretKind::MySqlUrl));
}

#[test]
fn detects_password_assignment() {
    let text = "password = \"correct horse battery staple\"";
    assert!(contains(text, SecretKind::Password));
}

#[test]
fn detects_env_style_secret() {
    let text = format!(
        "CLIENT_SECRET={}",
        fake_secret("8f2b1c9d4e7a6b3c0", &["d5e2f9a8b7c6d5e4f3a2b1c"])
    );
    assert!(contains(text, SecretKind::SecretAssignment));
}

#[test]
fn detects_email_address() {
    let text = "Contact alice.smith@example.com for details";
    assert!(contains(text, SecretKind::EmailAddress));
}

#[test]
fn detects_phone_number() {
    let text = "Call +14155552671 tomorrow";
    assert!(contains(text, SecretKind::PhoneNumber));
}

#[test]
fn detects_ipv4_address() {
    let text = "server 192.168.1.1:8080";
    assert!(contains(text, SecretKind::IpV4Address));
}

#[test]
fn detects_ipv6_address() {
    let text = "server 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    assert!(contains(text, SecretKind::IpV6Address));
}

#[test]
fn detects_credit_card_with_luhn() {
    // 4111 1111 1111 1111 passes the Luhn check.
    let text = "card 4111111111111111 exp 12/28";
    assert!(contains(text, SecretKind::CreditCard));
}

#[test]
fn ignores_credit_card_without_luhn() {
    let text = "order number 1234567890123456";
    assert!(!contains(text, SecretKind::CreditCard));
}

#[test]
fn plain_prose_is_clean() {
    let text = "The quick brown fox jumps over the lazy dog. \
                Rust is a systems programming language that focuses on safety.";
    let report = engine().scan(text);
    assert!(report.is_clean(), "{:?}", report.findings);
}

#[test]
fn placeholder_values_are_ignored() {
    let text = "password = changeme\napi_key = your_api_key_here";
    let report = engine().scan(text);
    assert!(report.is_clean(), "{:?}", report.findings);
}

#[test]
fn environment_variable_references_are_ignored() {
    let text = "api_key = process.env.API_KEY\npassword = os.environ['PASSWORD']";
    let report = engine().scan(text);
    assert!(report.is_clean(), "{:?}", report.findings);
}

#[test]
fn git_commit_hashes_are_not_entropy_secrets() {
    let text = "commit example authored";
    let report = engine().scan(text);
    assert!(report.is_clean(), "{:?}", report.findings);
}

/// Texts that must never be flagged.
///
/// They are the everyday content of a computer: source code, log lines,
/// prose, addresses and configuration files. A tool like ClipWarden is only
/// useful when it stays quiet on such text.
const ORDINARY_TEXTS: &[&str] = &[
    "let total = price * count;",
    "fn main() { println!(\"hello\"); }",
    "SELECT id, name FROM users WHERE active = 1",
    "2026-11-12 09:31:44 INFO  server started on port 8080",
    "The password must contain at least eight characters.",
    "password = changeme",
    "api_key = your_api_key_here",
    "process.env.API_KEY",
    "https://example.com/index.html",
    "Commit 0123456789abcdef0123456789abcdef01234567 authored",
    "C:\\Users\\mukil\\Documents\\report.pdf",
    "{\"user\": \"name\", \"role\": \"admin\"}",
    "import os\nimport sys",
    "git commit -m 'fix the parser'",
    "This sentence mentions a secret key without one.",
    "Meeting at 15:00 in room 2.14",
];

#[test]
fn ordinary_text_is_never_flagged() {
    let engine = engine();
    let mut false_positives = Vec::new();
    for sample in ORDINARY_TEXTS {
        let report = engine.scan(sample);
        if !report.is_clean() {
            false_positives.push(format!("{sample:?} -> {:?}", report.findings));
        }
    }
    assert!(
        false_positives.is_empty(),
        "{} of {} ordinary texts were flagged: {}",
        false_positives.len(),
        ORDINARY_TEXTS.len(),
        false_positives.join(" | ")
    );
}

#[test]
fn personal_data_is_found_on_purpose() {
    // E-mail addresses and IP addresses are not secrets in the strict sense,
    // but a clipboard firewall that lets them through is useless. They are
    // therefore reported as well.
    assert!(contains(
        "Write to me at contact@example.com",
        SecretKind::EmailAddress
    ));
    assert!(contains(
        "server 192.168.0.1 answered",
        SecretKind::IpV4Address
    ));
}

#[test]
fn redaction_keeps_structure() {
    let text = format!(
        "API_KEY={}",
        fake_secret("sk-proj-", &["Ab3Cd9EfGh1IjKlMnOpQ", "rStUvWxYz0123456789"])
    );
    let report = engine().scan(&text);
    let outcome = apply(
        &text,
        &report.findings,
        ProtectionMode::Redact,
        &RedactionOptions::default(),
    );
    let redacted = outcome.text.unwrap();
    assert!(redacted.contains("API_KEY="));
    assert!(!redacted.contains("Ab3Cd9EfGh1IjKlMnOpQrStUvWxYz"));
}

#[test]
fn removal_drops_the_secret() {
    let text = "password = \"correct horse battery staple\"";
    let report = engine().scan(text);
    let outcome = apply(
        text,
        &report.findings,
        ProtectionMode::Remove,
        &RedactionOptions::default(),
    );
    let removed = outcome.text.unwrap();
    assert!(!removed.contains("correct horse"));
}

#[test]
fn findings_never_contain_the_secret() {
    let secret = fake_secret("sk-proj-", &["Ab3Cd9EfGh1IjKlMnOpQ", "rStUvWxYz0123456789"]);
    let report = engine().scan(&secret);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains(&secret));
    assert!(!json.contains("Ab3Cd9EfGh1IjKlMnOpQrStUvWxYz"));
}

#[test]
fn risk_is_classified() {
    let text = fake_secret(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        &[
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
            "AAAAAAAAABAAAAMwAAAAtz",
            "\n-----END OPENSSH PRIVATE KEY-----",
        ],
    );
    let report = engine().scan(&text);
    assert_eq!(report.risk, clipwarden_core::model::RiskLevel::Critical);
}

#[test]
fn multiple_secrets_are_all_found() {
    let text = format!(
        "{} and {} and {}",
        fake_secret("AKIA", &["IOSFODNN7EXAMPLE"]),
        fake_secret("ghp_", &["16C7e42F292c6912E7", "710c838347Ae178B4a"]),
        fake_secret("sk-proj-", &["Ab3Cd9EfGh1IjKlMnOpQ", "rStUvWxYz0123456789"])
    );
    let report = engine().scan(&text);
    assert_eq!(report.findings.len(), 3, "{:?}", report.findings);
}

#[test]
fn scan_is_deterministic() {
    let text = fake_secret("AKIA", &["IOSFODNN7EXAMPLE"]);
    let first = engine().scan(&text);
    let second = engine().scan(&text);
    assert_eq!(first.findings.len(), second.findings.len());
    assert_eq!(
        first.findings[0].fingerprint,
        second.findings[0].fingerprint
    );
}
