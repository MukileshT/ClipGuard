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

//! Entropy analysis used to spot secrets that have no known signature.
//!
//! Entropy alone produces a lot of false positives (hashes, base64 encoded
//! blobs, compressed assets), so the detector combines it with a charset
//! analysis, a minimum length requirement and — optionally — a keyword
//! context requirement.

use serde::{Deserialize, Serialize};

/// Minimum length of a token considered for entropy analysis.
pub const DEFAULT_MIN_LENGTH: usize = 24;

/// Default Shannon entropy threshold (bits per character).
pub const DEFAULT_THRESHOLD: f64 = 4.2;

/// Characters that are common in base64 / base64url encoded material.
const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_";

/// Characters that appear in hexadecimal encoded material.
const HEX_CHARS: &[u8] = b"0123456789abcdefABCDEF";

/// Computes the Shannon entropy of `text` in bits per character.
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let bytes = text.as_bytes();
    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts.iter() {
        if *count == 0 {
            continue;
        }
        let probability = f64::from(*count) / length;
        entropy -= probability * probability.log2();
    }
    entropy
}

/// Returns `true` when every character of `token` is a base64/base64url
/// character.
pub fn is_base64ish(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| BASE64_CHARS.contains(&b))
}

/// Returns `true` when every character of `token` is a hexadecimal digit.
pub fn is_hex(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| HEX_CHARS.contains(&b))
}

/// Returns `true` when `token` mixes letters and digits, which is the case for
/// virtually every real credential but rarely for natural language.
pub fn has_mixed_alnum(token: &str) -> bool {
    let has_alpha = token.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = token.bytes().any(|b| b.is_ascii_digit());
    has_alpha && has_digit
}

/// Configuration for the entropy detector.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EntropyConfig {
    /// Minimum token length.
    pub min_length: usize,
    /// Shannon entropy threshold in bits per character.
    pub threshold: f64,
    /// Require a keyword such as `token` or `secret` near the candidate.
    pub require_context: bool,
    /// Detect pure hexadecimal tokens (git SHAs, checksums) as secrets.
    pub detect_hex: bool,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_length: DEFAULT_MIN_LENGTH,
            threshold: DEFAULT_THRESHOLD,
            require_context: true,
            detect_hex: false,
        }
    }
}

/// Result of the entropy analysis for a single token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyVerdict {
    /// The token is not secret enough to be reported.
    NotSecret,
    /// The token looks like a secret.
    Secret,
}

/// Decides whether `token` is likely to be a secret based on its entropy and
/// shape.
///
/// `context` is the text preceding the token; when `config.require_context` is
/// set, the token must be preceded by one of the known credential keywords.
pub fn evaluate(
    token: &str,
    context: &str,
    config: &EntropyConfig,
    keywords: &[&str],
) -> EntropyVerdict {
    if token.len() < config.min_length {
        return EntropyVerdict::NotSecret;
    }
    if !is_base64ish(token) {
        return EntropyVerdict::NotSecret;
    }
    if !has_mixed_alnum(token) {
        return EntropyVerdict::NotSecret;
    }
    if is_hex(token) && !config.detect_hex {
        // Pure hex strings are usually hashes or commit ids.
        return EntropyVerdict::NotSecret;
    }
    let entropy = shannon_entropy(token);
    if entropy < config.threshold {
        return EntropyVerdict::NotSecret;
    }
    if config.require_context && !context_contains(context, keywords) {
        return EntropyVerdict::NotSecret;
    }
    EntropyVerdict::Secret
}

/// Returns `true` when `context` contains any of the given keywords,
/// ignoring case.
pub fn context_contains(context: &str, keywords: &[&str]) -> bool {
    let lowered = context.to_ascii_lowercase();
    keywords.iter().any(|keyword| lowered.contains(keyword))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_of_uniform_text_is_low() {
        assert!(shannon_entropy("aaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn entropy_of_random_text_is_high() {
        assert!(shannon_entropy("Xq7ZpL2mNv9Kt4Rw8Yc3Bh") > 4.0);
    }

    #[test]
    fn hex_tokens_are_not_secrets_by_default() {
        let config = EntropyConfig::default();
        let token = format!("{}{}", "0123456789abcdef", "0123456789abcdef01234567");
        assert_eq!(
            evaluate(&token, "commit=", &config, &["commit"]),
            EntropyVerdict::NotSecret
        );
    }

    #[test]
    fn random_token_with_context_is_a_secret() {
        let config = EntropyConfig {
            require_context: false,
            ..EntropyConfig::default()
        };
        let token = "Xq7ZpL2mNv9Kt4Rw8Yc3Bh6Jd";
        assert_eq!(evaluate(token, "", &config, &[]), EntropyVerdict::Secret);
    }

    #[test]
    fn random_token_without_context_is_not_a_secret() {
        let config = EntropyConfig::default();
        let token = "Xq7ZpL2mNv9Kt4Rw8Yc3Bh6Jd";
        assert_eq!(
            evaluate(token, "some prose", &config, &["token"]),
            EntropyVerdict::NotSecret
        );
    }

    #[test]
    fn short_tokens_are_ignored() {
        let config = EntropyConfig {
            require_context: false,
            ..EntropyConfig::default()
        };
        assert_eq!(
            evaluate("Xq7ZpL2mNv9K", "", &config, &[]),
            EntropyVerdict::NotSecret
        );
    }
}
