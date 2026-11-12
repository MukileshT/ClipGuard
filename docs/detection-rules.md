# Detection rules

<!-- Copyright 2026 Mukilesh -->
<!-- -->
<!-- Licensed under the Apache License, Version 2.0 (the "License"); -->
<!-- you may not use this file except in compliance with the License. -->
<!-- You may obtain a copy of the License at -->
<!-- -->
<!--     http://www.apache.org/licenses/LICENSE-2.0 -->
<!-- -->
<!-- Unless required by applicable law or agreed to in writing, software -->
<!-- distributed under the License is distributed on an "AS IS" BASIS, -->
<!-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. -->
<!-- See the License for the specific language governing permissions and -->
<!-- limitations under the License. -->


This document describes the built-in rules, the templates and the detection
techniques. The authoritative sources are
[`crates/clipwarden-core/src/rules/builtin.rs`](../crates/clipwarden-core/src/rules/builtin.rs) and
[`crates/clipwarden-core/src/templates.rs`](../crates/clipwarden-core/src/templates.rs).

## Techniques

### Regular expressions

Most rules are anchored on the real format of a credential. Examples:

| Rule                 | Pattern                                                        |
| -------------------- | -------------------------------------------------------------- |
| `openai-api-key`     | `\bsk-(?:proj-\|svcacct-)?[A-Za-z0-9_\-]{20,}`                 |
| `anthropic-api-key`  | `sk-ant-[A-Za-z0-9_\-]{24,}`                                    |
| `google-api-key`     | `\bAIza[0-9A-Za-z_\-]{35}\b`                                     |
| `aws-access-key-id`  | `\b(?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16}\b`       |
| `github-token`       | `\b(?:gh[pousr]_[A-Za-z0-9]{36,255}\|github_pat_[A-Za-z0-9_]{22,255})` |
| `gitlab-token`       | `\bglpat-[A-Za-z0-9_\-]{20,}`                                    |
| `slack-token`        | `\bxox[abposr]-[A-Za-z0-9\-]{10,}`                               |
| `stripe-key`         | `\b(?:sk\|rk)_(?:live\|test)_[A-Za-z0-9]{16,}`                   |
| `npm-token`          | `\bnpm_[A-Za-z0-9]{36}\b`                                        |
| `huggingface-token`  | `\bhf_[A-Za-z0-9]{34,}`                                           |
| `twilio-key`         | `\b(?:SK[0-9a-fA-F]{32}\|AC[0-9a-f]{32})\b`                       |
| `sendgrid-key`       | `\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}`                 |
| `json-web-token`     | `\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}` |
| `private-key-pem`    | `-----BEGIN … PRIVATE KEY-----[\s\S]*?-----END … PRIVATE KEY-----` |
| `ipv4-address`       | `\b(?:(?:25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\.){3}…\b`     |
| `ipv6-address`       | `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`                   |

### Capture groups

A rule can point at the capture group that holds the secret. This keeps the
surrounding structure readable:

| Rule                  | Pattern (abridged)                                   | Group |
| --------------------- | ---------------------------------------------------- | ----- |
| `password-assignment` | `(?i)\b(?:pass(?:word\|wd\|phrase)?\|pwd)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{6,})` | 1 |
| `api-key-assignment`  | `(?i)\b(?:api[_\-]?key\|…)\b\s*[:=]\s*["']?([^\s"',;()\[\]{}]{8,})` | 1 |
| `bearer-token`        | `(?i)\bbearer\s+([A-Za-z0-9_\-\.=+/]{16,})`           | 1     |
| `postgres-url`        | `\bpostgres(?:ql)?://[^\s:/@]+:([^\s:/@]+)@[^\s/]+`   | 1     |
| `aws-secret-access-key` | `(?i)aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b` | 1 |

Redacting `postgresql://app:***@host/db` therefore yields
`postgresql://app:***@host/db` — the connection information stays
usable, the password is gone.

### Context awareness

A rule can require a keyword within the 160 bytes before the match. This is
what keeps generic rules from firing on ordinary prose.

### Checksum validation

| Validator       | Used by             | Effect                                   |
| --------------- | ------------------- | ---------------------------------------- |
| `luhn`          | `credit-card-number`| Only valid card numbers are reported.    |
| `iban_mod_97`   | `iban`              | Only valid IBANs are reported.           |
| `us_ssn`        | `social-security-number` | Invalid ranges are rejected.       |
| `not_placeholder`| assignment rules   | `changeme`, `your_api_key`, `xxxx` … are ignored. |
| `not_code_reference` | assignment rules | `os.environ["X"]` and `process.env.X` are ignored. |

### Entropy analysis

The entropy detector looks for tokens that look like base64 material and have
an unusually high Shannon entropy. It requires:

* a minimum length (24 characters by default),
* a base64/base64url character set,
* at least one letter and one digit,
* a keyword nearby (`api_key`, `secret`, `token`, `password`, …) unless the
  requirement is switched off,
* entropy above the configured threshold (4.2 bits per character by default).

Pure hexadecimal strings are excluded by default, so git commit hashes and
checksums do not show up as findings.

## Categories

| Family         | Kinds                                                                          |
| -------------- | ------------------------------------------------------------------------------ |
| API keys       | OpenAI, Anthropic, Google, Google OAuth, AWS access key, AWS secret, Azure storage key, Azure connection string, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, Discord, npm, Hugging Face, Firebase, GCP service account |
| Authentication | JWT, Bearer, Basic auth, OAuth token, session cookie                            |
| Credentials    | Password, secret assignment, credentials, PEM private key, SSH private key, certificate, entropy token |
| Databases      | PostgreSQL, MySQL, MongoDB, Redis, SQL Server, JDBC, connection string          |
| Personal       | Email address, phone number, credit card, SSN, IBAN                             |
| Network        | IPv4 address, IPv6 address                                                     |
| Custom         | Everything a user defined rule produces                                          |

## Templates

Templates are ordinary rules with a friendly name and description. They are
offered in the dashboard so that you do not have to write a regular expression
for the common cases.

### E-mail templates

One per provider — the pattern is always
`\b[A-Za-z0-9._%+\-]+@<domain>\b`:

`gmail.com`, `googlemail.com`, `outlook.com`, `hotmail.com`, `live.com`,
`outlook.in`, `yahoo.com`, `yahoo.co.uk`, `yahoo.co.in`, `protonmail.com`,
`proton.me`, `icloud.com`, `me.com`, `mac.com`, `aol.com`, `zoho.com`,
`yandex.com`, `gmx.com`, `mail.com`, `duck.com`, `fastmail.com`,
`tutanota.com`, `msn.com`, `live.in`, `rediffmail.com`.

### Phone templates

| Template                   | Pattern                                                    |
| -------------------------- | ---------------------------------------------------------- |
| International phone number | `\+[1-9][0-9]{9,14}\b`                                     |
| Labelled phone number      | `(?i)\b(?:phone\|tel\|…)\b\s*[:=]\s*(\+?[0-9][0-9 ()\-.]{6,20})` |
| National phone number      | `(?i)\b(?:phone\|tel\|…\|contact)\b\s*[:=]?\s*([0-9][0-9 \-().]{8,18}[0-9])` |
| My phone number            | The number you entered, escaped literally                   |

### Secret templates

One template per credential category, from API keys over database connection
strings to bank details. See the *Templates* tab in the dashboard for the full
list with descriptions.

## Writing your own rule

1. Open the dashboard and go to **Detection rules**.
2. Enter a name and a regular expression.
3. Choose the category and the risk.
4. Use the capture group field when only part of the match is the secret.
5. Test it:

   ```powershell
   clipwarden scan "your sample text"
   ```

The regular expression syntax is the one of the Rust `regex` crate. Look-around
(`(?=…)`, `(?<=…)`) is **not** supported — use a capture group and the `group`
field instead.