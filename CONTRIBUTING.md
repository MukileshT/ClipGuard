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

# Contributing to ClipWarden

Thank you for helping to keep secrets out of the clipboard.

## What helps most

1. **A false positive.** A rule that fires on ordinary text is the most
   common problem of a tool like this. Please open an issue with the text
   that was flagged and what should have happened instead.
2. **A missing detection.** The same, with the text that was *not* flagged
   and should have been.
3. **A crash or a hang**, especially of the background service. The log file
   `%APPDATA%\ClipWarden\ClipWarden.log` usually helps.

## Before you open a pull request

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The continuous integration runs the same three commands on every push, so a
green build is the same thing locally.

## Rules of the repository

- The detection engine (`crates/clipwarden-core`) must stay free of `unsafe`
  code and must not depend on Windows. It is the part that can be tested
  everywhere.
- A finding must never contain the secret itself. Only offsets, metadata
  and a fingerprint are allowed.
- No network access, no telemetry, no update check.
- Every new detection rule needs a test with a sample that **must** be
  detected and a sample that **must not** be detected.
- Every change of the configuration format needs a migration or a fallback
  that reads the older file.

## Commit messages

One change per commit, and the message says what the change does, not how.
The style of the existing history is a short summary line, followed by the
reason when it is not obvious.

## Sign-off

Every commit carries a `Signed-off-by` line (`git commit -s`). It states that
you wrote the change, or have the right to submit it, under the Developer
Certificate of Origin 1.1 (<https://developercertificate.org>).

## License

A pull request is a contribution of the code under the Apache License 2.0,
including the patent license of section 3. If a contribution should not be
licensed that way, please say so **before** you send it, so that it can be
handled as a private patch.
