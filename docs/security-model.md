# Security model

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


ClipWarden is a security tool. This document describes what it protects against,
what it deliberately does not do, and the decisions that were made along the
way.

## Trust assumptions

ClipWarden assumes:

| Assumption                                                            | Consequence                                                                 |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| The machine is not already compromised.                                | A rootkit can read the clipboard before ClipWarden ever sees it.              |
| The user account is trusted.                                           | The control channel is accessible to processes of the same user.            |
| The operating system enforces its own memory protections.               | Secrets in the clipboard are readable by any process of the user.            |
| Windows delivers clipboard notifications and keyboard hooks reliably.  | A failure leads to a missed event, not to a false claim of protection.     |

## Assets

* **The clipboard content** — the primary asset. It is read into memory,
  inspected and either kept or rewritten.
* **The configuration** — contains patterns, never credentials.
* **The statistics** — counts and categories, never content.
* **The log file** — `%APPDATA%\ClipWarden\clipwarden.log`, contains metadata.

## Data flow

```text
 clipboard ──► engine ──► findings ──► decision ──► clipboard
                   │           │
                   │           └──► fingerprint, kind, risk, offsets only
                   │
                   └──► never leaves the process
```

## Threats and mitigations

| Threat                                            | Mitigation                                                             |
| ------------------------------------------------- | ---------------------------------------------------------------------- |
| A secret ends up in a log file                     | Findings never contain the secret; the log records kinds and counts.    |
| A secret ends up in the configuration              | The configuration only stores patterns; there is no field for secrets.  |
| A secret is recoverable from the statistics        | Statistics store counts per category and per application.                |
| A secret survives in memory after use              | The vault holds the content in a `Zeroizing` buffer that is wiped when the clipboard changes. |
| Clipboard contention causes a missed protection    | The clipboard is opened with a bounded retry loop instead of a single attempt. |
| Two instances fight over the clipboard             | A named mutex guarantees a single instance.                             |
| A pasted secret bypasses the protection            | The paste hook modifies the clipboard before the target application reads it, and can suppress the key entirely. |
| An update or telemetry leaks data                  | There is no network code in the workspace at all.                       |
| A malicious rule set exfiltrates data              | Rules are local patterns; they are evaluated offline and cannot emit data. |
| The dashboard weakens the protection               | The dashboard is a client of the control channel and cannot bypass the policy engine. |

## Explicit non-goals

ClipWarden does **not**:

* encrypt the clipboard or provide a secure clipboard,
* protect against a compromised operating system or a malicious administrator,
* intercept drags and drops or inter-process data transfers,
* scan files on disk or network traffic,
* guarantee that a secret is never exposed — it reduces accidental exposure,
* report anything to a server, because there is no server.

## Detection philosophy

The engine is tuned for **precision over recall**, with one deliberate
exception: a secret that is missed is much more damaging than a false positive.

Concretely:

* Provider specific patterns are anchored on real key formats (`sk-…`,
  `AIza…`, `ghp_…`, `xoxb-…`, `glpat-…`, `AKIA…`).
* Generic patterns require a context keyword, a minimum length and a plausible
  charset.
* Checksums (Luhn, mod-97) are used where the format allows it.
* Placeholders and code references are rejected explicitly.
* The entropy detector requires a keyword nearby by default and never reports
  pure hexadecimal strings, which keeps git hashes and checksums out of the
  results.

The result is a rule set that reports a handful of findings per day in a real
development environment instead of hundreds.

## Templates

Templates are ordinary rules with a friendlier name and description. They do not
carry any extra privilege:

* An e-mail template is a regular expression that matches one provider
  domain, for example `\b[A-Za-z0-9._%+\-]+@gmail\.com\b`.
* The "my phone number" template matches the number the user entered
  literally. The number is escaped, so it can never act as a wildcard.
* A secret template is the same pattern the built-in rules use.

Because a template is just a rule, the user can edit it, disable it or remove
it again at any time.

## Failure behaviour

| Failure                            | Behaviour                                                     |
| ---------------------------------- | ------------------------------------------------------------- |
| The clipboard cannot be opened      | The event is skipped and logged at debug level.                |
| The configuration cannot be parsed  | The previous configuration stays active; the error is logged.  |
| The clipboard cannot be written     | The original content stays on the clipboard; the error is logged. |
| The protection pipeline fails      | The configured fail-safe applies (`redact` by default).       |
| The service is paused               | The clipboard is not touched at all.                           |
| The service is missing              | The dashboard starts it automatically with `CREATE_NO_WINDOW`. |

The fail-safe exists so that a bug in the protection path defaults to the
safer behaviour instead of silently leaking.

## Auditability

* The engine contains no `unsafe` code (`#![forbid(unsafe_code)]`).
* The Windows integration is small and isolated in `clipwarden-clipboard`.
* The application icon is generated from code, not shipped as an opaque blob.
* Every rule is a plain regular expression and can be reviewed line by line.
* The dashboard only receives metadata from the service.

## Platform specific dependencies

ClipWarden is a Windows application. The lock file of the dashboard contains the
whole dependency tree of Tauri, including the Linux stack:

```text
tauri 2.12.5 → tao 0.37.2 → gtk 0.18.2 → glib 0.18
```

`glib` is only compiled on Linux, where Tauri uses the GTK and WebKitGTK
toolkit. The Windows binaries contain none of it — there is no glib, GObject
or GTK symbol in `clipwarden-desktop.exe`. A vulnerability in that library
therefore does not affect the Windows release.

The newest published versions of `tauri` (2.12.5) and `tao` (0.37.2) still
require `gtk 0.18`, and `gtk 0.18` requires `glib 0.18`, so no version
without the advisory can be selected yet:

```text
error: failed to select a version for the requirement `glib = "^0.18"`
candidate versions found which didn't match: 0.20.0
required by package `gtk v0.18.2`
```

`gtk 0.19` — which would allow `glib 0.20` — exists, but no released
version of `tao` uses it yet. The alert can therefore be dismissed until the
Linux stack moves forward. A Linux build of ClipWarden would have to be
re-checked at that point.

## Reporting a vulnerability

Please report security issues privately to the maintainers rather than in a
public issue tracker. Include a description, the affected version and, if
possible, a reproduction that does not involve a real credential.