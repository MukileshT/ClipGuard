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

# Security policy

## Reporting a vulnerability

Please report a vulnerability **privately**, not in a public issue.

- GitHub: **Security → Report a vulnerability** on the repository. That
  reaches the maintainers privately.
- Or by mail to the address in [`NOTICE`](NOTICE).

Please include:

- what the problem is and which version is affected,
- how to reproduce it, ideally without a real credential,
- what an attacker could achieve with it.

You will get an answer within a few days. Please give the maintainers a
reasonable time to publish a fix before you disclose the problem.

## What ClipWarden does and does not protect

ClipWarden reduces the accidental disclosure of secrets through the Windows
clipboard. It does **not** make a machine safe:

- It only sees the clipboard of the user that runs it.
- It cannot intercept a paste that uses another mechanism than the clipboard
  (drag and drop, `WM_COPYDATA`, a remote desktop client).
- Windows keeps a **clipboard history of its own** (`Win+V`) and records the
  original text before ClipWarden can mask it. ClipWarden warns about this and
  switches the history off, but the entries that Windows already holds can
  only be deleted by Windows itself.
- A program that runs as the same user can read the clipboard, the
  configuration and the log file directly. ClipWarden protects against
  accidents, not against malware of the same user.

## Hardening of this project

| Area | How it is protected |
| --- | --- |
| Control channel | A named pipe with a security descriptor that only grants access to the owner; remote clients are rejected, the number of instances is limited, and the first instance refuses to start when another program owns the name. |
| Password of the dashboard | Stored as Argon2id with a random salt, compared in constant time. The plain text is never written. |
| Findings | Never contain the secret: only offsets, a rule name and a keyed fingerprint that is created per process. |
| Log file | Metadata only, no clipboard content. |
| Configuration | Written atomically, so a crash cannot leave a half written file behind. |
| Availability | The dashboard starts the service again when it dies unexpectedly. |
| Dependencies | Audited in the continuous integration of every push. |

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| older | no, please update |
