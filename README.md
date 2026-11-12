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

# ClipWarden

**Native Windows clipboard security firewall.**

ClipWarden watches the Windows clipboard, detects API keys, passwords, access
tokens, private keys and personal information, and protects them before they
reach another application. Everything happens locally: there is no network
traffic, no cloud service and no clipboard history.

ClipWarden is a native Rust project built around security, low resource usage
and deep Windows integration.

[![Release](https://img.shields.io/github/v/release/MukileshT/ClipWarden)](https://github.com/MukileshT/ClipWarden/releases/latest)

---

## Quick start

1. Download and extract `ClipWarden-Portable.zip` to any folder.
2. Double-click **clipwarden-desktop.exe**.
3. ClipWarden starts its background service automatically; no console window
   appears.
4. Copy any text that contains a secret. ClipWarden replaces it with
   `[REDACTED]`.

Closing the dashboard window keeps ClipWarden running in the system tray. Use
**Exit ClipWarden...** in the tray menu (right-click the tray icon) to stop it
completely.

> Never start `clipwarden.exe` by hand. It is the background service; the
> dashboard starts it for you, and it opens no console window when it is
> started on its own.

---

## Table of contents

- [Why](#why)
- [Features](#features)
- [Protection modes](#protection-modes)
- [Templates](#templates)
- [The Windows clipboard history](#the-windows-clipboard-history)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Building](#building)
- [Using the command line](#using-the-command-line)
- [Configuration](#configuration)
- [Settings](#settings)
- [Paths](#paths)
- [Removing ClipWarden](#removing-clipwarden)
- [Detection](#detection)
- [Security model](#security-model)
- [License and trademark](#license-and-trademark)
- [Limitations](#limitations)
- [Testing](#testing)
- [License](#license)

---

## Why

Developers constantly copy secrets: from source trees, `.env` files, terminal
output, API responses, connection strings and password managers. Pasting one
of them into an AI assistant, a forum, a chat message or a remote shell leaks
it, often without noticing.

ClipWarden acts as an additional layer between the application that copies and
the application that pastes. It inspects the clipboard locally, decides
whether the content is dangerous, and rewrites or blocks it before it can be
pasted into an untrusted application.

## Features

- **Real-time clipboard monitoring** using the Windows clipboard format
  listener.
- **45 detection categories**: provider API keys, bearer tokens, JWTs, private
  keys, database URLs, passwords, credit card numbers, IBANs, e-mail
  addresses, IPv4 and IPv6 addresses.
- **Four detection techniques**: regular expressions, entropy analysis, known
  credential signatures with checksums, and context-aware matching.
- **Ready-made templates** for e-mail addresses, phone numbers and every kind
  of secret: one click, no regex knowledge required.
- **Protection modes**: allow, redact, remove and block.
- **Ghost and satellite modes**: protect on copy, or apply per-application
  policies on paste.
- **Per-application policies** with wildcard patterns and explicit trust
  exceptions.
- **Custom detection rules**: user-defined regular expressions with a risk
  classification.
- **Live dashboard** with detection notifications and statistics that never
  contain secret material.
- **System tray** and optional start-with-Windows registration.
- **No Node.js**: the dashboard is plain HTML, CSS and JavaScript served by
  Tauri.

## Protection modes

| Mode     | Behaviour                                                          |
| -------- | ------------------------------------------------------------------ |
| `allow`  | The content is left untouched.                                     |
| `redact` | The secret is replaced with a placeholder such as `[REDACTED]`.    |
| `remove` | The secret is removed and the surrounding structure is cleaned up.  |
| `block`  | The paste is prevented and the user is notified.                   |

Two global strategies decide *when* the decision is made:

| Global mode   | Behaviour                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------- |
| **Ghost**     | The clipboard is protected the moment content is copied, no matter where it is pasted later.  |
| **Satellite** | The original value stays on the clipboard; the policy of the target application is applied when the paste happens. |

## Templates

The **Templates** tab in the dashboard offers ready-made detection rules so
that you do not have to write a single regular expression:

- **E-mail addresses**: Gmail, Googlemail, Outlook, Hotmail, Live, Outlook
  (`.in`), Yahoo, Proton, iCloud, AOL, Zoho, Yandex, GMX, Tutanota and more.
- **Phone numbers**: international format (`+14155552671`), labelled numbers
  (`phone: ...`) and national numbers. You can also enter **your own phone
  number**, which is then matched literally and never triggers on other
  numbers.
- **Secrets**: one template per category: OpenAI, Anthropic, GitHub, GitLab,
  AWS, Google, Slack, Stripe, npm, Hugging Face, JWT, Bearer, Basic auth,
  passwords, API keys, private keys, database connection strings, IP
  addresses, credit cards, social security numbers and IBANs.

Every template becomes a normal custom rule that you can edit or remove.

## The Windows clipboard history

Windows keeps a history of everything you copy: the panel that opens with
`Win+V`. The entries are stored by the operating system, **before** ClipWarden
can mask the clipboard, so the original secret would still be there and could
be pasted again later. With the cloud clipboard it even travels to the other
devices of the account.

The dashboard warns about this and switches the history off with one click.
The command line does the same:

```powershell
clipwarden history            # show the state
clipwarden history disable    # switch the history and the cloud upload off
```

Entries that are already in the history are deleted once with `Win+V` and
**Clear**; Windows offers no API for that.

## Architecture

```text
+--------------------------------------------------------------------------+
|  Windows applications: VS Code, browser, terminal, chat assistant        |
+---------------------------+----------------------------------------------+
                            | paste
                            v
+--------------------------------------------------------------------------+
|  Clipboard monitor (clipwarden-clipboard)                                  |
|  - AddClipboardFormatListener on a message-only window                   |
|  - Low level keyboard hook for paste shortcuts                           |
|  - Foreground application resolution                                     |
+---------------------------+----------------------------------------------+
                            | clipboard event
                            v
+--------------------------------------------------------------------------+
|  Secret detection engine (clipwarden-core)                                |
|  - Regular expressions, entropy, checksums, context awareness            |
+---------------------------+----------------------------------------------+
                            | findings (metadata only)
                            v
+--------------------------------------------------------------------------+
|  Policy engine (clipwarden-core)                                          |
|  - Application identity, protection mode, user rules, risk level         |
+---------------------------+----------------------------------------------+
                            | decision
              +-------------+-------------+--------------+
              v                           v              v
          allow                       redact          block
```

The security engine is completely independent of the user interface. The
desktop application is a client of the local control channel, not the owner
of the protection logic; the same engine also runs as a background service.

## Repository layout

```text
crates/
  clipwarden-core/          Detection engine, policy engine, templates, configuration
  clipwarden-clipboard/     Win32 clipboard access, monitor, paste hook, app identity
  clipwarden-daemon/        Background service, runtime, control channel, tray, CLI
  clipwarden-uninstaller/   The uninstaller of the portable package
apps/
  desktop/                 Tauri 2 dashboard (plain HTML, CSS and JavaScript)
scripts/                   Local maintenance scripts (not published)
docs/                      Architecture, security model, user documentation
```

## Building

### Prerequisites

- Rust 1.90 or newer (`rustup update stable`)
- Windows 10 1809 or newer

Node.js is **not** required: the dashboard is plain HTML, CSS and JavaScript.

### Release build

```powershell
cargo build --release --workspace
cargo build --release --manifest-path apps\desktop\src-tauri\Cargo.toml
```

That produces `target\release\clipwarden.exe`,
`target\release\clipwarden-desktop.exe` and
`target\release\clipwarden-uninstall.exe`. The portable package is assembled
from them: the two programs, `uninstall.exe`, `LICENSE` and `NOTICE`.

### Manual build

```powershell
cargo build --release --workspace
cargo build --release --manifest-path apps\desktop\src-tauri\Cargo.toml
```

> If the workspace does not fit on your drive, redirect the build directory:
> `$env:CARGO_TARGET_DIR = "D:\path\to\target"`.

## Using the command line

```powershell
# Run the background service with a tray icon
clipwarden run

# Run without a tray icon (for example at login)
clipwarden --headless

# Inspect what would be protected; the secret is never printed
clipwarden scan "token=ghp_<example>"
# 1 secret(s) detected:
#   [critical] GitHub token - rule `github-token`, 40 byte(s) at offset 6

# Show and change the configuration
clipwarden config show
clipwarden config set protection.default_mode block
clipwarden config path

# Statistics of the running service
clipwarden stats

# Stop the running service (the tray menu does the same)
clipwarden shutdown

# Show the clipboard history of Windows, or switch it off
clipwarden history
clipwarden history disable

# Start automatically with Windows
clipwarden autostart enable
```

## Configuration

The configuration lives in `%APPDATA%\ClipWarden\config.toml` and never
contains credentials, only patterns that describe what should be protected.

```toml
[general]
enabled = true
global_mode = "ghost"               # ghost | satellite
fail_safe = "redact"                # redact | allow | remove
monitor_clipboard = true
intercept_paste = true
restore_on_trusted_paste = true
start_with_windows = false
show_tray_icon = true
notifications = true
protect_existing_clipboard = false  # also mask what was copied before the start
disable_windows_history = false     # keep the clipboard history of Windows off
password_hash = ""                  # Argon2id hash, empty means no password

[detection]
enabled_kinds = []                  # empty means "all kinds"
disabled_kinds = []
detect_personal = true

[detection.entropy]
min_length = 24
threshold = 4.2
require_context = true
detect_hex = false

[protection]
default_mode = "redact"
placeholder = "[REDACTED]"

[[apps]]
id = "trusted-password-managers"
label = "Password managers"
pattern = "*1Password.exe"
mode = "allow"
trusted = true
enabled = true

[[rules]]
name = "Internal token"
pattern = "INT-[0-9A-Z]{16}"
kind = "custom"
risk = "high"
group = 0
```

Application patterns support `*` (any sequence), `?` (one character) and
brace alternatives such as `{chrome,msedge,firefox}.exe`.

## Settings

Everything is configurable from the **Settings** tab of the dashboard; no file
editing is required.

| Setting                      | What it does                                                           |
| ---------------------------- | ---------------------------------------------------------------------- |
| Global mode                  | `ghost` (protect on copy) or `satellite` (decide on paste)             |
| Fail-safe                    | What happens when the protection pipeline fails                        |
| Monitor the clipboard        | Turns the clipboard watcher on or off                                  |
| Intercept paste shortcuts    | Applies the policy of the target application when pasting              |
| Restore for trusted apps     | Gives the original value back to password managers                     |
| Notifications                | Shows a notification on a detection                                    |
| Mask older clipboard content | Also masks what was on the clipboard before the start (off by default) |
| System tray icon             | Shows the tray icon                                                    |
| Start with Windows           | Registers the per-user autostart entry                                 |
| Default action               | `allow`, `redact`, `remove` or `block`                                 |
| Placeholder                  | The text that replaces a secret, `[REDACTED]` by default               |
| Detection tuning             | Personal data, entropy threshold, minimum token length                 |
| Password                     | Locks the dashboard behind a password                                  |

The **Files and folders** card shows every location ClipWarden uses.

## Paths

ClipWarden is portable: it never writes into its own folder. Everything lives
in the user profile.

| What                    | Where                                                     |
| ----------------------- | --------------------------------------------------------- |
| Configuration           | `%APPDATA%\ClipWarden\config.toml`                        |
| Log file                | `%APPDATA%\ClipWarden\ClipWarden.log`                      |
| Data folder             | `%APPDATA%\ClipWarden\`                                   |
| Autostart entry         | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`      |
| Control channel (local) | `\\.\pipe\ClipWarden.Control`                             |
| Single instance mutex   | `Local\ClipWarden.SingleInstance`                         |
| Dashboard mutex         | `Local\ClipWarden.Dashboard`                              |
| Web view data           | `%LOCALAPPDATA%\dev.mukilesh.clipwarden`                  |

The portable folder contains the two programs, `uninstall.exe`,
`LICENSE` and `NOTICE`.

## Removing ClipWarden

There are two removal programs, and they are not the same:

| Program | Where | What it does |
| --- | --- | --- |
| `uninstall.exe` | inside the portable folder | Stops ClipWarden, removes the automatic start entry, the data folder of the dashboard and the program files (including the folder itself). **Your settings and the log file stay** in `%APPDATA%\ClipWarden`, so a new installation continues with the same configuration. |
| `clipwarden-cleanup.exe` | next to the portable ZIP, not inside it | The complete removal: everything the uninstaller does, plus the settings and the log file. Use it when the computer is given away or no trace should be left behind. |

Both programs ask for a confirmation first and print every step.

## Detection

| Category             | Examples                                                                                |
| -------------------- | --------------------------------------------------------------------------------------- |
| API keys             | OpenAI, Anthropic, Google, AWS, GitHub, GitLab, Stripe, Slack, npm, Hugging Face, Azure |
| Authentication       | Bearer tokens, JWTs, Basic auth, OAuth tokens, session cookies                          |
| Passwords            | `password = ...`, `pwd: ...`, credential assignments                                    |
| Private keys         | PEM (RSA, EC, DSA, OPENSSH, PGP), PuTTY keys, certificates                              |
| Databases            | PostgreSQL, MySQL, MongoDB, Redis, SQL Server, JDBC, ADO connection strings             |
| Cloud credentials    | AWS access keys and secrets, Azure storage keys, GCP service accounts                   |
| Personal information | E-mail addresses, phone numbers, credit cards, SSNs, IBANs                              |
| Network              | IPv4 and IPv6 addresses                                                                 |
| Custom secrets       | User-defined regular expressions                                                        |

Detection techniques:

1. **Regular expressions** anchored on provider-specific signatures.
2. **Entropy analysis** for unknown tokens, with a length floor, a charset
   analysis and an optional keyword requirement.
3. **Credential signatures** validated with checksums (Luhn for card numbers,
   ISO 13616 mod-97 for IBANs) to eliminate false positives.
4. **Context awareness**: a generic `secret = ...` only triggers when the key
   name actually talks about a secret, and obvious placeholders such as
   `changeme` or `your_api_key_here` are ignored.

### Measured accuracy

The numbers are produced by the test suite, not estimated:

| Measurement | Value |
| --- | --- |
| Detections that must be found | 21 of 21 (every provider, every format) |
| Ordinary texts that must not be flagged | 16 of 16 (0 false positives) |
| Ordinary texts used for the measurement | source code, log lines, SQL, configuration files, prose, placeholders, environment references, git hashes |

E-mail addresses and IP addresses are **reported on purpose** — they are not
secrets in the strict sense, but a clipboard firewall that lets them through
would be useless. They can be switched off with
`detect_personal = false`.

## Security model

- **All detection is local.** The engine performs no network access at all.
- **No secrets in logs.** Findings store byte offsets, a rule name and a keyed
  fingerprint (HMAC-SHA256, truncated). The fingerprint is created per
  process, so values cannot be correlated across restarts or machines.
- **No clipboard history.** Only the current clipboard content is inspected,
  and the in-memory copy is wiped as soon as the clipboard changes.
- **No plaintext credentials in the configuration.** The configuration only
  describes *patterns*.
- **No administrator privileges.** The service runs as the current user and
  registers itself in the per-user `Run` key.
- **Fail-safe behaviour is configurable.** If the protection pipeline fails,
  ClipWarden can redact (default), remove or allow.
- **Clipboard access is retried, not assumed.** Windows serialises clipboard
  access; ClipWarden retries with a bounded budget instead of losing an event.

## License and trademark

The source code is licensed under Apache-2.0, which grants every user an
express patent license from the contributors. The name *ClipWarden* is a
trademark of Mukilesh and is not covered by the license; see
[`TRADEMARK.md`](TRADEMARK.md).

## Limitations

Windows does not provide a universal, race-free API that intercepts every
application's paste operation. ClipWarden combines clipboard monitoring,
controlled clipboard replacement and a low-level keyboard hook, but it cannot
guarantee that no data ever leaves the machine:

- Applications that paste with a mechanism other than the clipboard (drag and
  drop, `WM_COPYDATA`, middle click in X11 apps) are not intercepted.
- A paste that happens between the copy and the protection decision may slip
  through in rare timing situations.
- Content that was on the clipboard before ClipWarden started stays untouched
  unless the option "Mask older clipboard content" is switched on.
- Very large clipboard payloads are truncated before scanning.

ClipWarden reduces accidental exposure. It is a firewall, not a guarantee.

## Testing

```powershell
cargo test --workspace
```

The test suite covers detection accuracy (true and false positives), redaction
and removal semantics, policy resolution, the template catalogue, the
configuration protocol, statistics and the clipboard access layer.

## License

Licensed under the [Apache License, Version 2.0](LICENSE); see
[`NOTICE`](NOTICE) for the copyright and trademark notice.
Copyright (c) 2026 Mukilesh <145214507+MukileshT@users.noreply.github.com>.

Apache-2.0 grants every user an **express patent license** from the
contributors. The name *ClipWarden* is a trademark and is not covered by the
license; see [`TRADEMARK.md`](TRADEMARK.md) and
[docs/intellectual-property.md](docs/intellectual-property.md).
