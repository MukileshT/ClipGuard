# User guide

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


## Installing

ClipGuard is portable — there is nothing to install.

1. Extract `ClipGuard-Portable.zip` to any folder.
2. Double-click **clipguard-desktop.exe**.

The background service starts automatically. No console window appears.

To start ClipGuard automatically when you log into Windows, open the dashboard
and enable **Start with Windows** in the protection settings.

## First start

ClipGuard starts in **Ghost mode** with the default action **Redact**:

1. Copy a piece of text that contains a secret.
2. ClipGuard detects it and rewrites the clipboard immediately.
3. Pasting anywhere now inserts `[REDACTED]` instead of the secret.

Open the dashboard to see what was detected. The dashboard shows the category,
the risk level and the application — never the secret itself.

## The dashboard

| Tab                 | What it does                                              |
| -------------------- | --------------------------------------------------------- |
| **Dashboard**        | Protection status, statistics and live detections          |
| **Applications**     | Per-application rules (allow, redact, remove, block)       |
| **Detection rules**  | Custom rules and detection tuning                         |
| **Templates**        | Ready-made rules for e-mail, phone and secret categories   |
| **About**            | What ClipGuard does and does not do                       |

## The system tray

ClipGuard lives in the system tray (the area next to the clock).

- **Left-click** the icon — opens the dashboard.
- **Right-click** the icon — opens the menu:
  - **Open ClipGuard** — show the dashboard
  - **Pause protection** / **Resume protection** — stop or start protecting
  - **Switch to ghost / satellite mode** — change when protection happens
  - **Start with Windows** — toggle the automatic start entry
  - **Exit** — stop ClipGuard completely

Closing the dashboard window does **not** stop ClipGuard; it keeps running in
the background. Only **Exit** in the tray menu stops it.

## Choosing a mode

### Ghost mode — protect on copy

The clipboard is protected the moment you copy. This is the safest mode and the
recommended default.

Use it when you regularly copy secrets and do not want to think about where
they end up.

### Satellite mode — protect on paste

The original value stays on the clipboard. When you press `Ctrl+V`, ClipGuard
looks at the application that receives the paste and applies its rule:

| Application       | Rule      | Result                                     |
| ----------------- | --------- | ------------------------------------------ |
| Password manager  | Allow     | The real secret is pasted.                 |
| Terminal          | Redact    | The secret is replaced by a placeholder.   |
| Browser           | Redact    | The secret is replaced by a placeholder.   |
| AI assistant      | Block     | The paste is prevented entirely.           |
| Anything else     | Default   | The configured default action is applied.  |

Satellite mode keeps more of your workflow intact, at the cost of holding the
original value in memory until the clipboard changes.

## The clipboard content that was there before

By default ClipGuard only masks what you copy **after** it started. The text
that was on the clipboard when the service started stays untouched — a password
you copied before you launched ClipGuard is not rewritten behind your back.

If you want the opposite, open the **Settings** tab and enable

> **Also mask content that was copied before ClipGuard started**

ClipGuard then checks the clipboard once at startup and masks it if it
contains a secret.

## Templates
The **Templates** tab is the fastest way to get protection without writing a
single regular expression.

### E-mail addresses

One template per provider: Gmail, Googlemail, Outlook, Hotmail, Live,
Outlook (`.in`), Yahoo, Proton, iCloud, AOL, Zoho, Yandex, GMX, Tutanota, MSN,
Duck and more. Click **Add** and addresses at that provider are redacted from
then on.

### Phone numbers

- **International phone number** — `+14155552671`
- **Labelled phone number** — anything written after `phone:` or `mobile:`
- **National phone number** — longer digit groups after a contact label
- **My phone number** — enter your own number and only that exact number is
  matched. Other phone numbers are not affected.

### Secrets

One template per category: OpenAI, Anthropic, GitHub, GitLab, AWS, Google,
Slack, Stripe, npm, Hugging Face, JWT, Bearer, Basic auth, passwords, API keys,
tokens, private keys, PostgreSQL, MySQL, MongoDB, Redis, JDBC, AWS secrets,
Azure keys, IP addresses, credit cards, social security numbers and IBANs.

Every template becomes a normal custom rule. You can edit it in the
**Detection rules** tab or remove it again.

## Application rules

Application rules match the executable name or the full path of the foreground
application.

| Pattern                | Matches                                    |
| ---------------------- | ------------------------------------------ |
| `Code.exe`             | Exactly this executable.                    |
| `*.exe`                | Every executable (very broad — avoid).     |
| `{chrome,msedge}.exe`  | Chrome or Edge.                             |
| `C:\Tools\*\app.exe`   | Everything below `C:\Tools`.                |

Rules are evaluated by specificity:

1. An exact executable name match wins.
2. An exact full path match comes next.
3. A wildcard match is the fallback.

A **trusted** rule always wins a tie. Trusted applications are never modified —
use this sparingly and only for password managers where you explicitly want
the real value.

## Custom detection rules

A custom rule is a regular expression:

| Field      | Meaning                                                                |
| ---------- | ---------------------------------------------------------------------- |
| `name`     | A unique name.                                                         |
| `pattern`  | The regular expression (Rust `regex` syntax, no look-around).         |
| `kind`     | The category the finding is reported as.                               |
| `risk`     | `low`, `medium`, `high` or `critical`.                                |
| `group`    | The capture group that contains the secret. `0` = the whole match.     |

Example — an internal token format:

```toml
[[rules]]
name = "Internal token"
pattern = "INT-[0-9A-Z]{16}"
kind = "custom"
risk = "high"
group = 0
```

Example — a password in an assignment, where only the value is the secret:

```toml
[[rules]]
name = "Service password"
pattern = "(?i)\\bservice_password\\s*=\\s*[\"']?([^\s\"',;]{8,})"
kind = "password"
risk = "high"
group = 1
```

Test a rule before you rely on it:

```powershell
clipguard scan "your sample text"
```

## Tuning the detection

```toml
[detection]
detect_personal = false        # ignore e-mail addresses, phone numbers, cards
disabled_kinds = ["credit_card"]

[detection.entropy]
threshold = 4.4                # higher = fewer entropy findings
min_length = 32                # longer tokens only
require_context = true         # a keyword must be nearby
```

Entropy detection is deliberately conservative. If you see too many findings of
the category *High entropy token*, raise the threshold instead of disabling the
detector entirely.

## Password protection

Set a password in the dashboard to lock it. The password is stored as a
SHA-256 hash in the configuration — the plain text is never written to disk.
The dashboard then asks for the password before it shows the settings or
changes them.

## Using the command line

```powershell
clipguard scan "text"           # report what would be protected
clipguard scan -                # read from standard input
clipguard rules                 # list the built-in rules
clipguard config show           # print the configuration
clipguard config path           # print the configuration path
clipguard config set protection.default_mode block
clipguard config reset          # restore the defaults
clipguard stats                 # statistics of the running service
clipguard autostart enable      # start with Windows
clipguard autostart disable
clipguard --headless            # run without a tray icon
clipguard --verbose             # more detailed logs
```

## The log file

`%APPDATA%\ClipGuard\clipguard.log` records what ClipGuard did. It contains
metadata only — categories, counts and error messages. It never contains
clipboard content.

```powershell
Get-Content "$env:APPDATA%\ClipGuard\clipguard.log" -Tail 20
```

## Troubleshooting

### A secret was not detected

1. Run `clipguard scan "<the text>"` to check the engine.
2. If it is not detected, add a template or a custom rule.
3. If `clipguard scan` detects it but the clipboard was not protected, check
   whether protection is paused and whether the service is running.

### The clipboard was not rewritten

* Another application may hold the clipboard open. ClipGuard retries for about
  200 ms and then gives up for that event.
* The payload may exceed the scan limit (512 KiB) and is truncated.
* Check the log file for `could not open the clipboard`.

### The paste was not blocked

* Make sure *Paste interception* is enabled.
* Some applications use their own paste handling that does not go through the
  keyboard hook.
* The paste happened before ClipGuard was started.

### Two ClipGuard instances

Not possible: a named mutex prevents a second service. If the dashboard
reports *ClipGuard is already running*, the background service is active and
the dashboard attached to it.