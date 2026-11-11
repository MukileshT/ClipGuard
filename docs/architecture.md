# Architecture

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


This document describes how ClipGuard is put together and why.

## Design goals

1. **The security engine must be testable without Windows.** All detection and
   policy logic lives in `clipguard-core`, a crate that contains no `unsafe`
   code and no platform API.
2. **The user interface must not be able to weaken the protection.** The
   dashboard is a client of a local control channel; it never touches the
   clipboard and it cannot bypass the policy engine.
3. **The background service must be cheap.** An idle ClipGuard consumes a few
   megabytes of memory and effectively no CPU: the clipboard listener only
   wakes up when the clipboard changes, and the keyboard hook only does work
   when a paste shortcut is pressed.
4. **Nothing may leave the machine.** There is no telemetry, no update check
   and no network code anywhere in the workspace.
5. **No build tooling beyond Cargo.** The dashboard is plain HTML, CSS and
   JavaScript, so Node.js is not needed to build or run the application.

## Crates

### `clipguard-core`

The security engine. It is a pure library:

| Module       | Responsibility                                                  |
| ------------ | --------------------------------------------------------------- |
| `model`      | Secret kinds, risk levels, findings, protection modes            |
| `rules`      | Rule description, compilation, validation                        |
| `rules::builtin` | The catalogue of built-in detection signatures              |
| `templates`  | Ready-made rules for e-mail addresses, phone numbers and secrets |
| `engine`     | The detection engine                                             |
| `entropy`    | Shannon entropy and charset analysis                            |
| `redact`     | Applying a protection decision to text                          |
| `policy`     | Application rules and mode resolution                           |
| `config`     | TOML configuration, defaults and validation                     |
| `stats`      | Counters that never contain secret material                     |

The crate is `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

#### The detection pipeline

```text
text
 │
 ├─► pattern rules ──► context check ──► checksum validation ──┐
 │                                                           │
 └─► entropy detector ──► keyword context ───────────────────►├─► merge ──► findings
                                                             │
```

* **Pattern rules** are regular expressions with an optional capture group
  that selects the secret inside a match. This allows rules such as
  `password = <capture>` to redact only the value and keep the structure
  intact.
* **Context checks** require a keyword to appear within the 160 bytes before a
  match. A rule like `token-assignment` therefore does not fire on the word
  "token" in a sentence.
* **Checksum validation** removes false positives. A credit card number must
  pass the Luhn check, an IBAN the ISO 13616 mod-97 check, an SSN the
  structural rules of the US Social Security Administration.
* **Placeholder rejection** filters values such as `changeme`,
  `your_api_key_here` or `os.environ["SECRET"]`, which are extremely common in
  source code and would otherwise drown the real findings.
* **Merging** removes overlapping findings. When two rules match the same
  region, the more severe one wins; ties are broken by length and then by rule
  priority.

#### Findings never contain secrets

```rust
pub struct Finding {
    pub kind: SecretKind,
    pub risk: RiskLevel,
    pub span: Range<usize>,
    pub rule: String,
    pub fingerprint: String, // HMAC-SHA256, truncated, per process
    pub length: usize,
}
```

The fingerprint allows "the same secret was seen again" checks inside one
session. Because the key is generated per process, fingerprints cannot be
correlated across restarts, and they cannot be reversed into the secret.

### `clipguard-clipboard`

Everything that talks to Windows:

| Module    | Responsibility                                                |
| --------- | ------------------------------------------------------------- |
| `access`  | Open/read/write/clear the clipboard with a bounded retry loop |
| `monitor` | Message-only window and the clipboard format listener          |
| `hook`    | Low level keyboard hook that observes paste shortcuts          |
| `app`     | Resolution of the foreground application into an identity      |

Two details deserve an explanation:

**Clipboard contention.** The Windows clipboard is a single global resource.
`OpenClipboard` fails while another application holds it. ClipGuard retries
with a short backoff (24 attempts, 8 ms apart) instead of dropping the event.
Inside the keyboard hook, where blocking is dangerous, a much shorter budget
(4 attempts) is used so that Windows never considers the hook unresponsive.

**The paste hook.** `WH_KEYBOARD_LL` hooks are invoked before the key is
delivered to the foreground application. That is the only moment at which the
clipboard can still be changed in time. When the policy says `block`, the hook
returns a non-zero value, which stops the key from reaching the target
application — the paste never happens.

### `clipguard-daemon`

The background service and the glue between the two crates above:

| Module      | Responsibility                                              |
| ----------- | ----------------------------------------------------------- |
| `protection`| The protection engine: clipboard events and paste decisions  |
| `runtime`   | Starts the monitor, the hook and the control channel         |
| `ipc`       | The local control channel (named pipe, JSON lines)           |
| `tray`      | The system tray icon and its menu                            |
| `autostart` | The per-user `Run` registry entry                            |
| `instance`  | The single instance mutex                                    |
| `icon`      | The application icon, generated at runtime                   |

### `apps/desktop`

The Tauri 2 dashboard. It is a pure client of the control channel:

* It acquires its own single instance mutex (`ClipGuard.Dashboard`), which is
  deliberately **different** from the service mutex. Using the same mutex would
  prevent the service from starting while the dashboard is open.
* If the service is not running, the dashboard starts `clipguard.exe --headless`
  with the `CREATE_NO_WINDOW` flag, so no console window appears.
* All commands are IPC requests (`get_stats`, `get_config`, `set_config`,
  `scan`, `set_paused`, …).
* Detection events are pushed by the service and forwarded to the web view.

## The control channel

The service exposes `\\.\pipe\ClipGuard.Control`. The protocol is one JSON
object per line:

```text
-> {"id":1,"cmd":"get_stats","args":{}}
<- {"id":1,"ok":true,"result":{"scans":42,"detections":3, ...}}
<- {"event":"detection","data":{"kinds":["github_token"],"risk":"critical", ...}}
```

The pipe is local to the machine and inherits the permissions of the user that
started the service. It contains no secret material — the detection events
carry metadata only.

## Threading model

```text
main thread          clipboard monitor thread      control channel thread
──────────           ──────────────────────       ─────────────────────
tray commands   ──►  window procedure                 accept loop
shutdown              keyboard hook                   command dispatch
                      (both run here)                 event broadcast
```

The clipboard monitor and the keyboard hook must live on the same thread: a low
level hook is dispatched by the thread that installs it. The control channel
runs on its own thread so that a slow client cannot delay protection.

## Decision flow

### On a clipboard change

```text
clipboard changed
   │
   ├─ configuration reloaded if the file changed
   ├─ protection disabled?  ─────────────► ignore
   ├─ no text?              ─────────────► ignore, wipe the buffer
   ├─ scan the content
   │    └─ no findings?     ─────────────► ignore, wipe the buffer
   ├─ remember the original and the protected variant in the vault
   ├─ ghost mode?
   │    ├─ allow  ──────────────────────► ignore
   │    ├─ redact / remove ─────────────► rewrite the clipboard
   │    └─ block  ──────────────────────► clear the clipboard
   └─ satellite mode ───────────────────► keep the original, decide on paste
```

### On a paste

```text
Ctrl+V pressed
   │
   ├─ protection disabled or interception off? ─► continue
   ├─ no secret pending?                       ─► continue
   ├─ resolve the policy of the foreground application
   ├─ allow   ─► restore the original (trusted app) ─► continue
   ├─ redact  ─► write the protected variant ──────────► continue
   ├─ remove  ─► write the protected variant ──────────► continue
   └─ block   ─► clear the clipboard ────────────────► suppress the key
```

## Extension points

* **Custom rules** — regular expressions with a risk classification, configured
  in the dashboard or in the TOML file.
* **Templates** — ready-made rules for the most common cases, offered in the
  dashboard.
* **Application rules** — wildcard patterns with a mode and a trust flag.
* **The engine** — `DetectionEngine::from_specs` accepts an arbitrary rule
  set, so an alternative front end (or a stricter profile) can be built
  without touching the rest of the system.