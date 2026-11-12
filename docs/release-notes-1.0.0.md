# ClipWarden 1.0.0

**Native Windows clipboard security firewall.** ClipWarden watches the clipboard,
detects credentials and personal data, and protects them before they reach
another application. Everything happens locally: no network traffic, no cloud
service, no clipboard history.

## Download

Grab `ClipWarden-Portable.zip`, extract it to any folder and double-click
**clipwarden-desktop.exe**. That is the whole installation.

The package contains:

| File | Purpose |
| --- | --- |
| `clipwarden-desktop.exe` | The dashboard, a Tauri application |
| `clipwarden.exe` | The background service with the tray icon |
| `uninstall.exe` | Removes the program and every file it created |
| `LICENSE` | The licence of the program |
| `NOTICE` | Copyright, patent and trademark notice |
| `README.txt` | Short instructions for the first start |

## What it does

- **45 detection categories**: provider API keys (OpenAI, Anthropic, Google,
  AWS, GitHub, GitLab, Stripe, Slack, npm, Hugging Face), bearer tokens, JWTs,
  private keys, database URLs, passwords, credit cards, IBANs, e-mail addresses,
  IPv4 and IPv6 addresses.
- **Four detection techniques**: regular expressions, entropy analysis,
  credential signatures validated with checksums (Luhn, ISO 13616 mod-97) and
  context awareness.
- **Protection modes**: `allow`, `redact`, `remove` and `block`.
- **Ghost and satellite modes**: protect the moment you copy, or decide when you
  paste depending on the application that receives it.
- **Ready-made templates** for e-mail addresses, phone numbers and every kind
  of secret, including a template for your own phone number.
- **Per-application policies** with wildcard patterns and trust exceptions.
- **A dashboard** with live statistics and a detection feed that never contains
  the secret itself.

## Privacy

- All detection runs **on your machine**. There is no network code in the
  project at all.
- Findings never contain the secret: they store byte offsets, a rule name and a
  keyed fingerprint that is created per process.
- The in-memory copy of the clipboard is wiped as soon as the clipboard changes.
- No administrator privileges, no service registration, no telemetry.

## The Windows clipboard history

Windows keeps a history of everything you copy (the panel that opens with
`Win+V`). It records the original secret **before** ClipWarden can mask the
clipboard. The dashboard therefore warns about this and switches the history
and the cloud clipboard off with one click. Entries that are already stored are
deleted once with `Win+V` and **Clear**; Windows offers no API for that.

## Usage

- The system tray icon is the control centre: it opens the dashboard, pauses
  the protection, switches between ghost and satellite mode, toggles the
  automatic start and quits ClipWarden.
- Closing the dashboard window keeps the protection running in the tray. Only
  **Exit ClipWarden...** in the tray menu stops it; it asks for a confirmation
  first.
- Everything is configurable in the **Settings** tab of the dashboard.

## Licence

Licensed under the Apache License 2.0, which grants every user an express
patent licence from the contributors. The project itself may be patented, and
the name *ClipWarden* is a trademark of Mukilesh.

Copyright (c) 2026 Mukilesh <145214507+MukileshT@users.noreply.github.com>
