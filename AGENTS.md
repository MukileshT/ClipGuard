<!-- Copyright 2026 Mukilesh -->
<!-- Licensed under the Apache License, Version 2.0. -->

# ClipWarden agent guide

## Project shape

- Windows-only Rust clipboard firewall. The root Cargo workspace contains `clipwarden-core`, `clipwarden-clipboard`, `clipwarden-daemon`, and `clipwarden-uninstaller`; `apps/desktop/src-tauri` is a **separate** Tauri workspace.
- Keep detection/policy code in `clipwarden-core`; it is platform-neutral and enforces `#![forbid(unsafe_code)]`. Put Win32 integration in `clipwarden-clipboard` or `clipwarden-daemon`.
- The dashboard is plain HTML/CSS/JS under `apps/desktop/src-tauri/frontend` (no Node.js). It is only an IPC client; it must not bypass the daemon’s protection decisions.
- `clipwarden.exe` is the background service/CLI. Do not launch it as the normal desktop entrypoint; `clipwarden-desktop.exe` starts it headlessly and owns service recovery.

## Commands

Run root workspace checks before changing behavior:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Focused checks:

```powershell
cargo test -p clipwarden-core --test detection
cargo test -p clipwarden-daemon --lib
cargo test -p clipwarden-daemon --test ipc
cargo build --release -p clipwarden-daemon
cargo build --release -p clipwarden-uninstaller
cargo build --release --manifest-path apps\desktop\src-tauri\Cargo.toml
```

- Release builds use `panic = "abort"`; stop running `clipwarden.exe` and `clipwarden-desktop.exe` before rebuilding, otherwise Windows locks the target `.exe`.
- The maintainer-only, gitignored `scripts\build-release.ps1` builds with `--locked`; after dependency or package-name changes, update both lockfiles before packaging: `cargo update --workspace`, then `Push-Location apps\desktop\src-tauri; cargo update; Pop-Location`.
- Set `CARGO_TARGET_DIR` when build output must be off the repository drive. `CLIPWARDEN_LOG_DIR` redirects daemon logs; `WEBVIEW2_USER_DATA_FOLDER` redirects WebView data.

## Security-sensitive constraints

- Do not log clipboard text or send it over IPC. Findings/events carry metadata only (kind, risk, offsets, keyed per-process fingerprint).
- Keep the named pipe `\\.\pipe\ClipWarden.Control` owner-only: SDDL `D:P(A;;GA;;;OW)`, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and the 8-instance cap are deliberate defenses. Exercise the daemon IPC tests after changing this code.
- The desktop watchdog is the crash recovery path; the deliberate-stop marker prevents it from restarting a tray-exited service. Preserve both behaviors when touching shutdown/startup.
- Password hashing is Argon2id; do not restore legacy SHA-256 compatibility. Clipboard vault values are encrypted in memory with a process-random AES-256-GCM key.
- Test credential-like strings must be synthetic and assembled at runtime (see `fake_secret` usages); never add literal realistic tokens, even encoded, because GitHub push protection scans history.

## Release and repository details

- Portable packaging includes `clipwarden.exe`, `clipwarden-desktop.exe`, `uninstall.exe`, `LICENSE`, `NOTICE`, and `README.txt`. `clipwarden-cleanup.exe` stays **outside** the ZIP because it deletes `%APPDATA%\ClipWarden` settings/logs; `uninstall.exe` must preserve them.
- The CI source of truth is `.github/workflows/build.yml`; it runs formatting, clippy with warnings denied, workspace tests, `cargo deny check`, and the separate dashboard build on Windows.
- `scripts/rename-to-clipwarden.ps1` is a one-time migration script. Do not run it or modify it for normal work; remove it when cleaning up local maintainer tooling.
- Add the repository’s Apache-2.0 copyright header to new source/docs, matching neighboring files.
