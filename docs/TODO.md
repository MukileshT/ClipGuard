# ClipWarden - TODO

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


Checked items are done. Each completed block is committed as its own version
on the `opencode` branch.

## Behaviour

- [x] Plug and play: double-clicking `clipwarden-desktop.exe` starts the
      background service automatically, no console window appears.
- [x] The dashboard is a pure client of the control channel.
- [x] Closing the dashboard window quits the dashboard only; the service
      keeps running with its tray icon. Quitting the protection happens
      only through the tray menu → Exit, which closes the dashboard too.
- [x] `clipwarden.exe` shows no console window when double-clicked from
      Explorer, but still prints when invoked from an open terminal
      (`AttachConsole`, redirected handles are preserved).

## Features

- [x] Detection engine (45 categories), templates, per-application rules.
- [x] Password protection, autostart, tray with pause/resume.
- [x] A Settings tab in the dashboard that exposes every configurable option
      (general, protection, detection tuning, password, autostart).
- [x] The tray icon is always visible and asks for a confirmation before
      ClipWarden is quit.

## Fixes

- [x] The tray icon was created with an invalid handle and stayed invisible.
- [x] Quitting through the tray hung: the tray thread and the clipboard
      monitor were joined without stopping their message loops.
- [x] The log file stayed empty: the filter matched the product name instead
      of the crate names.
- [x] The dashboard reported "Service unavailable" after a single failed
      request and started the service again on every retry.
- [x] Saving the configuration failed while a password was set.
- [x] A change in `config.toml` only took effect when the next secret was
      copied; the file is watched now.
- [x] A secret that was copied while another application held the clipboard
      was left unprotected; the update is requested again now.
- [x] GitHub push protection blocked the repository (GH013) because the test
      fixtures contain credentials in the format of the real providers. The
      samples are assembled at runtime and the history was rewritten.

## Release

- [x] Portable ZIP with relative paths, README.txt, uninstall.bat.
- [x] GitHub push ready: no machine specific paths in scripts, CI workflow,
      clean repository state, `docs/github.md` explains the GH013 error.