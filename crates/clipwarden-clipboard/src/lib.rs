// Copyright 2026 Mukilesh
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # ClipWarden Clipboard
//!
//! Windows specific clipboard integration for ClipWarden.
//!
//! The crate provides four building blocks:
//!
//! * [`access`] — safe wrappers around the Win32 clipboard APIs, including
//!   the retry logic that is required because the clipboard is a global,
//!   mutually exclusive resource.
//! * [`monitor`] — a message-only window that is notified whenever the
//!   clipboard content changes.
//! * [`hook`] — a low level keyboard hook that observes paste shortcuts so
//!   that per application policies can be applied before the target
//!   application reads the clipboard.
//! * [`app`] — resolution of the foreground application into an identity that
//!   the policy engine understands.
//!
//! The crate performs no network access and never writes clipboard content to
//! disk.

#![warn(missing_docs)]

pub mod access;
pub mod app;
pub mod hook;
pub mod monitor;

pub use access::{ClipboardError, clear, read_text, sequence_number, write_text};
pub use app::{AppResolver, process_image_path};
pub use hook::{HookError, PasteDecision, PasteHandler, PasteWatcher};
pub use monitor::{ClipboardAction, ClipboardHandler, ClipboardMonitor, MonitorError};
