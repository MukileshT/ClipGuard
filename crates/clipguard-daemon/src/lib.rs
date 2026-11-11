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

//! # ClipGuard Daemon
//!
//! The background service of ClipGuard. It wires the security engine
//! ([`clipguard_core`]) to the Windows clipboard ([`clipguard_clipboard`]) and
//! exposes the result through a local control channel.
//!
//! The daemon is completely independent of any user interface: the desktop
//! application is a client of the control channel, not the owner of the
//! protection logic.

#![warn(missing_docs)]

pub mod autostart;
pub mod history;
pub mod icon;
pub mod instance;
pub mod ipc;
pub mod protection;
pub mod runtime;
pub mod tray;

pub use instance::SingleInstance;
pub use ipc::{IpcClient, IpcEvent, IpcRequest, IpcResponse};
pub use protection::{DetectionEvent, ProtectionEngine, ProtectionStatus};
pub use runtime::Runtime;

/// The version of the ClipGuard daemon.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
