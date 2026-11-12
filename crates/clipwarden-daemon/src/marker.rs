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

//! The marker of a deliberate stop.
//!
//! The dashboard restarts the service when it dies, because a firewall that
//! silently stops working is worse than no firewall. A stop that the user
//! asked for must not be undone, so the service leaves a marker behind before
//! it quits. The dashboard reads the marker before it starts the service
//! again.

use std::path::PathBuf;

/// Name of the marker file.
const MARKER: &str = "stopped";

/// Returns the path of the marker file.
pub fn path() -> PathBuf {
    let mut folder = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    folder.push("ClipWarden");
    folder.push(MARKER);
    folder
}

/// Returns `true` when the service was stopped on purpose.
pub fn exists() -> bool {
    path().exists()
}

/// Writes the marker: the service quits on purpose.
pub fn set() {
    let path = path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, b"the service was stopped on purpose");
}

/// Removes the marker: the service is running again.
pub fn clear() {
    let _ = std::fs::remove_file(path());
}
