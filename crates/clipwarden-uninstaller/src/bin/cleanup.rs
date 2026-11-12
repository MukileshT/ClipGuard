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

//! Removes ClipWarden completely, including the settings and the log file.
//!
//! This program is **not** part of the portable package. It is the tool for a
//! clean removal, for example when the computer is given away or the settings
//! should not stay behind.

fn main() {
    clipwarden_uninstaller::run(clipwarden_uninstaller::Mode::Purge);
}
