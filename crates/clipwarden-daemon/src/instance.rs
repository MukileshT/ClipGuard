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

//! Single instance handling.
//!
//! ClipWarden must never run twice: two processes monitoring the clipboard
//! would fight over the clipboard and could undo each other's protection. A
//! named mutex guarantees that only one instance owns the clipboard.

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

/// A Windows mutex that marks the running instance.
pub struct SingleInstance(HANDLE);

// A Windows handle is a plain kernel handle; moving it between threads is
// safe as long as it is closed exactly once.
unsafe impl Send for SingleInstance {}

impl SingleInstance {
    /// Acquires the mutex.
    ///
    /// Returns `None` when another instance already holds it.
    pub fn acquire(name: &str) -> Option<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let handle =
            unsafe { CreateMutexW(None, true, windows::core::PCWSTR(wide.as_ptr())) }.ok()?;

        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return None;
        }
        Some(Self(handle))
    }

    /// Releases the mutex.
    pub fn release(self) {
        let _ = self;
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
