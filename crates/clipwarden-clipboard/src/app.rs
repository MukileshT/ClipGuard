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

//! Foreground application identification.
//!
//! The policy engine works with application identities ("this is Chrome, this
//! is Visual Studio Code"). Resolving an identity requires the process id of
//! the foreground window and its image path, which is comparatively slow, so
//! results are cached per process id.

use std::collections::HashMap;
use std::sync::Mutex;

use clipwarden_core::model::AppIdentity;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::core::PWSTR;

/// Resolves and caches the identity of the foreground application.
#[derive(Debug, Default)]
pub struct AppResolver {
    cache: Mutex<HashMap<u32, Option<AppIdentity>>>,
}

impl AppResolver {
    /// Creates an empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the identity of the application that currently has the focus.
    pub fn foreground(&self) -> Option<AppIdentity> {
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.is_invalid() {
            return None;
        }
        let mut process_id = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
        if process_id == 0 {
            return None;
        }
        self.identity_of(process_id)
    }

    /// Returns the identity of the process with the given id.
    pub fn identity_of(&self, process_id: u32) -> Option<AppIdentity> {
        if let Some(cached) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&process_id).cloned())
        {
            return cached;
        }
        let identity = process_image_path(process_id).map(|path| {
            let exe = path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(path.as_str())
                .to_string();
            AppIdentity::new(exe, Some(path))
        });
        if let Ok(mut cache) = self.cache.lock() {
            // Keep the cache small; it only exists to avoid hammering the
            // process table during rapid paste sequences.
            if cache.len() > 128 {
                cache.clear();
            }
            cache.insert(process_id, identity.clone());
        }
        identity
    }

    /// Removes all cached identities.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }
}

/// Returns the full image path of a process.
pub fn process_image_path(process_id: u32) -> Option<String> {
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }.ok()?;
    let mut size = 260u32;
    let mut buffer = vec![0u16; size as usize];
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    result.ok()?;
    buffer.truncate(size as usize);
    let path = String::from_utf16_lossy(&buffer);
    if path.is_empty() { None } else { Some(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_an_image_path() {
        let pid = std::process::id();
        let path = process_image_path(pid).expect("the current process must have an image path");
        assert!(
            path.to_lowercase().contains("ClipWarden") || path.to_lowercase().ends_with(".exe")
        );
    }

    #[test]
    fn resolver_returns_the_current_process() {
        let resolver = AppResolver::new();
        let identity = resolver.identity_of(std::process::id()).expect("identity");
        assert!(identity.exe.to_lowercase().ends_with(".exe"));
    }
}
