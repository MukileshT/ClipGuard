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

//! Automatic start configuration.
//!
//! ClipGuard registers itself in the per user `Run` key of the registry. No
//! administrator privileges are required and no service is installed.

use std::path::PathBuf;

use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

/// Sub key that contains the auto start entries.
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// Name of the registry value.
const VALUE_NAME: &str = "ClipGuard";

/// Errors that can occur while configuring the auto start entry.
#[derive(Debug, thiserror::Error)]
pub enum AutostartError {
    /// A registry call failed.
    #[error("registry error: {0}")]
    Registry(u32),
    /// The path of the executable could not be determined.
    #[error("the path of the ClipGuard executable is unknown")]
    UnknownPath,
}

/// Returns `true` when ClipGuard starts automatically with Windows.
pub fn is_enabled() -> bool {
    let mut key = HKEY::default();
    let sub_key = wide(RUN_KEY);
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(sub_key.as_ptr()),
            None,
            KEY_READ,
            &mut key,
        )
    };
    if status != windows::Win32::Foundation::WIN32_ERROR(0) {
        return false;
    }
    let value_name = wide(VALUE_NAME);
    let mut size: u32 = 0;
    let status = unsafe {
        RegQueryValueExW(
            key,
            windows::core::PCWSTR(value_name.as_ptr()),
            None,
            None,
            None,
            Some(&mut size),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    status == windows::Win32::Foundation::WIN32_ERROR(0)
}

/// Returns `true` when the entry points at the running executable.
///
/// The program can be moved or replaced, and then the entry points at a path
/// that no longer exists. In that case the entry is written again.
pub fn points_at_current_executable() -> bool {
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    match read_command() {
        Some(command) => {
            let command = command.trim().trim_matches('"');
            command.eq_ignore_ascii_case(&executable.display().to_string())
        }
        None => false,
    }
}

/// Reads the command of the entry.
fn read_command() -> Option<String> {
    let mut key = HKEY::default();
    let sub_key = wide(RUN_KEY);
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(sub_key.as_ptr()),
            None,
            KEY_READ,
            &mut key,
        )
    };
    if status != windows::Win32::Foundation::WIN32_ERROR(0) {
        return None;
    }

    let value_name = wide(VALUE_NAME);
    let mut size: u32 = 0;
    let status = unsafe {
        RegQueryValueExW(
            key,
            windows::core::PCWSTR(value_name.as_ptr()),
            None,
            None,
            None,
            Some(&mut size),
        )
    };
    if status != windows::Win32::Foundation::WIN32_ERROR(0) || size == 0 {
        unsafe {
            let _ = RegCloseKey(key);
        }
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        RegQueryValueExW(
            key,
            windows::core::PCWSTR(value_name.as_ptr()),
            None,
            None,
            Some(buffer.as_mut_ptr()),
            Some(&mut size),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if status != windows::Win32::Foundation::WIN32_ERROR(0) {
        return None;
    }

    let units: Vec<u16> = buffer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    Some(text.trim_end_matches('\0').to_string())
}

/// Enables or disables the auto start entry.
pub fn set_enabled(enabled: bool) -> Result<(), AutostartError> {
    let mut key = HKEY::default();
    let sub_key = wide(RUN_KEY);
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(sub_key.as_ptr()),
            None,
            windows::core::PCWSTR::null(),
            windows::Win32::System::Registry::REG_OPEN_CREATE_OPTIONS(0),
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
    };
    if status != windows::Win32::Foundation::WIN32_ERROR(0) {
        return Err(AutostartError::Registry(status.0));
    }

    let value_name = wide(VALUE_NAME);
    let result = if enabled {
        let executable = std::env::current_exe().map_err(|_| AutostartError::UnknownPath)?;
        // The service starts with its tray icon.
        let command = format!("\"{}\"", executable.display());
        let data = wide_bytes(&command);
        let status = unsafe {
            RegSetValueExW(
                key,
                windows::core::PCWSTR(value_name.as_ptr()),
                None,
                REG_SZ,
                Some(&data),
            )
        };
        if status != windows::Win32::Foundation::WIN32_ERROR(0) {
            Err(AutostartError::Registry(status.0))
        } else {
            Ok(())
        }
    } else {
        let status = unsafe { RegDeleteValueW(key, windows::core::PCWSTR(value_name.as_ptr())) };
        if status == windows::Win32::Foundation::WIN32_ERROR(0) || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(AutostartError::Registry(status.0))
        }
    };

    unsafe {
        let _ = RegCloseKey(key);
    }
    result
}

/// Returns the path of the running executable.
pub fn executable_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// Converts a string into a null terminated UTF-16 buffer.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Converts a string into a null terminated UTF-16 buffer.
///
/// The registry expects UTF-16 for `REG_SZ`; UTF-8 bytes would be read as
/// UTF-16 and produce a garbled path.
fn wide_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(Some(0))
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_path_is_available() {
        assert!(executable_path().is_some());
    }
}
