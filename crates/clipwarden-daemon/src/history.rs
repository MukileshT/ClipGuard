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

//! The clipboard history of Windows.
//!
//! Windows keeps a history of everything that was copied — the panel that
//! opens with `Win+V`. The entries are stored by the operating system, not
//! by ClipWarden, and ClipWarden can neither read nor delete them.
//!
//! That is a problem for a clipboard firewall: the original secret is
//! recorded by Windows *before* ClipWarden masks the clipboard, and it can be
//! pasted again long afterwards. The same is true for the cloud clipboard,
//! which synchronises the copied content between the devices of an account.
//!
//! The module reads and writes the settings of the history so that the
//! dashboard can warn about it and switch it off with one click.

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
    RegCloseKey, RegCreateKeyExW, RegQueryValueExW, RegSetValueExW,
};

/// The registry key that holds the clipboard settings of the user.
const CLIPBOARD_KEY: &str = r"Software\Microsoft\Clipboard";

/// Value that switches the history on and off.
const HISTORY_VALUE: &str = "EnableClipboardHistory";

/// Older Windows versions used this value to switch the history off.
const LEGACY_HISTORY_VALUE: &str = "DisableClipboardHistory";

/// Value that controls the synchronisation with the cloud clipboard.
const CLOUD_VALUE: &str = "CloudClipboardAutomaticUpload";

/// The state of the Windows clipboard history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct HistorySettings {
    /// Whether Windows keeps a history of the copied content.
    pub history_enabled: bool,
    /// Whether the copied content is sent to the cloud clipboard.
    pub cloud_upload: bool,
}

/// Whether the user asked ClipWarden to keep the history switched off.
///
/// Windows restores the setting on its own from time to time, for example
/// when the clipboard service starts. The choice is therefore remembered and
/// reapplied.
static KEEP_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Default for HistorySettings {
    fn default() -> Self {
        Self {
            history_enabled: true,
            cloud_upload: true,
        }
    }
}

/// Errors of the clipboard history settings.
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// The registry could not be changed.
    #[error("the clipboard settings could not be changed: {0}")]
    Registry(u32),
}

/// Returns the current state of the clipboard history.
pub fn settings() -> HistorySettings {
    let history = read_dword(HISTORY_VALUE);
    let legacy = read_dword(LEGACY_HISTORY_VALUE);
    let cloud = read_dword(CLOUD_VALUE);

    // The history is on unless it was switched off explicitly. The value
    // does not exist on a fresh installation, and then the history is on.
    let history_enabled = match history {
        Some(value) => value != 0,
        None => !matches!(legacy, Some(1)),
    };
    let cloud_upload = match cloud {
        Some(value) => value != 0,
        None => false,
    };

    HistorySettings {
        history_enabled,
        cloud_upload,
    }
}

/// Switches the clipboard history on or off.
///
/// Switching it off also stops the upload to the cloud clipboard: a secret
/// that is kept in the history of Windows must not travel between the
/// devices of an account either.
pub fn set_enabled(enabled: bool) -> Result<(), HistoryError> {
    use std::sync::atomic::Ordering;
    KEEP_OFF.store(!enabled, Ordering::Release);

    let key = open_key(KEY_SET_VALUE)?;
    let history = if enabled { 1u32 } else { 0 };
    write_dword(key, HISTORY_VALUE, history)?;
    // The old value would switch the history off again.
    write_dword(key, LEGACY_HISTORY_VALUE, if enabled { 0 } else { 1 })?;
    write_dword(key, CLOUD_VALUE, if enabled { 1 } else { 0 })?;
    unsafe {
        let _ = RegCloseKey(key);
    }
    Ok(())
}

/// Switches the history off again when Windows restored it.
///
/// The clipboard service of Windows writes the setting back from time to
/// time. As long as the user asked ClipWarden to keep the history off, the
/// choice is made again.
pub fn keep_applied() {
    use std::sync::atomic::Ordering;
    if !KEEP_OFF.load(Ordering::Acquire) {
        return;
    }
    if settings().history_enabled || settings().cloud_upload {
        let _ = set_enabled(false);
    }
}

/// Opens the clipboard key of the current user.
fn open_key(access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> Result<HKEY, HistoryError> {
    let mut key = HKEY::default();
    let sub_key = wide(CLIPBOARD_KEY);
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(sub_key.as_ptr()),
            None,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            access,
            None,
            &mut key,
            None,
        )
    };
    if status != WIN32_ERROR(0) {
        return Err(HistoryError::Registry(status.0));
    }
    Ok(key)
}

/// Reads a number from the clipboard key.
fn read_dword(name: &str) -> Option<u32> {
    let mut key = HKEY::default();
    let sub_key = wide(CLIPBOARD_KEY);
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(sub_key.as_ptr()),
            None,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ,
            None,
            &mut key,
            None,
        )
    };
    if status != WIN32_ERROR(0) {
        return None;
    }

    let value_name = wide(name);
    let mut data: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            windows::core::PCWSTR(value_name.as_ptr()),
            None,
            None,
            Some((&mut data as *mut u32).cast()),
            Some(&mut size),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if status == WIN32_ERROR(0) {
        Some(data)
    } else {
        None
    }
}

/// Writes a number into the clipboard key.
fn write_dword(key: HKEY, name: &str, value: u32) -> Result<(), HistoryError> {
    let value_name = wide(name);
    let bytes = value.to_le_bytes();
    let status = unsafe {
        RegSetValueExW(
            key,
            windows::core::PCWSTR(value_name.as_ptr()),
            None,
            REG_DWORD,
            Some(&bytes),
        )
    };
    if status != WIN32_ERROR(0) {
        return Err(HistoryError::Registry(status.0));
    }
    Ok(())
}

/// Converts a string into a null terminated UTF-16 buffer.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
