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

//! Clipboard access helpers.
//!
//! Windows clipboard access is a global, mutually exclusive resource: only
//! one process may have the clipboard open at a time. Every operation in this
//! module therefore uses a bounded retry loop so that a busy clipboard does
//! not turn into a lost protection event.

use std::time::Duration;

use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};

/// The `CF_UNICODETEXT` clipboard format identifier.
const CF_UNICODETEXT: u32 = 13;

/// Number of attempts made when opening the clipboard.
const OPEN_ATTEMPTS: u32 = 24;

/// Delay between two attempts to open the clipboard.
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(8);

/// Maximum number of characters that are read from the clipboard.
const MAX_READ_CHARS: usize = 4 * 1024 * 1024;

/// Errors that can occur while talking to the Windows clipboard.
#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    /// The clipboard could not be opened within the retry budget.
    #[error("the clipboard is busy and could not be opened")]
    Busy,
    /// A Win32 call failed.
    #[error("clipboard operation failed: {0}")]
    Win32(#[from] windows::core::Error),
    /// The clipboard contained data that is not valid UTF-16 text.
    #[error("the clipboard contains malformed text")]
    Malformed,
}

/// Convenience alias for clipboard results.
pub type Result<T> = std::result::Result<T, ClipboardError>;

/// RAII guard that keeps the clipboard open and closes it on drop.
///
/// The guard is returned by [`open`] and [`open_fast`]; dropping it releases
/// the clipboard so that other applications can use it again.
pub struct ClipboardGuard;

impl ClipboardGuard {
    /// Opens the clipboard, retrying while another process holds it.
    fn open(attempts: u32) -> Result<Self> {
        let mut last_error = None;
        for attempt in 0..attempts.max(1) {
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Self),
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < attempts.max(1) {
                        std::thread::sleep(OPEN_RETRY_DELAY);
                    }
                }
            }
        }
        tracing::debug!(
            error = ?last_error,
            "could not open the clipboard, another application is holding it"
        );
        Err(ClipboardError::Busy)
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseClipboard() };
    }
}

/// Opens the clipboard with the default retry budget.
pub fn open() -> Result<ClipboardGuard> {
    ClipboardGuard::open(OPEN_ATTEMPTS)
}

/// Opens the clipboard with a short retry budget.
///
/// Used from inside the low level keyboard hook where blocking for a long
/// time would make Windows consider the hook unresponsive.
pub fn open_fast() -> Result<ClipboardGuard> {
    ClipboardGuard::open(4)
}

/// Returns the current clipboard sequence number.
///
/// The value changes whenever the clipboard content changes and is used to
/// recognise updates that ClipWarden itself produced.
pub fn sequence_number() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}

/// Reads the text content of the clipboard.
///
/// Returns `Ok(None)` when the clipboard does not contain text.
pub fn read_text() -> Result<Option<String>> {
    let _guard = open()?;

    let handle = match unsafe { GetClipboardData(CF_UNICODETEXT) } {
        Ok(handle) => handle,
        Err(_) => return Ok(None),
    };

    let global = HGLOBAL(handle.0);
    let pointer = unsafe { GlobalLock(global) };
    if pointer.is_null() {
        return Ok(None);
    }

    let mut length = 0usize;
    let slice = unsafe { std::slice::from_raw_parts(pointer as *const u16, MAX_READ_CHARS) };
    while length < slice.len() && slice[length] != 0 {
        length += 1;
    }

    let text = String::from_utf16_lossy(&slice[..length]);
    let _ = unsafe { GlobalUnlock(global) };
    Ok(Some(text))
}

/// Writes text to the clipboard, replacing the current content.
pub fn write_text(text: &str) -> Result<()> {
    let _guard = open()?;

    unsafe { EmptyClipboard()? };

    let mut wide: Vec<u16> = text.encode_utf16().collect();
    wide.push(0);
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_len)? };
    let pointer = unsafe { GlobalLock(handle) };
    if pointer.is_null() {
        unsafe {
            let _ = GlobalFree(Some(handle));
        }
        return Err(ClipboardError::Malformed);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, pointer as *mut u8, byte_len);
        let _ = GlobalUnlock(handle);
    }

    // On success the operating system takes ownership of the memory block.
    match unsafe { SetClipboardData(CF_UNICODETEXT, Some(HANDLE(handle.0))) } {
        Ok(_) => Ok(()),
        Err(error) => {
            unsafe {
                let _ = GlobalFree(Some(handle));
            }
            Err(ClipboardError::Win32(error))
        }
    }
}

/// Removes everything from the clipboard.
pub fn clear() -> Result<()> {
    let _guard = open()?;
    unsafe { EmptyClipboard()? };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_number_is_readable() {
        // The sequence number is always available, even without a clipboard
        // owner.
        let _ = sequence_number();
    }

    #[test]
    fn read_and_write_round_trip() {
        // These tests touch the real clipboard, therefore they only run when
        // explicitly requested.
        if std::env::var_os("clipwarden_clipboard_TESTS").is_none() {
            return;
        }
        let original = read_text().unwrap();
        write_text("ClipWarden-test-value").unwrap();
        assert_eq!(
            read_text().unwrap().as_deref(),
            Some("ClipWarden-test-value")
        );
        clear().unwrap();
        if let Some(original) = original {
            let _ = write_text(&original);
        }
    }
}
