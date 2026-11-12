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

//! Paste interception.
//!
//! ClipWarden installs a low level keyboard hook to observe paste shortcuts
//! (`Ctrl+V`, `Ctrl+Shift+V`, `Ctrl+Insert`). The hook is invoked *before* the
//! key is delivered to the foreground application, which is the only moment
//! at which the clipboard can still be modified in time.
//!
//! The hook is deliberately minimal: it filters on the virtual key code and
//! only does work when a paste shortcut is actually pressed.

use std::cell::RefCell;

use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VK_CONTROL, VK_INSERT, VK_SHIFT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT, SetWindowsHookExW, UnhookWindowsHookEx,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
};

/// What should happen to the paste shortcut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteDecision {
    /// Let the paste happen.
    Continue,
    /// Swallow the key press so that the paste never happens.
    Suppress,
}

/// Handler that is called when a paste shortcut is detected.
pub trait PasteHandler {
    /// Called from inside the keyboard hook; must return quickly.
    fn on_paste(&mut self) -> PasteDecision;
}

impl<F> PasteHandler for F
where
    F: FnMut() -> PasteDecision,
{
    fn on_paste(&mut self) -> PasteDecision {
        self()
    }
}

thread_local! {
    /// The paste handler of the watcher that owns the current thread.
    static HANDLER: RefCell<Option<Box<dyn PasteHandler>>> = const { RefCell::new(None) };
}

/// Errors that can occur while installing the keyboard hook.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// The hook could not be installed.
    #[error("could not install the keyboard hook: {0}")]
    Install(#[from] windows::core::Error),
}

/// Returns `true` when the control key is currently pressed.
fn control_is_down() -> bool {
    let state = unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) };
    (state as u16) & 0x8000 != 0
}

/// Returns `true` when the shift key is currently pressed.
fn shift_is_down() -> bool {
    let state = unsafe { GetAsyncKeyState(VK_SHIFT.0 as i32) };
    (state as u16) & 0x8000 != 0
}

/// The low level keyboard hook procedure.
unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        let message = wparam.0 as u32;
        if message == WM_KEYDOWN || message == WM_SYSKEYDOWN {
            let keyboard = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
            let is_paste =
                keyboard.vkCode == u32::from(b'V') || keyboard.vkCode == VK_INSERT.0 as u32;
            if is_paste && control_is_down() {
                let decision = HANDLER.with(|handler| {
                    let mut handler = handler.borrow_mut();
                    match handler.as_mut() {
                        Some(handler) => handler.on_paste(),
                        None => PasteDecision::Continue,
                    }
                });
                if decision == PasteDecision::Suppress {
                    // A non-zero return value tells Windows to stop the key
                    // from reaching the foreground application.
                    return LRESULT(1);
                }
            }
            let _ = shift_is_down();
        }
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// Watches for paste shortcuts.
pub struct PasteWatcher {
    hook: HHOOK,
    #[allow(dead_code)]
    thread_id: u32,
}

impl PasteWatcher {
    /// Installs the keyboard hook for the current thread.
    pub fn install<H: PasteHandler + 'static>(handler: H) -> Result<Self, HookError> {
        HANDLER.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(handler));
        });

        let module = unsafe { GetModuleHandleW(None)? };
        let hook = unsafe {
            SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(hook_proc),
                Some(windows::Win32::Foundation::HINSTANCE(module.0)),
                0,
            )?
        };

        Ok(Self {
            hook,
            thread_id: unsafe { GetCurrentThreadId() },
        })
    }
}

impl Drop for PasteWatcher {
    fn drop(&mut self) {
        unsafe {
            let _ = UnhookWindowsHookEx(self.hook);
        }
        HANDLER.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}
