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

//! Clipboard monitoring.
//!
//! The monitor owns a hidden message-only window and registers it as a
//! clipboard format listener. Windows then posts a `WM_CLIPBOARDUPDATE`
//! message whenever the clipboard content changes.
//!
//! The monitor never writes the clipboard content to disk or to a log. The
//! text is handed to the handler and dropped as soon as the handler returns.

use std::cell::RefCell;

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HCURSOR, HICON,
    HWND_MESSAGE, MSG, PostMessageW, PostQuitMessage, PostThreadMessageW, RegisterClassW,
    TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLIPBOARDUPDATE, WM_DESTROY,
    WM_QUIT, WNDCLASSW,
};

use crate::access;

/// Name of the window class used by the listener.
const CLASS_NAME: &str = "ClipWardenClipboardListener";

/// Custom message used to stop the message loop from another thread.
const WM_CLIP_GUARD_STOP: u32 = WM_APP + 1;

/// What the handler wants the monitor to do with the clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardAction {
    /// Leave the clipboard untouched.
    Ignore,
    /// Replace the clipboard content.
    SetText(String),
    /// Empty the clipboard.
    Clear,
}

/// Handler that is called for every clipboard update.
pub trait ClipboardHandler {
    /// Called with the new clipboard content (`None` when the clipboard does
    /// not contain text) and returns the action the monitor should perform.
    ///
    /// `existed_before` is `true` when the content was already on the
    /// clipboard when the monitor started. Windows counts every change of the
    /// clipboard, so the sequence number tells old and new apart even when
    /// the text is the same.
    fn on_clipboard_changed(&mut self, text: Option<&str>, existed_before: bool)
    -> ClipboardAction;
}

impl<F> ClipboardHandler for F
where
    F: FnMut(Option<&str>, bool) -> ClipboardAction,
{
    fn on_clipboard_changed(
        &mut self,
        text: Option<&str>,
        existed_before: bool,
    ) -> ClipboardAction {
        self(text, existed_before)
    }
}

thread_local! {
    /// The handler of the monitor that owns the current thread.
    static HANDLER: RefCell<Option<Box<dyn ClipboardHandler>>> = const { RefCell::new(None) };
    /// The clipboard sequence number that ClipWarden produced itself.
    ///
    /// Windows notifies every listener about its own change as well, so the
    /// monitor has to recognise the update it caused itself.
    static OWN_SEQUENCE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// How often the reading of the clipboard was retried.
    static RETRIES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// The clipboard sequence number at the moment the monitor started.
    ///
    /// Every change of the clipboard increases the sequence number, so a
    /// content that was already there can be told apart from a new copy —
    /// even when the text is the same.
    static STARTUP_SEQUENCE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Number of times the clipboard is read again when another application
/// holds it at the very moment of the change.
const MAX_READ_RETRIES: u32 = 3;

/// Records the sequence number of a clipboard change that ClipWarden caused.
fn remember_own_write() {
    OWN_SEQUENCE.set(access::sequence_number());
}

/// Returns `true` when the update was caused by ClipWarden itself.
fn is_own_write(sequence: u32) -> bool {
    let own = OWN_SEQUENCE.get();
    if own != 0 && own == sequence {
        OWN_SEQUENCE.set(0);
        return true;
    }
    false
}

/// Errors that can occur while setting up the clipboard monitor.
#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    /// A Win32 call failed.
    #[error("clipboard monitor failed: {0}")]
    Win32(#[from] windows::core::Error),
    /// The window class could not be registered.
    #[error("could not register the clipboard listener window class")]
    RegisterClass,
}

type Result<T> = std::result::Result<T, MonitorError>;

/// Window procedure of the message-only listener window.
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_CLIPBOARDUPDATE => {
            let sequence = access::sequence_number();
            if is_own_write(sequence) {
                // This update was produced by ClipWarden itself.
                return LRESULT(0);
            }
            let text = match access::read_text() {
                Ok(text) => {
                    RETRIES.with(|slot| slot.set(0));
                    text
                }
                Err(error) => {
                    // Another application holds the clipboard at this moment.
                    // The update is requested again, so that a secret is
                    // never left unprotected just because of a busy clipboard.
                    tracing::debug!(?error, "could not read the clipboard content");
                    let retry = RETRIES.with(|slot| {
                        let count = slot.get() + 1;
                        slot.set(count);
                        count
                    });
                    if retry <= MAX_READ_RETRIES {
                        unsafe {
                            let _ =
                                PostMessageW(Some(hwnd), WM_CLIPBOARDUPDATE, WPARAM(0), LPARAM(0));
                        }
                    }
                    None
                }
            };
            // The content was already on the clipboard when the monitor
            // started when its sequence number did not change yet.
            let existed_before = sequence <= STARTUP_SEQUENCE.with(|slot| slot.get());
            let action = HANDLER.with(|handler| {
                let mut handler = handler.borrow_mut();
                match handler.as_mut() {
                    Some(handler) => handler.on_clipboard_changed(text.as_deref(), existed_before),
                    None => ClipboardAction::Ignore,
                }
            });
            match action {
                ClipboardAction::Ignore => {}
                ClipboardAction::SetText(text) => {
                    if let Err(error) = access::write_text(&text) {
                        tracing::warn!(?error, "could not write the protected clipboard content");
                    } else {
                        remember_own_write();
                    }
                    tracing::debug!(sequence, "clipboard content was rewritten");
                }
                ClipboardAction::Clear => {
                    if let Err(error) = access::clear() {
                        tracing::warn!(?error, "could not clear the clipboard");
                    } else {
                        remember_own_write();
                    }
                    tracing::debug!(sequence, "clipboard content was cleared");
                }
            }
            LRESULT(0)
        }
        WM_CLIP_GUARD_STOP => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

/// Monitors the Windows clipboard for changes.
pub struct ClipboardMonitor {
    hwnd: HWND,
    thread_id: u32,
}

impl ClipboardMonitor {
    /// Creates the listener window and registers it as a clipboard listener.
    pub fn new() -> Result<Self> {
        let module = unsafe { GetModuleHandleW(None)? };
        let instance = HINSTANCE(module.0);

        let class_name: Vec<u16> = CLASS_NAME.encode_utf16().chain(Some(0)).collect();
        let class = WNDCLASSW {
            style: windows::Win32::UI::WindowsAndMessaging::WNDCLASS_STYLES(0),
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: HICON::default(),
            hCursor: HCURSOR::default(),
            hbrBackground: HBRUSH::default(),
            lpszMenuName: windows::core::PCWSTR::null(),
            lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
        };

        // A class can only be registered once per process; a duplicate
        // registration is not an error for us.
        if unsafe { RegisterClassW(&class) } == 0 {
            tracing::debug!("the clipboard listener window class was already registered");
        }

        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                windows::core::PCWSTR(class_name.as_ptr()),
                windows::core::PCWSTR::null(),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(instance),
                None,
            )?
        };

        unsafe { AddClipboardFormatListener(hwnd)? };

        Ok(Self {
            hwnd,
            thread_id: unsafe { GetCurrentThreadId() },
        })
    }

    /// Runs the message loop until [`ClipboardMonitor::stop`] is called.
    pub fn run<H: ClipboardHandler + 'static>(&self, handler: H) {
        // The sequence number of the moment the monitor starts. Everything
        // that happens later is a new copy of the clipboard.
        STARTUP_SEQUENCE.with(|slot| slot.set(access::sequence_number()));
        HANDLER.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(handler));
        });

        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
            if result.0 <= 0 {
                break;
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        HANDLER.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }

    /// Stops the message loop.
    pub fn stop(&self) {
        unsafe {
            let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
        }
    }
}

impl Drop for ClipboardMonitor {
    fn drop(&mut self) {
        unsafe {
            let _ = RemoveClipboardFormatListener(self.hwnd);
            let _ = DestroyWindow(self.hwnd);
        }
    }
}
