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

//! The system tray icon.
//!
//! The tray runs on its own thread with its own message loop. User
//! interaction is translated into [`TrayCommand`] values that the daemon
//! processes on its main thread.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu,
    DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, HCURSOR, HICON, HWND_MESSAGE,
    IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO, MF_CHECKED, MF_SEPARATOR, MF_STRING, MSG,
    MessageBoxW, PostQuitMessage, PostThreadMessageW, RegisterClassW, SetForegroundWindow,
    TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, TRACK_POPUP_MENU_FLAGS, TrackPopupMenu,
    TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_DESTROY, WM_LBUTTONDBLCLK,
    WM_LBUTTONUP, WM_QUIT, WM_RBUTTONUP, WNDCLASSW,
};

use crate::icon;

/// Name of the tray window class.
const CLASS_NAME: &str = "ClipWardenTrayWindow";

/// Identifier of the tray icon.
const ICON_ID: u32 = 1;

/// Message that the shell uses to notify the tray window.
const WM_TRAY_CALLBACK: u32 = WM_APP + 2;

/// Message that asks the tray thread to refresh its state.
const WM_TRAY_REFRESH: u32 = WM_APP + 3;

/// Command identifiers of the tray menu.
const MENU_OPEN: usize = 100;
const MENU_TOGGLE_PAUSE: usize = 101;
const MENU_TOGGLE_MODE: usize = 102;
const MENU_TOGGLE_AUTOSTART: usize = 103;
const MENU_TOGGLE_EXISTING: usize = 105;
const MENU_EXIT: usize = 104;

/// A command that the user triggered through the tray icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayCommand {
    /// The user asked for the dashboard to be opened.
    OpenDashboard,
    /// The user toggled the paused state.
    TogglePause,
    /// The user toggled between ghost and satellite mode.
    ToggleMode,
    /// The user toggled the automatic start entry.
    ToggleAutostart,
    /// The user toggled the masking of the content that was already on the
    /// clipboard when ClipWarden started.
    ToggleExisting,
    /// The user asked ClipWarden to exit.
    Exit,
}

/// State that the tray renders.
#[derive(Debug, Clone, Default)]
pub struct TrayState {
    /// Whether protection is currently paused.
    pub paused: bool,
    /// Whether ClipWarden starts with Windows.
    pub autostart: bool,
    /// Whether the current mode is ghost mode.
    pub ghost_mode: bool,
    /// Whether the content that was on the clipboard when ClipWarden started
    /// is masked as well.
    pub protect_existing: bool,
    /// Number of secrets that were protected since the last refresh.
    pub protected_count: u64,
}

/// The tray icon.
pub struct Tray {
    state: Arc<Mutex<TrayState>>,
    commands: Sender<TrayCommand>,
    thread_id: Arc<Mutex<u32>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Tray {
    /// Creates the tray icon on a dedicated thread.
    pub fn spawn(commands: Sender<TrayCommand>) -> Result<Self, TrayError> {
        let state = Arc::new(Mutex::new(TrayState::default()));
        let thread_id = Arc::new(Mutex::new(0u32));

        let thread_state = Arc::clone(&state);
        let thread_id_handle = Arc::clone(&thread_id);
        let command_sender = commands.clone();

        let thread = std::thread::Builder::new()
            .name("ClipWarden-tray".into())
            .spawn(move || {
                if let Err(error) = run_tray(command_sender, thread_state, thread_id_handle) {
                    tracing::error!(?error, "the tray icon could not be created");
                }
            })
            .map_err(TrayError::Spawn)?;

        Ok(Self {
            state,
            commands,
            thread_id,
            thread: Some(thread),
        })
    }

    /// Updates the tooltip and the menu of the tray icon.
    pub fn update(&self, state: TrayState) {
        {
            let mut guard = self.state.lock().expect("tray state lock");
            *guard = state;
        }
        let thread_id = *self.thread_id.lock().expect("tray thread lock");
        if thread_id != 0 {
            unsafe {
                let _ = PostThreadMessageW(thread_id, WM_TRAY_REFRESH, WPARAM(0), LPARAM(0));
            }
        }
    }

    /// Returns a sender for tray commands.
    pub fn command_sender(&self) -> Sender<TrayCommand> {
        self.commands.clone()
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        // The tray thread waits in a message loop. Without this message the
        // join below would block forever and the service could never quit.
        let thread_id = *self.thread_id.lock().expect("tray thread lock");
        if thread_id != 0 {
            unsafe {
                let _ = PostThreadMessageW(thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Errors that can occur while creating the tray icon.
#[derive(Debug, thiserror::Error)]
pub enum TrayError {
    /// The tray thread could not be started.
    #[error("could not start the tray thread: {0}")]
    Spawn(std::io::Error),
}

/// The window procedure of the tray window.
unsafe extern "system" fn tray_window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_TRAY_CALLBACK => {
            let event = lparam.0 as u32;
            match event {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                    send_command(TrayCommand::OpenDashboard);
                }
                WM_RBUTTONUP => {
                    show_context_menu(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_TRAY_REFRESH => {
            refresh_tray(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

thread_local! {
    /// The command sender of the tray thread.
    static COMMAND_SENDER: std::cell::RefCell<Option<Sender<TrayCommand>>> =
        const { std::cell::RefCell::new(None) };
    /// The shared state of the tray thread.
    static TRAY_STATE: std::cell::RefCell<Option<Arc<Mutex<TrayState>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Sends a command to the daemon.
fn send_command(command: TrayCommand) {
    COMMAND_SENDER.with(|slot| {
        if let Some(sender) = slot.borrow().as_ref() {
            let _ = sender.send(command);
        }
    });
}

/// Shows the context menu of the tray icon.
fn show_context_menu(hwnd: HWND) {
    let state = current_state();
    let menu = match unsafe { CreatePopupMenu() } {
        Ok(menu) => menu,
        Err(error) => {
            tracing::warn!(?error, "could not create the tray menu");
            return;
        }
    };

    let pause_label = if state.paused {
        "Resume protection"
    } else {
        "Pause protection"
    };
    let mode_label = if state.ghost_mode {
        "Switch to satellite mode"
    } else {
        "Switch to ghost mode"
    };
    let autostart_label = if state.autostart {
        "Do not start with Windows"
    } else {
        "Start with Windows"
    };
    let existing_label = "Mask the clipboard content from before the start";
    let existing_flags = if state.protect_existing {
        MF_STRING | MF_CHECKED
    } else {
        MF_STRING
    };

    unsafe {
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_OPEN,
            windows::core::PCWSTR(wide("Open ClipWarden").as_ptr()),
        );
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_TOGGLE_PAUSE,
            windows::core::PCWSTR(wide(pause_label).as_ptr()),
        );
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_TOGGLE_MODE,
            windows::core::PCWSTR(wide(mode_label).as_ptr()),
        );
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_TOGGLE_AUTOSTART,
            windows::core::PCWSTR(wide(autostart_label).as_ptr()),
        );
        let _ = AppendMenuW(
            menu,
            existing_flags,
            MENU_TOGGLE_EXISTING,
            windows::core::PCWSTR(wide(existing_label).as_ptr()),
        );
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, windows::core::PCWSTR::null());
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_EXIT,
            windows::core::PCWSTR(wide("Exit ClipWarden...").as_ptr()),
        );
    }

    let mut point = POINT::default();
    let _ = unsafe { GetCursorPos(&mut point) };
    let _ = unsafe { SetForegroundWindow(hwnd) };

    let command = unsafe {
        TrackPopupMenu(
            menu,
            TRACK_POPUP_MENU_FLAGS(TPM_RIGHTBUTTON.0 | TPM_RETURNCMD.0 | TPM_NONOTIFY.0),
            point.x,
            point.y,
            None,
            hwnd,
            None,
        )
    };

    let _ = unsafe { DestroyMenu(menu) };
    let _ = unsafe { SetForegroundWindow(hwnd) };

    let command = match command.0 as usize {
        MENU_OPEN => TrayCommand::OpenDashboard,
        MENU_TOGGLE_PAUSE => TrayCommand::TogglePause,
        MENU_TOGGLE_MODE => TrayCommand::ToggleMode,
        MENU_TOGGLE_AUTOSTART => TrayCommand::ToggleAutostart,
        MENU_TOGGLE_EXISTING => TrayCommand::ToggleExisting,
        MENU_EXIT => {
            // Quitting stops the protection and the protected content is
            // removed from the clipboard — the user has to confirm that.
            if !confirm_exit(hwnd) {
                return;
            }
            TrayCommand::Exit
        }
        _ => return,
    };

    send_command(command);
}

/// Asks the user to confirm the shutdown.
///
/// Returns `true` when ClipWarden may quit.
fn confirm_exit(hwnd: HWND) -> bool {
    let message = wide(
        "Exiting ClipWarden stops the clipboard protection.\n\n\
         The protected content may be removed from your clipboard.\n\n\
         Do you want to exit ClipWarden?",
    );
    let title = wide("Exit ClipWarden");
    let answer = unsafe {
        MessageBoxW(
            Some(hwnd),
            windows::core::PCWSTR(message.as_ptr()),
            windows::core::PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        )
    };
    answer == IDYES
}

/// Returns the current tray state.
fn current_state() -> TrayState {
    TRAY_STATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .and_then(|state| state.lock().ok().map(|guard| guard.clone()))
            .unwrap_or_default()
    })
}

/// Refreshes the tooltip of the tray icon.
fn refresh_tray(hwnd: HWND) {
    let state = current_state();
    let tip = if state.paused {
        "ClipWarden — protection paused"
    } else {
        "ClipWarden — clipboard protection active"
    };
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: ICON_ID,
        uFlags: NIF_TIP,
        ..Default::default()
    };
    copy_wide(&mut data.szTip, tip);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
    }
}

/// Runs the tray message loop.
fn run_tray(
    commands: Sender<TrayCommand>,
    state: Arc<Mutex<TrayState>>,
    thread_id: Arc<Mutex<u32>>,
) -> Result<(), TrayError> {
    COMMAND_SENDER.with(|slot| {
        *slot.borrow_mut() = Some(commands);
    });
    TRAY_STATE.with(|slot| {
        *slot.borrow_mut() = Some(Arc::clone(&state));
    });
    *thread_id.lock().expect("tray thread lock") = unsafe { GetCurrentThreadId() };

    let module = unsafe { GetModuleHandleW(None) }
        .map_err(|error| TrayError::Spawn(std::io::Error::other(error.to_string())))?;
    let instance = HINSTANCE(module.0);

    let class_name = wide(CLASS_NAME);
    let class = WNDCLASSW {
        style: windows::Win32::UI::WindowsAndMessaging::WNDCLASS_STYLES(0),
        lpfnWndProc: Some(tray_window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: HICON::default(),
        hCursor: HCURSOR::default(),
        hbrBackground: HBRUSH::default(),
        lpszMenuName: windows::core::PCWSTR::null(),
        lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        tracing::debug!("the tray window class was already registered");
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
        )
    }
    .map_err(|error| TrayError::Spawn(std::io::Error::other(error.to_string())))?;

    let icon = icon::create_hicon(icon::ICON_SIZE);
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: ICON_ID,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY_CALLBACK,
        hIcon: icon.unwrap_or_default(),
        szTip: [0; 128],
        ..Default::default()
    };
    copy_wide(&mut data.szTip, "ClipWarden — clipboard protection active");

    if !unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool() {
        tracing::error!("could not add the tray icon");
        return Err(TrayError::Spawn(std::io::Error::other(
            "could not add the tray icon",
        )));
    }
    tracing::info!("the tray icon was created");

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

    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &data);
        let _ = DestroyWindow(hwnd);
    }
    if let Some(icon) = icon {
        unsafe {
            let _ = DestroyIcon(icon);
        }
    }
    Ok(())
}

/// Copies a string into a fixed size UTF-16 buffer.
fn copy_wide(buffer: &mut [u16], text: &str) {
    let encoded = text.encode_utf16();
    for (target, value) in buffer.iter_mut().zip(encoded) {
        *target = value;
    }
}

/// Converts a string into a null terminated UTF-16 buffer.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
