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

//! The ClipGuard runtime.
//!
//! The runtime starts the parts that make up a running ClipGuard instance:
//!
//! * the protection engine,
//! * the clipboard monitor and the paste hook,
//! * the local control channel.
//!
//! It is shared by the background service and by the desktop application so
//! that both behave identically.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;

use serde_json::Value;

use crate::ipc::{self, CommandHandler, IpcRequest, IpcResponse};
use crate::protection::ProtectionEngine;

/// Computes a SHA-256 hash of a password.
fn hash_password(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Verifies a plaintext password against a stored hash.
fn verify_password_hash(password: &str, hash: &str) -> bool {
    if hash.is_empty() {
        return true;
    }
    hash_password(password) == hash
}

/// Launches the dashboard (clipguard-desktop.exe) if it is not running.
///
/// The dashboard is started without a console window so nothing flashes up.
pub fn launch_dashboard() -> bool {
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };
    let dir = match exe.parent() {
        Some(dir) => dir,
        None => return false,
    };

    // The binary may be named either way depending on how the release was
    // built.
    let dashboard = ["clipguard-desktop.exe", "ClipGuard-desktop.exe"]
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists());

    let Some(dashboard) = dashboard else {
        return false;
    };

    let mut command = std::process::Command::new(dashboard);
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    match command.spawn() {
        Ok(child) => {
            let _pid = child.id();
            std::mem::forget(child);
            true
        }
        Err(error) => {
            tracing::warn!(?error, "could not launch the dashboard");
            false
        }
    }
}

/// Errors that can occur while starting the runtime.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The clipboard monitor could not be created.
    #[error("could not create the clipboard monitor: {0}")]
    Monitor(#[from] clipguard_clipboard::monitor::MonitorError),
    /// A thread could not be started.
    #[error("could not start a worker thread: {0}")]
    Thread(std::io::Error),
}

/// A running ClipGuard instance.
pub struct Runtime {
    engine: Arc<ProtectionEngine>,
    monitor: Option<std::thread::JoinHandle<()>>,
    /// The thread id of the clipboard monitor, used to stop its message loop.
    monitor_thread: Option<std::sync::mpsc::Receiver<u32>>,
}

impl Runtime {
    /// Starts the runtime with the configuration at `config_path`.
    pub fn start(config_path: PathBuf) -> Result<Self, RuntimeError> {
        let engine = Arc::new(ProtectionEngine::new(config_path));

        // The control channel. Detection events are forwarded to every
        // connected client.
        let ipc_engine = Arc::clone(&engine);
        let (event_sender, event_receiver) = channel::<Value>();
        engine.subscribe(event_sender);
        std::thread::Builder::new()
            .name("ClipGuard-ipc".into())
            .spawn(move || {
                let handler: CommandHandler =
                    Arc::new(move |request: IpcRequest| handle_command(&ipc_engine, request));
                ipc::serve(ipc::PIPE_NAME, handler, Some(event_receiver));
            })
            .map_err(RuntimeError::Thread)?;

        // The configuration file is watched. Without it a change that the
        // user made with a text editor would only take effect when the next
        // secret is copied.
        let watcher_engine = Arc::clone(&engine);
        std::thread::Builder::new()
            .name("ClipGuard-config".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(2));
                    watcher_engine.reload_if_changed();
                    // Windows restores the clipboard history from time to
                    // time; the choice of the user is made again.
                    if watcher_engine.config().general.disable_windows_history
                        && crate::history::settings().history_enabled
                    {
                        let _ = crate::history::set_enabled(false);
                    }
                }
            })
            .map_err(RuntimeError::Thread)?;

        // The clipboard monitor and the paste hook share one thread: the low
        // level keyboard hook is dispatched by the thread that installs it.
        let monitor_engine = Arc::clone(&engine);
        // The monitor reports its thread id, so that the message loop can be
        // stopped when the service shuts down.
        let (monitor_sender, monitor_receiver) = std::sync::mpsc::channel::<u32>();
        let monitor = std::thread::Builder::new()
            .name("ClipGuard-monitor".into())
            .spawn(move || {
                let monitor = match clipguard_clipboard::monitor::ClipboardMonitor::new() {
                    Ok(monitor) => monitor,
                    Err(error) => {
                        tracing::error!(?error, "could not create the clipboard monitor");
                        return;
                    }
                };

                // The window was created on this thread, so this is the thread
                // that has to receive the quit message.
                let _ = monitor_sender
                    .send(unsafe { windows::Win32::System::Threading::GetCurrentThreadId() });

                let hook_engine = Arc::clone(&monitor_engine);
                let watcher = match clipguard_clipboard::hook::PasteWatcher::install(move || {
                    hook_engine.on_paste()
                }) {
                    Ok(watcher) => Some(watcher),
                    Err(error) => {
                        tracing::error!(?error, "could not install the keyboard hook");
                        None
                    }
                };

                monitor.run(move |text: Option<&str>, existed_before: bool| {
                    monitor_engine.on_clipboard_changed(text, existed_before)
                });

                drop(watcher);
            })
            .map_err(RuntimeError::Thread)?;

        // The content that was already on the clipboard produces no event, so
        // it is checked once here. Nothing happens unless the user asked for
        // it in the settings.
        let startup_engine = Arc::clone(&engine);
        std::thread::Builder::new()
            .name("ClipGuard-startup".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(500));
                startup_engine.protect_existing_content();
            })
            .map_err(RuntimeError::Thread)?;

        Ok(Self {
            engine,
            monitor: Some(monitor),
            monitor_thread: Some(monitor_receiver),
        })
    }

    /// Returns the protection engine.
    pub fn engine(&self) -> &Arc<ProtectionEngine> {
        &self.engine
    }

    /// Stops the runtime.
    pub fn shutdown(mut self) {
        // The clipboard monitor runs a message loop; it has to be stopped
        // before the thread can be joined.
        if let Some(receiver) = self.monitor_thread.take()
            && let Ok(thread_id) = receiver.recv_timeout(Duration::from_secs(2))
        {
            unsafe {
                let _ = windows::Win32::UI::WindowsAndMessaging::PostThreadMessageW(
                    thread_id,
                    windows::Win32::UI::WindowsAndMessaging::WM_QUIT,
                    windows::Win32::Foundation::WPARAM(0),
                    windows::Win32::Foundation::LPARAM(0),
                );
            }
        }
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
    }
}

/// Executes a command of the control channel.
pub fn handle_command(engine: &ProtectionEngine, request: IpcRequest) -> IpcResponse {
    let args = request.args.clone();
    match request.cmd.as_str() {
        "get_status" => {
            let status = engine.status();
            IpcResponse::ok(
                request.id,
                serde_json::to_value(&status).unwrap_or(Value::Null),
            )
        }
        "get_stats" => IpcResponse::ok(
            request.id,
            serde_json::to_value(engine.stats()).unwrap_or(Value::Null),
        ),
        "get_config" => IpcResponse::ok(
            request.id,
            serde_json::to_value(engine.config()).unwrap_or(Value::Null),
        ),
        "verify_password" => {
            let password = args
                .get("password")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let config = engine.config();
            let valid = verify_password_hash(password, &config.general.password_hash);
            IpcResponse::ok(request.id, Value::Bool(valid))
        }
        "set_config" => {
            // The payload is `{"config": ..., "password": ...}`; a bare
            // config object is accepted for backwards compatibility.
            let config_value = match args.get("config") {
                Some(config) => config.clone(),
                None => args.clone(),
            };
            // If a password is set, require it in the args before applying.
            if !engine.config().general.password_hash.is_empty() {
                let provided = args
                    .get("password")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                if !verify_password_hash(provided, &engine.config().general.password_hash) {
                    return IpcResponse::error(request.id, "incorrect password".to_string());
                }
            }
            let config: clipguard_core::config::Config = match serde_json::from_value(config_value)
            {
                Ok(config) => config,
                Err(error) => return IpcResponse::error(request.id, error.to_string()),
            };
            match engine.set_config(config) {
                Ok(()) => IpcResponse::ok(request.id, Value::Null),
                Err(error) => IpcResponse::error(request.id, error),
            }
        }
        "shutdown" => {
            // The service quits on the next tick of the main loop.
            engine.request_shutdown();
            IpcResponse::ok(request.id, Value::Bool(true))
        }
        "scan" => {
            let text = args
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let report = engine.scan(text);
            IpcResponse::ok(
                request.id,
                serde_json::to_value(&report).unwrap_or(Value::Null),
            )
        }
        "set_paused" => {
            // If a password is set, require it in the args.
            if !engine.config().general.password_hash.is_empty() {
                let provided = args
                    .get("password")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                if !verify_password_hash(provided, &engine.config().general.password_hash) {
                    return IpcResponse::error(request.id, "incorrect password".to_string());
                }
            }
            let paused = args
                .get("paused")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            engine.set_paused(paused);
            IpcResponse::ok(request.id, Value::Null)
        }
        "autostart_status" => {
            IpcResponse::ok(request.id, Value::Bool(crate::autostart::is_enabled()))
        }
        "set_autostart" => {
            let enabled = args
                .get("enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            match crate::autostart::set_enabled(enabled) {
                Ok(()) => IpcResponse::ok(request.id, Value::Null),
                Err(error) => IpcResponse::error(request.id, error.to_string()),
            }
        }
        "list_templates" => {
            let templates = clipguard_core::templates::all_templates();
            IpcResponse::ok(
                request.id,
                serde_json::to_value(&templates).unwrap_or(Value::Null),
            )
        }
        "personal_phone_template" => {
            let number = args
                .get("number")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let template = clipguard_core::templates::personal_phone_template(number);
            match template {
                Some(template) => IpcResponse::ok(
                    request.id,
                    serde_json::to_value(&template).unwrap_or(Value::Null),
                ),
                None => IpcResponse::error(request.id, "the phone number is empty"),
            }
        }
        "show_dashboard" => {
            // Launch the dashboard if it is not running yet.
            let launched = launch_dashboard();
            IpcResponse::ok(request.id, Value::Bool(launched))
        }
        "clipboard_history" => {
            // The state of the history that Windows keeps on its own.
            let settings = crate::history::settings();
            IpcResponse::ok(
                request.id,
                serde_json::to_value(settings).unwrap_or(Value::Null),
            )
        }
        "set_clipboard_history" => {
            let enabled = args
                .get("enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            match crate::history::set_enabled(enabled) {
                Ok(()) => {
                    let settings = crate::history::settings();
                    IpcResponse::ok(
                        request.id,
                        serde_json::to_value(settings).unwrap_or(Value::Null),
                    )
                }
                Err(error) => IpcResponse::error(request.id, error.to_string()),
            }
        }
        "quit" => {
            // Ask the service to shut down.
            IpcResponse::ok(request.id, Value::Bool(true))
        }
        _ => IpcResponse::error(request.id, format!("unknown command `{}`", request.cmd)),
    }
}
