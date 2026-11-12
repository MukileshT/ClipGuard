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

//! The ClipWarden desktop application.
//!
//! The dashboard is a pure HTML/JS client of the ClipWarden control channel.
//! No Node.js, no Vite, no TypeScript — just static files served by Tauri.
//!
//! If no other instance is running, the dashboard starts the background
//! service itself so that a single click is enough to get protection.
//! The service keeps running even when the dashboard window is closed
//! (system tray).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clipwarden_core::config::Config;
use clipwarden_core::model::{SecretFamily, SecretKind};
use clipwarden_core::policy::AppRule;
use clipwarden_core::rules::RuleSpec;
use clipwarden_core::stats::StatsSnapshot;
use clipwarden_daemon::instance::SingleInstance;
use clipwarden_daemon::ipc::{self, IpcClient};
use clipwarden_daemon::runtime::Runtime;
use serde::Serialize;
use tauri::{Emitter, Manager};

/// Name of the single instance mutex for the dashboard itself.
const DASHBOARD_MUTEX: &str = r"Local\ClipWarden.Dashboard";

/// Shared state of the application.
pub struct AppState {
    client: Arc<IpcClient>,
    _runtime: Mutex<Option<Runtime>>,
}

impl AppState {
    /// Returns the control channel client.
    fn client(&self) -> &IpcClient {
        &self.client
    }
}

/// The kind metadata that the user interface needs.
#[derive(Debug, Clone, Serialize)]
pub struct KindInfo {
    /// Stable identifier.
    pub id: String,
    /// Human readable label.
    pub label: String,
    /// The family the kind belongs to.
    pub family: String,
    /// The default risk of the kind.
    pub risk: String,
}

/// Information about a built-in rule.
#[derive(Debug, Clone, Serialize)]
pub struct BuiltinRuleInfo {
    /// The name of the rule.
    pub name: String,
    /// The pattern source.
    pub pattern: String,
    /// The kind of the rule.
    pub kind: String,
    /// The risk of the rule.
    pub risk: String,
    /// Whether the rule is enabled.
    pub enabled: bool,
}

/// Returns the metadata of every secret kind.
#[tauri::command]
fn list_secret_kinds() -> Vec<KindInfo> {
    SecretKind::ALL
        .iter()
        .map(|kind| KindInfo {
            id: kind.as_str().to_string(),
            label: kind.label().to_string(),
            family: kind.family().as_str().to_string(),
            risk: kind.default_risk().as_str().to_string(),
        })
        .collect()
}

/// Returns the metadata of every secret family.
#[tauri::command]
fn list_secret_families() -> Vec<KindInfo> {
    SecretFamily::ALL
        .iter()
        .map(|family| KindInfo {
            id: family.as_str().to_string(),
            label: family.label().to_string(),
            family: family.as_str().to_string(),
            risk: String::new(),
        })
        .collect()
}

/// Returns the built-in detection rules.
#[tauri::command]
fn list_builtin_rules() -> Vec<BuiltinRuleInfo> {
    clipwarden_core::rules::builtin::builtin_rules()
        .into_iter()
        .map(|rule| BuiltinRuleInfo {
            name: rule.name,
            pattern: rule.pattern,
            kind: rule.kind.as_str().to_string(),
            risk: rule
                .risk
                .unwrap_or_else(|| rule.kind.default_risk())
                .as_str()
                .to_string(),
            enabled: rule.enabled,
        })
        .collect()
}

/// Returns the ready-made detection templates.
#[tauri::command]
fn list_templates() -> Vec<clipwarden_core::templates::Template> {
    clipwarden_core::templates::all_templates()
}

/// Builds a template that protects one specific phone number.
#[tauri::command]
fn personal_phone_template(number: String) -> Result<clipwarden_core::templates::Template, String> {
    clipwarden_core::templates::personal_phone_template(&number)
        .ok_or_else(|| "the phone number is empty".to_string())
}

/// Returns the current protection status.
#[tauri::command]
fn get_status(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    state
        .client()
        .call("get_status", serde_json::Value::Null)
        .map_err(|error| error.to_string())
}

/// Returns the protection statistics.
#[tauri::command]
fn get_stats(state: tauri::State<'_, AppState>) -> Result<StatsSnapshot, String> {
    let value = state
        .client()
        .call("get_stats", serde_json::Value::Null)
        .map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

/// Returns the current configuration.
#[tauri::command]
fn get_config(state: tauri::State<'_, AppState>) -> Result<Config, String> {
    fetch_config(state.inner())
}

/// Reads the configuration from the service.
fn fetch_config(state: &AppState) -> Result<Config, String> {
    let value = state
        .client()
        .call("get_config", serde_json::Value::Null)
        .map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

/// Stores the configuration and returns the fresh one.
#[tauri::command]
fn set_config(
    config: Config,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Config, String> {
    store_config(state.inner(), config, password)?;
    fetch_config(state.inner())
}

/// Writes the configuration to the service.
fn store_config(state: &AppState, config: Config, password: Option<String>) -> Result<(), String> {
    state
        .client()
        .call(
            "set_config",
            serde_json::json!({ "config": config, "password": password }),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Hashes a password with Argon2id.
///
/// The service does the work, so that the salt stays under its control and
/// the dashboard never handles the hash. The plain text is never written to
/// disk.
#[tauri::command]
fn hash_password(
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let value = state
        .client()
        .call("hash_password", serde_json::json!({ "password": password }))
        .map_err(|error| error.to_string())?;
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "the service did not return a hash".to_string())
}

/// Returns the file paths ClipWarden uses on this machine.
#[tauri::command]
fn get_paths() -> serde_json::Value {
    let base = dirs::config_dir().map(|dir| dir.join("ClipWarden"));
    let display = |path: Option<std::path::PathBuf>| {
        path.map(|p| p.display().to_string())
            .unwrap_or_else(|| "(unavailable)".into())
    };
    serde_json::json!({
        "data_dir": display(base.clone()),
        "config_path": display(base.as_ref().map(|dir| dir.join("config.toml"))),
        "log_path": display(base.map(|dir| dir.join("ClipWarden.log"))),
        "version": clipwarden_core::VERSION,
    })
}

/// Returns the state of the Windows clipboard history.
///
/// Windows keeps the copied content on its own. The user has to know about
/// that, because the original secret is stored there before ClipWarden masks
/// the clipboard.
#[tauri::command]
fn get_clipboard_history(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    state
        .client()
        .call("clipboard_history", serde_json::Value::Null)
        .map_err(|error| error.to_string())
}

/// Switches the Windows clipboard history on or off.
#[tauri::command]
fn set_clipboard_history(
    enabled: bool,
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    state
        .client()
        .call(
            "set_clipboard_history",
            serde_json::json!({ "enabled": enabled }),
        )
        .map_err(|error| error.to_string())
}

/// Pauses or resumes the protection.
#[tauri::command]
fn set_paused(
    paused: bool,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .client()
        .call(
            "set_paused",
            serde_json::json!({ "paused": paused, "password": password }),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Scans a piece of text without touching the clipboard.
#[tauri::command]
fn scan(text: String, state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    state
        .client()
        .call("scan", serde_json::json!({ "text": text }))
        .map_err(|error| error.to_string())
}

/// Verifies the application password.
#[tauri::command]
fn verify_password(password: String, state: tauri::State<'_, AppState>) -> Result<bool, String> {
    state
        .client()
        .call(
            "verify_password",
            serde_json::json!({ "password": password }),
        )
        .map(|value| value.as_bool().unwrap_or(false))
        .map_err(|error| error.to_string())
}

/// Returns whether ClipWarden starts automatically with Windows.
#[tauri::command]
fn autostart_status(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    state
        .client()
        .call("autostart_status", serde_json::Value::Null)
        .map(|value| value.as_bool().unwrap_or(false))
        .map_err(|error| error.to_string())
}

/// Enables or disables the automatic start entry.
#[tauri::command]
fn set_autostart(enabled: bool, state: tauri::State<'_, AppState>) -> Result<(), String> {
    state
        .client()
        .call("set_autostart", serde_json::json!({ "enabled": enabled }))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Adds or updates an application rule.
#[tauri::command]
fn upsert_app_rule(
    rule: AppRule,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Config, String> {
    let mut config = fetch_config(state.inner())?;
    match config
        .apps
        .iter_mut()
        .find(|existing| existing.id == rule.id)
    {
        Some(existing) => *existing = rule,
        None => config.apps.push(rule),
    }
    store_config(state.inner(), config.clone(), password)?;
    Ok(config)
}

/// Removes an application rule.
#[tauri::command]
fn remove_app_rule(
    id: String,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Config, String> {
    let mut config = fetch_config(state.inner())?;
    config.apps.retain(|rule| rule.id != id);
    store_config(state.inner(), config.clone(), password)?;
    Ok(config)
}

/// Adds or updates a custom detection rule.
#[tauri::command]
fn upsert_rule(
    rule: RuleSpec,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Config, String> {
    let mut config = fetch_config(state.inner())?;
    match config
        .rules
        .iter_mut()
        .find(|existing| existing.name == rule.name)
    {
        Some(existing) => *existing = rule,
        None => config.rules.push(rule),
    }
    store_config(state.inner(), config.clone(), password)?;
    Ok(config)
}

/// Removes a custom detection rule.
#[tauri::command]
fn remove_rule(
    name: String,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Config, String> {
    let mut config = fetch_config(state.inner())?;
    config.rules.retain(|rule| rule.name != name);
    store_config(state.inner(), config.clone(), password)?;
    Ok(config)
}

/// Connects to the control channel, retrying while the service starts.
/// If the service is not running, it is started once from the same directory
/// as this executable.
fn connect_with_retry() -> Result<IpcClient, String> {
    let mut last_error = String::from("the ClipWarden service is not running");
    let mut started = false;

    for _ in 0..150 {
        match IpcClient::connect(ipc::PIPE_NAME) {
            Ok(client) => return Ok(client),
            Err(e) => {
                // The service is started only once. Starting it again on every
                // attempt would spawn a pile of processes that immediately
                // quit because another instance holds the mutex.
                if !started {
                    started = true;
                    match start_service() {
                        Ok(()) => {}
                        Err(message) => last_error = message,
                    }
                } else {
                    last_error = e.to_string();
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Err(last_error)
}

/// Starts clipwarden.exe from the same directory as this executable.
///
/// The service runs *with* its system tray icon, so the protection stays
/// visible and controllable while the dashboard window is closed — quitting
/// happens through the tray menu → Exit.
///
/// The service is spawned with `CREATE_NO_WINDOW` so that no console window
/// flashes up behind the dashboard.
fn start_service() -> Result<(), String> {
    let exe_path =
        std::env::current_exe().map_err(|e| format!("could not get current exe path: {e}"))?;
    let dir = exe_path.parent().ok_or("could not get parent directory")?;

    // The binary may be named either "clipwarden.exe" or "ClipWarden.exe"
    // depending on how the release was built; try both.
    let service_path = ["clipwarden.exe", "ClipWarden.exe"]
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists())
        .ok_or_else(|| {
            format!(
                "service executable not found next to: {}",
                exe_path.display()
            )
        })?;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mut command = std::process::Command::new(&service_path);
    // No `--headless`: the service keeps its system tray icon, which is the
    // only place the whole application can be quit from.
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    match command.spawn() {
        Ok(child) => {
            // Detach the child so it keeps running after the dashboard exits.
            let _pid = child.id();
            std::mem::forget(child);
            Ok(())
        }
        Err(e) => Err(format!("could not start service: {e}")),
    }
}

/// Signals the running dashboard to bring its window to the front.
///
/// The first instance listens on a named event; a second instance that fails
/// to acquire the dashboard mutex sets the event and exits. This never goes
/// through the service, so a stale dashboard cannot trigger a spawn loop.
fn show_running_dashboard() {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, GetLastError};
        use windows::Win32::System::Threading::{
            CreateEventW, EVENT_MODIFY_STATE, OpenEventW, SetEvent,
        };
        use windows::core::{PCWSTR, w};

        let name = PCWSTR(w!("Local\\ClipWarden.ShowDashboard").as_ptr());
        // The first instance may not have created the event yet; create it so
        // the signal is not lost either way.
        if let Ok(event) = CreateEventW(None, false, false, name) {
            let _ = SetEvent(event);
            let _ = CloseHandle(event);
            return;
        }
        if GetLastError() != ERROR_FILE_NOT_FOUND {
            return;
        }
        if let Ok(event) = OpenEventW(EVENT_MODIFY_STATE, false, name) {
            let _ = SetEvent(event);
            let _ = CloseHandle(event);
        }
    }
}

/// Opens (or creates) the show-dashboard event for listening.
#[cfg(windows)]
fn open_show_event() -> Option<windows::Win32::Foundation::HANDLE> {
    unsafe {
        use windows::Win32::System::Threading::CreateEventW;
        use windows::core::w;

        let event = CreateEventW(
            None,
            false,
            false,
            windows::core::PCWSTR(w!("Local\\ClipWarden.ShowDashboard").as_ptr()),
        )
        .ok()?;
        Some(event)
    }
}

#[cfg(not(windows))]
fn open_show_event() -> Option<()> {
    None
}

/// Starts the desktop application.
pub fn run() {
    init_logging();

    // Only one dashboard may run. The background service uses a different
    // mutex, so the dashboard never blocks the service from starting.
    if SingleInstance::acquire(DASHBOARD_MUTEX).is_none() {
        // Another dashboard is already running; signal it to show its window.
        show_running_dashboard();
        return;
    }

    // Connect to the background service, starting it if necessary.
    let client = match connect_with_retry() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("could not reach the ClipWarden service: {error}");
            return;
        }
    };

    let client = Arc::new(client);
    let event_client = Arc::clone(&client);

    let state = AppState {
        client,
        _runtime: Mutex::new(None),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_secret_kinds,
            list_secret_families,
            list_builtin_rules,
            list_templates,
            personal_phone_template,
            get_status,
            get_stats,
            get_config,
            set_config,
            get_paths,
            hash_password,
            get_clipboard_history,
            set_clipboard_history,
            set_paused,
            verify_password,
            scan,
            autostart_status,
            set_autostart,
            upsert_app_rule,
            remove_app_rule,
            upsert_rule,
            remove_rule,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();

            // Forward the events of the service to the dashboard.
            let event_client = event_client.clone();
            let forward_handle = handle.clone();
            let quit_handle = handle.clone();
            std::thread::Builder::new()
                .name("clipwarden-ui-events".into())
                .spawn(move || {
                    loop {
                        if let Some(event) = event_client.try_event() {
                            if event.event == "shutdown" {
                                // The service quits on its own: the dashboard
                                // closes with it.
                                quit_handle.exit(0);
                                return;
                            }
                            let _ = forward_handle.emit("detection", event.data);
                        }
                        std::thread::sleep(Duration::from_millis(250));
                    }
                })
                .ok();

            // Watch the service. If it dies, it is started again: a firewall
            // that silently stops protecting the clipboard is worse than no
            // firewall at all. When the user quits through the tray menu, the
            // service says goodbye first and the dashboard closes with it.
            let monitor_handle = handle.clone();
            std::thread::Builder::new()
                .name("clipwarden-service-watch".into())
                .spawn(move || {
                    let mut failures = 0;
                    loop {
                        std::thread::sleep(Duration::from_secs(2));
                        match IpcClient::connect(ipc::PIPE_NAME) {
                            Ok(client) => {
                                // Any cheap round trip proves the service is alive.
                                let _ = client.call("get_stats", serde_json::Value::Null);
                                failures = 0;
                            }
                            Err(_) => {
                                failures += 1;
                                if failures >= 2 {
                                    if clipwarden_daemon::marker::exists() {
                                        // The service was stopped on purpose.
                                        tracing::info!("the service was stopped; closing");
                                        monitor_handle.exit(0);
                                        return;
                                    }
                                    tracing::warn!("the service is not answering; starting it again");
                                    if start_service().is_err() {
                                        tracing::error!("the service could not be started again");
                                        monitor_handle.exit(0);
                                        return;
                                    }
                                    failures = 0;
                                }
                            }
                        }
                    }
                })
                .ok();

            // Listen for the show event so a second dashboard instance can
            // bring this window back to the front.
            let show_handle = handle.clone();
            std::thread::Builder::new()
                .name("clipwarden-show-watch".into())
                .spawn(move || {
                    if let Some(event) = open_show_event() {
                        loop {
                            unsafe {
                                let _ = windows::Win32::System::Threading::WaitForSingleObject(
                                    event,
                                    windows::Win32::System::Threading::INFINITE,
                                );
                            }
                            if let Some(window) = show_handle.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .ok();

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the ClipWarden dashboard could not be started");
}

/// Configures the logging of the desktop application.
fn init_logging() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("clipwarden=info,clipwarden_core=warn"));
    let log_dir = dirs::config_dir()
        .map(|dir| dir.join("ClipWarden"))
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("clipwarden.log"))
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .with_ansi(false)
            .with_target(false)
            .try_init();
    }
}

/// Creates a channel that forwards daemon events to a client.
#[allow(dead_code)]
fn _unused() -> std::sync::mpsc::Receiver<()> {
    let (_, rx) = std::sync::mpsc::channel();
    rx
}
