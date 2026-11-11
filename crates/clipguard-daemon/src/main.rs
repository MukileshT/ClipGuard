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

//! The ClipGuard command line interface and background service.
//!
//! The binary is built with the `windows` subsystem: double-clicking the
//! executable from Explorer never opens a console window. Command line
//! invocations from an open terminal reattach to that terminal before the
//! first output, so `clipguard scan`, `clipguard stats` and friends keep
//! working as usual.
//!
//! When the service is started in the background by the desktop application
//! it is spawned with the `CREATE_NO_WINDOW` flag, so no console window ever
//! flashes up either.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use clap::{Parser, Subcommand};
use clipguard_core::config::Config;
use clipguard_core::model::{GlobalMode, ProtectionMode};
use clipguard_daemon::ipc::{self, IpcClient};
use clipguard_daemon::runtime::Runtime;
use clipguard_daemon::tray::{Tray, TrayCommand, TrayState};
use clipguard_daemon::{SingleInstance, VERSION};

/// Name of the single instance mutex.
const MUTEX_NAME: &str = r"Local\ClipGuard.SingleInstance";

#[derive(Parser, Debug)]
#[command(
    name = "ClipGuard",
    version,
    about = "ClipGuard — native clipboard security firewall",
    long_about = None
)]
struct Cli {
    /// Path of the configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Increase the log verbosity.
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Run without a system tray icon.
    #[arg(long, global = true)]
    headless: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Run the background service (default).
    Run,
    /// Scan a piece of text and report what would be protected.
    Scan {
        /// The text to scan. Use "-" to read from standard input.
        text: String,
    },
    /// Show or change the configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Show the protection statistics of the running service.
    Stats,
    /// Show or change the clipboard history of Windows.
    History {
        /// Switch the history on or off. Without it the state is only shown.
        #[arg(value_enum)]
        action: Option<HistoryAction>,
    },
    /// Stop the running service (the tray icon does the same).
    Shutdown,
    /// List the built-in detection rules.
    Rules,
    /// Start ClipGuard automatically with Windows.
    Autostart {
        /// Enable or disable the automatic start entry.
        #[arg(value_enum)]
        state: AutostartState,
    },
}

/// What to do with the clipboard history of Windows.
#[derive(clap::ValueEnum, Debug, Clone)]
enum HistoryAction {
    /// Switch the history on.
    Enable,
    /// Switch the history off.
    Disable,
}

#[derive(Subcommand, Debug, Clone)]
enum ConfigAction {
    /// Print the current configuration.
    Show,
    /// Print the path of the configuration file.
    Path,
    /// Change a single value.
    Set {
        /// The dotted key, for example `protection.default_mode`.
        key: String,
        /// The new value.
        value: String,
    },
    /// Restore the default configuration.
    Reset,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum AutostartState {
    /// Enable the automatic start entry.
    Enable,
    /// Disable the automatic start entry.
    Disable,
}

fn main() {
    let cli = Cli::parse();

    // Command line invocations reattach to the terminal they came from.
    if cli.command.is_some() {
        attach_console();
    }

    init_logging(cli.verbose);

    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(clipguard_core::config::default_config_path);

    match cli.command.clone().unwrap_or(Command::Run) {
        Command::Run => run_service(config_path, cli.headless),
        Command::Scan { text } => scan(&config_path, &text),
        Command::Config { action } => config_command(&config_path, action),
        Command::Stats => stats(),
        Command::History { action } => history(action),
        Command::Shutdown => shutdown(),
        Command::Rules => rules(),
        Command::Autostart { state } => autostart(state),
    }
}

/// Reattaches the console of the parent process.
///
/// The binary uses the `windows` subsystem in release builds, so a terminal
/// that starts the CLI does not hand it a working set of standard handles.
/// Reattaching and rebinding the standard handles before the first output
/// makes `println!` and `eprintln!` reach the terminal again. When there is
/// no parent console (double-click from Explorer, spawn from the dashboard)
/// every call fails silently and nothing changes.
#[cfg(windows)]
fn attach_console() {
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE, SetStdHandle,
    };
    use windows::core::{PCWSTR, w};

    unsafe {
        // Only the missing handles are rebound: a caller that redirected
        // stdout keeps its redirected output.
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);

        let open_output = || {
            CreateFileW(
                PCWSTR(w!("CONOUT$").as_ptr()),
                GENERIC_WRITE.0,
                FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .ok()
        };
        let open_input = || {
            CreateFileW(
                PCWSTR(w!("CONIN$").as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .ok()
        };

        if GetStdHandle(STD_OUTPUT_HANDLE)
            .unwrap_or_default()
            .0
            .is_null()
            && let Some(conout) = open_output()
        {
            let _ = SetStdHandle(STD_OUTPUT_HANDLE, conout);
        }

        if GetStdHandle(STD_ERROR_HANDLE)
            .unwrap_or_default()
            .0
            .is_null()
            && let Some(conout) = open_output()
        {
            let _ = SetStdHandle(STD_ERROR_HANDLE, conout);
        }

        if GetStdHandle(STD_INPUT_HANDLE)
            .unwrap_or_default()
            .0
            .is_null()
            && let Some(conin) = open_input()
        {
            let _ = SetStdHandle(STD_INPUT_HANDLE, conin);
        }
    }
}

/// Reattaches the console of the parent process on non-Windows platforms.
#[cfg(not(windows))]
fn attach_console() {}

/// Configures the logging subsystem.
///
/// Logs are written to `%APPDATA%\ClipGuard\ClipGuard.log`. Clipboard
/// content is never logged: only metadata such as the kind and the count of
/// detected secrets.
fn init_logging(verbosity: u8) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = match verbosity {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };
        // The filter matches the crate names of the targets: "clipguard" is
        // the binary, "clipguard_daemon" the library. "ClipGuard" is only
        // the product name and would filter everything away.
        EnvFilter::new(format!(
            "clipguard={level},clipguard_daemon={level},clipguard_core=warn,clipguard_clipboard=warn"
        ))
    });

    let log_dir = dirs::config_dir()
        .map(|dir| dir.join("ClipGuard"))
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    let log_file = log_dir.join("ClipGuard.log");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file);

    match file {
        Ok(file) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(file)
                .with_ansi(false)
                .with_target(false)
                .try_init();
        }
        Err(error) => {
            eprintln!("could not open the log file: {error}");
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .try_init();
        }
    }
}

/// Runs the background service.
fn run_service(config_path: PathBuf, headless: bool) {
    let Some(instance) = SingleInstance::acquire(MUTEX_NAME) else {
        eprintln!("ClipGuard is already running.");
        return;
    };

    let runtime = match Runtime::start(config_path) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("could not start ClipGuard: {error}");
            return;
        }
    };
    let engine = Arc::clone(runtime.engine());

    // The tray icon. The sender is kept alive for the whole run: when it is
    // dropped, the command channel disconnects and the service would exit.
    let (command_sender, command_receiver) = channel::<TrayCommand>();
    let command_guard = command_sender.clone();
    let _tray = if headless {
        None
    } else {
        match Tray::spawn(command_sender) {
            Ok(tray) => Some(tray),
            Err(error) => {
                tracing::error!(?error, "could not create the tray icon");
                None
            }
        }
    };

    tracing::info!("ClipGuard {VERSION} started");

    // The automatic start entry and the setting in the configuration have to
    // agree. If the entry is missing or points at an old copy of the program,
    // it is written again.
    if engine.config().general.start_with_windows
        && (!clipguard_daemon::autostart::is_enabled()
            || !clipguard_daemon::autostart::points_at_current_executable())
    {
        match clipguard_daemon::autostart::set_enabled(true) {
            Ok(()) => tracing::info!("the automatic start entry was written again"),
            Err(error) => tracing::error!(?error, "could not write the automatic start entry"),
        }
    }

    // The main thread only processes user interaction.
    loop {
        match command_receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(TrayCommand::Exit) => {
                tracing::info!("shutting down");
                break;
            }
            Ok(TrayCommand::OpenDashboard) => {
                // Launch the dashboard without a console window.
                let _ = clipguard_daemon::runtime::launch_dashboard();
            }
            Ok(TrayCommand::TogglePause) => {
                let paused = !engine.is_paused();
                engine.set_paused(paused);
                tracing::info!(paused, "protection toggled");
            }
            Ok(TrayCommand::ToggleMode) => {
                let mut config = engine.config();
                config.general.global_mode = match config.general.global_mode {
                    GlobalMode::Ghost => GlobalMode::Satellite,
                    GlobalMode::Satellite => GlobalMode::Ghost,
                };
                if let Err(error) = engine.set_config(config) {
                    tracing::error!(?error, "could not change the global mode");
                }
            }
            Ok(TrayCommand::ToggleAutostart) => {
                let enabled = !clipguard_daemon::autostart::is_enabled();
                if let Err(error) = clipguard_daemon::autostart::set_enabled(enabled) {
                    tracing::error!(?error, "could not change the automatic start entry");
                }
            }
            Ok(TrayCommand::ToggleExisting) => {
                // Switches between masking only new copies and masking the
                // content that was on the clipboard when ClipGuard started.
                let mut config = engine.config();
                config.general.protect_existing_clipboard =
                    !config.general.protect_existing_clipboard;
                let enabled = config.general.protect_existing_clipboard;
                if let Err(error) = engine.set_config(config) {
                    tracing::error!(?error, "could not change the clipboard setting");
                } else {
                    tracing::info!(
                        enabled,
                        "the masking of older clipboard content was switched"
                    );
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // The service may also be asked to quit over the control
                // channel.
                if engine.shutdown_requested() {
                    tracing::info!("shutting down");
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }

        // Keep the menu and the tooltip in sync with the real state.
        if let Some(tray) = _tray.as_ref() {
            let config = engine.config();
            tray.update(TrayState {
                paused: engine.is_paused(),
                autostart: clipguard_daemon::autostart::is_enabled(),
                ghost_mode: config.general.global_mode == GlobalMode::Ghost,
                protect_existing: config.general.protect_existing_clipboard,
                protected_count: engine.stats().redacted,
            });
        }
    }

    runtime.shutdown();
    drop(command_guard);
    drop(instance);
}

/// Scans a piece of text.
fn scan(config_path: &Path, text: &str) {
    let config = Config::load(config_path).unwrap_or_default();
    let engine = config
        .build_engine()
        .unwrap_or_else(|_| clipguard_core::engine::DetectionEngine::new());

    let input = if text == "-" {
        use std::io::Read;
        let mut buffer = String::new();
        let _ = std::io::stdin().read_to_string(&mut buffer);
        buffer
    } else {
        text.to_string()
    };

    let report = engine.scan(&input);
    if report.is_clean() {
        println!("No secrets detected.");
        return;
    }

    println!("{} secret(s) detected:", report.findings.len());
    for finding in &report.findings {
        println!(
            "  [{}] {} — rule `{}`, {} byte(s) at offset {}",
            finding.risk.as_str(),
            finding.kind.label(),
            finding.rule,
            finding.length,
            finding.span.start
        );
    }
}

/// Configuration commands.
fn config_command(config_path: &Path, action: ConfigAction) {
    match action {
        ConfigAction::Path => println!("{}", config_path.display()),
        ConfigAction::Show => {
            let config = Config::load(config_path).unwrap_or_default();
            match config.to_toml() {
                Ok(text) => println!("{text}"),
                Err(error) => eprintln!("could not serialise the configuration: {error}"),
            }
        }
        ConfigAction::Reset => {
            let config = Config::default();
            match config.save(config_path) {
                Ok(()) => println!("The configuration was reset."),
                Err(error) => eprintln!("could not write the configuration: {error}"),
            }
        }
        ConfigAction::Set { key, value } => {
            let mut config = Config::load(config_path).unwrap_or_default();
            match apply_setting(&mut config, &key, &value) {
                Ok(()) => match config.save(config_path) {
                    Ok(()) => println!("`{key}` = `{value}`"),
                    Err(error) => eprintln!("could not write the configuration: {error}"),
                },
                Err(error) => eprintln!("could not change the setting: {error}"),
            }
        }
    }
}

/// Applies a single configuration change.
fn apply_setting(config: &mut Config, key: &str, value: &str) -> Result<(), String> {
    match key {
        "general.enabled" => {
            config.general.enabled = parse_bool(value)?;
        }
        "general.global_mode" => {
            config.general.global_mode = value
                .parse::<GlobalMode>()
                .map_err(|error| error.to_string())?;
        }
        "general.fail_safe" => {
            config.general.fail_safe = value
                .parse::<clipguard_core::model::FailSafe>()
                .map_err(|error| error.to_string())?;
        }
        "general.monitor_clipboard" => {
            config.general.monitor_clipboard = parse_bool(value)?;
        }
        "general.intercept_paste" => {
            config.general.intercept_paste = parse_bool(value)?;
        }
        "general.restore_on_trusted_paste" => {
            config.general.restore_on_trusted_paste = parse_bool(value)?;
        }
        "general.notifications" => {
            config.general.notifications = parse_bool(value)?;
        }
        "protection.default_mode" => {
            config.protection.default_mode = value
                .parse::<ProtectionMode>()
                .map_err(|error| error.to_string())?;
        }
        "protection.placeholder" => {
            config.protection.placeholder = value.to_string();
        }
        "detection.detect_personal" => {
            config.detection.detect_personal = parse_bool(value)?;
        }
        "detection.entropy.threshold" => {
            config.detection.entropy.threshold = value
                .parse::<f64>()
                .map_err(|error| format!("invalid number: {error}"))?;
        }
        "detection.entropy.min_length" => {
            config.detection.entropy.min_length = value
                .parse::<usize>()
                .map_err(|error| format!("invalid number: {error}"))?;
        }
        "detection.entropy.require_context" => {
            config.detection.entropy.require_context = parse_bool(value)?;
        }
        other => return Err(format!("unknown setting `{other}`")),
    }
    config.validate().map_err(|error| error.to_string())
}

/// Parses a boolean setting.
fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(format!("`{other}` is not a boolean")),
    }
}

/// Prints the statistics of the running service.
fn stats() {
    let Ok(client) = IpcClient::connect(ipc::PIPE_NAME) else {
        eprintln!("ClipGuard is not running.");
        std::process::exit(1);
    };
    match client.call("get_stats", serde_json::Value::Null) {
        Ok(value) => {
            if let Some(stats) = value.as_object() {
                println!("scans:           {}", stat(stats, "scans"));
                println!("detections:      {}", stat(stats, "detections"));
                println!("redacted:        {}", stat(stats, "redacted"));
                println!("removed:         {}", stat(stats, "removed"));
                println!("blocked:         {}", stat(stats, "blocked"));
                println!("allowed:         {}", stat(stats, "allowed"));
            }
        }
        Err(error) => eprintln!("could not read the statistics: {error}"),
    }
}

/// Shows or changes the clipboard history of Windows.
///
/// Windows keeps every copied text in its own history. The original secret
/// is stored there before ClipGuard masks the clipboard, so the history
/// should be switched off.
fn history(action: Option<HistoryAction>) {
    match action {
        Some(HistoryAction::Enable) | Some(HistoryAction::Disable) => {
            let enabled = matches!(action, Some(HistoryAction::Enable));
            if let Err(error) = clipguard_daemon::history::set_enabled(enabled) {
                eprintln!("could not change the clipboard history: {error}");
                std::process::exit(1);
            }
        }
        None => {}
    }

    let settings = clipguard_daemon::history::settings();
    println!(
        "clipboard history: {}",
        if settings.history_enabled {
            "on - Windows keeps every copied text"
        } else {
            "off"
        }
    );
    println!(
        "cloud clipboard:   {}",
        if settings.cloud_upload {
            "on - the copied text is synchronised with your Microsoft account"
        } else {
            "off"
        }
    );
    if settings.history_enabled {
        println!();
        println!("Switch it off with: clipguard history disable");
        println!("Entries that are already there are deleted once with Win+V -> Clear.");
    }
}

/// Stops the running background service.
fn shutdown() {
    let Ok(client) = IpcClient::connect(ipc::PIPE_NAME) else {
        eprintln!("ClipGuard is not running.");
        std::process::exit(1);
    };
    match client.call("shutdown", serde_json::Value::Null) {
        Ok(_) => println!("ClipGuard is shutting down."),
        Err(error) => {
            eprintln!("could not stop the service: {error}");
            std::process::exit(1);
        }
    }
}

/// Formats a statistic.
fn stat(stats: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    stats
        .get(key)
        .and_then(|value| value.as_u64())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_string())
}

/// Prints the built-in detection rules.
fn rules() {
    for rule in clipguard_core::rules::builtin::builtin_rules() {
        println!(
            "{:<38} {:<24} {}",
            rule.name,
            rule.kind.as_str(),
            rule.risk.unwrap_or(rule.kind.default_risk()).as_str()
        );
    }
}

/// Configures the automatic start entry.
fn autostart(state: AutostartState) {
    match state {
        AutostartState::Enable => match clipguard_daemon::autostart::set_enabled(true) {
            Ok(()) => {
                // Keep the config file in sync with the registry.
                let config_path = clipguard_core::config::default_config_path();
                if let Ok(mut config) = Config::load(&config_path) {
                    config.general.start_with_windows = true;
                    let _ = config.save(&config_path);
                }
                println!("ClipGuard will start with Windows.");
            }
            Err(error) => eprintln!("could not enable the automatic start entry: {error}"),
        },
        AutostartState::Disable => match clipguard_daemon::autostart::set_enabled(false) {
            Ok(()) => {
                // Keep the config file in sync with the registry.
                let config_path = clipguard_core::config::default_config_path();
                if let Ok(mut config) = Config::load(&config_path) {
                    config.general.start_with_windows = false;
                    let _ = config.save(&config_path);
                }
                println!("The automatic start entry was removed.");
            }
            Err(error) => eprintln!("could not disable the automatic start entry: {error}"),
        },
    }
}
