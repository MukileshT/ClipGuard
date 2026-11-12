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

//! Removes ClipWarden from the computer.
//!
//! The uninstaller stops the running processes, removes the automatic start
//! entry and deletes every folder that the program created. The folder that
//! contains the uninstaller itself is deleted afterwards, because a running
//! program cannot remove its own files.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Name of the automatic start entry in the registry.
#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Name of the automatic start value in the registry.
#[cfg(windows)]
const VALUE_NAME: &str = "ClipWarden";

/// The application identifier of the dashboard.
///
/// It must match the identifier in `tauri.conf.json`, because Windows uses it
/// for the data folder of the web view.
const IDENTIFIER: &str = "dev.mukilesh.clipwarden";

fn main() {
    println!("ClipWarden uninstaller");
    println!("===================");
    println!();
    println!("The following is removed:");
    println!("  * the running ClipWarden processes");
    println!("  * the automatic start entry of Windows");
    println!("  * the settings and the log file");
    println!("  * the data folder of the dashboard");
    println!("  * this folder");
    println!();

    if !confirm() {
        println!("Nothing was removed.");
        return;
    }

    stop_processes();
    remove_autostart();
    remove_folder(&app_data_folder(), "settings and log");
    remove_folder(&install_folder(), "installed program");
    remove_folder(&webview_folder(), "data of the dashboard");
    remove_own_folder();

    println!();
    println!("ClipWarden was removed.");
    pause();
}

/// Asks the user to confirm.
fn confirm() -> bool {
    print!("Remove ClipWarden completely? [Y/n] ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    let answer = answer.trim().to_ascii_lowercase();
    answer.is_empty() || answer == "y" || answer == "yes"
}

/// Stops the background service and the dashboard.
fn stop_processes() {
    for name in ["clipwarden.exe", "clipwarden-desktop.exe"] {
        let output = Command::new("taskkill").args(["/F", "/IM", name]).output();
        match output {
            Ok(result) if result.status.success() => println!("  stopped {name}"),
            _ => println!("  {name} was not running"),
        }
    }
}

/// Removes the automatic start entry.
#[cfg(windows)]
fn remove_autostart() {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    };

    unsafe {
        let mut key = HKEY::default();
        let sub_key: Vec<u16> = RUN_KEY.encode_utf16().chain(Some(0)).collect();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(sub_key.as_ptr()),
            None,
            KEY_SET_VALUE,
            &mut key,
        );
        if status != WIN32_ERROR(0) {
            println!("  the automatic start entry was not there");
            return;
        }
        let value: Vec<u16> = VALUE_NAME.encode_utf16().chain(Some(0)).collect();
        let status = RegDeleteValueW(key, windows::core::PCWSTR(value.as_ptr()));
        let _ = RegCloseKey(key);
        if status == WIN32_ERROR(0) {
            println!("  removed the automatic start entry");
        } else {
            println!("  the automatic start entry was not there");
        }
    }
}

/// Removes the automatic start entry on other systems.
#[cfg(not(windows))]
fn remove_autostart() {
    println!("  the automatic start entry was not there");
}

/// Deletes a folder and everything in it.
///
/// The web view of the dashboard is a separate process that needs a moment to
/// end, so the deletion is repeated for up to half a minute.
fn remove_folder(path: &Path, what: &str) {
    if !path.exists() {
        println!("  no {what} to remove");
        return;
    }
    for attempt in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => {
                println!("  removed {what}");
                return;
            }
            Err(error) => {
                if attempt == 29 {
                    println!("  could not remove {what}: {error}");
                    println!("    close the program and run uninstall.exe again");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

/// The folder with the settings and the log file.
fn app_data_folder() -> PathBuf {
    data_folder().join("ClipWarden")
}

/// The folder the program is installed in.
fn install_folder() -> PathBuf {
    local_folder().join("ClipWarden")
}

/// The data folder of the web view.
fn webview_folder() -> PathBuf {
    local_folder().join(IDENTIFIER)
}

/// The roaming data folder of the user.
fn data_folder() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The local data folder of the user.
fn local_folder() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Removes the folder that contains the uninstaller.
///
/// A running program cannot delete its own files, so a helper script waits
/// until this program has finished.
fn remove_own_folder() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(folder) = executable.parent() else {
        return;
    };
    let folder = folder.display().to_string();

    // A small script avoids the quoting problems of a long command line. It
    // waits until this program has ended, because the running program keeps
    // its own file locked. The script keeps a fixed name, so a later run
    // simply overwrites it.
    let script = std::env::temp_dir().join("clipwarden-uninstall.bat");
    let content = format!(
        "@echo off\r\n\
         setlocal EnableDelayedExpansion\r\n\
         cd /d \"%TEMP%\"\r\n\
         ping -n 3 127.0.0.1 > nul\r\n\
         set /a tries=0\r\n\
         :remove\r\n\
         rmdir /s /q \"{folder}\" 2>nul\r\n\
         if exist \"{folder}\" (\r\n\
         \x20 set /a tries+=1\r\n\
         \x20 if !tries! lss 20 (\r\n\
         \x20\x20 ping -n 2 127.0.0.1 > nul\r\n\
         \x20\x20 goto remove\r\n\
         \x20 )\r\n\
         )\r\n\
         exit /b\r\n"
    );
    if std::fs::write(&script, content).is_err() {
        println!("  the folder could not be removed automatically");
        return;
    }
    let _ = Command::new("cmd")
        .args(["/C", &script.display().to_string()])
        .spawn();
    println!("  removing this folder");
}

/// Waits for a key press so the output can be read.
fn pause() {
    print!("Press Enter to close...");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}
