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

//! Integration tests for the configuration protocol of the control channel.
//!
//! The service protects every write with the dashboard password. The tests
//! make sure that a wrong password is rejected, that a correct one is
//! accepted, and that the payload format `{"config": …, "password": …}` is
//! understood.

use std::path::PathBuf;

use clipwarden_core::config::Config;
use clipwarden_daemon::ipc::{IpcRequest, IpcResponse};
use clipwarden_daemon::protection::ProtectionEngine;
use clipwarden_daemon::runtime::handle_command;

/// Hash of the test password "correct horse", computed the same way the
/// service does it.
fn hash(password: &str) -> String {
    clipwarden_daemon::password::hash(password).expect("the hash must be created")
}

/// Creates an engine with a configuration file in a temporary folder.
fn engine_with_password(password: &str) -> (ProtectionEngine, PathBuf) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "clipwarden-config-test-{}.toml",
        std::process::id()
    ));
    let mut config = Config::default();
    config.general.password_hash = hash(password);
    config
        .save(&path)
        .expect("the test configuration must be writable");
    let engine = ProtectionEngine::new(path.clone());
    (engine, path)
}

/// Runs a command and returns the response.
fn call(engine: &ProtectionEngine, cmd: &str, args: serde_json::Value) -> IpcResponse {
    handle_command(
        engine,
        IpcRequest {
            id: 1,
            cmd: cmd.to_string(),
            args,
        },
    )
}

#[test]
fn a_wrong_password_is_rejected() {
    let (engine, path) = engine_with_password("correct horse");
    let response = call(
        &engine,
        "set_config",
        serde_json::json!({ "config": Config::default(), "password": "wrong" }),
    );
    assert!(!response.ok, "a wrong password must be rejected");
    assert!(
        response
            .error
            .unwrap_or_default()
            .contains("incorrect password"),
        "the error must name the problem"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn the_correct_password_is_accepted() {
    let (engine, path) = engine_with_password("correct horse");
    let mut config = Config::default();
    config.protection.default_mode = clipwarden_core::model::ProtectionMode::Block;
    let response = call(
        &engine,
        "set_config",
        serde_json::json!({ "config": config, "password": "correct horse" }),
    );
    assert!(response.ok, "the correct password must be accepted");
    assert_eq!(
        engine.config().protection.default_mode,
        clipwarden_core::model::ProtectionMode::Block,
        "the new configuration must be active"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_bare_configuration_is_accepted_without_a_password() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "clipwarden-config-open-{}.toml",
        std::process::id()
    ));
    let config = Config::default();
    config
        .save(&path)
        .expect("the test configuration must be writable");
    let engine = ProtectionEngine::new(path.clone());

    // No password is set: the payload may be the bare configuration.
    let response = call(
        &engine,
        "set_config",
        serde_json::to_value(&config).unwrap(),
    );
    assert!(response.ok, "the configuration must be accepted");
    let _ = std::fs::remove_file(path);
}
