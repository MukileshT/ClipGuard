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

//! Integration tests for the local control channel.

use std::sync::Arc;
use std::time::Duration;

use clipguard_daemon::ipc::{self, IpcClient, IpcRequest, IpcResponse};

/// Returns a pipe name that is unique for the current process.
fn pipe_name(suffix: &str) -> String {
    format!(r"\\.\pipe\ClipGuard.Test.{suffix}.{}", std::process::id())
}

/// Starts a control channel with a handler that echoes a fixed result.
fn start_server(name: &str) {
    let name = name.to_string();
    let handler: ipc::CommandHandler = Arc::new(|request: IpcRequest| match request.cmd.as_str() {
        "ping" => IpcResponse::ok(request.id, serde_json::json!({ "pong": true })),
        "echo" => IpcResponse::ok(request.id, request.args),
        "fail" => IpcResponse::error(request.id, "intentional failure"),
        other => IpcResponse::error(request.id, format!("unknown command `{other}`")),
    });
    std::thread::spawn(move || ipc::serve(&name, handler, None));
}

#[test]
fn commands_are_answered() {
    let name = pipe_name("Ping");
    start_server(&name);
    std::thread::sleep(Duration::from_millis(300));

    let client = IpcClient::connect(&name).expect("the control channel must be reachable");
    let result = client
        .call("ping", serde_json::Value::Null)
        .expect("the command must be answered");
    assert_eq!(result["pong"], serde_json::json!(true));
}

#[test]
fn arguments_are_forwarded() {
    let name = pipe_name("Echo");
    start_server(&name);
    std::thread::sleep(Duration::from_millis(300));

    let client = IpcClient::connect(&name).expect("the control channel must be reachable");
    let result = client
        .call("echo", serde_json::json!({ "text": "hello" }))
        .expect("the command must be answered");
    assert_eq!(result["text"], serde_json::json!("hello"));
}

#[test]
fn errors_are_reported() {
    let name = pipe_name("Error");
    start_server(&name);
    std::thread::sleep(Duration::from_millis(300));

    let client = IpcClient::connect(&name).expect("the control channel must be reachable");
    let error = client
        .call("fail", serde_json::Value::Null)
        .expect_err("the command must fail");
    assert!(error.to_string().contains("intentional failure"), "{error}");

    let error = client
        .call("nonsense", serde_json::Value::Null)
        .expect_err("the command must fail");
    assert!(error.to_string().contains("unknown command"), "{error}");
}

#[test]
fn several_commands_are_answered() {
    let name = pipe_name("Sequence");
    start_server(&name);
    std::thread::sleep(Duration::from_millis(300));

    let client = IpcClient::connect(&name).expect("the control channel must be reachable");
    for _ in 0..5 {
        let result = client
            .call("ping", serde_json::Value::Null)
            .expect("the command must be answered");
        assert_eq!(result["pong"], serde_json::json!(true));
    }
}

#[test]
fn several_clients_can_be_connected() {
    let name = pipe_name("Multi");
    start_server(&name);
    std::thread::sleep(Duration::from_millis(300));

    let first = IpcClient::connect(&name).expect("the control channel must be reachable");
    let second = IpcClient::connect(&name).expect("the control channel must be reachable");

    assert_eq!(
        first
            .call("ping", serde_json::Value::Null)
            .expect("the command must be answered")["pong"],
        serde_json::json!(true)
    );
    assert_eq!(
        second
            .call("ping", serde_json::Value::Null)
            .expect("the command must be answered")["pong"],
        serde_json::json!(true)
    );
}
