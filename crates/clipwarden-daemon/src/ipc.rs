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

//! The local control channel.
//!
//! The daemon exposes a named pipe that the desktop application connects to.
//! The protocol is intentionally simple: every message is a single line of
//! JSON.
//!
//! ```text
//! -> {"id":1,"cmd":"get_stats","args":{}}
//! <- {"id":1,"ok":true,"result":{"scans":12}}
//! <- {"event":"detection","data":{...}}
//! ```
//!
//! The pipe is local to the machine and is only accessible to the user that
//! started the daemon.
//!
//! # Implementation notes
//!
//! The channel talks to the Win32 pipe API directly:
//!
//! * `std::fs::File` combined with `BufReader` must not be used here — the
//!   buffered reader competes with the writer for the same duplex handle and
//!   stalls the cycle.
//! * Every handle is opened with `FILE_FLAG_OVERLAPPED`. A pending
//!   synchronous `ReadFile` blocks every other operation on the same file
//!   object — even on a *duplicated* handle, because duplicates share the
//!   file object. With overlapped I/O a read and a write can be pending at
//!   the same time, which is exactly what the protocol needs: the client
//!   keeps a background reader (for unsolicited events) while the calling
//!   thread sends the next request.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    ReadFile, WriteFile,
};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{CreateEventW, INFINITE, ResetEvent, WaitForSingleObject};
use windows::core::PCWSTR;

/// Default name of the control pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\ClipWarden.Control";

/// Size of the buffer used to read from the pipe.
const READ_BUFFER: usize = 8192;

/// Security descriptor of the control pipe.
///
/// `OW` stands for the owner rights: the pipe belongs to the user that runs
/// the service, and nobody else may connect to it.
const PIPE_SDDL: &str = r"D:P(A;;GA;;;OW)";

/// Number of pipe instances that may exist at the same time.
///
/// The dashboard, the command line and a few tools may be connected at once;
/// more than that is not a normal use.
const MAX_PIPE_INSTANCES: u32 = 8;

/// A request sent by a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Identifier that is echoed in the response.
    pub id: u64,
    /// The command name.
    pub cmd: String,
    /// Optional arguments.
    #[serde(default)]
    pub args: serde_json::Value,
}

/// A response sent by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Identifier of the request this response belongs to.
    pub id: u64,
    /// Whether the command succeeded.
    pub ok: bool,
    /// The result payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// The error message, if the command failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl IpcResponse {
    /// Creates a successful response.
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// Creates an error response.
    pub fn error(id: u64, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(message.into()),
        }
    }
}

/// An event pushed by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEvent {
    /// The event name.
    pub event: String,
    /// The event payload.
    pub data: serde_json::Value,
}

/// Errors of the control channel.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// A Win32 call failed.
    #[error("control channel error: {0}")]
    Win32(#[from] windows::core::Error),
    /// The pipe could not be opened.
    #[error("the ClipWarden service is not running")]
    NotRunning,
    /// A message could not be decoded.
    #[error("invalid control channel message: {0}")]
    Invalid(String),
    /// The connection was closed unexpectedly.
    #[error("the control channel was closed")]
    Closed,
}

/// Handler that executes a command.
pub type CommandHandler = Arc<dyn Fn(IpcRequest) -> IpcResponse + Send + Sync>;

/// An owned, overlapped pipe handle together with its synchronisation events.
///
/// Overlapped I/O is essential here. A pending synchronous `ReadFile` blocks
/// every other operation on the same file object — even on a *duplicated*
/// handle, because duplicates share the file object. With overlapped I/O a
/// read and a write can be pending at the same time, which is what the
/// request/response plus unsolicited event protocol needs.
struct PipeHandle {
    handle: HANDLE,
    /// Event that completes read operations.
    read_event: HANDLE,
    /// Event that completes write operations.
    write_event: HANDLE,
}

// A pipe handle is a kernel handle; moving it between threads is safe as long
// as it is closed exactly once. Sharing it is intended: overlapped reads and
// writes on the same handle run concurrently by design.
unsafe impl Send for PipeHandle {}
unsafe impl Sync for PipeHandle {}

/// Creates an auto reset event for overlapped operations.
fn create_event() -> windows::core::Result<HANDLE> {
    unsafe { CreateEventW(None, false, false, None) }
}

impl PipeHandle {
    /// Wraps an existing handle and creates its events.
    ///
    /// On failure the caller owned handle is closed again.
    fn from_raw(raw: HANDLE) -> Result<Self, IpcError> {
        let read_event = create_event().map_err(|_| IpcError::NotRunning);
        let write_event = create_event().map_err(|_| IpcError::NotRunning);
        match (read_event, write_event) {
            (Ok(read_event), Ok(write_event)) => Ok(Self {
                handle: raw,
                read_event,
                write_event,
            }),
            (read_event, write_event) => {
                unsafe {
                    let _ = CloseHandle(raw);
                    if let Ok(event) = read_event {
                        let _ = CloseHandle(event);
                    }
                    if let Ok(event) = write_event {
                        let _ = CloseHandle(event);
                    }
                }
                Err(IpcError::NotRunning)
            }
        }
    }

    /// Opens the pipe as a client.
    fn open_client(path: &str) -> Result<Self, IpcError> {
        let raw = unsafe {
            CreateFileW(
                PCWSTR(wide(path).as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )?
        };
        Self::from_raw(raw)
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
            let _ = CloseHandle(self.read_event);
            let _ = CloseHandle(self.write_event);
        }
    }
}

/// Performs one overlapped read.
///
/// Returns `Ok(None)` when the connection was closed (end of stream).
fn read_overlapped(
    pipe: &PipeHandle,
    buffer: &mut [u8],
) -> std::result::Result<Option<u32>, IpcError> {
    let mut overlapped = OVERLAPPED {
        hEvent: pipe.read_event,
        ..Default::default()
    };
    unsafe {
        ResetEvent(pipe.read_event)?;
        match ReadFile(pipe.handle, Some(buffer), None, Some(&mut overlapped)) {
            // The operation may complete synchronously or stay pending; both
            // are resolved by waiting on the event.
            Ok(()) => {}
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {}
            Err(error) => return Err(error.into()),
        }
        if WaitForSingleObject(pipe.read_event, INFINITE) != WAIT_OBJECT_0 {
            return Err(IpcError::Invalid("the read did not complete".into()));
        }
        let mut transferred: u32 = 0;
        if GetOverlappedResult(pipe.handle, &overlapped, &mut transferred, true).is_err() {
            // The peer closed the connection or the operation was aborted.
            return Ok(None);
        }
        if transferred == 0 {
            return Ok(None);
        }
        Ok(Some(transferred))
    }
}

/// Performs one overlapped write.
///
/// Gives up after thirty seconds so that a wedged peer cannot block the
/// caller forever; the pending operation is cancelled first.
fn write_overlapped(pipe: &PipeHandle, data: &[u8]) -> std::result::Result<(), IpcError> {
    let mut overlapped = OVERLAPPED {
        hEvent: pipe.write_event,
        ..Default::default()
    };
    unsafe {
        ResetEvent(pipe.write_event)?;
        match WriteFile(pipe.handle, Some(data), None, Some(&mut overlapped)) {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {}
            Err(error) => return Err(error.into()),
        }
        let timeout = Duration::from_secs(30);
        if WaitForSingleObject(pipe.write_event, timeout.as_millis() as u32) != WAIT_OBJECT_0 {
            let _ = windows::Win32::System::IO::CancelIoEx(pipe.handle, Some(&overlapped));
            return Err(IpcError::Invalid("the write did not complete".into()));
        }
        let mut transferred: u32 = 0;
        GetOverlappedResult(pipe.handle, &overlapped, &mut transferred, true)?;
        Ok(())
    }
}

/// Reads a single line from the pipe.
///
/// Returns `None` when the connection was closed.
fn read_line(pipe: &PipeHandle, pending: &mut Vec<u8>) -> Option<String> {
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        if let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=position).collect();
            return Some(String::from_utf8_lossy(&line[..line.len() - 1]).into_owned());
        }
        let read = read_overlapped(pipe, &mut buffer).ok()??;
        pending.extend_from_slice(&buffer[..read as usize]);
    }
}

/// Writes a complete message to the pipe.
fn write_message(pipe: &PipeHandle, payload: &str) -> std::result::Result<(), IpcError> {
    let mut data = payload.as_bytes().to_vec();
    data.push(b'\n');
    write_overlapped(pipe, &data)
}

/// A connected client of the control channel.
struct Client {
    io: Arc<PipeHandle>,
    /// Serialises the writes of the connection thread and the event pump.
    write_lock: Mutex<()>,
}

/// Starts the control channel server.
///
/// The server accepts multiple clients; each connection is handled in its own
/// thread. When `events` is provided, every event is forwarded to all
/// connected clients as an unsolicited message.
pub fn serve(
    pipe_name: &str,
    handler: CommandHandler,
    events: Option<Receiver<serde_json::Value>>,
) {
    let clients: Arc<Mutex<Vec<Arc<Client>>>> = Arc::new(Mutex::new(Vec::new()));
    // The first instance of the pipe refuses to start when another program
    // already owns the name.
    let mut first = true;

    if let Some(events) = events {
        let clients = Arc::clone(&clients);
        std::thread::Builder::new()
            .name("ClipWarden-ipc-events".into())
            .spawn(move || {
                while let Ok(payload) = events.recv() {
                    // A payload may name its own event, for example the
                    // notice that the service is about to quit.
                    let name = payload
                        .get("event")
                        .and_then(|value| value.as_str())
                        .unwrap_or("detection")
                        .to_string();
                    let message = IpcEvent {
                        event: name,
                        data: payload,
                    };
                    let encoded = serde_json::to_string(&message).unwrap_or_default();
                    let guard = clients.lock().expect("clients lock");
                    for client in guard.iter() {
                        let _guard = client.write_lock.lock().expect("write lock");
                        let _ = write_message(&client.io, &encoded);
                    }
                }
            })
            .ok();
    }

    loop {
        let Some(pipe) = open_instance(pipe_name, first) else {
            tracing::error!("could not create the control pipe");
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        first = false;

        // A client may connect between the creation of the instance and the
        // call to `ConnectNamedPipe`. That is not an error: the connection is
        // already established.
        if !connect_instance(&pipe) {
            continue;
        }

        let handler = Arc::clone(&handler);
        let clients = Arc::clone(&clients);
        std::thread::spawn(move || {
            handle_connection(Arc::new(pipe), handler, clients);
        });
    }
}

/// Creates one listening pipe instance.
///
/// The pipe is only reachable for the user that runs the service: the
/// security descriptor grants the access to the owner rights alone. Remote
/// clients are rejected, so the pipe cannot be reached from another
/// machine.
fn open_instance(pipe_name: &str, first: bool) -> Option<PipeHandle> {
    let security = PipeSecurity::new()?;

    let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        // The first instance refuses to start when another program already
        // owns the name. That way a program of another user cannot take the
        // place of the service.
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    let raw = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide(pipe_name).as_ptr()),
            open_mode,
            mode,
            MAX_PIPE_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            Some(&security.attributes),
        )
    };
    if raw.is_invalid() {
        tracing::error!(
            code = unsafe { windows::Win32::Foundation::GetLastError().0 },
            "could not create the control pipe"
        );
        return None;
    }
    PipeHandle::from_raw(raw).ok()
}

/// The security descriptor of the control pipe.
///
/// Only the user that runs the service may connect to the pipe. Without it
/// every program of the same user could change the configuration and switch
/// the protection off.
struct PipeSecurity {
    attributes: SECURITY_ATTRIBUTES,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl PipeSecurity {
    /// Builds the attributes from the security descriptor of the pipe.
    fn new() -> Option<Self> {
        let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let size = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        };
        if size.is_err() {
            tracing::error!("could not build the security descriptor of the control pipe");
            return None;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        Some(Self {
            attributes,
            descriptor,
        })
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

/// Waits for a client to connect to the pipe instance.
fn connect_instance(pipe: &PipeHandle) -> bool {
    // The read event is free at this point: the connection is established
    // before any read starts.
    let mut overlapped = OVERLAPPED {
        hEvent: pipe.read_event,
        ..Default::default()
    };
    unsafe {
        let _ = ResetEvent(pipe.read_event);
        match ConnectNamedPipe(pipe.handle, Some(&mut overlapped)) {
            // The client connected before the call.
            Ok(()) => true,
            Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => true,
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {
                if WaitForSingleObject(pipe.read_event, INFINITE) != WAIT_OBJECT_0 {
                    return false;
                }
                // The operation is waited for again here: the event is
                // signalled a moment before the result can be read, and
                // without the wait the connection would be given up while
                // the client is already attached to it.
                let mut transferred: u32 = 0;
                GetOverlappedResult(pipe.handle, &overlapped, &mut transferred, true).is_ok()
            }
            Err(_) => false,
        }
    }
}

/// Serves a single client connection.
fn handle_connection(
    io: Arc<PipeHandle>,
    handler: CommandHandler,
    clients: Arc<Mutex<Vec<Arc<Client>>>>,
) {
    let client = Arc::new(Client {
        io: Arc::clone(&io),
        write_lock: Mutex::new(()),
    });
    {
        let mut guard = clients.lock().expect("clients lock");
        guard.push(Arc::clone(&client));
    }

    let mut pending = Vec::new();
    while let Some(line) = read_line(&io, &mut pending) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        tracing::trace!(command = %trimmed, "control channel request");
        let response = match serde_json::from_str::<IpcRequest>(trimmed) {
            Ok(request) => handler(request),
            Err(error) => IpcResponse::error(0, format!("invalid request: {error}")),
        };
        let payload = serde_json::to_string(&response).unwrap_or_default();
        {
            let _guard = client.write_lock.lock().expect("write lock");
            if write_message(&io, &payload).is_err() {
                break;
            }
        }
    }

    let mut guard = clients.lock().expect("clients lock");
    guard.retain(|entry| !Arc::ptr_eq(entry, &client));
}

/// A client of the control channel.
///
/// Reading happens on a dedicated thread that shares the overlapped pipe
/// handle. Overlapped I/O keeps the pending read from blocking the write of
/// the next request.
pub struct IpcClient {
    /// The overlapped pipe handle.
    io: Arc<PipeHandle>,
    /// The answers of the service. The receiver is shared with the reader
    /// thread and guarded so that the client stays `Sync`.
    inbox: Mutex<std::sync::mpsc::Receiver<serde_json::Value>>,
    /// The events of the service, filled by the reader thread.
    events: Mutex<std::sync::mpsc::Receiver<IpcEvent>>,
    /// Serialises the commands: only one request may be in flight.
    call_lock: Mutex<()>,
    next_id: Mutex<u64>,
}

impl IpcClient {
    /// Connects to the control channel.
    pub fn connect(pipe_name: &str) -> Result<Self, IpcError> {
        // All instances of the pipe may be busy; in that case Windows reports
        // ERROR_PIPE_BUSY and the connection is retried for a short time.
        let mut last_error = None;
        for _ in 0..40 {
            match Self::connect_once(pipe_name) {
                Ok(client) => return Ok(client),
                Err(error) => {
                    last_error = Some(error);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Err(last_error.unwrap_or(IpcError::NotRunning))
    }

    /// Opens the pipe exactly once.
    fn connect_once(pipe_name: &str) -> Result<Self, IpcError> {
        let io = Arc::new(PipeHandle::open_client(pipe_name)?);
        let (answer_sender, answers) = std::sync::mpsc::channel();
        let (event_sender, events) = std::sync::mpsc::channel();

        // A background reader sorts the messages of the service into answers
        // and events, so that an event is delivered even when no command is
        // running.
        let reader_io = Arc::clone(&io);
        std::thread::Builder::new()
            .name("clipwarden-ipc-reader".into())
            .spawn(move || {
                let mut pending = Vec::new();
                while let Some(line) = read_line(&reader_io, &mut pending) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let value: serde_json::Value = match serde_json::from_str(trimmed) {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::debug!(?error, "received an invalid control message");
                            continue;
                        }
                    };
                    if let Some(event) = parse_event(&value) {
                        if event_sender.send(event).is_err() {
                            break;
                        }
                    } else if answer_sender.send(value).is_err() {
                        break;
                    }
                }
            })
            .ok();

        Ok(Self {
            io,
            inbox: Mutex::new(answers),
            events: Mutex::new(events),
            call_lock: Mutex::new(()),
            next_id: Mutex::new(1),
        })
    }

    /// Sends a command and waits for the response.
    pub fn call(&self, cmd: &str, args: serde_json::Value) -> Result<serde_json::Value, IpcError> {
        let _call = self.call_lock.lock().expect("call lock");
        let id = {
            let mut next = self.next_id.lock().expect("id lock");
            let id = *next;
            *next += 1;
            id
        };
        let request = IpcRequest {
            id,
            cmd: cmd.to_string(),
            args,
        };
        let payload = serde_json::to_string(&request)
            .map_err(|error| IpcError::Invalid(error.to_string()))?;
        write_message(&self.io, &payload)?;

        loop {
            let value = {
                let inbox = self.inbox.lock().expect("inbox lock");
                match inbox.recv_timeout(Duration::from_secs(15)) {
                    Ok(value) => value,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(IpcError::Closed);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        return Err(IpcError::Invalid("the service did not respond".into()));
                    }
                }
            };
            if value.get("id").and_then(|v| v.as_u64()) == Some(id) {
                if value.get("ok").and_then(|v| v.as_bool()) == Some(false) {
                    let message = value
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown error")
                        .to_string();
                    return Err(IpcError::Invalid(message));
                }
                return Ok(value
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null));
            }
        }
    }

    /// Returns the next queued event, if any.
    pub fn try_event(&self) -> Option<IpcEvent> {
        let events = self.events.lock().expect("events lock");
        events.try_recv().ok()
    }
}

/// Parses an event message.
fn parse_event(value: &serde_json::Value) -> Option<IpcEvent> {
    let name = value.get("event")?.as_str()?.to_string();
    let data = value
        .get("data")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Some(IpcEvent { event: name, data })
}

/// Converts a string into a null terminated UTF-16 buffer.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Creates a channel that forwards daemon events to a client.
pub fn event_channel() -> (Sender<serde_json::Value>, Receiver<serde_json::Value>) {
    channel()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{ACE_HEADER, GetAce, GetSecurityDescriptorDacl};
    use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    #[test]
    fn the_control_pipe_is_limited_to_its_owner() {
        // The descriptor must come from the owner-only SDDL. A regression to
        // a world-accessible ACL would let every program of the same user
        // open the pipe and switch the protection off.
        assert_eq!(PIPE_SDDL, r"D:P(A;;GA;;;OW)");

        let security = PipeSecurity::new().expect("the pipe needs a security descriptor");
        assert_eq!(
            security.attributes.nLength as usize,
            std::mem::size_of::<SECURITY_ATTRIBUTES>()
        );
        assert_eq!(
            security.attributes.bInheritHandle,
            windows::core::BOOL::from(false)
        );

        // The descriptor must carry a real DACL with exactly one
        // access-allowed ACE: the owner.
        unsafe {
            let descriptor = PSECURITY_DESCRIPTOR(security.attributes.lpSecurityDescriptor);

            let mut dacl_present = windows::core::BOOL::from(false);
            let mut dacl = std::ptr::null_mut();
            let mut dacl_defaulted = windows::core::BOOL::from(false);
            GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
            .expect("the security descriptor must be readable");
            assert!(dacl_present.as_bool(), "the pipe needs a DACL");
            assert!(!dacl.is_null(), "the DACL must not be empty");
            assert_eq!((*dacl).AceCount, 1, "only the owner may have access");

            let mut ace = std::ptr::null_mut();
            GetAce(dacl, 0, &mut ace).expect("the DACL must hold an ACE");
            let header = &*(ace as *const ACE_HEADER);
            assert_eq!(
                header.AceType as u32, ACCESS_ALLOWED_ACE_TYPE,
                "the ACE must grant access, not deny it"
            );
        }
    }
}
