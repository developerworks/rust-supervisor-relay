use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

pub struct ProtocolTestTarget {
    _dir: TempDir,
    path: PathBuf,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ProtocolTestTarget {
    pub fn start(name: &str) -> Self {
        let dir = tempfile::tempdir().expect("temporary target directory should exist");
        let path = dir.path().join(format!("{name}.sock"));
        let listener = UnixListener::bind(&path).expect("target socket should bind");
        listener
            .set_nonblocking(true)
            .expect("target socket should be nonblocking");
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_stream(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            _dir: dir,
            path,
            running,
            worker: Some(worker),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn allowed_prefix(&self) -> &Path {
        self.path
            .parent()
            .expect("target socket should have parent")
    }
}

impl Drop for ProtocolTestTarget {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn handle_stream(mut stream: UnixStream) {
    let reader_stream = stream
        .try_clone()
        .expect("target stream clone should succeed");
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let request = match serde_json::from_str::<serde_json::Value>(line.trim()) {
        Ok(value) => value,
        Err(_) => return,
    };
    let response = response_for(request);
    let mut output = serde_json::to_vec(&response).expect("target response should serialize");
    output.push(b'\n');
    let _ = stream.write_all(&output);
}

fn response_for(request: serde_json::Value) -> serde_json::Value {
    let request_id = request
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("request-test");
    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    match method {
        "state" => json!({
            "request_id": request_id,
            "ok": true,
            "result": {
                "type": "state",
                "target_id": params.get("target_id").and_then(serde_json::Value::as_str).unwrap_or("payments-worker-a"),
                "state": {
                    "target": {
                        "target_id": params.get("target_id").and_then(serde_json::Value::as_str).unwrap_or("payments-worker-a"),
                        "display_name": "payments worker a"
                    },
                    "topology": {"root": {"path": "/root"}},
                    "runtime_state": [],
                    "recent_events": [],
                    "recent_logs": [],
                    "dropped_event_count": 0,
                    "dropped_log_count": 0,
                    "config_version": "cfg-test",
                    "generated_at_unix_nanos": 1,
                    "state_generation": 42
                }
            }
        }),
        "events.subscribe" | "logs.tail" => json!({
            "request_id": request_id,
            "ok": true,
            "result": {
                "type": "subscription",
                "target_id": params.get("target_id").and_then(serde_json::Value::as_str).unwrap_or("payments-worker-a"),
                "subscription": method
            }
        }),
        "command.restart_child"
        | "command.pause_child"
        | "command.resume_child"
        | "command.quarantine_child"
        | "command.remove_child"
        | "command.add_child"
        | "command.shutdown_tree" => json!({
            "request_id": request_id,
            "ok": true,
            "result": {
                "type": "command_result",
                "target_id": params.get("target_id").and_then(serde_json::Value::as_str).unwrap_or("payments-worker-a"),
                "result": {
                    "command_id": params.get("command_id").and_then(serde_json::Value::as_str).unwrap_or("cmd-test"),
                    "target_id": params.get("target_id").and_then(serde_json::Value::as_str).unwrap_or("payments-worker-a"),
                    "accepted": true,
                    "status": "completed",
                    "state_delta": {
                        "state_generation": 43
                    },
                    "completed_at_unix_nanos": 2
                }
            }
        }),
        _ => json!({
            "request_id": request_id,
            "ok": false,
            "error": {
                "code": "unsupported_method",
                "stage": "protocol",
                "message": "method is not supported",
                "retryable": false
            }
        }),
    }
}
