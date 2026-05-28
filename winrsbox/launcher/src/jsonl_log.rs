// JSONL structured logging — appends events to <state_dir>/sandbox.log.jsonl.
//
// Console output (println/eprintln) remains unchanged for human readability.
// This module provides machine-parseable persistent logs for post-mortem.
//
// Throttled: events are buffered in memory and flushed to disk at most once
// per FLUSH_INTERVAL. Critical events (violations) flush immediately.

use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BUFFER: usize = 256;

static LOGGER: std::sync::OnceLock<JsonlLogger> = std::sync::OnceLock::new();
static LOG_LEVEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2); // info

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Trace = 3,
}

pub fn init(log_path: PathBuf, level: &str) {
    let lvl = match level.to_ascii_lowercase().as_str() {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        "trace" => LogLevel::Trace,
        _ => LogLevel::Info,
    };
    LOG_LEVEL.store(lvl as u8, std::sync::atomic::Ordering::Relaxed);
    let _ = LOGGER.set(JsonlLogger::new(log_path));
}

fn level_enabled(level: LogLevel) -> bool {
    level as u8 <= LOG_LEVEL.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn log(event: Event) {
    if !level_enabled(event.level()) { return; }
    if let Some(logger) = LOGGER.get() {
        logger.push(event);
    }
}

pub fn log_immediate(event: Event) {
    if let Some(logger) = LOGGER.get() {
        logger.push_and_flush(event);
    }
}

pub fn flush() {
    if let Some(logger) = LOGGER.get() {
        logger.force_flush();
    }
}

struct JsonlLogger {
    path: PathBuf,
    buffer: Mutex<Vec<String>>,
    last_flush: Mutex<Instant>,
}

impl JsonlLogger {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            buffer: Mutex::new(Vec::with_capacity(MAX_BUFFER)),
            last_flush: Mutex::new(Instant::now() - FLUSH_INTERVAL),
        }
    }

    fn push(&self, event: Event) {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(mut buf) = self.buffer.lock() {
            buf.push(line);
        }
        self.maybe_flush();
    }

    fn push_and_flush(&self, event: Event) {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(mut buf) = self.buffer.lock() {
            buf.push(line);
        }
        self.force_flush();
    }

    fn maybe_flush(&self) {
        let mut last = match self.last_flush.try_lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        if last.elapsed() < FLUSH_INTERVAL {
            return;
        }
        *last = Instant::now();
        drop(last);
        self.do_flush();
    }

    fn force_flush(&self) {
        if let Ok(mut last) = self.last_flush.lock() {
            *last = Instant::now();
        }
        self.do_flush();
    }

    fn do_flush(&self) {
        let lines: Vec<String> = {
            let mut buf = match self.buffer.lock() {
                Ok(b) => b,
                Err(_) => return,
            };
            std::mem::take(&mut *buf)
        };
        if lines.is_empty() { return; }

        let mut file = match std::fs::OpenOptions::new()
            .create(true).append(true).open(&self.path)
        {
            Ok(f) => f,
            Err(_) => return,
        };
        for line in &lines {
            let _ = writeln!(file, "{}", line);
        }
    }
}

fn ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Serialize)]
#[serde(tag = "event")]
pub enum Event {
    #[serde(rename = "hello")]
    Hello { ts: u64, pid: u32, exe: String },
    #[serde(rename = "child")]
    Child { ts: u64, parent: u32, child: u32, exe: String },
    #[serde(rename = "decide")]
    Decide { ts: u64, path: String, write: bool, mode: String },
    #[serde(rename = "deny")]
    Deny { ts: u64, path: String, write: bool },
    #[serde(rename = "deny_device")]
    DenyDevice { ts: u64, path: String },
    #[serde(rename = "violation")]
    Violation { ts: u64, pid: u32, kind: String, detail: String },
    #[serde(rename = "reg_decide")]
    RegDecide { ts: u64, key: String, write: bool, mode: String },
    #[serde(rename = "net_decide")]
    NetDecide { ts: u64, host_port: String, allow: bool },
    #[serde(rename = "wfp")]
    Wfp { ts: u64, filters: usize },
    #[serde(rename = "exit")]
    Exit { ts: u64, code: u32, decides: u64, violations: u64 },
    #[serde(rename = "etw")]
    EtwEvent { ts: u64, pid: u32, kind: String },
}

impl Event {
    pub fn level(&self) -> LogLevel {
        match self {
            Event::Violation { .. } => LogLevel::Error,
            Event::Deny { .. } | Event::DenyDevice { .. } => LogLevel::Warn,
            Event::Hello { .. } | Event::Child { .. } | Event::Wfp { .. } | Event::Exit { .. }
            | Event::RegDecide { .. } | Event::NetDecide { .. } => LogLevel::Info,
            Event::Decide { .. } | Event::EtwEvent { .. } => LogLevel::Trace,
        }
    }

    pub fn hello(pid: u32, exe: &str) -> Self {
        Self::Hello { ts: ts(), pid, exe: exe.to_string() }
    }
    pub fn child(parent: u32, child: u32, exe: &str) -> Self {
        Self::Child { ts: ts(), parent, child, exe: exe.to_string() }
    }
    pub fn decide(path: &str, write: bool, mode: &str) -> Self {
        Self::Decide { ts: ts(), path: path.to_string(), write, mode: mode.to_string() }
    }
    pub fn deny(path: &str, write: bool) -> Self {
        Self::Deny { ts: ts(), path: path.to_string(), write }
    }
    pub fn violation(pid: u32, kind: &str, detail: &str) -> Self {
        Self::Violation { ts: ts(), pid, kind: kind.to_string(), detail: detail.to_string() }
    }
    pub fn reg_decide(key: &str, write: bool, mode: &str) -> Self {
        Self::RegDecide { ts: ts(), key: key.to_string(), write, mode: mode.to_string() }
    }
    pub fn net_decide(host_port: &str, allow: bool) -> Self {
        Self::NetDecide { ts: ts(), host_port: host_port.to_string(), allow }
    }
    pub fn wfp(filters: usize) -> Self {
        Self::Wfp { ts: ts(), filters }
    }
    pub fn exit(code: u32, decides: u64, violations: u64) -> Self {
        Self::Exit { ts: ts(), code, decides, violations }
    }
    pub fn etw_event(pid: u32, kind: &str) -> Self {
        Self::EtwEvent { ts: ts(), pid, kind: kind.to_string() }
    }
}
