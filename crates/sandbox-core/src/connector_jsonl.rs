//! Real connectors: JSONL file replay and channel-based streaming.
//!
//! Replaces the toy `VecConnector` with two production-shape connectors:
//!
//! - [`JsonlFileConnector`] — replays events from a JSON-lines file. Each
//!   line is one event of the customer's chosen type (parameterised by `T`).
//!   Used for backfill, replay, post-incident reconstruction, and offline
//!   audit reproduction.
//! - [`ChannelConnector`] — wraps a `std::sync::mpsc::Receiver`. Used to
//!   plug the sandbox into in-process producers (Kafka consumers, FIX
//!   parsers, FHIR Subscription handlers, etc.) without coupling the
//!   sandbox to a specific transport.
//!
//! Both implement [`crate::connector::Connector`] so they slot into the
//! existing `Sandbox::context(&faults).connector(...)` flow.
//!
//! ## Why these two?
//!
//! In every sector pilot we've seen, the customer starts with one of:
//!
//! 1. "Here's a CSV / JSONL of historical events — replay them through
//!    the sandbox so we can produce a backfilled audit trail."
//! 2. "We have a Kafka topic / NATS subject / WebSocket — plumb events
//!    through to the sandbox in real time."
//!
//! Customer-side adapters convert their transport into either a JSONL file
//! or an `mpsc::Sender`. These two connectors handle both cases without
//! us needing to depend on any specific Kafka / NATS / FIX library.

use crate::connector::{Connector, ConnectorConfig, ConnectorMetadata};
use crate::{SandboxError, SandboxResult};
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

// =============================================================================
// JsonlFileConnector — replay from a JSON-lines file.
// =============================================================================

/// Connector that replays events from a JSON-lines file.
///
/// `T` is the sector-specific event type that implements `Deserialize`.
/// Each line of the file is one `T` instance.
pub struct JsonlFileConnector<T: DeserializeOwned + Send + 'static> {
    metadata: ConnectorMetadata,
    config: ConnectorConfig,
    path: PathBuf,
    reader: Option<BufReader<File>>,
    consumed: u64,
    _marker: PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static> JsonlFileConnector<T> {
    /// New connector that reads from `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let display = path.display().to_string();
        Self {
            metadata: ConnectorMetadata {
                id: format!("jsonl_file:{display}"),
                label: format!("JSON-lines file at {display}"),
                protocol: "JSON-lines".into(),
                version: "1.0.0".into(),
            },
            config: ConnectorConfig {
                endpoint: display,
                auth_token: None,
                max_events: None,
                extension: serde_json::Map::new(),
            },
            path,
            reader: None,
            consumed: 0,
            _marker: PhantomData,
        }
    }

    /// Number of events drained so far.
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// `true` if the underlying file has been opened.
    pub fn is_open(&self) -> bool {
        self.reader.is_some()
    }
}

impl<T: DeserializeOwned + Send + 'static> Connector for JsonlFileConnector<T> {
    type Item = T;

    fn metadata(&self) -> ConnectorMetadata {
        self.metadata.clone()
    }

    fn open(&mut self) -> SandboxResult<()> {
        if self.reader.is_some() {
            return Ok(());
        }
        let f = File::open(&self.path).map_err(|e| SandboxError::Connector {
            connector: self.metadata.id.clone(),
            reason: format!("open {}: {}", self.path.display(), e),
        })?;
        self.reader = Some(BufReader::new(f));
        Ok(())
    }

    fn next(&mut self) -> SandboxResult<Option<Self::Item>> {
        if let Some(max) = self.config.max_events {
            if self.consumed as usize >= max {
                return Ok(None);
            }
        }
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => {
                return Err(SandboxError::Connector {
                    connector: self.metadata.id.clone(),
                    reason: "next() called before open()".into(),
                });
            }
        };
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| SandboxError::Connector {
                connector: self.metadata.id.clone(),
                reason: format!("read: {e}"),
            })?;
            if n == 0 {
                // EOF.
                return Ok(None);
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue; // Skip blank lines and comments.
            }
            let item: T = serde_json::from_str(trimmed).map_err(|e| SandboxError::Connector {
                connector: self.metadata.id.clone(),
                reason: format!("parse json: {e}"),
            })?;
            self.consumed += 1;
            return Ok(Some(item));
        }
    }

    fn close(&mut self) -> SandboxResult<()> {
        self.reader = None;
        Ok(())
    }
}

// =============================================================================
// ChannelConnector — receive from a std::sync::mpsc::Receiver.
// =============================================================================

/// Connector that pulls events from a `std::sync::mpsc::Receiver`.
///
/// Production deployments wire their Kafka / NATS / WebSocket consumer
/// into the corresponding `Sender` and let this connector pull from the
/// channel.
pub struct ChannelConnector<T: Send + 'static> {
    metadata: ConnectorMetadata,
    receiver: Option<Receiver<T>>,
    /// Receive timeout. `None` means non-blocking (`try_recv`).
    pub recv_timeout: Option<Duration>,
    consumed: u64,
}

impl<T: Send + 'static> ChannelConnector<T> {
    /// New connector wrapping `rx`.
    pub fn new(label: impl Into<String>, rx: Receiver<T>) -> Self {
        let label = label.into();
        Self {
            metadata: ConnectorMetadata {
                id: format!("mpsc:{label}"),
                label,
                protocol: "mpsc".into(),
                version: "1.0.0".into(),
            },
            receiver: Some(rx),
            recv_timeout: Some(Duration::from_millis(0)),
            consumed: 0,
        }
    }

    /// New connector with a timeout on `next()` calls.
    pub fn with_timeout(label: impl Into<String>, rx: Receiver<T>, t: Duration) -> Self {
        let mut c = Self::new(label, rx);
        c.recv_timeout = Some(t);
        c
    }

    /// Set a blocking receive (no timeout).
    pub fn blocking(mut self) -> Self {
        self.recv_timeout = None;
        self
    }

    /// Consumed event count.
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
}

impl<T: Send + 'static> Connector for ChannelConnector<T> {
    type Item = T;

    fn metadata(&self) -> ConnectorMetadata {
        self.metadata.clone()
    }

    fn open(&mut self) -> SandboxResult<()> {
        if self.receiver.is_none() {
            return Err(SandboxError::Connector {
                connector: self.metadata.id.clone(),
                reason: "channel already closed".into(),
            });
        }
        Ok(())
    }

    fn next(&mut self) -> SandboxResult<Option<Self::Item>> {
        let rx = match self.receiver.as_ref() {
            Some(r) => r,
            None => {
                return Err(SandboxError::Connector {
                    connector: self.metadata.id.clone(),
                    reason: "next() called after close()".into(),
                });
            }
        };
        let result = match self.recv_timeout {
            None => rx.recv().map(Some).unwrap_or(None),
            Some(d) if d.is_zero() => match rx.try_recv() {
                Ok(v) => Some(v),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
            },
            Some(d) => match rx.recv_timeout(d) {
                Ok(v) => Some(v),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => None,
            },
        };
        if result.is_some() {
            self.consumed += 1;
        }
        Ok(result)
    }

    fn close(&mut self) -> SandboxResult<()> {
        self.receiver = None;
        Ok(())
    }
}

// =============================================================================
// JsonlFileEmitter — auxiliary helper to write events to a JSONL file.
// =============================================================================

/// Helper that writes events to a JSON-lines file (matching the format
/// [`JsonlFileConnector`] reads). Used in tests and for golden-data
/// reproduction.
pub struct JsonlFileEmitter {
    path: PathBuf,
}

impl JsonlFileEmitter {
    /// New emitter that writes to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Append one event.
    pub fn emit<T: serde::Serialize>(&self, event: &T) -> SandboxResult<()> {
        use std::io::Write;
        let line = serde_json::to_string(event).map_err(|e| {
            SandboxError::Connector {
                connector: format!("jsonl_emitter:{}", self.path.display()),
                reason: format!("serialize: {e}"),
            }
        })?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SandboxError::Connector {
                connector: format!("jsonl_emitter:{}", self.path.display()),
                reason: format!("open: {e}"),
            })?;
        f.write_all(line.as_bytes()).map_err(|e| SandboxError::Connector {
            connector: format!("jsonl_emitter:{}", self.path.display()),
            reason: format!("write: {e}"),
        })?;
        f.write_all(b"\n").map_err(|e| SandboxError::Connector {
            connector: format!("jsonl_emitter:{}", self.path.display()),
            reason: format!("write nl: {e}"),
        })?;
        Ok(())
    }

    /// Append many events.
    pub fn emit_all<T: serde::Serialize>(&self, events: &[T]) -> SandboxResult<()> {
        for e in events {
            self.emit(e)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::sync::mpsc;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Event {
        id: String,
        amount: u64,
    }

    fn tmp(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aethelred-jsonl-{}-{}.jsonl",
            std::process::id(),
            suffix
        ))
    }

    fn write_lines(path: &std::path::Path, lines: &[&str]) {
        let mut content = String::new();
        for l in lines {
            content.push_str(l);
            content.push('\n');
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn jsonl_open_drains_in_order() {
        let p = tmp("order");
        write_lines(
            &p,
            &[
                r#"{"id":"a","amount":1}"#,
                r#"{"id":"b","amount":2}"#,
                r#"{"id":"c","amount":3}"#,
            ],
        );
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        let e1 = c.next().unwrap().unwrap();
        let e2 = c.next().unwrap().unwrap();
        let e3 = c.next().unwrap().unwrap();
        let e4 = c.next().unwrap();
        assert_eq!(e1.id, "a");
        assert_eq!(e2.id, "b");
        assert_eq!(e3.id, "c");
        assert!(e4.is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_skips_blank_and_comment_lines() {
        let p = tmp("skip");
        write_lines(
            &p,
            &[
                r#"{"id":"a","amount":1}"#,
                "",
                "# this is a comment",
                r#"{"id":"b","amount":2}"#,
            ],
        );
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        let e1 = c.next().unwrap().unwrap();
        let e2 = c.next().unwrap().unwrap();
        assert_eq!(e1.id, "a");
        assert_eq!(e2.id, "b");
        assert_eq!(c.consumed(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_next_before_open_errors() {
        let p = tmp("noopen");
        write_lines(&p, &[r#"{"id":"a","amount":1}"#]);
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        let r = c.next();
        assert!(r.is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_open_then_close_works() {
        let p = tmp("close");
        write_lines(&p, &[r#"{"id":"a","amount":1}"#]);
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        c.close().unwrap();
        assert!(!c.is_open());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_open_is_idempotent() {
        let p = tmp("idem");
        write_lines(&p, &[r#"{"id":"a","amount":1}"#]);
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        c.open().unwrap();
        assert!(c.is_open());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_invalid_line_returns_err() {
        let p = tmp("bad");
        write_lines(&p, &[r#"{"id":"a","amount":1}"#, "not valid json"]);
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        let _ = c.next().unwrap().unwrap();
        let r = c.next();
        assert!(r.is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_max_events_caps_drain() {
        let p = tmp("cap");
        write_lines(
            &p,
            &[
                r#"{"id":"a","amount":1}"#,
                r#"{"id":"b","amount":2}"#,
                r#"{"id":"c","amount":3}"#,
            ],
        );
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.config.max_events = Some(2);
        c.open().unwrap();
        assert!(c.next().unwrap().is_some());
        assert!(c.next().unwrap().is_some());
        assert!(c.next().unwrap().is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_metadata_includes_path() {
        let p = tmp("meta");
        let c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        let m = c.metadata();
        assert!(m.id.starts_with("jsonl_file:"));
        assert_eq!(m.protocol, "JSON-lines");
    }

    #[test]
    fn jsonl_emitter_round_trip() {
        let p = tmp("roundtrip");
        let _ = std::fs::remove_file(&p);
        let emitter = JsonlFileEmitter::new(&p);
        let events = vec![
            Event { id: "a".into(), amount: 1 },
            Event { id: "b".into(), amount: 2 },
        ];
        emitter.emit_all(&events).unwrap();
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        let e1 = c.next().unwrap().unwrap();
        let e2 = c.next().unwrap().unwrap();
        assert_eq!(e1, events[0]);
        assert_eq!(e2, events[1]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn channel_connector_drains_messages() {
        let (tx, rx) = mpsc::channel::<Event>();
        tx.send(Event { id: "a".into(), amount: 1 }).unwrap();
        tx.send(Event { id: "b".into(), amount: 2 }).unwrap();
        drop(tx);
        let mut c = ChannelConnector::new("test", rx).blocking();
        c.open().unwrap();
        let e1 = c.next().unwrap().unwrap();
        let e2 = c.next().unwrap().unwrap();
        let e3 = c.next().unwrap();
        assert_eq!(e1.id, "a");
        assert_eq!(e2.id, "b");
        assert!(e3.is_none());
        assert_eq!(c.consumed(), 2);
    }

    #[test]
    fn channel_try_recv_returns_none_when_empty() {
        let (_tx, rx) = mpsc::channel::<Event>();
        let mut c = ChannelConnector::new("test", rx);
        c.open().unwrap();
        assert!(c.next().unwrap().is_none());
    }

    #[test]
    fn channel_with_timeout_returns_none_after_timeout() {
        let (_tx, rx) = mpsc::channel::<Event>();
        let mut c = ChannelConnector::with_timeout("test", rx, Duration::from_millis(50));
        c.open().unwrap();
        let start = std::time::Instant::now();
        let r = c.next().unwrap();
        let elapsed = start.elapsed();
        assert!(r.is_none());
        assert!(elapsed >= Duration::from_millis(40));
    }

    #[test]
    fn channel_close_then_next_errors() {
        let (_tx, rx) = mpsc::channel::<Event>();
        let mut c = ChannelConnector::new("test", rx);
        c.open().unwrap();
        c.close().unwrap();
        let r = c.next();
        assert!(r.is_err());
    }

    #[test]
    fn channel_open_after_close_errors() {
        let (_tx, rx) = mpsc::channel::<Event>();
        let mut c = ChannelConnector::new("test", rx);
        c.open().unwrap();
        c.close().unwrap();
        let r = c.open();
        assert!(r.is_err());
    }

    #[test]
    fn channel_metadata_uses_label() {
        let (_tx, rx) = mpsc::channel::<Event>();
        let c = ChannelConnector::new("kafka:trades", rx);
        let m = c.metadata();
        assert!(m.id.contains("kafka:trades"));
        assert_eq!(m.protocol, "mpsc");
    }

    #[test]
    fn channel_disconnected_returns_none_not_err() {
        let (tx, rx) = mpsc::channel::<Event>();
        drop(tx);
        let mut c = ChannelConnector::new("test", rx).blocking();
        c.open().unwrap();
        assert!(c.next().unwrap().is_none());
    }

    #[test]
    fn jsonl_consumed_count_matches_drain() {
        let p = tmp("cc");
        write_lines(
            &p,
            &[
                r#"{"id":"a","amount":1}"#,
                r#"{"id":"b","amount":2}"#,
                r#"{"id":"c","amount":3}"#,
                r#"{"id":"d","amount":4}"#,
            ],
        );
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        while c.next().unwrap().is_some() {}
        assert_eq!(c.consumed(), 4);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_empty_file_returns_none() {
        let p = tmp("empty");
        std::fs::write(&p, "").unwrap();
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        c.open().unwrap();
        assert!(c.next().unwrap().is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn jsonl_missing_file_open_errors() {
        let p = tmp("missing");
        let _ = std::fs::remove_file(&p);
        let mut c: JsonlFileConnector<Event> = JsonlFileConnector::new(&p);
        assert!(c.open().is_err());
    }

    #[test]
    fn channel_consumed_is_zero_before_drain() {
        let (_tx, rx) = mpsc::channel::<Event>();
        let c = ChannelConnector::new("z", rx);
        assert_eq!(c.consumed(), 0);
    }

    #[test]
    fn many_messages_drain_correctly() {
        let (tx, rx) = mpsc::channel::<Event>();
        for i in 0..100 {
            tx.send(Event {
                id: format!("e-{i}"),
                amount: i,
            })
            .unwrap();
        }
        drop(tx);
        let mut c = ChannelConnector::new("many", rx).blocking();
        c.open().unwrap();
        let mut count = 0;
        while c.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 100);
    }
}
