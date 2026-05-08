//! Streaming connectors with reconnect, backpressure, and DLQ.
//!
//! [`crate::Connector`] handles pull-shaped data sources (FHIR, OPC-UA,
//! Kafka, FIX). For *streaming* sources (long-lived subscriptions, message
//! queues) the operator needs:
//!
//! - **Backpressure** — buffer, but stop pulling when downstream is slow.
//! - **Reconnect** — exponential backoff with jitter when the upstream
//!   disconnects.
//! - **At-least-once** — checkpoint cursor so a reconnect resumes from the
//!   last acknowledged position.
//! - **Dead-letter** — events that fail processing N times go to a DLQ.
//!
//! This module models the *control plane* for those streams; the actual
//! transport (HTTP/gRPC/AMQP/Kafka) is delegated to [`StreamSource`]
//! implementations.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

// =============================================================================
// StreamCursor
// =============================================================================

/// Opaque cursor an upstream uses to resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StreamCursor(pub String);

impl StreamCursor {
    /// New cursor.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// Empty cursor (start from beginning).
    pub fn empty() -> Self {
        Self(String::new())
    }
    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// StreamMessage
// =============================================================================

/// One message off the stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamMessage {
    /// Per-message id (for DLQ/audit).
    pub message_id: Uuid,
    /// Cursor *after* this message (so we can resume past it).
    pub cursor_after: StreamCursor,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// Optional source-supplied key for partitioning / dedupe.
    pub key: Option<String>,
}

// =============================================================================
// StreamSource
// =============================================================================

/// Pluggable source.
pub trait StreamSource: Send + Sync {
    /// Source name.
    fn source_name(&self) -> &str;
    /// Pull up to `max` messages starting at `cursor`. Implementations may
    /// return fewer if the upstream has none available.
    fn pull(&self, cursor: &StreamCursor, max: usize) -> SandboxResult<Vec<StreamMessage>>;
    /// Acknowledge the cursor up to and including `cursor` (best-effort).
    fn ack(&self, cursor: &StreamCursor) -> SandboxResult<()>;
}

// =============================================================================
// InMemorySource (test)
// =============================================================================

/// In-memory source for tests. Pre-load messages, optionally inject errors.
pub struct InMemorySource {
    state: Mutex<InMemSourceState>,
}

impl Default for InMemorySource {
    fn default() -> Self {
        Self {
            state: Mutex::new(InMemSourceState {
                messages: Vec::new(),
                pull_errors: VecDeque::new(),
                last_ack: StreamCursor::empty(),
            }),
        }
    }
}

struct InMemSourceState {
    /// All messages available.
    messages: Vec<StreamMessage>,
    /// Per-call errors to inject (in order).
    pull_errors: VecDeque<String>,
    /// Latest acked cursor.
    last_ack: StreamCursor,
}

impl std::fmt::Debug for InMemorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySource").finish()
    }
}

impl InMemorySource {
    /// New empty source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a message onto the source. Cursor is "msg-{idx}".
    pub fn push(&self, payload: Vec<u8>) -> StreamCursor {
        let mut g = self.state.lock().unwrap();
        let idx = g.messages.len();
        let cursor_after = StreamCursor::new(format!("msg-{}", idx + 1));
        g.messages.push(StreamMessage {
            message_id: Uuid::now_v7(),
            cursor_after: cursor_after.clone(),
            payload,
            key: None,
        });
        cursor_after
    }

    /// Inject an error for the next pull call.
    pub fn inject_error(&self, msg: impl Into<String>) {
        if let Ok(mut g) = self.state.lock() {
            g.pull_errors.push_back(msg.into());
        }
    }

    /// Last acked cursor.
    pub fn last_ack(&self) -> StreamCursor {
        self.state.lock().map(|g| g.last_ack.clone()).unwrap_or_else(|_| StreamCursor::empty())
    }
}

impl StreamSource for InMemorySource {
    fn source_name(&self) -> &str {
        "in-memory"
    }
    fn pull(&self, cursor: &StreamCursor, max: usize) -> SandboxResult<Vec<StreamMessage>> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("source poisoned".into()))?;
        if let Some(err) = g.pull_errors.pop_front() {
            return Err(SandboxError::Other(err));
        }
        let start = if cursor.0.is_empty() {
            0
        } else {
            // cursor format "msg-{N}" — start = N.
            cursor
                .0
                .strip_prefix("msg-")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0)
        };
        let end = (start + max).min(g.messages.len());
        Ok(g.messages[start..end].to_vec())
    }
    fn ack(&self, cursor: &StreamCursor) -> SandboxResult<()> {
        self.state
            .lock()
            .map_err(|_| SandboxError::Other("source poisoned".into()))?
            .last_ack = cursor.clone();
        Ok(())
    }
}

// =============================================================================
// ReconnectPolicy
// =============================================================================

/// Backoff parameters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ReconnectPolicy {
    /// Base delay.
    pub base_seconds: f64,
    /// Multiplier.
    pub multiplier: f64,
    /// Cap.
    pub cap_seconds: f64,
    /// Max consecutive errors before giving up (None = infinite).
    pub max_consecutive_errors: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            base_seconds: 0.5,
            multiplier: 2.0,
            cap_seconds: 60.0,
            max_consecutive_errors: Some(20),
        }
    }
}

impl ReconnectPolicy {
    /// Compute delay for the Nth consecutive error (1-indexed).
    pub fn delay_for(&self, error_count: u32) -> f64 {
        let raw = self.base_seconds * self.multiplier.powi(error_count as i32 - 1);
        raw.min(self.cap_seconds).max(0.0)
    }
}

// =============================================================================
// StreamWorker
// =============================================================================

/// Per-pull statistics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullStats {
    /// Successful messages pulled.
    pub messages_pulled: u32,
    /// Errors hit on this pull.
    pub errors: u32,
    /// `true` if backpressure was applied (buffer near full).
    pub backpressure: bool,
}

#[derive(Debug)]
struct WorkerState {
    cursor: StreamCursor,
    consecutive_errors: u32,
    next_pull_at: Instant,
    buffer: VecDeque<StreamMessage>,
    dlq: Vec<DeadLetterMessage>,
    /// Total messages ever ingested (for metrics).
    total_pulled: u64,
}

/// Dead-lettered message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadLetterMessage {
    /// Original message.
    pub message: StreamMessage,
    /// Reason it was dead-lettered.
    pub reason: String,
    /// Attempt count when it was DLQ'd.
    pub attempts: u32,
}

/// Streaming worker that pulls from a source, buffers with backpressure,
/// and supports reconnect via [`ReconnectPolicy`].
pub struct StreamWorker<'a> {
    source: &'a dyn StreamSource,
    policy: ReconnectPolicy,
    /// Maximum buffered messages before backpressure kicks in.
    buffer_capacity: usize,
    state: Mutex<WorkerState>,
}

impl<'a> std::fmt::Debug for StreamWorker<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamWorker")
            .field("source", &self.source.source_name())
            .field("policy", &self.policy)
            .finish()
    }
}

impl<'a> StreamWorker<'a> {
    /// New worker.
    pub fn new(
        source: &'a dyn StreamSource,
        policy: ReconnectPolicy,
        buffer_capacity: usize,
    ) -> Self {
        Self {
            source,
            policy,
            buffer_capacity,
            state: Mutex::new(WorkerState {
                cursor: StreamCursor::empty(),
                consecutive_errors: 0,
                next_pull_at: Instant::now(),
                buffer: VecDeque::new(),
                dlq: Vec::new(),
                total_pulled: 0,
            }),
        }
    }

    /// Pull once. Honors backoff (returns no-op if before `next_pull_at`).
    pub fn pull_once(&self, max: usize) -> SandboxResult<PullStats> {
        self.pull_once_at(max, Instant::now())
    }

    /// Pull at a specific instant (for testing).
    pub fn pull_once_at(&self, max: usize, now: Instant) -> SandboxResult<PullStats> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("worker poisoned".into()))?;
        if now < g.next_pull_at {
            return Ok(PullStats::default());
        }
        // Backpressure.
        if g.buffer.len() >= self.buffer_capacity {
            return Ok(PullStats {
                backpressure: true,
                ..Default::default()
            });
        }
        let cursor = g.cursor.clone();
        drop(g);

        let result = self.source.pull(&cursor, max);
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("worker poisoned".into()))?;
        match result {
            Ok(msgs) => {
                g.consecutive_errors = 0;
                let n = msgs.len() as u32;
                if let Some(last) = msgs.last() {
                    g.cursor = last.cursor_after.clone();
                }
                for m in msgs {
                    g.buffer.push_back(m);
                }
                g.total_pulled += n as u64;
                Ok(PullStats {
                    messages_pulled: n,
                    errors: 0,
                    backpressure: false,
                })
            }
            Err(e) => {
                g.consecutive_errors += 1;
                if let Some(cap) = self.policy.max_consecutive_errors {
                    if g.consecutive_errors > cap {
                        // Stay backed off, but propagate as a worker-level error.
                        return Err(SandboxError::Other(format!(
                            "stream worker exceeded max errors ({}): {}",
                            cap, e
                        )));
                    }
                }
                let delay = self.policy.delay_for(g.consecutive_errors);
                g.next_pull_at = now + Duration::from_secs_f64(delay);
                Ok(PullStats {
                    messages_pulled: 0,
                    errors: 1,
                    backpressure: false,
                })
            }
        }
    }

    /// Pop one message from the buffer if any.
    pub fn next_message(&self) -> Option<StreamMessage> {
        self.state.lock().ok()?.buffer.pop_front()
    }

    /// Acknowledge the current cursor with the source.
    pub fn ack_current(&self) -> SandboxResult<()> {
        let cursor = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("worker poisoned".into()))?
            .cursor
            .clone();
        self.source.ack(&cursor)
    }

    /// Dead-letter a message after max attempts.
    pub fn dead_letter(&self, message: StreamMessage, reason: impl Into<String>, attempts: u32) {
        if let Ok(mut g) = self.state.lock() {
            g.dlq.push(DeadLetterMessage {
                message,
                reason: reason.into(),
                attempts,
            });
        }
    }

    /// Snapshot the DLQ.
    pub fn dlq(&self) -> Vec<DeadLetterMessage> {
        self.state.lock().map(|g| g.dlq.clone()).unwrap_or_default()
    }

    /// DLQ length.
    pub fn dlq_len(&self) -> usize {
        self.state.lock().map(|g| g.dlq.len()).unwrap_or(0)
    }

    /// Buffer length.
    pub fn buffer_len(&self) -> usize {
        self.state.lock().map(|g| g.buffer.len()).unwrap_or(0)
    }

    /// Total ever pulled.
    pub fn total_pulled(&self) -> u64 {
        self.state.lock().map(|g| g.total_pulled).unwrap_or(0)
    }

    /// Consecutive-error counter (reset on success).
    pub fn consecutive_errors(&self) -> u32 {
        self.state.lock().map(|g| g.consecutive_errors).unwrap_or(0)
    }

    /// Current cursor.
    pub fn cursor(&self) -> StreamCursor {
        self.state
            .lock()
            .map(|g| g.cursor.clone())
            .unwrap_or_else(|_| StreamCursor::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_policy() -> ReconnectPolicy {
        ReconnectPolicy {
            base_seconds: 0.001,
            multiplier: 2.0,
            cap_seconds: 1.0,
            max_consecutive_errors: Some(5),
        }
    }

    #[test]
    fn pull_once_with_no_messages() {
        let s = InMemorySource::new();
        let w = StreamWorker::new(&s, small_policy(), 100);
        let st = w.pull_once(10).unwrap();
        assert_eq!(st.messages_pulled, 0);
    }

    #[test]
    fn pull_once_returns_messages() {
        let s = InMemorySource::new();
        s.push(b"a".to_vec());
        s.push(b"b".to_vec());
        let w = StreamWorker::new(&s, small_policy(), 100);
        let st = w.pull_once(10).unwrap();
        assert_eq!(st.messages_pulled, 2);
        assert_eq!(w.buffer_len(), 2);
    }

    #[test]
    fn cursor_advances_with_pulls() {
        let s = InMemorySource::new();
        s.push(b"a".to_vec());
        s.push(b"b".to_vec());
        let w = StreamWorker::new(&s, small_policy(), 100);
        w.pull_once(10).unwrap();
        // Cursor should now be msg-2.
        assert_eq!(w.cursor().as_str(), "msg-2");
    }

    #[test]
    fn next_message_pops_from_buffer() {
        let s = InMemorySource::new();
        s.push(b"a".to_vec());
        let w = StreamWorker::new(&s, small_policy(), 100);
        w.pull_once(10).unwrap();
        let m = w.next_message().unwrap();
        assert_eq!(m.payload, b"a");
        assert!(w.next_message().is_none());
    }

    #[test]
    fn injected_error_increments_counter() {
        let s = InMemorySource::new();
        s.inject_error("connection refused");
        let w = StreamWorker::new(&s, small_policy(), 100);
        let st = w.pull_once(10).unwrap();
        assert_eq!(st.errors, 1);
        assert_eq!(w.consecutive_errors(), 1);
    }

    #[test]
    fn success_resets_consecutive_errors() {
        let s = InMemorySource::new();
        s.inject_error("err");
        s.push(b"a".to_vec());
        let w = StreamWorker::new(&s, small_policy(), 100);
        let now = Instant::now();
        w.pull_once_at(10, now).unwrap(); // error
        // Sleep past backoff.
        let later = now + Duration::from_secs(5);
        w.pull_once_at(10, later).unwrap(); // success
        assert_eq!(w.consecutive_errors(), 0);
    }

    #[test]
    fn max_errors_propagates_error() {
        let s = InMemorySource::new();
        for _ in 0..10 {
            s.inject_error("e");
        }
        let w = StreamWorker::new(
            &s,
            ReconnectPolicy {
                base_seconds: 0.0,
                multiplier: 1.0,
                cap_seconds: 0.0,
                max_consecutive_errors: Some(3),
            },
            100,
        );
        // First 3 pulls swallow errors silently.
        for _ in 0..3 {
            w.pull_once(10).unwrap();
        }
        // 4th pull exceeds cap → error.
        assert!(w.pull_once(10).is_err());
    }

    #[test]
    fn backpressure_when_buffer_full() {
        let s = InMemorySource::new();
        for _ in 0..5 {
            s.push(b"x".to_vec());
        }
        let w = StreamWorker::new(&s, small_policy(), 2); // cap = 2
        w.pull_once(10).unwrap(); // pulls 5, buffer = 5
        let st = w.pull_once(10).unwrap();
        assert!(st.backpressure);
    }

    #[test]
    fn ack_reaches_source() {
        let s = InMemorySource::new();
        s.push(b"a".to_vec());
        let w = StreamWorker::new(&s, small_policy(), 100);
        w.pull_once(10).unwrap();
        w.ack_current().unwrap();
        assert_eq!(s.last_ack().as_str(), "msg-1");
    }

    #[test]
    fn dead_letter_pushes_to_dlq() {
        let s = InMemorySource::new();
        let w = StreamWorker::new(&s, small_policy(), 100);
        let m = StreamMessage {
            message_id: Uuid::now_v7(),
            cursor_after: StreamCursor::new("c"),
            payload: b"x".to_vec(),
            key: None,
        };
        w.dead_letter(m, "bad payload", 3);
        assert_eq!(w.dlq_len(), 1);
        assert_eq!(w.dlq()[0].reason, "bad payload");
    }

    #[test]
    fn reconnect_policy_delays_grow() {
        let p = ReconnectPolicy::default();
        assert!(p.delay_for(1) < p.delay_for(2));
        assert!(p.delay_for(2) < p.delay_for(3));
    }

    #[test]
    fn reconnect_policy_caps() {
        let p = ReconnectPolicy {
            base_seconds: 1.0,
            multiplier: 2.0,
            cap_seconds: 5.0,
            max_consecutive_errors: None,
        };
        assert_eq!(p.delay_for(20), 5.0);
    }

    #[test]
    fn pull_obeys_next_pull_at_backoff() {
        let s = InMemorySource::new();
        s.inject_error("e");
        let p = ReconnectPolicy {
            base_seconds: 60.0,
            multiplier: 2.0,
            cap_seconds: 60.0,
            max_consecutive_errors: Some(10),
        };
        let w = StreamWorker::new(&s, p, 100);
        let now = Instant::now();
        w.pull_once_at(10, now).unwrap();
        // Immediately call again — should be a no-op (still backing off).
        let st = w.pull_once_at(10, now + Duration::from_millis(1)).unwrap();
        assert_eq!(st.messages_pulled, 0);
        assert_eq!(st.errors, 0);
    }

    #[test]
    fn total_pulled_accumulates() {
        let s = InMemorySource::new();
        for _ in 0..3 {
            s.push(b"x".to_vec());
        }
        let w = StreamWorker::new(&s, small_policy(), 100);
        w.pull_once(10).unwrap();
        assert_eq!(w.total_pulled(), 3);
    }

    #[test]
    fn cursor_serde_transparent() {
        let c = StreamCursor::new("x");
        assert_eq!(serde_json::to_string(&c).unwrap(), "\"x\"");
    }

    #[test]
    fn stream_message_serde() {
        let m = StreamMessage {
            message_id: Uuid::now_v7(),
            cursor_after: StreamCursor::new("c"),
            payload: vec![1, 2, 3],
            key: Some("k".into()),
        };
        let j = serde_json::to_string(&m).unwrap();
        let p: StreamMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn dead_letter_serde() {
        let dl = DeadLetterMessage {
            message: StreamMessage {
                message_id: Uuid::now_v7(),
                cursor_after: StreamCursor::new("c"),
                payload: vec![],
                key: None,
            },
            reason: "x".into(),
            attempts: 5,
        };
        let j = serde_json::to_string(&dl).unwrap();
        let p: DeadLetterMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(p, dl);
    }

    #[test]
    fn pull_stats_serde() {
        let s = PullStats {
            messages_pulled: 1,
            errors: 0,
            backpressure: false,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: PullStats = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn reconnect_policy_serde() {
        let p = ReconnectPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        let q: ReconnectPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn empty_cursor_starts_at_beginning() {
        let s = InMemorySource::new();
        s.push(b"a".to_vec());
        let w = StreamWorker::new(&s, small_policy(), 100);
        assert_eq!(w.cursor(), StreamCursor::empty());
        w.pull_once(10).unwrap();
        assert_ne!(w.cursor(), StreamCursor::empty());
    }

    #[test]
    fn many_pulls_drain_source() {
        let s = InMemorySource::new();
        for _ in 0..50 {
            s.push(b"x".to_vec());
        }
        let w = StreamWorker::new(&s, small_policy(), 100);
        w.pull_once(50).unwrap();
        assert_eq!(w.buffer_len(), 50);
    }

    #[test]
    fn source_name_in_memory() {
        let s = InMemorySource::new();
        assert_eq!(s.source_name(), "in-memory");
    }
}
