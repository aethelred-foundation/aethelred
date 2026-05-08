//! Structured log aggregation with severity routing.
//!
//! In-process log collector for tools that don't ship to a central
//! observability backend. Records structured log entries with service +
//! severity + tags + correlation id, supports filtering, counts per
//! severity, and JSONL export.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// LogLevel
// =============================================================================

/// Per-entry severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Trace.
    Trace,
    /// Debug.
    Debug,
    /// Info.
    Info,
    /// Warn.
    Warn,
    /// Error.
    Error,
    /// Fatal.
    Fatal,
}

impl LogLevel {
    /// Numeric rank (lower = noisier).
    pub fn rank(self) -> u8 {
        match self {
            Self::Trace => 0,
            Self::Debug => 1,
            Self::Info => 2,
            Self::Warn => 3,
            Self::Error => 4,
            Self::Fatal => 5,
        }
    }
}

// =============================================================================
// LogEntry
// =============================================================================

/// One structured log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    /// Stable id.
    pub entry_id: Uuid,
    /// RFC 3339.
    pub at: String,
    /// Service.
    pub service: String,
    /// Level.
    pub level: LogLevel,
    /// Message.
    pub message: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Optional correlation id.
    pub correlation_id: Option<String>,
    /// Optional structured fields.
    pub fields: HashMap<String, String>,
}

// =============================================================================
// LogAggregator
// =============================================================================

#[derive(Default)]
struct State {
    entries: Vec<LogEntry>,
    /// Optional minimum level (entries below dropped).
    min_level: Option<LogLevel>,
    /// Buffer cap.
    max_entries: usize,
}

/// Aggregator.
pub struct LogAggregator {
    state: RwLock<State>,
}

impl Default for LogAggregator {
    fn default() -> Self {
        Self::with_capacity(10_000)
    }
}

impl std::fmt::Debug for LogAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogAggregator").field("entries", &self.len()).finish()
    }
}

impl LogAggregator {
    /// New with explicit capacity.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            state: RwLock::new(State {
                entries: Vec::new(),
                min_level: None,
                max_entries: max_entries.max(1),
            }),
        }
    }

    /// Set min level filter.
    pub fn set_min_level(&self, level: LogLevel) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("log aggregator poisoned".into()))?
            .min_level = Some(level);
        Ok(())
    }

    /// Record an entry.
    pub fn record(
        &self,
        service: impl Into<String>,
        level: LogLevel,
        message: impl Into<String>,
        tags: Vec<String>,
        correlation_id: Option<String>,
        fields: HashMap<String, String>,
    ) -> SandboxResult<Option<LogEntry>> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("log aggregator poisoned".into()))?;
        // Filter.
        if let Some(min) = g.min_level {
            if level.rank() < min.rank() {
                return Ok(None);
            }
        }
        let entry = LogEntry {
            entry_id: Uuid::now_v7(),
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            service: service.into(),
            level,
            message: message.into(),
            tags,
            correlation_id,
            fields,
        };
        g.entries.push(entry.clone());
        // Eviction (FIFO).
        while g.entries.len() > g.max_entries {
            g.entries.remove(0);
        }
        Ok(Some(entry))
    }

    /// All entries.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.state.read().map(|g| g.entries.clone()).unwrap_or_default()
    }

    /// Filter by level (≥).
    pub fn at_or_above(&self, level: LogLevel) -> Vec<LogEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.level.rank() >= level.rank())
            .collect()
    }

    /// Filter by service.
    pub fn for_service(&self, service: &str) -> Vec<LogEntry> {
        self.entries().into_iter().filter(|e| e.service == service).collect()
    }

    /// Filter by tag.
    pub fn with_tag(&self, tag: &str) -> Vec<LogEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Filter by correlation id.
    pub fn for_correlation(&self, id: &str) -> Vec<LogEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.correlation_id.as_deref() == Some(id))
            .collect()
    }

    /// Per-level counts.
    pub fn counts_by_level(&self) -> HashMap<LogLevel, u64> {
        let mut out: HashMap<LogLevel, u64> = HashMap::new();
        for e in self.entries() {
            *out.entry(e.level).or_insert(0) += 1;
        }
        out
    }

    /// Total count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.entries.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Export as JSONL.
    pub fn to_jsonl(&self) -> SandboxResult<String> {
        let mut out = String::new();
        for e in self.entries() {
            let line = serde_json::to_string(&e)
                .map_err(|err| SandboxError::Other(format!("log serialize: {err}")))?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Clear.
    pub fn clear(&self) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("log aggregator poisoned".into()))?
            .entries
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(agg: &LogAggregator, level: LogLevel, msg: &str) {
        agg.record("svc", level, msg, vec![], None, HashMap::new()).unwrap();
    }

    #[test]
    fn record_appends() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Info, "hello");
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn record_returns_entry() {
        let a = LogAggregator::default();
        let e = a
            .record("svc", LogLevel::Info, "x", vec![], None, HashMap::new())
            .unwrap()
            .unwrap();
        assert_eq!(e.message, "x");
    }

    #[test]
    fn min_level_filter_applied() {
        let a = LogAggregator::default();
        a.set_min_level(LogLevel::Warn).unwrap();
        rec(&a, LogLevel::Info, "skipped");
        rec(&a, LogLevel::Error, "kept");
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn capacity_eviction_fifo() {
        let a = LogAggregator::with_capacity(3);
        for i in 0..5 {
            rec(&a, LogLevel::Info, &format!("msg {i}"));
        }
        assert_eq!(a.len(), 3);
        let entries = a.entries();
        assert_eq!(entries[0].message, "msg 2");
    }

    #[test]
    fn level_ordering_correct() {
        assert!(LogLevel::Trace.rank() < LogLevel::Info.rank());
        assert!(LogLevel::Info.rank() < LogLevel::Error.rank());
    }

    #[test]
    fn at_or_above_filters() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Info, "i");
        rec(&a, LogLevel::Error, "e");
        rec(&a, LogLevel::Trace, "t");
        let warn_plus = a.at_or_above(LogLevel::Warn);
        assert_eq!(warn_plus.len(), 1);
    }

    #[test]
    fn for_service_filters() {
        let a = LogAggregator::default();
        a.record("svc-a", LogLevel::Info, "x", vec![], None, HashMap::new()).unwrap();
        a.record("svc-b", LogLevel::Info, "y", vec![], None, HashMap::new()).unwrap();
        assert_eq!(a.for_service("svc-a").len(), 1);
        assert_eq!(a.for_service("svc-b").len(), 1);
    }

    #[test]
    fn with_tag_filters() {
        let a = LogAggregator::default();
        a.record(
            "svc",
            LogLevel::Info,
            "x",
            vec!["fraud".into()],
            None,
            HashMap::new(),
        )
        .unwrap();
        a.record("svc", LogLevel::Info, "y", vec![], None, HashMap::new()).unwrap();
        assert_eq!(a.with_tag("fraud").len(), 1);
    }

    #[test]
    fn for_correlation_filters() {
        let a = LogAggregator::default();
        a.record(
            "svc",
            LogLevel::Info,
            "x",
            vec![],
            Some("req-1".into()),
            HashMap::new(),
        )
        .unwrap();
        a.record("svc", LogLevel::Info, "y", vec![], None, HashMap::new()).unwrap();
        assert_eq!(a.for_correlation("req-1").len(), 1);
    }

    #[test]
    fn counts_by_level() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Info, "x");
        rec(&a, LogLevel::Info, "y");
        rec(&a, LogLevel::Error, "z");
        let counts = a.counts_by_level();
        assert_eq!(counts[&LogLevel::Info], 2);
        assert_eq!(counts[&LogLevel::Error], 1);
    }

    #[test]
    fn jsonl_export() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Info, "x");
        rec(&a, LogLevel::Info, "y");
        let out = a.to_jsonl().unwrap();
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn clear_empties() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Info, "x");
        a.clear().unwrap();
        assert!(a.is_empty());
    }

    #[test]
    fn entry_serde() {
        let e = LogEntry {
            entry_id: Uuid::now_v7(),
            at: "t".into(),
            service: "svc".into(),
            level: LogLevel::Info,
            message: "m".into(),
            tags: vec!["x".into()],
            correlation_id: Some("c".into()),
            fields: HashMap::new(),
        };
        let j = serde_json::to_string(&e).unwrap();
        let p: LogEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn level_serde() {
        for l in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
            LogLevel::Fatal,
        ] {
            let j = serde_json::to_string(&l).unwrap();
            let p: LogLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, l);
        }
    }

    #[test]
    fn record_below_min_returns_none() {
        let a = LogAggregator::default();
        a.set_min_level(LogLevel::Error).unwrap();
        let r = a.record("svc", LogLevel::Info, "x", vec![], None, HashMap::new()).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn fields_recorded() {
        let a = LogAggregator::default();
        let mut f = HashMap::new();
        f.insert("user".into(), "alice".into());
        a.record("svc", LogLevel::Info, "x", vec![], None, f.clone()).unwrap();
        let entries = a.entries();
        assert_eq!(entries[0].fields.get("user").map(String::as_str), Some("alice"));
    }

    #[test]
    fn jsonl_empty_returns_empty() {
        let a = LogAggregator::default();
        assert!(a.to_jsonl().unwrap().is_empty());
    }

    #[test]
    fn many_entries_stay_within_cap() {
        let a = LogAggregator::with_capacity(100);
        for i in 0..1000 {
            rec(&a, LogLevel::Info, &format!("msg {i}"));
        }
        assert_eq!(a.len(), 100);
    }

    #[test]
    fn min_level_serde() {
        let j = serde_json::to_string(&LogLevel::Warn).unwrap();
        assert_eq!(j, "\"warn\"");
    }

    #[test]
    fn count_after_clear_zero() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Info, "x");
        a.clear().unwrap();
        assert!(a.counts_by_level().is_empty());
    }

    #[test]
    fn capacity_zero_treated_as_one() {
        let a = LogAggregator::with_capacity(0);
        rec(&a, LogLevel::Info, "x");
        rec(&a, LogLevel::Info, "y");
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn entries_preserve_insertion_order() {
        let a = LogAggregator::default();
        for i in 0..5 {
            rec(&a, LogLevel::Info, &format!("msg {i}"));
        }
        let entries = a.entries();
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.message, format!("msg {i}"));
        }
    }

    #[test]
    fn no_min_level_records_all() {
        let a = LogAggregator::default();
        rec(&a, LogLevel::Trace, "t");
        rec(&a, LogLevel::Fatal, "f");
        assert_eq!(a.len(), 2);
    }
}
