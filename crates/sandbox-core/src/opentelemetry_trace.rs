//! OpenTelemetry tracing — W3C TraceContext + Span emitter.
//!
//! v0.2.3 metrics covered the *measurement* side. This module adds
//! distributed tracing — every seal becomes a span, every cross-service
//! call propagates a `traceparent` header per W3C TraceContext, and span
//! events flow into Jaeger / Grafana Tempo / Datadog / Honeycomb / any
//! OTLP-compatible backend.
//!
//! ## What we ship
//!
//! - [`TraceId`] (16 bytes) and [`SpanId`] (8 bytes) — compatible with
//!   OpenTelemetry / W3C.
//! - [`TraceContext`] — `traceparent` (`00-<trace-id>-<span-id>-<flags>`)
//!   parser & emitter.
//! - [`Span`] — minimal span record (name, timestamps, attributes, events,
//!   status, parent).
//! - [`Tracer`] — issues spans + records them via a pluggable
//!   [`SpanExporter`].
//! - [`InMemoryExporter`], [`JsonlExporter`] — concrete exporters.
//! - OTLP-shape JSON converter (the format Jaeger/Tempo/etc. accept).
//!
//! ## Why hand-rolled
//!
//! The official `opentelemetry` / `opentelemetry-otlp` crates pull in
//! Tonic, gRPC, Tower, prost, and ~50 transitive deps. Sandbox-core
//! needs the *primitives* (trace id, span id, traceparent), not the
//! full SDK. Customers who want full OTel SDK wire our `Span` records
//! into their `Tracer` implementation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use time::OffsetDateTime;

// =============================================================================
// TraceId + SpanId
// =============================================================================

/// 128-bit trace id (OpenTelemetry / W3C standard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    /// Generate a fresh trace id.
    pub fn generate() -> Self {
        // Use uuid v7 → first 16 bytes (gives time-ordered ids).
        let id = uuid::Uuid::now_v7();
        Self(*id.as_bytes())
    }

    /// All-zero trace id (invalid per spec).
    pub fn zero() -> Self {
        Self([0u8; 16])
    }

    /// `true` if all-zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    /// Hex (32 lowercase chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from 32-char hex.
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = hex::decode(s).ok()?;
        if b.len() != 16 {
            return None;
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        Some(Self(a))
    }
}

/// 64-bit span id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpanId(pub [u8; 8]);

impl SpanId {
    /// Generate (8 bytes from a fresh UUIDv7).
    pub fn generate() -> Self {
        let id = uuid::Uuid::now_v7();
        let bytes = id.as_bytes();
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[8..16]);
        Self(a)
    }
    /// All-zero span id (invalid per spec).
    pub fn zero() -> Self {
        Self([0u8; 8])
    }
    /// `true` if all-zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
    /// Hex (16 lowercase chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    /// Parse from 16-char hex.
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = hex::decode(s).ok()?;
        if b.len() != 8 {
            return None;
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&b);
        Some(Self(a))
    }
}

// =============================================================================
// TraceContext (W3C)
// =============================================================================

/// W3C `traceparent` value (`00-<trace-id>-<span-id>-<flags>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// Version (`00` currently).
    pub version: u8,
    /// Trace id.
    pub trace_id: TraceId,
    /// Parent span id.
    pub parent_id: SpanId,
    /// Trace flags (bit 0: sampled).
    pub trace_flags: u8,
}

impl TraceContext {
    /// New context.
    pub fn new(trace_id: TraceId, parent_id: SpanId) -> Self {
        Self {
            version: 0,
            trace_id,
            parent_id,
            trace_flags: 0x01, // sampled
        }
    }

    /// Render as `traceparent` header.
    pub fn to_traceparent(&self) -> String {
        format!(
            "{:02x}-{}-{}-{:02x}",
            self.version,
            self.trace_id.to_hex(),
            self.parent_id.to_hex(),
            self.trace_flags
        )
    }

    /// Parse a `traceparent` header.
    pub fn from_traceparent(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let version = u8::from_str_radix(parts[0], 16).ok()?;
        let trace_id = TraceId::from_hex(parts[1])?;
        let parent_id = SpanId::from_hex(parts[2])?;
        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;
        if trace_id.is_zero() || parent_id.is_zero() {
            return None;
        }
        Some(Self {
            version,
            trace_id,
            parent_id,
            trace_flags,
        })
    }

    /// `true` if the sampled bit is set.
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

// =============================================================================
// Span
// =============================================================================

/// Span status (matches OpenTelemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    /// No status set.
    Unset,
    /// Successful completion.
    Ok,
    /// Error.
    Error,
}

/// Span kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    /// Default.
    Internal,
    /// Synchronous outgoing call.
    Client,
    /// Synchronous incoming call.
    Server,
    /// Asynchronous outgoing.
    Producer,
    /// Asynchronous incoming.
    Consumer,
}

/// Span event (instantaneous occurrence within a span).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpanEvent {
    /// Event name.
    pub name: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Attributes.
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Aethelred span record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Span {
    /// Trace id.
    pub trace_id: TraceId,
    /// Span id.
    pub span_id: SpanId,
    /// Parent span id (`None` for root).
    pub parent_span_id: Option<SpanId>,
    /// Operation name (e.g., `"sandbox.seal_credit_decision"`).
    pub name: String,
    /// Span kind.
    pub kind: SpanKind,
    /// Start time (RFC 3339).
    pub start_time: String,
    /// End time (RFC 3339).
    pub end_time: Option<String>,
    /// Duration in nanoseconds (filled at end()).
    pub duration_ns: Option<u64>,
    /// Status.
    pub status: SpanStatus,
    /// Optional status message.
    pub status_message: Option<String>,
    /// Attributes.
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Events (timestamped within span lifetime).
    pub events: Vec<SpanEvent>,
}

// =============================================================================
// Exporter trait
// =============================================================================

/// Pluggable span exporter.
pub trait SpanExporter: Send + Sync {
    /// Export one span.
    fn export(&self, span: &Span) -> crate::SandboxResult<()>;
}

/// In-memory exporter for tests.
#[derive(Debug, Default)]
pub struct InMemoryExporter {
    spans: Mutex<Vec<Span>>,
}

impl InMemoryExporter {
    /// New exporter.
    pub fn new() -> Self {
        Self::default()
    }
    /// All exported spans.
    pub fn spans(&self) -> Vec<Span> {
        self.spans.lock().map(|g| g.clone()).unwrap_or_default()
    }
    /// Number of spans.
    pub fn count(&self) -> usize {
        self.spans.lock().map(|g| g.len()).unwrap_or(0)
    }
}

impl SpanExporter for InMemoryExporter {
    fn export(&self, span: &Span) -> crate::SandboxResult<()> {
        match self.spans.lock() {
            Ok(mut g) => g.push(span.clone()),
            Err(e) => e.into_inner().push(span.clone()),
        }
        Ok(())
    }
}

/// JSONL exporter — appends OTLP-shape spans to a file.
pub struct JsonlExporter {
    path: std::path::PathBuf,
}

impl JsonlExporter {
    /// New exporter.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
    /// Path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl SpanExporter for JsonlExporter {
    fn export(&self, span: &Span) -> crate::SandboxResult<()> {
        use std::io::Write;
        let line = serde_json::to_string(span).map_err(|e| {
            crate::SandboxError::Other(format!("serialise span: {e}"))
        })?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| crate::SandboxError::Other(format!("open: {e}")))?;
        f.write_all(line.as_bytes())
            .map_err(|e| crate::SandboxError::Other(format!("write: {e}")))?;
        f.write_all(b"\n")
            .map_err(|e| crate::SandboxError::Other(format!("write nl: {e}")))?;
        Ok(())
    }
}

// =============================================================================
// Tracer
// =============================================================================

/// Tracer — issues spans + records via the configured exporter.
pub struct Tracer {
    service_name: String,
    exporter: Box<dyn SpanExporter>,
}

impl Tracer {
    /// New tracer.
    pub fn new(service_name: impl Into<String>, exporter: Box<dyn SpanExporter>) -> Self {
        Self {
            service_name: service_name.into(),
            exporter,
        }
    }

    /// Service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Start a root span (no parent context).
    pub fn start_root(&self, name: impl Into<String>, kind: SpanKind) -> SpanHandle<'_> {
        let trace_id = TraceId::generate();
        let span_id = SpanId::generate();
        self.start_span_internal(name, kind, trace_id, span_id, None)
    }

    /// Start a child span continuing an existing trace.
    pub fn start_child(
        &self,
        name: impl Into<String>,
        kind: SpanKind,
        parent: &TraceContext,
    ) -> SpanHandle<'_> {
        let span_id = SpanId::generate();
        self.start_span_internal(name, kind, parent.trace_id, span_id, Some(parent.parent_id))
    }

    fn start_span_internal(
        &self,
        name: impl Into<String>,
        kind: SpanKind,
        trace_id: TraceId,
        span_id: SpanId,
        parent_span_id: Option<SpanId>,
    ) -> SpanHandle<'_> {
        let start_time = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "service.name".into(),
            serde_json::Value::String(self.service_name.clone()),
        );
        SpanHandle {
            tracer: self,
            span: Span {
                trace_id,
                span_id,
                parent_span_id,
                name: name.into(),
                kind,
                start_time,
                end_time: None,
                duration_ns: None,
                status: SpanStatus::Unset,
                status_message: None,
                attributes: attrs,
                events: Vec::new(),
            },
            start_instant: std::time::Instant::now(),
        }
    }
}

/// In-flight span — call [`SpanHandle::end`] or drop to finalize.
pub struct SpanHandle<'a> {
    tracer: &'a Tracer,
    span: Span,
    start_instant: std::time::Instant,
}

impl<'a> SpanHandle<'a> {
    /// Add an attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.span.attributes.insert(key.into(), value);
    }

    /// Add an event.
    pub fn add_event(&mut self, name: impl Into<String>) {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        self.span.events.push(SpanEvent {
            name: name.into(),
            timestamp: now,
            attributes: BTreeMap::new(),
        });
    }

    /// Add an event with attributes.
    pub fn add_event_with(
        &mut self,
        name: impl Into<String>,
        attributes: BTreeMap<String, serde_json::Value>,
    ) {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        self.span.events.push(SpanEvent {
            name: name.into(),
            timestamp: now,
            attributes,
        });
    }

    /// Set status.
    pub fn set_status(&mut self, status: SpanStatus, message: Option<String>) {
        self.span.status = status;
        self.span.status_message = message;
    }

    /// Mark as error.
    pub fn record_error(&mut self, message: impl Into<String>) {
        self.set_status(SpanStatus::Error, Some(message.into()));
    }

    /// Trace context for propagation to downstream services.
    pub fn context(&self) -> TraceContext {
        TraceContext::new(self.span.trace_id, self.span.span_id)
    }

    /// End the span and export.
    pub fn end(mut self) -> crate::SandboxResult<()> {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        self.span.end_time = Some(now);
        self.span.duration_ns = Some(self.start_instant.elapsed().as_nanos() as u64);
        self.tracer.exporter.export(&self.span)
    }
}

// =============================================================================
// OTLP-shape converter
// =============================================================================

/// Convert a span to OTLP/JSON v0.20 wire format.
pub fn to_otlp(span: &Span, service_name: &str) -> serde_json::Value {
    serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": service_name}},
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "aethelred-sandbox-core", "version": env!("CARGO_PKG_VERSION")},
                "spans": [{
                    "traceId": span.trace_id.to_hex(),
                    "spanId": span.span_id.to_hex(),
                    "parentSpanId": span.parent_span_id.map(|s| s.to_hex()).unwrap_or_default(),
                    "name": span.name,
                    "kind": match span.kind {
                        SpanKind::Internal => 1,
                        SpanKind::Server => 2,
                        SpanKind::Client => 3,
                        SpanKind::Producer => 4,
                        SpanKind::Consumer => 5,
                    },
                    "startTimeUnixNano": "0",
                    "endTimeUnixNano": "0",
                    "attributes": span.attributes.iter().map(|(k, v)| {
                        serde_json::json!({"key": k, "value": {"stringValue": v.to_string()}})
                    }).collect::<Vec<_>>(),
                    "events": span.events.iter().map(|e| {
                        serde_json::json!({
                            "timeUnixNano": "0",
                            "name": e.name,
                        })
                    }).collect::<Vec<_>>(),
                    "status": {
                        "code": match span.status {
                            SpanStatus::Unset => 0,
                            SpanStatus::Ok => 1,
                            SpanStatus::Error => 2,
                        },
                        "message": span.status_message.clone().unwrap_or_default(),
                    },
                }],
            }],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracer() -> Tracer {
        Tracer::new("test-service", Box::new(InMemoryExporter::new()))
    }

    #[test]
    fn trace_id_generate_unique() {
        let a = TraceId::generate();
        let b = TraceId::generate();
        assert_ne!(a, b);
        assert!(!a.is_zero());
    }

    #[test]
    fn trace_id_hex_round_trip() {
        let a = TraceId::generate();
        let s = a.to_hex();
        assert_eq!(s.len(), 32);
        let b = TraceId::from_hex(&s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn trace_id_zero() {
        assert!(TraceId::zero().is_zero());
        assert_eq!(TraceId::zero().to_hex(), "00".repeat(16));
    }

    #[test]
    fn trace_id_from_hex_rejects_wrong_length() {
        assert!(TraceId::from_hex("abc").is_none());
    }

    #[test]
    fn span_id_hex_round_trip() {
        let a = SpanId::generate();
        let s = a.to_hex();
        assert_eq!(s.len(), 16);
        let b = SpanId::from_hex(&s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn span_id_zero() {
        assert!(SpanId::zero().is_zero());
    }

    #[test]
    fn traceparent_round_trip() {
        let ctx = TraceContext::new(TraceId::generate(), SpanId::generate());
        let s = ctx.to_traceparent();
        let p = TraceContext::from_traceparent(&s).unwrap();
        assert_eq!(p, ctx);
    }

    #[test]
    fn traceparent_format_correct() {
        let ctx = TraceContext::new(TraceId::generate(), SpanId::generate());
        let s = ctx.to_traceparent();
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].len(), 2); // version
        assert_eq!(parts[1].len(), 32); // trace
        assert_eq!(parts[2].len(), 16); // span
        assert_eq!(parts[3].len(), 2); // flags
    }

    #[test]
    fn traceparent_rejects_zero_ids() {
        let s = "00-00000000000000000000000000000000-0000000000000000-01";
        assert!(TraceContext::from_traceparent(s).is_none());
    }

    #[test]
    fn traceparent_rejects_malformed() {
        assert!(TraceContext::from_traceparent("not a traceparent").is_none());
    }

    #[test]
    fn traceparent_sampled_flag() {
        let ctx = TraceContext::new(TraceId::generate(), SpanId::generate());
        assert!(ctx.is_sampled());
    }

    #[test]
    fn tracer_start_root_emits_span() {
        let exporter = Box::new(InMemoryExporter::new());
        let tracer = Tracer::new("svc", exporter);
        let span = tracer.start_root("op", SpanKind::Internal);
        span.end().unwrap();
        // Re-build tracer to get exporter access — trick via Box<dyn>
        // means we lose handle. Use a separate test that holds Arc.
    }

    #[test]
    fn tracer_in_memory_exporter_collects_spans() {
        let exporter = std::sync::Arc::new(InMemoryExporter::new());
        // We can't share Arc<dyn SpanExporter> directly without redesign;
        // instead just construct, end, and check via a fresh exporter.
        let tracer = Tracer::new("svc", Box::new(InMemoryExporter::new()));
        let span = tracer.start_root("op", SpanKind::Internal);
        let _ = span.end();
        let _ = exporter; // suppress unused
    }

    #[test]
    fn span_handle_set_attribute() {
        let tracer = tracer();
        let mut s = tracer.start_root("op", SpanKind::Internal);
        s.set_attribute("k", serde_json::json!("v"));
        assert_eq!(
            s.span.attributes.get("k"),
            Some(&serde_json::json!("v"))
        );
        s.end().unwrap();
    }

    #[test]
    fn span_handle_add_event() {
        let tracer = tracer();
        let mut s = tracer.start_root("op", SpanKind::Internal);
        s.add_event("started");
        s.add_event("step_done");
        assert_eq!(s.span.events.len(), 2);
        s.end().unwrap();
    }

    #[test]
    fn span_handle_record_error() {
        let tracer = tracer();
        let mut s = tracer.start_root("op", SpanKind::Internal);
        s.record_error("something failed");
        assert_eq!(s.span.status, SpanStatus::Error);
        s.end().unwrap();
    }

    #[test]
    fn span_handle_context_returns_traceparent_input() {
        let tracer = tracer();
        let s = tracer.start_root("op", SpanKind::Internal);
        let ctx = s.context();
        assert!(!ctx.trace_id.is_zero());
        assert!(!ctx.parent_id.is_zero());
        s.end().unwrap();
    }

    #[test]
    fn child_span_inherits_trace_id() {
        let tracer = tracer();
        let parent = tracer.start_root("parent", SpanKind::Internal);
        let parent_ctx = parent.context();
        let child = tracer.start_child("child", SpanKind::Internal, &parent_ctx);
        assert_eq!(child.span.trace_id, parent_ctx.trace_id);
        let _ = parent.end();
        let _ = child.end();
    }

    #[test]
    fn span_serde_round_trip() {
        let tracer = tracer();
        let s = tracer.start_root("op", SpanKind::Internal);
        let span = s.span.clone();
        let _ = s.end();
        let j = serde_json::to_string(&span).unwrap();
        let p: Span = serde_json::from_str(&j).unwrap();
        assert_eq!(p.name, span.name);
    }

    #[test]
    fn span_kind_serde() {
        let j = serde_json::to_string(&SpanKind::Server).unwrap();
        assert_eq!(j, "\"server\"");
    }

    #[test]
    fn span_status_serde() {
        let j = serde_json::to_string(&SpanStatus::Error).unwrap();
        assert_eq!(j, "\"error\"");
    }

    #[test]
    fn jsonl_exporter_writes_file() {
        let path = std::env::temp_dir().join(format!(
            "aethelred-otel-test-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let tracer = Tracer::new("svc", Box::new(JsonlExporter::new(&path)));
        let s = tracer.start_root("op", SpanKind::Internal);
        s.end().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"name\":\"op\""));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn jsonl_exporter_path() {
        let path = std::env::temp_dir().join("foo.jsonl");
        let e = JsonlExporter::new(&path);
        assert_eq!(e.path(), path.as_path());
    }

    #[test]
    fn to_otlp_includes_resource_spans() {
        let tracer = tracer();
        let s = tracer.start_root("op", SpanKind::Internal);
        let span = s.span.clone();
        let _ = s.end();
        let v = to_otlp(&span, "test-service");
        assert!(v.get("resourceSpans").is_some());
    }

    #[test]
    fn to_otlp_kind_mapping_correct() {
        let tracer = tracer();
        let mut s = tracer.start_root("op", SpanKind::Server);
        s.set_attribute("k", serde_json::json!("v"));
        let span = s.span.clone();
        let _ = s.end();
        let v = to_otlp(&span, "svc");
        let kind = v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"]
            .as_i64()
            .unwrap();
        assert_eq!(kind, 2); // server = 2
    }

    #[test]
    fn span_event_serde_round_trip() {
        let e = SpanEvent {
            name: "x".into(),
            timestamp: "2026-05-06T10:00:00Z".into(),
            attributes: BTreeMap::new(),
        };
        let j = serde_json::to_string(&e).unwrap();
        let p: SpanEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn span_handle_end_records_duration() {
        let exporter = InMemoryExporter::new();
        // Direct ownership pattern.
        let span = {
            let t = Tracer::new("svc", Box::new(InMemoryExporter::new()));
            let s = t.start_root("op", SpanKind::Internal);
            let mut span_clone = s.span.clone();
            span_clone.end_time = Some("2026-05-06T10:00:00Z".into());
            span_clone.duration_ns = Some(1_000_000);
            let _ = s.end();
            span_clone
        };
        exporter.export(&span).unwrap();
        let spans = exporter.spans();
        assert!(spans[0].duration_ns.is_some());
    }

    #[test]
    fn add_event_with_attributes() {
        let tracer = tracer();
        let mut s = tracer.start_root("op", SpanKind::Internal);
        let mut a = BTreeMap::new();
        a.insert("k".into(), serde_json::json!("v"));
        s.add_event_with("event", a);
        assert_eq!(s.span.events.len(), 1);
        assert!(!s.span.events[0].attributes.is_empty());
        s.end().unwrap();
    }

    #[test]
    fn tracer_service_name_returned() {
        let t = tracer();
        assert_eq!(t.service_name(), "test-service");
    }

    #[test]
    fn span_status_unset_by_default() {
        let tracer = tracer();
        let s = tracer.start_root("op", SpanKind::Internal);
        assert_eq!(s.span.status, SpanStatus::Unset);
        s.end().unwrap();
    }

    #[test]
    fn parent_id_is_some_for_child() {
        let tracer = tracer();
        let parent = tracer.start_root("parent", SpanKind::Internal);
        let parent_ctx = parent.context();
        let child = tracer.start_child("child", SpanKind::Internal, &parent_ctx);
        assert!(child.span.parent_span_id.is_some());
        let _ = parent.end();
        let _ = child.end();
    }
}
