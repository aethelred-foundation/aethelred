//! Request-level trace correlation across services.
//!
//! Complements the span-level [`crate::opentelemetry_trace`] module by
//! providing a higher-level *request* abstraction: a request enters the
//! system at one service, traverses several others, and exits with a
//! final outcome. The [`RequestTrace`] is the rolled-up audit-friendly
//! record of that journey.
//!
//! ## Why both
//!
//! - OpenTelemetry spans answer "where did time go in this request?"
//! - [`RequestTrace`] answers "what services touched this request, in
//!   what order, and what was the outcome?"
//!
//! The two compose: a [`RequestTrace`] can carry a list of OTel
//! `trace_id`s for deep-link drill-down.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// RequestId
// =============================================================================

/// Stable request id (often W3C `traceparent` value, may be customer-supplied).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub String);

impl RequestId {
    /// New id.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// Random id (UUID).
    pub fn random() -> Self {
        Self(Uuid::now_v7().to_string())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// ServiceHop
// =============================================================================

/// One service touched by a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceHop {
    /// Sequence within the request (1-indexed).
    pub seq: u32,
    /// Service name.
    pub service: String,
    /// Operation (e.g., `"seal_credit_decision"`).
    pub operation: String,
    /// Started-at RFC 3339.
    pub started_at: String,
    /// Ended-at RFC 3339.
    pub ended_at: String,
    /// Duration in microseconds.
    pub duration_micros: u64,
    /// Outcome status.
    pub status: HopStatus,
    /// Optional error message if failed.
    pub error: Option<String>,
    /// Optional OTel trace id pointing to the span set for this hop.
    pub otel_trace_id: Option<String>,
}

/// Hop result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopStatus {
    /// Successful.
    Ok,
    /// Failed.
    Error,
    /// In flight.
    Pending,
}

// =============================================================================
// RequestTrace
// =============================================================================

/// Aggregate trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestTrace {
    /// Stable id.
    pub request_id: RequestId,
    /// Tenant.
    pub tenant_id: String,
    /// Hops in chronological order.
    pub hops: Vec<ServiceHop>,
    /// Total request status (Ok if all hops Ok, Error if any failed,
    /// Pending if any pending).
    pub status: HopStatus,
    /// Started-at (first hop).
    pub started_at: String,
    /// Ended-at (latest non-pending hop).
    pub ended_at: Option<String>,
    /// Total wall-clock micros from first start to last end.
    pub total_duration_micros: u64,
}

impl RequestTrace {
    /// Total hop count.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Number of failed hops.
    pub fn error_count(&self) -> usize {
        self.hops.iter().filter(|h| h.status == HopStatus::Error).count()
    }

    /// `true` if any hop errored.
    pub fn has_error(&self) -> bool {
        self.error_count() > 0
    }
}

// =============================================================================
// RequestTracer
// =============================================================================

#[derive(Default)]
struct State {
    traces: HashMap<RequestId, RequestTrace>,
}

/// Multi-request tracer.
pub struct RequestTracer {
    state: RwLock<State>,
}

impl Default for RequestTracer {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for RequestTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestTracer")
            .field("active", &self.len())
            .finish()
    }
}

impl RequestTracer {
    /// New empty tracer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin a new request.
    pub fn begin(
        &self,
        request_id: RequestId,
        tenant: impl Into<String>,
    ) -> SandboxResult<()> {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let trace = RequestTrace {
            request_id: request_id.clone(),
            tenant_id: tenant.into(),
            hops: Vec::new(),
            status: HopStatus::Pending,
            started_at: now,
            ended_at: None,
            total_duration_micros: 0,
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("tracer poisoned".into()))?;
        if g.traces.contains_key(&request_id) {
            return Err(SandboxError::Other(format!(
                "request {} already started",
                request_id.as_str()
            )));
        }
        g.traces.insert(request_id, trace);
        Ok(())
    }

    /// Record a completed hop.
    pub fn record_hop(
        &self,
        request_id: &RequestId,
        service: impl Into<String>,
        operation: impl Into<String>,
        started_at: OffsetDateTime,
        ended_at: OffsetDateTime,
        status: HopStatus,
        error: Option<String>,
        otel_trace_id: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("tracer poisoned".into()))?;
        let t = g
            .traces
            .get_mut(request_id)
            .ok_or_else(|| {
                SandboxError::Other(format!(
                    "request {} not found",
                    request_id.as_str()
                ))
            })?;
        let seq = (t.hops.len() as u32) + 1;
        let micros = ended_at.unix_timestamp_nanos().saturating_sub(started_at.unix_timestamp_nanos()) / 1_000;
        let micros = micros.max(0) as u64;
        let started = started_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let ended = ended_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        t.hops.push(ServiceHop {
            seq,
            service: service.into(),
            operation: operation.into(),
            started_at: started,
            ended_at: ended.clone(),
            duration_micros: micros,
            status,
            error,
            otel_trace_id,
        });
        // Update aggregate status & timing.
        if t.hops.iter().any(|h| h.status == HopStatus::Error) {
            t.status = HopStatus::Error;
        } else if t.hops.iter().all(|h| h.status == HopStatus::Ok) {
            t.status = HopStatus::Ok;
        } else {
            t.status = HopStatus::Pending;
        }
        t.ended_at = Some(ended);
        // total_duration is from start of first hop to end of last hop.
        if let (Some(first), Some(last)) = (t.hops.first(), t.hops.last()) {
            let f = OffsetDateTime::parse(
                &first.started_at,
                &time::format_description::well_known::Rfc3339,
            )
            .ok();
            let l = OffsetDateTime::parse(
                &last.ended_at,
                &time::format_description::well_known::Rfc3339,
            )
            .ok();
            if let (Some(f), Some(l)) = (f, l) {
                let micros = (l.unix_timestamp_nanos() - f.unix_timestamp_nanos()) / 1_000;
                t.total_duration_micros = micros.max(0) as u64;
            }
        }
        Ok(())
    }

    /// Look up a trace.
    pub fn get(&self, request_id: &RequestId) -> Option<RequestTrace> {
        self.state.read().ok()?.traces.get(request_id).cloned()
    }

    /// All active traces.
    pub fn all(&self) -> Vec<RequestTrace> {
        self.state
            .read()
            .map(|g| g.traces.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.traces.len()).unwrap_or(0)
    }

    /// `true` if no traces.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Filter: traces with at least one error.
    pub fn errored_traces(&self) -> Vec<RequestTrace> {
        self.all().into_iter().filter(|t| t.has_error()).collect()
    }

    /// Filter: traces by tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<RequestTrace> {
        self.all()
            .into_iter()
            .filter(|t| t.tenant_id == tenant)
            .collect()
    }

    /// Drop a trace from the active set (typically after persisting).
    pub fn drop_trace(&self, request_id: &RequestId) -> SandboxResult<bool> {
        Ok(self
            .state
            .write()
            .map_err(|_| SandboxError::Other("tracer poisoned".into()))?
            .traces
            .remove(request_id)
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn begin_creates_trace() {
        let t = RequestTracer::new();
        t.begin(RequestId::new("r1"), "FAB").unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn duplicate_begin_errors() {
        let t = RequestTracer::new();
        t.begin(RequestId::new("r1"), "FAB").unwrap();
        assert!(t.begin(RequestId::new("r1"), "FAB").is_err());
    }

    #[test]
    fn record_hop_appends() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        let e = s + Duration::milliseconds(100);
        t.record_hop(&id, "svc-a", "op-1", s, e, HopStatus::Ok, None, None)
            .unwrap();
        let trace = t.get(&id).unwrap();
        assert_eq!(trace.hops.len(), 1);
        assert_eq!(trace.hops[0].service, "svc-a");
        assert_eq!(trace.hops[0].seq, 1);
    }

    #[test]
    fn record_hop_unknown_errors() {
        let t = RequestTracer::new();
        let s = now();
        assert!(t
            .record_hop(
                &RequestId::new("ghost"),
                "svc",
                "op",
                s,
                s,
                HopStatus::Ok,
                None,
                None,
            )
            .is_err());
    }

    #[test]
    fn all_ok_status_aggregates_ok() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        let e = s + Duration::milliseconds(50);
        t.record_hop(&id, "a", "x", s, e, HopStatus::Ok, None, None).unwrap();
        t.record_hop(&id, "b", "y", e, e + Duration::milliseconds(10), HopStatus::Ok, None, None).unwrap();
        assert_eq!(t.get(&id).unwrap().status, HopStatus::Ok);
    }

    #[test]
    fn any_error_makes_status_error() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        t.record_hop(&id, "a", "x", s, s, HopStatus::Ok, None, None).unwrap();
        t.record_hop(
            &id,
            "b",
            "y",
            s,
            s,
            HopStatus::Error,
            Some("boom".into()),
            None,
        )
        .unwrap();
        assert_eq!(t.get(&id).unwrap().status, HopStatus::Error);
    }

    #[test]
    fn pending_hop_keeps_request_pending() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        t.record_hop(&id, "a", "x", s, s, HopStatus::Ok, None, None).unwrap();
        t.record_hop(&id, "b", "y", s, s, HopStatus::Pending, None, None)
            .unwrap();
        assert_eq!(t.get(&id).unwrap().status, HopStatus::Pending);
    }

    #[test]
    fn duration_micros_recorded() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        let e = s + Duration::microseconds(123_456);
        t.record_hop(&id, "a", "x", s, e, HopStatus::Ok, None, None).unwrap();
        let h = &t.get(&id).unwrap().hops[0];
        assert!(h.duration_micros >= 100_000);
    }

    #[test]
    fn for_tenant_filters() {
        let t = RequestTracer::new();
        t.begin(RequestId::new("r1"), "FAB").unwrap();
        t.begin(RequestId::new("r2"), "ENBD").unwrap();
        assert_eq!(t.for_tenant("FAB").len(), 1);
        assert_eq!(t.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn errored_traces_filter() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        t.record_hop(&id, "a", "x", s, s, HopStatus::Error, Some("e".into()), None)
            .unwrap();
        t.begin(RequestId::new("r2"), "FAB").unwrap();
        let s2 = now();
        t.record_hop(&RequestId::new("r2"), "a", "x", s2, s2, HopStatus::Ok, None, None)
            .unwrap();
        assert_eq!(t.errored_traces().len(), 1);
    }

    #[test]
    fn hop_count_helper() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        for i in 0..5 {
            t.record_hop(&id, &format!("s{i}"), "op", s, s, HopStatus::Ok, None, None)
                .unwrap();
        }
        assert_eq!(t.get(&id).unwrap().hop_count(), 5);
    }

    #[test]
    fn drop_removes_trace() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        assert!(t.drop_trace(&id).unwrap());
        assert!(t.get(&id).is_none());
    }

    #[test]
    fn drop_unknown_returns_false() {
        let t = RequestTracer::new();
        assert!(!t.drop_trace(&RequestId::new("ghost")).unwrap());
    }

    #[test]
    fn request_id_random_unique() {
        let a = RequestId::random();
        let b = RequestId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn hop_with_otel_trace_id() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        t.record_hop(
            &id,
            "a",
            "x",
            s,
            s,
            HopStatus::Ok,
            None,
            Some("otel-trace-1".into()),
        )
        .unwrap();
        assert_eq!(
            t.get(&id).unwrap().hops[0].otel_trace_id.as_deref(),
            Some("otel-trace-1")
        );
    }

    #[test]
    fn request_id_serde_transparent() {
        let id = RequestId::new("x");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"x\"");
    }

    #[test]
    fn trace_serde_round_trip() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        t.record_hop(&id, "a", "x", s, s, HopStatus::Ok, None, None).unwrap();
        let trace = t.get(&id).unwrap();
        let j = serde_json::to_string(&trace).unwrap();
        let p: RequestTrace = serde_json::from_str(&j).unwrap();
        assert_eq!(p, trace);
    }

    #[test]
    fn hop_serde() {
        let h = ServiceHop {
            seq: 1,
            service: "s".into(),
            operation: "o".into(),
            started_at: "2026-01-01T00:00:00Z".into(),
            ended_at: "2026-01-01T00:00:01Z".into(),
            duration_micros: 1_000_000,
            status: HopStatus::Ok,
            error: None,
            otel_trace_id: None,
        };
        let j = serde_json::to_string(&h).unwrap();
        let p: ServiceHop = serde_json::from_str(&j).unwrap();
        assert_eq!(p, h);
    }

    #[test]
    fn hop_status_serde() {
        for s in [HopStatus::Ok, HopStatus::Error, HopStatus::Pending] {
            let j = serde_json::to_string(&s).unwrap();
            let p: HopStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn error_count_correct() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        t.record_hop(&id, "a", "x", s, s, HopStatus::Ok, None, None).unwrap();
        t.record_hop(&id, "b", "y", s, s, HopStatus::Error, Some("e".into()), None)
            .unwrap();
        assert_eq!(t.get(&id).unwrap().error_count(), 1);
    }

    #[test]
    fn many_hops_sequence_correct() {
        let t = RequestTracer::new();
        let id = RequestId::new("r1");
        t.begin(id.clone(), "FAB").unwrap();
        let s = now();
        for _ in 0..10 {
            t.record_hop(&id, "s", "o", s, s, HopStatus::Ok, None, None).unwrap();
        }
        let trace = t.get(&id).unwrap();
        for (i, h) in trace.hops.iter().enumerate() {
            assert_eq!(h.seq, (i + 1) as u32);
        }
    }
}
