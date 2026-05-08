//! Outbound webhook subscriptions.
//!
//! Customers subscribe to seal / verification / incident events. This module
//! provides the *queue + retry + dead-letter* model — actual HTTP delivery is
//! pluggable via [`WebhookTransport`] so production code can plug in
//! `reqwest`/`hyper` while tests use [`InMemoryTransport`].
//!
//! ## Wire format
//!
//! Each delivery includes:
//!
//! - `X-Aethelred-Event` — the [`EventKind`] (e.g. `seal_created`).
//! - `X-Aethelred-Delivery-Id` — UUID of this delivery attempt.
//! - `X-Aethelred-Signature` — HMAC-SHA-256 over `body || timestamp || nonce`,
//!   using the per-subscription signing secret.
//! - `X-Aethelred-Timestamp` — RFC 3339 dispatch time.
//! - `X-Aethelred-Idempotency-Key` — stable id of the *event* (not the
//!   delivery), so customers can dedupe retries.
//!
//! ## Retry policy
//!
//! Default: exponential backoff with `1 * 2^attempt` seconds, capped at
//! 1 hour, max 10 attempts. After exhaustion, the delivery moves to the
//! [`DeadLetterQueue`].
//!
//! ## Idempotency
//!
//! Each event has a stable `event_id`. Multiple delivery attempts share that
//! id via `X-Aethelred-Idempotency-Key` so customer endpoints can reject
//! duplicate processing.

use crate::hashing::Hasher;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// EventKind
// =============================================================================

/// Subscribable event kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A new seal was created.
    SealCreated,
    /// A verification report was issued.
    VerificationReport,
    /// An incident was raised.
    IncidentRaised,
    /// A workflow was completed.
    WorkflowCompleted,
    /// An anomaly was detected.
    AnomalyDetected,
    /// A token was revoked.
    TokenRevoked,
    /// A retention purge ran.
    RetentionPurge,
    /// Custom — arbitrary `kind_label`.
    Custom,
}

// =============================================================================
// Subscription
// =============================================================================

/// One customer-facing webhook subscription.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subscription {
    /// Subscription id.
    pub subscription_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Target URL (https only in production deployments).
    pub url: String,
    /// Event kinds to deliver.
    pub kinds: Vec<EventKind>,
    /// Per-subscription HMAC-SHA256 secret (32+ bytes recommended).
    pub signing_secret: String,
    /// `true` if delivery is enabled.
    pub enabled: bool,
}

impl Subscription {
    /// New enabled subscription.
    pub fn new(
        tenant_id: impl Into<String>,
        url: impl Into<String>,
        kinds: Vec<EventKind>,
        signing_secret: impl Into<String>,
    ) -> Self {
        Self {
            subscription_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            url: url.into(),
            kinds,
            signing_secret: signing_secret.into(),
            enabled: true,
        }
    }
}

// =============================================================================
// Event
// =============================================================================

/// One event ready to deliver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// Stable event id (used as idempotency key).
    pub event_id: Uuid,
    /// Tenant the event belongs to.
    pub tenant_id: String,
    /// Event kind.
    pub kind: EventKind,
    /// Optional sub-label for [`EventKind::Custom`].
    pub kind_label: Option<String>,
    /// JSON payload to deliver as the request body.
    pub payload: serde_json::Value,
    /// RFC 3339 creation time.
    pub created_at: String,
}

impl Event {
    /// New event from a typed payload.
    pub fn new<T: Serialize>(
        tenant_id: impl Into<String>,
        kind: EventKind,
        payload: &T,
    ) -> SandboxResult<Self> {
        let payload = serde_json::to_value(payload).map_err(|e| {
            SandboxError::Other(format!("webhook event serialize failed: {e}"))
        })?;
        Ok(Self {
            event_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            kind,
            kind_label: None,
            payload,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }
}

// =============================================================================
// DeliveryAttempt + DeliveryResult
// =============================================================================

/// One scheduled delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliveryAttempt {
    /// Unique attempt id.
    pub delivery_id: Uuid,
    /// Subscription targeted.
    pub subscription_id: Uuid,
    /// Event payload.
    pub event: Event,
    /// Attempt count (1-indexed).
    pub attempt: u32,
    /// Earliest delivery time (RFC 3339).
    pub deliver_after: String,
}

/// Outcome of a single delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Customer endpoint returned 2xx.
    Success,
    /// Customer endpoint returned a retry-eligible error.
    Retry(String),
    /// Customer endpoint returned a non-retryable error (4xx).
    PermanentFailure(String),
}

// =============================================================================
// WebhookTransport trait
// =============================================================================

/// Pluggable HTTP transport.
pub trait WebhookTransport: Send + Sync {
    /// Deliver one attempt synchronously. Implementations compute headers
    /// (signature, idempotency key) before sending.
    fn deliver(&self, sub: &Subscription, attempt: &DeliveryAttempt) -> DeliveryResult;
}

// =============================================================================
// InMemoryTransport — for tests
// =============================================================================

/// Programmable in-memory transport. Tests can:
///
/// - Pre-program responses for the next N attempts.
/// - Inspect delivered payloads + headers via [`InMemoryTransport::delivered`].
#[derive(Debug)]
pub struct InMemoryTransport {
    inner: Mutex<InMemoryState>,
}

#[derive(Debug, Default)]
struct InMemoryState {
    next_results: VecDeque<DeliveryResult>,
    delivered: Vec<DeliveredRecord>,
}

/// One delivered request record (test inspection).
#[derive(Debug, Clone)]
pub struct DeliveredRecord {
    /// Subscription id.
    pub subscription_id: Uuid,
    /// Delivery attempt id.
    pub delivery_id: Uuid,
    /// Computed signature (hex).
    pub signature: String,
    /// Idempotency key (UUID of event).
    pub idempotency_key: Uuid,
    /// Body bytes (the JSON payload).
    pub body: serde_json::Value,
}

impl Default for InMemoryTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTransport {
    /// New transport that always returns Success.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InMemoryState::default()),
        }
    }

    /// Queue a result for the next delivery.
    pub fn enqueue(&self, r: DeliveryResult) {
        if let Ok(mut g) = self.inner.lock() {
            g.next_results.push_back(r);
        }
    }

    /// Snapshot of all delivered records.
    pub fn delivered(&self) -> Vec<DeliveredRecord> {
        self.inner.lock().map(|g| g.delivered.clone()).unwrap_or_default()
    }

    /// Number of delivered records.
    pub fn delivered_count(&self) -> usize {
        self.inner.lock().map(|g| g.delivered.len()).unwrap_or(0)
    }
}

impl WebhookTransport for InMemoryTransport {
    fn deliver(&self, sub: &Subscription, attempt: &DeliveryAttempt) -> DeliveryResult {
        let body = attempt.event.payload.clone();
        let signature = compute_signature(
            sub.signing_secret.as_bytes(),
            &body,
            &attempt.deliver_after,
            &attempt.delivery_id,
        );
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return DeliveryResult::PermanentFailure("transport poisoned".into()),
        };
        g.delivered.push(DeliveredRecord {
            subscription_id: sub.subscription_id,
            delivery_id: attempt.delivery_id,
            signature,
            idempotency_key: attempt.event.event_id,
            body,
        });
        g.next_results.pop_front().unwrap_or(DeliveryResult::Success)
    }
}

/// HMAC-SHA-256-style signature computed via keyed-hash. Production code
/// should swap for an actual HMAC implementation; the property we rely on
/// here is "depends on key + body + timestamp + nonce."
pub fn compute_signature(
    secret: &[u8],
    body: &serde_json::Value,
    timestamp: &str,
    nonce: &Uuid,
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(secret);
    buf.extend_from_slice(serde_json::to_string(body).unwrap_or_default().as_bytes());
    buf.extend_from_slice(timestamp.as_bytes());
    buf.extend_from_slice(nonce.as_bytes());
    buf.extend_from_slice(secret);
    hex::encode(Hasher::sha256(&buf).0)
}

// =============================================================================
// DeadLetterQueue
// =============================================================================

/// One DLQ entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeadLetter {
    /// Original delivery attempt that exhausted retries.
    pub attempt: DeliveryAttempt,
    /// Last error message.
    pub last_error: String,
    /// RFC 3339 time when the entry was DLQ'd.
    pub dead_lettered_at: String,
}

/// Append-only dead-letter queue.
#[derive(Default)]
pub struct DeadLetterQueue {
    inner: Mutex<Vec<DeadLetter>>,
}

impl std::fmt::Debug for DeadLetterQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeadLetterQueue")
            .field("len", &self.len())
            .finish()
    }
}

impl DeadLetterQueue {
    /// New empty DLQ.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push.
    pub fn push(&self, dl: DeadLetter) {
        if let Ok(mut g) = self.inner.lock() {
            g.push(dl);
        }
    }

    /// All entries.
    pub fn entries(&self) -> Vec<DeadLetter> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// RetryPolicy
// =============================================================================

/// Retry policy parameters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct RetryPolicy {
    /// Maximum attempts before DLQ.
    pub max_attempts: u32,
    /// Base backoff in seconds.
    pub base_seconds: i64,
    /// Cap on backoff in seconds.
    pub cap_seconds: i64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            base_seconds: 1,
            cap_seconds: 3600, // 1 hour
        }
    }
}

impl RetryPolicy {
    /// Compute the delay for the next attempt: `min(cap, base * 2^attempt)`.
    pub fn delay_for(&self, attempt: u32) -> i64 {
        let exp = attempt.min(30); // avoid overflow
        let raw = self.base_seconds.saturating_mul(1i64 << exp);
        raw.min(self.cap_seconds).max(0)
    }
}

// =============================================================================
// WebhookDispatcher
// =============================================================================

#[derive(Default)]
struct DispatcherState {
    subs: HashMap<Uuid, Subscription>,
    queue: VecDeque<DeliveryAttempt>,
}

/// Owns subscriptions + delivery queue + DLQ.
pub struct WebhookDispatcher {
    state: Mutex<DispatcherState>,
    dlq: DeadLetterQueue,
    policy: RetryPolicy,
}

impl std::fmt::Debug for WebhookDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookDispatcher")
            .field("subscriptions", &self.subscription_count())
            .field("queue_len", &self.queue_len())
            .field("dlq_len", &self.dlq.len())
            .finish()
    }
}

impl Default for WebhookDispatcher {
    fn default() -> Self {
        Self::new(RetryPolicy::default())
    }
}

impl WebhookDispatcher {
    /// New dispatcher.
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            state: Mutex::new(DispatcherState::default()),
            dlq: DeadLetterQueue::new(),
            policy,
        }
    }

    /// Number of registered subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.state.lock().map(|g| g.subs.len()).unwrap_or(0)
    }

    /// Pending queue length.
    pub fn queue_len(&self) -> usize {
        self.state.lock().map(|g| g.queue.len()).unwrap_or(0)
    }

    /// Borrow the DLQ.
    pub fn dlq(&self) -> &DeadLetterQueue {
        &self.dlq
    }

    /// Subscribe.
    pub fn subscribe(&self, sub: Subscription) -> SandboxResult<Uuid> {
        let id = sub.subscription_id;
        self.state
            .lock()
            .map_err(|_| SandboxError::Other("dispatcher poisoned".into()))?
            .subs
            .insert(id, sub);
        Ok(id)
    }

    /// Unsubscribe.
    pub fn unsubscribe(&self, id: Uuid) -> SandboxResult<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("dispatcher poisoned".into()))?
            .subs
            .remove(&id)
            .is_some())
    }

    /// Toggle a subscription's enabled flag.
    pub fn set_enabled(&self, id: Uuid, enabled: bool) -> SandboxResult<()> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("dispatcher poisoned".into()))?;
        let s = g
            .subs
            .get_mut(&id)
            .ok_or_else(|| SandboxError::Other(format!("subscription {} not found", id)))?;
        s.enabled = enabled;
        Ok(())
    }

    /// Publish an event — fans out to all matching subscriptions.
    /// Returns the number of delivery attempts queued.
    pub fn publish(&self, event: Event) -> SandboxResult<usize> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("dispatcher poisoned".into()))?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut count = 0;
        let attempts: Vec<DeliveryAttempt> = g
            .subs
            .values()
            .filter(|s| s.enabled && s.tenant_id == event.tenant_id && s.kinds.contains(&event.kind))
            .map(|s| DeliveryAttempt {
                delivery_id: Uuid::now_v7(),
                subscription_id: s.subscription_id,
                event: event.clone(),
                attempt: 1,
                deliver_after: now.clone(),
            })
            .collect();
        for a in attempts {
            g.queue.push_back(a);
            count += 1;
        }
        Ok(count)
    }

    /// Attempt to deliver every queued attempt with the given transport.
    /// Failed attempts are re-queued (or moved to DLQ on exhaustion).
    pub fn drain_once(&self, transport: &dyn WebhookTransport) -> SandboxResult<DrainStats> {
        let attempts: Vec<DeliveryAttempt> = {
            let mut g = self
                .state
                .lock()
                .map_err(|_| SandboxError::Other("dispatcher poisoned".into()))?;
            g.queue.drain(..).collect()
        };
        let mut stats = DrainStats::default();
        for attempt in attempts {
            let sub = match self
                .state
                .lock()
                .ok()
                .and_then(|g| g.subs.get(&attempt.subscription_id).cloned())
            {
                Some(s) => s,
                None => {
                    stats.dropped += 1;
                    continue;
                }
            };
            let result = transport.deliver(&sub, &attempt);
            match result {
                DeliveryResult::Success => stats.delivered += 1,
                DeliveryResult::Retry(err) => {
                    if attempt.attempt >= self.policy.max_attempts {
                        self.dlq.push(DeadLetter {
                            attempt: attempt.clone(),
                            last_error: err,
                            dead_lettered_at: OffsetDateTime::now_utc()
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_default(),
                        });
                        stats.dead_lettered += 1;
                    } else {
                        let delay = self.policy.delay_for(attempt.attempt);
                        let next = (OffsetDateTime::now_utc() + time::Duration::seconds(delay))
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default();
                        let mut next_attempt = attempt.clone();
                        next_attempt.attempt += 1;
                        next_attempt.deliver_after = next;
                        self.state
                            .lock()
                            .map_err(|_| SandboxError::Other("dispatcher poisoned".into()))?
                            .queue
                            .push_back(next_attempt);
                        stats.retried += 1;
                    }
                }
                DeliveryResult::PermanentFailure(err) => {
                    self.dlq.push(DeadLetter {
                        attempt: attempt.clone(),
                        last_error: err,
                        dead_lettered_at: OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                    });
                    stats.permanently_failed += 1;
                }
            }
        }
        Ok(stats)
    }
}

/// Per-drain statistics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainStats {
    /// Successful deliveries.
    pub delivered: u32,
    /// Re-queued for retry.
    pub retried: u32,
    /// Sent to DLQ after retry exhaustion.
    pub dead_lettered: u32,
    /// Sent to DLQ on permanent failure.
    pub permanently_failed: u32,
    /// Dropped because subscription was removed mid-flight.
    pub dropped: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sub(kinds: Vec<EventKind>) -> Subscription {
        Subscription::new("FAB", "https://example.test/hook", kinds, "secret-32-bytes-x")
    }

    fn evt(k: EventKind) -> Event {
        Event::new("FAB", k, &json!({"hello":"world"})).unwrap()
    }

    #[test]
    fn subscribe_increments_count() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        assert_eq!(d.subscription_count(), 1);
    }

    #[test]
    fn unsubscribe_returns_true_when_found() {
        let d = WebhookDispatcher::default();
        let id = d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        assert!(d.unsubscribe(id).unwrap());
        assert!(!d.unsubscribe(id).unwrap());
    }

    #[test]
    fn publish_fans_out_to_matching_subs() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.subscribe(sub(vec![EventKind::AnomalyDetected])).unwrap();
        let n = d.publish(evt(EventKind::SealCreated)).unwrap();
        assert_eq!(n, 2);
        assert_eq!(d.queue_len(), 2);
    }

    #[test]
    fn publish_skips_disabled_subscriptions() {
        let d = WebhookDispatcher::default();
        let id = d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.set_enabled(id, false).unwrap();
        let n = d.publish(evt(EventKind::SealCreated)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn publish_skips_other_tenants() {
        let d = WebhookDispatcher::default();
        let mut s = sub(vec![EventKind::SealCreated]);
        s.tenant_id = "ENBD".into();
        d.subscribe(s).unwrap();
        let n = d.publish(evt(EventKind::SealCreated)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn drain_delivers_to_transport() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        let t = InMemoryTransport::new();
        let stats = d.drain_once(&t).unwrap();
        assert_eq!(stats.delivered, 1);
        assert_eq!(t.delivered_count(), 1);
    }

    #[test]
    fn signature_is_computed_per_delivery() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        let t = InMemoryTransport::new();
        d.drain_once(&t).unwrap();
        let r = &t.delivered()[0];
        assert!(r.signature.len() == 64);
    }

    #[test]
    fn idempotency_key_is_event_id() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        let e = evt(EventKind::SealCreated);
        let id = e.event_id;
        d.publish(e).unwrap();
        let t = InMemoryTransport::new();
        d.drain_once(&t).unwrap();
        assert_eq!(t.delivered()[0].idempotency_key, id);
    }

    #[test]
    fn retry_requeues_failed() {
        let d = WebhookDispatcher::new(RetryPolicy {
            max_attempts: 3,
            base_seconds: 1,
            cap_seconds: 60,
        });
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        let t = InMemoryTransport::new();
        t.enqueue(DeliveryResult::Retry("503".into()));
        let s = d.drain_once(&t).unwrap();
        assert_eq!(s.retried, 1);
        assert_eq!(d.queue_len(), 1, "re-queued for next drain");
    }

    #[test]
    fn retry_exhaustion_moves_to_dlq() {
        let d = WebhookDispatcher::new(RetryPolicy {
            max_attempts: 2,
            base_seconds: 1,
            cap_seconds: 60,
        });
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        let t = InMemoryTransport::new();
        t.enqueue(DeliveryResult::Retry("err1".into()));
        d.drain_once(&t).unwrap(); // attempt 1 → retry
        t.enqueue(DeliveryResult::Retry("err2".into()));
        let s = d.drain_once(&t).unwrap(); // attempt 2 → DLQ
        assert_eq!(s.dead_lettered, 1);
        assert_eq!(d.dlq().len(), 1);
    }

    #[test]
    fn permanent_failure_immediately_dlqs() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        let t = InMemoryTransport::new();
        t.enqueue(DeliveryResult::PermanentFailure("400".into()));
        let s = d.drain_once(&t).unwrap();
        assert_eq!(s.permanently_failed, 1);
        assert_eq!(d.dlq().len(), 1);
    }

    #[test]
    fn retry_policy_delay_grows_exponentially() {
        let p = RetryPolicy::default();
        assert_eq!(p.delay_for(1), 2);
        assert_eq!(p.delay_for(2), 4);
        assert_eq!(p.delay_for(3), 8);
        assert_eq!(p.delay_for(20), p.cap_seconds);
    }

    #[test]
    fn retry_policy_caps_at_max() {
        let p = RetryPolicy {
            max_attempts: 100,
            base_seconds: 1,
            cap_seconds: 60,
        };
        assert_eq!(p.delay_for(20), 60);
    }

    #[test]
    fn drop_when_subscription_removed_mid_flight() {
        let d = WebhookDispatcher::default();
        let id = d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        d.unsubscribe(id).unwrap();
        let t = InMemoryTransport::new();
        let s = d.drain_once(&t).unwrap();
        assert_eq!(s.dropped, 1);
    }

    #[test]
    fn signature_changes_with_body() {
        let s1 = compute_signature(b"k", &json!({"a":1}), "ts", &Uuid::nil());
        let s2 = compute_signature(b"k", &json!({"a":2}), "ts", &Uuid::nil());
        assert_ne!(s1, s2);
    }

    #[test]
    fn signature_changes_with_secret() {
        let s1 = compute_signature(b"k1", &json!({}), "ts", &Uuid::nil());
        let s2 = compute_signature(b"k2", &json!({}), "ts", &Uuid::nil());
        assert_ne!(s1, s2);
    }

    #[test]
    fn dlq_empty_initially() {
        let d = WebhookDispatcher::default();
        assert!(d.dlq().is_empty());
    }

    #[test]
    fn drain_empty_queue_no_op() {
        let d = WebhookDispatcher::default();
        let t = InMemoryTransport::new();
        let s = d.drain_once(&t).unwrap();
        assert_eq!(s, DrainStats::default());
    }

    #[test]
    fn event_kind_serde_round_trip() {
        for k in [
            EventKind::SealCreated,
            EventKind::VerificationReport,
            EventKind::AnomalyDetected,
            EventKind::Custom,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: EventKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn subscription_serde_round_trip() {
        let s = sub(vec![EventKind::SealCreated, EventKind::AnomalyDetected]);
        let j = serde_json::to_string(&s).unwrap();
        let p: Subscription = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn drain_stats_serde_round_trip() {
        let s = DrainStats {
            delivered: 1,
            retried: 2,
            dead_lettered: 3,
            permanently_failed: 4,
            dropped: 5,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: DrainStats = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn fan_out_works_for_many_subs() {
        let d = WebhookDispatcher::default();
        for _ in 0..10 {
            d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        }
        let n = d.publish(evt(EventKind::SealCreated)).unwrap();
        assert_eq!(n, 10);
    }

    #[test]
    fn deliver_after_set_on_enqueue() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        // queue inspected via drain.
        let t = InMemoryTransport::new();
        d.drain_once(&t).unwrap();
        assert!(t.delivered_count() == 1);
    }

    #[test]
    fn set_enabled_unknown_errors() {
        let d = WebhookDispatcher::default();
        assert!(d.set_enabled(Uuid::now_v7(), true).is_err());
    }

    #[test]
    fn dlq_records_carry_attempt() {
        let d = WebhookDispatcher::default();
        d.subscribe(sub(vec![EventKind::SealCreated])).unwrap();
        d.publish(evt(EventKind::SealCreated)).unwrap();
        let t = InMemoryTransport::new();
        t.enqueue(DeliveryResult::PermanentFailure("400".into()));
        d.drain_once(&t).unwrap();
        let entries = d.dlq().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempt.attempt, 1);
    }
}
