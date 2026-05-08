//! Typed cross-service message bus.
//!
//! Lightweight in-process pub/sub abstraction for service composition.
//! Each topic carries a JSON-shaped payload with strict schema discriminators.
//! Distinct from [`crate::webhook_subscriptions`] (outbound to customers)
//! and [`crate::connector`] (data ingest).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// Topic
// =============================================================================

/// Stable topic name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Topic(pub String);

impl Topic {
    /// New.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// Message
// =============================================================================

/// One message envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    /// Stable id.
    pub message_id: Uuid,
    /// Topic.
    pub topic: Topic,
    /// JSON payload.
    pub payload: serde_json::Value,
    /// Producer service id.
    pub producer: String,
    /// RFC 3339 published.
    pub published_at: String,
    /// Optional correlation id (links to request / case / incident).
    pub correlation_id: Option<String>,
}

// =============================================================================
// Subscription
// =============================================================================

/// A subscription stub — operators register a per-subscription queue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    /// Stable id.
    pub subscription_id: String,
    /// Topic subscribed.
    pub topic: Topic,
    /// Subscriber service.
    pub subscriber: String,
}

// =============================================================================
// MessageBus
// =============================================================================

#[derive(Default)]
struct State {
    /// Topic → subscriber list.
    subscriptions: HashMap<Topic, Vec<Subscription>>,
    /// Per-subscription queue (`subscription_id` → queue).
    queues: HashMap<String, VecDeque<Message>>,
    /// All published messages (for audit / inspect).
    published: Vec<Message>,
}

/// In-process bus.
pub struct MessageBus {
    state: Mutex<State>,
}

impl Default for MessageBus {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }
}

impl std::fmt::Debug for MessageBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageBus")
            .field("subscriptions", &self.subscription_count())
            .field("published", &self.published_count())
            .finish()
    }
}

impl MessageBus {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe.
    pub fn subscribe(
        &self,
        subscription_id: impl Into<String>,
        topic: Topic,
        subscriber: impl Into<String>,
    ) -> SandboxResult<Subscription> {
        let id = subscription_id.into();
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("message bus poisoned".into()))?;
        if g.queues.contains_key(&id) {
            return Err(SandboxError::Other(format!(
                "subscription {} already registered",
                id
            )));
        }
        let s = Subscription {
            subscription_id: id.clone(),
            topic: topic.clone(),
            subscriber: subscriber.into(),
        };
        g.subscriptions.entry(topic).or_default().push(s.clone());
        g.queues.insert(id, VecDeque::new());
        Ok(s)
    }

    /// Unsubscribe.
    pub fn unsubscribe(&self, subscription_id: &str) -> SandboxResult<bool> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("message bus poisoned".into()))?;
        let removed_q = g.queues.remove(subscription_id).is_some();
        for subs in g.subscriptions.values_mut() {
            subs.retain(|s| s.subscription_id != subscription_id);
        }
        Ok(removed_q)
    }

    /// Publish.
    pub fn publish(
        &self,
        topic: Topic,
        producer: impl Into<String>,
        payload: serde_json::Value,
        correlation_id: Option<String>,
    ) -> SandboxResult<usize> {
        let producer = producer.into();
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let msg = Message {
            message_id: Uuid::now_v7(),
            topic: topic.clone(),
            payload,
            producer,
            published_at: now,
            correlation_id,
        };
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("message bus poisoned".into()))?;
        // Fan out into subscriber queues.
        let subs = g.subscriptions.get(&topic).cloned().unwrap_or_default();
        let mut delivered = 0usize;
        for sub in &subs {
            if let Some(q) = g.queues.get_mut(&sub.subscription_id) {
                q.push_back(msg.clone());
                delivered += 1;
            }
        }
        g.published.push(msg);
        Ok(delivered)
    }

    /// Consume next message for a subscription.
    pub fn consume(&self, subscription_id: &str) -> SandboxResult<Option<Message>> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("message bus poisoned".into()))?;
        let q = g
            .queues
            .get_mut(subscription_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("subscription {} not found", subscription_id))
            })?;
        Ok(q.pop_front())
    }

    /// Drain all available messages for a subscription.
    pub fn drain(&self, subscription_id: &str) -> SandboxResult<Vec<Message>> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("message bus poisoned".into()))?;
        let q = g
            .queues
            .get_mut(subscription_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("subscription {} not found", subscription_id))
            })?;
        let v: Vec<Message> = q.drain(..).collect();
        Ok(v)
    }

    /// Subscriptions for a topic.
    pub fn subscribers_of(&self, topic: &Topic) -> Vec<Subscription> {
        self.state
            .lock()
            .map(|g| g.subscriptions.get(topic).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// All subscriptions.
    pub fn subscriptions(&self) -> Vec<Subscription> {
        self.state
            .lock()
            .map(|g| g.subscriptions.values().flatten().cloned().collect())
            .unwrap_or_default()
    }

    /// Count of subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.state
            .lock()
            .map(|g| g.subscriptions.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }

    /// Count of published messages.
    pub fn published_count(&self) -> usize {
        self.state.lock().map(|g| g.published.len()).unwrap_or(0)
    }

    /// Queue depth for one subscription.
    pub fn queue_depth(&self, subscription_id: &str) -> usize {
        self.state
            .lock()
            .map(|g| g.queues.get(subscription_id).map(|q| q.len()).unwrap_or(0))
            .unwrap_or(0)
    }

    /// All published messages.
    pub fn published(&self) -> Vec<Message> {
        self.state.lock().map(|g| g.published.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t() -> Topic {
        Topic::new("seal.created")
    }

    #[test]
    fn subscribe_creates_queue() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "downstream").unwrap();
        assert_eq!(b.subscription_count(), 1);
        assert_eq!(b.queue_depth("s1"), 0);
    }

    #[test]
    fn duplicate_subscription_errors() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        assert!(b.subscribe("s1", t(), "x").is_err());
    }

    #[test]
    fn publish_to_no_subscribers() {
        let b = MessageBus::new();
        let n = b.publish(t(), "producer", json!({"a":1}), None).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn publish_fans_to_subscribers() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.subscribe("s2", t(), "y").unwrap();
        let n = b.publish(t(), "producer", json!({"a":1}), None).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn consume_returns_in_order() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.publish(t(), "p", json!({"i":1}), None).unwrap();
        b.publish(t(), "p", json!({"i":2}), None).unwrap();
        let m1 = b.consume("s1").unwrap().unwrap();
        let m2 = b.consume("s1").unwrap().unwrap();
        assert_eq!(m1.payload, json!({"i":1}));
        assert_eq!(m2.payload, json!({"i":2}));
    }

    #[test]
    fn consume_empty_returns_none() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        assert!(b.consume("s1").unwrap().is_none());
    }

    #[test]
    fn consume_unknown_errors() {
        let b = MessageBus::new();
        assert!(b.consume("ghost").is_err());
    }

    #[test]
    fn drain_returns_all() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        for i in 0..5 {
            b.publish(t(), "p", json!({"i":i}), None).unwrap();
        }
        let drained = b.drain("s1").unwrap();
        assert_eq!(drained.len(), 5);
        assert_eq!(b.queue_depth("s1"), 0);
    }

    #[test]
    fn unsubscribe_removes() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        assert!(b.unsubscribe("s1").unwrap());
        assert_eq!(b.subscription_count(), 0);
    }

    #[test]
    fn unsubscribe_unknown_false() {
        let b = MessageBus::new();
        assert!(!b.unsubscribe("ghost").unwrap());
    }

    #[test]
    fn correlation_id_propagates() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.publish(
            t(),
            "p",
            json!({"x":1}),
            Some("req-1".into()),
        )
        .unwrap();
        let m = b.consume("s1").unwrap().unwrap();
        assert_eq!(m.correlation_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn other_topics_not_delivered() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.publish(Topic::new("seal.deleted"), "p", json!({}), None).unwrap();
        assert_eq!(b.queue_depth("s1"), 0);
    }

    #[test]
    fn subscribers_of_filters_by_topic() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.subscribe("s2", Topic::new("other"), "y").unwrap();
        assert_eq!(b.subscribers_of(&t()).len(), 1);
    }

    #[test]
    fn subscription_serde() {
        let s = Subscription {
            subscription_id: "s1".into(),
            topic: t(),
            subscriber: "x".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: Subscription = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn message_serde() {
        let m = Message {
            message_id: Uuid::now_v7(),
            topic: t(),
            payload: json!({"a":1}),
            producer: "p".into(),
            published_at: "t".into(),
            correlation_id: Some("c".into()),
        };
        let j = serde_json::to_string(&m).unwrap();
        let p: Message = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn topic_serde_transparent() {
        let tp = Topic::new("x");
        assert_eq!(serde_json::to_string(&tp).unwrap(), "\"x\"");
    }

    #[test]
    fn published_count_tracks() {
        let b = MessageBus::new();
        for _ in 0..7 {
            b.publish(t(), "p", json!({}), None).unwrap();
        }
        assert_eq!(b.published_count(), 7);
    }

    #[test]
    fn published_returns_all() {
        let b = MessageBus::new();
        for i in 0..5 {
            b.publish(t(), "p", json!({"i":i}), None).unwrap();
        }
        assert_eq!(b.published().len(), 5);
    }

    #[test]
    fn many_subscribers_to_one_topic() {
        let b = MessageBus::new();
        for i in 0..20 {
            b.subscribe(format!("s{i}"), t(), "x").unwrap();
        }
        let n = b.publish(t(), "p", json!({}), None).unwrap();
        assert_eq!(n, 20);
    }

    #[test]
    fn drain_after_consume() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.publish(t(), "p", json!({"i":1}), None).unwrap();
        b.publish(t(), "p", json!({"i":2}), None).unwrap();
        let _ = b.consume("s1").unwrap();
        assert_eq!(b.drain("s1").unwrap().len(), 1);
    }

    #[test]
    fn subscriptions_returns_all() {
        let b = MessageBus::new();
        b.subscribe("s1", t(), "x").unwrap();
        b.subscribe("s2", Topic::new("other"), "y").unwrap();
        assert_eq!(b.subscriptions().len(), 2);
    }

    #[test]
    fn drain_unknown_errors() {
        let b = MessageBus::new();
        assert!(b.drain("ghost").is_err());
    }
}
