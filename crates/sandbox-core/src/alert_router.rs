//! Severity-based alert routing.
//!
//! Sends alerts to channels (PagerDuty, Slack, email) based on severity +
//! tag rules. Distinct from [`crate::incident::IncidentDispatcher`] which
//! handles full incidents — this module fires individual alerts.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// AlertSeverity
// =============================================================================

/// Severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Critical → page on-call.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
    /// Informational.
    Info,
}

// =============================================================================
// Channel
// =============================================================================

/// Channel kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    /// Pager (PagerDuty / Opsgenie).
    Pager,
    /// Slack / Teams chat.
    Chat,
    /// Email.
    Email,
    /// Webhook.
    Webhook,
}

/// Channel destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Channel {
    /// Stable id.
    pub channel_id: String,
    /// Display name.
    pub name: String,
    /// Kind.
    pub kind: ChannelKind,
    /// Endpoint (URL / email / pager-key).
    pub endpoint: String,
    /// Tags this channel handles.
    pub handles_tags: Vec<String>,
}

// =============================================================================
// RoutingRule
// =============================================================================

/// One routing rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingRule {
    /// Stable id.
    pub rule_id: String,
    /// Min severity (this rule fires for severity ≥ min).
    pub min_severity: AlertSeverity,
    /// Required tag (empty = match any).
    pub required_tag: Option<String>,
    /// Channel ids to fan out to.
    pub channel_ids: Vec<String>,
    /// Active flag.
    pub active: bool,
}

// =============================================================================
// Alert
// =============================================================================

/// One alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    /// Stable id.
    pub alert_id: Uuid,
    /// Title.
    pub title: String,
    /// Body.
    pub body: String,
    /// Severity.
    pub severity: AlertSeverity,
    /// Tags.
    pub tags: Vec<String>,
    /// RFC 3339 fired at.
    pub fired_at: String,
    /// Source.
    pub source: String,
}

// =============================================================================
// Delivery
// =============================================================================

/// One per-channel delivery record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertDelivery {
    /// Stable id.
    pub delivery_id: Uuid,
    /// Alert id.
    pub alert_id: Uuid,
    /// Channel id.
    pub channel_id: String,
    /// RFC 3339 attempted.
    pub attempted_at: String,
    /// Result.
    pub status: DeliveryStatus,
}

/// Per-delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Successfully delivered.
    Delivered,
    /// Failed.
    Failed,
    /// Suppressed (e.g., duplicate).
    Suppressed,
}

// =============================================================================
// AlertRouter
// =============================================================================

#[derive(Default)]
struct State {
    channels: HashMap<String, Channel>,
    rules: Vec<RoutingRule>,
    alerts: Vec<Alert>,
    deliveries: Vec<AlertDelivery>,
}

/// Router.
pub struct AlertRouter {
    state: RwLock<State>,
}

impl Default for AlertRouter {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for AlertRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertRouter")
            .field("channels", &self.channel_count())
            .field("rules", &self.rule_count())
            .finish()
    }
}

impl AlertRouter {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a channel.
    pub fn add_channel(&self, c: Channel) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("alert router poisoned".into()))?;
        if g.channels.contains_key(&c.channel_id) {
            return Err(SandboxError::Other(format!(
                "channel {} already exists",
                c.channel_id
            )));
        }
        g.channels.insert(c.channel_id.clone(), c);
        Ok(())
    }

    /// Add a rule.
    pub fn add_rule(&self, r: RoutingRule) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("alert router poisoned".into()))?;
        // Validate channels exist.
        for cid in &r.channel_ids {
            if !g.channels.contains_key(cid) {
                return Err(SandboxError::Other(format!(
                    "channel {} not registered",
                    cid
                )));
            }
        }
        g.rules.push(r);
        Ok(())
    }

    /// Route an alert. Returns deliveries fanned out.
    pub fn route(&self, alert: Alert) -> SandboxResult<Vec<AlertDelivery>> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("alert router poisoned".into()))?;
        // Find matching rules.
        let matching_rules: Vec<RoutingRule> = g
            .rules
            .iter()
            .filter(|r| r.active && rule_matches(r, &alert))
            .cloned()
            .collect();
        let mut channel_set: Vec<String> = Vec::new();
        for r in &matching_rules {
            for cid in &r.channel_ids {
                if !channel_set.contains(cid) {
                    channel_set.push(cid.clone());
                }
            }
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut deliveries = Vec::new();
        for cid in &channel_set {
            let d = AlertDelivery {
                delivery_id: Uuid::now_v7(),
                alert_id: alert.alert_id,
                channel_id: cid.clone(),
                attempted_at: now.clone(),
                status: DeliveryStatus::Delivered,
            };
            deliveries.push(d.clone());
            g.deliveries.push(d);
        }
        g.alerts.push(alert);
        Ok(deliveries)
    }

    /// All alerts.
    pub fn alerts(&self) -> Vec<Alert> {
        self.state.read().map(|g| g.alerts.clone()).unwrap_or_default()
    }
    /// All deliveries.
    pub fn deliveries(&self) -> Vec<AlertDelivery> {
        self.state.read().map(|g| g.deliveries.clone()).unwrap_or_default()
    }
    /// Alerts of severity.
    pub fn alerts_of(&self, sev: AlertSeverity) -> Vec<Alert> {
        self.alerts().into_iter().filter(|a| a.severity == sev).collect()
    }
    /// Channel count.
    pub fn channel_count(&self) -> usize {
        self.state.read().map(|g| g.channels.len()).unwrap_or(0)
    }
    /// Rule count.
    pub fn rule_count(&self) -> usize {
        self.state.read().map(|g| g.rules.len()).unwrap_or(0)
    }
    /// All channels.
    pub fn channels(&self) -> Vec<Channel> {
        self.state
            .read()
            .map(|g| g.channels.values().cloned().collect())
            .unwrap_or_default()
    }
}

fn rule_matches(r: &RoutingRule, a: &Alert) -> bool {
    // Severity check: lower-numeric = higher severity.
    if sev_rank(a.severity) > sev_rank(r.min_severity) {
        return false;
    }
    if let Some(tag) = &r.required_tag {
        if !a.tags.iter().any(|t| t == tag) {
            return false;
        }
    }
    true
}

fn sev_rank(s: AlertSeverity) -> u8 {
    match s {
        AlertSeverity::Critical => 0,
        AlertSeverity::High => 1,
        AlertSeverity::Medium => 2,
        AlertSeverity::Low => 3,
        AlertSeverity::Info => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(id: &str, kind: ChannelKind) -> Channel {
        Channel {
            channel_id: id.into(),
            name: id.into(),
            kind,
            endpoint: "http://endpoint".into(),
            handles_tags: vec![],
        }
    }

    fn alert(sev: AlertSeverity, tags: Vec<String>) -> Alert {
        Alert {
            alert_id: Uuid::now_v7(),
            title: "x".into(),
            body: "y".into(),
            severity: sev,
            tags,
            fired_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            source: "test".into(),
        }
    }

    #[test]
    fn add_channel() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        assert_eq!(r.channel_count(), 1);
    }

    #[test]
    fn duplicate_channel_errors() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        assert!(r.add_channel(channel("pd", ChannelKind::Pager)).is_err());
    }

    #[test]
    fn add_rule_with_unknown_channel_errors() {
        let r = AlertRouter::new();
        let rule = RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::High,
            required_tag: None,
            channel_ids: vec!["ghost".into()],
            active: true,
        };
        assert!(r.add_rule(rule).is_err());
    }

    #[test]
    fn route_critical_to_pager() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::High,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        let d = r.route(alert(AlertSeverity::Critical, vec![])).unwrap();
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn route_low_does_not_match_high_rule() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::High,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        let d = r.route(alert(AlertSeverity::Low, vec![])).unwrap();
        assert!(d.is_empty());
    }

    #[test]
    fn required_tag_filters() {
        let r = AlertRouter::new();
        r.add_channel(channel("slack-fraud", ChannelKind::Chat)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::Info,
            required_tag: Some("fraud".into()),
            channel_ids: vec!["slack-fraud".into()],
            active: true,
        })
        .unwrap();
        let no = r.route(alert(AlertSeverity::Critical, vec![])).unwrap();
        assert!(no.is_empty());
        let yes = r.route(alert(AlertSeverity::Info, vec!["fraud".into()])).unwrap();
        assert_eq!(yes.len(), 1);
    }

    #[test]
    fn inactive_rule_skipped() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::Critical,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: false,
        })
        .unwrap();
        let d = r.route(alert(AlertSeverity::Critical, vec![])).unwrap();
        assert!(d.is_empty());
    }

    #[test]
    fn multiple_rules_dedup_channels() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::Critical,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r2".into(),
            min_severity: AlertSeverity::High,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        let d = r.route(alert(AlertSeverity::Critical, vec![])).unwrap();
        assert_eq!(d.len(), 1, "channel should not be duplicated");
    }

    #[test]
    fn route_to_multiple_channels() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_channel(channel("slack", ChannelKind::Chat)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::High,
            required_tag: None,
            channel_ids: vec!["pd".into(), "slack".into()],
            active: true,
        })
        .unwrap();
        let d = r.route(alert(AlertSeverity::High, vec![])).unwrap();
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn alerts_of_filters() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::Info,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        r.route(alert(AlertSeverity::Critical, vec![])).unwrap();
        r.route(alert(AlertSeverity::High, vec![])).unwrap();
        assert_eq!(r.alerts_of(AlertSeverity::Critical).len(), 1);
    }

    #[test]
    fn rule_count_tracks() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        for i in 0..3 {
            r.add_rule(RoutingRule {
                rule_id: format!("r{i}"),
                min_severity: AlertSeverity::Info,
                required_tag: None,
                channel_ids: vec!["pd".into()],
                active: true,
            })
            .unwrap();
        }
        assert_eq!(r.rule_count(), 3);
    }

    #[test]
    fn alerts_returns_all() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::Info,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        for _ in 0..5 {
            r.route(alert(AlertSeverity::High, vec![])).unwrap();
        }
        assert_eq!(r.alerts().len(), 5);
    }

    #[test]
    fn deliveries_recorded() {
        let r = AlertRouter::new();
        r.add_channel(channel("pd", ChannelKind::Pager)).unwrap();
        r.add_rule(RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::Info,
            required_tag: None,
            channel_ids: vec!["pd".into()],
            active: true,
        })
        .unwrap();
        r.route(alert(AlertSeverity::High, vec![])).unwrap();
        assert_eq!(r.deliveries().len(), 1);
    }

    #[test]
    fn alert_serde() {
        let a = alert(AlertSeverity::Critical, vec!["fraud".into()]);
        let j = serde_json::to_string(&a).unwrap();
        let p: Alert = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn channel_serde() {
        let c = channel("pd", ChannelKind::Pager);
        let j = serde_json::to_string(&c).unwrap();
        let p: Channel = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn rule_serde() {
        let r = RoutingRule {
            rule_id: "r1".into(),
            min_severity: AlertSeverity::High,
            required_tag: Some("x".into()),
            channel_ids: vec!["pd".into()],
            active: true,
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: RoutingRule = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn delivery_serde() {
        let d = AlertDelivery {
            delivery_id: Uuid::now_v7(),
            alert_id: Uuid::now_v7(),
            channel_id: "pd".into(),
            attempted_at: "t".into(),
            status: DeliveryStatus::Delivered,
        };
        let j = serde_json::to_string(&d).unwrap();
        let p: AlertDelivery = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn severity_serde() {
        for s in [
            AlertSeverity::Critical,
            AlertSeverity::High,
            AlertSeverity::Medium,
            AlertSeverity::Low,
            AlertSeverity::Info,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: AlertSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn channel_kind_serde() {
        for k in [
            ChannelKind::Pager,
            ChannelKind::Chat,
            ChannelKind::Email,
            ChannelKind::Webhook,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: ChannelKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn delivery_status_serde() {
        for s in [
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::Suppressed,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: DeliveryStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn channels_returns_all() {
        let r = AlertRouter::new();
        r.add_channel(channel("a", ChannelKind::Pager)).unwrap();
        r.add_channel(channel("b", ChannelKind::Chat)).unwrap();
        assert_eq!(r.channels().len(), 2);
    }
}
