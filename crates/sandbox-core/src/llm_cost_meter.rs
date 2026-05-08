//! LLM-call cost meter — token-level usage and cost.
//!
//! Specializes [`crate::billing_meter`] for the unique LLM-cost shape:
//! per-call records of `(input_tokens, output_tokens, cached_tokens)`
//! with per-model rate cards, then aggregated to spend by tenant /
//! period / model.
//!
//! Token-level tracking is essential for:
//! - Per-tenant LLM-spend caps.
//! - Per-model cost allocation.
//! - Anomaly detection (a misbehaving prompt loop).
//! - SaaS pricing.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

/// Micro-units per currency unit (matches `billing_meter::MICRO_PER_UNIT`).
pub const MICRO_PER_UNIT: i64 = 1_000_000;

// =============================================================================
// LlmCallRecord
// =============================================================================

/// One LLM call's cost record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmCallRecord {
    /// Stable id.
    pub call_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Billing period (e.g. `"2026-05"`).
    pub period: String,
    /// Model id (must have a price card entry).
    pub model_id: String,
    /// Input tokens consumed.
    pub input_tokens: u64,
    /// Cached / prompt-cache hit tokens (priced separately).
    pub cached_tokens: u64,
    /// Output tokens generated.
    pub output_tokens: u64,
    /// Optional reasoning tokens (for o1-style models).
    pub reasoning_tokens: u64,
    /// RFC 3339 timestamp.
    pub at: String,
    /// Optional decision id this call belongs to.
    pub decision_id: Option<String>,
}

// =============================================================================
// LlmRateCard
// =============================================================================

/// Per-model rate (micro-currency units per 1k tokens).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmModelRate {
    /// Per 1k input tokens.
    pub input_per_1k_micro: i64,
    /// Per 1k cached tokens.
    pub cached_per_1k_micro: i64,
    /// Per 1k output tokens.
    pub output_per_1k_micro: i64,
    /// Per 1k reasoning tokens.
    pub reasoning_per_1k_micro: i64,
}

impl LlmModelRate {
    /// Convenience: same input/cached/output rates.
    pub fn flat(per_1k_micro: i64) -> Self {
        Self {
            input_per_1k_micro: per_1k_micro,
            cached_per_1k_micro: per_1k_micro,
            output_per_1k_micro: per_1k_micro,
            reasoning_per_1k_micro: per_1k_micro,
        }
    }
}

/// Versioned rate card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmRateCard {
    /// Stable id.
    pub id: String,
    /// Currency.
    pub currency: String,
    /// Per-model rates.
    pub rates: HashMap<String, LlmModelRate>,
}

impl LlmRateCard {
    /// New empty card.
    pub fn new(id: impl Into<String>, currency: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            currency: currency.into(),
            rates: HashMap::new(),
        }
    }

    /// Builder: add a model rate.
    pub fn with_rate(mut self, model_id: impl Into<String>, r: LlmModelRate) -> Self {
        self.rates.insert(model_id.into(), r);
        self
    }

    /// Lookup.
    pub fn rate(&self, model: &str) -> Option<&LlmModelRate> {
        self.rates.get(model)
    }

    /// Compute the cost (in micro-units) for one call. Returns `None` if no
    /// rate is registered for the model.
    pub fn cost_micro(&self, call: &LlmCallRecord) -> Option<i64> {
        let r = self.rates.get(&call.model_id)?;
        let mut total = 0i64;
        total = total.saturating_add(scale(r.input_per_1k_micro, call.input_tokens));
        total = total.saturating_add(scale(r.cached_per_1k_micro, call.cached_tokens));
        total = total.saturating_add(scale(r.output_per_1k_micro, call.output_tokens));
        total = total.saturating_add(scale(r.reasoning_per_1k_micro, call.reasoning_tokens));
        Some(total)
    }
}

fn scale(per_1k: i64, tokens: u64) -> i64 {
    // Avoids floats: tokens * per_1k / 1000.
    let prod = (per_1k as i128).saturating_mul(tokens as i128);
    (prod / 1000) as i64
}

// =============================================================================
// LlmInvoice
// =============================================================================

/// Per-model line in an LLM invoice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmInvoiceLine {
    /// Model.
    pub model_id: String,
    /// Number of calls.
    pub call_count: u64,
    /// Total input tokens.
    pub input_tokens: u64,
    /// Total cached tokens.
    pub cached_tokens: u64,
    /// Total output tokens.
    pub output_tokens: u64,
    /// Total reasoning tokens.
    pub reasoning_tokens: u64,
    /// Subtotal in micro-units.
    pub micro_subtotal: i64,
}

/// LLM-cost invoice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmInvoice {
    /// Invoice id.
    pub invoice_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Period.
    pub period: String,
    /// Rate card id used.
    pub rate_card_id: String,
    /// Currency.
    pub currency: String,
    /// Per-model lines.
    pub lines: Vec<LlmInvoiceLine>,
    /// Total in micro-units.
    pub micro_total: i64,
    /// RFC 3339 issued at.
    pub issued_at: String,
}

// =============================================================================
// LlmCostMeter
// =============================================================================

#[derive(Default)]
struct State {
    calls: Vec<LlmCallRecord>,
}

/// Stateful meter.
pub struct LlmCostMeter {
    state: RwLock<State>,
}

impl Default for LlmCostMeter {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for LlmCostMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmCostMeter")
            .field("calls", &self.call_count())
            .finish()
    }
}

impl LlmCostMeter {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call.
    pub fn record(&self, call: LlmCallRecord) -> SandboxResult<Uuid> {
        let id = call.call_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("llm cost meter poisoned".into()))?
            .calls
            .push(call);
        Ok(id)
    }

    /// Convenience constructor.
    pub fn record_call(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        model: impl Into<String>,
        input_tokens: u64,
        output_tokens: u64,
    ) -> SandboxResult<Uuid> {
        self.record(LlmCallRecord {
            call_id: Uuid::now_v7(),
            tenant_id: tenant.into(),
            period: period.into(),
            model_id: model.into(),
            input_tokens,
            cached_tokens: 0,
            output_tokens,
            reasoning_tokens: 0,
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            decision_id: None,
        })
    }

    /// Snapshot calls.
    pub fn calls(&self) -> Vec<LlmCallRecord> {
        self.state.read().map(|g| g.calls.clone()).unwrap_or_default()
    }

    /// Count.
    pub fn call_count(&self) -> usize {
        self.state.read().map(|g| g.calls.len()).unwrap_or(0)
    }

    /// Generate invoice.
    pub fn invoice(
        &self,
        tenant: &str,
        period: &str,
        rate_card: &LlmRateCard,
    ) -> SandboxResult<LlmInvoice> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("llm cost meter poisoned".into()))?;
        let mut by_model: HashMap<String, LlmInvoiceLine> = HashMap::new();
        for c in &g.calls {
            if c.tenant_id != tenant || c.period != period {
                continue;
            }
            let entry = by_model.entry(c.model_id.clone()).or_insert(LlmInvoiceLine {
                model_id: c.model_id.clone(),
                call_count: 0,
                input_tokens: 0,
                cached_tokens: 0,
                output_tokens: 0,
                reasoning_tokens: 0,
                micro_subtotal: 0,
            });
            entry.call_count += 1;
            entry.input_tokens += c.input_tokens;
            entry.cached_tokens += c.cached_tokens;
            entry.output_tokens += c.output_tokens;
            entry.reasoning_tokens += c.reasoning_tokens;
            let cost = rate_card.cost_micro(c).ok_or_else(|| {
                SandboxError::Other(format!(
                    "no rate for model {} in card {}",
                    c.model_id, rate_card.id
                ))
            })?;
            entry.micro_subtotal = entry.micro_subtotal.saturating_add(cost);
        }
        let mut lines: Vec<LlmInvoiceLine> = by_model.into_values().collect();
        lines.sort_by(|a, b| a.model_id.cmp(&b.model_id));
        let total: i64 = lines.iter().map(|l| l.micro_subtotal).sum();
        Ok(LlmInvoice {
            invoice_id: Uuid::now_v7(),
            tenant_id: tenant.to_string(),
            period: period.to_string(),
            rate_card_id: rate_card.id.clone(),
            currency: rate_card.currency.clone(),
            lines,
            micro_total: total,
            issued_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }

    /// Total tokens for a tenant + period.
    pub fn total_tokens(&self, tenant: &str, period: &str) -> u64 {
        self.calls()
            .iter()
            .filter(|c| c.tenant_id == tenant && c.period == period)
            .map(|c| {
                c.input_tokens + c.cached_tokens + c.output_tokens + c.reasoning_tokens
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> LlmRateCard {
        LlmRateCard::new("usd-2026", "USD")
            .with_rate(
                "gpt-x",
                LlmModelRate {
                    input_per_1k_micro: 5_000,
                    cached_per_1k_micro: 1_000,
                    output_per_1k_micro: 15_000,
                    reasoning_per_1k_micro: 30_000,
                },
            )
            .with_rate("gpt-y", LlmModelRate::flat(10_000))
    }

    #[test]
    fn record_increments() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 100, 50).unwrap();
        assert_eq!(m.call_count(), 1);
    }

    #[test]
    fn invoice_one_call() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 1000, 500).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // 1000 input * 5_000/1k = 5_000; 500 output * 15_000/1k = 7_500.
        // total = 12_500 micro = $0.0125.
        assert_eq!(inv.micro_total, 12_500);
        assert_eq!(inv.lines[0].call_count, 1);
    }

    #[test]
    fn invoice_aggregates_per_model() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 1000, 500).unwrap();
        m.record_call("FAB", "2026-05", "gpt-x", 2000, 1000).unwrap();
        m.record_call("FAB", "2026-05", "gpt-y", 1000, 1000).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.lines.len(), 2);
        let x = inv.lines.iter().find(|l| l.model_id == "gpt-x").unwrap();
        assert_eq!(x.call_count, 2);
        assert_eq!(x.input_tokens, 3000);
    }

    #[test]
    fn invoice_unknown_model_errors() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-z", 100, 100).unwrap();
        assert!(m.invoice("FAB", "2026-05", &card()).is_err());
    }

    #[test]
    fn invoice_other_period_excluded() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 1000, 0).unwrap();
        m.record_call("FAB", "2026-04", "gpt-x", 9999, 0).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.lines[0].input_tokens, 1000);
    }

    #[test]
    fn invoice_other_tenant_excluded() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 1000, 0).unwrap();
        m.record_call("ENBD", "2026-05", "gpt-x", 9999, 0).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.lines[0].input_tokens, 1000);
    }

    #[test]
    fn cached_tokens_priced_separately() {
        let m = LlmCostMeter::new();
        m.record(LlmCallRecord {
            call_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            period: "2026-05".into(),
            model_id: "gpt-x".into(),
            input_tokens: 1000,
            cached_tokens: 500,
            output_tokens: 0,
            reasoning_tokens: 0,
            at: "x".into(),
            decision_id: None,
        })
        .unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // input: 1000 * 5_000/1k = 5_000.
        // cached: 500 * 1_000/1k = 500.
        // total: 5_500.
        assert_eq!(inv.micro_total, 5_500);
    }

    #[test]
    fn reasoning_tokens_priced() {
        let m = LlmCostMeter::new();
        m.record(LlmCallRecord {
            call_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            period: "2026-05".into(),
            model_id: "gpt-x".into(),
            input_tokens: 0,
            cached_tokens: 0,
            output_tokens: 0,
            reasoning_tokens: 1000,
            at: "x".into(),
            decision_id: None,
        })
        .unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // 1000 * 30_000/1k = 30_000.
        assert_eq!(inv.micro_total, 30_000);
    }

    #[test]
    fn total_tokens_sums_all() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 100, 50).unwrap();
        m.record_call("FAB", "2026-05", "gpt-x", 200, 100).unwrap();
        assert_eq!(m.total_tokens("FAB", "2026-05"), 450);
    }

    #[test]
    fn rate_card_lookup() {
        let c = card();
        assert!(c.rate("gpt-x").is_some());
        assert!(c.rate("ghost").is_none());
    }

    #[test]
    fn flat_rate_uniform() {
        let r = LlmModelRate::flat(1000);
        assert_eq!(r.input_per_1k_micro, 1000);
        assert_eq!(r.output_per_1k_micro, 1000);
        assert_eq!(r.reasoning_per_1k_micro, 1000);
    }

    #[test]
    fn cost_micro_unknown_model_none() {
        let c = LlmRateCard::new("x", "USD");
        let call = LlmCallRecord {
            call_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            period: "2026-05".into(),
            model_id: "ghost".into(),
            input_tokens: 100,
            cached_tokens: 0,
            output_tokens: 0,
            reasoning_tokens: 0,
            at: "x".into(),
            decision_id: None,
        };
        assert!(c.cost_micro(&call).is_none());
    }

    #[test]
    fn rate_card_serde() {
        let c = card();
        let j = serde_json::to_string(&c).unwrap();
        let p: LlmRateCard = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn invoice_serde() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 100, 50).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        let j = serde_json::to_string(&inv).unwrap();
        let p: LlmInvoice = serde_json::from_str(&j).unwrap();
        assert_eq!(p, inv);
    }

    #[test]
    fn call_record_serde() {
        let c = LlmCallRecord {
            call_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            period: "2026-05".into(),
            model_id: "gpt-x".into(),
            input_tokens: 1,
            cached_tokens: 1,
            output_tokens: 1,
            reasoning_tokens: 1,
            at: "x".into(),
            decision_id: Some("d1".into()),
        };
        let j = serde_json::to_string(&c).unwrap();
        let p: LlmCallRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn line_serde() {
        let l = LlmInvoiceLine {
            model_id: "x".into(),
            call_count: 1,
            input_tokens: 1,
            cached_tokens: 0,
            output_tokens: 1,
            reasoning_tokens: 0,
            micro_subtotal: 0,
        };
        let j = serde_json::to_string(&l).unwrap();
        let p: LlmInvoiceLine = serde_json::from_str(&j).unwrap();
        assert_eq!(p, l);
    }

    #[test]
    fn lines_sorted_by_model() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-y", 1000, 0).unwrap();
        m.record_call("FAB", "2026-05", "gpt-x", 1000, 0).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.lines[0].model_id, "gpt-x");
    }

    #[test]
    fn empty_invoice_zero_total() {
        let m = LlmCostMeter::new();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.micro_total, 0);
        assert!(inv.lines.is_empty());
    }

    #[test]
    fn many_calls_aggregate() {
        let m = LlmCostMeter::new();
        for _ in 0..100 {
            m.record_call("FAB", "2026-05", "gpt-y", 1000, 1000).unwrap();
        }
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // 100 calls * (1000 input + 1000 output) * 10_000/1k = 100 * 20_000 = 2_000_000.
        assert_eq!(inv.micro_total, 2_000_000);
    }

    #[test]
    fn scale_helper_precise() {
        assert_eq!(scale(5_000, 1000), 5_000);
        assert_eq!(scale(5_000, 100), 500);
        assert_eq!(scale(1, 0), 0);
    }

    #[test]
    fn calls_returns_clone() {
        let m = LlmCostMeter::new();
        m.record_call("FAB", "2026-05", "gpt-x", 1, 1).unwrap();
        assert_eq!(m.calls().len(), 1);
    }
}
