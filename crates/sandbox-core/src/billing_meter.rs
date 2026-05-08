//! Per-tenant usage metering and billing.
//!
//! Three-layer model:
//!
//! 1. [`MeterRegistry`] — record raw [`UsageEvent`]s per tenant per period.
//! 2. [`RateCard`] — versioned price list keyed by [`MeterUnit`].
//! 3. [`Invoice`] — aggregate usage * rate, apply discounts/credits, produce
//!    a stable per-line bill.
//!
//! All amounts are stored as integer **micro-currency-units** (1/1,000,000
//! of one unit) to avoid floating-point drift.
//!
//! ## Example
//!
//! ```ignore
//! let m = MeterRegistry::new();
//! m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
//! let card = RateCard::new("usd-2026-q2")
//!     .with_price(MeterUnit::SealMint, 5_000) // $0.005 per seal
//!     .with_price(MeterUnit::AttestationVerify, 10_000);
//! let invoice = m.invoice("FAB", "2026-05", &card).unwrap();
//! ```

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

/// One micro-unit = 1/1,000,000 of a currency unit.
pub const MICRO_PER_UNIT: i64 = 1_000_000;

// =============================================================================
// MeterUnit
// =============================================================================

/// Stable kinds of meterable usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterUnit {
    /// One [`crate::DigitalSeal`] minted.
    SealMint,
    /// One [`crate::tee::Attestation`] verified.
    AttestationVerify,
    /// One zkML proof verified.
    ZkmlVerify,
    /// Per-GB-day of evidence storage.
    StorageGbDay,
    /// Per outbound webhook delivery.
    WebhookDelivery,
    /// Per anchor transaction.
    AnchorTx,
    /// Per federated verification report.
    FederatedVerify,
    /// Custom — see [`UsageEvent::custom_label`].
    Custom,
}

// =============================================================================
// UsageEvent
// =============================================================================

/// One raw usage event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageEvent {
    /// Event id.
    pub event_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Billing period ("YYYY-MM" or any stable label).
    pub period: String,
    /// Unit kind.
    pub unit: MeterUnit,
    /// Optional sub-label for [`MeterUnit::Custom`].
    pub custom_label: Option<String>,
    /// Quantity (e.g. seal mints, GB-days).
    pub quantity: i64,
    /// RFC 3339 timestamp.
    pub at: String,
}

// =============================================================================
// RateCard
// =============================================================================

/// Versioned price list. Prices are micro-units per quantity unit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateCard {
    /// Stable id (e.g. `"usd-2026-q2"`).
    pub id: String,
    /// Currency tag (e.g. `"USD"`, `"AED"`).
    pub currency: String,
    /// Price map.
    pub prices: HashMap<MeterUnit, i64>,
    /// Optional notes.
    pub note: Option<String>,
}

impl RateCard {
    /// New empty card.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            currency: "USD".into(),
            prices: HashMap::new(),
            note: None,
        }
    }

    /// Builder: currency.
    pub fn with_currency(mut self, c: impl Into<String>) -> Self {
        self.currency = c.into();
        self
    }

    /// Builder: price for one unit (in micro-units).
    pub fn with_price(mut self, unit: MeterUnit, micro_per_unit: i64) -> Self {
        self.prices.insert(unit, micro_per_unit);
        self
    }

    /// Builder: note.
    pub fn with_note(mut self, n: impl Into<String>) -> Self {
        self.note = Some(n.into());
        self
    }

    /// Look up price.
    pub fn price(&self, unit: MeterUnit) -> Option<i64> {
        self.prices.get(&unit).copied()
    }
}

// =============================================================================
// Invoice
// =============================================================================

/// One line on an invoice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvoiceLine {
    /// Unit metered.
    pub unit: MeterUnit,
    /// Custom label (for [`MeterUnit::Custom`]).
    pub custom_label: Option<String>,
    /// Total quantity.
    pub quantity: i64,
    /// Price per quantity unit, in micro-units.
    pub micro_per_unit: i64,
    /// Line total in micro-units.
    pub micro_subtotal: i64,
}

/// Final invoice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invoice {
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
    /// Line items.
    pub lines: Vec<InvoiceLine>,
    /// Discounts applied (negative micro-amounts).
    pub micro_discounts: i64,
    /// Credits applied (negative micro-amounts).
    pub micro_credits: i64,
    /// Subtotal before discount/credits.
    pub micro_subtotal: i64,
    /// Final total, micro-units.
    pub micro_total: i64,
    /// RFC 3339 issue time.
    pub issued_at: String,
}

impl Invoice {
    /// Total in major currency units (rounded down).
    pub fn major_total(&self) -> i64 {
        self.micro_total / MICRO_PER_UNIT
    }

    /// Pretty-print total ("$123.456789").
    pub fn pretty_total(&self) -> String {
        let major = self.micro_total / MICRO_PER_UNIT;
        let micro = (self.micro_total % MICRO_PER_UNIT).abs();
        format!("{}.{:06}", major, micro)
    }
}

// =============================================================================
// MeterRegistry
// =============================================================================

#[derive(Default)]
struct MeterState {
    events: Vec<UsageEvent>,
    /// `(tenant, period) -> Vec<credit_micro>` — applied to invoice generation.
    credits: HashMap<(String, String), Vec<i64>>,
    /// `(tenant, period) -> percentage discount in basis-points (1/10000)`.
    discounts_bps: HashMap<(String, String), u32>,
}

/// Per-tenant usage meter + invoice generator.
pub struct MeterRegistry {
    state: RwLock<MeterState>,
}

impl Default for MeterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MeterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeterRegistry")
            .field("events", &self.event_count())
            .finish()
    }
}

impl MeterRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(MeterState::default()),
        }
    }

    /// Record one usage event.
    pub fn record(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        unit: MeterUnit,
        quantity: i64,
    ) -> SandboxResult<Uuid> {
        if quantity <= 0 {
            return Err(SandboxError::Other(format!(
                "billing meter: quantity must be positive, got {}",
                quantity
            )));
        }
        let e = UsageEvent {
            event_id: Uuid::now_v7(),
            tenant_id: tenant.into(),
            period: period.into(),
            unit,
            custom_label: None,
            quantity,
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        let id = e.event_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("meter poisoned".into()))?
            .events
            .push(e);
        Ok(id)
    }

    /// Record a custom-unit event with a sub-label.
    pub fn record_custom(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        label: impl Into<String>,
        quantity: i64,
    ) -> SandboxResult<Uuid> {
        if quantity <= 0 {
            return Err(SandboxError::Other(format!(
                "billing meter: quantity must be positive, got {}",
                quantity
            )));
        }
        let e = UsageEvent {
            event_id: Uuid::now_v7(),
            tenant_id: tenant.into(),
            period: period.into(),
            unit: MeterUnit::Custom,
            custom_label: Some(label.into()),
            quantity,
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        let id = e.event_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("meter poisoned".into()))?
            .events
            .push(e);
        Ok(id)
    }

    /// Apply a fixed-amount credit (micro-units) to a tenant period.
    pub fn apply_credit(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        micro_amount: i64,
    ) -> SandboxResult<()> {
        if micro_amount <= 0 {
            return Err(SandboxError::Other(
                "credit amount must be positive".into(),
            ));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("meter poisoned".into()))?
            .credits
            .entry((tenant.into(), period.into()))
            .or_default()
            .push(micro_amount);
        Ok(())
    }

    /// Apply a discount in basis-points (e.g. 1500 = 15%) to a tenant period.
    pub fn apply_discount_bps(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        bps: u32,
    ) -> SandboxResult<()> {
        if bps > 10_000 {
            return Err(SandboxError::Other(
                "discount > 100% not allowed".into(),
            ));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("meter poisoned".into()))?
            .discounts_bps
            .insert((tenant.into(), period.into()), bps);
        Ok(())
    }

    /// All events.
    pub fn events(&self) -> Vec<UsageEvent> {
        self.state.read().map(|g| g.events.clone()).unwrap_or_default()
    }

    /// Count of events.
    pub fn event_count(&self) -> usize {
        self.state.read().map(|g| g.events.len()).unwrap_or(0)
    }

    /// Sum of usage for a tenant + period + unit.
    pub fn usage(&self, tenant: &str, period: &str, unit: MeterUnit) -> i64 {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        g.events
            .iter()
            .filter(|e| e.tenant_id == tenant && e.period == period && e.unit == unit)
            .map(|e| e.quantity)
            .sum()
    }

    /// Generate an invoice.
    pub fn invoice(
        &self,
        tenant: &str,
        period: &str,
        rate_card: &RateCard,
    ) -> SandboxResult<Invoice> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("meter poisoned".into()))?;
        // Aggregate by (unit, custom_label) for this tenant + period.
        let mut totals: HashMap<(MeterUnit, Option<String>), i64> = HashMap::new();
        for e in &g.events {
            if e.tenant_id != tenant || e.period != period {
                continue;
            }
            *totals.entry((e.unit, e.custom_label.clone())).or_insert(0) += e.quantity;
        }
        let mut lines = Vec::new();
        let mut subtotal_micro = 0i64;
        for ((unit, label), qty) in totals {
            let price = match rate_card.price(unit) {
                Some(p) => p,
                None => {
                    return Err(SandboxError::Other(format!(
                        "no price for unit {:?} in rate card {}",
                        unit, rate_card.id
                    )));
                }
            };
            let micro = price.saturating_mul(qty);
            subtotal_micro = subtotal_micro.saturating_add(micro);
            lines.push(InvoiceLine {
                unit,
                custom_label: label,
                quantity: qty,
                micro_per_unit: price,
                micro_subtotal: micro,
            });
        }
        // Stable line ordering.
        lines.sort_by(|a, b| {
            (a.unit as u32, a.custom_label.clone()).cmp(&(b.unit as u32, b.custom_label.clone()))
        });

        let credits: i64 = g
            .credits
            .get(&(tenant.to_string(), period.to_string()))
            .map(|v| v.iter().sum())
            .unwrap_or(0);
        let bps = g
            .discounts_bps
            .get(&(tenant.to_string(), period.to_string()))
            .copied()
            .unwrap_or(0) as i64;
        // Discount = subtotal * bps / 10000.
        let discount = subtotal_micro.saturating_mul(bps) / 10_000;
        let total = subtotal_micro
            .saturating_sub(discount)
            .saturating_sub(credits)
            .max(0);
        Ok(Invoice {
            invoice_id: Uuid::now_v7(),
            tenant_id: tenant.to_string(),
            period: period.to_string(),
            rate_card_id: rate_card.id.clone(),
            currency: rate_card.currency.clone(),
            lines,
            micro_discounts: -discount,
            micro_credits: -credits,
            micro_subtotal: subtotal_micro,
            micro_total: total,
            issued_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> RateCard {
        RateCard::new("usd-2026-q2")
            .with_currency("USD")
            .with_price(MeterUnit::SealMint, 5_000) // $0.005
            .with_price(MeterUnit::AttestationVerify, 10_000) // $0.010
            .with_price(MeterUnit::StorageGbDay, 100_000) // $0.100
            .with_price(MeterUnit::Custom, 1_000)
    }

    #[test]
    fn record_increments_count() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 2).unwrap();
        assert_eq!(m.event_count(), 2);
    }

    #[test]
    fn record_zero_quantity_errors() {
        let m = MeterRegistry::new();
        assert!(m.record("FAB", "2026-05", MeterUnit::SealMint, 0).is_err());
        assert!(m.record("FAB", "2026-05", MeterUnit::SealMint, -1).is_err());
    }

    #[test]
    fn usage_sums_for_tenant_period_unit() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 5).unwrap();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 7).unwrap();
        m.record("FAB", "2026-04", MeterUnit::SealMint, 100).unwrap();
        m.record("ENBD", "2026-05", MeterUnit::SealMint, 99).unwrap();
        assert_eq!(m.usage("FAB", "2026-05", MeterUnit::SealMint), 12);
    }

    #[test]
    fn invoice_with_no_usage_yields_empty_lines() {
        let m = MeterRegistry::new();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert!(inv.lines.is_empty());
        assert_eq!(inv.micro_total, 0);
    }

    #[test]
    fn invoice_one_unit_simple_total() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 100).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // 100 * 5_000 = 500_000 micro = $0.50.
        assert_eq!(inv.micro_subtotal, 500_000);
        assert_eq!(inv.micro_total, 500_000);
        assert_eq!(inv.lines.len(), 1);
        assert_eq!(inv.major_total(), 0); // < 1 unit
    }

    #[test]
    fn invoice_two_units_sums() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 100).unwrap();
        m.record("FAB", "2026-05", MeterUnit::AttestationVerify, 50).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // 100*5_000 + 50*10_000 = 500_000 + 500_000 = 1_000_000 micro = $1.00.
        assert_eq!(inv.micro_total, 1_000_000);
        assert_eq!(inv.major_total(), 1);
    }

    #[test]
    fn invoice_unknown_unit_errors() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::ZkmlVerify, 1).unwrap();
        // ZkmlVerify is not in the test card.
        assert!(m.invoice("FAB", "2026-05", &card()).is_err());
    }

    #[test]
    fn invoice_with_discount_applied() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 100).unwrap();
        m.apply_discount_bps("FAB", "2026-05", 1000).unwrap(); // 10%
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // Subtotal $0.50; discount 10% = $0.05; total = $0.45.
        assert_eq!(inv.micro_subtotal, 500_000);
        assert_eq!(inv.micro_discounts, -50_000);
        assert_eq!(inv.micro_total, 450_000);
    }

    #[test]
    fn invoice_with_credit_applied() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 100).unwrap();
        m.apply_credit("FAB", "2026-05", 100_000).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.micro_credits, -100_000);
        assert_eq!(inv.micro_total, 400_000);
    }

    #[test]
    fn invoice_credit_exceeds_subtotal_clamps_to_zero() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
        m.apply_credit("FAB", "2026-05", 999_999_999).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.micro_total, 0);
    }

    #[test]
    fn discount_too_high_errors() {
        let m = MeterRegistry::new();
        assert!(m.apply_discount_bps("FAB", "2026-05", 10_001).is_err());
    }

    #[test]
    fn apply_credit_zero_errors() {
        let m = MeterRegistry::new();
        assert!(m.apply_credit("FAB", "2026-05", 0).is_err());
    }

    #[test]
    fn pretty_total_formats_six_decimals() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        // 1 * 5_000 = 5_000 micro → "0.005000"
        assert_eq!(inv.pretty_total(), "0.005000");
    }

    #[test]
    fn record_custom_with_label() {
        let m = MeterRegistry::new();
        m.record_custom("FAB", "2026-05", "premium-export", 3).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.lines[0].unit, MeterUnit::Custom);
        assert_eq!(inv.lines[0].custom_label.as_deref(), Some("premium-export"));
    }

    #[test]
    fn invoice_isolates_tenants() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 100).unwrap();
        m.record("ENBD", "2026-05", MeterUnit::SealMint, 50).unwrap();
        let fab = m.invoice("FAB", "2026-05", &card()).unwrap();
        let enbd = m.invoice("ENBD", "2026-05", &card()).unwrap();
        assert_eq!(fab.lines[0].quantity, 100);
        assert_eq!(enbd.lines[0].quantity, 50);
    }

    #[test]
    fn invoice_isolates_periods() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 100).unwrap();
        m.record("FAB", "2026-04", MeterUnit::SealMint, 200).unwrap();
        let may = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(may.lines[0].quantity, 100);
    }

    #[test]
    fn rate_card_with_currency_and_note() {
        let c = RateCard::new("aed-2026").with_currency("AED").with_note("Q3");
        assert_eq!(c.currency, "AED");
        assert_eq!(c.note.as_deref(), Some("Q3"));
    }

    #[test]
    fn rate_card_price_lookup() {
        let c = card();
        assert_eq!(c.price(MeterUnit::SealMint), Some(5_000));
        assert_eq!(c.price(MeterUnit::ZkmlVerify), None);
    }

    #[test]
    fn invoice_serde_round_trip() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        let j = serde_json::to_string(&inv).unwrap();
        let p: Invoice = serde_json::from_str(&j).unwrap();
        assert_eq!(p, inv);
    }

    #[test]
    fn rate_card_serde_round_trip() {
        let c = card();
        let j = serde_json::to_string(&c).unwrap();
        let p: RateCard = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn meter_unit_serde_round_trip() {
        for u in [
            MeterUnit::SealMint,
            MeterUnit::AttestationVerify,
            MeterUnit::ZkmlVerify,
            MeterUnit::StorageGbDay,
            MeterUnit::WebhookDelivery,
            MeterUnit::AnchorTx,
            MeterUnit::FederatedVerify,
            MeterUnit::Custom,
        ] {
            let j = serde_json::to_string(&u).unwrap();
            let p: MeterUnit = serde_json::from_str(&j).unwrap();
            assert_eq!(p, u);
        }
    }

    #[test]
    fn invoice_lines_in_stable_order() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::AttestationVerify, 1).unwrap();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
        m.record("FAB", "2026-05", MeterUnit::StorageGbDay, 1).unwrap();
        let inv1 = m.invoice("FAB", "2026-05", &card()).unwrap();
        let inv2 = m.invoice("FAB", "2026-05", &card()).unwrap();
        let units1: Vec<MeterUnit> = inv1.lines.iter().map(|l| l.unit).collect();
        let units2: Vec<MeterUnit> = inv2.lines.iter().map(|l| l.unit).collect();
        assert_eq!(units1, units2);
    }

    #[test]
    fn discount_and_credit_compose() {
        let m = MeterRegistry::new();
        m.record("FAB", "2026-05", MeterUnit::SealMint, 1000).unwrap();
        // Subtotal $5.00.
        m.apply_discount_bps("FAB", "2026-05", 2000).unwrap(); // 20% → -$1.00
        m.apply_credit("FAB", "2026-05", 500_000).unwrap(); // -$0.50
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.micro_subtotal, 5_000_000);
        assert_eq!(inv.micro_discounts, -1_000_000);
        assert_eq!(inv.micro_credits, -500_000);
        // 5.00 - 1.00 - 0.50 = 3.50 = 3_500_000 micro.
        assert_eq!(inv.micro_total, 3_500_000);
    }

    #[test]
    fn many_events_aggregate_correctly() {
        let m = MeterRegistry::new();
        for _ in 0..1_000 {
            m.record("FAB", "2026-05", MeterUnit::SealMint, 1).unwrap();
        }
        let inv = m.invoice("FAB", "2026-05", &card()).unwrap();
        assert_eq!(inv.lines[0].quantity, 1000);
        assert_eq!(inv.micro_total, 5_000_000); // $5.00
    }
}
