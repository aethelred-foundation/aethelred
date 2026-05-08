//! Trading-event workflow.
//!
//! Production target: per-order-event seal with risk-limit check and
//! market-conduct evidence. Aligned to MAR (Regulation (EU) 596/2014) and
//! MiFID II (Directive 2014/65/EU). Compatible with FIX 4.4 / FpML.

use crate::protocols::{FinanceMessageEnvelope, FinanceProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Order side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    /// Buy.
    Buy,
    /// Sell.
    Sell,
}

impl OrderSide {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }
}

/// Order type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderType {
    /// Market order.
    Market,
    /// Limit order.
    Limit,
    /// Stop / stop-loss.
    Stop,
    /// Stop-limit.
    StopLimit,
}

impl OrderType {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Market => "market",
            Self::Limit => "limit",
            Self::Stop => "stop",
            Self::StopLimit => "stop_limit",
        }
    }
}

/// Risk-limit-check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitStatus {
    /// Within configured limits.
    WithinLimits,
    /// At limit threshold (warn).
    AtThreshold,
    /// Exceeded limits — order should be blocked or escalated.
    Exceeded,
    /// Limits not configured for this account / instrument.
    NotConfigured,
}

impl RiskLimitStatus {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WithinLimits => "within_limits",
            Self::AtThreshold => "at_threshold",
            Self::Exceeded => "exceeded",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// Trading-event input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradingEvent {
    /// Order id (FIX `ClOrdID` / FpML / internal).
    pub order_id: String,
    /// FIX-style `Symbol` or instrument identifier.
    pub instrument: String,
    /// Side.
    pub side: OrderSide,
    /// Order type.
    pub order_type: OrderType,
    /// Quantity.
    pub quantity: Decimal,
    /// Price (for `Limit` / `StopLimit`).
    pub price: Option<Decimal>,
    /// Notional value (qty × price). Optional — populated by the connector.
    pub notional: Option<Decimal>,
    /// Currency (ISO 4217).
    pub currency: String,
    /// Account pseudo id.
    pub account_pseudo_id: String,
    /// AI model id (where AI is involved — e.g., `"smart_order_router_v2"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Risk-limit-check status.
    pub risk_limit_status: RiskLimitStatus,
    /// Trader / desk role (e.g., `"desk:fx_emea"`, `"algo:taq_v3"`).
    pub trader_role: String,
    /// Trader / desk pseudo id.
    pub trader_pseudo_id: String,
    /// FIX / FpML / ISO 20022 message envelope.
    pub message: FinanceMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl TradingEvent {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"NewOrderSingle 35=D 11=ord-1 55=USDAED 54=1 38=1m");
        Self {
            order_id: "ord-2026-12-887211".into(),
            instrument: "USDAED".into(),
            side: OrderSide::Buy,
            order_type: OrderType::Market,
            quantity: Decimal::new(1_000_000, 0),
            price: None,
            notional: Some(Decimal::new(3_672_500, 0)),
            currency: "AED".into(),
            account_pseudo_id: "acct:fx-emea-7a1".into(),
            model_id: "smart_order_router_v2".into(),
            model_hash_hex: Hasher::sha256(b"demo-sor-weights").to_hex(),
            model_version: Some("2.1.0".into()),
            risk_limit_status: RiskLimitStatus::WithinLimits,
            trader_role: "desk:fx_emea".into(),
            trader_pseudo_id: "role:desk_fx_emea#012".into(),
            message: FinanceMessageEnvelope {
                protocol: FinanceProtocol::Fix44,
                message_type: "NewOrderSingle".into(),
                sender_id: "FAB".into(),
                receiver_id: "EXCHANGE".into(),
                correlation_id: "ord-2026-12-887211".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed trading event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradingEventSeal {
    /// The underlying canonical seal.
    pub seal: DigitalSeal,
    /// Risk-limit-check status (mirrored).
    pub risk_limit_status: RiskLimitStatus,
}

impl TradingEventSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &TradingEvent,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.order_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.side.as_str().as_bytes());
        bytes.extend_from_slice(input.quantity.to_string().as_bytes());
        if let Some(p) = &input.price {
            bytes.extend_from_slice(p.to_string().as_bytes());
        }
        bytes.extend_from_slice(input.risk_limit_status.as_str().as_bytes());
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("trading_event"));
    sector_extension.insert("order_id".into(), serde_json::json!(input.order_id));
    sector_extension.insert("instrument".into(), serde_json::json!(input.instrument));
    sector_extension.insert("side".into(), serde_json::json!(input.side.as_str()));
    sector_extension.insert("order_type".into(), serde_json::json!(input.order_type.as_str()));
    sector_extension.insert("quantity".into(), serde_json::json!(input.quantity.to_string()));
    if let Some(p) = &input.price {
        sector_extension.insert("price".into(), serde_json::json!(p.to_string()));
    }
    sector_extension.insert(
        "risk_limit_status".into(),
        serde_json::json!(input.risk_limit_status.as_str()),
    );
    sector_extension.insert("protocol".into(), serde_json::json!(input.message.protocol.as_str()));
    let approval = ApprovalRecord {
        approver_ref: input.trader_pseudo_id.clone(),
        role: input.trader_role.clone(),
        decision: format!("{}_{}", input.side.as_str(), input.order_type.as_str()),
        reason_class: Some(input.risk_limit_status.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: format!(
            "trading_event.{}_{}",
            input.side.as_str(),
            input.order_type.as_str()
        ),
        event_hash,
        model,
        policy_id: "po_trading_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "trading_event".to_string(),
        jurisdiction_tag: input
            .jurisdiction_tag
            .clone()
            .unwrap_or_else(|| default_jurisdiction.to_string()),
        // MAR / MiFID II 5-year retention minimum.
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None,
        sector_extension,
        validator_signature_hex: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_seal_carries_protocol_and_risk_status() {
        let t = TradingEvent::demo();
        let seal = build_seal(&t, "FAB", "AE-CBUAE").unwrap();
        assert_eq!(seal.workflow_id, "trading_event");
        assert_eq!(
            seal.sector_extension.get("protocol").unwrap(),
            &serde_json::json!("fix_4_4")
        );
        assert_eq!(
            seal.sector_extension.get("risk_limit_status").unwrap(),
            &serde_json::json!("within_limits")
        );
    }

    #[test]
    fn order_side_and_type_strings_unique() {
        let sides = [OrderSide::Buy, OrderSide::Sell];
        let mut ids: Vec<&str> = sides.iter().map(|o| o.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
        let types = [OrderType::Market, OrderType::Limit, OrderType::Stop, OrderType::StopLimit];
        let mut ids2: Vec<&str> = types.iter().map(|o| o.as_str()).collect();
        ids2.sort_unstable();
        let m = ids2.len();
        ids2.dedup();
        assert_eq!(ids2.len(), m);
    }
}
