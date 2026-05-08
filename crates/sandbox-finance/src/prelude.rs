//! Single-import prelude for finance.

pub use crate::fixtures::{FinanceFixture, FinanceFixtures};
pub use crate::regulators::{FinanceJurisdiction, RegulatorCitation, RegulatorView};
pub use crate::sandbox::{FinanceSandbox, FinanceSandboxBuilder};
pub use crate::workflows::advisory::{Advisory, AdvisorySeal, ClientClass, Suitability};
pub use crate::workflows::aml_screening::{AmlAlert, AmlAlertOutcome, AmlAlertSeal, AmlTypology};
pub use crate::workflows::credit_decision::{
    CreditDecision, CreditDecisionBuilder, CreditDecisionSeal, CreditOutcome,
};
pub use crate::workflows::trading_event::{
    OrderSide, OrderType, RiskLimitStatus, TradingEvent, TradingEventSeal,
};

// Core re-exports for one-shot importing.
pub use aethelred_sandbox_core::{
    audit::{AuditFormat, AuditTrail},
    error_code::{ErrorCategory, ErrorCode},
    verify::{VerificationReport, Verifier},
    DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
    SandboxResult, SealEnvelope, Sector, Sha256Digest,
};
