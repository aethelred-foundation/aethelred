//! Finance workflows. Each module exposes a typed input + typed sealed output.

pub mod advisory;
pub mod aml_screening;
pub mod credit_decision;
pub mod trading_event;

pub use advisory::{Advisory, AdvisorySeal};
pub use aml_screening::{AmlAlert, AmlAlertSeal};
pub use credit_decision::{CreditDecision, CreditDecisionSeal};
pub use trading_event::{TradingEvent, TradingEventSeal};
