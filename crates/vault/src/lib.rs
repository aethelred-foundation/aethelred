#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(non_camel_case_types)]
//! # Cruzible TEE Enclave Service
//!
//! Stateless HTTP service that runs validator selection, MEV protection, and
//! reward calculation inside a Trusted Execution Environment (TEE).
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │                       CRUZIBLE TEE SERVICE                         │
//! ├──────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  HTTP API (:8547)                                                   │
//! │  ├── POST /select-validators    → TEE Validator Selection           │
//! │  ├── POST /calculate-rewards    → TEE Reward Calculation            │
//! │  ├── POST /order-transactions   → TEE MEV-Protected Ordering        │
//! │  ├── POST /verify-commitment    → Commit-Reveal Verification        │
//! │  ├── GET  /health               → Service Health Check              │
//! │  └── GET  /capabilities         → Service Capabilities              │
//! │                                                                      │
//! │  Core Modules:                                                      │
//! │  ├── validator_selection  — Score, rank, and select validators      │
//! │  ├── mev_protection       — Commit-reveal MEV ordering              │
//! │  ├── reward_calculator    — Fair reward distribution + Merkle tree  │
//! │  └── attestation          — TEE attestation generation              │
//! │                                                                      │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```

pub mod attestation;
pub mod mev_protection;
pub mod reward_calculator;
pub mod server;
pub mod types;
pub mod validator_selection;
