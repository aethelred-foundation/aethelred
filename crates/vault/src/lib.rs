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
