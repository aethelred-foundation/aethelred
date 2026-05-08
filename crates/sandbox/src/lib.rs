#![allow(clippy::panicking_unwrap)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::match_like_matches_macro)]
#![allow(unused_doc_comments)]
#![allow(unexpected_cfgs)]
#![allow(ambiguous_glob_reexports)]
#![allow(clippy::upper_case_acronyms)]
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
//! # Aethelred Infinity Sandbox
//!
//! **"The World's First Sovereign AI Risk Simulator"**
//!
//! Most sandboxes answer: *"Does my code work?"*
//! The Aethelred Sandbox answers: *"Will my bank survive a subpoena,
//! a quantum attack, or a data leak?"*
//!
//! It is not just a developer tool; it is a **C-Level Risk Simulator**.
//!
//! ## The Three Layers
//!
//! ### Layer 1: The Interface
//! - **Hardware-Aware Runtime**: Choose target (SGX, H100, CPU)
//! - **Scenario Library**: Bank-grade templates (Trade Finance, Genomics)
//! - **Multi-Party Clean Rooms**: Blind collaboration with hidden variables
//! - **Immutable Audit Logs**: SOC2 report generator
//!
//! ### Layer 2: The Simulation Engine
//! - **Regulatory Hypervisor**: The "Lawyer in the Code"
//! - **AI Gas Profiler**: The "CFO in the Code"
//! - **Sovereign Border Visualizer**: 3D data flow map
//!
//! ### Layer 3: The War Room
//! - **Quantum Time-Machine**: Simulate Q-Day attacks
//! - **Adversarial War Room**: Inject malicious nodes
//! - **Capture The Flag**: Gamified security testing
//!
//! ## The Hero Workflow
//!
//! 1. Load "UAE-Singapore Trade Settlement" from Scenario Library
//! 2. Sovereign Visualizer draws 3D map of data flow
//! 3. Set Regulatory Hypervisor to "Strict Sovereignty"
//! 4. Invite DBS colleague to Multi-Party Clean Room
//! 5. AI Gas Profiler warns: "5 AETHEL, 400 Watts"
//! 6. Run on Hardware-Aware Runtime targeting Intel SGX
//! 7. Hit Quantum Time-Machine - watch Dilithium3 survive
//! 8. Export Immutable Audit Log as SOC2 PDF

// ============================================================================
// Layer 1: The Interface
// ============================================================================

/// Hardware-Aware Runtime - Choose your execution target
pub mod runtime;

/// Scenario Library - Bank-grade templates
pub mod scenarios;

/// Enterprise-grade regulated AI sandbox packs
pub mod enterprise_sandboxes;

/// Multi-Party Clean Rooms - Blind collaboration
pub mod cleanroom;

// ============================================================================
// Layer 2: The Simulation Engine
// ============================================================================

/// Regulatory Hypervisor - The "Lawyer in the Code"
pub mod regulatory;

/// AI Gas Profiler - The "CFO in the Code"
pub mod profiler;

/// Sovereign Border Visualizer - 3D data flow map
pub mod visualizer;

// ============================================================================
// Layer 3: The War Room
// ============================================================================

/// Quantum Time-Machine - Simulate Q-Day attacks
pub mod quantum;

/// Adversarial War Room - Inject malicious nodes
pub mod adversarial;

/// Capture The Flag - Gamified security testing
pub mod ctf;

// ============================================================================
// Core Infrastructure
// ============================================================================

/// Core types and sandbox engine
pub mod core;

// Re-exports
pub use adversarial::*;
pub use cleanroom::*;
pub use core::*;
pub use ctf::*;
pub use enterprise_sandboxes::*;
pub use profiler::*;
pub use quantum::*;
pub use regulatory::*;
pub use runtime::*;
pub use scenarios::*;
pub use visualizer::*;

// ============================================================================
// v0.2 — Infinity Sandbox sector crates (gated by the `infinity` feature)
// ============================================================================

/// The seven production-grade sector sandboxes — Finance, Healthcare,
/// Defense, Supply Chain, AI Agents, Autonomous Mobility, Research — built
/// on a shared [`infinity::core`] foundation that uses the workspace
/// `aethelred-core::crypto` primitives (real SHA-256 / Merkle / hybrid
/// ECDSA + Dilithium-3 signatures).
///
/// Each sector exposes a plug-and-play `<Sector>Sandbox::quickstart(tenant)`
/// constructor and a `prelude` module so customers can integrate in three
/// lines:
///
/// ```ignore
/// use aethelred_sandbox::infinity::finance::prelude::*;
/// let sb = FinanceSandbox::quickstart("FAB").unwrap();
/// let seal = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
/// ```
///
/// Enable with `features = ["infinity"]` on the `aethelred-sandbox`
/// dependency, or depend directly on a specific
/// `aethelred-sandbox-<sector>` crate to avoid pulling all seven.
#[cfg(feature = "infinity")]
pub mod infinity {
    /// Shared foundation.
    pub use aethelred_sandbox_core as core;

    /// Finance AI Assurance — credit, AML, trading, advisory.
    pub mod finance {
        pub use aethelred_sandbox_finance::*;
    }

    /// Healthcare AI Assurance — genomics, clinical AI, ambient scribe, claims.
    pub mod healthcare {
        pub use aethelred_sandbox_healthcare::*;
    }

    /// Defense AI Assurance — autonomous logistics, sensor fusion, inspection,
    /// cyber defense (with air-gap mode).
    pub mod defense {
        pub use aethelred_sandbox_defense::*;
    }

    /// Supply Chain Integrity — batch, customs, carbon, methane.
    pub mod supply_chain {
        pub use aethelred_sandbox_supply_chain::*;
    }

    /// AI Agent Control Plane — passport, tool manifest, action trail,
    /// prompt-injection defense.
    pub mod ai_agents {
        pub use aethelred_sandbox_ai_agents::*;
    }

    /// Autonomous Mobility Assurance — ODD validation, mission replay,
    /// perception events, safety case.
    pub mod autonomous_mobility {
        pub use aethelred_sandbox_autonomous_mobility::*;
    }

    /// Research Reproducibility — experiment runs, model release,
    /// reproducibility checks, training-run lineage.
    pub mod research {
        pub use aethelred_sandbox_research::*;
    }
}
