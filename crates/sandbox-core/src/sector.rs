//! Sector enumeration shared by every sandbox crate.

use serde::{Deserialize, Serialize};
use std::fmt;

/// One of the seven Aethelred Infinity Sandbox sectors.
///
/// Used by [`crate::seal::DigitalSeal`] for the `sector` discriminator and by
/// [`crate::workflow::Workflow`] implementations to declare their domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sector {
    /// Banking, capital markets, treasury, AML / FCC, advisory.
    Finance,
    /// Clinical AI, genomics, payor / provider AI, pharma R&D-adjacent.
    Healthcare,
    /// Defense, dual-use, autonomous systems, mission AI, cyber CoE.
    Defense,
    /// Industrial supply chain, customs, batch traceability, ESG / carbon.
    SupplyChain,
    /// AI agents (passport, tool manifest, action trail, prompt-injection).
    AiAgents,
    /// Autonomous mobility (UGV / UAV / fleet) with ODD + safety case.
    AutonomousMobility,
    /// Research reproducibility, model release, training-run lineage.
    Research,
}

impl Sector {
    /// Stable lowercase string id (used in URLs, logs, file names, CLI flags).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Finance => "finance",
            Self::Healthcare => "healthcare",
            Self::Defense => "defense",
            Self::SupplyChain => "supply_chain",
            Self::AiAgents => "ai_agents",
            Self::AutonomousMobility => "autonomous_mobility",
            Self::Research => "research",
        }
    }

    /// Human-friendly title.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Finance => "Finance AI Assurance",
            Self::Healthcare => "Healthcare AI Assurance",
            Self::Defense => "Defense AI Assurance",
            Self::SupplyChain => "Supply Chain Integrity",
            Self::AiAgents => "AI Agent Control Plane",
            Self::AutonomousMobility => "Autonomous Mobility Assurance",
            Self::Research => "Research Reproducibility",
        }
    }

    /// All seven sectors in canonical order.
    pub const fn all() -> [Sector; 7] {
        [
            Self::Finance,
            Self::Healthcare,
            Self::Defense,
            Self::SupplyChain,
            Self::AiAgents,
            Self::AutonomousMobility,
            Self::Research,
        ]
    }
}

impl fmt::Display for Sector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Sector-specific metadata exposed by sector crates for catalogues / UIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectorMetadata {
    /// Sector discriminator.
    pub sector: Sector,
    /// Crate name (e.g., `"aethelred-sandbox-finance"`).
    pub crate_name: &'static str,
    /// Crate version (filled by sector crate via `env!("CARGO_PKG_VERSION")`).
    pub crate_version: &'static str,
    /// Short marketing-grade description.
    pub description: &'static str,
    /// List of canonical workflow ids exposed by this sector crate.
    pub workflows: Vec<&'static str>,
    /// List of regulator-shape views supported (e.g., `"cbuae"`, `"hipaa"`).
    pub regulator_views: Vec<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_sectors_have_unique_string_ids() {
        let ids: Vec<&str> = Sector::all().iter().map(|s| s.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
        assert_eq!(ids.len(), 7);
    }

    #[test]
    fn serde_roundtrip() {
        for s in Sector::all() {
            let j = serde_json::to_string(&s).unwrap();
            let s2: Sector = serde_json::from_str(&j).unwrap();
            assert_eq!(s, s2);
        }
    }
}
