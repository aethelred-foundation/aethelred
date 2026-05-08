//! Defense regulator views.

use serde::{Deserialize, Serialize};

/// Defense regulator / governance jurisdiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseJurisdiction {
    /// UAE Tawazun Council — supplier sovereignty + offset.
    TawazunUae,
    /// UAE Armed Forces.
    UaeAf,
    /// NATO Principles of Responsible Use for AI in Defence.
    NatoPru,
    /// US DoD AI Ethical Principles.
    UsDodAiEp,
    /// UK MoD Defence AI Strategy.
    UkMod,
    /// US ITAR (International Traffic in Arms Regulations).
    Itar,
    /// EU Dual-Use Regulation (Regulation (EU) 2021/821).
    EuDualUse,
}

impl DefenseJurisdiction {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TawazunUae => "tawazun_uae",
            Self::UaeAf => "uae_af",
            Self::NatoPru => "nato_pru",
            Self::UsDodAiEp => "us_dod_ai_ep",
            Self::UkMod => "uk_mod",
            Self::Itar => "us_itar",
            Self::EuDualUse => "eu_dual_use",
        }
    }
    /// Seal jurisdiction tag.
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::TawazunUae => "AE-TAWAZUN",
            Self::UaeAf => "AE-AF",
            Self::NatoPru => "NATO-PRU",
            Self::UsDodAiEp => "US-DOD-AIEP",
            Self::UkMod => "UK-MOD",
            Self::Itar => "US-ITAR",
            Self::EuDualUse => "EU-DUAL-USE",
        }
    }
    /// Citations.
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::TawazunUae => vec![RegulatorCitation::tawazun_economic_programme()],
            Self::UaeAf => vec![RegulatorCitation::uae_af_te()],
            Self::NatoPru => vec![RegulatorCitation::nato_pru()],
            Self::UsDodAiEp => vec![RegulatorCitation::us_dod_ai_ethical_principles()],
            Self::UkMod => vec![RegulatorCitation::uk_mod_defence_ai_strategy()],
            Self::Itar => vec![RegulatorCitation::itar_22_cfr_120_130()],
            Self::EuDualUse => vec![RegulatorCitation::eu_dual_use_2021_821()],
        }
    }
}

/// A single regulator citation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorCitation {
    /// Regulator name.
    pub regulator: String,
    /// Citation id.
    pub citation_id: String,
    /// Section.
    pub section: String,
    /// Plain-English summary.
    pub summary: String,
}

impl RegulatorCitation {
    /// Tawazun Economic Programme.
    pub fn tawazun_economic_programme() -> Self {
        Self {
            regulator: "Tawazun Council (UAE)".into(),
            citation_id: "Tawazun Economic Programme".into(),
            section: "Industrial offset + supplier sovereignty".into(),
            summary: "UAE supplier sovereignty + offset value materialisation rules.".into(),
        }
    }
    /// UAE Armed Forces T&E.
    pub fn uae_af_te() -> Self {
        Self {
            regulator: "UAE Armed Forces".into(),
            citation_id: "Customer T&E".into(),
            section: "Acceptance + qualification".into(),
            summary: "Customer-side test, evaluation, acceptance, and qualification.".into(),
        }
    }
    /// NATO Principles of Responsible Use for AI in Defence.
    pub fn nato_pru() -> Self {
        Self {
            regulator: "NATO".into(),
            citation_id: "Principles of Responsible Use for AI in Defence".into(),
            section: "Lawfulness / Responsibility / Explainability / Reliability / Governability / Bias mitigation".into(),
            summary: "NATO PRU principles for AI in defence applications.".into(),
        }
    }
    /// US DoD AI Ethical Principles.
    pub fn us_dod_ai_ethical_principles() -> Self {
        Self {
            regulator: "US DoD".into(),
            citation_id: "AI Ethical Principles".into(),
            section: "Responsible / Equitable / Traceable / Reliable / Governable".into(),
            summary: "Five DoD AI ethical principles.".into(),
        }
    }
    /// UK MoD Defence AI Strategy 2022.
    pub fn uk_mod_defence_ai_strategy() -> Self {
        Self {
            regulator: "UK MoD".into(),
            citation_id: "Defence AI Strategy 2022".into(),
            section: "Five Ambitions".into(),
            summary: "UK MoD AI strategy ambitions including responsible AI in defence.".into(),
        }
    }
    /// ITAR 22 CFR §§120–130.
    pub fn itar_22_cfr_120_130() -> Self {
        Self {
            regulator: "US State Department (DDTC)".into(),
            citation_id: "22 CFR §§120–130".into(),
            section: "ITAR — International Traffic in Arms".into(),
            summary: "Cross-border defense article / technical data export controls.".into(),
        }
    }
    /// EU Dual-Use Regulation (Reg (EU) 2021/821).
    pub fn eu_dual_use_2021_821() -> Self {
        Self {
            regulator: "EU".into(),
            citation_id: "Regulation (EU) 2021/821".into(),
            section: "Dual-use".into(),
            summary: "EU dual-use export controls; cross-border component evidence.".into(),
        }
    }
}

/// A defense regulator view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorView {
    /// Jurisdiction.
    pub jurisdiction: DefenseJurisdiction,
    /// Citations.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id string.
    pub seal_id: String,
    /// Workflow id.
    pub workflow_id: String,
    /// Event class.
    pub event_class: String,
    /// Decision (e.g., `"approved_for_mission"`, `"rejected"`, `"escalated"`).
    pub decision: String,
    /// Tenant id.
    pub tenant_id: String,
}

impl RegulatorView {
    /// Project a [`aethelred_sandbox_core::DigitalSeal`].
    pub fn project(
        seal: &aethelred_sandbox_core::DigitalSeal,
        jurisdiction: DefenseJurisdiction,
        decision: impl Into<String>,
        event_class: impl Into<String>,
    ) -> Self {
        Self {
            jurisdiction,
            citations: jurisdiction.citations(),
            seal_id: seal.id_string(),
            workflow_id: seal.workflow_id.clone(),
            event_class: event_class.into(),
            decision: decision.into(),
            tenant_id: seal.tenant_id.clone(),
        }
    }
}
