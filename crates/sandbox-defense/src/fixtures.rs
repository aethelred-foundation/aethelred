//! Defense fixtures library — named, realistic scenarios.

use crate::workflows::autonomous_logistics::AutonomousLogistics;
use crate::workflows::cyber_defense::CyberDefenseEvent;
use crate::workflows::inspection_qa::InspectionQa;
use crate::workflows::sensor_fusion::SensorFusion;
use crate::DefenseSandbox;
use aethelred_sandbox_core::policy::Decision;
use aethelred_sandbox_core::SandboxResult;

/// One named, runnable defense scenario.
#[derive(Debug, Clone)]
pub enum DefenseFixture {
    /// Autonomous-logistics scenario.
    Logistics {
        /// id
        id: &'static str,
        /// description
        description: &'static str,
        /// tags
        tags: Vec<&'static str>,
        /// expected
        expected: Decision,
        /// input
        input: AutonomousLogistics,
    },
    /// Sensor-fusion scenario.
    Fusion {
        /// id
        id: &'static str,
        /// description
        description: &'static str,
        /// tags
        tags: Vec<&'static str>,
        /// expected
        expected: Decision,
        /// input
        input: SensorFusion,
    },
    /// Inspection scenario.
    Inspection {
        /// id
        id: &'static str,
        /// description
        description: &'static str,
        /// tags
        tags: Vec<&'static str>,
        /// expected
        expected: Decision,
        /// input
        input: InspectionQa,
    },
    /// Cyber-defense scenario.
    Cyber {
        /// id
        id: &'static str,
        /// description
        description: &'static str,
        /// tags
        tags: Vec<&'static str>,
        /// expected
        expected: Decision,
        /// input
        input: CyberDefenseEvent,
    },
}

impl DefenseFixture {
    /// Stable id.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Logistics { id, .. }
            | Self::Fusion { id, .. }
            | Self::Inspection { id, .. }
            | Self::Cyber { id, .. } => id,
        }
    }
    /// Description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Logistics { description, .. }
            | Self::Fusion { description, .. }
            | Self::Inspection { description, .. }
            | Self::Cyber { description, .. } => description,
        }
    }
    /// Tags.
    pub fn tags(&self) -> &[&'static str] {
        match self {
            Self::Logistics { tags, .. }
            | Self::Fusion { tags, .. }
            | Self::Inspection { tags, .. }
            | Self::Cyber { tags, .. } => tags,
        }
    }
    /// Expected decision.
    pub fn expected(&self) -> Decision {
        match self {
            Self::Logistics { expected, .. }
            | Self::Fusion { expected, .. }
            | Self::Inspection { expected, .. }
            | Self::Cyber { expected, .. } => *expected,
        }
    }

    /// Run.
    pub fn run(&self, sandbox: &DefenseSandbox) -> SandboxResult<()> {
        let result: SandboxResult<()> = match self {
            Self::Logistics { input, .. } => {
                sandbox.seal_autonomous_logistics(input.clone()).map(|_| ())
            }
            Self::Fusion { input, .. } => sandbox.seal_sensor_fusion(input.clone()).map(|_| ()),
            Self::Inspection { input, .. } => sandbox.seal_inspection(input.clone()).map(|_| ()),
            Self::Cyber { input, .. } => sandbox.seal_cyber_defense(input.clone()).map(|_| ()),
        };
        match (self.expected(), result) {
            (Decision::Allow | Decision::ReviewRequired, Ok(_)) => Ok(()),
            (Decision::FailClosed, Err(e)) if e.is_policy_denial() => Ok(()),
            (expected, actual) => Err(aethelred_sandbox_core::SandboxError::Other(format!(
                "fixture `{}` expected {:?}, got {:?}",
                self.id(),
                expected,
                actual
            ))),
        }
    }
}

/// Defense fixture catalog.
pub struct DefenseFixtures;

impl DefenseFixtures {
    /// All fixtures.
    pub fn all() -> Vec<DefenseFixture> {
        let mut v = Vec::new();
        v.extend(Self::happy_path());
        v.extend(Self::regulatory_edge());
        v.extend(Self::adversarial());
        v
    }

    /// Happy paths.
    pub fn happy_path() -> Vec<DefenseFixture> {
        vec![
            DefenseFixture::Logistics {
                id: "defense.logistics.happy.within_odd",
                description: "Autonomous logistics step within ODD with mission-commander bind",
                tags: vec!["happy", "tawazun", "logistics"],
                expected: Decision::Allow,
                input: AutonomousLogistics::demo(),
            },
            DefenseFixture::Fusion {
                id: "defense.fusion.happy.routine_track",
                description: "Routine sensor-fusion track with operator review",
                tags: vec!["happy", "tawazun", "fusion"],
                expected: Decision::Allow,
                input: SensorFusion::demo(),
            },
            DefenseFixture::Inspection {
                id: "defense.inspection.happy.qa_pass",
                description: "Inspection QA lot, no defects",
                tags: vec!["happy", "tawazun", "inspection"],
                expected: Decision::Allow,
                input: InspectionQa::demo(),
            },
            DefenseFixture::Cyber {
                id: "defense.cyber.happy.benign_alert",
                description: "Benign cyber alert dismissed by analyst",
                tags: vec!["happy", "tawazun", "cyber"],
                expected: Decision::Allow,
                input: CyberDefenseEvent::demo(),
            },
        ]
    }

    /// Edge cases — soft-fail to ReviewRequired.
    pub fn regulatory_edge() -> Vec<DefenseFixture> {
        let mut out_of_odd = AutonomousLogistics::demo();
        out_of_odd.within_odd = false;

        vec![DefenseFixture::Logistics {
            id: "defense.logistics.edge.outside_odd",
            description: "Outside ODD — soft-fails to escalation (optional gate)",
            tags: vec!["edge", "odd", "logistics"],
            expected: Decision::ReviewRequired,
            input: out_of_odd,
        }]
    }

    /// Adversarial. (Most defense gates are required + non-weaponized scope
    /// is enforced via seal extension; the ODD-out scenario is in
    /// `regulatory_edge` because the gate is optional.)
    pub fn adversarial() -> Vec<DefenseFixture> {
        vec![]
    }

    /// Subset by tag.
    pub fn by_tag(tag: &str) -> Vec<DefenseFixture> {
        Self::all()
            .into_iter()
            .filter(|f| f.tags().contains(&tag))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_runs() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        for f in DefenseFixtures::happy_path() {
            f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
        }
    }

    #[test]
    fn adversarial_runs() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        for f in DefenseFixtures::adversarial() {
            f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
        }
    }

    #[test]
    fn regulatory_edge_runs() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        for f in DefenseFixtures::regulatory_edge() {
            f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
        }
    }

    #[test]
    fn unique_ids() {
        let ids: Vec<&str> = DefenseFixtures::all().iter().map(|f| f.id()).collect();
        let mut s = ids.clone();
        s.sort_unstable();
        let n = s.len();
        s.dedup();
        assert_eq!(s.len(), n);
    }

    #[test]
    fn ids_namespaced() {
        for f in DefenseFixtures::all() {
            assert!(f.id().starts_with("defense."));
        }
    }
}
