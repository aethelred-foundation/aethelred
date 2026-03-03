//! # Cross-Border Transfer Rules
//!
//! Implements data transfer validation between jurisdictions.

use super::*;
use std::collections::HashMap;

// ============================================================================
// Transfer Rules Engine
// ============================================================================

/// Transfer rules engine
#[derive(Debug, Clone)]
pub struct TransferRules {
    /// Pre-approved transfer routes
    approved_routes: HashMap<(Jurisdiction, Jurisdiction), TransferApproval>,

    /// Blocked transfer routes
    blocked_routes: Vec<(Jurisdiction, Jurisdiction, String)>,
}

impl TransferRules {
    /// Create default transfer rules
    pub fn default() -> Self {
        let mut rules = TransferRules {
            approved_routes: HashMap::new(),
            blocked_routes: Vec::new(),
        };

        // EU adequacy decisions
        let eu_adequate = vec![
            (Jurisdiction::EU, Jurisdiction::Switzerland, "Adequacy Decision 2000/518/EC"),
            (Jurisdiction::EU, Jurisdiction::Japan, "Adequacy Decision 2019/419"),
            (Jurisdiction::EU, Jurisdiction::UK, "Adequacy Decision 2021/1772"),
            (Jurisdiction::EU, Jurisdiction::Canada, "Adequacy Decision 2002/2/EC"),
            (Jurisdiction::EU, Jurisdiction::SouthKorea, "Adequacy Decision 2022"),
        ];

        for (from, to, reference) in eu_adequate {
            rules.approved_routes.insert(
                (from, to),
                TransferApproval {
                    mechanism: TransferMechanism::AdequacyDecision,
                    reference: reference.to_string(),
                    conditions: vec![],
                    expiry: None,
                },
            );
            // Bi-directional
            rules.approved_routes.insert(
                (to, from),
                TransferApproval {
                    mechanism: TransferMechanism::AdequacyDecision,
                    reference: reference.to_string(),
                    conditions: vec![],
                    expiry: None,
                },
            );
        }

        // GCC mutual recognition
        let gcc_countries = vec![
            Jurisdiction::UAE,
            Jurisdiction::SaudiArabia,
        ];

        for from in &gcc_countries {
            for to in &gcc_countries {
                if from != to {
                    rules.approved_routes.insert(
                        (*from, *to),
                        TransferApproval {
                            mechanism: TransferMechanism::MutualRecognition,
                            reference: "GCC Data Protection Framework".to_string(),
                            conditions: vec!["Processing for approved purposes".to_string()],
                            expiry: None,
                        },
                    );
                }
            }
        }

        // Block transfers from China to most destinations (PIPL)
        rules.blocked_routes.push((
            Jurisdiction::China,
            Jurisdiction::Global,
            "PIPL Article 38 requires security assessment".to_string(),
        ));

        rules
    }

    /// Check if a transfer is allowed
    pub fn check(
        &self,
        from: Jurisdiction,
        to: Jurisdiction,
        regulations: &[Regulation],
        policies: &HashMap<Regulation, RegulationPolicy>,
    ) -> TransferResult {
        // Same jurisdiction is always allowed
        if from == to || from.is_part_of(&to) || to.is_part_of(&from) {
            return TransferResult::Allowed {
                mechanism: TransferMechanism::SameJurisdiction,
                conditions: vec![],
            };
        }

        // Check blocked routes
        for (blocked_from, blocked_to, reason) in &self.blocked_routes {
            if (*blocked_from == from || *blocked_from == Jurisdiction::Global)
                && (*blocked_to == to || *blocked_to == Jurisdiction::Global)
            {
                return TransferResult::Blocked {
                    reason: reason.clone(),
                    regulation: None,
                };
            }
        }

        // Check pre-approved routes
        if let Some(approval) = self.approved_routes.get(&(from, to)) {
            return TransferResult::Allowed {
                mechanism: approval.mechanism.clone(),
                conditions: approval.conditions.clone(),
            };
        }

        // Check regulation-specific policies
        for regulation in regulations {
            if let Some(policy) = policies.get(regulation) {
                // Check if destination is in allowed list
                if !policy.allowed_transfers.is_empty()
                    && !policy.allowed_transfers.contains(&to)
                    && !policy.allowed_transfers.iter().any(|j| to.is_part_of(j))
                {
                    // Check if it's a localization requirement
                    if policy.data_localization {
                        return TransferResult::Blocked {
                            reason: format!(
                                "{} requires data localization",
                                regulation.display_name()
                            ),
                            regulation: Some(regulation.clone()),
                        };
                    }

                    // Might be allowed with safeguards
                    return TransferResult::RequiresSafeguards {
                        available_mechanisms: vec![
                            TransferMechanism::StandardContractualClauses,
                            TransferMechanism::BindingCorporateRules,
                            TransferMechanism::ExplicitConsent,
                        ],
                        regulation: regulation.clone(),
                    };
                }
            }
        }

        // Default: allowed (no specific restrictions found)
        TransferResult::Allowed {
            mechanism: TransferMechanism::NoRestriction,
            conditions: vec![],
        }
    }

    /// Add an approved route
    pub fn approve_route(
        &mut self,
        from: Jurisdiction,
        to: Jurisdiction,
        approval: TransferApproval,
    ) {
        self.approved_routes.insert((from, to), approval);
    }

    /// Block a route
    pub fn block_route(&mut self, from: Jurisdiction, to: Jurisdiction, reason: String) {
        self.blocked_routes.push((from, to, reason));
    }

    /// Check if route exists
    pub fn has_approved_route(&self, from: Jurisdiction, to: Jurisdiction) -> bool {
        self.approved_routes.contains_key(&(from, to))
    }
}

// ============================================================================
// Transfer Types
// ============================================================================

/// Result of transfer check
#[derive(Debug, Clone)]
pub enum TransferResult {
    /// Transfer is allowed
    Allowed {
        mechanism: TransferMechanism,
        conditions: Vec<String>,
    },

    /// Transfer is blocked
    Blocked {
        reason: String,
        regulation: Option<Regulation>,
    },

    /// Transfer requires additional safeguards
    RequiresSafeguards {
        available_mechanisms: Vec<TransferMechanism>,
        regulation: Regulation,
    },
}

impl TransferResult {
    /// Check if transfer is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, TransferResult::Allowed { .. })
    }

    /// Get the mechanism if allowed
    pub fn mechanism(&self) -> Option<&TransferMechanism> {
        match self {
            TransferResult::Allowed { mechanism, .. } => Some(mechanism),
            _ => None,
        }
    }
}

/// Transfer mechanism / legal basis
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferMechanism {
    /// Same jurisdiction (no transfer)
    SameJurisdiction,

    /// No restrictions apply
    NoRestriction,

    /// EU Adequacy Decision
    AdequacyDecision,

    /// Standard Contractual Clauses (SCCs)
    StandardContractualClauses,

    /// Binding Corporate Rules (BCRs)
    BindingCorporateRules,

    /// Explicit consent from data subject
    ExplicitConsent,

    /// Contract necessity
    ContractNecessity,

    /// Public interest
    PublicInterest,

    /// Legal claims
    LegalClaims,

    /// Mutual recognition agreement
    MutualRecognition,

    /// Regulatory approval
    RegulatoryApproval,

    /// Security assessment (China)
    SecurityAssessment,
}

impl TransferMechanism {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            TransferMechanism::SameJurisdiction => "Same Jurisdiction",
            TransferMechanism::NoRestriction => "No Restriction",
            TransferMechanism::AdequacyDecision => "Adequacy Decision",
            TransferMechanism::StandardContractualClauses => "Standard Contractual Clauses (SCCs)",
            TransferMechanism::BindingCorporateRules => "Binding Corporate Rules (BCRs)",
            TransferMechanism::ExplicitConsent => "Explicit Consent",
            TransferMechanism::ContractNecessity => "Contract Necessity",
            TransferMechanism::PublicInterest => "Public Interest",
            TransferMechanism::LegalClaims => "Legal Claims",
            TransferMechanism::MutualRecognition => "Mutual Recognition",
            TransferMechanism::RegulatoryApproval => "Regulatory Approval",
            TransferMechanism::SecurityAssessment => "Security Assessment",
        }
    }

    /// GDPR article reference
    pub fn gdpr_reference(&self) -> Option<&'static str> {
        match self {
            TransferMechanism::AdequacyDecision => Some("Article 45"),
            TransferMechanism::StandardContractualClauses => Some("Article 46(2)(c)"),
            TransferMechanism::BindingCorporateRules => Some("Article 47"),
            TransferMechanism::ExplicitConsent => Some("Article 49(1)(a)"),
            TransferMechanism::ContractNecessity => Some("Article 49(1)(b)"),
            TransferMechanism::PublicInterest => Some("Article 49(1)(d)"),
            TransferMechanism::LegalClaims => Some("Article 49(1)(e)"),
            _ => None,
        }
    }
}

/// Pre-approved transfer route
#[derive(Debug, Clone)]
pub struct TransferApproval {
    /// Legal mechanism
    pub mechanism: TransferMechanism,

    /// Legal reference
    pub reference: String,

    /// Conditions for transfer
    pub conditions: Vec<String>,

    /// Expiry date (if applicable)
    pub expiry: Option<std::time::SystemTime>,
}

// ============================================================================
// Transfer Validator
// ============================================================================

/// Real-time transfer validator
pub struct TransferValidator {
    rules: TransferRules,
}

impl TransferValidator {
    /// Create a new validator
    pub fn new(rules: TransferRules) -> Self {
        TransferValidator { rules }
    }

    /// Validate a data transfer request
    pub fn validate(&self, request: &TransferRequest) -> TransferValidation {
        let result = self.rules.check(
            request.source,
            request.destination,
            &request.regulations,
            &HashMap::new(), // Would use actual policies
        );

        match result {
            TransferResult::Allowed { mechanism, conditions } => TransferValidation {
                allowed: true,
                mechanism: Some(mechanism),
                conditions,
                violations: vec![],
                required_actions: vec![],
            },
            TransferResult::Blocked { reason, regulation } => TransferValidation {
                allowed: false,
                mechanism: None,
                conditions: vec![],
                violations: vec![TransferViolation {
                    code: "TRANSFER_BLOCKED".to_string(),
                    reason,
                    regulation,
                }],
                required_actions: vec!["Process data in source jurisdiction".to_string()],
            },
            TransferResult::RequiresSafeguards { available_mechanisms, regulation } => {
                TransferValidation {
                    allowed: false,
                    mechanism: None,
                    conditions: vec![],
                    violations: vec![TransferViolation {
                        code: "SAFEGUARDS_REQUIRED".to_string(),
                        reason: "Transfer requires additional safeguards".to_string(),
                        regulation: Some(regulation),
                    }],
                    required_actions: available_mechanisms
                        .iter()
                        .map(|m| format!("Implement: {}", m.display_name()))
                        .collect(),
                }
            }
        }
    }
}

/// Transfer request
#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub source: Jurisdiction,
    pub destination: Jurisdiction,
    pub data_types: Vec<String>,
    pub regulations: Vec<Regulation>,
    pub purpose: String,
}

/// Transfer validation result
#[derive(Debug, Clone)]
pub struct TransferValidation {
    pub allowed: bool,
    pub mechanism: Option<TransferMechanism>,
    pub conditions: Vec<String>,
    pub violations: Vec<TransferViolation>,
    pub required_actions: Vec<String>,
}

/// Transfer violation
#[derive(Debug, Clone)]
pub struct TransferViolation {
    pub code: String,
    pub reason: String,
    pub regulation: Option<Regulation>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_jurisdiction() {
        let rules = TransferRules::default();
        let result = rules.check(
            Jurisdiction::UAE,
            Jurisdiction::UAE,
            &[],
            &HashMap::new(),
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_eu_adequacy() {
        let rules = TransferRules::default();
        let result = rules.check(
            Jurisdiction::EU,
            Jurisdiction::Switzerland,
            &[Regulation::GDPR],
            &HashMap::new(),
        );
        assert!(result.is_allowed());
        assert_eq!(
            result.mechanism(),
            Some(&TransferMechanism::AdequacyDecision)
        );
    }

    #[test]
    fn test_gcc_transfer() {
        let rules = TransferRules::default();
        let result = rules.check(
            Jurisdiction::UAE,
            Jurisdiction::SaudiArabia,
            &[Regulation::UAEDataProtection],
            &HashMap::new(),
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_china_blocked() {
        let rules = TransferRules::default();
        let result = rules.check(
            Jurisdiction::China,
            Jurisdiction::US,
            &[Regulation::ChinaPIPL],
            &HashMap::new(),
        );
        assert!(!result.is_allowed());
    }
}
