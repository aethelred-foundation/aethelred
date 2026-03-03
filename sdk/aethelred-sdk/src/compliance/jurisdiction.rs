//! # Jurisdiction Rules
//!
//! Defines rules for data processing within specific jurisdictions.

use super::*;
use std::collections::HashMap;

/// Jurisdiction-specific rules
#[derive(Debug, Clone)]
pub struct JurisdictionRules {
    /// Rules by jurisdiction
    rules: HashMap<Jurisdiction, JurisdictionRule>,
}

/// Rules for a specific jurisdiction
#[derive(Debug, Clone)]
pub struct JurisdictionRule {
    /// Jurisdiction this rule applies to
    pub jurisdiction: Jurisdiction,

    /// Allowed operation types
    pub allowed_operations: Vec<String>,

    /// Blocked operation types
    pub blocked_operations: Vec<String>,

    /// Required security level
    pub min_security_level: u8,

    /// Requires TEE for processing
    pub requires_tee: bool,

    /// Data center requirements
    pub datacenter_requirements: DataCenterRequirements,

    /// Working hours restrictions (if any)
    pub time_restrictions: Option<TimeRestrictions>,
}

/// Data center requirements
#[derive(Debug, Clone)]
pub struct DataCenterRequirements {
    /// Must be in specific countries
    pub allowed_countries: Vec<String>,

    /// Must use specific cloud providers
    pub allowed_providers: Vec<String>,

    /// Minimum security certifications
    pub required_certifications: Vec<String>,
}

/// Time-based restrictions
#[derive(Debug, Clone)]
pub struct TimeRestrictions {
    /// Allowed hours (0-23)
    pub allowed_hours: Vec<u8>,

    /// Timezone
    pub timezone: String,

    /// Allow weekends
    pub allow_weekends: bool,
}

impl JurisdictionRules {
    /// Create default jurisdiction rules
    pub fn default() -> Self {
        let mut rules = HashMap::new();

        // UAE rules
        rules.insert(
            Jurisdiction::UAE,
            JurisdictionRule {
                jurisdiction: Jurisdiction::UAE,
                allowed_operations: vec![
                    "read".to_string(),
                    "process".to_string(),
                    "compute".to_string(),
                    "store".to_string(),
                ],
                blocked_operations: vec!["export_to_non_gcc".to_string()],
                min_security_level: 4,
                requires_tee: true,
                datacenter_requirements: DataCenterRequirements {
                    allowed_countries: vec!["AE".to_string()],
                    allowed_providers: vec![
                        "AWS".to_string(),
                        "Azure".to_string(),
                        "OracleCloud".to_string(),
                        "LocalProvider".to_string(),
                    ],
                    required_certifications: vec![
                        "ISO27001".to_string(),
                        "UAE_NESA".to_string(),
                    ],
                },
                time_restrictions: None,
            },
        );

        // EU/GDPR rules
        rules.insert(
            Jurisdiction::EU,
            JurisdictionRule {
                jurisdiction: Jurisdiction::EU,
                allowed_operations: vec![
                    "read".to_string(),
                    "process".to_string(),
                    "compute".to_string(),
                    "store".to_string(),
                    "transfer_to_adequate".to_string(),
                ],
                blocked_operations: vec!["transfer_to_non_adequate".to_string()],
                min_security_level: 3,
                requires_tee: false,
                datacenter_requirements: DataCenterRequirements {
                    allowed_countries: vec![
                        "DE".to_string(),
                        "FR".to_string(),
                        "NL".to_string(),
                        "IE".to_string(),
                        "SE".to_string(),
                        "FI".to_string(),
                        // All EU countries...
                    ],
                    allowed_providers: vec![],
                    required_certifications: vec!["ISO27001".to_string()],
                },
                time_restrictions: None,
            },
        );

        // China rules
        rules.insert(
            Jurisdiction::China,
            JurisdictionRule {
                jurisdiction: Jurisdiction::China,
                allowed_operations: vec![
                    "read".to_string(),
                    "process".to_string(),
                    "compute".to_string(),
                    "store".to_string(),
                ],
                blocked_operations: vec![
                    "export".to_string(),
                    "transfer_cross_border".to_string(),
                ],
                min_security_level: 5,
                requires_tee: true,
                datacenter_requirements: DataCenterRequirements {
                    allowed_countries: vec!["CN".to_string()],
                    allowed_providers: vec![
                        "AlibabaCloud".to_string(),
                        "TencentCloud".to_string(),
                        "HuaweiCloud".to_string(),
                        "AWSChina".to_string(),
                        "AzureChina".to_string(),
                    ],
                    required_certifications: vec![
                        "MLPS".to_string(), // Multi-Level Protection Scheme
                    ],
                },
                time_restrictions: None,
            },
        );

        // US rules (general)
        rules.insert(
            Jurisdiction::US,
            JurisdictionRule {
                jurisdiction: Jurisdiction::US,
                allowed_operations: vec![
                    "read".to_string(),
                    "process".to_string(),
                    "compute".to_string(),
                    "store".to_string(),
                    "transfer".to_string(),
                ],
                blocked_operations: vec![],
                min_security_level: 2,
                requires_tee: false,
                datacenter_requirements: DataCenterRequirements {
                    allowed_countries: vec!["US".to_string()],
                    allowed_providers: vec![],
                    required_certifications: vec![],
                },
                time_restrictions: None,
            },
        );

        // Singapore rules
        rules.insert(
            Jurisdiction::Singapore,
            JurisdictionRule {
                jurisdiction: Jurisdiction::Singapore,
                allowed_operations: vec![
                    "read".to_string(),
                    "process".to_string(),
                    "compute".to_string(),
                    "store".to_string(),
                    "transfer_with_consent".to_string(),
                ],
                blocked_operations: vec![],
                min_security_level: 3,
                requires_tee: false,
                datacenter_requirements: DataCenterRequirements {
                    allowed_countries: vec!["SG".to_string()],
                    allowed_providers: vec![],
                    required_certifications: vec!["ISO27001".to_string()],
                },
                time_restrictions: None,
            },
        );

        JurisdictionRules { rules }
    }

    /// Check if an operation is allowed in a jurisdiction
    pub fn allows(&self, jurisdiction: Jurisdiction, operation: &str) -> bool {
        if let Some(rule) = self.rules.get(&jurisdiction) {
            // Check if explicitly blocked
            if rule.blocked_operations.iter().any(|o| o == operation) {
                return false;
            }

            // Check if explicitly allowed (if allowed list is specified)
            if !rule.allowed_operations.is_empty() {
                return rule.allowed_operations.iter().any(|o| o == operation);
            }

            // Default: allow
            true
        } else {
            // No rules for this jurisdiction, default to allow
            true
        }
    }

    /// Get rule for a jurisdiction
    pub fn get(&self, jurisdiction: &Jurisdiction) -> Option<&JurisdictionRule> {
        self.rules.get(jurisdiction)
    }

    /// Add or update a rule
    pub fn set(&mut self, rule: JurisdictionRule) {
        self.rules.insert(rule.jurisdiction, rule);
    }

    /// Check if jurisdiction requires TEE
    pub fn requires_tee(&self, jurisdiction: &Jurisdiction) -> bool {
        self.rules
            .get(jurisdiction)
            .map(|r| r.requires_tee)
            .unwrap_or(false)
    }

    /// Get minimum security level for jurisdiction
    pub fn min_security_level(&self, jurisdiction: &Jurisdiction) -> u8 {
        self.rules
            .get(jurisdiction)
            .map(|r| r.min_security_level)
            .unwrap_or(0)
    }

    /// Check if datacenter is allowed
    pub fn is_datacenter_allowed(
        &self,
        jurisdiction: &Jurisdiction,
        country: &str,
        provider: &str,
    ) -> bool {
        if let Some(rule) = self.rules.get(jurisdiction) {
            let reqs = &rule.datacenter_requirements;

            // Check country
            if !reqs.allowed_countries.is_empty()
                && !reqs.allowed_countries.iter().any(|c| c == country)
            {
                return false;
            }

            // Check provider
            if !reqs.allowed_providers.is_empty()
                && !reqs.allowed_providers.iter().any(|p| p == provider)
            {
                return false;
            }

            true
        } else {
            true
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uae_rules() {
        let rules = JurisdictionRules::default();

        assert!(rules.allows(Jurisdiction::UAE, "process"));
        assert!(!rules.allows(Jurisdiction::UAE, "export_to_non_gcc"));
        assert!(rules.requires_tee(&Jurisdiction::UAE));
    }

    #[test]
    fn test_china_rules() {
        let rules = JurisdictionRules::default();

        assert!(rules.allows(Jurisdiction::China, "process"));
        assert!(!rules.allows(Jurisdiction::China, "export"));
        assert!(rules.requires_tee(&Jurisdiction::China));
    }

    #[test]
    fn test_datacenter_allowed() {
        let rules = JurisdictionRules::default();

        assert!(rules.is_datacenter_allowed(&Jurisdiction::UAE, "AE", "AWS"));
        assert!(!rules.is_datacenter_allowed(&Jurisdiction::UAE, "US", "AWS"));
    }

    #[test]
    fn test_security_level() {
        let rules = JurisdictionRules::default();

        assert_eq!(rules.min_security_level(&Jurisdiction::UAE), 4);
        assert_eq!(rules.min_security_level(&Jurisdiction::US), 2);
    }
}
