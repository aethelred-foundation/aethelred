//! # Legal Linter
//!
//! **"The Lawyer in Your CI/CD Pipeline"**
//!
//! Static analysis tool that catches compliance violations before deployment.
//! Integrates into build systems to prevent non-compliant code from shipping.

use super::*;
use std::collections::HashSet;

// ============================================================================
// Legal Linter
// ============================================================================

/// Legal Linter for compliance configuration
pub struct LegalLinter {
    /// Enabled rule sets
    rule_sets: Vec<LintRuleSet>,
    /// Severity threshold for failure
    failure_threshold: LintSeverity,
}

impl LegalLinter {
    /// Create a new linter with default rules
    pub fn new() -> Self {
        LegalLinter {
            rule_sets: vec![
                LintRuleSet::DataLocalization,
                LintRuleSet::TransferRules,
                LintRuleSet::RetentionPolicies,
                LintRuleSet::EncryptionRequirements,
                LintRuleSet::ConsentManagement,
                LintRuleSet::AuditTrail,
            ],
            failure_threshold: LintSeverity::Error,
        }
    }

    /// Create linter with specific rule sets
    pub fn with_rules(rule_sets: Vec<LintRuleSet>) -> Self {
        LegalLinter {
            rule_sets,
            failure_threshold: LintSeverity::Error,
        }
    }

    /// Set the severity threshold for failure
    pub fn with_failure_threshold(mut self, threshold: LintSeverity) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Lint a compliance configuration
    pub fn lint(&self, config: &ComplianceConfig) -> LintResult {
        let mut issues = Vec::new();

        for rule_set in &self.rule_sets {
            issues.extend(self.run_rule_set(rule_set, config));
        }

        // Sort by severity
        issues.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Determine if linting passed
        let passed = !issues.iter().any(|i| i.severity >= self.failure_threshold);

        LintResult {
            passed,
            issues,
            rules_checked: self.rule_sets.len(),
            config_hash: Self::hash_config(config),
        }
    }

    /// Run a specific rule set
    fn run_rule_set(&self, rule_set: &LintRuleSet, config: &ComplianceConfig) -> Vec<LintIssue> {
        match rule_set {
            LintRuleSet::DataLocalization => self.check_data_localization(config),
            LintRuleSet::TransferRules => self.check_transfer_rules(config),
            LintRuleSet::RetentionPolicies => self.check_retention_policies(config),
            LintRuleSet::EncryptionRequirements => self.check_encryption_requirements(config),
            LintRuleSet::ConsentManagement => self.check_consent_management(config),
            LintRuleSet::AuditTrail => self.check_audit_trail(config),
            LintRuleSet::CrossBorder => self.check_cross_border(config),
            LintRuleSet::DataClassification => self.check_data_classification(config),
        }
    }

    // ========================================================================
    // Rule Implementations
    // ========================================================================

    /// Check data localization requirements
    fn check_data_localization(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        for regulation in &config.regulations {
            if regulation.requires_localization() {
                // Check if transfer rules respect localization
                for rule in &config.transfer_rules {
                    if let Some(to) = &rule.destination {
                        // Check if destination violates localization
                        match regulation {
                            Regulation::ChinaPIPL => {
                                if *to != Jurisdiction::China {
                                    issues.push(LintIssue {
                                        code: "PIPL_LOCALIZATION".to_string(),
                                        message: format!(
                                            "China PIPL requires data to remain in China, but transfer to {} is configured",
                                            to.display_name()
                                        ),
                                        severity: LintSeverity::Error,
                                        rule_set: LintRuleSet::DataLocalization,
                                        location: Some(format!("transfer_rule:{}", rule.name)),
                                        suggestion: "Remove cross-border transfer or use security assessment exemption".to_string(),
                                        legal_reference: Some("PIPL Article 38".to_string()),
                                    });
                                }
                            }
                            Regulation::UAEDataProtection => {
                                if *to != Jurisdiction::UAE && *to != Jurisdiction::GCC {
                                    issues.push(LintIssue {
                                        code: "UAE_LOCALIZATION".to_string(),
                                        message: format!(
                                            "UAE Data Protection Law restricts transfers, but transfer to {} is configured",
                                            to.display_name()
                                        ),
                                        severity: LintSeverity::Warning,
                                        rule_set: LintRuleSet::DataLocalization,
                                        location: Some(format!("transfer_rule:{}", rule.name)),
                                        suggestion: "Ensure regulatory approval for cross-border transfer".to_string(),
                                        legal_reference: Some("UAE Federal Decree-Law No. 45 of 2021".to_string()),
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        issues
    }

    /// Check transfer rules
    fn check_transfer_rules(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        // Check for EU data transfers without adequate protections
        if config.regulations.contains(&Regulation::GDPR) {
            for rule in &config.transfer_rules {
                if let (Some(from), Some(to)) = (&rule.source, &rule.destination) {
                    if *from == Jurisdiction::EU || from.is_part_of(&Jurisdiction::EU) {
                        if !Jurisdiction::EU.has_adequacy_with(to) {
                            // Check if SCCs are configured
                            if !rule.safeguards.contains(&TransferSafeguard::StandardContractualClauses) {
                                issues.push(LintIssue {
                                    code: "GDPR_TRANSFER_SAFEGUARD".to_string(),
                                    message: format!(
                                        "Transfer from EU to {} requires additional safeguards (no adequacy decision)",
                                        to.display_name()
                                    ),
                                    severity: LintSeverity::Error,
                                    rule_set: LintRuleSet::TransferRules,
                                    location: Some(format!("transfer_rule:{}", rule.name)),
                                    suggestion: "Add Standard Contractual Clauses (SCCs) or other appropriate safeguards".to_string(),
                                    legal_reference: Some("GDPR Article 46".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for conflicting transfer rules
        let mut seen_routes: HashSet<(Jurisdiction, Jurisdiction)> = HashSet::new();
        for rule in &config.transfer_rules {
            if let (Some(from), Some(to)) = (&rule.source, &rule.destination) {
                let route = (*from, *to);
                if seen_routes.contains(&route) {
                    issues.push(LintIssue {
                        code: "DUPLICATE_TRANSFER_RULE".to_string(),
                        message: format!(
                            "Duplicate transfer rule for {} -> {}",
                            from.display_name(),
                            to.display_name()
                        ),
                        severity: LintSeverity::Warning,
                        rule_set: LintRuleSet::TransferRules,
                        location: Some(format!("transfer_rule:{}", rule.name)),
                        suggestion: "Remove duplicate transfer rule".to_string(),
                        legal_reference: None,
                    });
                }
                seen_routes.insert(route);
            }
        }

        issues
    }

    /// Check retention policies
    fn check_retention_policies(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        for regulation in &config.regulations {
            if let Some(max_retention) = regulation.max_retention() {
                for (data_type, retention) in &config.retention_policies {
                    if *retention > max_retention {
                        issues.push(LintIssue {
                            code: "RETENTION_EXCEEDED".to_string(),
                            message: format!(
                                "Retention period for '{}' ({:?}) exceeds {} maximum ({:?})",
                                data_type,
                                retention,
                                regulation.display_name(),
                                max_retention
                            ),
                            severity: LintSeverity::Error,
                            rule_set: LintRuleSet::RetentionPolicies,
                            location: Some(format!("retention:{}", data_type)),
                            suggestion: format!(
                                "Reduce retention period to {:?} or less",
                                max_retention
                            ),
                            legal_reference: Some(format!(
                                "{} data retention requirements",
                                regulation.display_name()
                            )),
                        });
                    }
                }
            }
        }

        // Check for missing retention policies
        if config.retention_policies.is_empty() && !config.regulations.is_empty() {
            issues.push(LintIssue {
                code: "MISSING_RETENTION_POLICY".to_string(),
                message: "No data retention policies defined".to_string(),
                severity: LintSeverity::Warning,
                rule_set: LintRuleSet::RetentionPolicies,
                location: None,
                suggestion: "Define retention policies for all data types".to_string(),
                legal_reference: None,
            });
        }

        issues
    }

    /// Check encryption requirements
    fn check_encryption_requirements(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        // HIPAA requires encryption
        if config.regulations.contains(&Regulation::HIPAA) {
            issues.push(LintIssue {
                code: "HIPAA_ENCRYPTION_CHECK".to_string(),
                message: "HIPAA requires encryption of PHI at rest and in transit".to_string(),
                severity: LintSeverity::Info,
                rule_set: LintRuleSet::EncryptionRequirements,
                location: None,
                suggestion: "Verify AES-256 encryption is enabled for all PHI".to_string(),
                legal_reference: Some("45 CFR 164.312(a)(2)(iv)".to_string()),
            });
        }

        // PCI DSS encryption requirements
        if config.regulations.contains(&Regulation::PCIDSS) {
            issues.push(LintIssue {
                code: "PCI_ENCRYPTION_CHECK".to_string(),
                message: "PCI DSS requires strong cryptography for cardholder data".to_string(),
                severity: LintSeverity::Info,
                rule_set: LintRuleSet::EncryptionRequirements,
                location: None,
                suggestion: "Verify TLS 1.2+ and AES-256 are used for card data".to_string(),
                legal_reference: Some("PCI DSS Requirement 4".to_string()),
            });
        }

        issues
    }

    /// Check consent management
    fn check_consent_management(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        // GDPR consent requirements
        if config.regulations.contains(&Regulation::GDPR) {
            issues.push(LintIssue {
                code: "GDPR_CONSENT".to_string(),
                message: "GDPR requires lawful basis for processing (consent or other)".to_string(),
                severity: LintSeverity::Info,
                rule_set: LintRuleSet::ConsentManagement,
                location: None,
                suggestion: "Document lawful basis for each processing activity".to_string(),
                legal_reference: Some("GDPR Article 6".to_string()),
            });
        }

        issues
    }

    /// Check audit trail requirements
    fn check_audit_trail(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        // HIPAA audit requirements
        if config.regulations.contains(&Regulation::HIPAA) {
            issues.push(LintIssue {
                code: "HIPAA_AUDIT".to_string(),
                message: "HIPAA requires audit controls for PHI access".to_string(),
                severity: LintSeverity::Info,
                rule_set: LintRuleSet::AuditTrail,
                location: None,
                suggestion: "Enable audit logging for all PHI access and modifications".to_string(),
                legal_reference: Some("45 CFR 164.312(b)".to_string()),
            });
        }

        // SOC 2 audit requirements
        if config.regulations.contains(&Regulation::SOC2) {
            issues.push(LintIssue {
                code: "SOC2_AUDIT".to_string(),
                message: "SOC 2 requires comprehensive logging and monitoring".to_string(),
                severity: LintSeverity::Info,
                rule_set: LintRuleSet::AuditTrail,
                location: None,
                suggestion: "Implement centralized logging with 12-month retention".to_string(),
                legal_reference: Some("SOC 2 CC7.2".to_string()),
            });
        }

        issues
    }

    /// Check cross-border data flow
    fn check_cross_border(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        // Check for potential conflicts between jurisdictions
        for j1 in &config.jurisdictions {
            for j2 in &config.jurisdictions {
                if j1 != j2 {
                    // Check for conflicting localization requirements
                    if j1.regulations().iter().any(|r| r.requires_localization())
                        && j2.regulations().iter().any(|r| r.requires_localization())
                    {
                        issues.push(LintIssue {
                            code: "CONFLICTING_LOCALIZATION".to_string(),
                            message: format!(
                                "Both {} and {} require data localization - potential conflict",
                                j1.display_name(),
                                j2.display_name()
                            ),
                            severity: LintSeverity::Warning,
                            rule_set: LintRuleSet::CrossBorder,
                            location: None,
                            suggestion: "Consider separate data stores for each jurisdiction".to_string(),
                            legal_reference: None,
                        });
                    }
                }
            }
        }

        issues
    }

    /// Check data classification
    fn check_data_classification(&self, config: &ComplianceConfig) -> Vec<LintIssue> {
        let mut issues = Vec::new();

        if config.data_types.is_empty() {
            issues.push(LintIssue {
                code: "MISSING_DATA_CLASSIFICATION".to_string(),
                message: "No data types classified".to_string(),
                severity: LintSeverity::Warning,
                rule_set: LintRuleSet::DataClassification,
                location: None,
                suggestion: "Classify all data types by sensitivity level".to_string(),
                legal_reference: None,
            });
        }

        issues
    }

    /// Hash configuration for caching
    fn hash_config(config: &ComplianceConfig) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();

        for j in &config.jurisdictions {
            hasher.update(j.code().as_bytes());
        }
        for r in &config.regulations {
            hasher.update(r.display_name().as_bytes());
        }

        hex::encode(hasher.finalize())
    }
}

impl Default for LegalLinter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lint Types
// ============================================================================

/// Rule set categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LintRuleSet {
    DataLocalization,
    TransferRules,
    RetentionPolicies,
    EncryptionRequirements,
    ConsentManagement,
    AuditTrail,
    CrossBorder,
    DataClassification,
}

/// Lint severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LintSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// A single lint issue
#[derive(Debug, Clone)]
pub struct LintIssue {
    /// Issue code
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Severity
    pub severity: LintSeverity,
    /// Rule set that found this issue
    pub rule_set: LintRuleSet,
    /// Location in configuration
    pub location: Option<String>,
    /// Suggested fix
    pub suggestion: String,
    /// Legal reference (regulation article)
    pub legal_reference: Option<String>,
}

/// Result of linting
#[derive(Debug, Clone)]
pub struct LintResult {
    /// Whether linting passed
    pub passed: bool,
    /// All issues found
    pub issues: Vec<LintIssue>,
    /// Number of rules checked
    pub rules_checked: usize,
    /// Configuration hash
    pub config_hash: String,
}

impl LintResult {
    /// Get issues of a specific severity
    pub fn issues_by_severity(&self, severity: LintSeverity) -> Vec<&LintIssue> {
        self.issues.iter().filter(|i| i.severity == severity).collect()
    }

    /// Get error count
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.severity >= LintSeverity::Error).count()
    }

    /// Get warning count
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| i.severity == LintSeverity::Warning).count()
    }

    /// Generate human-readable report
    pub fn report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Legal Linter Report ===\n\n");
        report.push_str(&format!("Status: {}\n", if self.passed { "PASSED" } else { "FAILED" }));
        report.push_str(&format!("Rules Checked: {}\n", self.rules_checked));
        report.push_str(&format!(
            "Issues: {} errors, {} warnings\n\n",
            self.error_count(),
            self.warning_count()
        ));

        for (i, issue) in self.issues.iter().enumerate() {
            report.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                match issue.severity {
                    LintSeverity::Info => "INFO",
                    LintSeverity::Warning => "WARN",
                    LintSeverity::Error => "ERROR",
                    LintSeverity::Critical => "CRITICAL",
                },
                issue.code
            ));
            report.push_str(&format!("   {}\n", issue.message));
            if let Some(ref location) = issue.location {
                report.push_str(&format!("   Location: {}\n", location));
            }
            report.push_str(&format!("   Suggestion: {}\n", issue.suggestion));
            if let Some(ref legal_ref) = issue.legal_reference {
                report.push_str(&format!("   Reference: {}\n", legal_ref));
            }
            report.push('\n');
        }

        report
    }
}

// ============================================================================
// Transfer Rule (for linting)
// ============================================================================

/// Transfer rule in configuration
#[derive(Debug, Clone)]
pub struct TransferRule {
    pub name: String,
    pub source: Option<Jurisdiction>,
    pub destination: Option<Jurisdiction>,
    pub safeguards: Vec<TransferSafeguard>,
    pub requires_consent: bool,
}

/// Transfer safeguards
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferSafeguard {
    StandardContractualClauses,
    BindingCorporateRules,
    AdequacyDecision,
    ExplicitConsent,
    ContractNecessity,
    PublicInterest,
    LegalClaims,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_linter_creation() {
        let linter = LegalLinter::new();
        assert!(!linter.rule_sets.is_empty());
    }

    #[test]
    fn test_empty_config() {
        let linter = LegalLinter::new();
        let config = ComplianceConfig {
            jurisdictions: vec![],
            regulations: vec![],
            data_types: vec![],
            transfer_rules: vec![],
            retention_policies: HashMap::new(),
        };

        let result = linter.lint(&config);
        assert!(result.passed);
    }

    #[test]
    fn test_china_pipl_violation() {
        let linter = LegalLinter::new();
        let config = ComplianceConfig {
            jurisdictions: vec![Jurisdiction::China],
            regulations: vec![Regulation::ChinaPIPL],
            data_types: vec!["personal_data".to_string()],
            transfer_rules: vec![TransferRule {
                name: "export_to_us".to_string(),
                source: Some(Jurisdiction::China),
                destination: Some(Jurisdiction::US),
                safeguards: vec![],
                requires_consent: false,
            }],
            retention_policies: HashMap::new(),
        };

        let result = linter.lint(&config);
        assert!(!result.passed);
        assert!(result.issues.iter().any(|i| i.code == "PIPL_LOCALIZATION"));
    }

    #[test]
    fn test_gdpr_transfer_violation() {
        let linter = LegalLinter::new();
        let config = ComplianceConfig {
            jurisdictions: vec![Jurisdiction::EU, Jurisdiction::US],
            regulations: vec![Regulation::GDPR],
            data_types: vec!["personal_data".to_string()],
            transfer_rules: vec![TransferRule {
                name: "eu_to_us".to_string(),
                source: Some(Jurisdiction::EU),
                destination: Some(Jurisdiction::US),
                safeguards: vec![], // No SCCs!
                requires_consent: false,
            }],
            retention_policies: HashMap::new(),
        };

        let result = linter.lint(&config);
        assert!(!result.passed);
        assert!(result.issues.iter().any(|i| i.code == "GDPR_TRANSFER_SAFEGUARD"));
    }

    #[test]
    fn test_retention_violation() {
        let linter = LegalLinter::new();
        let mut retention = HashMap::new();
        retention.insert("logs".to_string(), Duration::from_secs(365 * 24 * 60 * 60 * 20)); // 20 years

        let config = ComplianceConfig {
            jurisdictions: vec![Jurisdiction::EU],
            regulations: vec![Regulation::GDPR],
            data_types: vec!["logs".to_string()],
            transfer_rules: vec![],
            retention_policies: retention,
        };

        let result = linter.lint(&config);
        assert!(result.issues.iter().any(|i| i.code == "RETENTION_EXCEEDED"));
    }
}
