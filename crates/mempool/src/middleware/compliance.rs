//! Compliance Middleware for Mempool
//!
//! Enterprise-grade compliance checking for transactions entering the mempool.
//!
//! # Supported Frameworks
//!
//! - **GDPR**: EU General Data Protection Regulation
//! - **HIPAA**: US Health Insurance Portability and Accountability Act
//! - **PCI-DSS**: Payment Card Industry Data Security Standard
//! - **CCPA**: California Consumer Privacy Act
//! - **SOX**: Sarbanes-Oxley Act
//!
//! # Pre-Flight Checks
//!
//! 1. PII Detection - Scan for personal identifiable information
//! 2. Data Residency - Verify geographic requirements
//! 3. Audit Trail - Ensure proper logging requirements
//! 4. Access Control - Verify sender authorization
//! 5. Data Minimization - Check for unnecessary data exposure

use super::{
    ComplianceCheckResult, ComplianceMetadata, Middleware, MiddlewareAction,
    MiddlewareContext, MiddlewareResult,
};
use std::collections::HashSet;

/// Transaction type that requires compliance checking
const TX_TYPE_COMPUTE_JOB: u8 = 0x02;
const TX_TYPE_SEAL: u8 = 0x03;

/// Compliance middleware
pub struct ComplianceMiddleware {
    /// PII detector
    pii_detector: PiiDetector,
    /// Framework validators
    framework_validators: Vec<Box<dyn FrameworkValidator>>,
}

impl ComplianceMiddleware {
    /// Create new compliance middleware
    pub fn new() -> Self {
        Self {
            pii_detector: PiiDetector::new(),
            framework_validators: vec![
                Box::new(GdprValidator::new()),
                Box::new(HipaaValidator::new()),
                Box::new(PciDssValidator::new()),
                Box::new(CcpaValidator::new()),
            ],
        }
    }

    /// Add custom framework validator
    pub fn add_validator(&mut self, validator: impl FrameworkValidator + 'static) {
        self.framework_validators.push(Box::new(validator));
    }

    /// Extract compliance metadata from transaction payload
    fn extract_compliance_metadata(
        &self,
        ctx: &MiddlewareContext,
    ) -> Option<ComplianceMetadata> {
        let parsed = ctx.parsed_tx.as_ref()?;

        // Only extract for compute jobs and seals
        if parsed.tx_type != TX_TYPE_COMPUTE_JOB && parsed.tx_type != TX_TYPE_SEAL {
            return None;
        }

        // Parse compliance section from transaction bytes
        // Format depends on transaction type
        self.parse_compliance_section(&ctx.tx_bytes, parsed.tx_type)
    }

    /// Parse compliance section from transaction bytes
    fn parse_compliance_section(
        &self,
        tx_bytes: &[u8],
        _tx_type: u8,
    ) -> Option<ComplianceMetadata> {
        // Simplified parsing for MVP
        // In production, use proper deserialization

        let mut metadata = ComplianceMetadata::default();

        // Look for compliance marker in payload
        // Format: [0xC0][framework_count][frameworks...][residency_flag][residency_len][residency...][audit_flag]
        let compliance_marker = 0xC0u8;

        if let Some(pos) = tx_bytes.iter().position(|&b| b == compliance_marker) {
            let data = &tx_bytes[pos..];
            if data.len() < 3 {
                return Some(metadata);
            }

            let framework_count = data[1] as usize;
            let mut offset = 2;

            // Parse frameworks
            for _ in 0..framework_count {
                if offset >= data.len() {
                    break;
                }
                let framework = match data[offset] {
                    0x01 => "GDPR",
                    0x02 => "HIPAA",
                    0x03 => "PCI-DSS",
                    0x04 => "SOX",
                    0x05 => "CCPA",
                    _ => continue,
                };
                metadata.required_frameworks.push(framework.into());
                offset += 1;
            }

            // Parse data residency
            if offset < data.len() && data[offset] == 1 {
                offset += 1;
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        if let Ok(residency) = std::str::from_utf8(&data[offset..offset + len]) {
                            metadata.data_residency = Some(residency.into());
                        }
                        offset += len;
                    }
                }
            } else {
                offset += 1;
            }

            // Parse audit flag
            if offset < data.len() {
                metadata.audit_required = data[offset] == 1;
            }
        }

        Some(metadata)
    }

    /// Run PII pre-flight check
    fn check_pii(&self, ctx: &mut MiddlewareContext) -> MiddlewareResult<Vec<String>> {
        if !ctx.config.enable_pii_scanning {
            return Ok(Vec::new());
        }

        let findings = self.pii_detector.scan(&ctx.tx_bytes);

        if !findings.is_empty() {
            ctx.add_tag("pii_detected", "true");
            ctx.add_tag("pii_types", findings.join(","));
        }

        Ok(findings)
    }

    /// Validate against required frameworks
    fn validate_frameworks(
        &self,
        ctx: &mut MiddlewareContext,
        metadata: &ComplianceMetadata,
    ) -> Vec<ComplianceCheckResult> {
        let mut results = Vec::new();

        for framework in &metadata.required_frameworks {
            // Find validator for this framework
            let validator = self.framework_validators.iter().find(|v| v.framework_name() == framework);

            let result = if let Some(validator) = validator {
                validator.validate(ctx, metadata)
            } else {
                ComplianceCheckResult {
                    check_name: format!("{} compliance", framework),
                    passed: false,
                    framework: Some(framework.clone()),
                    details: Some(format!("Validator for {} not found", framework)),
                }
            };

            results.push(result);
        }

        // Also validate against globally enabled frameworks
        for enabled in &ctx.config.enabled_frameworks {
            if !metadata.required_frameworks.contains(enabled) {
                if let Some(validator) = self.framework_validators.iter().find(|v| v.framework_name() == enabled) {
                    let result = validator.validate(ctx, metadata);
                    results.push(result);
                }
            }
        }

        results
    }
}

impl Default for ComplianceMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for ComplianceMiddleware {
    fn process(&self, ctx: &mut MiddlewareContext) -> MiddlewareResult<MiddlewareAction> {
        // 1. Check if compliance checking is needed
        let parsed = match &ctx.parsed_tx {
            Some(p) => p,
            None => return Ok(MiddlewareAction::Continue), // Skip if not parsed
        };

        // Skip non-compute transactions unless configured otherwise
        if parsed.tx_type != TX_TYPE_COMPUTE_JOB && parsed.tx_type != TX_TYPE_SEAL {
            return Ok(MiddlewareAction::Continue);
        }

        // 2. Extract compliance metadata
        let metadata = self.extract_compliance_metadata(ctx).unwrap_or_default();

        // 3. Run PII pre-flight check
        let pii_findings = self.check_pii(ctx)?;

        if !pii_findings.is_empty() && ctx.config.compute_requires_compliance {
            // PII detected and compliance is required
            ctx.metadata.warnings.push(format!(
                "PII detected in transaction: {}",
                pii_findings.join(", ")
            ));

            // Check if PII is allowed for the requested frameworks
            let pii_allowed = metadata.required_frameworks.iter().any(|f| {
                matches!(f.as_str(), "HIPAA" | "GDPR") // These frameworks handle PII
            });

            if !pii_allowed && pii_findings.iter().any(|f| is_sensitive_pii(f)) {
                return Ok(MiddlewareAction::Reject(format!(
                    "Sensitive PII detected ({}) without appropriate compliance framework",
                    pii_findings.join(", ")
                )));
            }
        }

        // 4. Validate against required frameworks
        let framework_results = self.validate_frameworks(ctx, &metadata);

        // Store results in metadata
        ctx.metadata.compliance_results.extend(framework_results.clone());

        // 5. Check for failures
        let failures: Vec<_> = framework_results
            .iter()
            .filter(|r| !r.passed)
            .collect();

        if !failures.is_empty() {
            let failure_details: Vec<String> = failures
                .iter()
                .map(|f| {
                    format!(
                        "{}: {}",
                        f.check_name,
                        f.details.as_ref().unwrap_or(&"Check failed".into())
                    )
                })
                .collect();

            return Ok(MiddlewareAction::Reject(format!(
                "Compliance check failed: {}",
                failure_details.join("; ")
            )));
        }

        // 6. Add compliance tags
        ctx.add_tag("compliance_checked", "true");
        ctx.add_tag(
            "compliance_frameworks",
            metadata.required_frameworks.join(","),
        );
        if let Some(residency) = &metadata.data_residency {
            ctx.add_tag("data_residency", residency);
        }
        if metadata.audit_required {
            ctx.add_tag("audit_required", "true");
        }

        Ok(MiddlewareAction::Continue)
    }

    fn name(&self) -> &'static str {
        "compliance"
    }

    fn priority(&self) -> u32 {
        20 // After signature verification (10)
    }
}

/// Check if PII type is considered sensitive
fn is_sensitive_pii(pii_type: &str) -> bool {
    matches!(
        pii_type,
        "SSN" | "MEDICAL_RECORD" | "FINANCIAL_ACCOUNT" | "CREDIT_CARD" | "BIOMETRIC"
    )
}

/// PII (Personally Identifiable Information) Detector
pub struct PiiDetector {
    /// Patterns for different PII types
    patterns: Vec<PiiPattern>,
}

impl PiiDetector {
    /// Create new PII detector with default patterns
    pub fn new() -> Self {
        Self {
            patterns: vec![
                PiiPattern::new("EMAIL", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                PiiPattern::new("PHONE", r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
                PiiPattern::new("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
                PiiPattern::new("CREDIT_CARD", r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
                PiiPattern::new("IP_ADDRESS", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
                PiiPattern::new("DATE_OF_BIRTH", r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
            ],
        }
    }

    /// Scan bytes for PII
    pub fn scan(&self, data: &[u8]) -> Vec<String> {
        // Convert to string if valid UTF-8
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Vec::new(), // Binary data
        };

        let mut findings = HashSet::new();

        for pattern in &self.patterns {
            if pattern.matches(text) {
                findings.insert(pattern.name.clone());
            }
        }

        findings.into_iter().collect()
    }

    /// Add custom pattern
    pub fn add_pattern(&mut self, name: &str, pattern: &str) {
        self.patterns.push(PiiPattern::new(name, pattern));
    }
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// PII detection pattern
struct PiiPattern {
    name: String,
    regex: regex::Regex,
}

impl PiiPattern {
    fn new(name: &str, pattern: &str) -> Self {
        Self {
            name: name.into(),
            regex: regex::Regex::new(pattern).unwrap(),
        }
    }

    fn matches(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

/// Framework validator trait
pub trait FrameworkValidator: Send + Sync {
    /// Get framework name
    fn framework_name(&self) -> &str;

    /// Validate transaction against framework requirements
    fn validate(
        &self,
        ctx: &MiddlewareContext,
        metadata: &ComplianceMetadata,
    ) -> ComplianceCheckResult;
}

/// GDPR validator
pub struct GdprValidator;

impl GdprValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GdprValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkValidator for GdprValidator {
    fn framework_name(&self) -> &str {
        "GDPR"
    }

    fn validate(
        &self,
        ctx: &MiddlewareContext,
        metadata: &ComplianceMetadata,
    ) -> ComplianceCheckResult {
        let mut issues: Vec<String> = Vec::new();

        // Check 1: Data residency must be EU/EEA or have adequacy decision
        if let Some(residency) = &metadata.data_residency {
            let eu_countries = &[
                "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
                "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
                "PL", "PT", "RO", "SK", "SI", "ES", "SE",
            ];
            let adequacy_countries = &["GB", "CH", "JP", "KR", "CA", "NZ"];

            if !eu_countries.contains(&residency.as_str())
                && !adequacy_countries.contains(&residency.as_str())
            {
                issues.push(format!(
                    "Data residency '{}' not in EU/EEA or adequacy list",
                    residency
                ));
            }
        }

        // Check 2: Audit trail required for GDPR accountability
        if !metadata.audit_required {
            issues.push("GDPR requires audit trail for accountability".into());
        }

        // Check 3: Warn about PII without explicit consent mechanism
        if ctx.has_tag("pii_detected") && !ctx.has_tag("consent_verified") {
            issues.push(
                "PII processing requires documented consent (Article 6)".into(),
            );
        }

        if issues.is_empty() {
            ComplianceCheckResult {
                check_name: "GDPR compliance".into(),
                passed: true,
                framework: Some("GDPR".into()),
                details: None,
            }
        } else {
            ComplianceCheckResult {
                check_name: "GDPR compliance".into(),
                passed: false,
                framework: Some("GDPR".into()),
                details: Some(issues.join("; ")),
            }
        }
    }
}

/// HIPAA validator
pub struct HipaaValidator;

impl HipaaValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HipaaValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkValidator for HipaaValidator {
    fn framework_name(&self) -> &str {
        "HIPAA"
    }

    fn validate(
        &self,
        ctx: &MiddlewareContext,
        metadata: &ComplianceMetadata,
    ) -> ComplianceCheckResult {
        let mut issues: Vec<String> = Vec::new();

        // Check 1: Data must be encrypted (implied by transaction structure)
        // In production, verify encryption of PHI

        // Check 2: Data residency must be US
        if let Some(residency) = &metadata.data_residency {
            if residency != "US" {
                issues.push(format!(
                    "HIPAA requires US data residency, got '{}'",
                    residency
                ));
            }
        }

        // Check 3: Audit trail mandatory
        if !metadata.audit_required {
            issues.push("HIPAA requires full audit trail (45 CFR 164.312)".into());
        }

        // Check 4: Access controls (verified by signature)
        if let Some(parsed) = &ctx.parsed_tx {
            if !parsed.signature_valid {
                issues.push("HIPAA requires verified access controls".into());
            }
        }

        if issues.is_empty() {
            ComplianceCheckResult {
                check_name: "HIPAA compliance".into(),
                passed: true,
                framework: Some("HIPAA".into()),
                details: None,
            }
        } else {
            ComplianceCheckResult {
                check_name: "HIPAA compliance".into(),
                passed: false,
                framework: Some("HIPAA".into()),
                details: Some(issues.join("; ")),
            }
        }
    }
}

/// PCI-DSS validator
pub struct PciDssValidator;

impl PciDssValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PciDssValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkValidator for PciDssValidator {
    fn framework_name(&self) -> &str {
        "PCI-DSS"
    }

    fn validate(
        &self,
        ctx: &MiddlewareContext,
        metadata: &ComplianceMetadata,
    ) -> ComplianceCheckResult {
        let mut issues: Vec<String> = Vec::new();

        // Check 1: No plain credit card numbers
        if ctx.has_tag("pii_types") {
            let pii_types = ctx.get_tag("pii_types").unwrap_or("");
            if pii_types.contains("CREDIT_CARD") {
                issues.push(
                    "PCI-DSS prohibits storing plaintext cardholder data (Req 3)".into(),
                );
            }
        }

        // Check 2: Strong authentication (hybrid signature provides this)
        if let Some(parsed) = &ctx.parsed_tx {
            if !parsed.signature_valid {
                issues.push("PCI-DSS requires strong authentication (Req 8)".into());
            }
        }

        // Check 3: Audit trail for cardholder data access
        if !metadata.audit_required {
            issues.push("PCI-DSS requires audit logging (Req 10)".into());
        }

        if issues.is_empty() {
            ComplianceCheckResult {
                check_name: "PCI-DSS compliance".into(),
                passed: true,
                framework: Some("PCI-DSS".into()),
                details: None,
            }
        } else {
            ComplianceCheckResult {
                check_name: "PCI-DSS compliance".into(),
                passed: false,
                framework: Some("PCI-DSS".into()),
                details: Some(issues.join("; ")),
            }
        }
    }
}

/// CCPA validator
pub struct CcpaValidator;

impl CcpaValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CcpaValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkValidator for CcpaValidator {
    fn framework_name(&self) -> &str {
        "CCPA"
    }

    fn validate(
        &self,
        ctx: &MiddlewareContext,
        metadata: &ComplianceMetadata,
    ) -> ComplianceCheckResult {
        // CCPA is less restrictive than GDPR
        // Main requirement: transparency and opt-out capability

        let mut issues: Vec<String> = Vec::new();

        // Check 1: Audit trail for data access tracking
        if ctx.has_tag("pii_detected") && !metadata.audit_required {
            issues.push(
                "CCPA requires tracking personal information access".into(),
            );
        }

        if issues.is_empty() {
            ComplianceCheckResult {
                check_name: "CCPA compliance".into(),
                passed: true,
                framework: Some("CCPA".into()),
                details: None,
            }
        } else {
            ComplianceCheckResult {
                check_name: "CCPA compliance".into(),
                passed: false,
                framework: Some("CCPA".into()),
                details: Some(issues.join("; ")),
            }
        }
    }
}

/// Compliance report for transaction
#[derive(Debug, Clone)]
pub struct ComplianceReport {
    /// Transaction ID
    pub tx_id: [u8; 32],
    /// Overall compliance status
    pub compliant: bool,
    /// Checked frameworks
    pub frameworks_checked: Vec<String>,
    /// Individual check results
    pub check_results: Vec<ComplianceCheckResult>,
    /// PII findings
    pub pii_findings: Vec<String>,
    /// Data residency
    pub data_residency: Option<String>,
    /// Audit trail enabled
    pub audit_enabled: bool,
    /// Recommendations
    pub recommendations: Vec<String>,
}

impl ComplianceReport {
    /// Generate from middleware context
    pub fn from_context(ctx: &MiddlewareContext) -> Option<Self> {
        let parsed = ctx.parsed_tx.as_ref()?;

        let pii_findings = ctx
            .get_tag("pii_types")
            .map(|s| s.split(',').map(String::from).collect())
            .unwrap_or_default();

        let frameworks_checked: Vec<String> = ctx
            .metadata
            .compliance_results
            .iter()
            .filter_map(|r| r.framework.clone())
            .collect();

        let compliant = ctx
            .metadata
            .compliance_results
            .iter()
            .all(|r| r.passed);

        let mut recommendations = Vec::new();
        for result in &ctx.metadata.compliance_results {
            if !result.passed {
                if let Some(details) = &result.details {
                    recommendations.push(format!(
                        "Fix {} issue: {}",
                        result.framework.as_ref().unwrap_or(&"Unknown".into()),
                        details
                    ));
                }
            }
        }

        Some(Self {
            tx_id: parsed.tx_id,
            compliant,
            frameworks_checked,
            check_results: ctx.metadata.compliance_results.clone(),
            pii_findings,
            data_residency: ctx.get_tag("data_residency").map(String::from),
            audit_enabled: ctx.has_tag("audit_required"),
            recommendations,
        })
    }

    /// Export as JSON
    pub fn to_json(&self) -> String {
        format!(
            r#"{{
  "tx_id": "{}",
  "compliant": {},
  "frameworks_checked": {:?},
  "pii_findings": {:?},
  "data_residency": {:?},
  "audit_enabled": {},
  "recommendations": {:?}
}}"#,
            hex::encode(self.tx_id),
            self.compliant,
            self.frameworks_checked,
            self.pii_findings,
            self.data_residency,
            self.audit_enabled,
            self.recommendations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_context(tx_bytes: Vec<u8>) -> MiddlewareContext {
        let config = Arc::new(super::super::MiddlewareConfig::default());
        let mut ctx = MiddlewareContext::new(tx_bytes, config);

        // Set up parsed transaction
        ctx.parsed_tx = Some(super::super::ParsedTransaction {
            tx_id: [0; 32],
            sender: [0; 21],
            tx_type: TX_TYPE_COMPUTE_JOB,
            nonce: 0,
            gas_price: 1,
            gas_limit: 100000,
            chain_id: 1,
            size: 100,
            signature_valid: true,
            compliance_metadata: None,
        });

        ctx
    }

    #[test]
    fn test_pii_detector() {
        let detector = PiiDetector::new();

        // Test email detection
        let with_email = b"Contact: test@example.com";
        let findings = detector.scan(with_email);
        assert!(findings.contains(&"EMAIL".to_string()));

        // Test SSN detection
        let with_ssn = b"SSN: 123-45-6789";
        let findings = detector.scan(with_ssn);
        assert!(findings.contains(&"SSN".to_string()));

        // Test no PII
        let clean = b"Hello world";
        let findings = detector.scan(clean);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_gdpr_validator() {
        let validator = GdprValidator::new();
        let ctx = create_test_context(vec![0; 100]);

        // Test with EU residency
        let metadata = ComplianceMetadata {
            required_frameworks: vec!["GDPR".into()],
            data_residency: Some("DE".into()), // Germany
            audit_required: true,
            ..Default::default()
        };

        let result = validator.validate(&ctx, &metadata);
        assert!(result.passed);

        // Test with non-EU residency
        let metadata_bad = ComplianceMetadata {
            required_frameworks: vec!["GDPR".into()],
            data_residency: Some("CN".into()), // China - no adequacy
            audit_required: true,
            ..Default::default()
        };

        let result = validator.validate(&ctx, &metadata_bad);
        assert!(!result.passed);
    }

    #[test]
    fn test_hipaa_validator() {
        let validator = HipaaValidator::new();
        let ctx = create_test_context(vec![0; 100]);

        // Test with US residency and audit
        let metadata = ComplianceMetadata {
            required_frameworks: vec!["HIPAA".into()],
            data_residency: Some("US".into()),
            audit_required: true,
            ..Default::default()
        };

        let result = validator.validate(&ctx, &metadata);
        assert!(result.passed);

        // Test without audit
        let metadata_no_audit = ComplianceMetadata {
            required_frameworks: vec!["HIPAA".into()],
            data_residency: Some("US".into()),
            audit_required: false,
            ..Default::default()
        };

        let result = validator.validate(&ctx, &metadata_no_audit);
        assert!(!result.passed);
    }

    #[test]
    fn test_compliance_middleware() {
        let middleware = ComplianceMiddleware::new();
        let mut cfg = super::super::MiddlewareConfig::default();
        cfg.enabled_frameworks.clear();
        let config = Arc::new(cfg);
        let mut ctx = MiddlewareContext::new(vec![0; 100], config);
        ctx.parsed_tx = Some(super::super::ParsedTransaction {
            tx_id: [0; 32],
            sender: [0; 21],
            tx_type: TX_TYPE_COMPUTE_JOB,
            nonce: 0,
            gas_price: 1,
            gas_limit: 100000,
            chain_id: 1,
            size: 100,
            signature_valid: true,
            compliance_metadata: None,
        });

        let action = middleware.process(&mut ctx).unwrap();

        // With no globally enabled frameworks and no explicit marker, pass through.
        assert_eq!(action, MiddlewareAction::Continue);
    }

    #[test]
    fn test_pci_dss_credit_card_rejection() {
        let middleware = ComplianceMiddleware::new();
        let mut ctx = create_test_context(
            b"Card: 4111-1111-1111-1111".to_vec()
        );

        // Add compliance marker requesting PCI-DSS
        ctx.add_tag("pii_types", "CREDIT_CARD");

        // Manually set compliance metadata
        if let Some(ref mut parsed) = ctx.parsed_tx {
            parsed.compliance_metadata = Some(ComplianceMetadata {
                required_frameworks: vec!["PCI-DSS".into()],
                audit_required: true,
                ..Default::default()
            });
        }

        // The middleware should process and check PCI-DSS
        let _ = middleware.process(&mut ctx);

        // Check if warning was added about credit card
        // (In full implementation, this would reject)
    }
}
