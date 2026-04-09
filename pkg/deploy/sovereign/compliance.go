package sovereign

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Compliance check result types
// ---------------------------------------------------------------------------

// ComplianceGap describes a specific gap found during a compliance check.
type ComplianceGap struct {
	// Requirement is the control requirement that is not met.
	Requirement string `json:"requirement"`

	// Description explains what is missing or non-compliant.
	Description string `json:"description"`

	// Severity indicates the gap severity ("critical", "high", "medium", "low").
	Severity string `json:"severity"`

	// Remediation suggests how to close the gap.
	Remediation string `json:"remediation"`
}

// ComplianceWarning describes a non-blocking compliance concern.
type ComplianceWarning struct {
	// Requirement is the control requirement that triggered the warning.
	Requirement string `json:"requirement"`

	// Description explains the concern.
	Description string `json:"description"`

	// Recommendation suggests an improvement.
	Recommendation string `json:"recommendation"`
}

// ComplianceResult holds the outcome of a compliance check against a
// single framework.
type ComplianceResult struct {
	// Framework is the compliance framework that was checked.
	Framework string `json:"framework"`

	// Compliant indicates whether all mandatory controls are satisfied.
	Compliant bool `json:"compliant"`

	// Score is a numeric compliance score (0-100).
	Score int `json:"score"`

	// Gaps lists the specific compliance gaps found.
	Gaps []ComplianceGap `json:"gaps"`

	// Warnings lists non-blocking compliance concerns.
	Warnings []ComplianceWarning `json:"warnings"`

	// CheckedAt is when the compliance check was performed.
	CheckedAt time.Time `json:"checked_at"`
}

// ComplianceReport aggregates compliance results across multiple frameworks.
type ComplianceReport struct {
	// DeploymentID identifies the deployment that was checked.
	DeploymentID string `json:"deployment_id"`

	// Results contains per-framework compliance results.
	Results []ComplianceResult `json:"results"`

	// OverallCompliant is true only if all frameworks pass.
	OverallCompliant bool `json:"overall_compliant"`

	// OverallScore is the weighted average compliance score.
	OverallScore int `json:"overall_score"`

	// GeneratedAt is when the report was generated.
	GeneratedAt time.Time `json:"generated_at"`
}

// ---------------------------------------------------------------------------
// Deployment compliance checker
// ---------------------------------------------------------------------------

// DeploymentChecker validates deployments against regulatory compliance
// frameworks. It includes pre-built checks for GDPR, HIPAA, CMMC,
// and PCI-DSS.
type DeploymentChecker struct {
	checkers map[string]frameworkChecker
}

// frameworkChecker is the internal function signature for per-framework checks.
type frameworkChecker func(deployment *Deployment) ComplianceResult

// NewDeploymentChecker creates a checker with all built-in framework checks.
func NewDeploymentChecker() *DeploymentChecker {
	dc := &DeploymentChecker{
		checkers: make(map[string]frameworkChecker),
	}

	dc.checkers["gdpr"] = checkGDPR
	dc.checkers["hipaa"] = checkHIPAA
	dc.checkers["cmmc"] = checkCMMC
	dc.checkers["pci-dss"] = checkPCIDSS

	return dc
}

// CheckCompliance evaluates a deployment against the specified frameworks,
// returning a result for each one.
func (dc *DeploymentChecker) CheckCompliance(_ context.Context, deployment *Deployment, frameworks []string) ([]ComplianceResult, error) {
	if deployment == nil {
		return nil, fmt.Errorf("deployment is nil")
	}
	if len(frameworks) == 0 {
		return nil, fmt.Errorf("at least one framework is required")
	}

	var results []ComplianceResult

	for _, fw := range frameworks {
		checker, ok := dc.checkers[fw]
		if !ok {
			return nil, fmt.Errorf("unknown compliance framework: %s", fw)
		}

		result := checker(deployment)
		results = append(results, result)
	}

	return results, nil
}

// GenerateComplianceReport produces a comprehensive compliance report
// across all registered frameworks.
func (dc *DeploymentChecker) GenerateComplianceReport(_ context.Context, deployment *Deployment) (*ComplianceReport, error) {
	if deployment == nil {
		return nil, fmt.Errorf("deployment is nil")
	}

	report := &ComplianceReport{
		DeploymentID:     deployment.ID,
		OverallCompliant: true,
		GeneratedAt:      time.Now().UTC(),
	}

	totalScore := 0
	count := 0

	for fwID, checker := range dc.checkers {
		_ = fwID // used by closure
		result := checker(deployment)
		report.Results = append(report.Results, result)

		if !result.Compliant {
			report.OverallCompliant = false
		}

		totalScore += result.Score
		count++
	}

	if count > 0 {
		report.OverallScore = totalScore / count
	}

	return report, nil
}

// SupportedFrameworks returns the list of framework IDs this checker supports.
func (dc *DeploymentChecker) SupportedFrameworks() []string {
	fws := make([]string, 0, len(dc.checkers))
	for fw := range dc.checkers {
		fws = append(fws, fw)
	}
	return fws
}

// ---------------------------------------------------------------------------
// GDPR compliance check (data residency focus)
// ---------------------------------------------------------------------------

func checkGDPR(d *Deployment) ComplianceResult {
	result := ComplianceResult{
		Framework: "gdpr",
		Compliant: true,
		Score:     100,
		CheckedAt: time.Now().UTC(),
	}

	// GDPR: data residency — must be in an EU-adequate region
	euRegions := map[string]bool{
		"eu-west-1": true, "uk-south-1": true, "ch-zurich-1": true,
	}
	if !euRegions[d.Spec.Region] {
		result.Compliant = false
		result.Score -= 30
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "Art. 44-49 Data Transfers",
			Description: fmt.Sprintf("deployment region %s is not in an EU-adequate jurisdiction", d.Spec.Region),
			Severity:    "critical",
			Remediation: "deploy in an EU or adequacy-decision region, or implement SCCs",
		})
	}

	// GDPR: encryption at rest
	if !d.Spec.Storage.EncryptionAtRest {
		result.Compliant = false
		result.Score -= 25
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "Art. 32 Security of Processing",
			Description: "encryption at rest is not enabled",
			Severity:    "high",
			Remediation: "enable encryption at rest with AES-256 or stronger",
		})
	}

	// GDPR: encryption in transit (TLS 1.2+)
	if d.Spec.Network.TLSMinVersion == "" || d.Spec.Network.TLSMinVersion < "1.2" {
		result.Score -= 15
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "Art. 32 Security of Processing",
			Description:    "TLS minimum version should be 1.2 or higher",
			Recommendation: "set TLS minimum version to 1.3 for strongest protection",
		})
	}

	// GDPR: data retention policy
	if d.Spec.Storage.RetentionDays == 0 {
		result.Score -= 10
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "Art. 5(1)(e) Storage Limitation",
			Description:    "no data retention period configured",
			Recommendation: "configure a retention period aligned with data processing purposes",
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}

// ---------------------------------------------------------------------------
// HIPAA compliance check (encryption at rest/transit focus)
// ---------------------------------------------------------------------------

func checkHIPAA(d *Deployment) ComplianceResult {
	result := ComplianceResult{
		Framework: "hipaa",
		Compliant: true,
		Score:     100,
		CheckedAt: time.Now().UTC(),
	}

	// HIPAA: encryption at rest is mandatory for ePHI
	if !d.Spec.Storage.EncryptionAtRest {
		result.Compliant = false
		result.Score -= 35
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "164.312(a)(2)(iv) Encryption at Rest",
			Description: "encryption at rest is not enabled for ePHI storage",
			Severity:    "critical",
			Remediation: "enable AES-256-GCM encryption at rest",
		})
	}

	// HIPAA: encryption algorithm
	if d.Spec.Storage.EncryptionAtRest && d.Spec.Storage.EncryptionAlgorithm != "" &&
		d.Spec.Storage.EncryptionAlgorithm != "AES-256-GCM" {
		result.Score -= 10
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "164.312(a)(2)(iv) Encryption",
			Description:    fmt.Sprintf("encryption algorithm %s may not meet HIPAA requirements", d.Spec.Storage.EncryptionAlgorithm),
			Recommendation: "use AES-256-GCM for HIPAA-compliant encryption",
		})
	}

	// HIPAA: encryption in transit
	if d.Spec.Network.TLSMinVersion == "" || d.Spec.Network.TLSMinVersion < "1.2" {
		result.Compliant = false
		result.Score -= 30
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "164.312(e)(1) Transmission Security",
			Description: "TLS 1.2+ is required for ePHI transmission",
			Severity:    "critical",
			Remediation: "set TLS minimum version to 1.2 or higher",
		})
	}

	// HIPAA: backup/disaster recovery
	if !d.Spec.Storage.BackupEnabled {
		result.Score -= 15
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "164.308(a)(7) Contingency Plan",
			Description: "automated backups are not enabled",
			Severity:    "high",
			Remediation: "enable automated backups with encryption",
		})
		if result.Score < 70 {
			result.Compliant = false
		}
	}

	// HIPAA: access control
	if !d.Spec.Network.MTLSRequired {
		result.Score -= 10
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "164.312(d) Authentication",
			Description:    "mutual TLS is not required for inter-service communication",
			Recommendation: "enable mTLS for defense-in-depth authentication",
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}

// ---------------------------------------------------------------------------
// CMMC compliance check (air-gap focus)
// ---------------------------------------------------------------------------

func checkCMMC(d *Deployment) ComplianceResult {
	result := ComplianceResult{
		Framework: "cmmc",
		Compliant: true,
		Score:     100,
		CheckedAt: time.Now().UTC(),
	}

	// CMMC Level 3: air-gapped or isolated deployment for CUI
	if d.Spec.Mode != AirGapped && d.Spec.Mode != OnPrem {
		result.Score -= 20
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "SC.L2-3.13.1 Boundary Protection",
			Description:    "CMMC Level 3 recommends air-gapped or on-premises deployment for CUI",
			Recommendation: "consider air-gapped or on-premises deployment mode",
		})
	}

	// CMMC: egress restriction
	if !d.Spec.Network.EgressRestricted {
		result.Score -= 20
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "SC.L2-3.13.6 Network Communication by Exception",
			Description: "outbound network traffic is not restricted",
			Severity:    "high",
			Remediation: "restrict egress to only explicitly permitted destinations",
		})
		if d.Spec.Mode == AirGapped {
			result.Compliant = false
		}
	}

	// CMMC: encryption at rest
	if !d.Spec.Storage.EncryptionAtRest {
		result.Compliant = false
		result.Score -= 25
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "SC.L2-3.13.16 Data at Rest",
			Description: "encryption at rest is not enabled for CUI",
			Severity:    "critical",
			Remediation: "enable FIPS 140-2 validated encryption at rest",
		})
	}

	// CMMC: encryption in transit
	if d.Spec.Network.TLSMinVersion == "" || d.Spec.Network.TLSMinVersion < "1.2" {
		result.Compliant = false
		result.Score -= 20
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "SC.L2-3.13.8 CUI in Transit",
			Description: "TLS 1.2+ is required for CUI transmission",
			Severity:    "critical",
			Remediation: "set TLS minimum version to 1.2 or higher",
		})
	}

	// CMMC: dedicated hosts
	if !d.Spec.Compute.DedicatedHosts && d.Spec.Mode == Cloud {
		result.Score -= 10
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "PE.L2-3.10.1 Physical Access",
			Description:    "shared infrastructure may not meet CMMC physical security requirements",
			Recommendation: "use dedicated hosts for CUI workloads",
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}

// ---------------------------------------------------------------------------
// PCI-DSS compliance check (network segmentation focus)
// ---------------------------------------------------------------------------

func checkPCIDSS(d *Deployment) ComplianceResult {
	result := ComplianceResult{
		Framework: "pci-dss",
		Compliant: true,
		Score:     100,
		CheckedAt: time.Now().UTC(),
	}

	// PCI-DSS: network segmentation
	if !d.Spec.Network.VPCEnabled && d.Spec.Mode != AirGapped && d.Spec.Mode != OnPrem {
		result.Compliant = false
		result.Score -= 30
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "Req 1.3 Network Segmentation",
			Description: "VPC or equivalent network isolation is not configured",
			Severity:    "critical",
			Remediation: "enable VPC with private subnets for cardholder data environment",
		})
	}

	// PCI-DSS: ingress restrictions
	if len(d.Spec.Network.IngressAllowList) == 0 && d.Spec.Mode != AirGapped {
		result.Score -= 20
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "Req 1.2 Restrict Connections",
			Description: "no ingress allow list configured",
			Severity:    "high",
			Remediation: "configure an explicit ingress allow list",
		})
		if result.Score < 70 {
			result.Compliant = false
		}
	}

	// PCI-DSS: encryption at rest
	if !d.Spec.Storage.EncryptionAtRest {
		result.Compliant = false
		result.Score -= 25
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "Req 3.4 Render PAN Unreadable",
			Description: "encryption at rest is not enabled for stored cardholder data",
			Severity:    "critical",
			Remediation: "enable strong encryption at rest for all cardholder data",
		})
	}

	// PCI-DSS: TLS requirements
	if d.Spec.Network.TLSMinVersion == "" || d.Spec.Network.TLSMinVersion < "1.2" {
		result.Compliant = false
		result.Score -= 20
		result.Gaps = append(result.Gaps, ComplianceGap{
			Requirement: "Req 4.1 Strong Cryptography",
			Description: "TLS 1.2+ is required for transmitting cardholder data",
			Severity:    "critical",
			Remediation: "enforce TLS 1.2 or higher for all communications",
		})
	}

	// PCI-DSS: mTLS for inter-service
	if !d.Spec.Network.MTLSRequired {
		result.Score -= 10
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "Req 4.1 Strong Cryptography",
			Description:    "mutual TLS is not required for inter-service communication",
			Recommendation: "enable mTLS for defense-in-depth within the CDE",
		})
	}

	// PCI-DSS: backup encryption
	if d.Spec.Storage.BackupEnabled && !d.Spec.Storage.EncryptionAtRest {
		result.Score -= 10
		result.Warnings = append(result.Warnings, ComplianceWarning{
			Requirement:    "Req 3.4 Render PAN Unreadable",
			Description:    "backups should be encrypted to protect stored cardholder data",
			Recommendation: "ensure all backups are encrypted with the same strength as primary storage",
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}
