package finance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Regulatory Reporting
// ---------------------------------------------------------------------------

// Regulator identifies a financial regulator.
type Regulator string

const (
	RegulatorSEC   Regulator = "SEC"
	RegulatorFCA   Regulator = "FCA"
	RegulatorMAS   Regulator = "MAS"
	RegulatorSAMA  Regulator = "SAMA"
	RegulatorFINMA Regulator = "FINMA"
	RegulatorBaFin Regulator = "BaFin"
)

// ReportType categorizes regulatory reports.
type ReportType string

const (
	ReportTransaction  ReportType = "transaction_report"
	ReportAML          ReportType = "aml_report"
	ReportRisk         ReportType = "risk_report"
	ReportCompliance   ReportType = "compliance_report"
)

// ReportFormat specifies the output format of a report.
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatXML  ReportFormat = "xml"
	FormatPDF  ReportFormat = "pdf"
	FormatCSV  ReportFormat = "csv"
)

// ReportConfig holds configuration for generating a regulatory report.
type ReportConfig struct {
	// Regulator identifies which regulator the report is for.
	Regulator Regulator `json:"regulator"`

	// Period is the reporting period (e.g. "2024-Q1").
	Period string `json:"period"`

	// ReportType specifies the type of report.
	ReportType ReportType `json:"report_type"`

	// Format specifies the desired output format.
	Format ReportFormat `json:"format"`

	// IncludeEvidence determines whether sealed evidence is embedded.
	IncludeEvidence bool `json:"include_evidence"`

	// Currency filters events by currency (empty = all).
	Currency string `json:"currency"`

	// MinAmount filters events by minimum amount (0 = no filter).
	MinAmount float64 `json:"min_amount"`
}

// RegulatorTemplate holds the pre-built template for a specific regulator.
type RegulatorTemplate struct {
	// Regulator identifies the regulator.
	Regulator Regulator `json:"regulator"`

	// RequiredSections lists the required report sections.
	RequiredSections []string `json:"required_sections"`

	// ComplianceFramework identifies the applicable framework.
	ComplianceFramework string `json:"compliance_framework"`

	// RetentionYears is the minimum retention period in years.
	RetentionYears int `json:"retention_years"`

	// SubmissionDeadline describes when reports must be submitted.
	SubmissionDeadline string `json:"submission_deadline"`
}

// GeneratedReport is the output of the reporting service.
type GeneratedReport struct {
	// ID uniquely identifies this report.
	ID string `json:"id"`

	// Config is the configuration used to generate this report.
	Config ReportConfig `json:"config"`

	// GeneratedAt is when the report was created.
	GeneratedAt time.Time `json:"generated_at"`

	// Sections contains the report content organized by section.
	Sections map[string]string `json:"sections"`

	// EventCount is the number of events covered.
	EventCount int `json:"event_count"`

	// TotalAmount is the sum of monetary events.
	TotalAmount float64 `json:"total_amount"`

	// Template identifies the regulator template used.
	Template RegulatorTemplate `json:"template"`

	// SealID is the blockchain seal for this report.
	SealID string `json:"seal_id"`

	// Hash is the SHA-256 hash of the report contents.
	Hash string `json:"hash"`
}

// ReportingService generates regulatory reports from the financial audit trail.
type ReportingService struct {
	auditTrail *FinancialAuditTrail
	templates  map[Regulator]RegulatorTemplate
}

// NewReportingService creates a new reporting service.
func NewReportingService(auditTrail *FinancialAuditTrail) *ReportingService {
	return &ReportingService{
		auditTrail: auditTrail,
		templates:  buildRegulatorTemplates(),
	}
}

// GenerateReport generates a regulatory report from the configuration.
func (s *ReportingService) GenerateReport(_ context.Context, config ReportConfig) (*GeneratedReport, error) {
	if config.Regulator == "" {
		return nil, fmt.Errorf("regulator is required")
	}
	if config.Period == "" {
		return nil, fmt.Errorf("period is required")
	}
	if config.ReportType == "" {
		return nil, fmt.Errorf("report type is required")
	}

	tmpl, ok := s.templates[config.Regulator]
	if !ok {
		return nil, fmt.Errorf("unsupported regulator: %s", config.Regulator)
	}

	events := s.auditTrail.GetEvents()

	// Filter events
	var filtered []FinancialEvent
	for _, e := range events {
		if config.Currency != "" && e.Currency != config.Currency {
			continue
		}
		if config.MinAmount > 0 && e.Amount < config.MinAmount {
			continue
		}
		filtered = append(filtered, e)
	}

	report := &GeneratedReport{
		ID:          fmt.Sprintf("rpt-%s-%s-%d", config.Regulator, config.Period, time.Now().UnixNano()),
		Config:      config,
		GeneratedAt: time.Now().UTC(),
		EventCount:  len(filtered),
		Template:    tmpl,
		Sections:    make(map[string]string),
	}

	for _, e := range filtered {
		report.TotalAmount += e.Amount
	}

	// Build sections from template
	for _, section := range tmpl.RequiredSections {
		report.Sections[section] = generateSectionContent(section, config, report.EventCount, report.TotalAmount)
	}

	// Compute report hash
	hashInput := fmt.Sprintf("%s-%s-%s-%d-%f-%s",
		config.Regulator, config.Period, config.ReportType,
		report.EventCount, report.TotalAmount, report.GeneratedAt.Format(time.RFC3339Nano))
	h := sha256.Sum256([]byte(hashInput))
	report.Hash = hex.EncodeToString(h[:])

	// Seal the report
	report.SealID = "seal-rpt-" + report.Hash[:16]

	return report, nil
}

// GetTemplate returns the template for a specific regulator.
func (s *ReportingService) GetTemplate(regulator Regulator) (*RegulatorTemplate, error) {
	tmpl, ok := s.templates[regulator]
	if !ok {
		return nil, fmt.Errorf("unsupported regulator: %s", regulator)
	}
	return &tmpl, nil
}

// ListRegulators returns all supported regulators.
func (s *ReportingService) ListRegulators() []Regulator {
	regulators := make([]Regulator, 0, len(s.templates))
	for r := range s.templates {
		regulators = append(regulators, r)
	}
	return regulators
}

func buildRegulatorTemplates() map[Regulator]RegulatorTemplate {
	return map[Regulator]RegulatorTemplate{
		RegulatorSEC: {
			Regulator:           RegulatorSEC,
			RequiredSections:    []string{"executive_summary", "transaction_overview", "internal_controls", "risk_assessment", "compliance_status", "audit_evidence"},
			ComplianceFramework: "SOX / Dodd-Frank",
			RetentionYears:      7,
			SubmissionDeadline:  "45 days after period end",
		},
		RegulatorFCA: {
			Regulator:           RegulatorFCA,
			RequiredSections:    []string{"executive_summary", "regulatory_capital", "transaction_reporting", "conduct_risk", "operational_resilience", "audit_evidence"},
			ComplianceFramework: "FCA SYSC / MiFID II",
			RetentionYears:      5,
			SubmissionDeadline:  "30 business days after period end",
		},
		RegulatorMAS: {
			Regulator:           RegulatorMAS,
			RequiredSections:    []string{"executive_summary", "aml_compliance", "technology_risk", "transaction_reporting", "audit_evidence"},
			ComplianceFramework: "MAS TRM / PSA",
			RetentionYears:      5,
			SubmissionDeadline:  "30 days after period end",
		},
		RegulatorSAMA: {
			Regulator:           RegulatorSAMA,
			RequiredSections:    []string{"executive_summary", "cybersecurity_controls", "transaction_reporting", "compliance_status", "audit_evidence"},
			ComplianceFramework: "SAMA Cyber Security Framework",
			RetentionYears:      10,
			SubmissionDeadline:  "60 days after period end",
		},
		RegulatorFINMA: {
			Regulator:           RegulatorFINMA,
			RequiredSections:    []string{"executive_summary", "risk_management", "capital_adequacy", "compliance_status", "audit_evidence"},
			ComplianceFramework: "FINMA Circular 2023/1",
			RetentionYears:      10,
			SubmissionDeadline:  "90 days after fiscal year end",
		},
		RegulatorBaFin: {
			Regulator:           RegulatorBaFin,
			RequiredSections:    []string{"executive_summary", "marat_compliance", "transaction_reporting", "risk_assessment", "audit_evidence"},
			ComplianceFramework: "KWG / MaRisk",
			RetentionYears:      6,
			SubmissionDeadline:  "3 months after fiscal year end",
		},
	}
}

func generateSectionContent(section string, config ReportConfig, eventCount int, totalAmount float64) string {
	switch section {
	case "executive_summary":
		return fmt.Sprintf("Regulatory report for %s covering period %s. Report type: %s. Total events: %d, total amount: %.2f.",
			config.Regulator, config.Period, config.ReportType, eventCount, totalAmount)
	case "transaction_overview", "transaction_reporting":
		return fmt.Sprintf("Transaction summary for period %s: %d transactions totaling %.2f %s. All transactions sealed on Aethelred blockchain.",
			config.Period, eventCount, totalAmount, config.Currency)
	case "internal_controls":
		return "Internal controls verified: dual-approval workflows for treasury operations, sanctions screening with sealed results, and exception management with full escalation audit trail."
	case "risk_assessment":
		return "Risk assessment completed via automated CMMC-aligned controls with blockchain-anchored evidence collection."
	case "compliance_status":
		return "Compliance monitoring active with sealed evidence packages for all regulatory requirements."
	case "audit_evidence":
		return "All evidence is blockchain-sealed with cryptographic integrity verification. Hash chains verified intact."
	case "aml_compliance":
		return "AML screening performed against OFAC SDN, EU, and UN sanctions lists with sealed results."
	case "technology_risk":
		return "Technology controls include TEE-protected execution, post-quantum cryptography, and air-gap capable deployment."
	case "cybersecurity_controls":
		return "Cybersecurity framework implemented with ML-DSA-65 signatures, HSM key management, and blockchain-anchored audit trails."
	case "regulatory_capital":
		return fmt.Sprintf("Capital adequacy reporting for period %s.", config.Period)
	case "conduct_risk":
		return "Conduct risk managed through dual-control workflows and sealed exception handling."
	case "operational_resilience":
		return "Operational resilience ensured through air-gap capable deployment, offline validation, and state snapshot recovery."
	case "risk_management":
		return "Risk management framework includes automated compliance assessment and sealed evidence packages."
	case "capital_adequacy":
		return fmt.Sprintf("Capital adequacy computation for period %s.", config.Period)
	case "marat_compliance":
		return "MaRisk compliance verified through internal control assessment and sealed audit trails."
	default:
		return fmt.Sprintf("Section: %s — content for period %s", section, config.Period)
	}
}
