package assurance

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Evidence Export
// ---------------------------------------------------------------------------
//
// Evidence export converts execution receipts into regulator-ready and
// auditor-ready packages in multiple output formats. These packages are
// designed for consumption by external parties who do not have direct
// access to the Aethelred platform.
// ---------------------------------------------------------------------------

// ExportFormat specifies the output format for evidence packages.
type ExportFormat string

const (
	ExportFormatJSON  ExportFormat = "json"
	ExportFormatPDF   ExportFormat = "pdf"
	ExportFormatOSCAL ExportFormat = "oscal"
	ExportFormatCSV   ExportFormat = "csv"
)

// ParseExportFormat converts a string to an ExportFormat.
func ParseExportFormat(s string) (ExportFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return ExportFormatJSON, nil
	case "pdf":
		return ExportFormatPDF, nil
	case "oscal":
		return ExportFormatOSCAL, nil
	case "csv":
		return ExportFormatCSV, nil
	default:
		return "", fmt.Errorf("assurance/export: unknown format: %s", s)
	}
}

// ---------------------------------------------------------------------------
// Regulator package
// ---------------------------------------------------------------------------

// RegulatorPackage is a structured evidence package formatted for
// regulatory submission.
type RegulatorPackage struct {
	// Framework identifies the regulatory framework targeted.
	Framework string `json:"framework"`

	// Controls lists the compliance controls with evidence mappings.
	Controls []RegulatorControl `json:"controls"`

	// Evidence contains the execution receipts as evidence.
	Evidence []ExecutionReceipt `json:"evidence"`

	// Assessment contains the overall assessment result.
	Assessment RegulatorAssessment `json:"assessment"`

	// GeneratedAt records when the package was produced.
	GeneratedAt string `json:"generated_at"`
}

// RegulatorControl maps a compliance control to evidence within the package.
type RegulatorControl struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Status        string   `json:"status"`
	EvidenceRefs  []string `json:"evidence_refs"`
	Observations  []string `json:"observations,omitempty"`
}

// RegulatorAssessment summarizes the overall compliance posture.
type RegulatorAssessment struct {
	OverallStatus    string  `json:"overall_status"`
	ControlsMet      int     `json:"controls_met"`
	ControlsTotal    int     `json:"controls_total"`
	CoveragePercent  float64 `json:"coverage_percent"`
	AssuranceLevel   string  `json:"assurance_level"`
}

// ExportRegulatorPackage creates a regulator-ready evidence package from
// a set of execution receipts for the specified compliance framework.
func ExportRegulatorPackage(_ context.Context, receipts []ExecutionReceipt, framework string) (*RegulatorPackage, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("assurance/export: at least one receipt is required")
	}
	if framework == "" {
		return nil, fmt.Errorf("assurance/export: framework is required")
	}

	pkg := &RegulatorPackage{
		Framework:   framework,
		Evidence:    receipts,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Build control mappings from receipt compliance metadata.
	controlMap := make(map[string]*RegulatorControl)
	controlsMet := 0
	controlsTotal := 0

	for i := range receipts {
		r := &receipts[i]
		if r.Compliance == nil {
			continue
		}
		controlsTotal = r.Compliance.ControlsTotal
		controlsMet = r.Compliance.ControlsMet

		for _, fw := range r.Compliance.Frameworks {
			if _, exists := controlMap[fw]; !exists {
				controlMap[fw] = &RegulatorControl{
					ControlID:    fw,
					ControlName:  fw,
					Status:       "assessed",
					EvidenceRefs: []string{r.ID},
				}
			} else {
				controlMap[fw].EvidenceRefs = append(controlMap[fw].EvidenceRefs, r.ID)
			}
		}
	}

	for _, ctrl := range controlMap {
		pkg.Controls = append(pkg.Controls, *ctrl)
	}

	// Compute overall assessment.
	coveragePercent := 0.0
	if controlsTotal > 0 {
		coveragePercent = float64(controlsMet) / float64(controlsTotal) * 100
	}

	// Determine highest assurance level.
	highestLevel := AssuranceLevelNone
	for _, r := range receipts {
		if r.AssuranceLevel > highestLevel {
			highestLevel = r.AssuranceLevel
		}
	}

	status := "incomplete"
	if coveragePercent >= 100 {
		status = "compliant"
	} else if coveragePercent >= 80 {
		status = "substantially_compliant"
	} else if coveragePercent >= 50 {
		status = "partially_compliant"
	}

	pkg.Assessment = RegulatorAssessment{
		OverallStatus:   status,
		ControlsMet:     controlsMet,
		ControlsTotal:   controlsTotal,
		CoveragePercent: coveragePercent,
		AssuranceLevel:  highestLevel.String(),
	}

	return pkg, nil
}

// ---------------------------------------------------------------------------
// Auditor bundle
// ---------------------------------------------------------------------------

// AuditorBundle is a structured evidence package formatted for external
// audit firms.
type AuditorBundle struct {
	// Scope describes the audit scope.
	Scope string `json:"scope"`

	// Period defines the time window covered.
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`

	// Receipts contains the execution receipts.
	Receipts []ExecutionReceipt `json:"receipts"`

	// Summary provides aggregate statistics.
	Summary AuditorSummary `json:"summary"`

	// GeneratedAt records when the bundle was produced.
	GeneratedAt string `json:"generated_at"`
}

// AuditorSummary provides aggregate statistics for the auditor.
type AuditorSummary struct {
	TotalReceipts       int     `json:"total_receipts"`
	AverageAssurance    float64 `json:"average_assurance_score"`
	HighAssuranceCount  int     `json:"high_assurance_count"`
	LowAssuranceCount   int     `json:"low_assurance_count"`
	WithAttestations    int     `json:"with_attestations"`
	WithSeals           int     `json:"with_seals"`
	WithCompliance      int     `json:"with_compliance"`
}

// ExportAuditorBundle creates an auditor-ready evidence bundle from a set
// of execution receipts.
func ExportAuditorBundle(_ context.Context, receipts []ExecutionReceipt, scope string) (*AuditorBundle, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("assurance/export: at least one receipt is required")
	}
	if scope == "" {
		return nil, fmt.Errorf("assurance/export: scope is required")
	}

	bundle := &AuditorBundle{
		Scope:       scope,
		Receipts:    receipts,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Determine period from receipt timestamps.
	earliest := receipts[0].Timestamp
	latest := receipts[0].Timestamp
	for _, r := range receipts[1:] {
		if r.Timestamp < earliest {
			earliest = r.Timestamp
		}
		if r.Timestamp > latest {
			latest = r.Timestamp
		}
	}
	bundle.PeriodStart = earliest
	bundle.PeriodEnd = latest

	// Compute summary.
	var totalScore float64
	summary := AuditorSummary{
		TotalReceipts: len(receipts),
	}

	for _, r := range receipts {
		totalScore += float64(r.AssuranceLevel.Score())
		if r.AssuranceLevel >= AssuranceLevelHigh {
			summary.HighAssuranceCount++
		}
		if r.AssuranceLevel <= AssuranceLevelBasic {
			summary.LowAssuranceCount++
		}
		if r.Attestation != nil {
			summary.WithAttestations++
		}
		if r.Seal != nil {
			summary.WithSeals++
		}
		if r.Compliance != nil {
			summary.WithCompliance++
		}
	}
	summary.AverageAssurance = totalScore / float64(len(receipts))
	bundle.Summary = summary

	return bundle, nil
}

// ---------------------------------------------------------------------------
// Format-specific rendering
// ---------------------------------------------------------------------------

// RenderRegulatorJSON renders a regulator package as JSON.
func RenderRegulatorJSON(pkg *RegulatorPackage) ([]byte, error) {
	return json.MarshalIndent(pkg, "", "  ")
}

// RenderAuditorJSON renders an auditor bundle as JSON.
func RenderAuditorJSON(bundle *AuditorBundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", "  ")
}

// RenderRegulatorCSV renders a regulator package as CSV.
func RenderRegulatorCSV(pkg *RegulatorPackage) (string, error) {
	var sb strings.Builder
	w := csv.NewWriter(&sb)

	// Header.
	if err := w.Write([]string{
		"Framework", "Control ID", "Control Name", "Status", "Evidence Refs",
	}); err != nil {
		return "", fmt.Errorf("assurance/export: CSV write error: %w", err)
	}

	for _, ctrl := range pkg.Controls {
		if err := w.Write([]string{
			pkg.Framework,
			ctrl.ControlID,
			ctrl.ControlName,
			ctrl.Status,
			strings.Join(ctrl.EvidenceRefs, ";"),
		}); err != nil {
			return "", fmt.Errorf("assurance/export: CSV write error: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("assurance/export: CSV flush error: %w", err)
	}

	return sb.String(), nil
}

// RenderRegulatorOSCAL renders a regulator package in NIST OSCAL format.
func RenderRegulatorOSCAL(pkg *RegulatorPackage) ([]byte, error) {
	// OSCAL assessment results structure.
	type OSCALResult struct {
		UUID        string `json:"uuid"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Start       string `json:"start"`
		End         string `json:"end"`
	}
	type OSCALAssessmentResults struct {
		UUID    string       `json:"uuid"`
		Results []OSCALResult `json:"results"`
	}
	type OSCALDocument struct {
		SchemaVersion     string                  `json:"schema-version"`
		AssessmentResults *OSCALAssessmentResults `json:"assessment-results"`
	}

	doc := OSCALDocument{
		SchemaVersion: "1.1.2",
		AssessmentResults: &OSCALAssessmentResults{
			UUID: fmt.Sprintf("ar-%s", pkg.GeneratedAt),
			Results: []OSCALResult{
				{
					UUID:        fmt.Sprintf("result-%s", pkg.GeneratedAt),
					Title:       fmt.Sprintf("%s Assessment", pkg.Framework),
					Description: fmt.Sprintf("Automated assessment: %s", pkg.Assessment.OverallStatus),
					Start:       pkg.GeneratedAt,
					End:         pkg.GeneratedAt,
				},
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}
