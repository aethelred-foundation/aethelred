// Package exports provides generators for exporting compliance assessment
// reports in standard formats including JSON, CSV, and OSCAL.
package exports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
	"github.com/aethelred/aethelred/pkg/compliance/assessor"
)

// ---------------------------------------------------------------------------
// JSON export
// ---------------------------------------------------------------------------

// ExportJSON serializes an assessment report to a formatted JSON byte slice.
func ExportJSON(report *assessor.AssessmentReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("ExportJSON: %w: report cannot be nil", compliance.ErrInvalidInput)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("ExportJSON: %w: %v", compliance.ErrExportFailed, err)
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

// ExportCSV generates a CSV-formatted control matrix from an assessment
// report. Each row represents a control with its coverage status, mapped
// capabilities, and evidence summary.
func ExportCSV(report *assessor.AssessmentReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("ExportCSV: %w: report cannot be nil", compliance.ErrInvalidInput)
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Write header.
	header := []string{
		"Framework",
		"Control ID",
		"Control Name",
		"Category",
		"Coverage Level",
		"Capabilities",
		"Evidence",
		"Gap Description",
		"Recommendation",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("ExportCSV: %w: csv header write failed: %v", compliance.ErrExportFailed, err)
	}

	// Write control rows.
	for _, cr := range report.ControlResults {
		caps := ""
		for i, c := range cr.Capabilities {
			if i > 0 {
				caps += ", "
			}
			caps += c
		}

		row := []string{
			report.FrameworkName,
			cr.ControlID,
			cr.ControlName,
			cr.Category,
			cr.CoverageName,
			caps,
			cr.Evidence,
			cr.GapDescription,
			cr.Recommendation,
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("ExportCSV: %w: csv row write failed: %v", compliance.ErrExportFailed, err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("ExportCSV: %w: csv flush failed: %v", compliance.ErrExportFailed, err)
	}

	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// OSCAL export
// ---------------------------------------------------------------------------

// OSCAL types implement a subset of the NIST OSCAL (Open Security Controls
// Assessment Language) specification for machine-readable compliance output.
//
// Reference: https://pages.nist.gov/OSCAL/

// OSCALAssessmentResult represents an OSCAL assessment-results document.
type OSCALAssessmentResult struct {
	UUID     string           `json:"uuid"`
	Metadata OSCALMetadata    `json:"metadata"`
	Results  []OSCALResult    `json:"results"`
}

// OSCALMetadata contains document-level metadata.
type OSCALMetadata struct {
	Title        string    `json:"title"`
	LastModified time.Time `json:"last-modified"`
	Version      string    `json:"version"`
	OSCALVersion string    `json:"oscal-version"`
}

// OSCALResult represents a single assessment result.
type OSCALResult struct {
	UUID        string              `json:"uuid"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Start       time.Time           `json:"start"`
	Findings    []OSCALFinding      `json:"findings"`
	Props       []OSCALProperty     `json:"props,omitempty"`
}

// OSCALFinding represents a single control finding.
type OSCALFinding struct {
	UUID        string          `json:"uuid"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Target      OSCALTarget     `json:"target"`
	Props       []OSCALProperty `json:"props,omitempty"`
}

// OSCALTarget identifies the subject of a finding.
type OSCALTarget struct {
	Type      string `json:"type"`
	TargetID  string `json:"target-id"`
	Status    string `json:"status"`
}

// OSCALProperty represents a name-value property.
type OSCALProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ExportOSCAL generates an OSCAL assessment-results document from an
// assessment report.
func ExportOSCAL(report *assessor.AssessmentReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("ExportOSCAL: %w: report cannot be nil", compliance.ErrInvalidInput)
	}

	findings := make([]OSCALFinding, 0, len(report.ControlResults))
	for i, cr := range report.ControlResults {
		status := mapCoverageToOSCALStatus(cr.CoverageName)

		props := []OSCALProperty{
			{Name: "coverage-level", Value: cr.CoverageName},
			{Name: "category", Value: cr.Category},
		}

		if cr.GapDescription != "" {
			props = append(props, OSCALProperty{
				Name: "gap-description", Value: cr.GapDescription,
			})
		}

		for _, cap := range cr.Capabilities {
			props = append(props, OSCALProperty{
				Name: "aethelred-capability", Value: cap,
			})
		}

		findings = append(findings, OSCALFinding{
			UUID:        fmt.Sprintf("finding-%s-%d", report.FrameworkID, i),
			Title:       cr.ControlName,
			Description: cr.Evidence,
			Target: OSCALTarget{
				Type:     "control",
				TargetID: cr.ControlID,
				Status:   status,
			},
			Props: props,
		})
	}

	result := OSCALAssessmentResult{
		UUID: fmt.Sprintf("assessment-%s-%d", report.FrameworkID, report.AssessedAt.Unix()),
		Metadata: OSCALMetadata{
			Title:        fmt.Sprintf("Aethelred Compliance Assessment: %s", report.FrameworkName),
			LastModified: report.AssessedAt,
			Version:      "1.0.0",
			OSCALVersion: "1.1.2",
		},
		Results: []OSCALResult{
			{
				UUID:        fmt.Sprintf("result-%s-%d", report.FrameworkID, report.AssessedAt.Unix()),
				Title:       fmt.Sprintf("%s Assessment Results", report.FrameworkName),
				Description: fmt.Sprintf("Automated compliance assessment of Aethelred platform capabilities against %s (%s)", report.FrameworkName, report.Version),
				Start:       report.AssessedAt,
				Findings:    findings,
				Props: []OSCALProperty{
					{Name: "overall-score", Value: fmt.Sprintf("%d", report.OverallScore)},
					{Name: "total-controls", Value: fmt.Sprintf("%d", report.TotalControls)},
					{Name: "full-coverage", Value: fmt.Sprintf("%d", report.FullCount)},
					{Name: "partial-coverage", Value: fmt.Sprintf("%d", report.PartialCount)},
					{Name: "gap-count", Value: fmt.Sprintf("%d", report.GapCount)},
				},
			},
		},
	}

	return json.MarshalIndent(result, "", "  ")
}

// mapCoverageToOSCALStatus maps a coverage level string to an OSCAL
// finding status value.
func mapCoverageToOSCALStatus(coverage string) string {
	switch coverage {
	case "Full":
		return "satisfied"
	case "Partial":
		return "other"
	case "Planned":
		return "other"
	case "Not Applicable":
		return "not-applicable"
	case "Gap":
		return "not-satisfied"
	default:
		return "other"
	}
}
