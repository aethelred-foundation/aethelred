package export

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// NIST OSCAL Export
// ---------------------------------------------------------------------------
//
// Exports evidence bundles in NIST OSCAL (Open Security Controls Assessment
// Language) format. OSCAL is the standard machine-readable format for
// security assessment plans, results, and system security plans.
//
// Reference: https://pages.nist.gov/OSCAL/
// ---------------------------------------------------------------------------

// OSCALMetadata contains document-level metadata.
type OSCALMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

// OSCALObservation is an individual finding or data point.
type OSCALObservation struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Methods     []string `json:"methods"`
	Collected   string   `json:"collected"`
}

// OSCALFinding represents a compliance finding.
type OSCALFinding struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// OSCALResult is a single assessment result.
type OSCALResult struct {
	UUID         string             `json:"uuid"`
	Title        string             `json:"title"`
	Description  string             `json:"description"`
	Start        string             `json:"start"`
	End          string             `json:"end"`
	Observations []OSCALObservation `json:"observations,omitempty"`
	Findings     []OSCALFinding     `json:"findings,omitempty"`
}

// OSCALAssessmentResults is the top-level assessment results document.
type OSCALAssessmentResults struct {
	UUID     string        `json:"uuid"`
	Metadata OSCALMetadata `json:"metadata"`
	Results  []OSCALResult `json:"results"`
}

// OSCALDocument is the complete OSCAL document wrapper.
type OSCALDocument struct {
	AssessmentResults *OSCALAssessmentResults `json:"assessment-results"`
}

// OSCALExporter exports evidence bundles to NIST OSCAL format.
type OSCALExporter struct{}

// NewOSCALExporter creates a new OSCAL exporter.
func NewOSCALExporter() *OSCALExporter {
	return &OSCALExporter{}
}

// ExportBundle exports an evidence bundle to OSCAL assessment results format.
func (e *OSCALExporter) ExportBundle(bundle *evidence.EvidenceBundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("evidence/export/oscal: nil bundle")
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Build observations from records.
	var observations []OSCALObservation
	for _, r := range bundle.Records {
		observations = append(observations, OSCALObservation{
			UUID:        uuid.New().String(),
			Title:       fmt.Sprintf("%s: %s", r.Type, r.Action),
			Description: fmt.Sprintf("Evidence record from %s by %s", r.Timestamp, r.Actor),
			Methods:     []string{"AUTOMATED"},
			Collected:   r.Timestamp,
		})
	}

	// Build findings from seals.
	var findings []OSCALFinding
	for _, s := range bundle.Seals {
		findings = append(findings, OSCALFinding{
			UUID:        uuid.New().String(),
			Title:       fmt.Sprintf("Seal Verification: %s", s.SealID),
			Description: fmt.Sprintf("Digital seal with %d validator attestations at block %d", s.ValidatorCount, s.BlockHeight),
		})
	}

	doc := OSCALDocument{
		AssessmentResults: &OSCALAssessmentResults{
			UUID: uuid.New().String(),
			Metadata: OSCALMetadata{
				Title:        fmt.Sprintf("Aethelred Evidence Assessment - %s", bundle.Framework),
				LastModified: now,
				Version:      bundle.Version,
				OSCALVersion: "1.1.2",
			},
			Results: []OSCALResult{
				{
					UUID:         uuid.New().String(),
					Title:        fmt.Sprintf("Evidence Bundle Assessment: %s", bundle.ID),
					Description:  fmt.Sprintf("Automated assessment for framework %s", bundle.Framework),
					Start:        bundle.CreatedAt,
					End:          now,
					Observations: observations,
					Findings:     findings,
				},
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}
