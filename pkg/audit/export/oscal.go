package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/audit"
)

// ---------------------------------------------------------------------------
// OSCAL Export -- NIST Open Security Controls Assessment Language
// ---------------------------------------------------------------------------
//
// OSCAL is the NIST standard for machine-readable security and compliance
// documentation. This exporter produces OSCAL Assessment Results documents
// from evidence bundles, enabling direct ingestion by GRC platforms and
// compliance automation pipelines.
//
// Reference: https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/
//
// The export targets OSCAL Assessment Results v1.1.2 schema.
// ---------------------------------------------------------------------------

// OSCALAssessmentResult follows the NIST OSCAL Assessment Results model.
// This is a simplified representation sufficient for automated compliance
// tooling.
type OSCALAssessmentResult struct {
	AssessmentResults OSCALAssessmentResults `json:"assessment-results"`
}

// OSCALAssessmentResults is the top-level OSCAL assessment results structure.
type OSCALAssessmentResults struct {
	UUID     string            `json:"uuid"`
	Metadata OSCALMetadata     `json:"metadata"`
	ImportAP OSCALImportAP     `json:"import-ap,omitempty"`
	Results  []OSCALResult     `json:"results"`
}

// OSCALMetadata provides document-level metadata.
type OSCALMetadata struct {
	Title        string          `json:"title"`
	LastModified string          `json:"last-modified"`
	Version      string          `json:"version"`
	OSCALVersion string          `json:"oscal-version"`
	Roles        []OSCALRole     `json:"roles,omitempty"`
	Parties      []OSCALParty    `json:"parties,omitempty"`
	Props        []OSCALProperty `json:"props,omitempty"`
}

// OSCALRole defines a role in the assessment context.
type OSCALRole struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// OSCALParty represents an organization or individual involved in the
// assessment.
type OSCALParty struct {
	UUID  string `json:"uuid"`
	Type  string `json:"type"` // "organization" or "person"
	Name  string `json:"name"`
}

// OSCALProperty is a typed name-value pair.
type OSCALProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
}

// OSCALImportAP references the assessment plan.
type OSCALImportAP struct {
	Href string `json:"href,omitempty"`
}

// OSCALResult is a single assessment result entry.
type OSCALResult struct {
	UUID        string                `json:"uuid"`
	Title       string                `json:"title"`
	Description string                `json:"description"`
	Start       string                `json:"start"`
	End         string                `json:"end,omitempty"`
	Props       []OSCALProperty       `json:"props,omitempty"`
	ReviewedControls OSCALReviewedControls `json:"reviewed-controls"`
	Findings    []OSCALFinding        `json:"findings"`
	Observations []OSCALObservation   `json:"observations,omitempty"`
	Attestations []OSCALAttestation   `json:"attestations,omitempty"`
}

// OSCALReviewedControls lists the controls that were assessed.
type OSCALReviewedControls struct {
	ControlSelections []OSCALControlSelection `json:"control-selections"`
}

// OSCALControlSelection identifies which controls were in scope.
type OSCALControlSelection struct {
	IncludeControls []OSCALSelectControlByID `json:"include-controls,omitempty"`
}

// OSCALSelectControlByID selects controls by their identifiers.
type OSCALSelectControlByID struct {
	WithIDs []string `json:"with-ids,omitempty"`
}

// OSCALFinding represents an individual control assessment finding.
type OSCALFinding struct {
	UUID        string              `json:"uuid"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Target      OSCALFindingTarget  `json:"target"`
	Props       []OSCALProperty     `json:"props,omitempty"`
	RelatedObservations []OSCALRelatedObservation `json:"related-observations,omitempty"`
}

// OSCALFindingTarget identifies the control being assessed.
type OSCALFindingTarget struct {
	Type       string `json:"type"` // "objective-id"
	TargetID   string `json:"target-id"`
	Status     OSCALFindingStatus `json:"status"`
}

// OSCALFindingStatus represents the finding outcome.
type OSCALFindingStatus struct {
	State string `json:"state"` // "satisfied", "not-satisfied"
}

// OSCALObservation records evidence collected during assessment.
type OSCALObservation struct {
	UUID        string          `json:"uuid"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Methods     []string        `json:"methods"`
	Collected   string          `json:"collected"`
	Props       []OSCALProperty `json:"props,omitempty"`
}

// OSCALRelatedObservation links a finding to supporting observations.
type OSCALRelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

// OSCALAttestation captures attestation information.
type OSCALAttestation struct {
	Parts []OSCALAttestationPart `json:"parts"`
}

// OSCALAttestationPart is a component of an attestation statement.
type OSCALAttestationPart struct {
	Name  string `json:"name"`
	Prose string `json:"prose"`
}

// ---------------------------------------------------------------------------
// Export function
// ---------------------------------------------------------------------------

// ExportOSCAL converts an evidence bundle into a NIST OSCAL Assessment
// Results document. The output conforms to OSCAL v1.1.2 schema.
func ExportOSCAL(bundle *audit.Bundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("export/oscal: nil bundle")
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Generate deterministic UUIDs from bundle content.
	resultUUID := deterministicUUID(bundle.ID + ":result")
	docUUID := deterministicUUID(bundle.ID + ":document")

	// Build observations from audit records.
	observations := make([]OSCALObservation, 0, len(bundle.Records))
	for _, r := range bundle.Records {
		obsUUID := deterministicUUID(fmt.Sprintf("%s:obs:%d", bundle.ID, r.Sequence))
		obs := OSCALObservation{
			UUID:        obsUUID,
			Title:       fmt.Sprintf("Audit Record #%d: %s", r.Sequence, r.Action),
			Description: fmt.Sprintf("Category: %s, Severity: %s, Actor: %s", r.Category, r.Severity, r.Actor),
			Methods:     []string{"EXAMINE", "TEST"},
			Collected:   r.Timestamp,
			Props: []OSCALProperty{
				{Name: "sequence", Value: fmt.Sprintf("%d", r.Sequence)},
				{Name: "record-hash", Value: r.RecordHash},
				{Name: "category", Value: string(r.Category)},
				{Name: "severity", Value: string(r.Severity)},
				{Name: "block-height", Value: fmt.Sprintf("%d", r.BlockHeight)},
			},
		}
		observations = append(observations, obs)
	}

	// Build observation UUID index for linking.
	obsUUIDs := make(map[uint64]string, len(bundle.Records))
	for _, r := range bundle.Records {
		obsUUIDs[r.Sequence] = deterministicUUID(fmt.Sprintf("%s:obs:%d", bundle.ID, r.Sequence))
	}

	// Build findings from control mappings.
	findings := make([]OSCALFinding, 0, len(bundle.Controls))
	controlIDs := make([]string, 0, len(bundle.Controls))
	for _, ctrl := range bundle.Controls {
		findingUUID := deterministicUUID(fmt.Sprintf("%s:finding:%s", bundle.ID, ctrl.ControlID))
		controlIDs = append(controlIDs, ctrl.ControlID)

		// Map control status to OSCAL state.
		oscalState := mapControlStatusToOSCAL(ctrl.Status)

		finding := OSCALFinding{
			UUID:        findingUUID,
			Title:       fmt.Sprintf("Assessment of %s: %s", ctrl.ControlID, ctrl.ControlName),
			Description: ctrl.Description,
			Target: OSCALFindingTarget{
				Type:     "objective-id",
				TargetID: ctrl.ControlID,
				Status: OSCALFindingStatus{
					State: oscalState,
				},
			},
		}

		// Add findings as props.
		if len(ctrl.Findings) > 0 {
			for i, f := range ctrl.Findings {
				finding.Props = append(finding.Props, OSCALProperty{
					Name:  fmt.Sprintf("finding-%d", i+1),
					Value: f,
				})
			}
		}

		// Link to observations.
		for _, ref := range ctrl.EvidenceRefs {
			if uuid, ok := obsUUIDs[ref]; ok {
				finding.RelatedObservations = append(finding.RelatedObservations, OSCALRelatedObservation{
					ObservationUUID: uuid,
				})
			}
		}

		findings = append(findings, finding)
	}

	// Build the OSCAL document.
	result := OSCALAssessmentResult{
		AssessmentResults: OSCALAssessmentResults{
			UUID: docUUID,
			Metadata: OSCALMetadata{
				Title:        fmt.Sprintf("Aethelred Compliance Assessment - %s", bundle.Framework),
				LastModified: now,
				Version:      "1.0.0",
				OSCALVersion: "1.1.2",
				Roles: []OSCALRole{
					{ID: "assessor", Title: "Automated Assessment Engine"},
					{ID: "system-owner", Title: "Aethelred Network Operator"},
				},
				Parties: []OSCALParty{
					{
						UUID: deterministicUUID(bundle.ID + ":party:aethelred"),
						Type: "organization",
						Name: "Aethelred Network",
					},
				},
				Props: []OSCALProperty{
					{Name: "framework", Value: string(bundle.Framework)},
					{Name: "bundle-id", Value: bundle.ID},
					{Name: "schema-version", Value: bundle.SchemaVersion},
					{Name: "content-hash", Value: bundle.ContentHash},
				},
			},
			Results: []OSCALResult{
				{
					UUID:        resultUUID,
					Title:       fmt.Sprintf("Automated Assessment: %s", bundle.Framework),
					Description: "Automated compliance assessment generated from Aethelred audit evidence bundle.",
					Start:       bundle.CreatedAt,
					End:         now,
					Props: []OSCALProperty{
						{Name: "total-records", Value: fmt.Sprintf("%d", len(bundle.Records))},
						{Name: "total-seals", Value: fmt.Sprintf("%d", len(bundle.Seals))},
						{Name: "total-attestations", Value: fmt.Sprintf("%d", len(bundle.Attestations))},
						{Name: "total-proofs", Value: fmt.Sprintf("%d", len(bundle.Proofs))},
						{Name: "chain-intact", Value: fmt.Sprintf("%t", audit.VerifyChain(bundle.Records) == nil)},
					},
					ReviewedControls: OSCALReviewedControls{
						ControlSelections: []OSCALControlSelection{
							{
								IncludeControls: []OSCALSelectControlByID{
									{WithIDs: controlIDs},
								},
							},
						},
					},
					Findings:     findings,
					Observations: observations,
				},
			},
		},
	}

	return json.MarshalIndent(result, "", "  ")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deterministicUUID generates a deterministic UUID-like string from a seed.
// This ensures the same bundle always produces the same OSCAL document.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	h := hex.EncodeToString(sum[:16])
	// Format as UUID v4-like: 8-4-4-4-12
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		h[0:8], h[4:8], h[8:12], h[12:16], h[16:28])
}

// mapControlStatusToOSCAL converts an Aethelred control status to the
// OSCAL finding state vocabulary.
func mapControlStatusToOSCAL(status audit.ControlStatus) string {
	switch status {
	case audit.ControlSatisfied:
		return "satisfied"
	case audit.ControlPartial:
		return "not-satisfied" // OSCAL does not have partial; map to not-satisfied with props.
	case audit.ControlNotSatisfied:
		return "not-satisfied"
	case audit.ControlNotApplicable:
		return "not-applicable"
	default:
		return "not-satisfied"
	}
}
