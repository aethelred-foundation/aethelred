package export

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ControlLedgerOSCALDocument is a compact OSCAL-inspired assessment result
// document for control-ledger exports.
type ControlLedgerOSCALDocument struct {
	AssessmentResults ControlLedgerOSCALAssessmentResults `json:"assessment-results"`
}

type ControlLedgerOSCALAssessmentResults struct {
	UUID     string                     `json:"uuid"`
	Metadata ControlLedgerOSCALMetadata `json:"metadata"`
	Results  []ControlLedgerOSCALResult `json:"results"`
}

type ControlLedgerOSCALMetadata struct {
	Title        string                       `json:"title"`
	LastModified string                       `json:"last-modified"`
	Version      string                       `json:"version"`
	OSCALVersion string                       `json:"oscal-version"`
	Roles        []ControlLedgerOSCALRole     `json:"roles,omitempty"`
	Parties      []ControlLedgerOSCALParty    `json:"parties,omitempty"`
	Props        []ControlLedgerOSCALProperty `json:"props,omitempty"`
}

type ControlLedgerOSCALRole struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type ControlLedgerOSCALParty struct {
	UUID string `json:"uuid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type ControlLedgerOSCALProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
}

type ControlLedgerOSCALResult struct {
	UUID             string                             `json:"uuid"`
	Title            string                             `json:"title"`
	Description      string                             `json:"description"`
	Start            string                             `json:"start"`
	End              string                             `json:"end,omitempty"`
	ReviewedControls ControlLedgerOSCALReviewedControls `json:"reviewed-controls"`
	Findings         []ControlLedgerOSCALFinding        `json:"findings"`
	Observations     []ControlLedgerOSCALObservation    `json:"observations,omitempty"`
	Attestations     []ControlLedgerOSCALAttestation    `json:"attestations,omitempty"`
}

type ControlLedgerOSCALReviewedControls struct {
	ControlSelections []ControlLedgerOSCALControlSelection `json:"control-selections"`
}

type ControlLedgerOSCALControlSelection struct {
	IncludeControls []ControlLedgerOSCALSelectControlByID `json:"include-controls,omitempty"`
}

type ControlLedgerOSCALSelectControlByID struct {
	WithIDs []string `json:"with-ids,omitempty"`
}

type ControlLedgerOSCALFinding struct {
	UUID        string                          `json:"uuid"`
	Title       string                          `json:"title"`
	Description string                          `json:"description"`
	Target      ControlLedgerOSCALFindingTarget `json:"target"`
	Props       []ControlLedgerOSCALProperty    `json:"props,omitempty"`
}

type ControlLedgerOSCALFindingTarget struct {
	Type     string                          `json:"type"`
	TargetID string                          `json:"target-id"`
	Status   ControlLedgerOSCALFindingStatus `json:"status"`
}

type ControlLedgerOSCALFindingStatus struct {
	State string `json:"state"`
}

type ControlLedgerOSCALObservation struct {
	UUID        string                       `json:"uuid"`
	Title       string                       `json:"title"`
	Description string                       `json:"description"`
	Methods     []string                     `json:"methods"`
	Collected   string                       `json:"collected"`
	Props       []ControlLedgerOSCALProperty `json:"props,omitempty"`
}

type ControlLedgerOSCALAttestation struct {
	Parts []ControlLedgerOSCALAttestationPart `json:"parts"`
}

type ControlLedgerOSCALAttestationPart struct {
	Name  string `json:"name"`
	Prose string `json:"prose"`
}

// ExportControlLedgerOSCAL converts a control ledger into a machine-readable
// OSCAL assessment results document.
func ExportControlLedgerOSCAL(ledger any) ([]byte, error) {
	snap, err := normalizeControlLedger(ledger)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	controlIDs := make([]string, 0, len(snap.Controls))
	for _, control := range snap.Controls {
		controlIDs = append(controlIDs, control.ControlID)
	}

	observations := make([]ControlLedgerOSCALObservation, 0, len(snap.Controls)+len(snap.Passports)+len(snap.ApproverAttestations)+len(snap.ValueSettlements)+len(snap.PolicyReceipts)+len(snap.Seals))
	for _, control := range snap.Controls {
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":control:" + control.ControlID),
			Title:       control.ControlName,
			Description: control.Description,
			Methods:     []string{"EXAMINE", "TEST"},
			Collected:   snap.CreatedAt,
			Props: []ControlLedgerOSCALProperty{
				{Name: "control-id", Value: control.ControlID},
				{Name: "status", Value: control.Status},
				{Name: "evidence-count", Value: fmt.Sprintf("%d", control.EvidenceCount)},
			},
		})
	}
	for _, passport := range snap.Passports {
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":passport:" + passport.DID),
			Title:       "Enterprise Agent Passport",
			Description: passport.HumanOwner,
			Methods:     []string{"EXAMINE"},
			Collected:   passport.IssuedAt,
			Props: []ControlLedgerOSCALProperty{
				{Name: "did", Value: passport.DID},
				{Name: "issuer", Value: passport.Issuer},
				{Name: "public-key-hash", Value: passport.PublicKeyHash},
			},
		})
	}
	for _, attestation := range snap.ApproverAttestations {
		description := attestation.Comment
		if description == "" {
			description = attestation.Action
		}
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":approver-attestation:" + attestation.ID),
			Title:       "Authenticated Approver Attestation",
			Description: description,
			Methods:     []string{"EXAMINE"},
			Collected:   attestation.AuthorizedAt,
			Props: []ControlLedgerOSCALProperty{
				{Name: "approver-attestation-id", Value: attestation.ID},
				{Name: "approval-record-id", Value: attestation.ApprovalRecordID},
				{Name: "approver-did", Value: attestation.ApproverDID},
				{Name: "passport-did", Value: attestation.PassportDID},
				{Name: "policy-receipt-id", Value: attestation.PolicyReceiptID},
				{Name: "decision", Value: attestation.Decision},
				{Name: "trace-link-id", Value: attestation.TraceLinkID},
				{Name: "seal-id", Value: attestation.SealID},
			},
		})
	}
	for _, settlement := range snap.ValueSettlements {
		description := settlement.ReasonCode
		if description == "" {
			description = settlement.Status
		}
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":value-settlement:" + settlement.ID),
			Title:       "Policy-Bound Value Settlement",
			Description: description,
			Methods:     []string{"EXAMINE", "TEST"},
			Collected:   settlement.SettledAt,
			Props: []ControlLedgerOSCALProperty{
				{Name: "settlement-id", Value: settlement.SettlementID},
				{Name: "network", Value: settlement.Network},
				{Name: "counterparty", Value: settlement.Counterparty},
				{Name: "beneficiary", Value: settlement.Beneficiary},
				{Name: "status", Value: settlement.Status},
				{Name: "policy-receipt-id", Value: settlement.PolicyReceiptID},
				{Name: "seal-id", Value: settlement.SealID},
				{Name: "tx-hash", Value: settlement.TxHash},
			},
		})
	}
	for _, receipt := range snap.PolicyReceipts {
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":receipt:" + receipt.ID),
			Title:       "Signed Policy Receipt",
			Description: receipt.Action,
			Methods:     []string{"EXAMINE"},
			Collected:   receipt.EvaluatedAt,
			Props: []ControlLedgerOSCALProperty{
				{Name: "receipt-id", Value: receipt.ID},
				{Name: "decision", Value: receipt.Decision},
				{Name: "content-hash", Value: receipt.ContentHash},
			},
		})
	}
	for _, seal := range snap.Seals {
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":seal:" + seal.SealID),
			Title:       "Execution Seal",
			Description: seal.JobID,
			Methods:     []string{"TEST"},
			Collected:   seal.Timestamp,
			Props: []ControlLedgerOSCALProperty{
				{Name: "seal-id", Value: seal.SealID},
				{Name: "output-hash", Value: seal.OutputHash},
				{Name: "validator-count", Value: fmt.Sprintf("%d", seal.ValidatorCount)},
			},
		})
	}
	for _, pkg := range snap.TrustCompliancePackages {
		description := pkg.Format
		if pkg.AuditAnchorAction != "" {
			description = pkg.AuditAnchorAction
		}
		observations = append(observations, ControlLedgerOSCALObservation{
			UUID:        deterministicUUID(snap.LedgerID + ":trust-compliance-package:" + pkg.ID),
			Title:       "Anchored Trust Compliance Package",
			Description: description,
			Methods:     []string{"EXAMINE"},
			Collected:   pkg.GeneratedAt,
			Props: []ControlLedgerOSCALProperty{
				{Name: "package-id", Value: pkg.ID},
				{Name: "package-hash", Value: pkg.PackageHash},
				{Name: "document-hash", Value: pkg.DocumentHash},
				{Name: "signed", Value: boolString(pkg.Signed)},
				{Name: "audit-anchor-sequence", Value: fmt.Sprintf("%d", pkg.AuditAnchorSequence)},
			},
		})
	}

	findings := make([]ControlLedgerOSCALFinding, 0, len(snap.Controls))
	for _, control := range snap.Controls {
		findings = append(findings, ControlLedgerOSCALFinding{
			UUID:        deterministicUUID(snap.LedgerID + ":finding:" + control.ControlID),
			Title:       control.ControlName,
			Description: control.Description,
			Target: ControlLedgerOSCALFindingTarget{
				Type:     "objective-id",
				TargetID: control.ControlID,
				Status: ControlLedgerOSCALFindingStatus{
					State: normalizeFindingState(control.Status),
				},
			},
			Props: []ControlLedgerOSCALProperty{
				{Name: "evidence-count", Value: fmt.Sprintf("%d", control.EvidenceCount)},
			},
		})
	}

	doc := ControlLedgerOSCALDocument{
		AssessmentResults: ControlLedgerOSCALAssessmentResults{
			UUID: deterministicUUID(snap.LedgerID + ":document"),
			Metadata: ControlLedgerOSCALMetadata{
				Title:        "Aethelred Control Ledger Assessment",
				LastModified: now,
				Version:      snap.Version,
				OSCALVersion: "1.1.2",
				Roles: []ControlLedgerOSCALRole{
					{ID: "assessor", Title: "Automated Control Ledger Exporter"},
					{ID: "system-owner", Title: "Aethelred Control Plane"},
				},
				Parties: []ControlLedgerOSCALParty{
					{UUID: deterministicUUID(snap.LedgerID + ":party:aethelred"), Type: "organization", Name: "Aethelred"},
				},
				Props: []ControlLedgerOSCALProperty{
					{Name: "ledger-id", Value: snap.LedgerID},
					{Name: "framework", Value: snap.Framework},
					{Name: "controls-total", Value: fmt.Sprintf("%d", snap.Summary.TotalControls)},
					{Name: "passports-total", Value: fmt.Sprintf("%d", snap.Summary.TotalPassports)},
					{Name: "approver-attestations-total", Value: fmt.Sprintf("%d", snap.Summary.TotalApproverAttestations)},
					{Name: "value-settlements-total", Value: fmt.Sprintf("%d", snap.Summary.TotalValueSettlements)},
					{Name: "policy-receipts-total", Value: fmt.Sprintf("%d", snap.Summary.TotalPolicyReceipts)},
					{Name: "seals-total", Value: fmt.Sprintf("%d", snap.Summary.TotalSeals)},
					{Name: "trace-links-total", Value: fmt.Sprintf("%d", snap.Summary.TotalTraceLinks)},
					{Name: "trust-compliance-packages-total", Value: fmt.Sprintf("%d", snap.Summary.TotalTrustCompliancePackages)},
					{Name: "chain-intact", Value: boolString(snap.Summary.ChainIntact)},
				},
			},
			Results: []ControlLedgerOSCALResult{
				{
					UUID:        deterministicUUID(snap.LedgerID + ":result"),
					Title:       "Control Ledger Assessment Result",
					Description: "Auditor-ready export of identity, policy, seal, traceability, and anchored trust compliance evidence",
					Start:       snap.CreatedAt,
					End:         now,
					ReviewedControls: ControlLedgerOSCALReviewedControls{
						ControlSelections: []ControlLedgerOSCALControlSelection{
							{IncludeControls: []ControlLedgerOSCALSelectControlByID{{WithIDs: controlIDs}}},
						},
					},
					Findings:     findings,
					Observations: observations,
					Attestations: []ControlLedgerOSCALAttestation{
						{
							Parts: []ControlLedgerOSCALAttestationPart{
								{Name: "summary", Prose: fmt.Sprintf("controls=%d, passports=%d, approver_attestations=%d, value_settlements=%d, receipts=%d, seals=%d, trace_links=%d, trust_compliance_packages=%d", snap.Summary.TotalControls, snap.Summary.TotalPassports, snap.Summary.TotalApproverAttestations, snap.Summary.TotalValueSettlements, snap.Summary.TotalPolicyReceipts, snap.Summary.TotalSeals, snap.Summary.TotalTraceLinks, snap.Summary.TotalTrustCompliancePackages)},
								{Name: "integrity", Prose: fmt.Sprintf("chain_intact=%s", boolString(snap.Summary.ChainIntact))},
							},
						},
					},
				},
			},
		},
	}

	for _, attestation := range snap.ApproverAttestations {
		statement := attestation.Comment
		if statement == "" {
			statement = fmt.Sprintf("%s approved %s", attestation.Approver, attestation.Resource)
		}
		doc.AssessmentResults.Results[0].Attestations = append(doc.AssessmentResults.Results[0].Attestations, ControlLedgerOSCALAttestation{
			Parts: []ControlLedgerOSCALAttestationPart{
				{Name: "approver", Prose: firstNonEmpty(attestation.ApproverDID, attestation.Approver)},
				{Name: "control", Prose: attestation.Action},
				{Name: "statement", Prose: statement},
			},
		})
	}
	for _, settlement := range snap.ValueSettlements {
		statement := fmt.Sprintf("%.2f %s settled to %s on %s", settlement.FiatAmount, settlement.FiatCurrency, settlement.Counterparty, settlement.Network)
		doc.AssessmentResults.Results[0].Attestations = append(doc.AssessmentResults.Results[0].Attestations, ControlLedgerOSCALAttestation{
			Parts: []ControlLedgerOSCALAttestationPart{
				{Name: "settlement", Prose: settlement.SettlementID},
				{Name: "counterparty", Prose: settlement.Counterparty},
				{Name: "statement", Prose: statement},
			},
		})
	}

	return json.MarshalIndent(doc, "", "  ")
}

func deterministicUUID(seed string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String()
}

func normalizeFindingState(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return "not-assessed"
	}
	return status
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
