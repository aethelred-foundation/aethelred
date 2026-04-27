package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus describes the
// receipt collection posture for a launch clearance register.
type SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchReceiptManifestBlocked                  SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus = "collection_blocked"
	SecureCellGovernmentAgentExecutionLaunchReceiptManifestAwaitingAcknowledgements SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus = "awaiting_operator_acknowledgements"
	SecureCellGovernmentAgentExecutionLaunchReceiptManifestReady                    SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus = "collection_ready"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus records the
// expected posture for one launch receipt.
type SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchReceiptRequirementBlocked                SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingAcknowledgement SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus = "pending_acknowledgement"
	SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingCollection      SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus = "pending_collection"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptRequirement is one receipt
// the operator must preserve before launch can be treated as governed.
type SecureCellGovernmentAgentExecutionLaunchReceiptRequirement struct {
	RequirementID       string                                                           `json:"requirement_id"`
	Sequence            int                                                              `json:"sequence"`
	CellID              string                                                           `json:"cell_id"`
	RegisterID          string                                                           `json:"register_id"`
	AuthorizationID     string                                                           `json:"authorization_id"`
	ClearanceItemID     string                                                           `json:"clearance_item_id"`
	GateCode            string                                                           `json:"gate_code"`
	ReceiptType         string                                                           `json:"receipt_type"`
	Status              SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus `json:"status"`
	ValidationRule      string                                                           `json:"validation_rule"`
	ExpectedAttachment  string                                                           `json:"expected_attachment"`
	EvidenceBindingID   string                                                           `json:"evidence_binding_id,omitempty"`
	ClearanceItemDigest string                                                           `json:"clearance_item_digest"`
	RequirementDigest   string                                                           `json:"requirement_digest"`
	GeneratedAt         time.Time                                                        `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchReceiptManifest is the expected
// receipt contract for launch clearance.
type SecureCellGovernmentAgentExecutionLaunchReceiptManifest struct {
	ManifestID                         string                                                        `json:"manifest_id"`
	RegisterID                         string                                                        `json:"register_id"`
	AuthorizationID                    string                                                        `json:"authorization_id"`
	VerificationID                     string                                                        `json:"verification_id"`
	BundleID                           string                                                        `json:"bundle_id"`
	CellID                             string                                                        `json:"cell_id"`
	Name                               string                                                        `json:"name"`
	Jurisdiction                       string                                                        `json:"jurisdiction,omitempty"`
	ServiceCode                        string                                                        `json:"service_code,omitempty"`
	ServiceTier                        string                                                        `json:"service_tier,omitempty"`
	Status                             SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus `json:"status"`
	ClearanceStatus                    SecureCellGovernmentAgentExecutionLaunchClearanceStatus       `json:"clearance_status"`
	CanAcceptReceipts                  bool                                                          `json:"can_accept_receipts"`
	CanLaunchAfterReceipts             bool                                                          `json:"can_launch_after_receipts"`
	ReceiptRequirementCount            int                                                           `json:"receipt_requirement_count"`
	PendingAcknowledgementReceiptCount int                                                           `json:"pending_acknowledgement_receipt_count"`
	PendingCollectionReceiptCount      int                                                           `json:"pending_collection_receipt_count"`
	BlockedReceiptCount                int                                                           `json:"blocked_receipt_count"`
	RemediationReceiptCount            int                                                           `json:"remediation_receipt_count"`
	EvidencePreservationReceiptCount   int                                                           `json:"evidence_preservation_receipt_count"`
	RequiredReceiptTypes               []string                                                      `json:"required_receipt_types,omitempty"`
	WitnessID                          string                                                        `json:"witness_id"`
	LedgerID                           string                                                        `json:"ledger_id"`
	QueueID                            string                                                        `json:"queue_id"`
	RegisterDigest                     string                                                        `json:"register_digest"`
	LaunchDigest                       string                                                        `json:"launch_digest"`
	VerificationDigest                 string                                                        `json:"verification_digest"`
	BundleDigest                       string                                                        `json:"bundle_digest"`
	Requirements                       []SecureCellGovernmentAgentExecutionLaunchReceiptRequirement  `json:"requirements"`
	ManifestDigest                     string                                                        `json:"manifest_digest"`
	GeneratedAt                        time.Time                                                     `json:"generated_at"`
	UpdatedAt                          time.Time                                                     `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchReceiptManifest returns the launch receipt
// manifest for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchReceiptManifest(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchReceiptManifest, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchReceiptManifests(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-receipts: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchReceiptManifests returns launch receipt
// manifests for matching government-service launch clearances.
func (s *Service) ListGovernmentAgentExecutionLaunchReceiptManifests(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchReceiptManifest, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-receipts: service is required")
	}
	registers, err := s.ListGovernmentAgentExecutionLaunchClearances(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	manifests := make([]SecureCellGovernmentAgentExecutionLaunchReceiptManifest, 0, len(registers))
	for _, register := range registers {
		manifests = append(manifests, secureCellGovernmentAgentExecutionLaunchReceiptManifest(register, now))
	}
	sort.SliceStable(manifests, func(i, j int) bool {
		if manifests[i].Status == manifests[j].Status {
			if manifests[i].BlockedReceiptCount == manifests[j].BlockedReceiptCount {
				if manifests[i].PendingAcknowledgementReceiptCount == manifests[j].PendingAcknowledgementReceiptCount {
					return manifests[i].CellID < manifests[j].CellID
				}
				return manifests[i].PendingAcknowledgementReceiptCount > manifests[j].PendingAcknowledgementReceiptCount
			}
			return manifests[i].BlockedReceiptCount > manifests[j].BlockedReceiptCount
		}
		return secureCellGovernmentAgentExecutionLaunchReceiptManifestStatusRank(manifests[i].Status) < secureCellGovernmentAgentExecutionLaunchReceiptManifestStatusRank(manifests[j].Status)
	})
	return manifests, nil
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifest(
	register SecureCellGovernmentAgentExecutionLaunchClearanceRegister,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptManifest {
	requirements := make([]SecureCellGovernmentAgentExecutionLaunchReceiptRequirement, 0)
	sequence := 1
	for _, item := range register.Items {
		for _, receiptType := range item.RequiredReceiptTypes {
			requirements = append(requirements, secureCellGovernmentAgentExecutionLaunchReceiptRequirement(register, item, receiptType, sequence, generatedAt))
			sequence++
		}
	}
	sort.SliceStable(requirements, func(i, j int) bool {
		if requirements[i].Status == requirements[j].Status {
			if requirements[i].GateCode == requirements[j].GateCode {
				if requirements[i].ReceiptType == requirements[j].ReceiptType {
					return requirements[i].Sequence < requirements[j].Sequence
				}
				return requirements[i].ReceiptType < requirements[j].ReceiptType
			}
			return requirements[i].GateCode < requirements[j].GateCode
		}
		return secureCellGovernmentAgentExecutionLaunchReceiptRequirementStatusRank(requirements[i].Status) < secureCellGovernmentAgentExecutionLaunchReceiptRequirementStatusRank(requirements[j].Status)
	})
	manifest := SecureCellGovernmentAgentExecutionLaunchReceiptManifest{
		RegisterID:             register.RegisterID,
		AuthorizationID:        register.AuthorizationID,
		VerificationID:         register.VerificationID,
		BundleID:               register.BundleID,
		CellID:                 register.CellID,
		Name:                   register.Name,
		Jurisdiction:           register.Jurisdiction,
		ServiceCode:            register.ServiceCode,
		ServiceTier:            register.ServiceTier,
		ClearanceStatus:        register.Status,
		CanAcceptReceipts:      len(requirements) > 0,
		CanLaunchAfterReceipts: register.CanLaunchNow || register.CanLaunchAfterOperatorReview,
		WitnessID:              register.WitnessID,
		LedgerID:               register.LedgerID,
		QueueID:                register.QueueID,
		RegisterDigest:         register.RegisterDigest,
		LaunchDigest:           register.LaunchDigest,
		VerificationDigest:     register.VerificationDigest,
		BundleDigest:           register.BundleDigest,
		Requirements:           requirements,
		GeneratedAt:            generatedAt.UTC(),
		UpdatedAt:              register.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(requirements))
	for _, requirement := range manifest.Requirements {
		manifest.ReceiptRequirementCount++
		receiptTypes = append(receiptTypes, requirement.ReceiptType)
		switch requirement.Status {
		case SecureCellGovernmentAgentExecutionLaunchReceiptRequirementBlocked:
			manifest.BlockedReceiptCount++
		case SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingAcknowledgement:
			manifest.PendingAcknowledgementReceiptCount++
		default:
			manifest.PendingCollectionReceiptCount++
		}
		switch requirement.ReceiptType {
		case "remediation_receipt":
			manifest.RemediationReceiptCount++
		case "evidence_preservation_receipt":
			manifest.EvidencePreservationReceiptCount++
		}
	}
	manifest.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	manifest.Status = secureCellGovernmentAgentExecutionLaunchReceiptManifestStatus(manifest)
	manifest.ManifestDigest = secureCellGovernmentAgentExecutionLaunchReceiptManifestDigest(manifest)
	manifest.ManifestID = "government-agent-execution-launch-receipts:" + manifest.CellID + ":" + manifest.ManifestDigest[:12]
	return manifest
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirement(
	register SecureCellGovernmentAgentExecutionLaunchClearanceRegister,
	item SecureCellGovernmentAgentExecutionLaunchClearanceItem,
	receiptType string,
	sequence int,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptRequirement {
	requirement := SecureCellGovernmentAgentExecutionLaunchReceiptRequirement{
		Sequence:            sequence,
		CellID:              register.CellID,
		RegisterID:          register.RegisterID,
		AuthorizationID:     register.AuthorizationID,
		ClearanceItemID:     item.ItemID,
		GateCode:            item.GateCode,
		ReceiptType:         strings.TrimSpace(receiptType),
		Status:              secureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus(item),
		ValidationRule:      secureCellGovernmentAgentExecutionLaunchReceiptValidationRule(item, receiptType),
		ExpectedAttachment:  secureCellGovernmentAgentExecutionLaunchReceiptExpectedAttachment(item, receiptType),
		EvidenceBindingID:   item.EvidenceBindingID,
		ClearanceItemDigest: item.ItemDigest,
		GeneratedAt:         generatedAt.UTC(),
	}
	requirement.RequirementDigest = secureCellGovernmentAgentExecutionLaunchReceiptRequirementDigest(requirement)
	requirement.RequirementID = "government-agent-execution-launch-receipt:" + requirement.CellID + ":" + requirement.RequirementDigest[:12]
	return requirement
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus(item SecureCellGovernmentAgentExecutionLaunchClearanceItem) SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchClearanceItemRemediationRequired:
		return SecureCellGovernmentAgentExecutionLaunchReceiptRequirementBlocked
	case SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired:
		return SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingAcknowledgement
	default:
		return SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingCollection
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationRule(
	item SecureCellGovernmentAgentExecutionLaunchClearanceItem,
	receiptType string,
) string {
	switch strings.TrimSpace(receiptType) {
	case "remediation_receipt":
		return "Attach remediation evidence and regenerate launch clearance before execution."
	case "operator_acknowledgement_receipt":
		return "Attach operator acknowledgement bound to the launch authorization and clearance item."
	case "evidence_preservation_receipt":
		return "Preserve the referenced evidence binding with the launch record."
	default:
		if item.Status == SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired {
			return "Attach the required operator receipt before launch."
		}
		return "Attach the required receipt before launch completion is accepted."
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptExpectedAttachment(
	item SecureCellGovernmentAgentExecutionLaunchClearanceItem,
	receiptType string,
) string {
	switch strings.TrimSpace(receiptType) {
	case "remediation_receipt":
		return "remediation_evidence"
	case "operator_acknowledgement_receipt":
		return "operator_acknowledgement"
	case "evidence_preservation_receipt":
		return "evidence_binding_snapshot"
	default:
		if item.Status == SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired {
			return "operator_receipt"
		}
		return "launch_receipt"
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifestStatus(manifest SecureCellGovernmentAgentExecutionLaunchReceiptManifest) SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus {
	if manifest.ClearanceStatus == SecureCellGovernmentAgentExecutionLaunchClearanceBlocked || manifest.BlockedReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchReceiptManifestBlocked
	}
	if manifest.PendingAcknowledgementReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchReceiptManifestAwaitingAcknowledgements
	}
	return SecureCellGovernmentAgentExecutionLaunchReceiptManifestReady
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifestStatusRank(status SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptManifestBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchReceiptManifestAwaitingAcknowledgements:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchReceiptManifestReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirementStatusRank(status SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptRequirementBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingAcknowledgement:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchReceiptRequirementPendingCollection:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirementDigest(requirement SecureCellGovernmentAgentExecutionLaunchReceiptRequirement) string {
	core := struct {
		Sequence            int                                                              `json:"sequence"`
		CellID              string                                                           `json:"cell_id"`
		RegisterID          string                                                           `json:"register_id"`
		AuthorizationID     string                                                           `json:"authorization_id"`
		ClearanceItemID     string                                                           `json:"clearance_item_id"`
		GateCode            string                                                           `json:"gate_code"`
		ReceiptType         string                                                           `json:"receipt_type"`
		Status              SecureCellGovernmentAgentExecutionLaunchReceiptRequirementStatus `json:"status"`
		ValidationRule      string                                                           `json:"validation_rule"`
		ExpectedAttachment  string                                                           `json:"expected_attachment"`
		EvidenceBindingID   string                                                           `json:"evidence_binding_id,omitempty"`
		ClearanceItemDigest string                                                           `json:"clearance_item_digest"`
	}{
		Sequence:            requirement.Sequence,
		CellID:              requirement.CellID,
		RegisterID:          requirement.RegisterID,
		AuthorizationID:     requirement.AuthorizationID,
		ClearanceItemID:     requirement.ClearanceItemID,
		GateCode:            requirement.GateCode,
		ReceiptType:         requirement.ReceiptType,
		Status:              requirement.Status,
		ValidationRule:      requirement.ValidationRule,
		ExpectedAttachment:  requirement.ExpectedAttachment,
		EvidenceBindingID:   requirement.EvidenceBindingID,
		ClearanceItemDigest: requirement.ClearanceItemDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifestDigest(manifest SecureCellGovernmentAgentExecutionLaunchReceiptManifest) string {
	requirementDigests := make([]string, 0, len(manifest.Requirements))
	for _, requirement := range manifest.Requirements {
		requirementDigests = append(requirementDigests, requirement.RequirementDigest)
	}
	core := struct {
		RegisterID             string                                                        `json:"register_id"`
		AuthorizationID        string                                                        `json:"authorization_id"`
		CellID                 string                                                        `json:"cell_id"`
		Status                 SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus `json:"status"`
		CanAcceptReceipts      bool                                                          `json:"can_accept_receipts"`
		CanLaunchAfterReceipts bool                                                          `json:"can_launch_after_receipts"`
		RequiredReceiptTypes   []string                                                      `json:"required_receipt_types,omitempty"`
		RequirementDigests     []string                                                      `json:"requirement_digests"`
		RegisterDigest         string                                                        `json:"register_digest"`
		LaunchDigest           string                                                        `json:"launch_digest"`
	}{
		RegisterID:             manifest.RegisterID,
		AuthorizationID:        manifest.AuthorizationID,
		CellID:                 manifest.CellID,
		Status:                 manifest.Status,
		CanAcceptReceipts:      manifest.CanAcceptReceipts,
		CanLaunchAfterReceipts: manifest.CanLaunchAfterReceipts,
		RequiredReceiptTypes:   manifest.RequiredReceiptTypes,
		RequirementDigests:     requirementDigests,
		RegisterDigest:         manifest.RegisterDigest,
		LaunchDigest:           manifest.LaunchDigest,
	}
	return EvidenceHash(core)
}
