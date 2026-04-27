package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClearanceStatus describes the
// register-level launch clearance posture for an authorized handoff.
type SecureCellGovernmentAgentExecutionLaunchClearanceStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClearanceBlocked       SecureCellGovernmentAgentExecutionLaunchClearanceStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchClearanceHeldForReview SecureCellGovernmentAgentExecutionLaunchClearanceStatus = "held_for_review"
	SecureCellGovernmentAgentExecutionLaunchClearanceSupervised    SecureCellGovernmentAgentExecutionLaunchClearanceStatus = "clear_for_supervised_launch"
	SecureCellGovernmentAgentExecutionLaunchClearanceAutonomous    SecureCellGovernmentAgentExecutionLaunchClearanceStatus = "clear_for_autonomous_launch"
)

// SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus is the operator
// posture for one launch gate.
type SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClearanceItemClear                   SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus = "clear"
	SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus = "acknowledgement_required"
	SecureCellGovernmentAgentExecutionLaunchClearanceItemRemediationRequired     SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus = "remediation_required"
)

// SecureCellGovernmentAgentExecutionLaunchClearancePriority is the operator
// urgency for clearing a launch gate.
type SecureCellGovernmentAgentExecutionLaunchClearancePriority string

const (
	SecureCellGovernmentAgentExecutionLaunchClearancePriorityCritical SecureCellGovernmentAgentExecutionLaunchClearancePriority = "critical"
	SecureCellGovernmentAgentExecutionLaunchClearancePriorityHigh     SecureCellGovernmentAgentExecutionLaunchClearancePriority = "high"
	SecureCellGovernmentAgentExecutionLaunchClearancePriorityStandard SecureCellGovernmentAgentExecutionLaunchClearancePriority = "standard"
)

// SecureCellGovernmentAgentExecutionLaunchClearanceItem is one actionable
// launch clearance line derived from an authorization gate.
type SecureCellGovernmentAgentExecutionLaunchClearanceItem struct {
	ItemID               string                                                      `json:"item_id"`
	Sequence             int                                                         `json:"sequence"`
	CellID               string                                                      `json:"cell_id"`
	AuthorizationID      string                                                      `json:"authorization_id"`
	GateID               string                                                      `json:"gate_id"`
	GateCode             string                                                      `json:"gate_code"`
	GateStatus           SecureCellGovernmentAgentExecutionLaunchGateStatus          `json:"gate_status"`
	Status               SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus `json:"status"`
	Priority             SecureCellGovernmentAgentExecutionLaunchClearancePriority   `json:"priority"`
	Action               string                                                      `json:"action"`
	Reason               string                                                      `json:"reason"`
	RequiredReceiptTypes []string                                                    `json:"required_receipt_types,omitempty"`
	EvidenceBindingID    string                                                      `json:"evidence_binding_id,omitempty"`
	GateDigest           string                                                      `json:"gate_digest"`
	ItemDigest           string                                                      `json:"item_digest"`
	GeneratedAt          time.Time                                                   `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClearanceRegister is the operator
// checklist for launch clearance, derived from a launch authorization.
type SecureCellGovernmentAgentExecutionLaunchClearanceRegister struct {
	RegisterID                           string                                                      `json:"register_id"`
	AuthorizationID                      string                                                      `json:"authorization_id"`
	VerificationID                       string                                                      `json:"verification_id"`
	BundleID                             string                                                      `json:"bundle_id"`
	CellID                               string                                                      `json:"cell_id"`
	Name                                 string                                                      `json:"name"`
	Jurisdiction                         string                                                      `json:"jurisdiction,omitempty"`
	ServiceCode                          string                                                      `json:"service_code,omitempty"`
	ServiceTier                          string                                                      `json:"service_tier,omitempty"`
	Status                               SecureCellGovernmentAgentExecutionLaunchClearanceStatus     `json:"status"`
	AuthorizationStatus                  SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus `json:"authorization_status"`
	CarryMode                            SecureCellGovernmentAgentCarryMode                          `json:"carry_mode"`
	CanLaunchNow                         bool                                                        `json:"can_launch_now"`
	CanLaunchAfterOperatorReview         bool                                                        `json:"can_launch_after_operator_review"`
	CanAutonomousLaunch                  bool                                                        `json:"can_autonomous_launch"`
	RequiredOperatorAcknowledgementCount int                                                         `json:"required_operator_acknowledgement_count"`
	ClearanceItemCount                   int                                                         `json:"clearance_item_count"`
	ClearItemCount                       int                                                         `json:"clear_item_count"`
	AcknowledgementItemCount             int                                                         `json:"acknowledgement_item_count"`
	RemediationItemCount                 int                                                         `json:"remediation_item_count"`
	CriticalItemCount                    int                                                         `json:"critical_item_count"`
	HighItemCount                        int                                                         `json:"high_item_count"`
	RequiredReceiptTypes                 []string                                                    `json:"required_receipt_types,omitempty"`
	TopBlockerCodes                      []string                                                    `json:"top_blocker_codes,omitempty"`
	MissingPreconditions                 []string                                                    `json:"missing_preconditions,omitempty"`
	WitnessID                            string                                                      `json:"witness_id"`
	LedgerID                             string                                                      `json:"ledger_id"`
	QueueID                              string                                                      `json:"queue_id"`
	LaunchDigest                         string                                                      `json:"launch_digest"`
	VerificationDigest                   string                                                      `json:"verification_digest"`
	BundleDigest                         string                                                      `json:"bundle_digest"`
	Items                                []SecureCellGovernmentAgentExecutionLaunchClearanceItem     `json:"items"`
	RegisterDigest                       string                                                      `json:"register_digest"`
	GeneratedAt                          time.Time                                                   `json:"generated_at"`
	UpdatedAt                            time.Time                                                   `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClearance returns the launch clearance
// register for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClearance(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClearanceRegister, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClearances(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-clearance: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClearances returns launch clearance
// registers for matching government-service launch authorizations.
func (s *Service) ListGovernmentAgentExecutionLaunchClearances(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClearanceRegister, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-clearance: service is required")
	}
	authorizations, err := s.ListGovernmentAgentExecutionLaunchAuthorizations(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	registers := make([]SecureCellGovernmentAgentExecutionLaunchClearanceRegister, 0, len(authorizations))
	for _, authorization := range authorizations {
		registers = append(registers, secureCellGovernmentAgentExecutionLaunchClearanceRegister(authorization, now))
	}
	sort.SliceStable(registers, func(i, j int) bool {
		if registers[i].Status == registers[j].Status {
			if registers[i].RemediationItemCount == registers[j].RemediationItemCount {
				if registers[i].AcknowledgementItemCount == registers[j].AcknowledgementItemCount {
					return registers[i].CellID < registers[j].CellID
				}
				return registers[i].AcknowledgementItemCount > registers[j].AcknowledgementItemCount
			}
			return registers[i].RemediationItemCount > registers[j].RemediationItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchClearanceStatusRank(registers[i].Status) < secureCellGovernmentAgentExecutionLaunchClearanceStatusRank(registers[j].Status)
	})
	return registers, nil
}

func secureCellGovernmentAgentExecutionLaunchClearanceRegister(
	authorization SecureCellGovernmentAgentExecutionLaunchAuthorization,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClearanceRegister {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClearanceItem, 0, len(authorization.Gates))
	for idx, gate := range authorization.Gates {
		items = append(items, secureCellGovernmentAgentExecutionLaunchClearanceItem(authorization, gate, idx+1, generatedAt))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Priority == items[j].Priority {
				return items[i].Sequence < items[j].Sequence
			}
			return secureCellGovernmentAgentExecutionLaunchClearancePriorityRank(items[i].Priority) < secureCellGovernmentAgentExecutionLaunchClearancePriorityRank(items[j].Priority)
		}
		return secureCellGovernmentAgentExecutionLaunchClearanceItemStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClearanceItemStatusRank(items[j].Status)
	})
	register := SecureCellGovernmentAgentExecutionLaunchClearanceRegister{
		AuthorizationID:                      authorization.AuthorizationID,
		VerificationID:                       authorization.VerificationID,
		BundleID:                             authorization.BundleID,
		CellID:                               authorization.CellID,
		Name:                                 authorization.Name,
		Jurisdiction:                         authorization.Jurisdiction,
		ServiceCode:                          authorization.ServiceCode,
		ServiceTier:                          authorization.ServiceTier,
		AuthorizationStatus:                  authorization.Status,
		CarryMode:                            authorization.CarryMode,
		CanLaunchNow:                         authorization.CanLaunchNow,
		CanLaunchAfterOperatorReview:         authorization.CanLaunchAfterOperatorReview,
		CanAutonomousLaunch:                  authorization.CanAutonomousLaunch,
		RequiredOperatorAcknowledgementCount: authorization.RequiredOperatorAcknowledgementCount,
		RequiredReceiptTypes:                 append([]string(nil), authorization.RequiredReceiptTypes...),
		TopBlockerCodes:                      append([]string(nil), authorization.TopBlockerCodes...),
		MissingPreconditions:                 append([]string(nil), authorization.MissingPreconditions...),
		WitnessID:                            authorization.WitnessID,
		LedgerID:                             authorization.LedgerID,
		QueueID:                              authorization.QueueID,
		LaunchDigest:                         authorization.LaunchDigest,
		VerificationDigest:                   authorization.VerificationDigest,
		BundleDigest:                         authorization.BundleDigest,
		Items:                                items,
		GeneratedAt:                          generatedAt.UTC(),
		UpdatedAt:                            authorization.UpdatedAt.UTC(),
	}
	for _, item := range register.Items {
		register.ClearanceItemCount++
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClearanceItemRemediationRequired:
			register.RemediationItemCount++
		case SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired:
			register.AcknowledgementItemCount++
		default:
			register.ClearItemCount++
		}
		switch item.Priority {
		case SecureCellGovernmentAgentExecutionLaunchClearancePriorityCritical:
			register.CriticalItemCount++
		case SecureCellGovernmentAgentExecutionLaunchClearancePriorityHigh:
			register.HighItemCount++
		}
	}
	register.Status = secureCellGovernmentAgentExecutionLaunchClearanceStatus(authorization)
	register.RegisterDigest = secureCellGovernmentAgentExecutionLaunchClearanceRegisterDigest(register)
	register.RegisterID = "government-agent-execution-launch-clearance:" + register.CellID + ":" + register.RegisterDigest[:12]
	return register
}

func secureCellGovernmentAgentExecutionLaunchClearanceItem(
	authorization SecureCellGovernmentAgentExecutionLaunchAuthorization,
	gate SecureCellGovernmentAgentExecutionLaunchGate,
	sequence int,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClearanceItem {
	item := SecureCellGovernmentAgentExecutionLaunchClearanceItem{
		Sequence:             sequence,
		CellID:               authorization.CellID,
		AuthorizationID:      authorization.AuthorizationID,
		GateID:               gate.GateID,
		GateCode:             gate.Code,
		GateStatus:           gate.Status,
		Status:               secureCellGovernmentAgentExecutionLaunchClearanceItemStatus(gate),
		Priority:             secureCellGovernmentAgentExecutionLaunchClearancePriority(gate),
		Action:               secureCellGovernmentAgentExecutionLaunchClearanceAction(gate),
		Reason:               gate.Detail,
		RequiredReceiptTypes: secureCellGovernmentAgentExecutionLaunchClearanceReceipts(authorization, gate),
		EvidenceBindingID:    gate.EvidenceBindingID,
		GeneratedAt:          generatedAt.UTC(),
	}
	item.GateDigest = secureCellGovernmentAgentExecutionLaunchGateDigest(gate)
	item.ItemDigest = secureCellGovernmentAgentExecutionLaunchClearanceItemDigest(item)
	item.ItemID = "government-agent-execution-launch-clearance-item:" + item.CellID + ":" + item.ItemDigest[:12]
	return item
}

func secureCellGovernmentAgentExecutionLaunchClearanceItemStatus(gate SecureCellGovernmentAgentExecutionLaunchGate) SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus {
	switch gate.Status {
	case SecureCellGovernmentAgentExecutionLaunchGateBlock:
		return SecureCellGovernmentAgentExecutionLaunchClearanceItemRemediationRequired
	case SecureCellGovernmentAgentExecutionLaunchGateHold:
		return SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired
	default:
		return SecureCellGovernmentAgentExecutionLaunchClearanceItemClear
	}
}

func secureCellGovernmentAgentExecutionLaunchClearancePriority(gate SecureCellGovernmentAgentExecutionLaunchGate) SecureCellGovernmentAgentExecutionLaunchClearancePriority {
	switch gate.Status {
	case SecureCellGovernmentAgentExecutionLaunchGateBlock:
		return SecureCellGovernmentAgentExecutionLaunchClearancePriorityCritical
	case SecureCellGovernmentAgentExecutionLaunchGateHold:
		return SecureCellGovernmentAgentExecutionLaunchClearancePriorityHigh
	default:
		return SecureCellGovernmentAgentExecutionLaunchClearancePriorityStandard
	}
}

func secureCellGovernmentAgentExecutionLaunchClearanceAction(gate SecureCellGovernmentAgentExecutionLaunchGate) string {
	if strings.TrimSpace(gate.RequiredAction) != "" {
		return gate.RequiredAction
	}
	switch gate.Status {
	case SecureCellGovernmentAgentExecutionLaunchGateBlock:
		return "Remediate this launch gate and regenerate the authorization."
	case SecureCellGovernmentAgentExecutionLaunchGateHold:
		return "Record the required acknowledgement before launch."
	default:
		return "Preserve the evidence binding during launch."
	}
}

func secureCellGovernmentAgentExecutionLaunchClearanceReceipts(
	authorization SecureCellGovernmentAgentExecutionLaunchAuthorization,
	gate SecureCellGovernmentAgentExecutionLaunchGate,
) []string {
	switch gate.Status {
	case SecureCellGovernmentAgentExecutionLaunchGateBlock:
		return uniqueSortedStrings([]string{"remediation_receipt"})
	case SecureCellGovernmentAgentExecutionLaunchGateHold:
		receipts := append([]string{"operator_acknowledgement_receipt"}, authorization.RequiredReceiptTypes...)
		return uniqueSortedStrings(receipts)
	default:
		if strings.TrimSpace(gate.EvidenceBindingID) == "" {
			return nil
		}
		return uniqueSortedStrings([]string{"evidence_preservation_receipt"})
	}
}

func secureCellGovernmentAgentExecutionLaunchClearanceStatus(authorization SecureCellGovernmentAgentExecutionLaunchAuthorization) SecureCellGovernmentAgentExecutionLaunchClearanceStatus {
	switch authorization.Status {
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClearanceBlocked
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired:
		return SecureCellGovernmentAgentExecutionLaunchClearanceHeldForReview
	case SecureCellGovernmentAgentExecutionLaunchAuthorizationAutonomous:
		return SecureCellGovernmentAgentExecutionLaunchClearanceAutonomous
	default:
		return SecureCellGovernmentAgentExecutionLaunchClearanceSupervised
	}
}

func secureCellGovernmentAgentExecutionLaunchClearanceStatusRank(status SecureCellGovernmentAgentExecutionLaunchClearanceStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClearanceBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClearanceHeldForReview:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClearanceSupervised:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchClearanceAutonomous:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchClearanceItemStatusRank(status SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClearanceItemRemediationRequired:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClearanceItemAcknowledgementRequired:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClearanceItemClear:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClearancePriorityRank(priority SecureCellGovernmentAgentExecutionLaunchClearancePriority) int {
	switch priority {
	case SecureCellGovernmentAgentExecutionLaunchClearancePriorityCritical:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClearancePriorityHigh:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClearancePriorityStandard:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchGateDigest(gate SecureCellGovernmentAgentExecutionLaunchGate) string {
	core := struct {
		GateID            string                                             `json:"gate_id"`
		Code              string                                             `json:"code"`
		Status            SecureCellGovernmentAgentExecutionLaunchGateStatus `json:"status"`
		Detail            string                                             `json:"detail"`
		RequiredAction    string                                             `json:"required_action,omitempty"`
		EvidenceBindingID string                                             `json:"evidence_binding_id,omitempty"`
	}{
		GateID:            gate.GateID,
		Code:              gate.Code,
		Status:            gate.Status,
		Detail:            gate.Detail,
		RequiredAction:    gate.RequiredAction,
		EvidenceBindingID: gate.EvidenceBindingID,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClearanceItemDigest(item SecureCellGovernmentAgentExecutionLaunchClearanceItem) string {
	core := struct {
		Sequence             int                                                         `json:"sequence"`
		CellID               string                                                      `json:"cell_id"`
		AuthorizationID      string                                                      `json:"authorization_id"`
		GateID               string                                                      `json:"gate_id"`
		GateCode             string                                                      `json:"gate_code"`
		Status               SecureCellGovernmentAgentExecutionLaunchClearanceItemStatus `json:"status"`
		Priority             SecureCellGovernmentAgentExecutionLaunchClearancePriority   `json:"priority"`
		Action               string                                                      `json:"action"`
		RequiredReceiptTypes []string                                                    `json:"required_receipt_types,omitempty"`
		EvidenceBindingID    string                                                      `json:"evidence_binding_id,omitempty"`
		GateDigest           string                                                      `json:"gate_digest"`
	}{
		Sequence:             item.Sequence,
		CellID:               item.CellID,
		AuthorizationID:      item.AuthorizationID,
		GateID:               item.GateID,
		GateCode:             item.GateCode,
		Status:               item.Status,
		Priority:             item.Priority,
		Action:               item.Action,
		RequiredReceiptTypes: item.RequiredReceiptTypes,
		EvidenceBindingID:    item.EvidenceBindingID,
		GateDigest:           item.GateDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClearanceRegisterDigest(register SecureCellGovernmentAgentExecutionLaunchClearanceRegister) string {
	itemDigests := make([]string, 0, len(register.Items))
	for _, item := range register.Items {
		itemDigests = append(itemDigests, item.ItemDigest)
	}
	core := struct {
		AuthorizationID              string                                                  `json:"authorization_id"`
		VerificationID               string                                                  `json:"verification_id"`
		CellID                       string                                                  `json:"cell_id"`
		Status                       SecureCellGovernmentAgentExecutionLaunchClearanceStatus `json:"status"`
		CanLaunchNow                 bool                                                    `json:"can_launch_now"`
		CanLaunchAfterOperatorReview bool                                                    `json:"can_launch_after_operator_review"`
		CanAutonomousLaunch          bool                                                    `json:"can_autonomous_launch"`
		ItemDigests                  []string                                                `json:"item_digests"`
		LaunchDigest                 string                                                  `json:"launch_digest"`
		VerificationDigest           string                                                  `json:"verification_digest"`
		BundleDigest                 string                                                  `json:"bundle_digest"`
	}{
		AuthorizationID:              register.AuthorizationID,
		VerificationID:               register.VerificationID,
		CellID:                       register.CellID,
		Status:                       register.Status,
		CanLaunchNow:                 register.CanLaunchNow,
		CanLaunchAfterOperatorReview: register.CanLaunchAfterOperatorReview,
		CanAutonomousLaunch:          register.CanAutonomousLaunch,
		ItemDigests:                  itemDigests,
		LaunchDigest:                 register.LaunchDigest,
		VerificationDigest:           register.VerificationDigest,
		BundleDigest:                 register.BundleDigest,
	}
	return EvidenceHash(core)
}
