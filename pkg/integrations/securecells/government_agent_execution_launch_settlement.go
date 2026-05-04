package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchSettlementStatus describes whether a
// closed execution can be archived and released.
type SecureCellGovernmentAgentExecutionLaunchSettlementStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchSettlementBlocked              SecureCellGovernmentAgentExecutionLaunchSettlementStatus = "settlement_blocked"
	SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation SecureCellGovernmentAgentExecutionLaunchSettlementStatus = "awaiting_preservation"
	SecureCellGovernmentAgentExecutionLaunchSettlementReady                SecureCellGovernmentAgentExecutionLaunchSettlementStatus = "settlement_ready"
)

// SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus records the
// final settlement posture for one closeout gate.
type SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked              SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchSettlementItemAwaitingPreservation SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus = "awaiting_preservation"
	SecureCellGovernmentAgentExecutionLaunchSettlementItemReady                SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus = "ready"
)

// SecureCellGovernmentAgentExecutionLaunchSettlementAction is the archive or
// escalation action generated from one closeout gate.
type SecureCellGovernmentAgentExecutionLaunchSettlementAction string

const (
	SecureCellGovernmentAgentExecutionLaunchSettlementActionEscalate       SecureCellGovernmentAgentExecutionLaunchSettlementAction = "escalate_blocker"
	SecureCellGovernmentAgentExecutionLaunchSettlementActionPreserve       SecureCellGovernmentAgentExecutionLaunchSettlementAction = "preserve_evidence"
	SecureCellGovernmentAgentExecutionLaunchSettlementActionReleaseArchive SecureCellGovernmentAgentExecutionLaunchSettlementAction = "release_to_archive"
)

// SecureCellGovernmentAgentExecutionLaunchSettlementItem is one digest-bound
// settlement obligation derived from closeout.
type SecureCellGovernmentAgentExecutionLaunchSettlementItem struct {
	ItemID            string                                                       `json:"item_id"`
	Sequence          int                                                          `json:"sequence"`
	CellID            string                                                       `json:"cell_id"`
	RegisterID        string                                                       `json:"register_id"`
	LedgerID          string                                                       `json:"ledger_id"`
	MonitorID         string                                                       `json:"monitor_id"`
	OrderID           string                                                       `json:"order_id"`
	GateID            string                                                       `json:"gate_id"`
	IntakeItemID      string                                                       `json:"intake_item_id"`
	ReceiptType       string                                                       `json:"receipt_type"`
	GateKind          string                                                       `json:"gate_kind"`
	Status            SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus `json:"status"`
	Action            SecureCellGovernmentAgentExecutionLaunchSettlementAction     `json:"action"`
	RequiredAction    string                                                       `json:"required_action"`
	DueAt             *time.Time                                                   `json:"due_at,omitempty"`
	EvidenceBindingID string                                                       `json:"evidence_binding_id"`
	EvidenceDigest    string                                                       `json:"evidence_digest,omitempty"`
	GateDigest        string                                                       `json:"gate_digest"`
	SettlementDigest  string                                                       `json:"settlement_digest"`
	GeneratedAt       time.Time                                                    `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchSettlementRegister is the final
// archive-and-release surface for one launch execution.
type SecureCellGovernmentAgentExecutionLaunchSettlementRegister struct {
	RegisterID                 string                                                   `json:"register_id"`
	CloseoutRegisterID         string                                                   `json:"closeout_register_id"`
	LedgerID                   string                                                   `json:"ledger_id"`
	MonitorID                  string                                                   `json:"monitor_id"`
	OrderID                    string                                                   `json:"order_id"`
	ActivationID               string                                                   `json:"activation_id"`
	CustodyID                  string                                                   `json:"custody_id"`
	PackageID                  string                                                   `json:"package_id"`
	CellID                     string                                                   `json:"cell_id"`
	Name                       string                                                   `json:"name"`
	Jurisdiction               string                                                   `json:"jurisdiction,omitempty"`
	ServiceCode                string                                                   `json:"service_code,omitempty"`
	ServiceTier                string                                                   `json:"service_tier,omitempty"`
	Status                     SecureCellGovernmentAgentExecutionLaunchSettlementStatus `json:"status"`
	CloseoutStatus             SecureCellGovernmentAgentExecutionLaunchCloseoutStatus   `json:"closeout_status"`
	CanSettleNow               bool                                                     `json:"can_settle_now"`
	CanSettleAfterPreservation bool                                                     `json:"can_settle_after_preservation"`
	CanEscalateNow             bool                                                     `json:"can_escalate_now"`
	SettlementItemCount        int                                                      `json:"settlement_item_count"`
	BlockedSettlementItemCount int                                                      `json:"blocked_settlement_item_count"`
	PendingSettlementItemCount int                                                      `json:"pending_settlement_item_count"`
	ReadySettlementItemCount   int                                                      `json:"ready_settlement_item_count"`
	RequiredReceiptTypes       []string                                                 `json:"required_receipt_types,omitempty"`
	OperatorInstructions       []string                                                 `json:"operator_instructions,omitempty"`
	CloseoutDigest             string                                                   `json:"closeout_digest"`
	LedgerDigest               string                                                   `json:"ledger_digest"`
	MonitorDigest              string                                                   `json:"monitor_digest"`
	OrderDigest                string                                                   `json:"order_digest"`
	ActivationDigest           string                                                   `json:"activation_digest"`
	CustodyDigest              string                                                   `json:"custody_digest"`
	PackageDigest              string                                                   `json:"package_digest"`
	LaunchDigest               string                                                   `json:"launch_digest"`
	ReceiptManifestDigest      string                                                   `json:"receipt_manifest_digest"`
	ReceiptValidationDigest    string                                                   `json:"receipt_validation_digest"`
	Items                      []SecureCellGovernmentAgentExecutionLaunchSettlementItem `json:"items"`
	Closeout                   SecureCellGovernmentAgentExecutionLaunchCloseoutRegister `json:"closeout"`
	SettlementRegisterDigest   string                                                   `json:"settlement_register_digest"`
	GeneratedAt                time.Time                                                `json:"generated_at"`
	UpdatedAt                  time.Time                                                `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchSettlement returns the final settlement
// register for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchSettlement(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchSettlementRegister, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchSettlements(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-settlement: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchSettlements returns final settlement
// registers for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchSettlements(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchSettlementRegister, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-settlement: service is required")
	}
	closeouts, err := s.ListGovernmentAgentExecutionLaunchCloseouts(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	registers := make([]SecureCellGovernmentAgentExecutionLaunchSettlementRegister, 0, len(closeouts))
	for _, closeout := range closeouts {
		registers = append(registers, secureCellGovernmentAgentExecutionLaunchSettlementRegister(closeout, now))
	}
	sort.SliceStable(registers, func(i, j int) bool {
		if registers[i].Status == registers[j].Status {
			if registers[i].BlockedSettlementItemCount == registers[j].BlockedSettlementItemCount {
				if registers[i].PendingSettlementItemCount == registers[j].PendingSettlementItemCount {
					return registers[i].CellID < registers[j].CellID
				}
				return registers[i].PendingSettlementItemCount > registers[j].PendingSettlementItemCount
			}
			return registers[i].BlockedSettlementItemCount > registers[j].BlockedSettlementItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchSettlementStatusRank(registers[i].Status) < secureCellGovernmentAgentExecutionLaunchSettlementStatusRank(registers[j].Status)
	})
	return registers, nil
}

func secureCellGovernmentAgentExecutionLaunchSettlementRegister(
	closeout SecureCellGovernmentAgentExecutionLaunchCloseoutRegister,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchSettlementRegister {
	items := secureCellGovernmentAgentExecutionLaunchSettlementItems(closeout, generatedAt)
	register := SecureCellGovernmentAgentExecutionLaunchSettlementRegister{
		CloseoutRegisterID:      closeout.RegisterID,
		LedgerID:                closeout.LedgerID,
		MonitorID:               closeout.MonitorID,
		OrderID:                 closeout.OrderID,
		ActivationID:            closeout.ActivationID,
		CustodyID:               closeout.CustodyID,
		PackageID:               closeout.PackageID,
		CellID:                  closeout.CellID,
		Name:                    closeout.Name,
		Jurisdiction:            closeout.Jurisdiction,
		ServiceCode:             closeout.ServiceCode,
		ServiceTier:             closeout.ServiceTier,
		CloseoutStatus:          closeout.Status,
		CloseoutDigest:          closeout.RegisterDigest,
		LedgerDigest:            closeout.LedgerDigest,
		MonitorDigest:           closeout.MonitorDigest,
		OrderDigest:             closeout.OrderDigest,
		ActivationDigest:        closeout.ActivationDigest,
		CustodyDigest:           closeout.CustodyDigest,
		PackageDigest:           closeout.PackageDigest,
		LaunchDigest:            closeout.LaunchDigest,
		ReceiptManifestDigest:   closeout.ReceiptManifestDigest,
		ReceiptValidationDigest: closeout.ReceiptValidationDigest,
		Items:                   items,
		Closeout:                closeout,
		GeneratedAt:             generatedAt.UTC(),
		UpdatedAt:               closeout.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(items))
	for _, item := range register.Items {
		register.SettlementItemCount++
		receiptTypes = append(receiptTypes, item.ReceiptType)
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked:
			register.BlockedSettlementItemCount++
		case SecureCellGovernmentAgentExecutionLaunchSettlementItemAwaitingPreservation:
			register.PendingSettlementItemCount++
		default:
			register.ReadySettlementItemCount++
		}
	}
	register.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	register.Status = secureCellGovernmentAgentExecutionLaunchSettlementStatus(register)
	register.CanSettleNow = register.Status == SecureCellGovernmentAgentExecutionLaunchSettlementReady
	register.CanSettleAfterPreservation = register.Status == SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation
	register.CanEscalateNow = register.Status == SecureCellGovernmentAgentExecutionLaunchSettlementBlocked
	register.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchSettlementInstructions(register)
	register.SettlementRegisterDigest = secureCellGovernmentAgentExecutionLaunchSettlementRegisterDigest(register)
	register.RegisterID = "government-agent-execution-launch-settlement:" + register.CellID + ":" + register.SettlementRegisterDigest[:12]
	return register
}

func secureCellGovernmentAgentExecutionLaunchSettlementItems(
	closeout SecureCellGovernmentAgentExecutionLaunchCloseoutRegister,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchSettlementItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchSettlementItem, 0, len(closeout.Gates))
	for _, gate := range closeout.Gates {
		item := SecureCellGovernmentAgentExecutionLaunchSettlementItem{
			Sequence:          gate.Sequence,
			CellID:            closeout.CellID,
			RegisterID:        closeout.RegisterID,
			LedgerID:          closeout.LedgerID,
			MonitorID:         closeout.MonitorID,
			OrderID:           closeout.OrderID,
			GateID:            gate.GateID,
			IntakeItemID:      gate.IntakeItemID,
			ReceiptType:       gate.ReceiptType,
			GateKind:          gate.GateKind,
			Status:            secureCellGovernmentAgentExecutionLaunchSettlementItemStatus(gate.Status),
			Action:            secureCellGovernmentAgentExecutionLaunchSettlementActionForGate(gate.Status),
			RequiredAction:    secureCellGovernmentAgentExecutionLaunchSettlementRequiredAction(gate),
			DueAt:             cloneTimePtr(gate.DueAt),
			EvidenceBindingID: gate.EvidenceBindingID,
			EvidenceDigest:    gate.EvidenceDigest,
			GateDigest:        gate.GateDigest,
			GeneratedAt:       generatedAt.UTC(),
		}
		item.SettlementDigest = secureCellGovernmentAgentExecutionLaunchSettlementItemDigest(item)
		item.ItemID = "government-agent-execution-launch-settlement-item:" + item.CellID + ":" + item.SettlementDigest[:12]
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Sequence == items[j].Sequence {
				return items[i].ReceiptType < items[j].ReceiptType
			}
			return items[i].Sequence < items[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchSettlementItemStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchSettlementItemStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchSettlementItemStatus(status SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus) SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked:
		return SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateReadyForPreservation:
		return SecureCellGovernmentAgentExecutionLaunchSettlementItemReady
	default:
		return SecureCellGovernmentAgentExecutionLaunchSettlementItemAwaitingPreservation
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementActionForGate(status SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus) SecureCellGovernmentAgentExecutionLaunchSettlementAction {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked:
		return SecureCellGovernmentAgentExecutionLaunchSettlementActionEscalate
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateReadyForPreservation:
		return SecureCellGovernmentAgentExecutionLaunchSettlementActionReleaseArchive
	default:
		return SecureCellGovernmentAgentExecutionLaunchSettlementActionPreserve
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementRequiredAction(gate SecureCellGovernmentAgentExecutionLaunchCloseoutGate) string {
	switch gate.Status {
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked:
		return "Escalate blocked closeout gate before settlement can proceed."
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateReadyForPreservation:
		return "Release preserved evidence for archival settlement."
	default:
		return "Preserve receipt evidence before archival settlement."
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementStatus(register SecureCellGovernmentAgentExecutionLaunchSettlementRegister) SecureCellGovernmentAgentExecutionLaunchSettlementStatus {
	if register.CloseoutStatus == SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked || register.BlockedSettlementItemCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchSettlementBlocked
	}
	if register.PendingSettlementItemCount > 0 || register.CloseoutStatus == SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingOperatorReceipts || register.CloseoutStatus == SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingRuntimeReceipts {
		return SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation
	}
	return SecureCellGovernmentAgentExecutionLaunchSettlementReady
}

func secureCellGovernmentAgentExecutionLaunchSettlementInstructions(register SecureCellGovernmentAgentExecutionLaunchSettlementRegister) []string {
	instructions := append([]string(nil), register.Closeout.OperatorInstructions...)
	switch register.Status {
	case SecureCellGovernmentAgentExecutionLaunchSettlementBlocked:
		instructions = append(instructions, "Escalate blocked settlement items before archive release.")
	case SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation:
		instructions = append(instructions, "Preserve all pending runtime evidence before archive release.")
	default:
		instructions = append(instructions, "Release preserved launch evidence into the final archive register.")
	}
	if register.SettlementItemCount > 0 {
		instructions = append(instructions, fmt.Sprintf("Review %d settlement items before marking the archive complete.", register.SettlementItemCount))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchSettlementStatusRank(status SecureCellGovernmentAgentExecutionLaunchSettlementStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchSettlementBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchSettlementAwaitingPreservation:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchSettlementReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementItemStatusRank(status SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemAwaitingPreservation:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchSettlementItemReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementItemDigest(item SecureCellGovernmentAgentExecutionLaunchSettlementItem) string {
	core := struct {
		Sequence     int                                                          `json:"sequence"`
		CellID       string                                                       `json:"cell_id"`
		RegisterID   string                                                       `json:"register_id"`
		LedgerID     string                                                       `json:"ledger_id"`
		MonitorID    string                                                       `json:"monitor_id"`
		OrderID      string                                                       `json:"order_id"`
		GateID       string                                                       `json:"gate_id"`
		IntakeItemID string                                                       `json:"intake_item_id"`
		ReceiptType  string                                                       `json:"receipt_type"`
		GateKind     string                                                       `json:"gate_kind"`
		Status       SecureCellGovernmentAgentExecutionLaunchSettlementItemStatus `json:"status"`
		Action       SecureCellGovernmentAgentExecutionLaunchSettlementAction     `json:"action"`
		GateDigest   string                                                       `json:"gate_digest"`
	}{
		Sequence:     item.Sequence,
		CellID:       item.CellID,
		RegisterID:   item.RegisterID,
		LedgerID:     item.LedgerID,
		MonitorID:    item.MonitorID,
		OrderID:      item.OrderID,
		GateID:       item.GateID,
		IntakeItemID: item.IntakeItemID,
		ReceiptType:  item.ReceiptType,
		GateKind:     item.GateKind,
		Status:       item.Status,
		Action:       item.Action,
		GateDigest:   item.GateDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchSettlementRegisterDigest(register SecureCellGovernmentAgentExecutionLaunchSettlementRegister) string {
	itemDigests := make([]string, 0, len(register.Items))
	for _, item := range register.Items {
		itemDigests = append(itemDigests, item.SettlementDigest)
	}
	core := struct {
		CloseoutRegisterID         string                                                   `json:"closeout_register_id"`
		LedgerID                   string                                                   `json:"ledger_id"`
		MonitorID                  string                                                   `json:"monitor_id"`
		OrderID                    string                                                   `json:"order_id"`
		ActivationID               string                                                   `json:"activation_id"`
		CellID                     string                                                   `json:"cell_id"`
		Status                     SecureCellGovernmentAgentExecutionLaunchSettlementStatus `json:"status"`
		CloseoutStatus             SecureCellGovernmentAgentExecutionLaunchCloseoutStatus   `json:"closeout_status"`
		CanSettleNow               bool                                                     `json:"can_settle_now"`
		CanSettleAfterPreservation bool                                                     `json:"can_settle_after_preservation"`
		CanEscalateNow             bool                                                     `json:"can_escalate_now"`
		RequiredReceiptTypes       []string                                                 `json:"required_receipt_types,omitempty"`
		ItemDigests                []string                                                 `json:"item_digests,omitempty"`
		CloseoutDigest             string                                                   `json:"closeout_digest"`
		LedgerDigest               string                                                   `json:"ledger_digest"`
		MonitorDigest              string                                                   `json:"monitor_digest"`
		OrderDigest                string                                                   `json:"order_digest"`
		ActivationDigest           string                                                   `json:"activation_digest"`
		CustodyDigest              string                                                   `json:"custody_digest"`
		PackageDigest              string                                                   `json:"package_digest"`
		LaunchDigest               string                                                   `json:"launch_digest"`
		ReceiptManifestDigest      string                                                   `json:"receipt_manifest_digest"`
		ReceiptValidationDigest    string                                                   `json:"receipt_validation_digest"`
	}{
		CloseoutRegisterID:         register.CloseoutRegisterID,
		LedgerID:                   register.LedgerID,
		MonitorID:                  register.MonitorID,
		OrderID:                    register.OrderID,
		ActivationID:               register.ActivationID,
		CellID:                     register.CellID,
		Status:                     register.Status,
		CloseoutStatus:             register.CloseoutStatus,
		CanSettleNow:               register.CanSettleNow,
		CanSettleAfterPreservation: register.CanSettleAfterPreservation,
		CanEscalateNow:             register.CanEscalateNow,
		RequiredReceiptTypes:       register.RequiredReceiptTypes,
		ItemDigests:                itemDigests,
		CloseoutDigest:             register.CloseoutDigest,
		LedgerDigest:               register.LedgerDigest,
		MonitorDigest:              register.MonitorDigest,
		OrderDigest:                register.OrderDigest,
		ActivationDigest:           register.ActivationDigest,
		CustodyDigest:              register.CustodyDigest,
		PackageDigest:              register.PackageDigest,
		LaunchDigest:               register.LaunchDigest,
		ReceiptManifestDigest:      register.ReceiptManifestDigest,
		ReceiptValidationDigest:    register.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
