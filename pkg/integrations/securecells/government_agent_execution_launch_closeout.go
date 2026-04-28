package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchCloseoutStatus describes whether a
// launch execution can close after runtime receipt review.
type SecureCellGovernmentAgentExecutionLaunchCloseoutStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked                  SecureCellGovernmentAgentExecutionLaunchCloseoutStatus = "closeout_blocked"
	SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingOperatorReceipts SecureCellGovernmentAgentExecutionLaunchCloseoutStatus = "awaiting_operator_receipts"
	SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingRuntimeReceipts  SecureCellGovernmentAgentExecutionLaunchCloseoutStatus = "awaiting_runtime_receipts"
	SecureCellGovernmentAgentExecutionLaunchCloseoutReady                    SecureCellGovernmentAgentExecutionLaunchCloseoutStatus = "closeout_ready"
)

// SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus records the state
// of one closeout gate generated from a receipt intake item.
type SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked                 SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingOperatorReceipt SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus = "awaiting_operator_receipt"
	SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingRuntimeReceipt  SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus = "awaiting_runtime_receipt"
	SecureCellGovernmentAgentExecutionLaunchCloseoutGateReadyForPreservation    SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus = "ready_for_preservation"
)

// SecureCellGovernmentAgentExecutionLaunchCloseoutDecision is the operator
// action produced by one closeout gate.
type SecureCellGovernmentAgentExecutionLaunchCloseoutDecision string

const (
	SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionStopCloseout        SecureCellGovernmentAgentExecutionLaunchCloseoutDecision = "stop_closeout"
	SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionHoldOperatorReceipt SecureCellGovernmentAgentExecutionLaunchCloseoutDecision = "hold_for_operator_receipt"
	SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionHoldRuntimeReceipt  SecureCellGovernmentAgentExecutionLaunchCloseoutDecision = "hold_for_runtime_receipt"
	SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionPreserveAndClose    SecureCellGovernmentAgentExecutionLaunchCloseoutDecision = "preserve_and_close"
)

// SecureCellGovernmentAgentExecutionLaunchCloseoutGate is one digest-bound
// closeout decision generated from runtime receipt intake.
type SecureCellGovernmentAgentExecutionLaunchCloseoutGate struct {
	GateID            string                                                     `json:"gate_id"`
	Sequence          int                                                        `json:"sequence"`
	CellID            string                                                     `json:"cell_id"`
	LedgerID          string                                                     `json:"ledger_id"`
	MonitorID         string                                                     `json:"monitor_id"`
	OrderID           string                                                     `json:"order_id"`
	IntakeItemID      string                                                     `json:"intake_item_id"`
	CheckpointID      string                                                     `json:"checkpoint_id"`
	GateKind          string                                                     `json:"gate_kind"`
	ReceiptType       string                                                     `json:"receipt_type"`
	Status            SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus `json:"status"`
	Decision          SecureCellGovernmentAgentExecutionLaunchCloseoutDecision   `json:"decision"`
	RequiredAction    string                                                     `json:"required_action"`
	DueAt             *time.Time                                                 `json:"due_at,omitempty"`
	EvidenceBindingID string                                                     `json:"evidence_binding_id"`
	EvidenceDigest    string                                                     `json:"evidence_digest,omitempty"`
	IntakeItemDigest  string                                                     `json:"intake_item_digest"`
	CheckpointDigest  string                                                     `json:"checkpoint_digest"`
	GateDigest        string                                                     `json:"gate_digest"`
	GeneratedAt       time.Time                                                  `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchCloseoutRegister is the completion
// control surface for one monitored launch execution.
type SecureCellGovernmentAgentExecutionLaunchCloseoutRegister struct {
	RegisterID                   string                                                      `json:"register_id"`
	LedgerID                     string                                                      `json:"ledger_id"`
	MonitorID                    string                                                      `json:"monitor_id"`
	OrderID                      string                                                      `json:"order_id"`
	ActivationID                 string                                                      `json:"activation_id"`
	CustodyID                    string                                                      `json:"custody_id"`
	PackageID                    string                                                      `json:"package_id"`
	CellID                       string                                                      `json:"cell_id"`
	Name                         string                                                      `json:"name"`
	Jurisdiction                 string                                                      `json:"jurisdiction,omitempty"`
	ServiceCode                  string                                                      `json:"service_code,omitempty"`
	ServiceTier                  string                                                      `json:"service_tier,omitempty"`
	Status                       SecureCellGovernmentAgentExecutionLaunchCloseoutStatus      `json:"status"`
	IntakeStatus                 SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus `json:"intake_status"`
	MonitorStatus                SecureCellGovernmentAgentExecutionLaunchMonitorStatus       `json:"monitor_status"`
	CanCloseNow                  bool                                                        `json:"can_close_now"`
	CanCloseAfterRuntimeReceipts bool                                                        `json:"can_close_after_runtime_receipts"`
	CanEscalateBlocked           bool                                                        `json:"can_escalate_blocked"`
	GateCount                    int                                                         `json:"gate_count"`
	BlockedGateCount             int                                                         `json:"blocked_gate_count"`
	OperatorReceiptGateCount     int                                                         `json:"operator_receipt_gate_count"`
	RuntimeReceiptGateCount      int                                                         `json:"runtime_receipt_gate_count"`
	ReadyGateCount               int                                                         `json:"ready_gate_count"`
	StopConditionGateCount       int                                                         `json:"stop_condition_gate_count"`
	HeartbeatGateCount           int                                                         `json:"heartbeat_gate_count"`
	ReturnReceiptGateCount       int                                                         `json:"return_receipt_gate_count"`
	RequiredReceiptTypes         []string                                                    `json:"required_receipt_types,omitempty"`
	OperatorInstructions         []string                                                    `json:"operator_instructions,omitempty"`
	LedgerDigest                 string                                                      `json:"ledger_digest"`
	MonitorDigest                string                                                      `json:"monitor_digest"`
	OrderDigest                  string                                                      `json:"order_digest"`
	ActivationDigest             string                                                      `json:"activation_digest"`
	CustodyDigest                string                                                      `json:"custody_digest"`
	PackageDigest                string                                                      `json:"package_digest"`
	LaunchDigest                 string                                                      `json:"launch_digest"`
	ReceiptManifestDigest        string                                                      `json:"receipt_manifest_digest"`
	ReceiptValidationDigest      string                                                      `json:"receipt_validation_digest"`
	Gates                        []SecureCellGovernmentAgentExecutionLaunchCloseoutGate      `json:"gates"`
	Intake                       SecureCellGovernmentAgentExecutionLaunchReceiptIntake       `json:"intake"`
	RegisterDigest               string                                                      `json:"register_digest"`
	GeneratedAt                  time.Time                                                   `json:"generated_at"`
	UpdatedAt                    time.Time                                                   `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchCloseout returns the closeout register for
// one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchCloseout(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchCloseoutRegister, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchCloseouts(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closeout: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchCloseouts returns closeout registers for
// matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchCloseouts(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchCloseoutRegister, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closeout: service is required")
	}
	intakes, err := s.ListGovernmentAgentExecutionLaunchReceiptIntakes(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	registers := make([]SecureCellGovernmentAgentExecutionLaunchCloseoutRegister, 0, len(intakes))
	for _, intake := range intakes {
		registers = append(registers, secureCellGovernmentAgentExecutionLaunchCloseoutRegister(intake, now))
	}
	sort.SliceStable(registers, func(i, j int) bool {
		if registers[i].Status == registers[j].Status {
			if registers[i].BlockedGateCount == registers[j].BlockedGateCount {
				if registers[i].OperatorReceiptGateCount == registers[j].OperatorReceiptGateCount {
					return registers[i].CellID < registers[j].CellID
				}
				return registers[i].OperatorReceiptGateCount > registers[j].OperatorReceiptGateCount
			}
			return registers[i].BlockedGateCount > registers[j].BlockedGateCount
		}
		return secureCellGovernmentAgentExecutionLaunchCloseoutStatusRank(registers[i].Status) < secureCellGovernmentAgentExecutionLaunchCloseoutStatusRank(registers[j].Status)
	})
	return registers, nil
}

func secureCellGovernmentAgentExecutionLaunchCloseoutRegister(
	intake SecureCellGovernmentAgentExecutionLaunchReceiptIntake,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchCloseoutRegister {
	gates := secureCellGovernmentAgentExecutionLaunchCloseoutGates(intake, generatedAt)
	register := SecureCellGovernmentAgentExecutionLaunchCloseoutRegister{
		LedgerID:                intake.LedgerID,
		MonitorID:               intake.MonitorID,
		OrderID:                 intake.OrderID,
		ActivationID:            intake.ActivationID,
		CustodyID:               intake.CustodyID,
		PackageID:               intake.PackageID,
		CellID:                  intake.CellID,
		Name:                    intake.Name,
		Jurisdiction:            intake.Jurisdiction,
		ServiceCode:             intake.ServiceCode,
		ServiceTier:             intake.ServiceTier,
		IntakeStatus:            intake.Status,
		MonitorStatus:           intake.MonitorStatus,
		LedgerDigest:            intake.LedgerDigest,
		MonitorDigest:           intake.MonitorDigest,
		OrderDigest:             intake.OrderDigest,
		ActivationDigest:        intake.ActivationDigest,
		CustodyDigest:           intake.CustodyDigest,
		PackageDigest:           intake.PackageDigest,
		LaunchDigest:            intake.LaunchDigest,
		ReceiptManifestDigest:   intake.ReceiptManifestDigest,
		ReceiptValidationDigest: intake.ReceiptValidationDigest,
		Gates:                   gates,
		Intake:                  intake,
		GeneratedAt:             generatedAt.UTC(),
		UpdatedAt:               intake.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(gates))
	for _, gate := range register.Gates {
		register.GateCount++
		receiptTypes = append(receiptTypes, gate.ReceiptType)
		switch gate.Status {
		case SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked:
			register.BlockedGateCount++
		case SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingOperatorReceipt:
			register.OperatorReceiptGateCount++
		case SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingRuntimeReceipt:
			register.RuntimeReceiptGateCount++
		default:
			register.ReadyGateCount++
		}
		switch gate.GateKind {
		case "stop_condition_watch":
			register.StopConditionGateCount++
		case "heartbeat":
			register.HeartbeatGateCount++
		case "return_receipt":
			register.ReturnReceiptGateCount++
		}
	}
	register.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	register.Status = secureCellGovernmentAgentExecutionLaunchCloseoutStatus(register)
	register.CanCloseNow = register.Status == SecureCellGovernmentAgentExecutionLaunchCloseoutReady
	register.CanCloseAfterRuntimeReceipts = register.Status == SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingRuntimeReceipts && intake.CanCollectNow
	register.CanEscalateBlocked = register.Status == SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked
	register.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchCloseoutInstructions(register)
	register.RegisterDigest = secureCellGovernmentAgentExecutionLaunchCloseoutDigest(register)
	register.RegisterID = "government-agent-execution-launch-closeout:" + register.CellID + ":" + register.RegisterDigest[:12]
	return register
}

func secureCellGovernmentAgentExecutionLaunchCloseoutGates(
	intake SecureCellGovernmentAgentExecutionLaunchReceiptIntake,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchCloseoutGate {
	gates := make([]SecureCellGovernmentAgentExecutionLaunchCloseoutGate, 0, len(intake.Items))
	for _, item := range intake.Items {
		gate := SecureCellGovernmentAgentExecutionLaunchCloseoutGate{
			Sequence:          item.Sequence,
			CellID:            intake.CellID,
			LedgerID:          intake.LedgerID,
			MonitorID:         intake.MonitorID,
			OrderID:           intake.OrderID,
			IntakeItemID:      item.ItemID,
			CheckpointID:      item.CheckpointID,
			GateKind:          item.CheckpointKind,
			ReceiptType:       item.ReceiptType,
			Status:            secureCellGovernmentAgentExecutionLaunchCloseoutGateStatus(item.Status),
			Decision:          secureCellGovernmentAgentExecutionLaunchCloseoutDecision(item.Status),
			RequiredAction:    secureCellGovernmentAgentExecutionLaunchCloseoutRequiredAction(item),
			DueAt:             cloneTimePtr(item.DueAt),
			EvidenceBindingID: item.EvidenceBindingID,
			EvidenceDigest:    item.EvidenceDigest,
			IntakeItemDigest:  item.ItemDigest,
			CheckpointDigest:  item.CheckpointDigest,
			GeneratedAt:       generatedAt.UTC(),
		}
		gate.GateDigest = secureCellGovernmentAgentExecutionLaunchCloseoutGateDigest(gate)
		gate.GateID = "government-agent-execution-launch-closeout-gate:" + gate.CellID + ":" + gate.GateDigest[:12]
		gates = append(gates, gate)
	}
	sort.SliceStable(gates, func(i, j int) bool {
		if gates[i].Status == gates[j].Status {
			if gates[i].Sequence == gates[j].Sequence {
				return gates[i].ReceiptType < gates[j].ReceiptType
			}
			return gates[i].Sequence < gates[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchCloseoutGateStatusRank(gates[i].Status) < secureCellGovernmentAgentExecutionLaunchCloseoutGateStatusRank(gates[j].Status)
	})
	return gates
}

func secureCellGovernmentAgentExecutionLaunchCloseoutGateStatus(status SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus) SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingOperatorReceipt
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingRuntimeReceipt
	default:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutGateReadyForPreservation
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutDecision(status SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus) SecureCellGovernmentAgentExecutionLaunchCloseoutDecision {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionStopCloseout
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionHoldOperatorReceipt
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionHoldRuntimeReceipt
	default:
		return SecureCellGovernmentAgentExecutionLaunchCloseoutDecisionPreserveAndClose
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutRequiredAction(item SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem) string {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked:
		return "Stop closeout until blocked receipt intake item is remediated."
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending:
		return "Hold closeout until operator receipt unlocks intake item " + item.ItemID + "."
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled:
		return "Hold closeout until runtime receipt is preserved for " + item.ReceiptType + "."
	default:
		return "Preserve receipt evidence and close " + item.ReceiptType + "."
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutStatus(register SecureCellGovernmentAgentExecutionLaunchCloseoutRegister) SecureCellGovernmentAgentExecutionLaunchCloseoutStatus {
	if register.IntakeStatus == SecureCellGovernmentAgentExecutionLaunchReceiptIntakeBlocked || register.BlockedGateCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked
	}
	if register.IntakeStatus == SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts || register.OperatorReceiptGateCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingOperatorReceipts
	}
	if register.RuntimeReceiptGateCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingRuntimeReceipts
	}
	return SecureCellGovernmentAgentExecutionLaunchCloseoutReady
}

func secureCellGovernmentAgentExecutionLaunchCloseoutInstructions(register SecureCellGovernmentAgentExecutionLaunchCloseoutRegister) []string {
	instructions := append([]string(nil), register.Intake.OperatorInstructions...)
	switch register.Status {
	case SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked:
		instructions = append(instructions, "Stop closeout and escalate blocked runtime receipt gates.")
	case SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingOperatorReceipts:
		instructions = append(instructions, "Hold closeout until operator receipts clear all pending gates.")
	case SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingRuntimeReceipts:
		instructions = append(instructions, "Hold closeout until runtime heartbeat, return, and stop-condition receipts are preserved.")
	default:
		instructions = append(instructions, "Close launch execution after preserving all receipt evidence bindings.")
	}
	if register.GateCount > 0 {
		instructions = append(instructions, fmt.Sprintf("Review %d closeout gates before marking execution complete.", register.GateCount))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchCloseoutStatusRank(status SecureCellGovernmentAgentExecutionLaunchCloseoutStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchCloseoutBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingOperatorReceipts:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchCloseoutAwaitingRuntimeReceipts:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchCloseoutReady:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutGateStatusRank(status SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingOperatorReceipt:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateAwaitingRuntimeReceipt:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchCloseoutGateReadyForPreservation:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutGateDigest(gate SecureCellGovernmentAgentExecutionLaunchCloseoutGate) string {
	core := struct {
		Sequence         int                                                        `json:"sequence"`
		CellID           string                                                     `json:"cell_id"`
		LedgerID         string                                                     `json:"ledger_id"`
		MonitorID        string                                                     `json:"monitor_id"`
		OrderID          string                                                     `json:"order_id"`
		IntakeItemID     string                                                     `json:"intake_item_id"`
		CheckpointID     string                                                     `json:"checkpoint_id"`
		GateKind         string                                                     `json:"gate_kind"`
		ReceiptType      string                                                     `json:"receipt_type"`
		Status           SecureCellGovernmentAgentExecutionLaunchCloseoutGateStatus `json:"status"`
		Decision         SecureCellGovernmentAgentExecutionLaunchCloseoutDecision   `json:"decision"`
		IntakeItemDigest string                                                     `json:"intake_item_digest"`
		CheckpointDigest string                                                     `json:"checkpoint_digest"`
	}{
		Sequence:         gate.Sequence,
		CellID:           gate.CellID,
		LedgerID:         gate.LedgerID,
		MonitorID:        gate.MonitorID,
		OrderID:          gate.OrderID,
		IntakeItemID:     gate.IntakeItemID,
		CheckpointID:     gate.CheckpointID,
		GateKind:         gate.GateKind,
		ReceiptType:      gate.ReceiptType,
		Status:           gate.Status,
		Decision:         gate.Decision,
		IntakeItemDigest: gate.IntakeItemDigest,
		CheckpointDigest: gate.CheckpointDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchCloseoutDigest(register SecureCellGovernmentAgentExecutionLaunchCloseoutRegister) string {
	gateDigests := make([]string, 0, len(register.Gates))
	for _, gate := range register.Gates {
		gateDigests = append(gateDigests, gate.GateDigest)
	}
	core := struct {
		LedgerID                     string                                                      `json:"ledger_id"`
		MonitorID                    string                                                      `json:"monitor_id"`
		OrderID                      string                                                      `json:"order_id"`
		ActivationID                 string                                                      `json:"activation_id"`
		CellID                       string                                                      `json:"cell_id"`
		Status                       SecureCellGovernmentAgentExecutionLaunchCloseoutStatus      `json:"status"`
		IntakeStatus                 SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus `json:"intake_status"`
		MonitorStatus                SecureCellGovernmentAgentExecutionLaunchMonitorStatus       `json:"monitor_status"`
		CanCloseNow                  bool                                                        `json:"can_close_now"`
		CanCloseAfterRuntimeReceipts bool                                                        `json:"can_close_after_runtime_receipts"`
		CanEscalateBlocked           bool                                                        `json:"can_escalate_blocked"`
		RequiredReceiptTypes         []string                                                    `json:"required_receipt_types,omitempty"`
		GateDigests                  []string                                                    `json:"gate_digests,omitempty"`
		LedgerDigest                 string                                                      `json:"ledger_digest"`
		MonitorDigest                string                                                      `json:"monitor_digest"`
		OrderDigest                  string                                                      `json:"order_digest"`
		ActivationDigest             string                                                      `json:"activation_digest"`
		CustodyDigest                string                                                      `json:"custody_digest"`
		PackageDigest                string                                                      `json:"package_digest"`
		LaunchDigest                 string                                                      `json:"launch_digest"`
		ReceiptManifestDigest        string                                                      `json:"receipt_manifest_digest"`
		ReceiptValidationDigest      string                                                      `json:"receipt_validation_digest"`
	}{
		LedgerID:                     register.LedgerID,
		MonitorID:                    register.MonitorID,
		OrderID:                      register.OrderID,
		ActivationID:                 register.ActivationID,
		CellID:                       register.CellID,
		Status:                       register.Status,
		IntakeStatus:                 register.IntakeStatus,
		MonitorStatus:                register.MonitorStatus,
		CanCloseNow:                  register.CanCloseNow,
		CanCloseAfterRuntimeReceipts: register.CanCloseAfterRuntimeReceipts,
		CanEscalateBlocked:           register.CanEscalateBlocked,
		RequiredReceiptTypes:         register.RequiredReceiptTypes,
		GateDigests:                  gateDigests,
		LedgerDigest:                 register.LedgerDigest,
		MonitorDigest:                register.MonitorDigest,
		OrderDigest:                  register.OrderDigest,
		ActivationDigest:             register.ActivationDigest,
		CustodyDigest:                register.CustodyDigest,
		PackageDigest:                register.PackageDigest,
		LaunchDigest:                 register.LaunchDigest,
		ReceiptManifestDigest:        register.ReceiptManifestDigest,
		ReceiptValidationDigest:      register.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
