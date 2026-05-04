package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus describes whether
// runtime receipts can be collected from a launch monitor.
type SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeBlocked                  SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus = "intake_blocked"
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus = "awaiting_operator_receipts"
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeReady                    SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus = "intake_ready"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus records the
// collection posture for one receipt derived from a monitor checkpoint.
type SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked     SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending     SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus = "pending"
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled   SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus = "scheduled"
	SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemCollectable SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus = "collectable"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem is one evidence
// receipt expected during or after launch execution.
type SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem struct {
	ItemID                  string                                                          `json:"item_id"`
	Sequence                int                                                             `json:"sequence"`
	CellID                  string                                                          `json:"cell_id"`
	MonitorID               string                                                          `json:"monitor_id"`
	OrderID                 string                                                          `json:"order_id"`
	CheckpointID            string                                                          `json:"checkpoint_id"`
	CheckpointKind          string                                                          `json:"checkpoint_kind"`
	ReceiptType             string                                                          `json:"receipt_type"`
	Status                  SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus `json:"status"`
	ExpectedStateTransition string                                                          `json:"expected_state_transition"`
	RequiredAction          string                                                          `json:"required_action"`
	DueAt                   *time.Time                                                      `json:"due_at,omitempty"`
	EvidenceDigest          string                                                          `json:"evidence_digest,omitempty"`
	EvidenceBindingID       string                                                          `json:"evidence_binding_id"`
	CheckpointDigest        string                                                          `json:"checkpoint_digest"`
	ItemDigest              string                                                          `json:"item_digest"`
	GeneratedAt             time.Time                                                       `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchReceiptIntake is the operator-facing
// ledger of runtime receipts expected from a launch monitor.
type SecureCellGovernmentAgentExecutionLaunchReceiptIntake struct {
	LedgerID                        string                                                      `json:"ledger_id"`
	MonitorID                       string                                                      `json:"monitor_id"`
	OrderID                         string                                                      `json:"order_id"`
	ActivationID                    string                                                      `json:"activation_id"`
	CustodyID                       string                                                      `json:"custody_id"`
	PackageID                       string                                                      `json:"package_id"`
	CellID                          string                                                      `json:"cell_id"`
	Name                            string                                                      `json:"name"`
	Jurisdiction                    string                                                      `json:"jurisdiction,omitempty"`
	ServiceCode                     string                                                      `json:"service_code,omitempty"`
	ServiceTier                     string                                                      `json:"service_tier,omitempty"`
	Status                          SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus `json:"status"`
	MonitorStatus                   SecureCellGovernmentAgentExecutionLaunchMonitorStatus       `json:"monitor_status"`
	CanCollectNow                   bool                                                        `json:"can_collect_now"`
	CanCollectAfterOperatorReceipts bool                                                        `json:"can_collect_after_operator_receipts"`
	ReceiptItemCount                int                                                         `json:"receipt_item_count"`
	BlockedReceiptItemCount         int                                                         `json:"blocked_receipt_item_count"`
	PendingReceiptItemCount         int                                                         `json:"pending_receipt_item_count"`
	ScheduledReceiptItemCount       int                                                         `json:"scheduled_receipt_item_count"`
	CollectableReceiptItemCount     int                                                         `json:"collectable_receipt_item_count"`
	RequiredReceiptTypes            []string                                                    `json:"required_receipt_types,omitempty"`
	OperatorInstructions            []string                                                    `json:"operator_instructions,omitempty"`
	MonitorDigest                   string                                                      `json:"monitor_digest"`
	OrderDigest                     string                                                      `json:"order_digest"`
	ActivationDigest                string                                                      `json:"activation_digest"`
	CustodyDigest                   string                                                      `json:"custody_digest"`
	PackageDigest                   string                                                      `json:"package_digest"`
	LaunchDigest                    string                                                      `json:"launch_digest"`
	ReceiptManifestDigest           string                                                      `json:"receipt_manifest_digest"`
	ReceiptValidationDigest         string                                                      `json:"receipt_validation_digest"`
	Items                           []SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem `json:"items"`
	Monitor                         SecureCellGovernmentAgentExecutionLaunchMonitor             `json:"monitor"`
	LedgerDigest                    string                                                      `json:"ledger_digest"`
	GeneratedAt                     time.Time                                                   `json:"generated_at"`
	UpdatedAt                       time.Time                                                   `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchReceiptIntake returns the runtime receipt
// intake ledger for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchReceiptIntake(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchReceiptIntake, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchReceiptIntakes(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-receipt-intake: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchReceiptIntakes returns runtime receipt
// intake ledgers for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchReceiptIntakes(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchReceiptIntake, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-receipt-intake: service is required")
	}
	monitors, err := s.ListGovernmentAgentExecutionLaunchMonitors(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	ledgers := make([]SecureCellGovernmentAgentExecutionLaunchReceiptIntake, 0, len(monitors))
	for _, monitor := range monitors {
		ledgers = append(ledgers, secureCellGovernmentAgentExecutionLaunchReceiptIntake(monitor, now))
	}
	sort.SliceStable(ledgers, func(i, j int) bool {
		if ledgers[i].Status == ledgers[j].Status {
			if ledgers[i].BlockedReceiptItemCount == ledgers[j].BlockedReceiptItemCount {
				if ledgers[i].PendingReceiptItemCount == ledgers[j].PendingReceiptItemCount {
					return ledgers[i].CellID < ledgers[j].CellID
				}
				return ledgers[i].PendingReceiptItemCount > ledgers[j].PendingReceiptItemCount
			}
			return ledgers[i].BlockedReceiptItemCount > ledgers[j].BlockedReceiptItemCount
		}
		return secureCellGovernmentAgentExecutionLaunchReceiptIntakeStatusRank(ledgers[i].Status) < secureCellGovernmentAgentExecutionLaunchReceiptIntakeStatusRank(ledgers[j].Status)
	})
	return ledgers, nil
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntake(
	monitor SecureCellGovernmentAgentExecutionLaunchMonitor,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptIntake {
	items := secureCellGovernmentAgentExecutionLaunchReceiptIntakeItems(monitor, generatedAt)
	ledger := SecureCellGovernmentAgentExecutionLaunchReceiptIntake{
		MonitorID:               monitor.MonitorID,
		OrderID:                 monitor.OrderID,
		ActivationID:            monitor.ActivationID,
		CustodyID:               monitor.CustodyID,
		PackageID:               monitor.PackageID,
		CellID:                  monitor.CellID,
		Name:                    monitor.Name,
		Jurisdiction:            monitor.Jurisdiction,
		ServiceCode:             monitor.ServiceCode,
		ServiceTier:             monitor.ServiceTier,
		MonitorStatus:           monitor.Status,
		MonitorDigest:           monitor.MonitorDigest,
		OrderDigest:             monitor.OrderDigest,
		ActivationDigest:        monitor.ActivationDigest,
		CustodyDigest:           monitor.CustodyDigest,
		PackageDigest:           monitor.PackageDigest,
		LaunchDigest:            monitor.LaunchDigest,
		ReceiptManifestDigest:   monitor.ReceiptManifestDigest,
		ReceiptValidationDigest: monitor.ReceiptValidationDigest,
		Items:                   items,
		Monitor:                 monitor,
		GeneratedAt:             generatedAt.UTC(),
		UpdatedAt:               monitor.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(items))
	for _, item := range ledger.Items {
		ledger.ReceiptItemCount++
		receiptTypes = append(receiptTypes, item.ReceiptType)
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked:
			ledger.BlockedReceiptItemCount++
		case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending:
			ledger.PendingReceiptItemCount++
		case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled:
			ledger.ScheduledReceiptItemCount++
		default:
			ledger.CollectableReceiptItemCount++
		}
	}
	ledger.RequiredReceiptTypes = uniqueSortedStrings(receiptTypes)
	ledger.Status = secureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus(ledger)
	ledger.CanCollectNow = ledger.Status == SecureCellGovernmentAgentExecutionLaunchReceiptIntakeReady
	ledger.CanCollectAfterOperatorReceipts = ledger.Status == SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts && monitor.CanMonitorAfterOperatorReceipts
	ledger.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchReceiptIntakeInstructions(ledger)
	ledger.LedgerDigest = secureCellGovernmentAgentExecutionLaunchReceiptIntakeDigest(ledger)
	ledger.LedgerID = "government-agent-execution-launch-receipt-intake:" + ledger.CellID + ":" + ledger.LedgerDigest[:12]
	return ledger
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeItems(
	monitor SecureCellGovernmentAgentExecutionLaunchMonitor,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem, 0, len(monitor.Checkpoints))
	for _, checkpoint := range monitor.Checkpoints {
		receiptType := secureCellGovernmentAgentExecutionLaunchReceiptIntakeReceiptType(checkpoint)
		if receiptType == "" {
			continue
		}
		item := SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem{
			Sequence:                checkpoint.Sequence,
			CellID:                  monitor.CellID,
			MonitorID:               monitor.MonitorID,
			OrderID:                 monitor.OrderID,
			CheckpointID:            checkpoint.CheckpointID,
			CheckpointKind:          checkpoint.Kind,
			ReceiptType:             receiptType,
			Status:                  secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus(checkpoint.Status),
			ExpectedStateTransition: secureCellGovernmentAgentExecutionLaunchReceiptIntakeStateTransition(checkpoint.Status),
			RequiredAction:          secureCellGovernmentAgentExecutionLaunchReceiptIntakeRequiredAction(checkpoint, receiptType),
			DueAt:                   cloneTimePtr(checkpoint.DueAt),
			EvidenceDigest:          checkpoint.EvidenceDigest,
			CheckpointDigest:        checkpoint.CheckpointDigest,
			GeneratedAt:             generatedAt.UTC(),
		}
		item.ItemDigest = secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemDigest(item)
		item.EvidenceBindingID = "government-agent-launch-receipt-binding:" + item.ItemDigest[:16]
		item.ItemID = "government-agent-execution-launch-receipt-intake-item:" + item.CellID + ":" + item.ItemDigest[:12]
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Sequence == items[j].Sequence {
				return items[i].ReceiptType < items[j].ReceiptType
			}
			return items[i].Sequence < items[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeReceiptType(checkpoint SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint) string {
	switch checkpoint.Kind {
	case "return_receipt":
		return strings.TrimSpace(checkpoint.ReceiptType)
	case "heartbeat":
		return "heartbeat_receipt"
	case "stop_condition_watch":
		return "stop_condition_watch_receipt"
	default:
		return ""
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus(status SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus) SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked:
		return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending:
		return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled:
		return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled
	default:
		return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemCollectable
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeStateTransition(status SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked:
		return "blocked_to_collectable_after_remediation"
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending:
		return "pending_to_collectable_after_operator_receipt"
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled:
		return "scheduled_to_collectable_at_runtime_due_time"
	default:
		return "collectable_to_preserved_after_receipt_ingest"
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeRequiredAction(
	checkpoint SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint,
	receiptType string,
) string {
	switch checkpoint.Status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked:
		if checkpoint.Kind == "stop_condition_watch" {
			return "Resolve launch stop condition before accepting " + receiptType + "."
		}
		return "Resolve launch monitor block before accepting " + receiptType + "."
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending:
		return "Collect operator receipt before accepting " + receiptType + "."
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled:
		return "Collect " + receiptType + " when the runtime checkpoint becomes due."
	default:
		return "Accept and preserve " + receiptType + " against the checkpoint digest."
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus(ledger SecureCellGovernmentAgentExecutionLaunchReceiptIntake) SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus {
	if ledger.MonitorStatus == SecureCellGovernmentAgentExecutionLaunchMonitorDenied || ledger.BlockedReceiptItemCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeBlocked
	}
	if ledger.MonitorStatus == SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts || ledger.PendingReceiptItemCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts
	}
	return SecureCellGovernmentAgentExecutionLaunchReceiptIntakeReady
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeInstructions(ledger SecureCellGovernmentAgentExecutionLaunchReceiptIntake) []string {
	instructions := append([]string(nil), ledger.Monitor.OperatorInstructions...)
	switch ledger.Status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeBlocked:
		instructions = append(instructions, "Do not accept runtime receipts until blocked checkpoint remediation is complete.")
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts:
		instructions = append(instructions, "Hold receipt intake until operator acknowledgement receipts unlock collection.")
	default:
		instructions = append(instructions, "Accept runtime receipts and bind each receipt to the monitor checkpoint digest.")
	}
	if ledger.ReceiptItemCount > 0 {
		instructions = append(instructions, fmt.Sprintf("Collect %d runtime receipt items for this launch monitor.", ledger.ReceiptItemCount))
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeStatusRank(status SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeAwaitingOperatorReceipts:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatusRank(status SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemPending:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemScheduled:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemCollectable:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeItemDigest(item SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem) string {
	core := struct {
		Sequence                int                                                             `json:"sequence"`
		CellID                  string                                                          `json:"cell_id"`
		MonitorID               string                                                          `json:"monitor_id"`
		OrderID                 string                                                          `json:"order_id"`
		CheckpointID            string                                                          `json:"checkpoint_id"`
		CheckpointKind          string                                                          `json:"checkpoint_kind"`
		ReceiptType             string                                                          `json:"receipt_type"`
		Status                  SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItemStatus `json:"status"`
		ExpectedStateTransition string                                                          `json:"expected_state_transition"`
		EvidenceDigest          string                                                          `json:"evidence_digest,omitempty"`
		CheckpointDigest        string                                                          `json:"checkpoint_digest"`
	}{
		Sequence:                item.Sequence,
		CellID:                  item.CellID,
		MonitorID:               item.MonitorID,
		OrderID:                 item.OrderID,
		CheckpointID:            item.CheckpointID,
		CheckpointKind:          item.CheckpointKind,
		ReceiptType:             item.ReceiptType,
		Status:                  item.Status,
		ExpectedStateTransition: item.ExpectedStateTransition,
		EvidenceDigest:          item.EvidenceDigest,
		CheckpointDigest:        item.CheckpointDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeDigest(ledger SecureCellGovernmentAgentExecutionLaunchReceiptIntake) string {
	itemDigests := make([]string, 0, len(ledger.Items))
	for _, item := range ledger.Items {
		itemDigests = append(itemDigests, item.ItemDigest)
	}
	core := struct {
		MonitorID                       string                                                      `json:"monitor_id"`
		OrderID                         string                                                      `json:"order_id"`
		ActivationID                    string                                                      `json:"activation_id"`
		CellID                          string                                                      `json:"cell_id"`
		Status                          SecureCellGovernmentAgentExecutionLaunchReceiptIntakeStatus `json:"status"`
		MonitorStatus                   SecureCellGovernmentAgentExecutionLaunchMonitorStatus       `json:"monitor_status"`
		CanCollectNow                   bool                                                        `json:"can_collect_now"`
		CanCollectAfterOperatorReceipts bool                                                        `json:"can_collect_after_operator_receipts"`
		RequiredReceiptTypes            []string                                                    `json:"required_receipt_types,omitempty"`
		ItemDigests                     []string                                                    `json:"item_digests,omitempty"`
		MonitorDigest                   string                                                      `json:"monitor_digest"`
		OrderDigest                     string                                                      `json:"order_digest"`
		ActivationDigest                string                                                      `json:"activation_digest"`
		CustodyDigest                   string                                                      `json:"custody_digest"`
		PackageDigest                   string                                                      `json:"package_digest"`
		LaunchDigest                    string                                                      `json:"launch_digest"`
		ReceiptManifestDigest           string                                                      `json:"receipt_manifest_digest"`
		ReceiptValidationDigest         string                                                      `json:"receipt_validation_digest"`
	}{
		MonitorID:                       ledger.MonitorID,
		OrderID:                         ledger.OrderID,
		ActivationID:                    ledger.ActivationID,
		CellID:                          ledger.CellID,
		Status:                          ledger.Status,
		MonitorStatus:                   ledger.MonitorStatus,
		CanCollectNow:                   ledger.CanCollectNow,
		CanCollectAfterOperatorReceipts: ledger.CanCollectAfterOperatorReceipts,
		RequiredReceiptTypes:            ledger.RequiredReceiptTypes,
		ItemDigests:                     itemDigests,
		MonitorDigest:                   ledger.MonitorDigest,
		OrderDigest:                     ledger.OrderDigest,
		ActivationDigest:                ledger.ActivationDigest,
		CustodyDigest:                   ledger.CustodyDigest,
		PackageDigest:                   ledger.PackageDigest,
		LaunchDigest:                    ledger.LaunchDigest,
		ReceiptManifestDigest:           ledger.ReceiptManifestDigest,
		ReceiptValidationDigest:         ledger.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
