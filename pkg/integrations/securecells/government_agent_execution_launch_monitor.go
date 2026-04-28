package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchMonitorStatus describes whether a
// runtime monitor can supervise an execution order.
type SecureCellGovernmentAgentExecutionLaunchMonitorStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchMonitorDenied                  SecureCellGovernmentAgentExecutionLaunchMonitorStatus = "monitor_denied"
	SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts SecureCellGovernmentAgentExecutionLaunchMonitorStatus = "waiting_for_operator_receipts"
	SecureCellGovernmentAgentExecutionLaunchMonitorReadySupervised         SecureCellGovernmentAgentExecutionLaunchMonitorStatus = "ready_supervised_monitoring"
	SecureCellGovernmentAgentExecutionLaunchMonitorReadyAutonomous         SecureCellGovernmentAgentExecutionLaunchMonitorStatus = "ready_autonomous_monitoring"
)

// SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus records the
// state of one runtime checkpoint.
type SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked   SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending   SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus = "pending"
	SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus = "scheduled"
	SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointReady     SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus = "ready"
)

// SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint is one heartbeat,
// receipt, or stop-condition watch derived from a launch order.
type SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint struct {
	CheckpointID     string                                                          `json:"checkpoint_id"`
	Sequence         int                                                             `json:"sequence"`
	CellID           string                                                          `json:"cell_id"`
	OrderID          string                                                          `json:"order_id"`
	Kind             string                                                          `json:"kind"`
	Status           SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus `json:"status"`
	Detail           string                                                          `json:"detail"`
	ReceiptType      string                                                          `json:"receipt_type,omitempty"`
	StopConditionID  string                                                          `json:"stop_condition_id,omitempty"`
	DueAt            *time.Time                                                      `json:"due_at,omitempty"`
	EvidenceDigest   string                                                          `json:"evidence_digest,omitempty"`
	CheckpointDigest string                                                          `json:"checkpoint_digest"`
	GeneratedAt      time.Time                                                       `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchMonitor is the runtime supervision
// plan generated from a launch order.
type SecureCellGovernmentAgentExecutionLaunchMonitor struct {
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
	Status                          SecureCellGovernmentAgentExecutionLaunchMonitorStatus       `json:"status"`
	OrderStatus                     SecureCellGovernmentAgentExecutionLaunchOrderStatus         `json:"order_status"`
	CanMonitorNow                   bool                                                        `json:"can_monitor_now"`
	CanMonitorAfterOperatorReceipts bool                                                        `json:"can_monitor_after_operator_receipts"`
	CanMonitorAutonomous            bool                                                        `json:"can_monitor_autonomous"`
	HeartbeatIntervalSeconds        int                                                         `json:"heartbeat_interval_seconds"`
	RuntimeMinutes                  int                                                         `json:"runtime_minutes"`
	StartWindowOpensAt              time.Time                                                   `json:"start_window_opens_at"`
	StartWindowExpiresAt            time.Time                                                   `json:"start_window_expires_at"`
	NextHeartbeatAt                 time.Time                                                   `json:"next_heartbeat_at"`
	CheckpointCount                 int                                                         `json:"checkpoint_count"`
	ReadyCheckpointCount            int                                                         `json:"ready_checkpoint_count"`
	ScheduledCheckpointCount        int                                                         `json:"scheduled_checkpoint_count"`
	PendingCheckpointCount          int                                                         `json:"pending_checkpoint_count"`
	BlockedCheckpointCount          int                                                         `json:"blocked_checkpoint_count"`
	StopConditionWatchCount         int                                                         `json:"stop_condition_watch_count"`
	CriticalStopWatchCount          int                                                         `json:"critical_stop_watch_count"`
	HighStopWatchCount              int                                                         `json:"high_stop_watch_count"`
	ReturnReceiptCount              int                                                         `json:"return_receipt_count"`
	RequiredReturnReceipts          []string                                                    `json:"required_return_receipts,omitempty"`
	OperatorInstructions            []string                                                    `json:"operator_instructions,omitempty"`
	OrderDigest                     string                                                      `json:"order_digest"`
	ActivationDigest                string                                                      `json:"activation_digest"`
	CustodyDigest                   string                                                      `json:"custody_digest"`
	PackageDigest                   string                                                      `json:"package_digest"`
	LaunchDigest                    string                                                      `json:"launch_digest"`
	ReceiptManifestDigest           string                                                      `json:"receipt_manifest_digest"`
	ReceiptValidationDigest         string                                                      `json:"receipt_validation_digest"`
	Checkpoints                     []SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint `json:"checkpoints"`
	Order                           SecureCellGovernmentAgentExecutionLaunchOrder               `json:"order"`
	MonitorDigest                   string                                                      `json:"monitor_digest"`
	GeneratedAt                     time.Time                                                   `json:"generated_at"`
	UpdatedAt                       time.Time                                                   `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchMonitor returns the runtime monitor for one
// secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchMonitor(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchMonitor, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchMonitors(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-monitor: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchMonitors returns runtime monitors for
// matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchMonitors(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchMonitor, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-monitor: service is required")
	}
	orders, err := s.ListGovernmentAgentExecutionLaunchOrders(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	monitors := make([]SecureCellGovernmentAgentExecutionLaunchMonitor, 0, len(orders))
	for _, order := range orders {
		monitors = append(monitors, secureCellGovernmentAgentExecutionLaunchMonitor(order, now))
	}
	sort.SliceStable(monitors, func(i, j int) bool {
		if monitors[i].Status == monitors[j].Status {
			if monitors[i].BlockedCheckpointCount == monitors[j].BlockedCheckpointCount {
				if monitors[i].PendingCheckpointCount == monitors[j].PendingCheckpointCount {
					return monitors[i].CellID < monitors[j].CellID
				}
				return monitors[i].PendingCheckpointCount > monitors[j].PendingCheckpointCount
			}
			return monitors[i].BlockedCheckpointCount > monitors[j].BlockedCheckpointCount
		}
		return secureCellGovernmentAgentExecutionLaunchMonitorStatusRank(monitors[i].Status) < secureCellGovernmentAgentExecutionLaunchMonitorStatusRank(monitors[j].Status)
	})
	return monitors, nil
}

func secureCellGovernmentAgentExecutionLaunchMonitor(
	order SecureCellGovernmentAgentExecutionLaunchOrder,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchMonitor {
	heartbeatInterval := secureCellGovernmentAgentExecutionLaunchMonitorHeartbeatInterval(order.ServiceTier)
	monitor := SecureCellGovernmentAgentExecutionLaunchMonitor{
		OrderID:                  order.OrderID,
		ActivationID:             order.ActivationID,
		CustodyID:                order.CustodyID,
		PackageID:                order.PackageID,
		CellID:                   order.CellID,
		Name:                     order.Name,
		Jurisdiction:             order.Jurisdiction,
		ServiceCode:              order.ServiceCode,
		ServiceTier:              order.ServiceTier,
		OrderStatus:              order.Status,
		HeartbeatIntervalSeconds: heartbeatInterval,
		RuntimeMinutes:           order.RuntimeMinutes,
		StartWindowOpensAt:       order.StartWindowOpensAt.UTC(),
		StartWindowExpiresAt:     order.StartWindowExpiresAt.UTC(),
		NextHeartbeatAt:          generatedAt.UTC().Add(time.Duration(heartbeatInterval) * time.Second),
		ReturnReceiptCount:       order.ReturnReceiptCount,
		RequiredReturnReceipts:   append([]string(nil), order.RequiredReturnReceipts...),
		OrderDigest:              order.OrderDigest,
		ActivationDigest:         order.ActivationDigest,
		CustodyDigest:            order.CustodyDigest,
		PackageDigest:            order.PackageDigest,
		LaunchDigest:             order.LaunchDigest,
		ReceiptManifestDigest:    order.ReceiptManifestDigest,
		ReceiptValidationDigest:  order.ReceiptValidationDigest,
		Order:                    order,
		GeneratedAt:              generatedAt.UTC(),
		UpdatedAt:                order.UpdatedAt.UTC(),
	}
	monitor.Status = secureCellGovernmentAgentExecutionLaunchMonitorStatus(order)
	monitor.CanMonitorNow = monitor.Status == SecureCellGovernmentAgentExecutionLaunchMonitorReadySupervised || monitor.Status == SecureCellGovernmentAgentExecutionLaunchMonitorReadyAutonomous
	monitor.CanMonitorAfterOperatorReceipts = monitor.Status == SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts && order.CanStartAfterOperatorReceipts
	monitor.CanMonitorAutonomous = monitor.Status == SecureCellGovernmentAgentExecutionLaunchMonitorReadyAutonomous
	monitor.Checkpoints = secureCellGovernmentAgentExecutionLaunchMonitorCheckpoints(monitor, order, generatedAt)
	for _, checkpoint := range monitor.Checkpoints {
		monitor.CheckpointCount++
		switch checkpoint.Status {
		case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked:
			monitor.BlockedCheckpointCount++
		case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending:
			monitor.PendingCheckpointCount++
		case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled:
			monitor.ScheduledCheckpointCount++
		default:
			monitor.ReadyCheckpointCount++
		}
		if checkpoint.Kind == "stop_condition_watch" {
			monitor.StopConditionWatchCount++
		}
	}
	for _, condition := range order.StopConditions {
		switch condition.Priority {
		case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical:
			monitor.CriticalStopWatchCount++
		case SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityHigh:
			monitor.HighStopWatchCount++
		}
	}
	monitor.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchMonitorInstructions(monitor)
	monitor.MonitorDigest = secureCellGovernmentAgentExecutionLaunchMonitorDigest(monitor)
	monitor.MonitorID = "government-agent-execution-launch-monitor:" + monitor.CellID + ":" + monitor.MonitorDigest[:12]
	return monitor
}

func secureCellGovernmentAgentExecutionLaunchMonitorCheckpoints(
	monitor SecureCellGovernmentAgentExecutionLaunchMonitor,
	order SecureCellGovernmentAgentExecutionLaunchOrder,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint {
	checkpoints := make([]SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint, 0, len(order.RequiredReturnReceipts)+len(order.StopConditions)+1)
	sequence := 1
	checkpoints = append(checkpoints, secureCellGovernmentAgentExecutionLaunchMonitorCheckpoint(monitor, sequence, "heartbeat", secureCellGovernmentAgentExecutionLaunchMonitorHeartbeatStatus(monitor), "Runtime heartbeat must arrive on schedule.", "", "", monitor.NextHeartbeatAt, order.OrderDigest, generatedAt))
	sequence++
	for _, receiptType := range order.RequiredReturnReceipts {
		dueAt := monitor.StartWindowOpensAt.Add(time.Duration(order.RuntimeMinutes) * time.Minute)
		checkpoints = append(checkpoints, secureCellGovernmentAgentExecutionLaunchMonitorCheckpoint(monitor, sequence, "return_receipt", secureCellGovernmentAgentExecutionLaunchMonitorReceiptStatus(monitor), "Return receipt must be preserved before completion.", receiptType, "", dueAt, order.OrderDigest, generatedAt))
		sequence++
	}
	for _, condition := range order.StopConditions {
		checkpoints = append(checkpoints, secureCellGovernmentAgentExecutionLaunchMonitorCheckpoint(monitor, sequence, "stop_condition_watch", secureCellGovernmentAgentExecutionLaunchMonitorStopWatchStatus(monitor, condition), condition.Detail, "", condition.ConditionID, monitor.StartWindowExpiresAt, condition.ConditionDigest, generatedAt))
		sequence++
	}
	sort.SliceStable(checkpoints, func(i, j int) bool {
		if checkpoints[i].Status == checkpoints[j].Status {
			return checkpoints[i].Sequence < checkpoints[j].Sequence
		}
		return secureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatusRank(checkpoints[i].Status) < secureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatusRank(checkpoints[j].Status)
	})
	return checkpoints
}

func secureCellGovernmentAgentExecutionLaunchMonitorCheckpoint(
	monitor SecureCellGovernmentAgentExecutionLaunchMonitor,
	sequence int,
	kind string,
	status SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus,
	detail string,
	receiptType string,
	stopConditionID string,
	dueAt time.Time,
	evidenceDigest string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint {
	checkpoint := SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint{
		Sequence:        sequence,
		CellID:          monitor.CellID,
		OrderID:         monitor.OrderID,
		Kind:            strings.TrimSpace(kind),
		Status:          status,
		Detail:          strings.TrimSpace(detail),
		ReceiptType:     strings.TrimSpace(receiptType),
		StopConditionID: strings.TrimSpace(stopConditionID),
		DueAt:           cloneTimePtr(&dueAt),
		EvidenceDigest:  strings.TrimSpace(evidenceDigest),
		GeneratedAt:     generatedAt.UTC(),
	}
	checkpoint.CheckpointDigest = secureCellGovernmentAgentExecutionLaunchMonitorCheckpointDigest(checkpoint)
	checkpoint.CheckpointID = "government-agent-execution-launch-monitor-checkpoint:" + checkpoint.CellID + ":" + checkpoint.CheckpointDigest[:12]
	return checkpoint
}

func secureCellGovernmentAgentExecutionLaunchMonitorStatus(order SecureCellGovernmentAgentExecutionLaunchOrder) SecureCellGovernmentAgentExecutionLaunchMonitorStatus {
	switch order.Status {
	case SecureCellGovernmentAgentExecutionLaunchOrderDenied:
		return SecureCellGovernmentAgentExecutionLaunchMonitorDenied
	case SecureCellGovernmentAgentExecutionLaunchOrderWaitingOperatorReceipts:
		return SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts
	case SecureCellGovernmentAgentExecutionLaunchOrderReadyAutonomous:
		return SecureCellGovernmentAgentExecutionLaunchMonitorReadyAutonomous
	default:
		return SecureCellGovernmentAgentExecutionLaunchMonitorReadySupervised
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorHeartbeatStatus(monitor SecureCellGovernmentAgentExecutionLaunchMonitor) SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus {
	switch monitor.Status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorDenied:
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked
	case SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts:
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending
	default:
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorReceiptStatus(monitor SecureCellGovernmentAgentExecutionLaunchMonitor) SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus {
	switch monitor.Status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorDenied:
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked
	case SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts:
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending
	default:
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointReady
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorStopWatchStatus(
	monitor SecureCellGovernmentAgentExecutionLaunchMonitor,
	condition SecureCellGovernmentAgentExecutionLaunchOrderStopCondition,
) SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus {
	if monitor.Status == SecureCellGovernmentAgentExecutionLaunchMonitorDenied && condition.Priority == SecureCellGovernmentAgentExecutionLaunchOrderStopPriorityCritical {
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked
	}
	if monitor.Status == SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts {
		return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending
	}
	return SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled
}

func secureCellGovernmentAgentExecutionLaunchMonitorHeartbeatInterval(serviceTier string) int {
	switch strings.ToLower(strings.TrimSpace(serviceTier)) {
	case "tier_1", "tier1", "critical":
		return 300
	case "tier_2", "tier2", "high":
		return 600
	case "tier_3", "tier3", "standard":
		return 900
	default:
		return 600
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorInstructions(monitor SecureCellGovernmentAgentExecutionLaunchMonitor) []string {
	instructions := append([]string(nil), monitor.Order.OperatorInstructions...)
	switch monitor.Status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorDenied:
		instructions = append(instructions, "Do not arm runtime monitoring until denied launch order checkpoints are cleared.")
	case SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts:
		instructions = append(instructions, "Keep monitoring pending until operator receipts unlock the start order.")
	case SecureCellGovernmentAgentExecutionLaunchMonitorReadyAutonomous:
		instructions = append(instructions, "Arm autonomous monitoring with heartbeat and supervision receipts enabled.")
	default:
		instructions = append(instructions, "Arm supervised monitoring before executor start.")
	}
	instructions = append(instructions, fmt.Sprintf("Require a heartbeat every %d seconds while execution is active.", monitor.HeartbeatIntervalSeconds))
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchMonitorStatusRank(status SecureCellGovernmentAgentExecutionLaunchMonitorStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorDenied:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchMonitorWaitingOperatorReceipts:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchMonitorReadySupervised:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchMonitorReadyAutonomous:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatusRank(status SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointPending:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointScheduled:
		return 2
	case SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointReady:
		return 3
	default:
		return 4
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorCheckpointDigest(checkpoint SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint) string {
	core := struct {
		Sequence        int                                                             `json:"sequence"`
		CellID          string                                                          `json:"cell_id"`
		OrderID         string                                                          `json:"order_id"`
		Kind            string                                                          `json:"kind"`
		Status          SecureCellGovernmentAgentExecutionLaunchMonitorCheckpointStatus `json:"status"`
		ReceiptType     string                                                          `json:"receipt_type,omitempty"`
		StopConditionID string                                                          `json:"stop_condition_id,omitempty"`
		EvidenceDigest  string                                                          `json:"evidence_digest,omitempty"`
	}{
		Sequence:        checkpoint.Sequence,
		CellID:          checkpoint.CellID,
		OrderID:         checkpoint.OrderID,
		Kind:            checkpoint.Kind,
		Status:          checkpoint.Status,
		ReceiptType:     checkpoint.ReceiptType,
		StopConditionID: checkpoint.StopConditionID,
		EvidenceDigest:  checkpoint.EvidenceDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchMonitorDigest(monitor SecureCellGovernmentAgentExecutionLaunchMonitor) string {
	checkpointDigests := make([]string, 0, len(monitor.Checkpoints))
	for _, checkpoint := range monitor.Checkpoints {
		checkpointDigests = append(checkpointDigests, checkpoint.CheckpointDigest)
	}
	core := struct {
		OrderID                         string                                                `json:"order_id"`
		ActivationID                    string                                                `json:"activation_id"`
		CellID                          string                                                `json:"cell_id"`
		Status                          SecureCellGovernmentAgentExecutionLaunchMonitorStatus `json:"status"`
		OrderStatus                     SecureCellGovernmentAgentExecutionLaunchOrderStatus   `json:"order_status"`
		CanMonitorNow                   bool                                                  `json:"can_monitor_now"`
		CanMonitorAfterOperatorReceipts bool                                                  `json:"can_monitor_after_operator_receipts"`
		CanMonitorAutonomous            bool                                                  `json:"can_monitor_autonomous"`
		HeartbeatIntervalSeconds        int                                                   `json:"heartbeat_interval_seconds"`
		RuntimeMinutes                  int                                                   `json:"runtime_minutes"`
		RequiredReturnReceipts          []string                                              `json:"required_return_receipts,omitempty"`
		CheckpointDigests               []string                                              `json:"checkpoint_digests,omitempty"`
		OrderDigest                     string                                                `json:"order_digest"`
		ActivationDigest                string                                                `json:"activation_digest"`
		CustodyDigest                   string                                                `json:"custody_digest"`
		PackageDigest                   string                                                `json:"package_digest"`
		LaunchDigest                    string                                                `json:"launch_digest"`
		ReceiptManifestDigest           string                                                `json:"receipt_manifest_digest"`
		ReceiptValidationDigest         string                                                `json:"receipt_validation_digest"`
	}{
		OrderID:                         monitor.OrderID,
		ActivationID:                    monitor.ActivationID,
		CellID:                          monitor.CellID,
		Status:                          monitor.Status,
		OrderStatus:                     monitor.OrderStatus,
		CanMonitorNow:                   monitor.CanMonitorNow,
		CanMonitorAfterOperatorReceipts: monitor.CanMonitorAfterOperatorReceipts,
		CanMonitorAutonomous:            monitor.CanMonitorAutonomous,
		HeartbeatIntervalSeconds:        monitor.HeartbeatIntervalSeconds,
		RuntimeMinutes:                  monitor.RuntimeMinutes,
		RequiredReturnReceipts:          monitor.RequiredReturnReceipts,
		CheckpointDigests:               checkpointDigests,
		OrderDigest:                     monitor.OrderDigest,
		ActivationDigest:                monitor.ActivationDigest,
		CustodyDigest:                   monitor.CustodyDigest,
		PackageDigest:                   monitor.PackageDigest,
		LaunchDigest:                    monitor.LaunchDigest,
		ReceiptManifestDigest:           monitor.ReceiptManifestDigest,
		ReceiptValidationDigest:         monitor.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
