package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus describes
// the urgency for one launch closure operator queue.
type SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus = "overdue"
	SecureCellGovernmentAgentExecutionLaunchClosureActionQueueDue     SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus = "due"
)

// SecureCellGovernmentAgentExecutionLaunchClosureActionKind identifies the
// operator step needed to move closure forward.
type SecureCellGovernmentAgentExecutionLaunchClosureActionKind string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked SecureCellGovernmentAgentExecutionLaunchClosureActionKind = "escalate_blocked_closure"
	SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive    SecureCellGovernmentAgentExecutionLaunchClosureActionKind = "issue_archive_certificate"
	SecureCellGovernmentAgentExecutionLaunchClosureActionCloseRecord     SecureCellGovernmentAgentExecutionLaunchClosureActionKind = "close_launch_record"
)

// SecureCellGovernmentAgentExecutionLaunchClosureActionPriority is the queue
// urgency for one closure command.
type SecureCellGovernmentAgentExecutionLaunchClosureActionPriority string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityCritical SecureCellGovernmentAgentExecutionLaunchClosureActionPriority = "critical"
	SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityHigh     SecureCellGovernmentAgentExecutionLaunchClosureActionPriority = "high"
	SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityMedium   SecureCellGovernmentAgentExecutionLaunchClosureActionPriority = "medium"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAction is one timed operator
// action derived from a closure dashboard row.
type SecureCellGovernmentAgentExecutionLaunchClosureAction struct {
	ActionID              string                                                           `json:"action_id"`
	CellID                string                                                           `json:"cell_id"`
	DashboardID           string                                                           `json:"dashboard_id"`
	CenterID              string                                                           `json:"center_id"`
	BoardID               string                                                           `json:"board_id"`
	RegistryID            string                                                           `json:"registry_id"`
	CertificateID         string                                                           `json:"certificate_id"`
	Kind                  SecureCellGovernmentAgentExecutionLaunchClosureActionKind        `json:"kind"`
	Status                SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus `json:"status"`
	Priority              SecureCellGovernmentAgentExecutionLaunchClosureActionPriority    `json:"priority"`
	Action                string                                                           `json:"action"`
	Reason                string                                                           `json:"reason"`
	DueAt                 *time.Time                                                       `json:"due_at,omitempty"`
	OverdueSeconds        int64                                                            `json:"overdue_seconds"`
	EscalationRecommended bool                                                             `json:"escalation_recommended"`
	RequiredReceiptTypes  []string                                                         `json:"required_receipt_types,omitempty"`
	OperatorInstructions  []string                                                         `json:"operator_instructions,omitempty"`
	DashboardDigest       string                                                           `json:"dashboard_digest"`
	ActionDigest          string                                                           `json:"action_digest"`
	GeneratedAt           time.Time                                                        `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureActionQueue is the timed
// operator queue for one secure cell launch closure lifecycle.
type SecureCellGovernmentAgentExecutionLaunchClosureActionQueue struct {
	QueueID                    string                                                           `json:"queue_id"`
	CellID                     string                                                           `json:"cell_id"`
	DashboardID                string                                                           `json:"dashboard_id"`
	CenterID                   string                                                           `json:"center_id"`
	BoardID                    string                                                           `json:"board_id"`
	RegistryID                 string                                                           `json:"registry_id"`
	CertificateID              string                                                           `json:"certificate_id"`
	SettlementRegisterID       string                                                           `json:"settlement_register_id"`
	CloseoutRegisterID         string                                                           `json:"closeout_register_id"`
	LedgerID                   string                                                           `json:"ledger_id"`
	MonitorID                  string                                                           `json:"monitor_id"`
	OrderID                    string                                                           `json:"order_id"`
	ActivationID               string                                                           `json:"activation_id"`
	CustodyID                  string                                                           `json:"custody_id"`
	PackageID                  string                                                           `json:"package_id"`
	Name                       string                                                           `json:"name"`
	Jurisdiction               string                                                           `json:"jurisdiction,omitempty"`
	ServiceCode                string                                                           `json:"service_code,omitempty"`
	ServiceTier                string                                                           `json:"service_tier,omitempty"`
	Status                     SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus `json:"status"`
	DashboardStatus            SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus   `json:"dashboard_status"`
	ActionCount                int                                                              `json:"action_count"`
	BlockedActionCount         int                                                              `json:"blocked_action_count"`
	OverdueActionCount         int                                                              `json:"overdue_action_count"`
	DueActionCount             int                                                              `json:"due_action_count"`
	EscalationRecommendedCount int                                                              `json:"escalation_recommended_count"`
	Actions                    []SecureCellGovernmentAgentExecutionLaunchClosureAction          `json:"actions"`
	RequiredReceiptTypes       []string                                                         `json:"required_receipt_types,omitempty"`
	PrimaryAction              string                                                           `json:"primary_action"`
	DashboardDigest            string                                                           `json:"dashboard_digest"`
	QueueDigest                string                                                           `json:"queue_digest"`
	GeneratedAt                time.Time                                                        `json:"generated_at"`
	UpdatedAt                  time.Time                                                        `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureActionQueue returns the timed
// closure action queue for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureActionQueue(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureActionQueue, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureActionQueues(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-action-queue: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureActionQueues returns timed closure
// action queues for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureActionQueues(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureActionQueue, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-action-queue: service is required")
	}
	dashboards, err := s.ListGovernmentAgentExecutionLaunchClosureDashboards(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	queues := make([]SecureCellGovernmentAgentExecutionLaunchClosureActionQueue, 0, len(dashboards))
	for _, dashboard := range dashboards {
		queues = append(queues, secureCellGovernmentAgentExecutionLaunchClosureActionQueue(dashboard, now))
	}
	sort.SliceStable(queues, func(i, j int) bool {
		if queues[i].Status == queues[j].Status {
			if queues[i].Actions[0].Priority == queues[j].Actions[0].Priority {
				return queues[i].CellID < queues[j].CellID
			}
			return secureCellGovernmentAgentExecutionLaunchClosureActionPriorityRank(queues[i].Actions[0].Priority) < secureCellGovernmentAgentExecutionLaunchClosureActionPriorityRank(queues[j].Actions[0].Priority)
		}
		return secureCellGovernmentAgentExecutionLaunchClosureActionQueueStatusRank(queues[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureActionQueueStatusRank(queues[j].Status)
	})
	return queues, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureActionQueue(
	dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureActionQueue {
	action := secureCellGovernmentAgentExecutionLaunchClosureQueueAction(dashboard, generatedAt)
	queue := SecureCellGovernmentAgentExecutionLaunchClosureActionQueue{
		CellID:               dashboard.CellID,
		DashboardID:          dashboard.DashboardID,
		CenterID:             dashboard.CenterID,
		BoardID:              dashboard.BoardID,
		RegistryID:           dashboard.RegistryID,
		CertificateID:        dashboard.CertificateID,
		SettlementRegisterID: dashboard.SettlementRegisterID,
		CloseoutRegisterID:   dashboard.CloseoutRegisterID,
		LedgerID:             dashboard.LedgerID,
		MonitorID:            dashboard.MonitorID,
		OrderID:              dashboard.OrderID,
		ActivationID:         dashboard.ActivationID,
		CustodyID:            dashboard.CustodyID,
		PackageID:            dashboard.PackageID,
		Name:                 dashboard.Name,
		Jurisdiction:         dashboard.Jurisdiction,
		ServiceCode:          dashboard.ServiceCode,
		ServiceTier:          dashboard.ServiceTier,
		DashboardStatus:      dashboard.Status,
		Actions:              []SecureCellGovernmentAgentExecutionLaunchClosureAction{action},
		RequiredReceiptTypes: append([]string(nil), dashboard.RequiredReceiptTypes...),
		PrimaryAction:        dashboard.PrimaryAction,
		DashboardDigest:      dashboard.DashboardDigest,
		GeneratedAt:          generatedAt.UTC(),
		UpdatedAt:            dashboard.UpdatedAt.UTC(),
	}
	queue.ActionCount = 1
	switch action.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked:
		queue.BlockedActionCount = 1
	case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue:
		queue.OverdueActionCount = 1
	default:
		queue.DueActionCount = 1
	}
	if action.EscalationRecommended {
		queue.EscalationRecommendedCount = 1
	}
	queue.Status = action.Status
	queue.QueueDigest = secureCellGovernmentAgentExecutionLaunchClosureActionQueueDigest(queue)
	queue.QueueID = "government-agent-execution-launch-closure-action-queue:" + queue.CellID + ":" + queue.QueueDigest[:12]
	return queue
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueAction(
	dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAction {
	kind := secureCellGovernmentAgentExecutionLaunchClosureQueueActionKind(dashboard)
	dueAt := secureCellGovernmentAgentExecutionLaunchClosureQueueActionDueAt(dashboard, kind)
	status := secureCellGovernmentAgentExecutionLaunchClosureQueueActionStatus(dashboard, kind, dueAt, generatedAt)
	action := SecureCellGovernmentAgentExecutionLaunchClosureAction{
		CellID:                dashboard.CellID,
		DashboardID:           dashboard.DashboardID,
		CenterID:              dashboard.CenterID,
		BoardID:               dashboard.BoardID,
		RegistryID:            dashboard.RegistryID,
		CertificateID:         dashboard.CertificateID,
		Kind:                  kind,
		Status:                status,
		Priority:              secureCellGovernmentAgentExecutionLaunchClosureQueueActionPriority(dashboard, kind, status),
		Action:                dashboard.PrimaryAction,
		Reason:                secureCellGovernmentAgentExecutionLaunchClosureQueueActionReason(dashboard, kind),
		DueAt:                 dueAt,
		EscalationRecommended: kind == SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked || status == SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue,
		RequiredReceiptTypes:  append([]string(nil), dashboard.RequiredReceiptTypes...),
		OperatorInstructions:  append([]string(nil), dashboard.OperatorInstructions...),
		DashboardDigest:       dashboard.DashboardDigest,
		GeneratedAt:           generatedAt.UTC(),
	}
	if dueAt != nil && generatedAt.After(*dueAt) {
		action.OverdueSeconds = int64(generatedAt.Sub(*dueAt).Seconds())
	}
	core := struct {
		CellID          string                                                           `json:"cell_id"`
		DashboardID     string                                                           `json:"dashboard_id"`
		Kind            SecureCellGovernmentAgentExecutionLaunchClosureActionKind        `json:"kind"`
		Status          SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus `json:"status"`
		Priority        SecureCellGovernmentAgentExecutionLaunchClosureActionPriority    `json:"priority"`
		Action          string                                                           `json:"action"`
		DashboardDigest string                                                           `json:"dashboard_digest"`
	}{
		CellID:          action.CellID,
		DashboardID:     action.DashboardID,
		Kind:            action.Kind,
		Status:          action.Status,
		Priority:        action.Priority,
		Action:          action.Action,
		DashboardDigest: action.DashboardDigest,
	}
	action.ActionDigest = EvidenceHash(core)
	action.ActionID = "government-agent-execution-launch-closure-action:" + action.CellID + ":" + action.ActionDigest[:12]
	return action
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueActionKind(dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard) SecureCellGovernmentAgentExecutionLaunchClosureActionKind {
	switch dashboard.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureDashboardBlocked:
		return SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked
	case SecureCellGovernmentAgentExecutionLaunchClosureDashboardReadyToClose:
		return SecureCellGovernmentAgentExecutionLaunchClosureActionCloseRecord
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueActionDueAt(
	dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	kind SecureCellGovernmentAgentExecutionLaunchClosureActionKind,
) *time.Time {
	base := dashboard.UpdatedAt.UTC()
	sla := secureCellGovernmentAgentExecutionLaunchClosureQueueActionSLA(strings.TrimSpace(dashboard.ServiceTier), kind)
	dueAt := base.Add(sla)
	return cloneTimePtr(&dueAt)
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueActionSLA(
	serviceTier string,
	kind SecureCellGovernmentAgentExecutionLaunchClosureActionKind,
) time.Duration {
	normalized := strings.ToLower(strings.TrimSpace(serviceTier))
	switch normalized {
	case "tier_1", "tier1":
		switch kind {
		case SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked:
			return 15 * time.Minute
		case SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive:
			return 30 * time.Minute
		default:
			return 45 * time.Minute
		}
	case "tier_2", "tier2":
		switch kind {
		case SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked:
			return 30 * time.Minute
		case SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive:
			return 90 * time.Minute
		default:
			return 2 * time.Hour
		}
	default:
		switch kind {
		case SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked:
			return time.Hour
		case SecureCellGovernmentAgentExecutionLaunchClosureActionIssueArchive:
			return 4 * time.Hour
		default:
			return 6 * time.Hour
		}
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueActionStatus(
	dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	kind SecureCellGovernmentAgentExecutionLaunchClosureActionKind,
	dueAt *time.Time,
	at time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus {
	if kind == SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked {
		return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked
	}
	if dueAt != nil && !dueAt.After(at) {
		return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueDue
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueActionPriority(
	dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	kind SecureCellGovernmentAgentExecutionLaunchClosureActionKind,
	status SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus,
) SecureCellGovernmentAgentExecutionLaunchClosureActionPriority {
	if kind == SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked || status == SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue {
		return SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityCritical
	}
	if strings.EqualFold(strings.TrimSpace(dashboard.ServiceTier), "tier_1") {
		return SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityHigh
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityMedium
}

func secureCellGovernmentAgentExecutionLaunchClosureQueueActionReason(
	dashboard SecureCellGovernmentAgentExecutionLaunchClosureDashboard,
	kind SecureCellGovernmentAgentExecutionLaunchClosureActionKind,
) string {
	switch kind {
	case SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked:
		return "blocked launch closure items require operator escalation before archive issue or record closeout"
	case SecureCellGovernmentAgentExecutionLaunchClosureActionCloseRecord:
		return "archive evidence is complete and the launch record can be closed from the operator queue"
	default:
		if dashboard.PendingItemCount > 0 {
			return "archive certificate must be issued before final launch record closeout"
		}
		return "archive issue confirmation is required before final launch record closeout"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureActionQueueStatusRank(status SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueDue:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureActionPriorityRank(priority SecureCellGovernmentAgentExecutionLaunchClosureActionPriority) int {
	switch priority {
	case SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityCritical:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityHigh:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureActionPriorityMedium:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureActionQueueDigest(queue SecureCellGovernmentAgentExecutionLaunchClosureActionQueue) string {
	actionDigests := make([]string, 0, len(queue.Actions))
	for _, action := range queue.Actions {
		actionDigests = append(actionDigests, action.ActionDigest)
	}
	core := struct {
		CellID               string                                                           `json:"cell_id"`
		DashboardID          string                                                           `json:"dashboard_id"`
		Status               SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus `json:"status"`
		DashboardStatus      SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus   `json:"dashboard_status"`
		RequiredReceiptTypes []string                                                         `json:"required_receipt_types,omitempty"`
		PrimaryAction        string                                                           `json:"primary_action"`
		ActionDigests        []string                                                         `json:"action_digests,omitempty"`
		DashboardDigest      string                                                           `json:"dashboard_digest"`
	}{
		CellID:               queue.CellID,
		DashboardID:          queue.DashboardID,
		Status:               queue.Status,
		DashboardStatus:      queue.DashboardStatus,
		RequiredReceiptTypes: queue.RequiredReceiptTypes,
		PrimaryAction:        queue.PrimaryAction,
		ActionDigests:        actionDigests,
		DashboardDigest:      queue.DashboardDigest,
	}
	return EvidenceHash(core)
}
