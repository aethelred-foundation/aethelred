package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction is one
// operator-queryable timed automation candidate derived from a closure queue.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction struct {
	RecordID              string                                                           `json:"record_id"`
	CellID                string                                                           `json:"cell_id"`
	Name                  string                                                           `json:"name"`
	Jurisdiction          string                                                           `json:"jurisdiction,omitempty"`
	ServiceCode           string                                                           `json:"service_code,omitempty"`
	ServiceTier           string                                                           `json:"service_tier,omitempty"`
	QueueID               string                                                           `json:"queue_id"`
	DashboardID           string                                                           `json:"dashboard_id"`
	CenterID              string                                                           `json:"center_id"`
	BoardID               string                                                           `json:"board_id"`
	RegistryID            string                                                           `json:"registry_id"`
	CertificateID         string                                                           `json:"certificate_id"`
	QueueStatus           SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus `json:"queue_status"`
	DashboardStatus       SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus   `json:"dashboard_status"`
	PendingAction         string                                                           `json:"pending_action"`
	AutomationAction      string                                                           `json:"automation_action"`
	ActionKind            SecureCellGovernmentAgentExecutionLaunchClosureActionKind        `json:"action_kind"`
	ActionPriority        SecureCellGovernmentAgentExecutionLaunchClosureActionPriority    `json:"action_priority"`
	Reason                string                                                           `json:"reason"`
	DueAt                 *time.Time                                                       `json:"due_at,omitempty"`
	OverdueSeconds        int64                                                            `json:"overdue_seconds"`
	EscalationRecommended bool                                                             `json:"escalation_recommended"`
	RequiredReceiptTypes  []string                                                         `json:"required_receipt_types,omitempty"`
	OperatorInstructions  []string                                                         `json:"operator_instructions,omitempty"`
	ActionID              string                                                           `json:"action_id"`
	ActionDigest          string                                                           `json:"action_digest"`
	QueueDigest           string                                                           `json:"queue_digest"`
	DashboardDigest       string                                                           `json:"dashboard_digest"`
	GeneratedAt           time.Time                                                        `json:"generated_at"`
	UpdatedAt             time.Time                                                        `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAction returns the timed
// automation record for one secure cell closure queue.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAction(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureAutomationActions(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-action: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureAutomationActions returns timed
// automation candidates for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureAutomationActions(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-action: service is required")
	}
	queues, err := s.ListGovernmentAgentExecutionLaunchClosureActionQueues(ctx, filter)
	if err != nil {
		return nil, err
	}
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction, 0, len(queues))
	for _, queue := range queues {
		items = append(items, secureCellGovernmentAgentExecutionLaunchClosureAutomationAction(queue))
	}
	sort.SliceStable(items, func(i, j int) bool {
		leftDue := items[i].DueAt
		rightDue := items[j].DueAt
		if leftDue == nil || rightDue == nil {
			if leftDue == nil && rightDue != nil {
				return false
			}
			if leftDue != nil && rightDue == nil {
				return true
			}
			return items[i].CellID < items[j].CellID
		}
		if leftDue.Equal(*rightDue) {
			return items[i].CellID < items[j].CellID
		}
		return leftDue.Before(*rightDue)
	})
	return items, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAction(
	queue SecureCellGovernmentAgentExecutionLaunchClosureActionQueue,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction {
	var action SecureCellGovernmentAgentExecutionLaunchClosureAction
	if len(queue.Actions) > 0 {
		action = queue.Actions[0]
	}
	item := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction{
		CellID:                queue.CellID,
		Name:                  queue.Name,
		Jurisdiction:          queue.Jurisdiction,
		ServiceCode:           queue.ServiceCode,
		ServiceTier:           queue.ServiceTier,
		QueueID:               queue.QueueID,
		DashboardID:           queue.DashboardID,
		CenterID:              queue.CenterID,
		BoardID:               queue.BoardID,
		RegistryID:            queue.RegistryID,
		CertificateID:         queue.CertificateID,
		QueueStatus:           queue.Status,
		DashboardStatus:       queue.DashboardStatus,
		PendingAction:         action.Action,
		AutomationAction:      secureCellGovernmentAgentExecutionLaunchClosureAutomationActionName(action),
		ActionKind:            action.Kind,
		ActionPriority:        action.Priority,
		Reason:                action.Reason,
		DueAt:                 cloneTimePtr(action.DueAt),
		OverdueSeconds:        action.OverdueSeconds,
		EscalationRecommended: action.EscalationRecommended,
		RequiredReceiptTypes:  append([]string(nil), action.RequiredReceiptTypes...),
		OperatorInstructions:  append([]string(nil), action.OperatorInstructions...),
		ActionID:              action.ActionID,
		ActionDigest:          action.ActionDigest,
		QueueDigest:           queue.QueueDigest,
		DashboardDigest:       queue.DashboardDigest,
		GeneratedAt:           queue.GeneratedAt.UTC(),
		UpdatedAt:             queue.UpdatedAt.UTC(),
	}
	core := struct {
		CellID           string                                                           `json:"cell_id"`
		QueueID          string                                                           `json:"queue_id"`
		PendingAction    string                                                           `json:"pending_action"`
		AutomationAction string                                                           `json:"automation_action"`
		QueueStatus      SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus `json:"queue_status"`
		ActionKind       SecureCellGovernmentAgentExecutionLaunchClosureActionKind        `json:"action_kind"`
		ActionDigest     string                                                           `json:"action_digest"`
		QueueDigest      string                                                           `json:"queue_digest"`
	}{
		CellID:           item.CellID,
		QueueID:          item.QueueID,
		PendingAction:    item.PendingAction,
		AutomationAction: item.AutomationAction,
		QueueStatus:      item.QueueStatus,
		ActionKind:       item.ActionKind,
		ActionDigest:     item.ActionDigest,
		QueueDigest:      item.QueueDigest,
	}
	digest := EvidenceHash(core)
	item.RecordID = "government-agent-execution-launch-closure-automation-action:" + item.CellID + ":" + digest[:12]
	return item
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationActionName(action SecureCellGovernmentAgentExecutionLaunchClosureAction) string {
	switch action.Kind {
	case SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked:
		return "secure_cell.government_agent_execution_launch_closure_escalated"
	case SecureCellGovernmentAgentExecutionLaunchClosureActionCloseRecord:
		if action.Status == SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue {
			return "secure_cell.government_agent_execution_launch_closure_closeout_breached"
		}
		return "secure_cell.government_agent_execution_launch_closure_closeout_ready"
	default:
		if action.Status == SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue {
			return "secure_cell.government_agent_execution_launch_archive_issue_breached"
		}
		return "secure_cell.government_agent_execution_launch_archive_issue_pending"
	}
}
