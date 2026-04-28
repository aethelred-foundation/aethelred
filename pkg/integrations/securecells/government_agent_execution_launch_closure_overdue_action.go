package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter narrows
// operator views over breached closure automation actions.
type SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter struct {
	CellID       string     `json:"cell_id,omitempty"`
	Jurisdiction string     `json:"jurisdiction,omitempty"`
	ServiceCode  string     `json:"service_code,omitempty"`
	ServiceTier  string     `json:"service_tier,omitempty"`
	Before       *time.Time `json:"before,omitempty"`
	Limit        int        `json:"limit,omitempty"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction projects one
// breached archive-issue or closeout automation action.
type SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction struct {
	RecordID              string                                                         `json:"record_id"`
	CellID                string                                                         `json:"cell_id"`
	Name                  string                                                         `json:"name"`
	Jurisdiction          string                                                         `json:"jurisdiction,omitempty"`
	ServiceCode           string                                                         `json:"service_code,omitempty"`
	ServiceTier           string                                                         `json:"service_tier,omitempty"`
	QueueID               string                                                         `json:"queue_id"`
	DashboardID           string                                                         `json:"dashboard_id"`
	CenterID              string                                                         `json:"center_id"`
	BoardID               string                                                         `json:"board_id"`
	RegistryID            string                                                         `json:"registry_id"`
	CertificateID         string                                                         `json:"certificate_id"`
	DashboardStatus       SecureCellGovernmentAgentExecutionLaunchClosureDashboardStatus `json:"dashboard_status"`
	PendingAction         string                                                         `json:"pending_action"`
	AutomationAction      string                                                         `json:"automation_action"`
	ActionKind            SecureCellGovernmentAgentExecutionLaunchClosureActionKind      `json:"action_kind"`
	ActionPriority        SecureCellGovernmentAgentExecutionLaunchClosureActionPriority  `json:"action_priority"`
	Reason                string                                                         `json:"reason"`
	DueAt                 time.Time                                                      `json:"due_at"`
	OverdueSeconds        int64                                                          `json:"overdue_seconds"`
	EscalationRecommended bool                                                           `json:"escalation_recommended"`
	RequiredReceiptTypes  []string                                                       `json:"required_receipt_types,omitempty"`
	OperatorInstructions  []string                                                       `json:"operator_instructions,omitempty"`
	ActionID              string                                                         `json:"action_id"`
	ActionDigest          string                                                         `json:"action_digest"`
	QueueDigest           string                                                         `json:"queue_digest"`
	DashboardDigest       string                                                         `json:"dashboard_digest"`
	GeneratedAt           time.Time                                                      `json:"generated_at"`
	UpdatedAt             time.Time                                                      `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureOverdueAction returns the first
// overdue closure automation action for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureOverdueAction(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchClosureOverdueActions(ctx, SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-overdue-action: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchClosureOverdueActions returns breached
// closure automation actions for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchClosureOverdueActions(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) ([]SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-overdue-action: service is required")
	}
	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items, err := s.ListGovernmentAgentExecutionLaunchClosureAutomationActions(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID:       strings.TrimSpace(filter.CellID),
		Jurisdiction: strings.TrimSpace(filter.Jurisdiction),
		ServiceCode:  strings.TrimSpace(filter.ServiceCode),
		ServiceTier:  strings.TrimSpace(filter.ServiceTier),
	})
	if err != nil {
		return nil, err
	}
	overdue := make([]SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction, 0, len(items))
	for _, item := range items {
		if item.DueAt == nil || item.DueAt.IsZero() {
			continue
		}
		if !at.After(item.DueAt.UTC()) {
			continue
		}
		overdue = append(overdue, secureCellGovernmentAgentExecutionLaunchClosureOverdueAction(item, at))
	}
	sort.SliceStable(overdue, func(i, j int) bool {
		if overdue[i].DueAt.Equal(overdue[j].DueAt) {
			return overdue[i].CellID < overdue[j].CellID
		}
		return overdue[i].DueAt.Before(overdue[j].DueAt)
	})
	if filter.Limit > 0 && len(overdue) > filter.Limit {
		overdue = overdue[:filter.Limit]
	}
	return overdue, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureOverdueAction(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction,
	at time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction {
	overdueAt := item.DueAt.UTC()
	overdue := SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction{
		CellID:                item.CellID,
		Name:                  item.Name,
		Jurisdiction:          item.Jurisdiction,
		ServiceCode:           item.ServiceCode,
		ServiceTier:           item.ServiceTier,
		QueueID:               item.QueueID,
		DashboardID:           item.DashboardID,
		CenterID:              item.CenterID,
		BoardID:               item.BoardID,
		RegistryID:            item.RegistryID,
		CertificateID:         item.CertificateID,
		DashboardStatus:       item.DashboardStatus,
		PendingAction:         item.PendingAction,
		AutomationAction:      item.AutomationAction,
		ActionKind:            item.ActionKind,
		ActionPriority:        item.ActionPriority,
		Reason:                item.Reason,
		DueAt:                 overdueAt,
		OverdueSeconds:        int64(at.Sub(overdueAt).Seconds()),
		EscalationRecommended: item.EscalationRecommended,
		RequiredReceiptTypes:  append([]string(nil), item.RequiredReceiptTypes...),
		OperatorInstructions:  append([]string(nil), item.OperatorInstructions...),
		ActionID:              item.ActionID,
		ActionDigest:          item.ActionDigest,
		QueueDigest:           item.QueueDigest,
		DashboardDigest:       item.DashboardDigest,
		GeneratedAt:           item.GeneratedAt.UTC(),
		UpdatedAt:             item.UpdatedAt.UTC(),
	}
	core := struct {
		CellID       string    `json:"cell_id"`
		QueueID      string    `json:"queue_id"`
		ActionID     string    `json:"action_id"`
		ActionDigest string    `json:"action_digest"`
		DueAt        time.Time `json:"due_at"`
	}{
		CellID:       overdue.CellID,
		QueueID:      overdue.QueueID,
		ActionID:     overdue.ActionID,
		ActionDigest: overdue.ActionDigest,
		DueAt:        overdue.DueAt,
	}
	digest := EvidenceHash(core)
	overdue.RecordID = "government-agent-execution-launch-closure-overdue-action:" + overdue.CellID + ":" + digest[:12]
	return overdue
}
