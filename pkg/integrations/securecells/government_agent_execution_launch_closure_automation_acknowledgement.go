package securecells

import (
	"context"
	"fmt"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusPending SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus = "pending"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus = "overdue"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement is the
// acknowledgement control record derived from one operator directive.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement struct {
	AcknowledgementID      string                                                                         `json:"acknowledgement_id"`
	DirectiveID            string                                                                         `json:"directive_id"`
	DispatchID             string                                                                         `json:"dispatch_id"`
	BriefID                string                                                                         `json:"brief_id"`
	RunbookID              string                                                                         `json:"runbook_id"`
	PacketID               string                                                                         `json:"packet_id"`
	BoardID                string                                                                         `json:"board_id"`
	SummaryID              string                                                                         `json:"summary_id"`
	Jurisdiction           string                                                                         `json:"jurisdiction,omitempty"`
	ServiceCode            string                                                                         `json:"service_code,omitempty"`
	ServiceTier            string                                                                         `json:"service_tier,omitempty"`
	EvaluatedAt            time.Time                                                                      `json:"evaluated_at"`
	FocusLane              SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane             `json:"focus_lane"`
	FocusAction            string                                                                         `json:"focus_action"`
	Severity               SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity         `json:"severity"`
	AckRequired            bool                                                                           `json:"ack_required"`
	AckStatus              SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus `json:"ack_status"`
	AckDueAt               *time.Time                                                                     `json:"ack_due_at,omitempty"`
	AckOverdueSeconds      int64                                                                          `json:"ack_overdue_seconds"`
	AckAction              string                                                                         `json:"ack_action"`
	LeadRole               string                                                                         `json:"lead_role"`
	RequiredRoles          []string                                                                       `json:"required_roles,omitempty"`
	RequiredPendingActions []string                                                                       `json:"required_pending_actions,omitempty"`
	EscalationRequired     bool                                                                           `json:"escalation_required"`
	AssignmentCount        int                                                                            `json:"assignment_count"`
	Assignments            []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment  `json:"assignments"`
	Items                  []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem           `json:"items"`
	DirectiveDigest        string                                                                         `json:"directive_digest"`
	AcknowledgementDigest  string                                                                         `json:"acknowledgement_digest"`
	GeneratedAt            time.Time                                                                      `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement returns the
// acknowledgement control record for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement: service is required")
	}
	directive, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationDirective(ctx, filter)
	if err != nil {
		return nil, err
	}
	acknowledgement := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(*directive, time.Now().UTC())
	return &acknowledgement, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(
	directive SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement {
	ackDueAt := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementDueAt(directive)
	ackStatus := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusPending
	var overdueSeconds int64
	if ackDueAt != nil && directive.EvaluatedAt.UTC().After(ackDueAt.UTC()) {
		ackStatus = SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue
		overdueSeconds = int64(directive.EvaluatedAt.UTC().Sub(ackDueAt.UTC()).Seconds())
	}
	acknowledgement := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement{
		DirectiveID:            directive.DirectiveID,
		DispatchID:             directive.DispatchID,
		BriefID:                directive.BriefID,
		RunbookID:              directive.RunbookID,
		PacketID:               directive.PacketID,
		BoardID:                directive.BoardID,
		SummaryID:              directive.SummaryID,
		Jurisdiction:           directive.Jurisdiction,
		ServiceCode:            directive.ServiceCode,
		ServiceTier:            directive.ServiceTier,
		EvaluatedAt:            directive.EvaluatedAt.UTC(),
		FocusLane:              directive.FocusLane,
		FocusAction:            directive.FocusAction,
		Severity:               directive.Severity,
		AckRequired:            directive.AckRequired,
		AckStatus:              ackStatus,
		AckDueAt:               ackDueAt,
		AckOverdueSeconds:      overdueSeconds,
		AckAction:              secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementAction(directive, ackStatus),
		LeadRole:               directive.LeadRole,
		RequiredRoles:          secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementRoles(directive.Assignments),
		RequiredPendingActions: secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementPendingActions(directive.Assignments),
		EscalationRequired:     directive.EscalationRequired,
		AssignmentCount:        directive.AssignmentCount,
		Assignments:            append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment(nil), directive.Assignments...),
		Items:                  append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem(nil), directive.Items...),
		DirectiveDigest:        directive.DirectiveDigest,
		GeneratedAt:            generatedAt.UTC(),
	}
	acknowledgement.AcknowledgementDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementDigest(acknowledgement)
	acknowledgement.AcknowledgementID = "government-agent-execution-launch-closure-automation-acknowledgement:" + firstNonEmpty(acknowledgement.Jurisdiction, "all") + ":" + acknowledgement.AcknowledgementDigest[:12]
	return acknowledgement
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementDueAt(
	directive SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective,
) *time.Time {
	var dueAt *time.Time
	for _, item := range directive.Items {
		if item.DueAt == nil || item.DueAt.IsZero() {
			continue
		}
		candidate := item.DueAt.UTC()
		if dueAt == nil || candidate.Before(*dueAt) {
			dueAt = &candidate
		}
	}
	if dueAt != nil {
		return dueAt
	}
	fallback := directive.EvaluatedAt.UTC()
	switch directive.ExecutionWindow {
	case "immediate":
	case "within_15_minutes":
		fallback = fallback.Add(15 * time.Minute)
	default:
		fallback = fallback.Add(time.Hour)
	}
	return &fallback
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementAction(
	directive SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective,
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus,
) string {
	if status == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue {
		if directive.EscalationRequired {
			return "escalate_launch_closure_acknowledgement"
		}
		return "recover_launch_closure_acknowledgement"
	}
	return "acknowledge_launch_closure_directive"
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementRoles(
	assignments []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment,
) []string {
	roles := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		roles = append(roles, assignment.Role)
	}
	return uniqueTrimmedStrings(roles)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementPendingActions(
	assignments []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment,
) []string {
	actions := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		actions = append(actions, assignment.PendingAction)
	}
	return uniqueTrimmedStrings(actions)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementDigest(
	acknowledgement SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement,
) string {
	core := struct {
		DirectiveID            string                                                                         `json:"directive_id"`
		DispatchID             string                                                                         `json:"dispatch_id"`
		FocusLane              SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane             `json:"focus_lane"`
		FocusAction            string                                                                         `json:"focus_action"`
		Severity               SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity         `json:"severity"`
		AckRequired            bool                                                                           `json:"ack_required"`
		AckStatus              SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus `json:"ack_status"`
		AckDueAt               *time.Time                                                                     `json:"ack_due_at,omitempty"`
		AckOverdueSeconds      int64                                                                          `json:"ack_overdue_seconds"`
		AckAction              string                                                                         `json:"ack_action"`
		LeadRole               string                                                                         `json:"lead_role"`
		RequiredRoles          []string                                                                       `json:"required_roles,omitempty"`
		RequiredPendingActions []string                                                                       `json:"required_pending_actions,omitempty"`
		EscalationRequired     bool                                                                           `json:"escalation_required"`
		Assignments            []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment  `json:"assignments"`
		Items                  []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem           `json:"items"`
		DirectiveDigest        string                                                                         `json:"directive_digest"`
	}{
		DirectiveID:            acknowledgement.DirectiveID,
		DispatchID:             acknowledgement.DispatchID,
		FocusLane:              acknowledgement.FocusLane,
		FocusAction:            acknowledgement.FocusAction,
		Severity:               acknowledgement.Severity,
		AckRequired:            acknowledgement.AckRequired,
		AckStatus:              acknowledgement.AckStatus,
		AckDueAt:               acknowledgement.AckDueAt,
		AckOverdueSeconds:      acknowledgement.AckOverdueSeconds,
		AckAction:              acknowledgement.AckAction,
		LeadRole:               acknowledgement.LeadRole,
		RequiredRoles:          acknowledgement.RequiredRoles,
		RequiredPendingActions: acknowledgement.RequiredPendingActions,
		EscalationRequired:     acknowledgement.EscalationRequired,
		Assignments:            acknowledgement.Assignments,
		Items:                  acknowledgement.Items,
		DirectiveDigest:        acknowledgement.DirectiveDigest,
	}
	return EvidenceHash(core)
}
