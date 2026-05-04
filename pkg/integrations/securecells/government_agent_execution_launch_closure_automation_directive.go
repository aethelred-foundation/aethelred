package securecells

import (
	"context"
	"fmt"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective is the
// authoritative operator directive derived from one dispatch.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective struct {
	DirectiveID        string                                                                        `json:"directive_id"`
	DispatchID         string                                                                        `json:"dispatch_id"`
	BriefID            string                                                                        `json:"brief_id"`
	RunbookID          string                                                                        `json:"runbook_id"`
	PacketID           string                                                                        `json:"packet_id"`
	BoardID            string                                                                        `json:"board_id"`
	SummaryID          string                                                                        `json:"summary_id"`
	Jurisdiction       string                                                                        `json:"jurisdiction,omitempty"`
	ServiceCode        string                                                                        `json:"service_code,omitempty"`
	ServiceTier        string                                                                        `json:"service_tier,omitempty"`
	EvaluatedAt        time.Time                                                                     `json:"evaluated_at"`
	FocusLane          SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane            `json:"focus_lane"`
	FocusAction        string                                                                        `json:"focus_action"`
	Severity           SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity        `json:"severity"`
	Directive          string                                                                        `json:"directive"`
	LeadRole           string                                                                        `json:"lead_role"`
	LeadPendingAction  string                                                                        `json:"lead_pending_action,omitempty"`
	AckRequired        bool                                                                          `json:"ack_required"`
	ExecutionWindow    string                                                                        `json:"execution_window"`
	EscalationRequired bool                                                                          `json:"escalation_required"`
	AssignmentCount    int                                                                           `json:"assignment_count"`
	Assignments        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment `json:"assignments"`
	Items              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem          `json:"items"`
	DispatchDigest     string                                                                        `json:"dispatch_digest"`
	DirectiveDigest    string                                                                        `json:"directive_digest"`
	GeneratedAt        time.Time                                                                     `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationDirective returns the
// authoritative closure directive for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationDirective(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-directive: service is required")
	}
	dispatch, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationDispatch(ctx, filter)
	if err != nil {
		return nil, err
	}
	directive := secureCellGovernmentAgentExecutionLaunchClosureAutomationDirective(*dispatch, time.Now().UTC())
	return &directive, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDirective(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective {
	directive := SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective{
		DispatchID:         dispatch.DispatchID,
		BriefID:            dispatch.BriefID,
		RunbookID:          dispatch.RunbookID,
		PacketID:           dispatch.PacketID,
		BoardID:            dispatch.BoardID,
		SummaryID:          dispatch.SummaryID,
		Jurisdiction:       dispatch.Jurisdiction,
		ServiceCode:        dispatch.ServiceCode,
		ServiceTier:        dispatch.ServiceTier,
		EvaluatedAt:        dispatch.EvaluatedAt.UTC(),
		FocusLane:          dispatch.FocusLane,
		FocusAction:        dispatch.FocusAction,
		Severity:           dispatch.Severity,
		Directive:          dispatch.Command,
		LeadRole:           dispatch.LeadRole,
		LeadPendingAction:  dispatch.LeadPendingAction,
		AckRequired:        true,
		ExecutionWindow:    secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveWindow(dispatch),
		EscalationRequired: dispatch.EscalationRequired,
		AssignmentCount:    dispatch.AssignmentCount,
		Assignments:        append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment(nil), dispatch.Assignments...),
		Items:              append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem(nil), dispatch.Items...),
		DispatchDigest:     dispatch.DispatchDigest,
		GeneratedAt:        generatedAt.UTC(),
	}
	directive.DirectiveDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveDigest(directive)
	directive.DirectiveID = "government-agent-execution-launch-closure-automation-directive:" + firstNonEmpty(directive.Jurisdiction, "all") + ":" + directive.DirectiveDigest[:12]
	return directive
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveWindow(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch,
) string {
	switch dispatch.FocusLane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return "immediate"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return "within_15_minutes"
	default:
		return "within_60_minutes"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveDigest(
	directive SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective,
) string {
	core := struct {
		DispatchID         string                                                                        `json:"dispatch_id"`
		BriefID            string                                                                        `json:"brief_id"`
		FocusLane          SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane            `json:"focus_lane"`
		FocusAction        string                                                                        `json:"focus_action"`
		Severity           SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity        `json:"severity"`
		Directive          string                                                                        `json:"directive"`
		LeadRole           string                                                                        `json:"lead_role"`
		LeadPendingAction  string                                                                        `json:"lead_pending_action"`
		AckRequired        bool                                                                          `json:"ack_required"`
		ExecutionWindow    string                                                                        `json:"execution_window"`
		EscalationRequired bool                                                                          `json:"escalation_required"`
		Assignments        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment `json:"assignments"`
		Items              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem          `json:"items"`
		DispatchDigest     string                                                                        `json:"dispatch_digest"`
	}{
		DispatchID:         directive.DispatchID,
		BriefID:            directive.BriefID,
		FocusLane:          directive.FocusLane,
		FocusAction:        directive.FocusAction,
		Severity:           directive.Severity,
		Directive:          directive.Directive,
		LeadRole:           directive.LeadRole,
		LeadPendingAction:  directive.LeadPendingAction,
		AckRequired:        directive.AckRequired,
		ExecutionWindow:    directive.ExecutionWindow,
		EscalationRequired: directive.EscalationRequired,
		Assignments:        directive.Assignments,
		Items:              directive.Items,
		DispatchDigest:     directive.DispatchDigest,
	}
	return EvidenceHash(core)
}
