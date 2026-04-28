package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment is one
// command assignment for a grouped pending action.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment struct {
	Sequence         int      `json:"sequence"`
	Role             string   `json:"role"`
	PendingAction    string   `json:"pending_action"`
	AutomationAction string   `json:"automation_action"`
	CellIDs          []string `json:"cell_ids,omitempty"`
	Instruction      string   `json:"instruction"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch is the
// command-dispatch artifact derived from one brief.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch struct {
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
	Command            string                                                                        `json:"command"`
	LeadRole           string                                                                        `json:"lead_role"`
	LeadPendingAction  string                                                                        `json:"lead_pending_action,omitempty"`
	EscalationRequired bool                                                                          `json:"escalation_required"`
	AssignmentCount    int                                                                           `json:"assignment_count"`
	Assignments        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment `json:"assignments"`
	Steps              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep        `json:"steps"`
	Items              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem          `json:"items"`
	BriefDigest        string                                                                        `json:"brief_digest"`
	DispatchDigest     string                                                                        `json:"dispatch_digest"`
	GeneratedAt        time.Time                                                                     `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationDispatch returns the command
// dispatch view for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationDispatch(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-dispatch: service is required")
	}
	brief, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationBrief(ctx, filter)
	if err != nil {
		return nil, err
	}
	dispatch := secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch(*brief, time.Now().UTC())
	return &dispatch, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch(
	brief SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch {
	dispatch := SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch{
		BriefID:            brief.BriefID,
		RunbookID:          brief.RunbookID,
		PacketID:           brief.PacketID,
		BoardID:            brief.BoardID,
		SummaryID:          brief.SummaryID,
		Jurisdiction:       brief.Jurisdiction,
		ServiceCode:        brief.ServiceCode,
		ServiceTier:        brief.ServiceTier,
		EvaluatedAt:        brief.EvaluatedAt.UTC(),
		FocusLane:          brief.FocusLane,
		FocusAction:        brief.FocusAction,
		Severity:           brief.Severity,
		Command:            secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchCommand(brief),
		LeadRole:           secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchLeadRole(brief),
		LeadPendingAction:  firstNonEmpty(brief.UniquePendingAction...),
		EscalationRequired: brief.FocusLane == SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked,
		Steps:              append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep(nil), brief.Steps...),
		Items:              append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem(nil), brief.Items...),
		BriefDigest:        brief.BriefDigest,
		GeneratedAt:        generatedAt.UTC(),
	}
	dispatch.Assignments = secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignments(brief)
	dispatch.AssignmentCount = len(dispatch.Assignments)
	dispatch.DispatchDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchDigest(dispatch)
	dispatch.DispatchID = "government-agent-execution-launch-closure-automation-dispatch:" + firstNonEmpty(dispatch.Jurisdiction, "all") + ":" + dispatch.DispatchDigest[:12]
	return dispatch
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchCommand(
	brief SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief,
) string {
	switch brief.FocusLane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return "Activate escalation command and unblock closure before archive or closeout resumes."
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return "Dispatch immediate recovery work to clear breached closure timers."
	default:
		return "Dispatch preventive work to clear the next due closure actions."
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchLeadRole(
	brief SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief,
) string {
	switch brief.FocusLane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return "incident_commander"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return "operations_lead"
	default:
		return "workflow_coordinator"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignmentRole(
	pendingAction string,
	focusLane SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane,
) string {
	switch pendingAction {
	case "escalate_blocked_closure":
		return "incident_commander"
	case "issue_archive_certificate":
		return "archive_officer"
	case "close_launch_record":
		return "records_officer"
	default:
		if focusLane == SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue {
			return "operations_lead"
		}
		return "workflow_coordinator"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignments(
	brief SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment {
	type key struct {
		pendingAction    string
		automationAction string
	}
	assignmentMap := map[key]*SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment{}
	order := make([]key, 0)
	for _, item := range brief.Items {
		k := key{
			pendingAction:    item.PendingAction,
			automationAction: item.AutomationAction,
		}
		assignment, ok := assignmentMap[k]
		if !ok {
			assignment = &SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment{
				Role:             secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignmentRole(item.PendingAction, brief.FocusLane),
				PendingAction:    item.PendingAction,
				AutomationAction: item.AutomationAction,
				Instruction:      secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignmentInstruction(item.PendingAction, brief.Directive),
			}
			assignmentMap[k] = assignment
			order = append(order, k)
		}
		assignment.CellIDs = append(assignment.CellIDs, item.CellID)
	}
	assignments := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment, 0, len(order))
	for _, k := range order {
		assignment := assignmentMap[k]
		assignment.CellIDs = uniqueTrimmedStrings(assignment.CellIDs)
		assignments = append(assignments, *assignment)
	}
	sort.SliceStable(assignments, func(i, j int) bool {
		if assignments[i].Role == assignments[j].Role {
			return assignments[i].PendingAction < assignments[j].PendingAction
		}
		return assignments[i].Role < assignments[j].Role
	})
	for idx := range assignments {
		assignments[idx].Sequence = idx + 1
	}
	return assignments
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignmentInstruction(
	pendingAction string,
	directive string,
) string {
	switch pendingAction {
	case "escalate_blocked_closure":
		return "Open escalation handling immediately and clear the blocked closure dependency path. " + directive
	case "issue_archive_certificate":
		return "Issue archive certificates for the assigned cells and clear the preservation queue. " + directive
	case "close_launch_record":
		return "Complete closure record finalization for the assigned cells. " + directive
	default:
		return directive
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchDigest(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch,
) string {
	core := struct {
		BriefID            string                                                                        `json:"brief_id"`
		RunbookID          string                                                                        `json:"runbook_id"`
		FocusLane          SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane            `json:"focus_lane"`
		FocusAction        string                                                                        `json:"focus_action"`
		Severity           SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity        `json:"severity"`
		Command            string                                                                        `json:"command"`
		LeadRole           string                                                                        `json:"lead_role"`
		LeadPendingAction  string                                                                        `json:"lead_pending_action"`
		EscalationRequired bool                                                                          `json:"escalation_required"`
		Assignments        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment `json:"assignments"`
		Steps              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep        `json:"steps"`
		Items              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem          `json:"items"`
		BriefDigest        string                                                                        `json:"brief_digest"`
	}{
		BriefID:            dispatch.BriefID,
		RunbookID:          dispatch.RunbookID,
		FocusLane:          dispatch.FocusLane,
		FocusAction:        dispatch.FocusAction,
		Severity:           dispatch.Severity,
		Command:            dispatch.Command,
		LeadRole:           dispatch.LeadRole,
		LeadPendingAction:  dispatch.LeadPendingAction,
		EscalationRequired: dispatch.EscalationRequired,
		Assignments:        dispatch.Assignments,
		Steps:              dispatch.Steps,
		Items:              dispatch.Items,
		BriefDigest:        dispatch.BriefDigest,
	}
	return EvidenceHash(core)
}
