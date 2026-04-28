package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane captures
// the estate queue lane an operator should work from first.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane = "blocked"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane = "overdue"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneDue     SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane = "due"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem is one
// actionable operator row inside the command board.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem struct {
	CellID           string                                                             `json:"cell_id"`
	Name             string                                                             `json:"name"`
	Lane             SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane `json:"lane"`
	PendingAction    string                                                             `json:"pending_action"`
	AutomationAction string                                                             `json:"automation_action"`
	ActionPriority   SecureCellGovernmentAgentExecutionLaunchClosureActionPriority      `json:"action_priority"`
	DueAt            *time.Time                                                         `json:"due_at,omitempty"`
	OverdueSeconds   int64                                                              `json:"overdue_seconds"`
	EscalationNeeded bool                                                               `json:"escalation_needed"`
	ActionDigest     string                                                             `json:"action_digest"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard is the
// operator command board derived from the portfolio automation summary.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard struct {
	BoardID           string                                                                   `json:"board_id"`
	SummaryID         string                                                                   `json:"summary_id"`
	Jurisdiction      string                                                                   `json:"jurisdiction,omitempty"`
	ServiceCode       string                                                                   `json:"service_code,omitempty"`
	ServiceTier       string                                                                   `json:"service_tier,omitempty"`
	EvaluatedAt       time.Time                                                                `json:"evaluated_at"`
	RecommendedLane   SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane       `json:"recommended_lane"`
	RecommendedAction string                                                                   `json:"recommended_action"`
	BlockedCount      int                                                                      `json:"blocked_count"`
	OverdueCount      int                                                                      `json:"overdue_count"`
	DueCount          int                                                                      `json:"due_count"`
	Items             []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem     `json:"items"`
	TopActions        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction `json:"top_actions,omitempty"`
	SummaryDigest     string                                                                   `json:"summary_digest"`
	BoardDigest       string                                                                   `json:"board_digest"`
	GeneratedAt       time.Time                                                                `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationBoard returns the
// operator board for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationBoard(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-board: service is required")
	}
	summary, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationSummary(ctx, filter)
	if err != nil {
		return nil, err
	}
	board := secureCellGovernmentAgentExecutionLaunchClosureAutomationBoard(*summary, time.Now().UTC())
	return &board, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBoard(
	summary SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem, 0, len(summary.Items))
	for _, item := range summary.Items {
		boardItem := SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem{
			CellID:           item.CellID,
			Name:             item.Name,
			Lane:             secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneFor(summary.EvaluatedAt, item),
			PendingAction:    item.PendingAction,
			AutomationAction: item.AutomationAction,
			ActionPriority:   item.ActionPriority,
			DueAt:            cloneTimePtr(item.DueAt),
			EscalationNeeded: item.EscalationRecommended,
			ActionDigest:     item.ActionDigest,
		}
		if item.DueAt != nil && summary.EvaluatedAt.After(item.DueAt.UTC()) {
			boardItem.OverdueSeconds = int64(summary.EvaluatedAt.Sub(item.DueAt.UTC()).Seconds())
		}
		items = append(items, boardItem)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Lane == items[j].Lane {
			if items[i].ActionPriority == items[j].ActionPriority {
				return items[i].CellID < items[j].CellID
			}
			return secureCellGovernmentAgentExecutionLaunchClosureActionPriorityRank(items[i].ActionPriority) < secureCellGovernmentAgentExecutionLaunchClosureActionPriorityRank(items[j].ActionPriority)
		}
		return secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneRank(items[i].Lane) < secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneRank(items[j].Lane)
	})
	board := SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard{
		SummaryID:     summary.SummaryID,
		Jurisdiction:  summary.Jurisdiction,
		ServiceCode:   summary.ServiceCode,
		ServiceTier:   summary.ServiceTier,
		EvaluatedAt:   summary.EvaluatedAt.UTC(),
		BlockedCount:  summary.BlockedCount,
		OverdueCount:  summary.OverdueCount,
		DueCount:      summary.DueCount,
		Items:         items,
		TopActions:    append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction(nil), summary.TopActions...),
		SummaryDigest: summary.SummaryDigest,
		GeneratedAt:   generatedAt.UTC(),
	}
	board.RecommendedLane, board.RecommendedAction = secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardRecommendation(board)
	board.BoardDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardDigest(board)
	board.BoardID = "government-agent-execution-launch-closure-automation-board:" + firstNonEmpty(board.Jurisdiction, "all") + ":" + board.BoardDigest[:12]
	return board
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneFor(
	evaluatedAt time.Time,
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane {
	if item.ActionKind == SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked
	}
	switch secureCellGovernmentAgentExecutionLaunchClosureAutomationStatusAt(item, evaluatedAt) {
	case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneDue
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneRank(lane SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane) int {
	switch lane {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneDue:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardRecommendation(
	board SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard,
) (SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane, string) {
	for _, item := range board.Items {
		if item.Lane == SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked {
			return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked, "clear_blocked_closure_path"
		}
	}
	for _, item := range board.Items {
		if item.Lane == SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue {
			return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue, "drain_overdue_closure_actions"
		}
	}
	if board.BlockedCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneBlocked, "clear_blocked_closure_path"
	}
	if board.OverdueCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneOverdue, "drain_overdue_closure_actions"
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLaneDue, "work_next_due_closure_actions"
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardDigest(board SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard) string {
	core := struct {
		SummaryID         string                                                                   `json:"summary_id"`
		EvaluatedAt       time.Time                                                                `json:"evaluated_at"`
		RecommendedLane   SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane       `json:"recommended_lane"`
		RecommendedAction string                                                                   `json:"recommended_action"`
		Items             []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem     `json:"items"`
		TopActions        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction `json:"top_actions,omitempty"`
		SummaryDigest     string                                                                   `json:"summary_digest"`
	}{
		SummaryID:         board.SummaryID,
		EvaluatedAt:       board.EvaluatedAt.UTC(),
		RecommendedLane:   board.RecommendedLane,
		RecommendedAction: board.RecommendedAction,
		Items:             board.Items,
		TopActions:        board.TopActions,
		SummaryDigest:     board.SummaryDigest,
	}
	return EvidenceHash(core)
}
