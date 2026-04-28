package app

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

type secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardResponse struct {
	Board *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard `json:"board,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-board" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		board, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationBoard(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardResponse{Board: board})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-board/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		board, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationBoard(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardExport(w, r, board); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardExport(w http.ResponseWriter, r *http.Request, board *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardResponse{Board: board})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-board.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardCSVRows(board) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-board csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBoardCSVRows(board *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoard) [][]string {
	rows := [][]string{{
		"board_id",
		"summary_id",
		"jurisdiction",
		"service_code_filter",
		"service_tier_filter",
		"evaluated_at",
		"recommended_lane",
		"recommended_action",
		"blocked_count",
		"overdue_count",
		"due_count",
		"cell_id",
		"name",
		"lane",
		"pending_action",
		"automation_action",
		"action_priority",
		"due_at",
		"overdue_seconds",
		"escalation_needed",
		"action_digest",
		"board_digest",
		"summary_digest",
		"generated_at",
	}}
	if board == nil {
		return rows
	}
	if len(board.Items) == 0 {
		rows = append(rows, []string{
			board.BoardID,
			board.SummaryID,
			board.Jurisdiction,
			board.ServiceCode,
			board.ServiceTier,
			board.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(board.RecommendedLane),
			board.RecommendedAction,
			strconv.Itoa(board.BlockedCount),
			strconv.Itoa(board.OverdueCount),
			strconv.Itoa(board.DueCount),
			"", "", "", "", "", "", "", "", "", "",
			board.BoardDigest,
			board.SummaryDigest,
			board.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	for _, item := range board.Items {
		dueAt := ""
		if item.DueAt != nil {
			dueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			board.BoardID,
			board.SummaryID,
			board.Jurisdiction,
			board.ServiceCode,
			board.ServiceTier,
			board.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(board.RecommendedLane),
			board.RecommendedAction,
			strconv.Itoa(board.BlockedCount),
			strconv.Itoa(board.OverdueCount),
			strconv.Itoa(board.DueCount),
			item.CellID,
			item.Name,
			string(item.Lane),
			item.PendingAction,
			item.AutomationAction,
			string(item.ActionPriority),
			dueAt,
			strconv.FormatInt(item.OverdueSeconds, 10),
			strconv.FormatBool(item.EscalationNeeded),
			item.ActionDigest,
			board.BoardDigest,
			board.SummaryDigest,
			board.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
