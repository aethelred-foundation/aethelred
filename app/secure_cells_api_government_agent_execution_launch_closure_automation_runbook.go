package app

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

type secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookResponse struct {
	Runbook *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook `json:"runbook,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-runbook" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		runbook, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationRunbook(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookResponse{Runbook: runbook})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-runbook/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		runbook, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationRunbook(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookExport(w, r, runbook); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookExport(w http.ResponseWriter, r *http.Request, runbook *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookResponse{Runbook: runbook})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-runbook.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookCSVRows(runbook) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-runbook csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookCSVRows(runbook *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbook) [][]string {
	rows := [][]string{{
		"runbook_id",
		"packet_id",
		"board_id",
		"summary_id",
		"jurisdiction",
		"service_code_filter",
		"service_tier_filter",
		"evaluated_at",
		"focus_lane",
		"focus_action",
		"headline",
		"cell_count",
		"item_count",
		"step_sequence",
		"step_title",
		"step_instruction",
		"step_pending_action",
		"step_cell_ids",
		"item_cell_id",
		"item_name",
		"item_lane",
		"item_pending_action",
		"item_automation_action",
		"item_action_priority",
		"item_due_at",
		"item_overdue_seconds",
		"item_escalation_needed",
		"item_action_digest",
		"packet_digest",
		"runbook_digest",
		"generated_at",
	}}
	if runbook == nil {
		return rows
	}
	if len(runbook.Items) == 0 && len(runbook.Steps) == 0 {
		rows = append(rows, []string{
			runbook.RunbookID,
			runbook.PacketID,
			runbook.BoardID,
			runbook.SummaryID,
			runbook.Jurisdiction,
			runbook.ServiceCode,
			runbook.ServiceTier,
			runbook.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(runbook.FocusLane),
			runbook.FocusAction,
			runbook.Headline,
			strconv.Itoa(runbook.CellCount),
			strconv.Itoa(runbook.ItemCount),
			"", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
			runbook.PacketDigest,
			runbook.RunbookDigest,
			runbook.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	steps := runbook.Steps
	if len(steps) == 0 {
		steps = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep{{}}
	}
	items := runbook.Items
	if len(items) == 0 {
		items = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem{{}}
	}
	maxLen := len(steps)
	if len(items) > maxLen {
		maxLen = len(items)
	}
	for i := 0; i < maxLen; i++ {
		var step securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep
		var item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem
		if i < len(steps) {
			step = steps[i]
		}
		if i < len(items) {
			item = items[i]
		}
		dueAt := ""
		if item.DueAt != nil {
			dueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
		}
		stepSequence := ""
		if step.Sequence > 0 {
			stepSequence = strconv.Itoa(step.Sequence)
		}
		rows = append(rows, []string{
			runbook.RunbookID,
			runbook.PacketID,
			runbook.BoardID,
			runbook.SummaryID,
			runbook.Jurisdiction,
			runbook.ServiceCode,
			runbook.ServiceTier,
			runbook.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(runbook.FocusLane),
			runbook.FocusAction,
			runbook.Headline,
			strconv.Itoa(runbook.CellCount),
			strconv.Itoa(runbook.ItemCount),
			stepSequence,
			step.Title,
			step.Instruction,
			step.PendingAction,
			strings.Join(step.CellIDs, "|"),
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
			runbook.PacketDigest,
			runbook.RunbookDigest,
			runbook.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
