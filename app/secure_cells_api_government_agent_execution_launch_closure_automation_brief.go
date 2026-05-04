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

type secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefResponse struct {
	Brief *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief `json:"brief,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-brief" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		brief, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationBrief(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefResponse{Brief: brief})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-brief/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		brief, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationBrief(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefExport(w, r, brief); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefExport(w http.ResponseWriter, r *http.Request, brief *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefResponse{Brief: brief})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-brief.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefCSVRows(brief) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-brief csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationBriefCSVRows(brief *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBrief) [][]string {
	rows := [][]string{{
		"brief_id",
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
		"severity",
		"headline",
		"directive",
		"top_checkpoint",
		"unique_pending_actions",
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
		"runbook_digest",
		"brief_digest",
		"generated_at",
	}}
	if brief == nil {
		return rows
	}
	if len(brief.Items) == 0 && len(brief.Steps) == 0 {
		rows = append(rows, []string{
			brief.BriefID,
			brief.RunbookID,
			brief.PacketID,
			brief.BoardID,
			brief.SummaryID,
			brief.Jurisdiction,
			brief.ServiceCode,
			brief.ServiceTier,
			brief.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(brief.FocusLane),
			brief.FocusAction,
			string(brief.Severity),
			brief.Headline,
			brief.Directive,
			brief.TopCheckpoint,
			strings.Join(brief.UniquePendingAction, "|"),
			strconv.Itoa(brief.CellCount),
			strconv.Itoa(brief.ItemCount),
			"", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
			brief.RunbookDigest,
			brief.BriefDigest,
			brief.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	steps := brief.Steps
	if len(steps) == 0 {
		steps = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationRunbookStep{{}}
	}
	items := brief.Items
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
			brief.BriefID,
			brief.RunbookID,
			brief.PacketID,
			brief.BoardID,
			brief.SummaryID,
			brief.Jurisdiction,
			brief.ServiceCode,
			brief.ServiceTier,
			brief.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(brief.FocusLane),
			brief.FocusAction,
			string(brief.Severity),
			brief.Headline,
			brief.Directive,
			brief.TopCheckpoint,
			strings.Join(brief.UniquePendingAction, "|"),
			strconv.Itoa(brief.CellCount),
			strconv.Itoa(brief.ItemCount),
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
			brief.RunbookDigest,
			brief.BriefDigest,
			brief.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
