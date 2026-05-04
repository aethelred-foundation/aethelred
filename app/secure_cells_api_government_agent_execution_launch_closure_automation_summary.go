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

type secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryResponse struct {
	Summary *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary `json:"summary,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-summary" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		summary, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationSummary(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryResponse{Summary: summary})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-summary/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		summary, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationSummary(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryExport(w, r, summary); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryExport(w http.ResponseWriter, r *http.Request, summary *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryResponse{Summary: summary})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-summary.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryCSVRows(summary) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-summary csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryCSVRows(summary *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary) [][]string {
	rows := [][]string{{
		"summary_id",
		"jurisdiction",
		"service_code_filter",
		"service_tier_filter",
		"evaluated_at",
		"action_count",
		"blocked_count",
		"due_count",
		"overdue_count",
		"escalation_recommended_count",
		"next_due_at",
		"max_overdue_seconds",
		"top_actions",
		"cell_id",
		"name",
		"pending_action",
		"automation_action",
		"action_priority",
		"due_at",
		"action_digest",
		"summary_digest",
		"generated_at",
	}}
	if summary == nil {
		return rows
	}
	nextDueAt := ""
	if summary.NextDueAt != nil {
		nextDueAt = summary.NextDueAt.UTC().Format(time.RFC3339Nano)
	}
	topActions := secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryTopActionsCSV(summary.TopActions)
	if len(summary.Items) == 0 {
		rows = append(rows, []string{
			summary.SummaryID,
			summary.Jurisdiction,
			summary.ServiceCode,
			summary.ServiceTier,
			summary.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			strconv.Itoa(summary.ActionCount),
			strconv.Itoa(summary.BlockedCount),
			strconv.Itoa(summary.DueCount),
			strconv.Itoa(summary.OverdueCount),
			strconv.Itoa(summary.EscalationRecommendedCount),
			nextDueAt,
			strconv.FormatInt(summary.MaxOverdueSeconds, 10),
			topActions,
			"", "", "", "", "", "", "",
			summary.SummaryDigest,
			summary.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	for _, item := range summary.Items {
		dueAt := ""
		if item.DueAt != nil {
			dueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			summary.SummaryID,
			summary.Jurisdiction,
			summary.ServiceCode,
			summary.ServiceTier,
			summary.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			strconv.Itoa(summary.ActionCount),
			strconv.Itoa(summary.BlockedCount),
			strconv.Itoa(summary.DueCount),
			strconv.Itoa(summary.OverdueCount),
			strconv.Itoa(summary.EscalationRecommendedCount),
			nextDueAt,
			strconv.FormatInt(summary.MaxOverdueSeconds, 10),
			topActions,
			item.CellID,
			item.Name,
			item.PendingAction,
			item.AutomationAction,
			string(item.ActionPriority),
			dueAt,
			item.ActionDigest,
			summary.SummaryDigest,
			summary.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryTopActionsCSV(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction) string {
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, item.PendingAction+":"+item.AutomationAction+":"+strconv.Itoa(item.Count))
	}
	return strings.Join(parts, "|")
}
