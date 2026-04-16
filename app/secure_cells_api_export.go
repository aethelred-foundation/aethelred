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

func writeSecureCellOverdueDecisionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellOverdueDecision) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellOverdueDecisionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-overdue-decisions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"name",
			"jurisdiction",
			"cell_status",
			"session_id",
			"thread_id",
			"decision_id",
			"decision_title",
			"decision_status",
			"governance_template",
			"automation_action",
			"overdue_reason",
			"tier_id",
			"target_did",
			"due_at",
			"overdue_seconds",
			"escalation_due_at",
			"resolution_due_at",
			"updated_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.Name,
				item.Jurisdiction,
				string(item.CellStatus),
				item.SessionID,
				item.ThreadID,
				item.DecisionID,
				item.DecisionTitle,
				string(item.DecisionStatus),
				item.GovernanceTemplate,
				item.AutomationAction,
				item.OverdueReason,
				item.TierID,
				item.TargetDID,
				item.DueAt.UTC().Format(time.RFC3339Nano),
				strconv.FormatInt(item.OverdueSeconds, 10),
				formatSecureCellOptionalTime(item.EscalationDueAt),
				formatSecureCellOptionalTime(item.ResolutionDueAt),
				item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write overdue-decision csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func writeSecureCellDecisionAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellDecisionAutomationActionRecord) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellDecisionAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-decision-automation-actions.csv"`)
		writer := csv.NewWriter(w)
		rows := [][]string{{
			"cell_id",
			"name",
			"jurisdiction",
			"cell_status",
			"session_id",
			"thread_id",
			"decision_id",
			"decision_title",
			"decision_status_before",
			"decision_status_after",
			"action",
			"tier_id",
			"target_did",
			"trigger",
			"due_at",
			"actor",
			"automated_actor",
			"reason",
			"transition_id",
			"occurred_at",
		}}
		for _, item := range items {
			rows = append(rows, []string{
				item.CellID,
				item.Name,
				item.Jurisdiction,
				string(item.CellStatus),
				item.SessionID,
				item.ThreadID,
				item.DecisionID,
				item.DecisionTitle,
				string(item.DecisionStatusBefore),
				string(item.DecisionStatusAfter),
				item.Action,
				item.TierID,
				item.TargetDID,
				item.Trigger,
				formatSecureCellOptionalTime(item.DueAt),
				item.Actor,
				item.AutomatedActor,
				item.Reason,
				item.TransitionID,
				item.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write decision-automation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellExportFormat(r *http.Request) string {
	if r == nil {
		return "json"
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		return "json"
	}
	return format
}

func formatSecureCellOptionalTime(in *time.Time) string {
	if in == nil || in.IsZero() {
		return ""
	}
	return in.UTC().Format(time.RFC3339Nano)
}
