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

type secureCellGovernmentAgentExecutionLaunchClosureAutomationActionResponse struct {
	Item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction `json:"item,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationActionGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-actions" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureAutomationActions(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationActionListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-actions/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureAutomationActions(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationActionExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-automation-action") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-automation-action")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		item, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAction(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationActionResponse{Item: item})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-actions.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationActionCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationActionCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction) [][]string {
	rows := [][]string{{
		"record_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"queue_id",
		"dashboard_id",
		"center_id",
		"board_id",
		"registry_id",
		"certificate_id",
		"queue_status",
		"dashboard_status",
		"pending_action",
		"automation_action",
		"action_kind",
		"action_priority",
		"reason",
		"due_at",
		"overdue_seconds",
		"escalation_recommended",
		"required_receipt_types",
		"operator_instructions",
		"action_id",
		"action_digest",
		"queue_digest",
		"dashboard_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		dueAt := ""
		if item.DueAt != nil {
			dueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			item.RecordID,
			item.CellID,
			item.Name,
			item.Jurisdiction,
			item.ServiceCode,
			item.ServiceTier,
			item.QueueID,
			item.DashboardID,
			item.CenterID,
			item.BoardID,
			item.RegistryID,
			item.CertificateID,
			string(item.QueueStatus),
			string(item.DashboardStatus),
			item.PendingAction,
			item.AutomationAction,
			string(item.ActionKind),
			string(item.ActionPriority),
			item.Reason,
			dueAt,
			strconv.FormatInt(item.OverdueSeconds, 10),
			strconv.FormatBool(item.EscalationRecommended),
			strings.Join(item.RequiredReceiptTypes, "|"),
			strings.Join(item.OperatorInstructions, "|"),
			item.ActionID,
			item.ActionDigest,
			item.QueueDigest,
			item.DashboardDigest,
			item.GeneratedAt.UTC().Format(time.RFC3339Nano),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
