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

type secureCellGovernmentAgentExecutionLaunchClosureOverdueActionResponse struct {
	Item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction `json:"item,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureOverdueActionListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-overdue-actions" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureOverdueActions(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureOverdueActionListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-overdue-actions/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureOverdueActions(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-overdue-action") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-overdue-action")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		filter.CellID = cellID
		filter.Limit = 1
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureOverdueActions(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		if len(items) == 0 {
			writeSecureCellAPIError(w, http.StatusNotFound, fmt.Sprintf("securecells/government-agent-execution-launch-closure-overdue-action: %v: %q", securecellsintegration.ErrCellNotFound, cellID))
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureOverdueActionResponse{Item: &items[0]})
		return true
	}

	return false
}

func parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r *http.Request) (securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter, error) {
	filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
	if err != nil {
		return securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{}, err
	}
	before, err := parseSecureCellOptionalTime(r.URL.Query().Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{}, err
	}
	return securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter{
		CellID:       filter.CellID,
		Jurisdiction: filter.Jurisdiction,
		ServiceCode:  filter.ServiceCode,
		ServiceTier:  filter.ServiceTier,
		Before:       before,
		Limit:        filter.Limit,
	}, nil
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureOverdueActionListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-overdue-actions.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureOverdueActionCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-overdue-action csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureOverdueActionCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureOverdueAction) [][]string {
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
			string(item.DashboardStatus),
			item.PendingAction,
			item.AutomationAction,
			string(item.ActionKind),
			string(item.ActionPriority),
			item.Reason,
			item.DueAt.UTC().Format(time.RFC3339Nano),
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
