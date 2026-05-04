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

type secureCellGovernmentAgentExecutionLaunchClosureActionQueueResponse struct {
	Queue *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureActionQueue `json:"queue,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureActionQueueListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureActionQueue `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureActionQueueGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-action-queues" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureActionQueues(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureActionQueueListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-action-queues/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureActionQueues(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureActionQueueExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-action-queue") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-action-queue")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		queue, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureActionQueue(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureActionQueueResponse{Queue: queue})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureActionQueueExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureActionQueue) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureActionQueueListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-action-queues.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureActionQueueCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-action-queue csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureActionQueueCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureActionQueue) [][]string {
	rows := [][]string{{
		"queue_id",
		"cell_id",
		"dashboard_id",
		"center_id",
		"board_id",
		"registry_id",
		"certificate_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"dashboard_status",
		"action_count",
		"blocked_action_count",
		"overdue_action_count",
		"due_action_count",
		"escalation_recommended_count",
		"required_receipt_types",
		"primary_action",
		"action_id",
		"action_kind",
		"action_status",
		"action_priority",
		"action",
		"reason",
		"due_at",
		"overdue_seconds",
		"escalation_recommended",
		"action_required_receipt_types",
		"operator_instructions",
		"action_digest",
		"dashboard_digest",
		"queue_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Actions) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosureActionQueueCSVRow(item, nil))
			continue
		}
		for idx := range item.Actions {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosureActionQueueCSVRow(item, &item.Actions[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchClosureActionQueueCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureActionQueue,
	action *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAction,
) []string {
	actionID := ""
	actionKind := ""
	actionStatus := ""
	actionPriority := ""
	actionText := ""
	reason := ""
	dueAt := ""
	overdueSeconds := ""
	escalationRecommended := ""
	actionReceiptTypes := ""
	operatorInstructions := ""
	actionDigest := ""
	if action != nil {
		actionID = action.ActionID
		actionKind = string(action.Kind)
		actionStatus = string(action.Status)
		actionPriority = string(action.Priority)
		actionText = action.Action
		reason = action.Reason
		if action.DueAt != nil {
			dueAt = action.DueAt.UTC().Format(time.RFC3339Nano)
		}
		overdueSeconds = strconv.FormatInt(action.OverdueSeconds, 10)
		escalationRecommended = strconv.FormatBool(action.EscalationRecommended)
		actionReceiptTypes = strings.Join(action.RequiredReceiptTypes, "|")
		operatorInstructions = strings.Join(action.OperatorInstructions, "|")
		actionDigest = action.ActionDigest
	}
	return []string{
		item.QueueID,
		item.CellID,
		item.DashboardID,
		item.CenterID,
		item.BoardID,
		item.RegistryID,
		item.CertificateID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.DashboardStatus),
		strconv.Itoa(item.ActionCount),
		strconv.Itoa(item.BlockedActionCount),
		strconv.Itoa(item.OverdueActionCount),
		strconv.Itoa(item.DueActionCount),
		strconv.Itoa(item.EscalationRecommendedCount),
		strings.Join(item.RequiredReceiptTypes, "|"),
		item.PrimaryAction,
		actionID,
		actionKind,
		actionStatus,
		actionPriority,
		actionText,
		reason,
		dueAt,
		overdueSeconds,
		escalationRecommended,
		actionReceiptTypes,
		operatorInstructions,
		actionDigest,
		item.DashboardDigest,
		item.QueueDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
