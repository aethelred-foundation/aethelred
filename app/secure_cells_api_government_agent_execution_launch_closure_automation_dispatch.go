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

type secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchResponse struct {
	Dispatch *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch `json:"dispatch,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-dispatch" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		dispatch, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationDispatch(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchResponse{Dispatch: dispatch})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-dispatch/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		dispatch, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationDispatch(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchExport(w, r, dispatch); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchExport(w http.ResponseWriter, r *http.Request, dispatch *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchResponse{Dispatch: dispatch})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-dispatch.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchCSVRows(dispatch) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-dispatch csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchCSVRows(dispatch *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatch) [][]string {
	rows := [][]string{{
		"dispatch_id",
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
		"command",
		"lead_role",
		"lead_pending_action",
		"escalation_required",
		"assignment_count",
		"assignment_sequence",
		"assignment_role",
		"assignment_pending_action",
		"assignment_automation_action",
		"assignment_instruction",
		"assignment_cell_ids",
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
		"brief_digest",
		"dispatch_digest",
		"generated_at",
	}}
	if dispatch == nil {
		return rows
	}
	if len(dispatch.Items) == 0 && len(dispatch.Assignments) == 0 {
		rows = append(rows, []string{
			dispatch.DispatchID,
			dispatch.BriefID,
			dispatch.RunbookID,
			dispatch.PacketID,
			dispatch.BoardID,
			dispatch.SummaryID,
			dispatch.Jurisdiction,
			dispatch.ServiceCode,
			dispatch.ServiceTier,
			dispatch.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(dispatch.FocusLane),
			dispatch.FocusAction,
			string(dispatch.Severity),
			dispatch.Command,
			dispatch.LeadRole,
			dispatch.LeadPendingAction,
			strconv.FormatBool(dispatch.EscalationRequired),
			strconv.Itoa(dispatch.AssignmentCount),
			"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
			dispatch.BriefDigest,
			dispatch.DispatchDigest,
			dispatch.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	assignments := dispatch.Assignments
	if len(assignments) == 0 {
		assignments = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment{{}}
	}
	items := dispatch.Items
	if len(items) == 0 {
		items = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem{{}}
	}
	maxLen := len(assignments)
	if len(items) > maxLen {
		maxLen = len(items)
	}
	for i := 0; i < maxLen; i++ {
		var assignment securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment
		var item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem
		if i < len(assignments) {
			assignment = assignments[i]
		}
		if i < len(items) {
			item = items[i]
		}
		dueAt := ""
		if item.DueAt != nil {
			dueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
		}
		assignmentSequence := ""
		if assignment.Sequence > 0 {
			assignmentSequence = strconv.Itoa(assignment.Sequence)
		}
		rows = append(rows, []string{
			dispatch.DispatchID,
			dispatch.BriefID,
			dispatch.RunbookID,
			dispatch.PacketID,
			dispatch.BoardID,
			dispatch.SummaryID,
			dispatch.Jurisdiction,
			dispatch.ServiceCode,
			dispatch.ServiceTier,
			dispatch.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(dispatch.FocusLane),
			dispatch.FocusAction,
			string(dispatch.Severity),
			dispatch.Command,
			dispatch.LeadRole,
			dispatch.LeadPendingAction,
			strconv.FormatBool(dispatch.EscalationRequired),
			strconv.Itoa(dispatch.AssignmentCount),
			assignmentSequence,
			assignment.Role,
			assignment.PendingAction,
			assignment.AutomationAction,
			assignment.Instruction,
			strings.Join(assignment.CellIDs, "|"),
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
			dispatch.BriefDigest,
			dispatch.DispatchDigest,
			dispatch.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
