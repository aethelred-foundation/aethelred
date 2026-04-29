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

type secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveResponse struct {
	Directive *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective `json:"directive,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-directive" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		directive, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationDirective(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveResponse{Directive: directive})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-directive/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		directive, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationDirective(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveExport(w, r, directive); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveExport(w http.ResponseWriter, r *http.Request, directive *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveResponse{Directive: directive})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-directive.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveCSVRows(directive) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-directive csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationDirectiveCSVRows(directive *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDirective) [][]string {
	rows := [][]string{{
		"directive_id",
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
		"directive",
		"lead_role",
		"lead_pending_action",
		"ack_required",
		"execution_window",
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
		"dispatch_digest",
		"directive_digest",
		"generated_at",
	}}
	if directive == nil {
		return rows
	}
	if len(directive.Items) == 0 && len(directive.Assignments) == 0 {
		rows = append(rows, []string{
			directive.DirectiveID,
			directive.DispatchID,
			directive.BriefID,
			directive.RunbookID,
			directive.PacketID,
			directive.BoardID,
			directive.SummaryID,
			directive.Jurisdiction,
			directive.ServiceCode,
			directive.ServiceTier,
			directive.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(directive.FocusLane),
			directive.FocusAction,
			string(directive.Severity),
			directive.Directive,
			directive.LeadRole,
			directive.LeadPendingAction,
			strconv.FormatBool(directive.AckRequired),
			directive.ExecutionWindow,
			strconv.FormatBool(directive.EscalationRequired),
			strconv.Itoa(directive.AssignmentCount),
			"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
			directive.DispatchDigest,
			directive.DirectiveDigest,
			directive.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	assignments := directive.Assignments
	if len(assignments) == 0 {
		assignments = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment{{}}
	}
	items := directive.Items
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
			directive.DirectiveID,
			directive.DispatchID,
			directive.BriefID,
			directive.RunbookID,
			directive.PacketID,
			directive.BoardID,
			directive.SummaryID,
			directive.Jurisdiction,
			directive.ServiceCode,
			directive.ServiceTier,
			directive.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(directive.FocusLane),
			directive.FocusAction,
			string(directive.Severity),
			directive.Directive,
			directive.LeadRole,
			directive.LeadPendingAction,
			strconv.FormatBool(directive.AckRequired),
			directive.ExecutionWindow,
			strconv.FormatBool(directive.EscalationRequired),
			strconv.Itoa(directive.AssignmentCount),
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
			directive.DispatchDigest,
			directive.DirectiveDigest,
			directive.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
