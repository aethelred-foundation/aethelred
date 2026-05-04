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

type launchClosureAutomationAck = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement
type launchClosureAutomationAckAssignment = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment
type launchClosureAutomationAckItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem

type secureCellLaunchClosureAutomationAckResponse struct {
	Acknowledgement *launchClosureAutomationAck `json:"acknowledgement,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		acknowledgement, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckResponse{Acknowledgement: acknowledgement})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		acknowledgement, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckExport(w, r, acknowledgement); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckExport(w http.ResponseWriter, r *http.Request, acknowledgement *launchClosureAutomationAck) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckResponse{Acknowledgement: acknowledgement})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckCSVRows(acknowledgement) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckCSVRows(acknowledgement *launchClosureAutomationAck) [][]string {
	rows := [][]string{{
		"acknowledgement_id",
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
		"ack_required",
		"ack_status",
		"ack_due_at",
		"ack_overdue_seconds",
		"ack_action",
		"lead_role",
		"required_roles",
		"required_pending_actions",
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
		"directive_digest",
		"acknowledgement_digest",
		"generated_at",
	}}
	if acknowledgement == nil {
		return rows
	}
	if len(acknowledgement.Items) == 0 && len(acknowledgement.Assignments) == 0 {
		rows = append(rows, secureCellLaunchClosureAutomationAckCSVRow(acknowledgement, launchClosureAutomationAckAssignment{}, launchClosureAutomationAckItem{}))
		return rows
	}
	assignments := acknowledgement.Assignments
	if len(assignments) == 0 {
		assignments = []launchClosureAutomationAckAssignment{{}}
	}
	items := acknowledgement.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckItem{{}}
	}
	maxLen := len(assignments)
	if len(items) > maxLen {
		maxLen = len(items)
	}
	for i := 0; i < maxLen; i++ {
		var assignment launchClosureAutomationAckAssignment
		var item launchClosureAutomationAckItem
		if i < len(assignments) {
			assignment = assignments[i]
		}
		if i < len(items) {
			item = items[i]
		}
		rows = append(rows, secureCellLaunchClosureAutomationAckCSVRow(acknowledgement, assignment, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckCSVRow(
	acknowledgement *launchClosureAutomationAck,
	assignment launchClosureAutomationAckAssignment,
	item launchClosureAutomationAckItem,
) []string {
	ackDueAt := ""
	if acknowledgement.AckDueAt != nil {
		ackDueAt = acknowledgement.AckDueAt.UTC().Format(time.RFC3339Nano)
	}
	itemDueAt := ""
	if item.DueAt != nil {
		itemDueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
	}
	assignmentSequence := ""
	if assignment.Sequence > 0 {
		assignmentSequence = strconv.Itoa(assignment.Sequence)
	}
	return []string{
		acknowledgement.AcknowledgementID,
		acknowledgement.DirectiveID,
		acknowledgement.DispatchID,
		acknowledgement.BriefID,
		acknowledgement.RunbookID,
		acknowledgement.PacketID,
		acknowledgement.BoardID,
		acknowledgement.SummaryID,
		acknowledgement.Jurisdiction,
		acknowledgement.ServiceCode,
		acknowledgement.ServiceTier,
		acknowledgement.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		string(acknowledgement.FocusLane),
		acknowledgement.FocusAction,
		string(acknowledgement.Severity),
		strconv.FormatBool(acknowledgement.AckRequired),
		string(acknowledgement.AckStatus),
		ackDueAt,
		strconv.FormatInt(acknowledgement.AckOverdueSeconds, 10),
		acknowledgement.AckAction,
		acknowledgement.LeadRole,
		strings.Join(acknowledgement.RequiredRoles, "|"),
		strings.Join(acknowledgement.RequiredPendingActions, "|"),
		strconv.FormatBool(acknowledgement.EscalationRequired),
		strconv.Itoa(acknowledgement.AssignmentCount),
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
		itemDueAt,
		strconv.FormatInt(item.OverdueSeconds, 10),
		strconv.FormatBool(item.EscalationNeeded),
		item.ActionDigest,
		acknowledgement.DirectiveDigest,
		acknowledgement.AcknowledgementDigest,
		acknowledgement.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
