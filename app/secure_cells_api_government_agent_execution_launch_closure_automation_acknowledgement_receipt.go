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

type launchClosureAutomationAckReceipt = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt
type launchClosureAutomationAckReceiptAssignment = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment
type launchClosureAutomationAckReceiptItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem

type secureCellLaunchClosureAutomationAckReceiptResponse struct {
	Receipt *launchClosureAutomationAckReceipt `json:"receipt,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckReceiptGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		receipt, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptResponse{Receipt: receipt})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		receipt, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckReceiptExport(w, r, receipt); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckReceiptExport(w http.ResponseWriter, r *http.Request, receipt *launchClosureAutomationAckReceipt) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptResponse{Receipt: receipt})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement-receipt.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckReceiptCSVRows(receipt) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement-receipt csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckReceiptCSVRows(receipt *launchClosureAutomationAckReceipt) [][]string {
	rows := [][]string{{
		"acknowledgement_receipt_id",
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
		"ack_status",
		"ack_action",
		"receipt_status",
		"receipt_action",
		"receipt_due_at",
		"receipt_overdue_seconds",
		"receipt_evidence",
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
		"acknowledgement_digest",
		"receipt_digest",
		"generated_at",
	}}
	if receipt == nil {
		return rows
	}
	if len(receipt.Items) == 0 && len(receipt.Assignments) == 0 {
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptCSVRow(receipt, launchClosureAutomationAckReceiptAssignment{}, launchClosureAutomationAckReceiptItem{}))
		return rows
	}
	assignments := receipt.Assignments
	if len(assignments) == 0 {
		assignments = []launchClosureAutomationAckReceiptAssignment{{}}
	}
	items := receipt.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckReceiptItem{{}}
	}
	maxLen := len(assignments)
	if len(items) > maxLen {
		maxLen = len(items)
	}
	for i := 0; i < maxLen; i++ {
		var assignment launchClosureAutomationAckReceiptAssignment
		var item launchClosureAutomationAckReceiptItem
		if i < len(assignments) {
			assignment = assignments[i]
		}
		if i < len(items) {
			item = items[i]
		}
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptCSVRow(receipt, assignment, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckReceiptCSVRow(
	receipt *launchClosureAutomationAckReceipt,
	assignment launchClosureAutomationAckReceiptAssignment,
	item launchClosureAutomationAckReceiptItem,
) []string {
	receiptDueAt := ""
	if receipt.ReceiptDueAt != nil {
		receiptDueAt = receipt.ReceiptDueAt.UTC().Format(time.RFC3339Nano)
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
		receipt.AcknowledgementReceiptID,
		receipt.AcknowledgementID,
		receipt.DirectiveID,
		receipt.DispatchID,
		receipt.BriefID,
		receipt.RunbookID,
		receipt.PacketID,
		receipt.BoardID,
		receipt.SummaryID,
		receipt.Jurisdiction,
		receipt.ServiceCode,
		receipt.ServiceTier,
		receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		string(receipt.FocusLane),
		receipt.FocusAction,
		string(receipt.Severity),
		string(receipt.AckStatus),
		receipt.AckAction,
		string(receipt.ReceiptStatus),
		receipt.ReceiptAction,
		receiptDueAt,
		strconv.FormatInt(receipt.ReceiptOverdueSeconds, 10),
		strings.Join(receipt.ReceiptEvidence, "|"),
		receipt.LeadRole,
		strings.Join(receipt.RequiredRoles, "|"),
		strings.Join(receipt.RequiredPendingActions, "|"),
		strconv.FormatBool(receipt.EscalationRequired),
		strconv.Itoa(receipt.AssignmentCount),
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
		receipt.AcknowledgementDigest,
		receipt.ReceiptDigest,
		receipt.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
