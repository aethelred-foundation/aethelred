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

type launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceipt = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt
type launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem

type secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptResponse struct {
	Receipt *launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceipt `json:"receipt,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		receipt, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptResponse{Receipt: receipt})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		receipt, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptExport(w, r, receipt); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptExport(w http.ResponseWriter, r *http.Request, receipt *launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceipt) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptResponse{Receipt: receipt})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptCSVRows(receipt) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptCSVRows(receipt *launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceipt) [][]string {
	rows := [][]string{{
		"acceptance_receipt_id",
		"acceptance_id",
		"dispatch_id",
		"queue_id",
		"manifest_id",
		"acknowledgement_receipt_id",
		"acknowledgement_id",
		"directive_id",
		"closure_dispatch_id",
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
		"dispatch_status",
		"acceptance_status",
		"receipt_status",
		"receipt_count",
		"awaiting_receipt_count",
		"overdue_receipt_count",
		"escalation_receipt_count",
		"primary_receipt_action",
		"receipt_item_id",
		"acceptance_item_id",
		"dispatch_item_id",
		"queue_item_id",
		"item_sequence",
		"item_evidence",
		"item_status",
		"item_priority",
		"item_accepting_role",
		"item_receipt_action",
		"item_receipt_evidence",
		"item_acceptance_channel",
		"item_escalation_target",
		"item_pending_actions",
		"item_cell_ids",
		"item_due_at",
		"item_overdue_seconds",
		"item_acceptance_digest",
		"item_receipt_digest",
		"acknowledgement_receipt_digest",
		"manifest_digest",
		"queue_digest",
		"dispatch_digest",
		"acceptance_digest",
		"acceptance_receipt_digest",
		"generated_at",
	}}
	if receipt == nil {
		return rows
	}
	items := receipt.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptItem{{}}
	}
	for _, item := range items {
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptCSVRow(receipt, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptCSVRow(
	receipt *launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceipt,
	item launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceReceiptItem,
) []string {
	itemSequence := ""
	if item.Sequence > 0 {
		itemSequence = strconv.Itoa(item.Sequence)
	}
	itemDueAt := ""
	if item.DueAt != nil {
		itemDueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
	}
	return []string{
		receipt.AcceptanceReceiptID,
		receipt.AcceptanceID,
		receipt.DispatchID,
		receipt.QueueID,
		receipt.ManifestID,
		receipt.AcknowledgementReceiptID,
		receipt.AcknowledgementID,
		receipt.DirectiveID,
		receipt.ClosureDispatchID,
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
		string(receipt.DispatchStatus),
		string(receipt.AcceptanceStatus),
		string(receipt.Status),
		strconv.Itoa(receipt.ReceiptCount),
		strconv.Itoa(receipt.AwaitingReceiptCount),
		strconv.Itoa(receipt.OverdueReceiptCount),
		strconv.Itoa(receipt.EscalationReceiptCount),
		receipt.PrimaryReceiptAction,
		item.AcceptanceReceiptItemID,
		item.AcceptanceItemID,
		item.DispatchItemID,
		item.QueueItemID,
		itemSequence,
		item.Evidence,
		string(item.Status),
		string(item.Priority),
		item.AcceptingRole,
		item.ReceiptAction,
		strings.Join(item.ReceiptEvidence, "|"),
		item.AcceptanceChannel,
		item.EscalationTarget,
		strings.Join(item.PendingActions, "|"),
		strings.Join(item.CellIDs, "|"),
		itemDueAt,
		strconv.FormatInt(item.OverdueSeconds, 10),
		item.AcceptanceItemDigest,
		item.ReceiptItemDigest,
		receipt.AcknowledgementReceiptDigest,
		receipt.ManifestDigest,
		receipt.QueueDigest,
		receipt.DispatchDigest,
		receipt.AcceptanceDigest,
		receipt.AcceptanceReceiptDigest,
		receipt.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
