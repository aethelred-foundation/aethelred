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

type launchClosureAutomationAckReceiptEvidenceDispatch = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch
type launchClosureAutomationAckReceiptEvidenceDispatchItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem

type secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchResponse struct {
	Dispatch *launchClosureAutomationAckReceiptEvidenceDispatch `json:"dispatch,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		dispatch, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchResponse{Dispatch: dispatch})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		dispatch, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchExport(w, r, dispatch); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchExport(w http.ResponseWriter, r *http.Request, dispatch *launchClosureAutomationAckReceiptEvidenceDispatch) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchResponse{Dispatch: dispatch})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchCSVRows(dispatch) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchCSVRows(dispatch *launchClosureAutomationAckReceiptEvidenceDispatch) [][]string {
	rows := [][]string{{
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
		"receipt_status",
		"receipt_action",
		"dispatch_status",
		"dispatch_count",
		"ready_dispatch_count",
		"overdue_dispatch_count",
		"escalation_dispatch_count",
		"primary_operator_command",
		"dispatch_item_id",
		"queue_item_id",
		"item_sequence",
		"item_evidence",
		"item_status",
		"item_priority",
		"item_responsible_role",
		"item_dispatch_channel",
		"item_operator_command",
		"item_escalation_target",
		"item_pending_actions",
		"item_cell_ids",
		"item_due_at",
		"item_overdue_seconds",
		"item_evidence_binding_id",
		"item_queue_digest",
		"item_dispatch_digest",
		"receipt_digest",
		"manifest_digest",
		"queue_digest",
		"dispatch_digest",
		"generated_at",
	}}
	if dispatch == nil {
		return rows
	}
	items := dispatch.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckReceiptEvidenceDispatchItem{{}}
	}
	for _, item := range items {
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchCSVRow(dispatch, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchCSVRow(
	dispatch *launchClosureAutomationAckReceiptEvidenceDispatch,
	item launchClosureAutomationAckReceiptEvidenceDispatchItem,
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
		dispatch.DispatchID,
		dispatch.QueueID,
		dispatch.ManifestID,
		dispatch.AcknowledgementReceiptID,
		dispatch.AcknowledgementID,
		dispatch.DirectiveID,
		dispatch.ClosureDispatchID,
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
		string(dispatch.ReceiptStatus),
		dispatch.ReceiptAction,
		string(dispatch.Status),
		strconv.Itoa(dispatch.DispatchCount),
		strconv.Itoa(dispatch.ReadyDispatchCount),
		strconv.Itoa(dispatch.OverdueDispatchCount),
		strconv.Itoa(dispatch.EscalationDispatchCount),
		dispatch.PrimaryOperatorCommand,
		item.DispatchItemID,
		item.QueueItemID,
		itemSequence,
		item.Evidence,
		string(item.Status),
		string(item.Priority),
		item.ResponsibleRole,
		item.DispatchChannel,
		item.OperatorCommand,
		item.EscalationTarget,
		strings.Join(item.PendingActions, "|"),
		strings.Join(item.CellIDs, "|"),
		itemDueAt,
		strconv.FormatInt(item.OverdueSeconds, 10),
		item.EvidenceBindingID,
		item.QueueItemDigest,
		item.DispatchItemDigest,
		dispatch.ReceiptDigest,
		dispatch.ManifestDigest,
		dispatch.QueueDigest,
		dispatch.DispatchDigest,
		dispatch.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
