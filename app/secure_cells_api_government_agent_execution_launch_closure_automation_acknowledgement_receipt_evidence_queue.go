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

type launchClosureAutomationAckReceiptEvidenceQueue = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue
type launchClosureAutomationAckReceiptEvidenceQueueItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem

type secureCellLaunchClosureAutomationAckReceiptEvidenceQueueResponse struct {
	Queue *launchClosureAutomationAckReceiptEvidenceQueue `json:"queue,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckReceiptEvidenceQueueGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-queue" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		queue, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceQueueResponse{Queue: queue})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-queue/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		queue, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckReceiptEvidenceQueueExport(w, r, queue); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckReceiptEvidenceQueueExport(w http.ResponseWriter, r *http.Request, queue *launchClosureAutomationAckReceiptEvidenceQueue) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceQueueResponse{Queue: queue})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-queue.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckReceiptEvidenceQueueCSVRows(queue) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-queue csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceQueueCSVRows(queue *launchClosureAutomationAckReceiptEvidenceQueue) [][]string {
	rows := [][]string{{
		"queue_id",
		"manifest_id",
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
		"receipt_status",
		"receipt_action",
		"queue_status",
		"item_count",
		"due_count",
		"overdue_count",
		"escalation_count",
		"queue_item_id",
		"item_sequence",
		"item_evidence",
		"item_status",
		"item_priority",
		"item_action",
		"item_responsible_role",
		"item_pending_actions",
		"item_cell_ids",
		"item_due_at",
		"item_overdue_seconds",
		"item_digest",
		"receipt_digest",
		"manifest_digest",
		"queue_digest",
		"generated_at",
	}}
	if queue == nil {
		return rows
	}
	items := queue.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckReceiptEvidenceQueueItem{{}}
	}
	for _, item := range items {
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptEvidenceQueueCSVRow(queue, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceQueueCSVRow(
	queue *launchClosureAutomationAckReceiptEvidenceQueue,
	item launchClosureAutomationAckReceiptEvidenceQueueItem,
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
		queue.QueueID,
		queue.ManifestID,
		queue.AcknowledgementReceiptID,
		queue.AcknowledgementID,
		queue.DirectiveID,
		queue.DispatchID,
		queue.BriefID,
		queue.RunbookID,
		queue.PacketID,
		queue.BoardID,
		queue.SummaryID,
		queue.Jurisdiction,
		queue.ServiceCode,
		queue.ServiceTier,
		queue.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		string(queue.FocusLane),
		queue.FocusAction,
		string(queue.Severity),
		string(queue.ReceiptStatus),
		queue.ReceiptAction,
		string(queue.Status),
		strconv.Itoa(queue.ItemCount),
		strconv.Itoa(queue.DueCount),
		strconv.Itoa(queue.OverdueCount),
		strconv.Itoa(queue.EscalationCount),
		item.QueueItemID,
		itemSequence,
		item.Evidence,
		string(item.Status),
		string(item.Priority),
		item.Action,
		item.ResponsibleRole,
		strings.Join(item.PendingActions, "|"),
		strings.Join(item.CellIDs, "|"),
		itemDueAt,
		strconv.FormatInt(item.OverdueSeconds, 10),
		item.ItemDigest,
		queue.ReceiptDigest,
		queue.ManifestDigest,
		queue.QueueDigest,
		queue.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
