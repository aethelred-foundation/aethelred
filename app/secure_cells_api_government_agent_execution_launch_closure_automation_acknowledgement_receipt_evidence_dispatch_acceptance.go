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

type launchClosureAutomationAckReceiptEvidenceDispatchAcceptance = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance
type launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem

type secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceResponse struct {
	Acceptance *launchClosureAutomationAckReceiptEvidenceDispatchAcceptance `json:"acceptance,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		acceptance, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceResponse{Acceptance: acceptance})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		acceptance, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceExport(w, r, acceptance); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceExport(w http.ResponseWriter, r *http.Request, acceptance *launchClosureAutomationAckReceiptEvidenceDispatchAcceptance) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceResponse{Acceptance: acceptance})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceCSVRows(acceptance) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceCSVRows(acceptance *launchClosureAutomationAckReceiptEvidenceDispatchAcceptance) [][]string {
	rows := [][]string{{
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
		"receipt_status",
		"dispatch_status",
		"acceptance_status",
		"acceptance_count",
		"required_acceptance_count",
		"overdue_acceptance_count",
		"escalation_acceptance_count",
		"primary_acceptance_action",
		"acceptance_item_id",
		"dispatch_item_id",
		"queue_item_id",
		"item_sequence",
		"item_evidence",
		"item_status",
		"item_priority",
		"item_accepting_role",
		"item_acceptance_action",
		"item_acceptance_channel",
		"item_acceptance_evidence",
		"item_escalation_target",
		"item_pending_actions",
		"item_cell_ids",
		"item_due_at",
		"item_overdue_seconds",
		"item_dispatch_digest",
		"item_acceptance_digest",
		"receipt_digest",
		"manifest_digest",
		"queue_digest",
		"dispatch_digest",
		"acceptance_digest",
		"generated_at",
	}}
	if acceptance == nil {
		return rows
	}
	items := acceptance.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceItem{{}}
	}
	for _, item := range items {
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceCSVRow(acceptance, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckReceiptEvidenceDispatchAcceptanceCSVRow(
	acceptance *launchClosureAutomationAckReceiptEvidenceDispatchAcceptance,
	item launchClosureAutomationAckReceiptEvidenceDispatchAcceptanceItem,
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
		acceptance.AcceptanceID,
		acceptance.DispatchID,
		acceptance.QueueID,
		acceptance.ManifestID,
		acceptance.AcknowledgementReceiptID,
		acceptance.AcknowledgementID,
		acceptance.DirectiveID,
		acceptance.ClosureDispatchID,
		acceptance.BriefID,
		acceptance.RunbookID,
		acceptance.PacketID,
		acceptance.BoardID,
		acceptance.SummaryID,
		acceptance.Jurisdiction,
		acceptance.ServiceCode,
		acceptance.ServiceTier,
		acceptance.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		string(acceptance.FocusLane),
		acceptance.FocusAction,
		string(acceptance.Severity),
		string(acceptance.ReceiptStatus),
		string(acceptance.DispatchStatus),
		string(acceptance.Status),
		strconv.Itoa(acceptance.AcceptanceCount),
		strconv.Itoa(acceptance.RequiredAcceptanceCount),
		strconv.Itoa(acceptance.OverdueAcceptanceCount),
		strconv.Itoa(acceptance.EscalationAcceptanceCount),
		acceptance.PrimaryAcceptanceAction,
		item.AcceptanceItemID,
		item.DispatchItemID,
		item.QueueItemID,
		itemSequence,
		item.Evidence,
		string(item.Status),
		string(item.Priority),
		item.AcceptingRole,
		item.AcceptanceAction,
		item.AcceptanceChannel,
		strings.Join(item.AcceptanceEvidence, "|"),
		item.EscalationTarget,
		strings.Join(item.PendingActions, "|"),
		strings.Join(item.CellIDs, "|"),
		itemDueAt,
		strconv.FormatInt(item.OverdueSeconds, 10),
		item.DispatchItemDigest,
		item.AcceptanceDigest,
		acceptance.ReceiptDigest,
		acceptance.ManifestDigest,
		acceptance.QueueDigest,
		acceptance.DispatchDigest,
		acceptance.AcceptanceDigest,
		acceptance.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
