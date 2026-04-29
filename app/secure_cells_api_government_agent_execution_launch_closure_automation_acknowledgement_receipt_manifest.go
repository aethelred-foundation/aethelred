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

type launchClosureAutomationAckReceiptManifest = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest
type launchClosureAutomationAckReceiptManifestItem = securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem

type secureCellLaunchClosureAutomationAckReceiptManifestResponse struct {
	Manifest *launchClosureAutomationAckReceiptManifest `json:"manifest,omitempty"`
}

func (app *AethelredApp) handleSecureCellLaunchClosureAutomationAckReceiptManifestGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-manifest" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		manifest, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptManifestResponse{Manifest: manifest})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-acknowledgement-receipt-manifest/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		manifest, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellLaunchClosureAutomationAckReceiptManifestExport(w, r, manifest); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellLaunchClosureAutomationAckReceiptManifestExport(w http.ResponseWriter, r *http.Request, manifest *launchClosureAutomationAckReceiptManifest) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellLaunchClosureAutomationAckReceiptManifestResponse{Manifest: manifest})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-acknowledgement-receipt-manifest.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellLaunchClosureAutomationAckReceiptManifestCSVRows(manifest) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-acknowledgement-receipt-manifest csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellLaunchClosureAutomationAckReceiptManifestCSVRows(manifest *launchClosureAutomationAckReceiptManifest) [][]string {
	rows := [][]string{{
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
		"receipt_due_at",
		"receipt_overdue_seconds",
		"evidence_count",
		"overdue_evidence_count",
		"escalation_evidence_count",
		"item_sequence",
		"item_evidence",
		"item_status",
		"item_responsible_role",
		"item_pending_actions",
		"item_cell_ids",
		"receipt_digest",
		"manifest_digest",
		"generated_at",
	}}
	if manifest == nil {
		return rows
	}
	items := manifest.Items
	if len(items) == 0 {
		items = []launchClosureAutomationAckReceiptManifestItem{{}}
	}
	for _, item := range items {
		rows = append(rows, secureCellLaunchClosureAutomationAckReceiptManifestCSVRow(manifest, item))
	}
	return rows
}

func secureCellLaunchClosureAutomationAckReceiptManifestCSVRow(
	manifest *launchClosureAutomationAckReceiptManifest,
	item launchClosureAutomationAckReceiptManifestItem,
) []string {
	receiptDueAt := ""
	if manifest.ReceiptDueAt != nil {
		receiptDueAt = manifest.ReceiptDueAt.UTC().Format(time.RFC3339Nano)
	}
	itemSequence := ""
	if item.Sequence > 0 {
		itemSequence = strconv.Itoa(item.Sequence)
	}
	return []string{
		manifest.ManifestID,
		manifest.AcknowledgementReceiptID,
		manifest.AcknowledgementID,
		manifest.DirectiveID,
		manifest.DispatchID,
		manifest.BriefID,
		manifest.RunbookID,
		manifest.PacketID,
		manifest.BoardID,
		manifest.SummaryID,
		manifest.Jurisdiction,
		manifest.ServiceCode,
		manifest.ServiceTier,
		manifest.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		string(manifest.FocusLane),
		manifest.FocusAction,
		string(manifest.Severity),
		string(manifest.ReceiptStatus),
		manifest.ReceiptAction,
		receiptDueAt,
		strconv.FormatInt(manifest.ReceiptOverdueSeconds, 10),
		strconv.Itoa(manifest.EvidenceCount),
		strconv.Itoa(manifest.OverdueEvidenceCount),
		strconv.Itoa(manifest.EscalationEvidenceCount),
		itemSequence,
		item.Evidence,
		string(item.Status),
		item.ResponsibleRole,
		strings.Join(item.PendingActions, "|"),
		strings.Join(item.CellIDs, "|"),
		manifest.ReceiptDigest,
		manifest.ManifestDigest,
		manifest.GeneratedAt.UTC().Format(time.RFC3339Nano),
	}
}
