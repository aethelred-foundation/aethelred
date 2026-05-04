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

type secureCellGovernmentAgentExecutionLaunchArchiveCertificateResponse struct {
	Certificate *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchArchiveCertificate `json:"certificate,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchArchiveCertificateListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchArchiveCertificate `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchArchiveCertificateGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-archive-certificates" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchArchiveCertificates(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchArchiveCertificateListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-archive-certificates/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchArchiveCertificates(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchArchiveCertificateExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-archive-certificate") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-archive-certificate")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		certificate, err := app.secureCellService.GetGovernmentAgentExecutionLaunchArchiveCertificate(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchArchiveCertificateResponse{Certificate: certificate})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchArchiveCertificateExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchArchiveCertificate) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchArchiveCertificateListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-archive-certificates.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchArchiveCertificateCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-archive-certificate csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchArchiveCertificate) [][]string {
	rows := [][]string{{
		"certificate_id",
		"settlement_register_id",
		"closeout_register_id",
		"ledger_id",
		"monitor_id",
		"order_id",
		"activation_id",
		"custody_id",
		"package_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"settlement_status",
		"can_issue_now",
		"can_issue_after_preservation",
		"can_escalate_blocked",
		"archive_item_count",
		"blocked_archive_item_count",
		"pending_archive_item_count",
		"archived_item_count",
		"required_receipt_types",
		"operator_instructions",
		"settlement_register_digest",
		"closeout_digest",
		"ledger_digest",
		"monitor_digest",
		"order_digest",
		"activation_digest",
		"custody_digest",
		"package_digest",
		"launch_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"item_id",
		"item_sequence",
		"settlement_item_id",
		"receipt_type",
		"gate_kind",
		"item_status",
		"archive_disposition",
		"required_action",
		"item_due_at",
		"evidence_binding_id",
		"evidence_digest",
		"settlement_digest",
		"archive_item_digest",
		"certificate_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Items) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchArchiveCertificateCSVRow(item, nil))
			continue
		}
		for idx := range item.Items {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchArchiveCertificateCSVRow(item, &item.Items[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateCSVRow(
	certificate securecellsintegration.SecureCellGovernmentAgentExecutionLaunchArchiveCertificate,
	item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchArchiveCertificateItem,
) []string {
	itemID := ""
	itemSequence := ""
	settlementItemID := ""
	receiptType := ""
	gateKind := ""
	itemStatus := ""
	archiveDisposition := ""
	requiredAction := ""
	itemDueAt := ""
	evidenceBindingID := ""
	evidenceDigest := ""
	settlementDigest := ""
	archiveItemDigest := ""
	if item != nil {
		itemID = item.ItemID
		itemSequence = strconv.Itoa(item.Sequence)
		settlementItemID = item.SettlementItemID
		receiptType = item.ReceiptType
		gateKind = item.GateKind
		itemStatus = string(item.Status)
		archiveDisposition = item.ArchiveDisposition
		requiredAction = item.RequiredAction
		itemDueAt = secureCellGovernmentAgentExecutionLaunchArchiveCertificateTime(item.DueAt)
		evidenceBindingID = item.EvidenceBindingID
		evidenceDigest = item.EvidenceDigest
		settlementDigest = item.SettlementDigest
		archiveItemDigest = item.ArchiveItemDigest
	}
	return []string{
		certificate.CertificateID,
		certificate.SettlementRegisterID,
		certificate.CloseoutRegisterID,
		certificate.LedgerID,
		certificate.MonitorID,
		certificate.OrderID,
		certificate.ActivationID,
		certificate.CustodyID,
		certificate.PackageID,
		certificate.CellID,
		certificate.Name,
		certificate.Jurisdiction,
		certificate.ServiceCode,
		certificate.ServiceTier,
		string(certificate.Status),
		string(certificate.SettlementStatus),
		strconv.FormatBool(certificate.CanIssueNow),
		strconv.FormatBool(certificate.CanIssueAfterPreservation),
		strconv.FormatBool(certificate.CanEscalateBlocked),
		strconv.Itoa(certificate.ArchiveItemCount),
		strconv.Itoa(certificate.BlockedArchiveItemCount),
		strconv.Itoa(certificate.PendingArchiveItemCount),
		strconv.Itoa(certificate.ArchivedItemCount),
		strings.Join(certificate.RequiredReceiptTypes, "|"),
		strings.Join(certificate.OperatorInstructions, "|"),
		certificate.SettlementRegisterDigest,
		certificate.CloseoutDigest,
		certificate.LedgerDigest,
		certificate.MonitorDigest,
		certificate.OrderDigest,
		certificate.ActivationDigest,
		certificate.CustodyDigest,
		certificate.PackageDigest,
		certificate.LaunchDigest,
		certificate.ReceiptManifestDigest,
		certificate.ReceiptValidationDigest,
		itemID,
		itemSequence,
		settlementItemID,
		receiptType,
		gateKind,
		itemStatus,
		archiveDisposition,
		requiredAction,
		itemDueAt,
		evidenceBindingID,
		evidenceDigest,
		settlementDigest,
		archiveItemDigest,
		certificate.CertificateDigest,
		certificate.GeneratedAt.UTC().Format(time.RFC3339Nano),
		certificate.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchArchiveCertificateTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
