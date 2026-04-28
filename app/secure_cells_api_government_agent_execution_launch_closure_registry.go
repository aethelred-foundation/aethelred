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

type secureCellGovernmentAgentExecutionLaunchClosureRegistryResponse struct {
	Registry *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureRegistry `json:"registry,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureRegistryListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureRegistry `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureRegistryGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-registries" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureRegistries(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureRegistryListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-registries/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureRegistries(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureRegistryExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-registry") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-registry")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		registry, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureRegistry(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureRegistryResponse{Registry: registry})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureRegistryExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureRegistry) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureRegistryListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-registries.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureRegistryCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-registry csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureRegistry) [][]string {
	rows := [][]string{{
		"registry_id",
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
		"certificate_status",
		"can_close_record_now",
		"can_close_after_archive_issue",
		"can_escalate_blocked",
		"closure_item_count",
		"blocked_closure_item_count",
		"pending_closure_item_count",
		"closed_closure_item_count",
		"required_receipt_types",
		"operator_instructions",
		"certificate_digest",
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
		"archive_item_id",
		"receipt_type",
		"gate_kind",
		"item_status",
		"closure_action",
		"required_action",
		"item_due_at",
		"evidence_binding_id",
		"evidence_digest",
		"archive_item_digest",
		"closure_item_digest",
		"registry_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Items) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosureRegistryCSVRow(item, nil))
			continue
		}
		for idx := range item.Items {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosureRegistryCSVRow(item, &item.Items[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryCSVRow(
	registry securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureRegistry,
	item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureItem,
) []string {
	itemID := ""
	itemSequence := ""
	archiveItemID := ""
	receiptType := ""
	gateKind := ""
	itemStatus := ""
	closureAction := ""
	requiredAction := ""
	itemDueAt := ""
	evidenceBindingID := ""
	evidenceDigest := ""
	archiveItemDigest := ""
	closureItemDigest := ""
	if item != nil {
		itemID = item.ItemID
		itemSequence = strconv.Itoa(item.Sequence)
		archiveItemID = item.ArchiveItemID
		receiptType = item.ReceiptType
		gateKind = item.GateKind
		itemStatus = string(item.Status)
		closureAction = item.ClosureAction
		requiredAction = item.RequiredAction
		itemDueAt = secureCellGovernmentAgentExecutionLaunchClosureRegistryTime(item.DueAt)
		evidenceBindingID = item.EvidenceBindingID
		evidenceDigest = item.EvidenceDigest
		archiveItemDigest = item.ArchiveItemDigest
		closureItemDigest = item.ClosureItemDigest
	}
	return []string{
		registry.RegistryID,
		registry.CertificateID,
		registry.SettlementRegisterID,
		registry.CloseoutRegisterID,
		registry.LedgerID,
		registry.MonitorID,
		registry.OrderID,
		registry.ActivationID,
		registry.CustodyID,
		registry.PackageID,
		registry.CellID,
		registry.Name,
		registry.Jurisdiction,
		registry.ServiceCode,
		registry.ServiceTier,
		string(registry.Status),
		string(registry.CertificateStatus),
		strconv.FormatBool(registry.CanCloseRecordNow),
		strconv.FormatBool(registry.CanCloseAfterArchiveIssue),
		strconv.FormatBool(registry.CanEscalateBlocked),
		strconv.Itoa(registry.ClosureItemCount),
		strconv.Itoa(registry.BlockedClosureItemCount),
		strconv.Itoa(registry.PendingClosureItemCount),
		strconv.Itoa(registry.ClosedClosureItemCount),
		strings.Join(registry.RequiredReceiptTypes, "|"),
		strings.Join(registry.OperatorInstructions, "|"),
		registry.CertificateDigest,
		registry.SettlementRegisterDigest,
		registry.CloseoutDigest,
		registry.LedgerDigest,
		registry.MonitorDigest,
		registry.OrderDigest,
		registry.ActivationDigest,
		registry.CustodyDigest,
		registry.PackageDigest,
		registry.LaunchDigest,
		registry.ReceiptManifestDigest,
		registry.ReceiptValidationDigest,
		itemID,
		itemSequence,
		archiveItemID,
		receiptType,
		gateKind,
		itemStatus,
		closureAction,
		requiredAction,
		itemDueAt,
		evidenceBindingID,
		evidenceDigest,
		archiveItemDigest,
		closureItemDigest,
		registry.RegistryDigest,
		registry.GeneratedAt.UTC().Format(time.RFC3339Nano),
		registry.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureRegistryTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
