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

type secureCellGovernmentAgentExecutionLaunchClosureCommandCenterResponse struct {
	Center *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter `json:"center,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureCommandCenterListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureCommandCenterGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-command-centers" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureCommandCenters(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureCommandCenterListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-command-centers/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureCommandCenters(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureCommandCenterExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-command-center") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-command-center")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		center, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureCommandCenter(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureCommandCenterResponse{Center: center})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureCommandCenterExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureCommandCenterListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-command-centers.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureCommandCenterCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-command-center csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureCommandCenterCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureCommandCenter) [][]string {
	rows := [][]string{{
		"center_id",
		"board_id",
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
		"board_status",
		"can_close_now",
		"can_close_after_archive_issue",
		"can_escalate_blocked",
		"item_count",
		"blocked_item_count",
		"pending_item_count",
		"ready_item_count",
		"required_receipt_types",
		"primary_action",
		"operator_instructions",
		"board_digest",
		"registry_digest",
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
		"center_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		rows = append(rows, []string{
			item.CenterID,
			item.BoardID,
			item.RegistryID,
			item.CertificateID,
			item.SettlementRegisterID,
			item.CloseoutRegisterID,
			item.LedgerID,
			item.MonitorID,
			item.OrderID,
			item.ActivationID,
			item.CustodyID,
			item.PackageID,
			item.CellID,
			item.Name,
			item.Jurisdiction,
			item.ServiceCode,
			item.ServiceTier,
			string(item.Status),
			string(item.BoardStatus),
			strconv.FormatBool(item.CanCloseNow),
			strconv.FormatBool(item.CanCloseAfterArchiveIssue),
			strconv.FormatBool(item.CanEscalateBlocked),
			strconv.Itoa(item.ItemCount),
			strconv.Itoa(item.BlockedItemCount),
			strconv.Itoa(item.PendingItemCount),
			strconv.Itoa(item.ReadyItemCount),
			strings.Join(item.RequiredReceiptTypes, "|"),
			item.PrimaryAction,
			strings.Join(item.OperatorInstructions, "|"),
			item.BoardDigest,
			item.RegistryDigest,
			item.CertificateDigest,
			item.SettlementRegisterDigest,
			item.CloseoutDigest,
			item.LedgerDigest,
			item.MonitorDigest,
			item.OrderDigest,
			item.ActivationDigest,
			item.CustodyDigest,
			item.PackageDigest,
			item.LaunchDigest,
			item.ReceiptManifestDigest,
			item.ReceiptValidationDigest,
			item.CenterDigest,
			item.GeneratedAt.UTC().Format(time.RFC3339Nano),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
