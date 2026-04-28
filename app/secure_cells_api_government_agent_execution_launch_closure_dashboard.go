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

type secureCellGovernmentAgentExecutionLaunchClosureDashboardResponse struct {
	Dashboard *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureDashboard `json:"dashboard,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureDashboardListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureDashboard `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureDashboardGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-dashboards" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureDashboards(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureDashboardListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-dashboards/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureDashboards(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureDashboardExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-dashboard") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-dashboard")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		dashboard, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureDashboard(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureDashboardResponse{Dashboard: dashboard})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureDashboardExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureDashboard) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureDashboardListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-dashboards.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureDashboardCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-dashboard csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureDashboardCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureDashboard) [][]string {
	rows := [][]string{{
		"dashboard_id",
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
		"center_status",
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
		"center_digest",
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
		"dashboard_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		rows = append(rows, []string{
			item.DashboardID,
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
			string(item.CenterStatus),
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
			item.CenterDigest,
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
			item.DashboardDigest,
			item.GeneratedAt.UTC().Format(time.RFC3339Nano),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
