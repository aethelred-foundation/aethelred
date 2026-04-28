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

type secureCellGovernmentAgentExecutionLaunchPackageResponse struct {
	Package *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchPackage `json:"package,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchPackageListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchPackage `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchPackageGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-packages" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchPackages(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchPackageListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-packages/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchPackages(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchPackageExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-package") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-package")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		pkg, err := app.secureCellService.GetGovernmentAgentExecutionLaunchPackage(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchPackageResponse{Package: pkg})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchPackageExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchPackage) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchPackageListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-packages.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchPackageCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-package csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchPackageCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchPackage) [][]string {
	rows := [][]string{{
		"package_id",
		"package_version",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"authorization_status",
		"clearance_status",
		"receipt_manifest_status",
		"receipt_validation_status",
		"can_launch_now",
		"can_launch_after_operator_review",
		"can_autonomous_launch",
		"required_operator_acknowledgement_count",
		"clearance_item_count",
		"receipt_requirement_count",
		"pending_acknowledgement_receipt_count",
		"blocked_receipt_count",
		"validation_fail_count",
		"required_receipt_types",
		"operator_instructions",
		"authorization_id",
		"clearance_register_id",
		"receipt_manifest_id",
		"receipt_validation_id",
		"launch_digest",
		"clearance_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"package_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		rows = append(rows, []string{
			item.PackageID,
			item.PackageVersion,
			item.CellID,
			item.Name,
			item.Jurisdiction,
			item.ServiceCode,
			item.ServiceTier,
			string(item.Status),
			string(item.AuthorizationStatus),
			string(item.ClearanceStatus),
			string(item.ReceiptManifestStatus),
			string(item.ReceiptValidationStatus),
			strconv.FormatBool(item.CanLaunchNow),
			strconv.FormatBool(item.CanLaunchAfterOperatorReview),
			strconv.FormatBool(item.CanAutonomousLaunch),
			strconv.Itoa(item.RequiredOperatorAcknowledgementCount),
			strconv.Itoa(item.ClearanceItemCount),
			strconv.Itoa(item.ReceiptRequirementCount),
			strconv.Itoa(item.PendingAcknowledgementReceiptCount),
			strconv.Itoa(item.BlockedReceiptCount),
			strconv.Itoa(item.ValidationFailCount),
			strings.Join(item.RequiredReceiptTypes, "|"),
			strings.Join(item.OperatorInstructions, "|"),
			item.AuthorizationID,
			item.ClearanceRegisterID,
			item.ReceiptManifestID,
			item.ReceiptValidationID,
			item.LaunchDigest,
			item.ClearanceDigest,
			item.ReceiptManifestDigest,
			item.ReceiptValidationDigest,
			item.PackageDigest,
			item.GeneratedAt.UTC().Format(time.RFC3339Nano),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
