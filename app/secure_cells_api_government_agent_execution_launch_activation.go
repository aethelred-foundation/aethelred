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

type secureCellGovernmentAgentExecutionLaunchActivationResponse struct {
	Activation *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchActivationCertificate `json:"activation,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchActivationListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchActivationCertificate `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchActivationGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-activations" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchActivations(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchActivationListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-activations/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchActivations(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchActivationExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-activation") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-activation")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		activation, err := app.secureCellService.GetGovernmentAgentExecutionLaunchActivation(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchActivationResponse{Activation: activation})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchActivationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchActivationCertificate) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchActivationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-activations.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchActivationCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-activation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchActivationCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchActivationCertificate) [][]string {
	rows := [][]string{{
		"activation_id",
		"custody_id",
		"package_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"custody_status",
		"package_status",
		"can_execute_now",
		"can_execute_after_operator_receipts",
		"can_execute_autonomous",
		"lease_minutes",
		"activation_window_starts_at",
		"activation_window_expires_at",
		"check_count",
		"pass_count",
		"warn_count",
		"fail_count",
		"required_receipt_types",
		"operator_instructions",
		"package_digest",
		"custody_digest",
		"launch_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"check_id",
		"check_code",
		"check_status",
		"check_detail",
		"check_remediation",
		"check_evidence_digest",
		"check_digest",
		"activation_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Checks) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchActivationCSVRow(item, nil))
			continue
		}
		for idx := range item.Checks {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchActivationCSVRow(item, &item.Checks[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchActivationCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchActivationCertificate,
	check *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchActivationCheck,
) []string {
	checkID := ""
	checkCode := ""
	checkStatus := ""
	checkDetail := ""
	checkRemediation := ""
	checkEvidenceDigest := ""
	checkDigest := ""
	if check != nil {
		checkID = check.CheckID
		checkCode = check.Code
		checkStatus = string(check.Status)
		checkDetail = check.Detail
		checkRemediation = check.Remediation
		checkEvidenceDigest = check.EvidenceDigest
		checkDigest = check.CheckDigest
	}
	return []string{
		item.ActivationID,
		item.CustodyID,
		item.PackageID,
		item.CellID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.CustodyStatus),
		string(item.PackageStatus),
		strconv.FormatBool(item.CanExecuteNow),
		strconv.FormatBool(item.CanExecuteAfterOperatorReceipts),
		strconv.FormatBool(item.CanExecuteAutonomous),
		strconv.Itoa(item.LeaseMinutes),
		item.ActivationWindowStartsAt.UTC().Format(time.RFC3339Nano),
		item.ActivationWindowExpiresAt.UTC().Format(time.RFC3339Nano),
		strconv.Itoa(item.CheckCount),
		strconv.Itoa(item.PassCount),
		strconv.Itoa(item.WarnCount),
		strconv.Itoa(item.FailCount),
		strings.Join(item.RequiredReceiptTypes, "|"),
		strings.Join(item.OperatorInstructions, "|"),
		item.PackageDigest,
		item.CustodyDigest,
		item.LaunchDigest,
		item.ReceiptManifestDigest,
		item.ReceiptValidationDigest,
		checkID,
		checkCode,
		checkStatus,
		checkDetail,
		checkRemediation,
		checkEvidenceDigest,
		checkDigest,
		item.ActivationDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
