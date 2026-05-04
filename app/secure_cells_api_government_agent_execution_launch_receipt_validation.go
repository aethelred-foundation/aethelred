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

type secureCellGovernmentAgentExecutionLaunchReceiptValidationResponse struct {
	Validation *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptValidation `json:"validation,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchReceiptValidationListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptValidation `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchReceiptValidationGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-receipt-validations" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchReceiptValidations(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptValidationListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-receipt-validations/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchReceiptValidations(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchReceiptValidationExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-receipt-validation") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-receipt-validation")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		validation, err := app.secureCellService.GetGovernmentAgentExecutionLaunchReceiptValidation(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptValidationResponse{Validation: validation})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchReceiptValidationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptValidation) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptValidationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-receipt-validations.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchReceiptValidationCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-receipt-validation csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptValidation) [][]string {
	rows := [][]string{{
		"validation_id",
		"manifest_id",
		"register_id",
		"authorization_id",
		"verification_id",
		"bundle_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"manifest_status",
		"clearance_status",
		"can_accept_receipts",
		"can_launch_after_receipts",
		"check_count",
		"pass_count",
		"warn_count",
		"fail_count",
		"receipt_requirement_count",
		"pending_acknowledgement_receipt_count",
		"pending_collection_receipt_count",
		"blocked_receipt_count",
		"required_receipt_types",
		"manifest_digest",
		"register_digest",
		"launch_digest",
		"check_id",
		"requirement_id",
		"receipt_type",
		"check_code",
		"check_outcome",
		"check_detail",
		"check_remediation",
		"validation_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Checks) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchReceiptValidationCSVRow(item, nil))
			continue
		}
		for idx := range item.Checks {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchReceiptValidationCSVRow(item, &item.Checks[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationCSVRow(
	validation securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptValidation,
	check *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck,
) []string {
	checkID := ""
	requirementID := ""
	receiptType := ""
	checkCode := ""
	checkOutcome := ""
	checkDetail := ""
	checkRemediation := ""
	if check != nil {
		checkID = check.CheckID
		requirementID = check.RequirementID
		receiptType = check.ReceiptType
		checkCode = check.Code
		checkOutcome = string(check.Outcome)
		checkDetail = check.Detail
		checkRemediation = check.Remediation
	}
	return []string{
		validation.ValidationID,
		validation.ManifestID,
		validation.RegisterID,
		validation.AuthorizationID,
		validation.VerificationID,
		validation.BundleID,
		validation.CellID,
		validation.Name,
		validation.Jurisdiction,
		validation.ServiceCode,
		validation.ServiceTier,
		string(validation.Status),
		string(validation.ManifestStatus),
		string(validation.ClearanceStatus),
		strconv.FormatBool(validation.CanAcceptReceipts),
		strconv.FormatBool(validation.CanLaunchAfterReceipts),
		strconv.Itoa(validation.CheckCount),
		strconv.Itoa(validation.PassCount),
		strconv.Itoa(validation.WarnCount),
		strconv.Itoa(validation.FailCount),
		strconv.Itoa(validation.ReceiptRequirementCount),
		strconv.Itoa(validation.PendingAcknowledgementReceiptCount),
		strconv.Itoa(validation.PendingCollectionReceiptCount),
		strconv.Itoa(validation.BlockedReceiptCount),
		strings.Join(validation.RequiredReceiptTypes, "|"),
		validation.ManifestDigest,
		validation.RegisterDigest,
		validation.LaunchDigest,
		checkID,
		requirementID,
		receiptType,
		checkCode,
		checkOutcome,
		checkDetail,
		checkRemediation,
		validation.ValidationDigest,
		validation.GeneratedAt.UTC().Format(time.RFC3339Nano),
		validation.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
