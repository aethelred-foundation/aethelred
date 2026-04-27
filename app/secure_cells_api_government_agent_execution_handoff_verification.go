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

type secureCellGovernmentAgentExecutionHandoffVerificationResponse struct {
	Verification *securecellsintegration.SecureCellGovernmentAgentExecutionHandoffVerification `json:"verification,omitempty"`
}

type secureCellGovernmentAgentExecutionHandoffVerificationListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionHandoffVerification `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionHandoffVerificationGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-handoff-verifications" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionHandoffVerifications(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionHandoffVerificationListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-handoff-verifications/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionHandoffVerifications(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionHandoffVerificationExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-handoff-verification") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-handoff-verification")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		verification, err := app.secureCellService.GetGovernmentAgentExecutionHandoffVerification(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionHandoffVerificationResponse{Verification: verification})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionHandoffVerificationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionHandoffVerification) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionHandoffVerificationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-handoff-verifications.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionHandoffVerificationCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-handoff-verification csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionHandoffVerificationCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionHandoffVerification) [][]string {
	rows := [][]string{{
		"verification_id",
		"bundle_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"bundle_status",
		"carry_mode",
		"can_handoff",
		"can_autonomous_handoff",
		"requires_operator_review",
		"check_count",
		"pass_count",
		"warn_count",
		"fail_count",
		"blocked_action_count",
		"release_gate_action_count",
		"receipt_collection_count",
		"required_receipt_types",
		"top_blocker_codes",
		"missing_preconditions",
		"witness_id",
		"ledger_id",
		"queue_id",
		"witness_digest",
		"expected_witness_digest",
		"ledger_digest",
		"expected_ledger_digest",
		"queue_digest",
		"expected_queue_digest",
		"bundle_digest",
		"expected_bundle_digest",
		"check_id",
		"check_code",
		"check_outcome",
		"check_detail",
		"check_recommendation",
		"verification_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Checks) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionHandoffVerificationCSVRow(item, nil))
			continue
		}
		for idx := range item.Checks {
			rows = append(rows, secureCellGovernmentAgentExecutionHandoffVerificationCSVRow(item, &item.Checks[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionHandoffVerificationCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionHandoffVerification,
	check *securecellsintegration.SecureCellGovernmentAgentExecutionHandoffVerificationCheck,
) []string {
	checkID := ""
	checkCode := ""
	checkOutcome := ""
	checkDetail := ""
	checkRecommendation := ""
	if check != nil {
		checkID = check.CheckID
		checkCode = check.Code
		checkOutcome = string(check.Outcome)
		checkDetail = check.Detail
		checkRecommendation = check.Recommendation
	}
	return []string{
		item.VerificationID,
		item.BundleID,
		item.CellID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.BundleStatus),
		string(item.CarryMode),
		strconv.FormatBool(item.CanHandoff),
		strconv.FormatBool(item.CanAutonomousHandoff),
		strconv.FormatBool(item.RequiresOperatorReview),
		strconv.Itoa(item.CheckCount),
		strconv.Itoa(item.PassCount),
		strconv.Itoa(item.WarnCount),
		strconv.Itoa(item.FailCount),
		strconv.Itoa(item.BlockedActionCount),
		strconv.Itoa(item.ReleaseGateActionCount),
		strconv.Itoa(item.ReceiptCollectionCount),
		strings.Join(item.RequiredReceiptTypes, "|"),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.MissingPreconditions, "|"),
		item.WitnessID,
		item.LedgerID,
		item.QueueID,
		item.WitnessDigest,
		item.ExpectedWitnessDigest,
		item.LedgerDigest,
		item.ExpectedLedgerDigest,
		item.QueueDigest,
		item.ExpectedQueueDigest,
		item.BundleDigest,
		item.ExpectedBundleDigest,
		checkID,
		checkCode,
		checkOutcome,
		checkDetail,
		checkRecommendation,
		item.VerificationDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
