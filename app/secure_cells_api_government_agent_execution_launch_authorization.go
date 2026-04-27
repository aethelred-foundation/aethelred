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

type secureCellGovernmentAgentExecutionLaunchAuthorizationResponse struct {
	Authorization *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchAuthorization `json:"authorization,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchAuthorizationListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchAuthorization `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchAuthorizationGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-authorizations" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchAuthorizations(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchAuthorizationListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-authorizations/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchAuthorizations(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchAuthorizationExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-authorization") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-authorization")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		authorization, err := app.secureCellService.GetGovernmentAgentExecutionLaunchAuthorization(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchAuthorizationResponse{Authorization: authorization})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchAuthorizationExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchAuthorization) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchAuthorizationListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-authorizations.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchAuthorizationCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-authorization csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchAuthorizationCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchAuthorization) [][]string {
	rows := [][]string{{
		"authorization_id",
		"verification_id",
		"bundle_id",
		"cell_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"verification_status",
		"bundle_status",
		"carry_mode",
		"can_launch_now",
		"can_launch_after_operator_review",
		"can_autonomous_launch",
		"requires_operator_review",
		"required_operator_acknowledgement_count",
		"gate_count",
		"pass_gate_count",
		"hold_gate_count",
		"block_gate_count",
		"failed_verification_check_count",
		"blocked_action_count",
		"release_gate_action_count",
		"receipt_collection_count",
		"required_receipt_types",
		"top_blocker_codes",
		"missing_preconditions",
		"witness_id",
		"ledger_id",
		"queue_id",
		"verification_digest",
		"bundle_digest",
		"gate_id",
		"gate_code",
		"gate_status",
		"gate_detail",
		"gate_required_action",
		"gate_evidence_binding_id",
		"launch_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Gates) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchAuthorizationCSVRow(item, nil))
			continue
		}
		for idx := range item.Gates {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchAuthorizationCSVRow(item, &item.Gates[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchAuthorizationCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchAuthorization,
	gate *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchGate,
) []string {
	gateID := ""
	gateCode := ""
	gateStatus := ""
	gateDetail := ""
	gateRequiredAction := ""
	gateEvidenceBindingID := ""
	if gate != nil {
		gateID = gate.GateID
		gateCode = gate.Code
		gateStatus = string(gate.Status)
		gateDetail = gate.Detail
		gateRequiredAction = gate.RequiredAction
		gateEvidenceBindingID = gate.EvidenceBindingID
	}
	return []string{
		item.AuthorizationID,
		item.VerificationID,
		item.BundleID,
		item.CellID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.VerificationStatus),
		string(item.BundleStatus),
		string(item.CarryMode),
		strconv.FormatBool(item.CanLaunchNow),
		strconv.FormatBool(item.CanLaunchAfterOperatorReview),
		strconv.FormatBool(item.CanAutonomousLaunch),
		strconv.FormatBool(item.RequiresOperatorReview),
		strconv.Itoa(item.RequiredOperatorAcknowledgementCount),
		strconv.Itoa(item.GateCount),
		strconv.Itoa(item.PassGateCount),
		strconv.Itoa(item.HoldGateCount),
		strconv.Itoa(item.BlockGateCount),
		strconv.Itoa(item.FailedVerificationCheckCount),
		strconv.Itoa(item.BlockedActionCount),
		strconv.Itoa(item.ReleaseGateActionCount),
		strconv.Itoa(item.ReceiptCollectionCount),
		strings.Join(item.RequiredReceiptTypes, "|"),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.MissingPreconditions, "|"),
		item.WitnessID,
		item.LedgerID,
		item.QueueID,
		item.VerificationDigest,
		item.BundleDigest,
		gateID,
		gateCode,
		gateStatus,
		gateDetail,
		gateRequiredAction,
		gateEvidenceBindingID,
		item.LaunchDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
