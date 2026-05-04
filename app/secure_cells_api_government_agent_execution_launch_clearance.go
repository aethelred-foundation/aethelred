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

type secureCellGovernmentAgentExecutionLaunchClearanceResponse struct {
	Register *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClearanceRegister `json:"register,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClearanceListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClearanceRegister `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClearanceGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-clearances" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClearances(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClearanceListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-clearances/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClearances(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClearanceExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-clearance") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-clearance")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		register, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClearance(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClearanceResponse{Register: register})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClearanceExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClearanceRegister) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClearanceListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-clearances.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClearanceCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-clearance csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClearanceCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClearanceRegister) [][]string {
	rows := [][]string{{
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
		"authorization_status",
		"carry_mode",
		"can_launch_now",
		"can_launch_after_operator_review",
		"can_autonomous_launch",
		"required_operator_acknowledgement_count",
		"clearance_item_count",
		"clear_item_count",
		"acknowledgement_item_count",
		"remediation_item_count",
		"critical_item_count",
		"high_item_count",
		"required_receipt_types",
		"top_blocker_codes",
		"missing_preconditions",
		"witness_id",
		"ledger_id",
		"queue_id",
		"launch_digest",
		"verification_digest",
		"bundle_digest",
		"item_id",
		"item_sequence",
		"gate_id",
		"gate_code",
		"gate_status",
		"item_status",
		"item_priority",
		"item_action",
		"item_reason",
		"item_required_receipt_types",
		"item_evidence_binding_id",
		"gate_digest",
		"item_digest",
		"register_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Items) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClearanceCSVRow(item, nil))
			continue
		}
		for idx := range item.Items {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClearanceCSVRow(item, &item.Items[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchClearanceCSVRow(
	register securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClearanceRegister,
	item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClearanceItem,
) []string {
	itemID := ""
	itemSequence := ""
	gateID := ""
	gateCode := ""
	gateStatus := ""
	itemStatus := ""
	itemPriority := ""
	itemAction := ""
	itemReason := ""
	itemRequiredReceiptTypes := ""
	itemEvidenceBindingID := ""
	gateDigest := ""
	itemDigest := ""
	if item != nil {
		itemID = item.ItemID
		itemSequence = strconv.Itoa(item.Sequence)
		gateID = item.GateID
		gateCode = item.GateCode
		gateStatus = string(item.GateStatus)
		itemStatus = string(item.Status)
		itemPriority = string(item.Priority)
		itemAction = item.Action
		itemReason = item.Reason
		itemRequiredReceiptTypes = strings.Join(item.RequiredReceiptTypes, "|")
		itemEvidenceBindingID = item.EvidenceBindingID
		gateDigest = item.GateDigest
		itemDigest = item.ItemDigest
	}
	return []string{
		register.RegisterID,
		register.AuthorizationID,
		register.VerificationID,
		register.BundleID,
		register.CellID,
		register.Name,
		register.Jurisdiction,
		register.ServiceCode,
		register.ServiceTier,
		string(register.Status),
		string(register.AuthorizationStatus),
		string(register.CarryMode),
		strconv.FormatBool(register.CanLaunchNow),
		strconv.FormatBool(register.CanLaunchAfterOperatorReview),
		strconv.FormatBool(register.CanAutonomousLaunch),
		strconv.Itoa(register.RequiredOperatorAcknowledgementCount),
		strconv.Itoa(register.ClearanceItemCount),
		strconv.Itoa(register.ClearItemCount),
		strconv.Itoa(register.AcknowledgementItemCount),
		strconv.Itoa(register.RemediationItemCount),
		strconv.Itoa(register.CriticalItemCount),
		strconv.Itoa(register.HighItemCount),
		strings.Join(register.RequiredReceiptTypes, "|"),
		strings.Join(register.TopBlockerCodes, "|"),
		strings.Join(register.MissingPreconditions, "|"),
		register.WitnessID,
		register.LedgerID,
		register.QueueID,
		register.LaunchDigest,
		register.VerificationDigest,
		register.BundleDigest,
		itemID,
		itemSequence,
		gateID,
		gateCode,
		gateStatus,
		itemStatus,
		itemPriority,
		itemAction,
		itemReason,
		itemRequiredReceiptTypes,
		itemEvidenceBindingID,
		gateDigest,
		itemDigest,
		register.RegisterDigest,
		register.GeneratedAt.UTC().Format(time.RFC3339Nano),
		register.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
