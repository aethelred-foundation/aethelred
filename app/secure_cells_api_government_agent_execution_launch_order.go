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

type secureCellGovernmentAgentExecutionLaunchOrderResponse struct {
	Order *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchOrder `json:"order,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchOrderListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchOrder `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchOrderGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-orders" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchOrders(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchOrderListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-orders/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchOrders(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchOrderExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-order") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-order")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		order, err := app.secureCellService.GetGovernmentAgentExecutionLaunchOrder(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchOrderResponse{Order: order})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchOrderExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchOrder) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchOrderListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-orders.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchOrderCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-order csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchOrderCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchOrder) [][]string {
	rows := [][]string{{
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
		"activation_status",
		"can_start_now",
		"can_start_after_operator_receipts",
		"can_start_autonomous",
		"lease_minutes",
		"runtime_minutes",
		"start_window_opens_at",
		"start_window_expires_at",
		"stop_condition_count",
		"critical_stop_condition_count",
		"high_stop_condition_count",
		"standard_stop_condition_count",
		"return_receipt_count",
		"required_return_receipts",
		"required_launch_receipts",
		"operator_instructions",
		"package_digest",
		"custody_digest",
		"activation_digest",
		"launch_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"condition_id",
		"condition_code",
		"condition_priority",
		"condition_detail",
		"condition_required_action",
		"condition_evidence_digest",
		"condition_digest",
		"order_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.StopConditions) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchOrderCSVRow(item, nil))
			continue
		}
		for idx := range item.StopConditions {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchOrderCSVRow(item, &item.StopConditions[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchOrderCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchOrder,
	condition *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchOrderStopCondition,
) []string {
	conditionID := ""
	conditionCode := ""
	conditionPriority := ""
	conditionDetail := ""
	conditionRequiredAction := ""
	conditionEvidenceDigest := ""
	conditionDigest := ""
	if condition != nil {
		conditionID = condition.ConditionID
		conditionCode = condition.Code
		conditionPriority = string(condition.Priority)
		conditionDetail = condition.Detail
		conditionRequiredAction = condition.RequiredAction
		conditionEvidenceDigest = condition.EvidenceDigest
		conditionDigest = condition.ConditionDigest
	}
	return []string{
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
		string(item.ActivationStatus),
		strconv.FormatBool(item.CanStartNow),
		strconv.FormatBool(item.CanStartAfterOperatorReceipts),
		strconv.FormatBool(item.CanStartAutonomous),
		strconv.Itoa(item.LeaseMinutes),
		strconv.Itoa(item.RuntimeMinutes),
		item.StartWindowOpensAt.UTC().Format(time.RFC3339Nano),
		item.StartWindowExpiresAt.UTC().Format(time.RFC3339Nano),
		strconv.Itoa(item.StopConditionCount),
		strconv.Itoa(item.CriticalStopConditionCount),
		strconv.Itoa(item.HighStopConditionCount),
		strconv.Itoa(item.StandardStopConditionCount),
		strconv.Itoa(item.ReturnReceiptCount),
		strings.Join(item.RequiredReturnReceipts, "|"),
		strings.Join(item.RequiredLaunchReceipts, "|"),
		strings.Join(item.OperatorInstructions, "|"),
		item.PackageDigest,
		item.CustodyDigest,
		item.ActivationDigest,
		item.LaunchDigest,
		item.ReceiptManifestDigest,
		item.ReceiptValidationDigest,
		conditionID,
		conditionCode,
		conditionPriority,
		conditionDetail,
		conditionRequiredAction,
		conditionEvidenceDigest,
		conditionDigest,
		item.OrderDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
