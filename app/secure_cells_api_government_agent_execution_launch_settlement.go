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

type secureCellGovernmentAgentExecutionLaunchSettlementResponse struct {
	Settlement *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchSettlementRegister `json:"settlement,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchSettlementListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchSettlementRegister `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchSettlementGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-settlements" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchSettlements(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchSettlementListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-settlements/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchSettlements(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchSettlementExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-settlement") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-settlement")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		settlement, err := app.secureCellService.GetGovernmentAgentExecutionLaunchSettlement(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchSettlementResponse{Settlement: settlement})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchSettlementExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchSettlementRegister) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchSettlementListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-settlements.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchSettlementCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-settlement csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchSettlementRegister) [][]string {
	rows := [][]string{{
		"register_id",
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
		"closeout_status",
		"can_settle_now",
		"can_settle_after_preservation",
		"can_escalate_now",
		"settlement_item_count",
		"blocked_settlement_item_count",
		"pending_settlement_item_count",
		"ready_settlement_item_count",
		"required_receipt_types",
		"operator_instructions",
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
		"gate_id",
		"intake_item_id",
		"gate_kind",
		"receipt_type",
		"item_status",
		"action",
		"required_action",
		"item_due_at",
		"evidence_binding_id",
		"evidence_digest",
		"gate_digest",
		"settlement_digest",
		"settlement_register_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Items) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchSettlementCSVRow(item, nil))
			continue
		}
		for idx := range item.Items {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchSettlementCSVRow(item, &item.Items[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchSettlementCSVRow(
	settlement securecellsintegration.SecureCellGovernmentAgentExecutionLaunchSettlementRegister,
	item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchSettlementItem,
) []string {
	itemID := ""
	itemSequence := ""
	gateID := ""
	intakeItemID := ""
	gateKind := ""
	receiptType := ""
	itemStatus := ""
	action := ""
	requiredAction := ""
	itemDueAt := ""
	evidenceBindingID := ""
	evidenceDigest := ""
	gateDigest := ""
	settlementDigest := ""
	if item != nil {
		itemID = item.ItemID
		itemSequence = strconv.Itoa(item.Sequence)
		gateID = item.GateID
		intakeItemID = item.IntakeItemID
		gateKind = item.GateKind
		receiptType = item.ReceiptType
		itemStatus = string(item.Status)
		action = string(item.Action)
		requiredAction = item.RequiredAction
		itemDueAt = secureCellGovernmentAgentExecutionLaunchSettlementTime(item.DueAt)
		evidenceBindingID = item.EvidenceBindingID
		evidenceDigest = item.EvidenceDigest
		gateDigest = item.GateDigest
		settlementDigest = item.SettlementDigest
	}
	return []string{
		settlement.RegisterID,
		settlement.CloseoutRegisterID,
		settlement.LedgerID,
		settlement.MonitorID,
		settlement.OrderID,
		settlement.ActivationID,
		settlement.CustodyID,
		settlement.PackageID,
		settlement.CellID,
		settlement.Name,
		settlement.Jurisdiction,
		settlement.ServiceCode,
		settlement.ServiceTier,
		string(settlement.Status),
		string(settlement.CloseoutStatus),
		strconv.FormatBool(settlement.CanSettleNow),
		strconv.FormatBool(settlement.CanSettleAfterPreservation),
		strconv.FormatBool(settlement.CanEscalateNow),
		strconv.Itoa(settlement.SettlementItemCount),
		strconv.Itoa(settlement.BlockedSettlementItemCount),
		strconv.Itoa(settlement.PendingSettlementItemCount),
		strconv.Itoa(settlement.ReadySettlementItemCount),
		strings.Join(settlement.RequiredReceiptTypes, "|"),
		strings.Join(settlement.OperatorInstructions, "|"),
		settlement.CloseoutDigest,
		settlement.LedgerDigest,
		settlement.MonitorDigest,
		settlement.OrderDigest,
		settlement.ActivationDigest,
		settlement.CustodyDigest,
		settlement.PackageDigest,
		settlement.LaunchDigest,
		settlement.ReceiptManifestDigest,
		settlement.ReceiptValidationDigest,
		itemID,
		itemSequence,
		gateID,
		intakeItemID,
		gateKind,
		receiptType,
		itemStatus,
		action,
		requiredAction,
		itemDueAt,
		evidenceBindingID,
		evidenceDigest,
		gateDigest,
		settlementDigest,
		settlement.SettlementRegisterDigest,
		settlement.GeneratedAt.UTC().Format(time.RFC3339Nano),
		settlement.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchSettlementTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
