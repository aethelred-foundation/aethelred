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

type secureCellGovernmentAgentExecutionLaunchReceiptIntakeResponse struct {
	Intake *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptIntake `json:"intake,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchReceiptIntakeListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptIntake `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchReceiptIntakeGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-receipt-intakes" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchReceiptIntakes(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptIntakeListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-receipt-intakes/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchReceiptIntakes(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchReceiptIntakeExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-receipt-intake") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-receipt-intake")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		intake, err := app.secureCellService.GetGovernmentAgentExecutionLaunchReceiptIntake(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptIntakeResponse{Intake: intake})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchReceiptIntakeExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptIntake) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchReceiptIntakeListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-receipt-intakes.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchReceiptIntakeCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-receipt-intake csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptIntake) [][]string {
	rows := [][]string{{
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
		"monitor_status",
		"can_collect_now",
		"can_collect_after_operator_receipts",
		"receipt_item_count",
		"blocked_receipt_item_count",
		"pending_receipt_item_count",
		"scheduled_receipt_item_count",
		"collectable_receipt_item_count",
		"required_receipt_types",
		"operator_instructions",
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
		"checkpoint_id",
		"checkpoint_kind",
		"receipt_type",
		"item_status",
		"expected_state_transition",
		"required_action",
		"item_due_at",
		"item_evidence_digest",
		"item_evidence_binding_id",
		"checkpoint_digest",
		"item_digest",
		"ledger_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Items) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchReceiptIntakeCSVRow(item, nil))
			continue
		}
		for idx := range item.Items {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchReceiptIntakeCSVRow(item, &item.Items[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeCSVRow(
	intake securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptIntake,
	item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchReceiptIntakeItem,
) []string {
	itemID := ""
	itemSequence := ""
	checkpointID := ""
	checkpointKind := ""
	receiptType := ""
	itemStatus := ""
	expectedStateTransition := ""
	requiredAction := ""
	itemDueAt := ""
	itemEvidenceDigest := ""
	itemEvidenceBindingID := ""
	checkpointDigest := ""
	itemDigest := ""
	if item != nil {
		itemID = item.ItemID
		itemSequence = strconv.Itoa(item.Sequence)
		checkpointID = item.CheckpointID
		checkpointKind = item.CheckpointKind
		receiptType = item.ReceiptType
		itemStatus = string(item.Status)
		expectedStateTransition = item.ExpectedStateTransition
		requiredAction = item.RequiredAction
		itemDueAt = secureCellGovernmentAgentExecutionLaunchReceiptIntakeTime(item.DueAt)
		itemEvidenceDigest = item.EvidenceDigest
		itemEvidenceBindingID = item.EvidenceBindingID
		checkpointDigest = item.CheckpointDigest
		itemDigest = item.ItemDigest
	}
	return []string{
		intake.LedgerID,
		intake.MonitorID,
		intake.OrderID,
		intake.ActivationID,
		intake.CustodyID,
		intake.PackageID,
		intake.CellID,
		intake.Name,
		intake.Jurisdiction,
		intake.ServiceCode,
		intake.ServiceTier,
		string(intake.Status),
		string(intake.MonitorStatus),
		strconv.FormatBool(intake.CanCollectNow),
		strconv.FormatBool(intake.CanCollectAfterOperatorReceipts),
		strconv.Itoa(intake.ReceiptItemCount),
		strconv.Itoa(intake.BlockedReceiptItemCount),
		strconv.Itoa(intake.PendingReceiptItemCount),
		strconv.Itoa(intake.ScheduledReceiptItemCount),
		strconv.Itoa(intake.CollectableReceiptItemCount),
		strings.Join(intake.RequiredReceiptTypes, "|"),
		strings.Join(intake.OperatorInstructions, "|"),
		intake.MonitorDigest,
		intake.OrderDigest,
		intake.ActivationDigest,
		intake.CustodyDigest,
		intake.PackageDigest,
		intake.LaunchDigest,
		intake.ReceiptManifestDigest,
		intake.ReceiptValidationDigest,
		itemID,
		itemSequence,
		checkpointID,
		checkpointKind,
		receiptType,
		itemStatus,
		expectedStateTransition,
		requiredAction,
		itemDueAt,
		itemEvidenceDigest,
		itemEvidenceBindingID,
		checkpointDigest,
		itemDigest,
		intake.LedgerDigest,
		intake.GeneratedAt.UTC().Format(time.RFC3339Nano),
		intake.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptIntakeTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
