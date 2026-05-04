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

type secureCellGovernmentAgentExecutionLaunchClosureBoardResponse struct {
	Board *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureBoard `json:"board,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchClosureBoardListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureBoard `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureBoardGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-boards" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureBoards(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureBoardListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-boards/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchClosureBoards(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureBoardExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closure-board") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closure-board")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		board, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureBoard(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureBoardResponse{Board: board})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureBoardExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureBoard) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureBoardListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-boards.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureBoardCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-board csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureBoard) [][]string {
	rows := [][]string{{
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
		"registry_status",
		"can_close_now",
		"can_close_after_archive_issue",
		"can_escalate_blocked",
		"item_count",
		"blocked_item_count",
		"pending_item_count",
		"ready_item_count",
		"required_receipt_types",
		"operator_instructions",
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
		"item_id",
		"item_sequence",
		"closure_item_id",
		"receipt_type",
		"gate_kind",
		"item_status",
		"board_action",
		"required_action",
		"item_due_at",
		"evidence_binding_id",
		"evidence_digest",
		"closure_item_digest",
		"board_item_digest",
		"board_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Items) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosureBoardCSVRow(item, nil))
			continue
		}
		for idx := range item.Items {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchClosureBoardCSVRow(item, &item.Items[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardCSVRow(
	board securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureBoard,
	item *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureBoardItem,
) []string {
	itemID := ""
	itemSequence := ""
	closureItemID := ""
	receiptType := ""
	gateKind := ""
	itemStatus := ""
	boardAction := ""
	requiredAction := ""
	itemDueAt := ""
	evidenceBindingID := ""
	evidenceDigest := ""
	closureItemDigest := ""
	boardItemDigest := ""
	if item != nil {
		itemID = item.ItemID
		itemSequence = strconv.Itoa(item.Sequence)
		closureItemID = item.ClosureItemID
		receiptType = item.ReceiptType
		gateKind = item.GateKind
		itemStatus = string(item.Status)
		boardAction = item.BoardAction
		requiredAction = item.RequiredAction
		itemDueAt = secureCellGovernmentAgentExecutionLaunchClosureBoardTime(item.DueAt)
		evidenceBindingID = item.EvidenceBindingID
		evidenceDigest = item.EvidenceDigest
		closureItemDigest = item.ClosureItemDigest
		boardItemDigest = item.BoardItemDigest
	}
	return []string{
		board.BoardID,
		board.RegistryID,
		board.CertificateID,
		board.SettlementRegisterID,
		board.CloseoutRegisterID,
		board.LedgerID,
		board.MonitorID,
		board.OrderID,
		board.ActivationID,
		board.CustodyID,
		board.PackageID,
		board.CellID,
		board.Name,
		board.Jurisdiction,
		board.ServiceCode,
		board.ServiceTier,
		string(board.Status),
		string(board.RegistryStatus),
		strconv.FormatBool(board.CanCloseNow),
		strconv.FormatBool(board.CanCloseAfterArchiveIssue),
		strconv.FormatBool(board.CanEscalateBlocked),
		strconv.Itoa(board.ItemCount),
		strconv.Itoa(board.BlockedItemCount),
		strconv.Itoa(board.PendingItemCount),
		strconv.Itoa(board.ReadyItemCount),
		strings.Join(board.RequiredReceiptTypes, "|"),
		strings.Join(board.OperatorInstructions, "|"),
		board.RegistryDigest,
		board.CertificateDigest,
		board.SettlementRegisterDigest,
		board.CloseoutDigest,
		board.LedgerDigest,
		board.MonitorDigest,
		board.OrderDigest,
		board.ActivationDigest,
		board.CustodyDigest,
		board.PackageDigest,
		board.LaunchDigest,
		board.ReceiptManifestDigest,
		board.ReceiptValidationDigest,
		itemID,
		itemSequence,
		closureItemID,
		receiptType,
		gateKind,
		itemStatus,
		boardAction,
		requiredAction,
		itemDueAt,
		evidenceBindingID,
		evidenceDigest,
		closureItemDigest,
		boardItemDigest,
		board.BoardDigest,
		board.GeneratedAt.UTC().Format(time.RFC3339Nano),
		board.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureBoardTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
