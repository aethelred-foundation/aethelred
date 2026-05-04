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

type secureCellGovernmentAgentExecutionLaunchCloseoutResponse struct {
	Closeout *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCloseoutRegister `json:"closeout,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchCloseoutListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCloseoutRegister `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchCloseoutGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closeouts" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchCloseouts(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchCloseoutListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closeouts/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchCloseouts(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchCloseoutExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-closeout") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-closeout")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		closeout, err := app.secureCellService.GetGovernmentAgentExecutionLaunchCloseout(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchCloseoutResponse{Closeout: closeout})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchCloseoutExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCloseoutRegister) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchCloseoutListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closeouts.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchCloseoutCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closeout csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCloseoutRegister) [][]string {
	rows := [][]string{{
		"register_id",
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
		"intake_status",
		"monitor_status",
		"can_close_now",
		"can_close_after_runtime_receipts",
		"can_escalate_blocked",
		"gate_count",
		"blocked_gate_count",
		"operator_receipt_gate_count",
		"runtime_receipt_gate_count",
		"ready_gate_count",
		"stop_condition_gate_count",
		"heartbeat_gate_count",
		"return_receipt_gate_count",
		"required_receipt_types",
		"operator_instructions",
		"ledger_digest",
		"monitor_digest",
		"order_digest",
		"activation_digest",
		"custody_digest",
		"package_digest",
		"launch_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"gate_id",
		"gate_sequence",
		"intake_item_id",
		"checkpoint_id",
		"gate_kind",
		"receipt_type",
		"gate_status",
		"decision",
		"required_action",
		"gate_due_at",
		"evidence_binding_id",
		"evidence_digest",
		"intake_item_digest",
		"checkpoint_digest",
		"gate_digest",
		"register_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Gates) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchCloseoutCSVRow(item, nil))
			continue
		}
		for idx := range item.Gates {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchCloseoutCSVRow(item, &item.Gates[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchCloseoutCSVRow(
	closeout securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCloseoutRegister,
	gate *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchCloseoutGate,
) []string {
	gateID := ""
	gateSequence := ""
	intakeItemID := ""
	checkpointID := ""
	gateKind := ""
	receiptType := ""
	gateStatus := ""
	decision := ""
	requiredAction := ""
	gateDueAt := ""
	evidenceBindingID := ""
	evidenceDigest := ""
	intakeItemDigest := ""
	checkpointDigest := ""
	gateDigest := ""
	if gate != nil {
		gateID = gate.GateID
		gateSequence = strconv.Itoa(gate.Sequence)
		intakeItemID = gate.IntakeItemID
		checkpointID = gate.CheckpointID
		gateKind = gate.GateKind
		receiptType = gate.ReceiptType
		gateStatus = string(gate.Status)
		decision = string(gate.Decision)
		requiredAction = gate.RequiredAction
		gateDueAt = secureCellGovernmentAgentExecutionLaunchCloseoutTime(gate.DueAt)
		evidenceBindingID = gate.EvidenceBindingID
		evidenceDigest = gate.EvidenceDigest
		intakeItemDigest = gate.IntakeItemDigest
		checkpointDigest = gate.CheckpointDigest
		gateDigest = gate.GateDigest
	}
	return []string{
		closeout.RegisterID,
		closeout.LedgerID,
		closeout.MonitorID,
		closeout.OrderID,
		closeout.ActivationID,
		closeout.CustodyID,
		closeout.PackageID,
		closeout.CellID,
		closeout.Name,
		closeout.Jurisdiction,
		closeout.ServiceCode,
		closeout.ServiceTier,
		string(closeout.Status),
		string(closeout.IntakeStatus),
		string(closeout.MonitorStatus),
		strconv.FormatBool(closeout.CanCloseNow),
		strconv.FormatBool(closeout.CanCloseAfterRuntimeReceipts),
		strconv.FormatBool(closeout.CanEscalateBlocked),
		strconv.Itoa(closeout.GateCount),
		strconv.Itoa(closeout.BlockedGateCount),
		strconv.Itoa(closeout.OperatorReceiptGateCount),
		strconv.Itoa(closeout.RuntimeReceiptGateCount),
		strconv.Itoa(closeout.ReadyGateCount),
		strconv.Itoa(closeout.StopConditionGateCount),
		strconv.Itoa(closeout.HeartbeatGateCount),
		strconv.Itoa(closeout.ReturnReceiptGateCount),
		strings.Join(closeout.RequiredReceiptTypes, "|"),
		strings.Join(closeout.OperatorInstructions, "|"),
		closeout.LedgerDigest,
		closeout.MonitorDigest,
		closeout.OrderDigest,
		closeout.ActivationDigest,
		closeout.CustodyDigest,
		closeout.PackageDigest,
		closeout.LaunchDigest,
		closeout.ReceiptManifestDigest,
		closeout.ReceiptValidationDigest,
		gateID,
		gateSequence,
		intakeItemID,
		checkpointID,
		gateKind,
		receiptType,
		gateStatus,
		decision,
		requiredAction,
		gateDueAt,
		evidenceBindingID,
		evidenceDigest,
		intakeItemDigest,
		checkpointDigest,
		gateDigest,
		closeout.RegisterDigest,
		closeout.GeneratedAt.UTC().Format(time.RFC3339Nano),
		closeout.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchCloseoutTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
