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

type secureCellGovernmentAgentExecutionLaunchMonitorResponse struct {
	Monitor *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchMonitor `json:"monitor,omitempty"`
}

type secureCellGovernmentAgentExecutionLaunchMonitorListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchMonitor `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchMonitorGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-monitors" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchMonitors(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchMonitorListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-monitors/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionLaunchMonitors(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchMonitorExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-launch-monitor") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-launch-monitor")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		monitor, err := app.secureCellService.GetGovernmentAgentExecutionLaunchMonitor(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchMonitorResponse{Monitor: monitor})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchMonitorExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchMonitor) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchMonitorListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-monitors.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchMonitorCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-monitor csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchMonitor) [][]string {
	rows := [][]string{{
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
		"order_status",
		"can_monitor_now",
		"can_monitor_after_operator_receipts",
		"can_monitor_autonomous",
		"heartbeat_interval_seconds",
		"runtime_minutes",
		"start_window_opens_at",
		"start_window_expires_at",
		"next_heartbeat_at",
		"checkpoint_count",
		"ready_checkpoint_count",
		"scheduled_checkpoint_count",
		"pending_checkpoint_count",
		"blocked_checkpoint_count",
		"stop_condition_watch_count",
		"critical_stop_watch_count",
		"high_stop_watch_count",
		"return_receipt_count",
		"required_return_receipts",
		"operator_instructions",
		"order_digest",
		"activation_digest",
		"custody_digest",
		"package_digest",
		"launch_digest",
		"receipt_manifest_digest",
		"receipt_validation_digest",
		"checkpoint_id",
		"checkpoint_kind",
		"checkpoint_status",
		"checkpoint_receipt_type",
		"checkpoint_stop_condition_id",
		"checkpoint_due_at",
		"checkpoint_evidence_digest",
		"checkpoint_digest",
		"monitor_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Checkpoints) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchMonitorCSVRow(item, nil))
			continue
		}
		for idx := range item.Checkpoints {
			rows = append(rows, secureCellGovernmentAgentExecutionLaunchMonitorCSVRow(item, &item.Checkpoints[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionLaunchMonitorCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchMonitor,
	checkpoint *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchMonitorCheckpoint,
) []string {
	checkpointID := ""
	checkpointKind := ""
	checkpointStatus := ""
	checkpointReceiptType := ""
	checkpointStopConditionID := ""
	checkpointDueAt := ""
	checkpointEvidenceDigest := ""
	checkpointDigest := ""
	if checkpoint != nil {
		checkpointID = checkpoint.CheckpointID
		checkpointKind = checkpoint.Kind
		checkpointStatus = string(checkpoint.Status)
		checkpointReceiptType = checkpoint.ReceiptType
		checkpointStopConditionID = checkpoint.StopConditionID
		checkpointDueAt = secureCellGovernmentAgentExecutionLaunchMonitorTime(checkpoint.DueAt)
		checkpointEvidenceDigest = checkpoint.EvidenceDigest
		checkpointDigest = checkpoint.CheckpointDigest
	}
	return []string{
		item.MonitorID,
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
		string(item.OrderStatus),
		strconv.FormatBool(item.CanMonitorNow),
		strconv.FormatBool(item.CanMonitorAfterOperatorReceipts),
		strconv.FormatBool(item.CanMonitorAutonomous),
		strconv.Itoa(item.HeartbeatIntervalSeconds),
		strconv.Itoa(item.RuntimeMinutes),
		item.StartWindowOpensAt.UTC().Format(time.RFC3339Nano),
		item.StartWindowExpiresAt.UTC().Format(time.RFC3339Nano),
		item.NextHeartbeatAt.UTC().Format(time.RFC3339Nano),
		strconv.Itoa(item.CheckpointCount),
		strconv.Itoa(item.ReadyCheckpointCount),
		strconv.Itoa(item.ScheduledCheckpointCount),
		strconv.Itoa(item.PendingCheckpointCount),
		strconv.Itoa(item.BlockedCheckpointCount),
		strconv.Itoa(item.StopConditionWatchCount),
		strconv.Itoa(item.CriticalStopWatchCount),
		strconv.Itoa(item.HighStopWatchCount),
		strconv.Itoa(item.ReturnReceiptCount),
		strings.Join(item.RequiredReturnReceipts, "|"),
		strings.Join(item.OperatorInstructions, "|"),
		item.OrderDigest,
		item.ActivationDigest,
		item.CustodyDigest,
		item.PackageDigest,
		item.LaunchDigest,
		item.ReceiptManifestDigest,
		item.ReceiptValidationDigest,
		checkpointID,
		checkpointKind,
		checkpointStatus,
		checkpointReceiptType,
		checkpointStopConditionID,
		checkpointDueAt,
		checkpointEvidenceDigest,
		checkpointDigest,
		item.MonitorDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func secureCellGovernmentAgentExecutionLaunchMonitorTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
