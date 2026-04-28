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

type secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketResponse struct {
	Packet *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket `json:"packet,omitempty"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-packet" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		packet, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationPacket(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketResponse{Packet: packet})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-launch-closure-automation-packet/export" {
		filter, err := parseSecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		packet, err := app.secureCellService.GetGovernmentAgentExecutionLaunchClosureAutomationPacket(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketExport(w, r, packet); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketExport(w http.ResponseWriter, r *http.Request, packet *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketResponse{Packet: packet})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-launch-closure-automation-packet.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketCSVRows(packet) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-launch-closure-automation-packet csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationPacketCSVRows(packet *securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacket) [][]string {
	rows := [][]string{{
		"packet_id",
		"board_id",
		"summary_id",
		"jurisdiction",
		"service_code_filter",
		"service_tier_filter",
		"evaluated_at",
		"focus_lane",
		"focus_action",
		"cell_count",
		"item_count",
		"step_sequence",
		"step_lane",
		"step_pending_action",
		"step_automation_action",
		"step_instruction",
		"step_cell_ids",
		"item_cell_id",
		"item_name",
		"item_lane",
		"item_pending_action",
		"item_automation_action",
		"item_action_priority",
		"item_due_at",
		"item_overdue_seconds",
		"item_escalation_needed",
		"item_action_digest",
		"packet_digest",
		"board_digest",
		"generated_at",
	}}
	if packet == nil {
		return rows
	}
	if len(packet.Items) == 0 && len(packet.Steps) == 0 {
		rows = append(rows, []string{
			packet.PacketID,
			packet.BoardID,
			packet.SummaryID,
			packet.Jurisdiction,
			packet.ServiceCode,
			packet.ServiceTier,
			packet.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(packet.FocusLane),
			packet.FocusAction,
			strconv.Itoa(packet.CellCount),
			strconv.Itoa(packet.ItemCount),
			"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
			packet.PacketDigest,
			packet.BoardDigest,
			packet.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
		return rows
	}
	steps := packet.Steps
	if len(steps) == 0 {
		steps = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep{{}}
	}
	items := packet.Items
	if len(items) == 0 {
		items = []securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem{{}}
	}
	maxLen := len(steps)
	if len(items) > maxLen {
		maxLen = len(items)
	}
	for i := 0; i < maxLen; i++ {
		var step securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationPacketStep
		var item securecellsintegration.SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem
		if i < len(steps) {
			step = steps[i]
		}
		if i < len(items) {
			item = items[i]
		}
		dueAt := ""
		if item.DueAt != nil {
			dueAt = item.DueAt.UTC().Format(time.RFC3339Nano)
		}
		stepSequence := ""
		if step.Sequence > 0 {
			stepSequence = strconv.Itoa(step.Sequence)
		}
		rows = append(rows, []string{
			packet.PacketID,
			packet.BoardID,
			packet.SummaryID,
			packet.Jurisdiction,
			packet.ServiceCode,
			packet.ServiceTier,
			packet.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			string(packet.FocusLane),
			packet.FocusAction,
			strconv.Itoa(packet.CellCount),
			strconv.Itoa(packet.ItemCount),
			stepSequence,
			step.Lane,
			step.PendingAction,
			step.AutomationAction,
			step.Instruction,
			strings.Join(step.CellIDs, "|"),
			item.CellID,
			item.Name,
			string(item.Lane),
			item.PendingAction,
			item.AutomationAction,
			string(item.ActionPriority),
			dueAt,
			strconv.FormatInt(item.OverdueSeconds, 10),
			strconv.FormatBool(item.EscalationNeeded),
			item.ActionDigest,
			packet.PacketDigest,
			packet.BoardDigest,
			packet.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}
