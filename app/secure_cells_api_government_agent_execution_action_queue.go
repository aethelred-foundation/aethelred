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

type secureCellGovernmentAgentExecutionActionQueueResponse struct {
	Queue *securecellsintegration.SecureCellGovernmentAgentExecutionActionQueue `json:"queue,omitempty"`
}

type secureCellGovernmentAgentExecutionActionQueueListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionActionQueue `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionActionQueueGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-action-queues" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionActionQueues(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionActionQueueListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-action-queues/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionActionQueues(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionActionQueueExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-action-queue") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-action-queue")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		queue, err := app.secureCellService.GetGovernmentAgentExecutionActionQueue(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionActionQueueResponse{Queue: queue})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionActionQueueExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionActionQueue) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionActionQueueListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-action-queues.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionActionQueueCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-action-queue csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionActionQueueCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionActionQueue) [][]string {
	rows := [][]string{{
		"queue_id",
		"cell_id",
		"ledger_id",
		"witness_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"ledger_status",
		"action_count",
		"blocked_action_count",
		"overdue_action_count",
		"due_action_count",
		"release_gate_action_count",
		"receipt_collection_count",
		"escalation_recommended_count",
		"top_blocker_codes",
		"missing_preconditions",
		"action_id",
		"action_kind",
		"action_status",
		"action_priority",
		"receipt_type",
		"step_id",
		"step_name",
		"step_lane",
		"action",
		"reason",
		"expected_state_transition",
		"release_gate_reasons",
		"required_input_evidence",
		"blocker_codes",
		"due_at",
		"escalation_targets",
		"escalation_recommended",
		"evidence_binding_id",
		"obligation_id",
		"obligation_digest",
		"action_digest",
		"queue_digest",
		"ledger_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Actions) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionActionQueueCSVRow(item, nil))
			continue
		}
		for idx := range item.Actions {
			rows = append(rows, secureCellGovernmentAgentExecutionActionQueueCSVRow(item, &item.Actions[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionActionQueueCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionActionQueue,
	action *securecellsintegration.SecureCellGovernmentAgentExecutionAction,
) []string {
	actionID := ""
	actionKind := ""
	actionStatus := ""
	actionPriority := ""
	receiptType := ""
	stepID := ""
	stepName := ""
	stepLane := ""
	actionText := ""
	reason := ""
	expectedStateTransition := ""
	releaseGateReasons := ""
	requiredInputEvidence := ""
	blockerCodes := ""
	dueAt := ""
	escalationTargets := ""
	escalationRecommended := ""
	evidenceBindingID := ""
	obligationID := ""
	obligationDigest := ""
	actionDigest := ""
	if action != nil {
		actionID = action.ActionID
		actionKind = string(action.Kind)
		actionStatus = string(action.Status)
		actionPriority = string(action.Priority)
		receiptType = action.ReceiptType
		stepID = action.StepID
		stepName = action.StepName
		stepLane = string(action.StepLane)
		actionText = action.Action
		reason = action.Reason
		expectedStateTransition = action.ExpectedStateTransition
		releaseGateReasons = strings.Join(action.ReleaseGateReasons, "|")
		requiredInputEvidence = strings.Join(action.RequiredInputEvidence, "|")
		blockerCodes = strings.Join(action.BlockerCodes, "|")
		if action.DueAt != nil {
			dueAt = action.DueAt.UTC().Format(time.RFC3339Nano)
		}
		escalationTargets = strings.Join(action.EscalationTargets, "|")
		escalationRecommended = strconv.FormatBool(action.EscalationRecommended)
		evidenceBindingID = action.EvidenceBindingID
		obligationID = action.ObligationID
		obligationDigest = action.ObligationDigest
		actionDigest = action.ActionDigest
	}
	return []string{
		item.QueueID,
		item.CellID,
		item.LedgerID,
		item.WitnessID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.LedgerStatus),
		strconv.Itoa(item.ActionCount),
		strconv.Itoa(item.BlockedActionCount),
		strconv.Itoa(item.OverdueActionCount),
		strconv.Itoa(item.DueActionCount),
		strconv.Itoa(item.ReleaseGateActionCount),
		strconv.Itoa(item.ReceiptCollectionCount),
		strconv.Itoa(item.EscalationRecommendedCount),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.MissingPreconditions, "|"),
		actionID,
		actionKind,
		actionStatus,
		actionPriority,
		receiptType,
		stepID,
		stepName,
		stepLane,
		actionText,
		reason,
		expectedStateTransition,
		releaseGateReasons,
		requiredInputEvidence,
		blockerCodes,
		dueAt,
		escalationTargets,
		escalationRecommended,
		evidenceBindingID,
		obligationID,
		obligationDigest,
		actionDigest,
		item.QueueDigest,
		item.LedgerDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
