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

type secureCellGovernmentAgentExecutionWitnessResponse struct {
	Witness *securecellsintegration.SecureCellGovernmentAgentExecutionWitness `json:"witness,omitempty"`
}

type secureCellGovernmentAgentExecutionWitnessListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionWitness `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionWitnessGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-witnesses" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionWitnesses(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionWitnessListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-witnesses/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionWitnesses(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionWitnessExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-witness") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-witness")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		witness, err := app.secureCellService.GetGovernmentAgentExecutionWitness(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionWitnessResponse{Witness: witness})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionWitnessExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionWitness) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionWitnessListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-witnesses.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionWitnessCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-witness csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionWitnessCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionWitness) [][]string {
	rows := [][]string{{
		"witness_id",
		"cell_id",
		"carry_pack_id",
		"rehearsal_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"carry_mode",
		"rehearsal_status",
		"ready_for_execution_handoff",
		"ready_for_supervised_handoff",
		"ready_for_autonomous_handoff",
		"execution_witness_score",
		"step_count",
		"executable_step_count",
		"release_gate_count",
		"expected_return_receipt_count",
		"blocked_step_count",
		"handoff_blocker_count",
		"operator_attestation_count",
		"top_blocker_codes",
		"missing_preconditions",
		"operator_attestations",
		"ingress_evidence",
		"egress_receipts",
		"required_input_evidence",
		"expected_return_receipts",
		"step_sequence",
		"step_id",
		"step_kind",
		"step_lane",
		"step_name",
		"step_action",
		"step_can_execute",
		"step_release_gate",
		"step_release_gate_reasons",
		"step_return_required",
		"step_expected_state_transition",
		"step_allowed_tools",
		"step_blocker_codes",
		"step_expected_return_receipts",
		"step_due_at",
		"witness_digest",
		"rehearsal_digest",
		"carry_pack_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Steps) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionWitnessCSVRow(item, nil))
			continue
		}
		for idx := range item.Steps {
			rows = append(rows, secureCellGovernmentAgentExecutionWitnessCSVRow(item, &item.Steps[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionWitnessCSVRow(item securecellsintegration.SecureCellGovernmentAgentExecutionWitness, step *securecellsintegration.SecureCellGovernmentAgentExecutionWitnessStep) []string {
	stepSequence := ""
	stepID := ""
	stepKind := ""
	stepLane := ""
	stepName := ""
	stepAction := ""
	stepCanExecute := ""
	stepReleaseGate := ""
	stepReleaseGateReasons := ""
	stepReturnRequired := ""
	stepExpectedStateTransition := ""
	stepAllowedTools := ""
	stepBlockerCodes := ""
	stepExpectedReceipts := ""
	stepDueAt := ""
	if step != nil {
		stepSequence = strconv.Itoa(step.Sequence)
		stepID = step.StepID
		stepKind = string(step.Kind)
		stepLane = string(step.Lane)
		stepName = step.Name
		stepAction = step.Action
		stepCanExecute = strconv.FormatBool(step.CanExecute)
		stepReleaseGate = strconv.FormatBool(step.ReleaseGate)
		stepReleaseGateReasons = strings.Join(step.ReleaseGateReasons, "|")
		stepReturnRequired = strconv.FormatBool(step.ReturnRequired)
		stepExpectedStateTransition = step.ExpectedStateTransition
		stepAllowedTools = strings.Join(step.AllowedTools, "|")
		stepBlockerCodes = strings.Join(step.BlockerCodes, "|")
		stepExpectedReceipts = strings.Join(step.ExpectedReturnReceipts, "|")
		if step.DueAt != nil {
			stepDueAt = step.DueAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return []string{
		item.WitnessID,
		item.CellID,
		item.CarryPackID,
		item.RehearsalID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.CarryMode),
		string(item.RehearsalStatus),
		strconv.FormatBool(item.ReadyForExecutionHandoff),
		strconv.FormatBool(item.ReadyForSupervisedHandoff),
		strconv.FormatBool(item.ReadyForAutonomousHandoff),
		strconv.Itoa(item.ExecutionWitnessScore),
		strconv.Itoa(item.StepCount),
		strconv.Itoa(item.ExecutableStepCount),
		strconv.Itoa(item.ReleaseGateCount),
		strconv.Itoa(item.ExpectedReturnReceiptCount),
		strconv.Itoa(item.BlockedStepCount),
		strconv.Itoa(item.HandoffBlockerCount),
		strconv.Itoa(item.OperatorAttestationCount),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.MissingPreconditions, "|"),
		strings.Join(item.OperatorAttestations, "|"),
		strings.Join(item.IngressEvidence, "|"),
		strings.Join(item.EgressReceipts, "|"),
		strings.Join(item.RequiredInputEvidence, "|"),
		strings.Join(item.ExpectedReturnReceipts, "|"),
		stepSequence,
		stepID,
		stepKind,
		stepLane,
		stepName,
		stepAction,
		stepCanExecute,
		stepReleaseGate,
		stepReleaseGateReasons,
		stepReturnRequired,
		stepExpectedStateTransition,
		stepAllowedTools,
		stepBlockerCodes,
		stepExpectedReceipts,
		stepDueAt,
		item.WitnessDigest,
		item.RehearsalDigest,
		item.CarryPackDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
