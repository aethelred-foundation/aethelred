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

type secureCellGovernmentAgentExecutionReceiptLedgerResponse struct {
	Ledger *securecellsintegration.SecureCellGovernmentAgentExecutionReceiptLedger `json:"ledger,omitempty"`
}

type secureCellGovernmentAgentExecutionReceiptLedgerListResponse struct {
	Items []securecellsintegration.SecureCellGovernmentAgentExecutionReceiptLedger `json:"items"`
}

func (app *AethelredApp) handleSecureCellGovernmentAgentExecutionReceiptLedgerGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-receipt-ledgers" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionReceiptLedgers(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionReceiptLedgerListResponse{Items: items})
		return true
	}

	if r.URL.Path == secureCellsCollectionRoute+"/government-agent-execution-receipt-ledgers/export" {
		filter, err := parseSecureCellGovernmentAgentProgramFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		items, err := app.secureCellService.ListGovernmentAgentExecutionReceiptLedgers(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return true
		}
		if err := writeSecureCellGovernmentAgentExecutionReceiptLedgerExport(w, r, items); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
		}
		return true
	}

	if strings.HasPrefix(r.URL.Path, secureCellsItemPrefix) && strings.HasSuffix(r.URL.Path, "/government-agent-execution-receipt-ledger") {
		cellID, err := parseSecureCellID(r.URL.Path, "/government-agent-execution-receipt-ledger")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return true
		}
		ledger, err := app.secureCellService.GetGovernmentAgentExecutionReceiptLedger(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusNotFound), err.Error())
			return true
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionReceiptLedgerResponse{Ledger: ledger})
		return true
	}

	return false
}

func writeSecureCellGovernmentAgentExecutionReceiptLedgerExport(w http.ResponseWriter, r *http.Request, items []securecellsintegration.SecureCellGovernmentAgentExecutionReceiptLedger) error {
	format := secureCellExportFormat(r)
	switch format {
	case "json":
		writeSecureCellJSON(w, http.StatusOK, secureCellGovernmentAgentExecutionReceiptLedgerListResponse{Items: items})
		return nil
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="secure-cell-government-agent-execution-receipt-ledgers.csv"`)
		writer := csv.NewWriter(w)
		for _, row := range secureCellGovernmentAgentExecutionReceiptLedgerCSVRows(items) {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write government-agent-execution-receipt-ledger csv row: %w", err)
			}
		}
		writer.Flush()
		return writer.Error()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func secureCellGovernmentAgentExecutionReceiptLedgerCSVRows(items []securecellsintegration.SecureCellGovernmentAgentExecutionReceiptLedger) [][]string {
	rows := [][]string{{
		"ledger_id",
		"cell_id",
		"witness_id",
		"carry_pack_id",
		"rehearsal_id",
		"name",
		"jurisdiction",
		"service_code",
		"service_tier",
		"status",
		"witness_status",
		"carry_mode",
		"receipt_obligation_count",
		"blocked_receipt_count",
		"release_gate_receipt_count",
		"receipt_due_count",
		"human_approval_receipt_count",
		"operator_attestation_count",
		"tool_invocation_receipt_count",
		"sla_receipt_count",
		"escalation_receipt_count",
		"receipt_types",
		"top_blocker_codes",
		"missing_preconditions",
		"obligation_id",
		"obligation_status",
		"receipt_type",
		"step_sequence",
		"step_id",
		"step_name",
		"step_kind",
		"step_lane",
		"expected_state_transition",
		"release_gate",
		"release_gate_reasons",
		"required_input_evidence",
		"allowed_tools",
		"blocker_codes",
		"due_at",
		"escalation_targets",
		"evidence_binding_id",
		"obligation_digest",
		"ledger_digest",
		"witness_digest",
		"generated_at",
		"updated_at",
	}}
	for _, item := range items {
		if len(item.Obligations) == 0 {
			rows = append(rows, secureCellGovernmentAgentExecutionReceiptLedgerCSVRow(item, nil))
			continue
		}
		for idx := range item.Obligations {
			rows = append(rows, secureCellGovernmentAgentExecutionReceiptLedgerCSVRow(item, &item.Obligations[idx]))
		}
	}
	return rows
}

func secureCellGovernmentAgentExecutionReceiptLedgerCSVRow(
	item securecellsintegration.SecureCellGovernmentAgentExecutionReceiptLedger,
	obligation *securecellsintegration.SecureCellGovernmentAgentExecutionReceiptObligation,
) []string {
	obligationID := ""
	obligationStatus := ""
	receiptType := ""
	stepSequence := ""
	stepID := ""
	stepName := ""
	stepKind := ""
	stepLane := ""
	expectedStateTransition := ""
	releaseGate := ""
	releaseGateReasons := ""
	requiredInputEvidence := ""
	allowedTools := ""
	blockerCodes := ""
	dueAt := ""
	escalationTargets := ""
	evidenceBindingID := ""
	obligationDigest := ""
	if obligation != nil {
		obligationID = obligation.ObligationID
		obligationStatus = string(obligation.Status)
		receiptType = obligation.ReceiptType
		stepSequence = strconv.Itoa(obligation.Sequence)
		stepID = obligation.StepID
		stepName = obligation.StepName
		stepKind = string(obligation.StepKind)
		stepLane = string(obligation.StepLane)
		expectedStateTransition = obligation.ExpectedStateTransition
		releaseGate = strconv.FormatBool(obligation.ReleaseGate)
		releaseGateReasons = strings.Join(obligation.ReleaseGateReasons, "|")
		requiredInputEvidence = strings.Join(obligation.RequiredInputEvidence, "|")
		allowedTools = strings.Join(obligation.AllowedTools, "|")
		blockerCodes = strings.Join(obligation.BlockerCodes, "|")
		if obligation.DueAt != nil {
			dueAt = obligation.DueAt.UTC().Format(time.RFC3339Nano)
		}
		escalationTargets = strings.Join(obligation.EscalationTargets, "|")
		evidenceBindingID = obligation.EvidenceBindingID
		obligationDigest = obligation.ObligationDigest
	}
	return []string{
		item.LedgerID,
		item.CellID,
		item.WitnessID,
		item.CarryPackID,
		item.RehearsalID,
		item.Name,
		item.Jurisdiction,
		item.ServiceCode,
		item.ServiceTier,
		string(item.Status),
		string(item.WitnessStatus),
		string(item.CarryMode),
		strconv.Itoa(item.ReceiptObligationCount),
		strconv.Itoa(item.BlockedReceiptCount),
		strconv.Itoa(item.ReleaseGateReceiptCount),
		strconv.Itoa(item.ReceiptDueCount),
		strconv.Itoa(item.HumanApprovalReceiptCount),
		strconv.Itoa(item.OperatorAttestationCount),
		strconv.Itoa(item.ToolInvocationReceiptCount),
		strconv.Itoa(item.SLAReceiptCount),
		strconv.Itoa(item.EscalationReceiptCount),
		strings.Join(item.ReceiptTypes, "|"),
		strings.Join(item.TopBlockerCodes, "|"),
		strings.Join(item.MissingPreconditions, "|"),
		obligationID,
		obligationStatus,
		receiptType,
		stepSequence,
		stepID,
		stepName,
		stepKind,
		stepLane,
		expectedStateTransition,
		releaseGate,
		releaseGateReasons,
		requiredInputEvidence,
		allowedTools,
		blockerCodes,
		dueAt,
		escalationTargets,
		evidenceBindingID,
		obligationDigest,
		item.LedgerDigest,
		item.WitnessDigest,
		item.GeneratedAt.UTC().Format(time.RFC3339Nano),
		item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
