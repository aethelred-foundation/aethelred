package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionReceiptLedgerStatus describes the
// collection posture for the receipts expected by an execution witness.
type SecureCellGovernmentAgentExecutionReceiptLedgerStatus string

const (
	SecureCellGovernmentAgentExecutionReceiptLedgerBlocked        SecureCellGovernmentAgentExecutionReceiptLedgerStatus = "blocked"
	SecureCellGovernmentAgentExecutionReceiptLedgerReleaseGateDue SecureCellGovernmentAgentExecutionReceiptLedgerStatus = "release_gate_due"
	SecureCellGovernmentAgentExecutionReceiptLedgerReceiptDue     SecureCellGovernmentAgentExecutionReceiptLedgerStatus = "receipt_due"
)

// SecureCellGovernmentAgentExecutionReceiptObligationStatus describes one
// expected receipt before any executor is allowed to claim completion.
type SecureCellGovernmentAgentExecutionReceiptObligationStatus string

const (
	SecureCellGovernmentAgentExecutionReceiptObligationBlocked        SecureCellGovernmentAgentExecutionReceiptObligationStatus = "blocked"
	SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue SecureCellGovernmentAgentExecutionReceiptObligationStatus = "release_gate_due"
	SecureCellGovernmentAgentExecutionReceiptObligationReceiptDue     SecureCellGovernmentAgentExecutionReceiptObligationStatus = "receipt_due"
)

// SecureCellGovernmentAgentExecutionReceiptObligation is one receipt the
// operator must collect, verify, or remediate for a handoff step.
type SecureCellGovernmentAgentExecutionReceiptObligation struct {
	ObligationID            string                                                    `json:"obligation_id"`
	CellID                  string                                                    `json:"cell_id"`
	WitnessID               string                                                    `json:"witness_id"`
	StepID                  string                                                    `json:"step_id,omitempty"`
	Sequence                int                                                       `json:"sequence"`
	StepName                string                                                    `json:"step_name,omitempty"`
	StepKind                SecureCellGovernmentAgentWorkflowStepKind                 `json:"step_kind,omitempty"`
	StepLane                SecureCellGovernmentAgentCarryLane                        `json:"step_lane,omitempty"`
	ReceiptType             string                                                    `json:"receipt_type"`
	Status                  SecureCellGovernmentAgentExecutionReceiptObligationStatus `json:"status"`
	ExpectedStateTransition string                                                    `json:"expected_state_transition,omitempty"`
	ReleaseGate             bool                                                      `json:"release_gate"`
	ReleaseGateReasons      []string                                                  `json:"release_gate_reasons,omitempty"`
	RequiredInputEvidence   []string                                                  `json:"required_input_evidence,omitempty"`
	AllowedTools            []string                                                  `json:"allowed_tools,omitempty"`
	BlockerCodes            []string                                                  `json:"blocker_codes,omitempty"`
	DueAt                   *time.Time                                                `json:"due_at,omitempty"`
	EscalationTargets       []string                                                  `json:"escalation_targets,omitempty"`
	EvidenceBindingID       string                                                    `json:"evidence_binding_id"`
	ObligationDigest        string                                                    `json:"obligation_digest"`
	GeneratedAt             time.Time                                                 `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionReceiptLedger is the operator-facing
// matrix of receipt obligations generated from an execution witness.
type SecureCellGovernmentAgentExecutionReceiptLedger struct {
	LedgerID                   string                                                `json:"ledger_id"`
	CellID                     string                                                `json:"cell_id"`
	WitnessID                  string                                                `json:"witness_id"`
	CarryPackID                string                                                `json:"carry_pack_id"`
	RehearsalID                string                                                `json:"rehearsal_id"`
	Name                       string                                                `json:"name"`
	Jurisdiction               string                                                `json:"jurisdiction,omitempty"`
	ServiceCode                string                                                `json:"service_code,omitempty"`
	ServiceTier                string                                                `json:"service_tier,omitempty"`
	Status                     SecureCellGovernmentAgentExecutionReceiptLedgerStatus `json:"status"`
	WitnessStatus              SecureCellGovernmentAgentExecutionWitnessStatus       `json:"witness_status"`
	CarryMode                  SecureCellGovernmentAgentCarryMode                    `json:"carry_mode"`
	ReceiptObligationCount     int                                                   `json:"receipt_obligation_count"`
	BlockedReceiptCount        int                                                   `json:"blocked_receipt_count"`
	ReleaseGateReceiptCount    int                                                   `json:"release_gate_receipt_count"`
	ReceiptDueCount            int                                                   `json:"receipt_due_count"`
	HumanApprovalReceiptCount  int                                                   `json:"human_approval_receipt_count"`
	OperatorAttestationCount   int                                                   `json:"operator_attestation_count"`
	ToolInvocationReceiptCount int                                                   `json:"tool_invocation_receipt_count"`
	SLAReceiptCount            int                                                   `json:"sla_receipt_count"`
	EscalationReceiptCount     int                                                   `json:"escalation_receipt_count"`
	ReceiptTypes               []string                                              `json:"receipt_types,omitempty"`
	TopBlockerCodes            []string                                              `json:"top_blocker_codes,omitempty"`
	MissingPreconditions       []string                                              `json:"missing_preconditions,omitempty"`
	Obligations                []SecureCellGovernmentAgentExecutionReceiptObligation `json:"obligations"`
	WitnessDigest              string                                                `json:"witness_digest"`
	LedgerDigest               string                                                `json:"ledger_digest"`
	GeneratedAt                time.Time                                             `json:"generated_at"`
	UpdatedAt                  time.Time                                             `json:"updated_at"`
}

// GetGovernmentAgentExecutionReceiptLedger returns the receipt obligation ledger
// for one secure cell.
func (s *Service) GetGovernmentAgentExecutionReceiptLedger(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionReceiptLedger, error) {
	items, err := s.ListGovernmentAgentExecutionReceiptLedgers(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-receipts: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionReceiptLedgers returns receipt obligation ledgers
// for matching government-service execution witnesses.
func (s *Service) ListGovernmentAgentExecutionReceiptLedgers(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionReceiptLedger, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-receipts: service is required")
	}
	witnesses, err := s.ListGovernmentAgentExecutionWitnesses(ctx, filter)
	if err != nil {
		return nil, err
	}
	ledgers := make([]SecureCellGovernmentAgentExecutionReceiptLedger, 0, len(witnesses))
	now := time.Now().UTC()
	for _, witness := range witnesses {
		ledgers = append(ledgers, secureCellGovernmentAgentExecutionReceiptLedger(witness, now))
	}
	sort.SliceStable(ledgers, func(i, j int) bool {
		if ledgers[i].Status == ledgers[j].Status {
			if ledgers[i].BlockedReceiptCount == ledgers[j].BlockedReceiptCount {
				return ledgers[i].CellID < ledgers[j].CellID
			}
			return ledgers[i].BlockedReceiptCount > ledgers[j].BlockedReceiptCount
		}
		return secureCellGovernmentAgentExecutionReceiptLedgerStatusRank(ledgers[i].Status) < secureCellGovernmentAgentExecutionReceiptLedgerStatusRank(ledgers[j].Status)
	})
	return ledgers, nil
}

func secureCellGovernmentAgentExecutionReceiptLedger(
	witness SecureCellGovernmentAgentExecutionWitness,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionReceiptLedger {
	obligations := make([]SecureCellGovernmentAgentExecutionReceiptObligation, 0, witness.ExpectedReturnReceiptCount)
	coveredReceipts := make(map[string]struct{})
	for _, step := range witness.Steps {
		for _, receiptType := range step.ExpectedReturnReceipts {
			coveredReceipts[receiptType] = struct{}{}
			obligations = append(obligations, secureCellGovernmentAgentExecutionReceiptObligation(witness, step, receiptType, generatedAt))
		}
	}
	for _, receiptType := range witness.ExpectedReturnReceipts {
		if _, ok := coveredReceipts[receiptType]; ok {
			continue
		}
		obligations = append(obligations, secureCellGovernmentAgentExecutionGlobalReceiptObligation(witness, receiptType, generatedAt))
	}
	sort.SliceStable(obligations, func(i, j int) bool {
		if obligations[i].Sequence == obligations[j].Sequence {
			if obligations[i].StepID == obligations[j].StepID {
				return obligations[i].ReceiptType < obligations[j].ReceiptType
			}
			return obligations[i].StepID < obligations[j].StepID
		}
		return obligations[i].Sequence < obligations[j].Sequence
	})

	ledger := SecureCellGovernmentAgentExecutionReceiptLedger{
		CellID:               witness.CellID,
		WitnessID:            witness.WitnessID,
		CarryPackID:          witness.CarryPackID,
		RehearsalID:          witness.RehearsalID,
		Name:                 witness.Name,
		Jurisdiction:         witness.Jurisdiction,
		ServiceCode:          witness.ServiceCode,
		ServiceTier:          witness.ServiceTier,
		WitnessStatus:        witness.Status,
		CarryMode:            witness.CarryMode,
		TopBlockerCodes:      append([]string(nil), witness.TopBlockerCodes...),
		MissingPreconditions: append([]string(nil), witness.MissingPreconditions...),
		Obligations:          obligations,
		WitnessDigest:        witness.WitnessDigest,
		GeneratedAt:          generatedAt.UTC(),
		UpdatedAt:            witness.UpdatedAt.UTC(),
	}
	receiptTypes := make([]string, 0, len(obligations))
	for _, obligation := range ledger.Obligations {
		ledger.ReceiptObligationCount++
		receiptTypes = append(receiptTypes, obligation.ReceiptType)
		switch obligation.Status {
		case SecureCellGovernmentAgentExecutionReceiptObligationBlocked:
			ledger.BlockedReceiptCount++
		case SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue:
			ledger.ReleaseGateReceiptCount++
		default:
			ledger.ReceiptDueCount++
		}
		switch obligation.ReceiptType {
		case "human_approval_receipt":
			ledger.HumanApprovalReceiptCount++
		case "operator_attestation_receipt":
			ledger.OperatorAttestationCount++
		case "tool_invocation_receipt":
			ledger.ToolInvocationReceiptCount++
		case "sla_timer_receipt":
			ledger.SLAReceiptCount++
		case "escalation_path_receipt":
			ledger.EscalationReceiptCount++
		}
	}
	ledger.ReceiptTypes = uniqueSortedStrings(receiptTypes)
	ledger.Status = secureCellGovernmentAgentExecutionReceiptLedgerStatus(ledger)
	obligationDigests := make([]string, 0, len(ledger.Obligations))
	for _, obligation := range ledger.Obligations {
		obligationDigests = append(obligationDigests, obligation.ObligationDigest)
	}
	core := struct {
		CellID               string                                                `json:"cell_id"`
		WitnessID            string                                                `json:"witness_id"`
		Status               SecureCellGovernmentAgentExecutionReceiptLedgerStatus `json:"status"`
		ReceiptTypes         []string                                              `json:"receipt_types,omitempty"`
		TopBlockerCodes      []string                                              `json:"top_blocker_codes,omitempty"`
		MissingPreconditions []string                                              `json:"missing_preconditions,omitempty"`
		ObligationDigests    []string                                              `json:"obligation_digests"`
		WitnessDigest        string                                                `json:"witness_digest"`
	}{
		CellID:               ledger.CellID,
		WitnessID:            ledger.WitnessID,
		Status:               ledger.Status,
		ReceiptTypes:         ledger.ReceiptTypes,
		TopBlockerCodes:      ledger.TopBlockerCodes,
		MissingPreconditions: ledger.MissingPreconditions,
		ObligationDigests:    obligationDigests,
		WitnessDigest:        ledger.WitnessDigest,
	}
	ledger.LedgerDigest = EvidenceHash(core)
	ledger.LedgerID = "government-agent-execution-receipts:" + ledger.CellID + ":" + ledger.LedgerDigest[:12]
	return ledger
}

func secureCellGovernmentAgentExecutionReceiptObligation(
	witness SecureCellGovernmentAgentExecutionWitness,
	step SecureCellGovernmentAgentExecutionWitnessStep,
	receiptType string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionReceiptObligation {
	obligation := SecureCellGovernmentAgentExecutionReceiptObligation{
		CellID:                  witness.CellID,
		WitnessID:               witness.WitnessID,
		StepID:                  step.StepID,
		Sequence:                step.Sequence,
		StepName:                step.Name,
		StepKind:                step.Kind,
		StepLane:                step.Lane,
		ReceiptType:             strings.TrimSpace(receiptType),
		Status:                  secureCellGovernmentAgentExecutionReceiptObligationStatus(witness, step),
		ExpectedStateTransition: step.ExpectedStateTransition,
		ReleaseGate:             step.ReleaseGate,
		ReleaseGateReasons:      append([]string(nil), step.ReleaseGateReasons...),
		RequiredInputEvidence:   append([]string(nil), step.RequiredInputEvidence...),
		AllowedTools:            append([]string(nil), step.AllowedTools...),
		BlockerCodes:            append([]string(nil), step.BlockerCodes...),
		DueAt:                   cloneTimePtr(step.DueAt),
		EscalationTargets:       append([]string(nil), step.EscalationTargets...),
		GeneratedAt:             generatedAt.UTC(),
	}
	return secureCellGovernmentAgentFinalizeReceiptObligation(witness, obligation)
}

func secureCellGovernmentAgentExecutionGlobalReceiptObligation(
	witness SecureCellGovernmentAgentExecutionWitness,
	receiptType string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionReceiptObligation {
	obligation := SecureCellGovernmentAgentExecutionReceiptObligation{
		CellID:                  witness.CellID,
		WitnessID:               witness.WitnessID,
		ReceiptType:             strings.TrimSpace(receiptType),
		Status:                  SecureCellGovernmentAgentExecutionReceiptObligationBlocked,
		ExpectedStateTransition: "blocked_to_ready_after_resolution",
		ReleaseGate:             true,
		ReleaseGateReasons:      []string{"blocker_resolution_required"},
		RequiredInputEvidence:   append([]string(nil), witness.IngressEvidence...),
		BlockerCodes:            append([]string(nil), witness.TopBlockerCodes...),
		GeneratedAt:             generatedAt.UTC(),
	}
	return secureCellGovernmentAgentFinalizeReceiptObligation(witness, obligation)
}

func secureCellGovernmentAgentFinalizeReceiptObligation(
	witness SecureCellGovernmentAgentExecutionWitness,
	obligation SecureCellGovernmentAgentExecutionReceiptObligation,
) SecureCellGovernmentAgentExecutionReceiptObligation {
	core := struct {
		CellID                  string                                                    `json:"cell_id"`
		WitnessID               string                                                    `json:"witness_id"`
		StepID                  string                                                    `json:"step_id,omitempty"`
		Sequence                int                                                       `json:"sequence"`
		ReceiptType             string                                                    `json:"receipt_type"`
		Status                  SecureCellGovernmentAgentExecutionReceiptObligationStatus `json:"status"`
		ExpectedStateTransition string                                                    `json:"expected_state_transition,omitempty"`
		ReleaseGateReasons      []string                                                  `json:"release_gate_reasons,omitempty"`
		RequiredInputEvidence   []string                                                  `json:"required_input_evidence,omitempty"`
		BlockerCodes            []string                                                  `json:"blocker_codes,omitempty"`
		WitnessDigest           string                                                    `json:"witness_digest"`
	}{
		CellID:                  obligation.CellID,
		WitnessID:               obligation.WitnessID,
		StepID:                  obligation.StepID,
		Sequence:                obligation.Sequence,
		ReceiptType:             obligation.ReceiptType,
		Status:                  obligation.Status,
		ExpectedStateTransition: obligation.ExpectedStateTransition,
		ReleaseGateReasons:      obligation.ReleaseGateReasons,
		RequiredInputEvidence:   obligation.RequiredInputEvidence,
		BlockerCodes:            obligation.BlockerCodes,
		WitnessDigest:           witness.WitnessDigest,
	}
	obligation.ObligationDigest = EvidenceHash(core)
	obligation.EvidenceBindingID = "government-agent-evidence-binding:" + obligation.ObligationDigest[:16]
	obligation.ObligationID = "government-agent-execution-receipt:" + obligation.CellID + ":" + obligation.ObligationDigest[:12]
	return obligation
}

func secureCellGovernmentAgentExecutionReceiptObligationStatus(
	witness SecureCellGovernmentAgentExecutionWitness,
	step SecureCellGovernmentAgentExecutionWitnessStep,
) SecureCellGovernmentAgentExecutionReceiptObligationStatus {
	if witness.Status == SecureCellGovernmentAgentExecutionWitnessBlocked || !step.CanExecute || step.Outcome == SecureCellGovernmentAgentRehearsalOutcomeBlock {
		return SecureCellGovernmentAgentExecutionReceiptObligationBlocked
	}
	if step.ReleaseGate {
		return SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue
	}
	return SecureCellGovernmentAgentExecutionReceiptObligationReceiptDue
}

func secureCellGovernmentAgentExecutionReceiptLedgerStatus(ledger SecureCellGovernmentAgentExecutionReceiptLedger) SecureCellGovernmentAgentExecutionReceiptLedgerStatus {
	if ledger.BlockedReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionReceiptLedgerBlocked
	}
	if ledger.ReleaseGateReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionReceiptLedgerReleaseGateDue
	}
	return SecureCellGovernmentAgentExecutionReceiptLedgerReceiptDue
}

func secureCellGovernmentAgentExecutionReceiptLedgerStatusRank(status SecureCellGovernmentAgentExecutionReceiptLedgerStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionReceiptLedgerBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionReceiptLedgerReleaseGateDue:
		return 1
	case SecureCellGovernmentAgentExecutionReceiptLedgerReceiptDue:
		return 2
	default:
		return 3
	}
}
