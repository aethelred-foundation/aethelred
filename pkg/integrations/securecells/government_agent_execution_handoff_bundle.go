package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionHandoffBundleStatus describes whether a
// service workflow can be handed to an executor package.
type SecureCellGovernmentAgentExecutionHandoffBundleStatus string

const (
	SecureCellGovernmentAgentExecutionHandoffBundleBlocked                SecureCellGovernmentAgentExecutionHandoffBundleStatus = "blocked"
	SecureCellGovernmentAgentExecutionHandoffBundleOperatorReviewRequired SecureCellGovernmentAgentExecutionHandoffBundleStatus = "operator_review_required"
	SecureCellGovernmentAgentExecutionHandoffBundleReady                  SecureCellGovernmentAgentExecutionHandoffBundleStatus = "ready_for_handoff"
)

// SecureCellGovernmentAgentExecutionHandoffBundle is the portable package an
// operator can review before any government-service execution handoff.
type SecureCellGovernmentAgentExecutionHandoffBundle struct {
	BundleID                   string                                                `json:"bundle_id"`
	BundleVersion              string                                                `json:"bundle_version"`
	CellID                     string                                                `json:"cell_id"`
	Name                       string                                                `json:"name"`
	Jurisdiction               string                                                `json:"jurisdiction,omitempty"`
	ServiceCode                string                                                `json:"service_code,omitempty"`
	ServiceTier                string                                                `json:"service_tier,omitempty"`
	Status                     SecureCellGovernmentAgentExecutionHandoffBundleStatus `json:"status"`
	CarryMode                  SecureCellGovernmentAgentCarryMode                    `json:"carry_mode"`
	CanHandoff                 bool                                                  `json:"can_handoff"`
	CanAutonomousHandoff       bool                                                  `json:"can_autonomous_handoff"`
	RequiresOperatorReview     bool                                                  `json:"requires_operator_review"`
	BlockedActionCount         int                                                   `json:"blocked_action_count"`
	ReleaseGateActionCount     int                                                   `json:"release_gate_action_count"`
	ReceiptCollectionCount     int                                                   `json:"receipt_collection_count"`
	EscalationRecommendedCount int                                                   `json:"escalation_recommended_count"`
	ReceiptObligationCount     int                                                   `json:"receipt_obligation_count"`
	RequiredReceiptTypes       []string                                              `json:"required_receipt_types,omitempty"`
	TopBlockerCodes            []string                                              `json:"top_blocker_codes,omitempty"`
	MissingPreconditions       []string                                              `json:"missing_preconditions,omitempty"`
	OperatorInstructions       []string                                              `json:"operator_instructions,omitempty"`
	Witness                    SecureCellGovernmentAgentExecutionWitness             `json:"witness"`
	ReceiptLedger              SecureCellGovernmentAgentExecutionReceiptLedger       `json:"receipt_ledger"`
	ActionQueue                SecureCellGovernmentAgentExecutionActionQueue         `json:"action_queue"`
	WitnessDigest              string                                                `json:"witness_digest"`
	LedgerDigest               string                                                `json:"ledger_digest"`
	QueueDigest                string                                                `json:"queue_digest"`
	BundleDigest               string                                                `json:"bundle_digest"`
	GeneratedAt                time.Time                                             `json:"generated_at"`
	UpdatedAt                  time.Time                                             `json:"updated_at"`
}

// GetGovernmentAgentExecutionHandoffBundle returns the handoff bundle for one
// secure cell.
func (s *Service) GetGovernmentAgentExecutionHandoffBundle(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionHandoffBundle, error) {
	items, err := s.ListGovernmentAgentExecutionHandoffBundles(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-handoff: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionHandoffBundles returns portable handoff bundles
// for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionHandoffBundles(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionHandoffBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-handoff: service is required")
	}
	witnesses, err := s.ListGovernmentAgentExecutionWitnesses(ctx, filter)
	if err != nil {
		return nil, err
	}
	ledgers, err := s.ListGovernmentAgentExecutionReceiptLedgers(ctx, filter)
	if err != nil {
		return nil, err
	}
	queues, err := s.ListGovernmentAgentExecutionActionQueues(ctx, filter)
	if err != nil {
		return nil, err
	}
	ledgerByCellID := make(map[string]SecureCellGovernmentAgentExecutionReceiptLedger, len(ledgers))
	for _, ledger := range ledgers {
		ledgerByCellID[ledger.CellID] = ledger
	}
	queueByCellID := make(map[string]SecureCellGovernmentAgentExecutionActionQueue, len(queues))
	for _, queue := range queues {
		queueByCellID[queue.CellID] = queue
	}
	now := time.Now().UTC()
	bundles := make([]SecureCellGovernmentAgentExecutionHandoffBundle, 0, len(witnesses))
	for _, witness := range witnesses {
		ledger, ledgerOK := ledgerByCellID[witness.CellID]
		queue, queueOK := queueByCellID[witness.CellID]
		if !ledgerOK || !queueOK {
			continue
		}
		bundles = append(bundles, secureCellGovernmentAgentExecutionHandoffBundle(witness, ledger, queue, now))
	}
	sort.SliceStable(bundles, func(i, j int) bool {
		if bundles[i].Status == bundles[j].Status {
			if bundles[i].BlockedActionCount == bundles[j].BlockedActionCount {
				return bundles[i].CellID < bundles[j].CellID
			}
			return bundles[i].BlockedActionCount > bundles[j].BlockedActionCount
		}
		return secureCellGovernmentAgentExecutionHandoffBundleStatusRank(bundles[i].Status) < secureCellGovernmentAgentExecutionHandoffBundleStatusRank(bundles[j].Status)
	})
	return bundles, nil
}

func secureCellGovernmentAgentExecutionHandoffBundle(
	witness SecureCellGovernmentAgentExecutionWitness,
	ledger SecureCellGovernmentAgentExecutionReceiptLedger,
	queue SecureCellGovernmentAgentExecutionActionQueue,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionHandoffBundle {
	bundle := SecureCellGovernmentAgentExecutionHandoffBundle{
		BundleVersion:              "secure-cell-government-agent-execution-handoff/v1",
		CellID:                     witness.CellID,
		Name:                       witness.Name,
		Jurisdiction:               witness.Jurisdiction,
		ServiceCode:                witness.ServiceCode,
		ServiceTier:                witness.ServiceTier,
		CarryMode:                  witness.CarryMode,
		CanAutonomousHandoff:       witness.ReadyForAutonomousHandoff && queue.BlockedActionCount == 0 && queue.OverdueActionCount == 0 && queue.ReleaseGateActionCount == 0,
		BlockedActionCount:         queue.BlockedActionCount,
		ReleaseGateActionCount:     queue.ReleaseGateActionCount,
		ReceiptCollectionCount:     queue.ReceiptCollectionCount,
		EscalationRecommendedCount: queue.EscalationRecommendedCount,
		ReceiptObligationCount:     ledger.ReceiptObligationCount,
		RequiredReceiptTypes:       append([]string(nil), ledger.ReceiptTypes...),
		TopBlockerCodes:            append([]string(nil), queue.TopBlockerCodes...),
		MissingPreconditions:       append([]string(nil), queue.MissingPreconditions...),
		Witness:                    witness,
		ReceiptLedger:              ledger,
		ActionQueue:                queue,
		WitnessDigest:              witness.WitnessDigest,
		LedgerDigest:               ledger.LedgerDigest,
		QueueDigest:                queue.QueueDigest,
		GeneratedAt:                generatedAt.UTC(),
		UpdatedAt:                  witness.UpdatedAt.UTC(),
	}
	bundle.RequiresOperatorReview = queue.ReleaseGateActionCount > 0 || queue.OverdueActionCount > 0 || witness.Status == SecureCellGovernmentAgentExecutionWitnessOperatorAttestationRequired
	bundle.CanHandoff = queue.BlockedActionCount == 0 && queue.OverdueActionCount == 0
	bundle.Status = secureCellGovernmentAgentExecutionHandoffBundleStatus(bundle)
	bundle.OperatorInstructions = secureCellGovernmentAgentExecutionHandoffInstructions(bundle)
	bundle.BundleDigest = secureCellGovernmentAgentExecutionHandoffBundleDigest(bundle)
	bundle.BundleID = "government-agent-execution-handoff:" + bundle.CellID + ":" + bundle.BundleDigest[:12]
	return bundle
}

func secureCellGovernmentAgentExecutionHandoffBundleStatus(bundle SecureCellGovernmentAgentExecutionHandoffBundle) SecureCellGovernmentAgentExecutionHandoffBundleStatus {
	if bundle.BlockedActionCount > 0 {
		return SecureCellGovernmentAgentExecutionHandoffBundleBlocked
	}
	if bundle.RequiresOperatorReview {
		return SecureCellGovernmentAgentExecutionHandoffBundleOperatorReviewRequired
	}
	return SecureCellGovernmentAgentExecutionHandoffBundleReady
}

func secureCellGovernmentAgentExecutionHandoffInstructions(bundle SecureCellGovernmentAgentExecutionHandoffBundle) []string {
	instructions := make([]string, 0, 5)
	if bundle.BlockedActionCount > 0 {
		instructions = append(instructions, "Resolve blocked actions and regenerate the handoff bundle before execution.")
	}
	if bundle.ReleaseGateActionCount > 0 {
		instructions = append(instructions, "Complete release-gate approvals and operator attestations before execution.")
	}
	if bundle.EscalationRecommendedCount > 0 {
		instructions = append(instructions, "Escalate overdue receipt obligations using the listed escalation targets.")
	}
	if bundle.ReceiptCollectionCount > 0 {
		instructions = append(instructions, "Collect and verify every required receipt against its evidence binding.")
	}
	if len(instructions) == 0 {
		instructions = append(instructions, "Handoff is ready once the execution operator preserves all listed receipt bindings.")
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionHandoffBundleStatusRank(status SecureCellGovernmentAgentExecutionHandoffBundleStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionHandoffBundleBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionHandoffBundleOperatorReviewRequired:
		return 1
	case SecureCellGovernmentAgentExecutionHandoffBundleReady:
		return 2
	default:
		return 3
	}
}
