package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionActionQueueStatus describes the operator
// posture for closing an execution receipt ledger.
type SecureCellGovernmentAgentExecutionActionQueueStatus string

const (
	SecureCellGovernmentAgentExecutionActionQueueBlocked SecureCellGovernmentAgentExecutionActionQueueStatus = "blocked"
	SecureCellGovernmentAgentExecutionActionQueueOverdue SecureCellGovernmentAgentExecutionActionQueueStatus = "overdue"
	SecureCellGovernmentAgentExecutionActionQueueDue     SecureCellGovernmentAgentExecutionActionQueueStatus = "due"
)

// SecureCellGovernmentAgentExecutionActionKind tells operators what action is
// needed before an execution handoff can be treated as complete.
type SecureCellGovernmentAgentExecutionActionKind string

const (
	SecureCellGovernmentAgentExecutionActionResolveBlocker     SecureCellGovernmentAgentExecutionActionKind = "resolve_blocker"
	SecureCellGovernmentAgentExecutionActionApproveReleaseGate SecureCellGovernmentAgentExecutionActionKind = "approve_release_gate"
	SecureCellGovernmentAgentExecutionActionCollectReceipt     SecureCellGovernmentAgentExecutionActionKind = "collect_receipt"
)

// SecureCellGovernmentAgentExecutionActionPriority is the operator urgency for
// an execution action.
type SecureCellGovernmentAgentExecutionActionPriority string

const (
	SecureCellGovernmentAgentExecutionActionPriorityCritical SecureCellGovernmentAgentExecutionActionPriority = "critical"
	SecureCellGovernmentAgentExecutionActionPriorityHigh     SecureCellGovernmentAgentExecutionActionPriority = "high"
	SecureCellGovernmentAgentExecutionActionPriorityMedium   SecureCellGovernmentAgentExecutionActionPriority = "medium"
)

// SecureCellGovernmentAgentExecutionAction is one operator command derived
// from a receipt obligation.
type SecureCellGovernmentAgentExecutionAction struct {
	ActionID                string                                              `json:"action_id"`
	CellID                  string                                              `json:"cell_id"`
	LedgerID                string                                              `json:"ledger_id"`
	WitnessID               string                                              `json:"witness_id"`
	ObligationID            string                                              `json:"obligation_id"`
	Kind                    SecureCellGovernmentAgentExecutionActionKind        `json:"kind"`
	Status                  SecureCellGovernmentAgentExecutionActionQueueStatus `json:"status"`
	Priority                SecureCellGovernmentAgentExecutionActionPriority    `json:"priority"`
	ReceiptType             string                                              `json:"receipt_type"`
	StepID                  string                                              `json:"step_id,omitempty"`
	StepName                string                                              `json:"step_name,omitempty"`
	StepLane                SecureCellGovernmentAgentCarryLane                  `json:"step_lane,omitempty"`
	Action                  string                                              `json:"action"`
	Reason                  string                                              `json:"reason"`
	ExpectedStateTransition string                                              `json:"expected_state_transition,omitempty"`
	ReleaseGateReasons      []string                                            `json:"release_gate_reasons,omitempty"`
	RequiredInputEvidence   []string                                            `json:"required_input_evidence,omitempty"`
	BlockerCodes            []string                                            `json:"blocker_codes,omitempty"`
	DueAt                   *time.Time                                          `json:"due_at,omitempty"`
	EscalationTargets       []string                                            `json:"escalation_targets,omitempty"`
	EscalationRecommended   bool                                                `json:"escalation_recommended"`
	EvidenceBindingID       string                                              `json:"evidence_binding_id"`
	ObligationDigest        string                                              `json:"obligation_digest"`
	ActionDigest            string                                              `json:"action_digest"`
	GeneratedAt             time.Time                                           `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionActionQueue is the operator-ready queue of
// next actions for one government-service execution ledger.
type SecureCellGovernmentAgentExecutionActionQueue struct {
	QueueID                    string                                                `json:"queue_id"`
	CellID                     string                                                `json:"cell_id"`
	LedgerID                   string                                                `json:"ledger_id"`
	WitnessID                  string                                                `json:"witness_id"`
	Name                       string                                                `json:"name"`
	Jurisdiction               string                                                `json:"jurisdiction,omitempty"`
	ServiceCode                string                                                `json:"service_code,omitempty"`
	ServiceTier                string                                                `json:"service_tier,omitempty"`
	Status                     SecureCellGovernmentAgentExecutionActionQueueStatus   `json:"status"`
	LedgerStatus               SecureCellGovernmentAgentExecutionReceiptLedgerStatus `json:"ledger_status"`
	ActionCount                int                                                   `json:"action_count"`
	BlockedActionCount         int                                                   `json:"blocked_action_count"`
	OverdueActionCount         int                                                   `json:"overdue_action_count"`
	DueActionCount             int                                                   `json:"due_action_count"`
	ReleaseGateActionCount     int                                                   `json:"release_gate_action_count"`
	ReceiptCollectionCount     int                                                   `json:"receipt_collection_count"`
	EscalationRecommendedCount int                                                   `json:"escalation_recommended_count"`
	TopBlockerCodes            []string                                              `json:"top_blocker_codes,omitempty"`
	MissingPreconditions       []string                                              `json:"missing_preconditions,omitempty"`
	Actions                    []SecureCellGovernmentAgentExecutionAction            `json:"actions"`
	LedgerDigest               string                                                `json:"ledger_digest"`
	QueueDigest                string                                                `json:"queue_digest"`
	GeneratedAt                time.Time                                             `json:"generated_at"`
	UpdatedAt                  time.Time                                             `json:"updated_at"`
}

// GetGovernmentAgentExecutionActionQueue returns the operator action queue for
// one secure cell.
func (s *Service) GetGovernmentAgentExecutionActionQueue(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionActionQueue, error) {
	items, err := s.ListGovernmentAgentExecutionActionQueues(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-actions: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionActionQueues returns operator action queues for
// matching government-service execution ledgers.
func (s *Service) ListGovernmentAgentExecutionActionQueues(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionActionQueue, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-actions: service is required")
	}
	ledgers, err := s.ListGovernmentAgentExecutionReceiptLedgers(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	queues := make([]SecureCellGovernmentAgentExecutionActionQueue, 0, len(ledgers))
	for _, ledger := range ledgers {
		queues = append(queues, secureCellGovernmentAgentExecutionActionQueue(ledger, now))
	}
	sort.SliceStable(queues, func(i, j int) bool {
		if queues[i].Status == queues[j].Status {
			if queues[i].ActionCount == queues[j].ActionCount {
				return queues[i].CellID < queues[j].CellID
			}
			return queues[i].ActionCount > queues[j].ActionCount
		}
		return secureCellGovernmentAgentExecutionActionQueueStatusRank(queues[i].Status) < secureCellGovernmentAgentExecutionActionQueueStatusRank(queues[j].Status)
	})
	return queues, nil
}

func secureCellGovernmentAgentExecutionActionQueue(
	ledger SecureCellGovernmentAgentExecutionReceiptLedger,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionActionQueue {
	actions := make([]SecureCellGovernmentAgentExecutionAction, 0, len(ledger.Obligations))
	for _, obligation := range ledger.Obligations {
		actions = append(actions, secureCellGovernmentAgentExecutionAction(ledger, obligation, generatedAt))
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Status == actions[j].Status {
			if actions[i].Priority == actions[j].Priority {
				if actions[i].DueAt == nil || actions[j].DueAt == nil {
					if actions[i].DueAt == nil && actions[j].DueAt != nil {
						return false
					}
					if actions[i].DueAt != nil && actions[j].DueAt == nil {
						return true
					}
					return actions[i].ActionID < actions[j].ActionID
				}
				return actions[i].DueAt.Before(*actions[j].DueAt)
			}
			return secureCellGovernmentAgentExecutionActionPriorityRank(actions[i].Priority) < secureCellGovernmentAgentExecutionActionPriorityRank(actions[j].Priority)
		}
		return secureCellGovernmentAgentExecutionActionQueueStatusRank(actions[i].Status) < secureCellGovernmentAgentExecutionActionQueueStatusRank(actions[j].Status)
	})

	queue := SecureCellGovernmentAgentExecutionActionQueue{
		CellID:               ledger.CellID,
		LedgerID:             ledger.LedgerID,
		WitnessID:            ledger.WitnessID,
		Name:                 ledger.Name,
		Jurisdiction:         ledger.Jurisdiction,
		ServiceCode:          ledger.ServiceCode,
		ServiceTier:          ledger.ServiceTier,
		LedgerStatus:         ledger.Status,
		TopBlockerCodes:      append([]string(nil), ledger.TopBlockerCodes...),
		MissingPreconditions: append([]string(nil), ledger.MissingPreconditions...),
		Actions:              actions,
		LedgerDigest:         ledger.LedgerDigest,
		GeneratedAt:          generatedAt.UTC(),
		UpdatedAt:            ledger.UpdatedAt.UTC(),
	}
	for _, action := range queue.Actions {
		queue.ActionCount++
		switch action.Status {
		case SecureCellGovernmentAgentExecutionActionQueueBlocked:
			queue.BlockedActionCount++
		case SecureCellGovernmentAgentExecutionActionQueueOverdue:
			queue.OverdueActionCount++
		default:
			queue.DueActionCount++
		}
		switch action.Kind {
		case SecureCellGovernmentAgentExecutionActionApproveReleaseGate:
			queue.ReleaseGateActionCount++
		case SecureCellGovernmentAgentExecutionActionCollectReceipt:
			queue.ReceiptCollectionCount++
		}
		if action.EscalationRecommended {
			queue.EscalationRecommendedCount++
		}
	}
	queue.Status = secureCellGovernmentAgentExecutionActionQueueStatus(queue)
	actionDigests := make([]string, 0, len(queue.Actions))
	for _, action := range queue.Actions {
		actionDigests = append(actionDigests, action.ActionDigest)
	}
	core := struct {
		CellID               string                                              `json:"cell_id"`
		LedgerID             string                                              `json:"ledger_id"`
		Status               SecureCellGovernmentAgentExecutionActionQueueStatus `json:"status"`
		TopBlockerCodes      []string                                            `json:"top_blocker_codes,omitempty"`
		MissingPreconditions []string                                            `json:"missing_preconditions,omitempty"`
		ActionDigests        []string                                            `json:"action_digests"`
		LedgerDigest         string                                              `json:"ledger_digest"`
	}{
		CellID:               queue.CellID,
		LedgerID:             queue.LedgerID,
		Status:               queue.Status,
		TopBlockerCodes:      queue.TopBlockerCodes,
		MissingPreconditions: queue.MissingPreconditions,
		ActionDigests:        actionDigests,
		LedgerDigest:         queue.LedgerDigest,
	}
	queue.QueueDigest = EvidenceHash(core)
	queue.QueueID = "government-agent-execution-actions:" + queue.CellID + ":" + queue.QueueDigest[:12]
	return queue
}

func secureCellGovernmentAgentExecutionAction(
	ledger SecureCellGovernmentAgentExecutionReceiptLedger,
	obligation SecureCellGovernmentAgentExecutionReceiptObligation,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionAction {
	action := SecureCellGovernmentAgentExecutionAction{
		CellID:                  ledger.CellID,
		LedgerID:                ledger.LedgerID,
		WitnessID:               ledger.WitnessID,
		ObligationID:            obligation.ObligationID,
		Kind:                    secureCellGovernmentAgentExecutionActionKind(obligation),
		Status:                  secureCellGovernmentAgentExecutionActionStatus(obligation, generatedAt),
		Priority:                secureCellGovernmentAgentExecutionActionPriority(obligation, generatedAt),
		ReceiptType:             obligation.ReceiptType,
		StepID:                  obligation.StepID,
		StepName:                obligation.StepName,
		StepLane:                obligation.StepLane,
		Action:                  secureCellGovernmentAgentExecutionActionText(obligation),
		Reason:                  secureCellGovernmentAgentExecutionActionReason(obligation),
		ExpectedStateTransition: obligation.ExpectedStateTransition,
		ReleaseGateReasons:      append([]string(nil), obligation.ReleaseGateReasons...),
		RequiredInputEvidence:   append([]string(nil), obligation.RequiredInputEvidence...),
		BlockerCodes:            append([]string(nil), obligation.BlockerCodes...),
		DueAt:                   cloneTimePtr(obligation.DueAt),
		EscalationTargets:       append([]string(nil), obligation.EscalationTargets...),
		EvidenceBindingID:       obligation.EvidenceBindingID,
		ObligationDigest:        obligation.ObligationDigest,
		GeneratedAt:             generatedAt.UTC(),
	}
	action.EscalationRecommended = action.Status == SecureCellGovernmentAgentExecutionActionQueueOverdue && len(action.EscalationTargets) > 0
	core := struct {
		CellID             string                                              `json:"cell_id"`
		LedgerID           string                                              `json:"ledger_id"`
		ObligationID       string                                              `json:"obligation_id"`
		Kind               SecureCellGovernmentAgentExecutionActionKind        `json:"kind"`
		Status             SecureCellGovernmentAgentExecutionActionQueueStatus `json:"status"`
		Priority           SecureCellGovernmentAgentExecutionActionPriority    `json:"priority"`
		ReceiptType        string                                              `json:"receipt_type"`
		ReleaseGateReasons []string                                            `json:"release_gate_reasons,omitempty"`
		BlockerCodes       []string                                            `json:"blocker_codes,omitempty"`
		ObligationDigest   string                                              `json:"obligation_digest"`
		LedgerDigest       string                                              `json:"ledger_digest"`
	}{
		CellID:             action.CellID,
		LedgerID:           action.LedgerID,
		ObligationID:       action.ObligationID,
		Kind:               action.Kind,
		Status:             action.Status,
		Priority:           action.Priority,
		ReceiptType:        action.ReceiptType,
		ReleaseGateReasons: action.ReleaseGateReasons,
		BlockerCodes:       action.BlockerCodes,
		ObligationDigest:   action.ObligationDigest,
		LedgerDigest:       ledger.LedgerDigest,
	}
	action.ActionDigest = EvidenceHash(core)
	action.ActionID = "government-agent-execution-action:" + action.CellID + ":" + action.ActionDigest[:12]
	return action
}

func secureCellGovernmentAgentExecutionActionKind(obligation SecureCellGovernmentAgentExecutionReceiptObligation) SecureCellGovernmentAgentExecutionActionKind {
	switch obligation.Status {
	case SecureCellGovernmentAgentExecutionReceiptObligationBlocked:
		return SecureCellGovernmentAgentExecutionActionResolveBlocker
	case SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue:
		return SecureCellGovernmentAgentExecutionActionApproveReleaseGate
	default:
		return SecureCellGovernmentAgentExecutionActionCollectReceipt
	}
}

func secureCellGovernmentAgentExecutionActionStatus(
	obligation SecureCellGovernmentAgentExecutionReceiptObligation,
	now time.Time,
) SecureCellGovernmentAgentExecutionActionQueueStatus {
	if obligation.Status == SecureCellGovernmentAgentExecutionReceiptObligationBlocked {
		return SecureCellGovernmentAgentExecutionActionQueueBlocked
	}
	if obligation.DueAt != nil && obligation.DueAt.UTC().Before(now.UTC()) {
		return SecureCellGovernmentAgentExecutionActionQueueOverdue
	}
	return SecureCellGovernmentAgentExecutionActionQueueDue
}

func secureCellGovernmentAgentExecutionActionPriority(
	obligation SecureCellGovernmentAgentExecutionReceiptObligation,
	now time.Time,
) SecureCellGovernmentAgentExecutionActionPriority {
	if obligation.Status == SecureCellGovernmentAgentExecutionReceiptObligationBlocked {
		return SecureCellGovernmentAgentExecutionActionPriorityCritical
	}
	if obligation.DueAt != nil && obligation.DueAt.UTC().Before(now.UTC()) {
		return SecureCellGovernmentAgentExecutionActionPriorityCritical
	}
	if obligation.Status == SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue || len(obligation.EscalationTargets) > 0 {
		return SecureCellGovernmentAgentExecutionActionPriorityHigh
	}
	return SecureCellGovernmentAgentExecutionActionPriorityMedium
}

func secureCellGovernmentAgentExecutionActionText(obligation SecureCellGovernmentAgentExecutionReceiptObligation) string {
	switch obligation.Status {
	case SecureCellGovernmentAgentExecutionReceiptObligationBlocked:
		return "Resolve blockers and regenerate the execution witness before accepting this receipt."
	case SecureCellGovernmentAgentExecutionReceiptObligationReleaseGateDue:
		return "Complete the release gate and attach the required receipt to the evidence binding."
	default:
		return "Collect and verify the receipt against the evidence binding."
	}
}

func secureCellGovernmentAgentExecutionActionReason(obligation SecureCellGovernmentAgentExecutionReceiptObligation) string {
	if len(obligation.BlockerCodes) > 0 {
		return "Blocked by " + strings.Join(obligation.BlockerCodes, ",")
	}
	if len(obligation.ReleaseGateReasons) > 0 {
		return "Release gate requires " + strings.Join(obligation.ReleaseGateReasons, ",")
	}
	return "Receipt is required for " + obligation.ExpectedStateTransition
}

func secureCellGovernmentAgentExecutionActionQueueStatus(queue SecureCellGovernmentAgentExecutionActionQueue) SecureCellGovernmentAgentExecutionActionQueueStatus {
	if queue.BlockedActionCount > 0 {
		return SecureCellGovernmentAgentExecutionActionQueueBlocked
	}
	if queue.OverdueActionCount > 0 {
		return SecureCellGovernmentAgentExecutionActionQueueOverdue
	}
	return SecureCellGovernmentAgentExecutionActionQueueDue
}

func secureCellGovernmentAgentExecutionActionQueueStatusRank(status SecureCellGovernmentAgentExecutionActionQueueStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionActionQueueBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionActionQueueOverdue:
		return 1
	case SecureCellGovernmentAgentExecutionActionQueueDue:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionActionPriorityRank(priority SecureCellGovernmentAgentExecutionActionPriority) int {
	switch priority {
	case SecureCellGovernmentAgentExecutionActionPriorityCritical:
		return 0
	case SecureCellGovernmentAgentExecutionActionPriorityHigh:
		return 1
	case SecureCellGovernmentAgentExecutionActionPriorityMedium:
		return 2
	default:
		return 3
	}
}
