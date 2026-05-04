package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusAwaiting   SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus = "awaiting_acceptance_receipt"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue    SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus = "overdue_acceptance_receipt"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus = "escalation_acceptance_receipt"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem
// is one evidence-bearing custody receipt required for an accepted dispatch.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem struct {
	AcceptanceReceiptItemID string                                                                                                                 `json:"acceptance_receipt_item_id"`
	AcceptanceItemID        string                                                                                                                 `json:"acceptance_item_id"`
	DispatchItemID          string                                                                                                                 `json:"dispatch_item_id"`
	QueueItemID             string                                                                                                                 `json:"queue_item_id"`
	Sequence                int                                                                                                                    `json:"sequence"`
	Evidence                string                                                                                                                 `json:"evidence"`
	Status                  SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus `json:"status"`
	Priority                SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority                   `json:"priority"`
	AcceptingRole           string                                                                                                                 `json:"accepting_role,omitempty"`
	ReceiptAction           string                                                                                                                 `json:"receipt_action"`
	ReceiptEvidence         []string                                                                                                               `json:"receipt_evidence,omitempty"`
	AcceptanceChannel       string                                                                                                                 `json:"acceptance_channel"`
	EscalationTarget        string                                                                                                                 `json:"escalation_target,omitempty"`
	PendingActions          []string                                                                                                               `json:"pending_actions,omitempty"`
	CellIDs                 []string                                                                                                               `json:"cell_ids,omitempty"`
	DueAt                   *time.Time                                                                                                             `json:"due_at,omitempty"`
	OverdueSeconds          int64                                                                                                                  `json:"overdue_seconds"`
	AcceptanceItemDigest    string                                                                                                                 `json:"acceptance_item_digest"`
	ReceiptItemDigest       string                                                                                                                 `json:"receipt_item_digest"`
	GeneratedAt             time.Time                                                                                                              `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt
// packages dispatch acceptance custody into receipt obligations operators can query and export.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt struct {
	AcceptanceReceiptID          string                                                                                                                 `json:"acceptance_receipt_id"`
	AcceptanceID                 string                                                                                                                 `json:"acceptance_id"`
	DispatchID                   string                                                                                                                 `json:"dispatch_id"`
	QueueID                      string                                                                                                                 `json:"queue_id"`
	ManifestID                   string                                                                                                                 `json:"manifest_id"`
	AcknowledgementReceiptID     string                                                                                                                 `json:"acknowledgement_receipt_id"`
	AcknowledgementID            string                                                                                                                 `json:"acknowledgement_id"`
	DirectiveID                  string                                                                                                                 `json:"directive_id"`
	ClosureDispatchID            string                                                                                                                 `json:"closure_dispatch_id"`
	BriefID                      string                                                                                                                 `json:"brief_id"`
	RunbookID                    string                                                                                                                 `json:"runbook_id"`
	PacketID                     string                                                                                                                 `json:"packet_id"`
	BoardID                      string                                                                                                                 `json:"board_id"`
	SummaryID                    string                                                                                                                 `json:"summary_id"`
	Jurisdiction                 string                                                                                                                 `json:"jurisdiction,omitempty"`
	ServiceCode                  string                                                                                                                 `json:"service_code,omitempty"`
	ServiceTier                  string                                                                                                                 `json:"service_tier,omitempty"`
	EvaluatedAt                  time.Time                                                                                                              `json:"evaluated_at"`
	FocusLane                    SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                                                     `json:"focus_lane"`
	FocusAction                  string                                                                                                                 `json:"focus_action"`
	Severity                     SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                                                 `json:"severity"`
	DispatchStatus               SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus                  `json:"dispatch_status"`
	AcceptanceStatus             SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus        `json:"acceptance_status"`
	Status                       SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus `json:"status"`
	ReceiptCount                 int                                                                                                                    `json:"receipt_count"`
	AwaitingReceiptCount         int                                                                                                                    `json:"awaiting_receipt_count"`
	OverdueReceiptCount          int                                                                                                                    `json:"overdue_receipt_count"`
	EscalationReceiptCount       int                                                                                                                    `json:"escalation_receipt_count"`
	PrimaryReceiptAction         string                                                                                                                 `json:"primary_receipt_action"`
	Items                        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem `json:"items"`
	AcknowledgementReceiptDigest string                                                                                                                 `json:"acknowledgement_receipt_digest"`
	ManifestDigest               string                                                                                                                 `json:"manifest_digest"`
	QueueDigest                  string                                                                                                                 `json:"queue_digest"`
	DispatchDigest               string                                                                                                                 `json:"dispatch_digest"`
	AcceptanceDigest             string                                                                                                                 `json:"acceptance_digest"`
	AcceptanceReceiptDigest      string                                                                                                                 `json:"acceptance_receipt_digest"`
	GeneratedAt                  time.Time                                                                                                              `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt
// returns evidence-bearing receipt obligations for dispatch acceptance custody.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt: service is required")
	}
	acceptance, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(ctx, filter)
	if err != nil {
		return nil, err
	}
	receipt := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(*acceptance, time.Now().UTC())
	return &receipt, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt(
	acceptance SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt {
	receipt := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt{
		AcceptanceID:                 acceptance.AcceptanceID,
		DispatchID:                   acceptance.DispatchID,
		QueueID:                      acceptance.QueueID,
		ManifestID:                   acceptance.ManifestID,
		AcknowledgementReceiptID:     acceptance.AcknowledgementReceiptID,
		AcknowledgementID:            acceptance.AcknowledgementID,
		DirectiveID:                  acceptance.DirectiveID,
		ClosureDispatchID:            acceptance.ClosureDispatchID,
		BriefID:                      acceptance.BriefID,
		RunbookID:                    acceptance.RunbookID,
		PacketID:                     acceptance.PacketID,
		BoardID:                      acceptance.BoardID,
		SummaryID:                    acceptance.SummaryID,
		Jurisdiction:                 acceptance.Jurisdiction,
		ServiceCode:                  acceptance.ServiceCode,
		ServiceTier:                  acceptance.ServiceTier,
		EvaluatedAt:                  acceptance.EvaluatedAt.UTC(),
		FocusLane:                    acceptance.FocusLane,
		FocusAction:                  acceptance.FocusAction,
		Severity:                     acceptance.Severity,
		DispatchStatus:               acceptance.DispatchStatus,
		AcceptanceStatus:             acceptance.Status,
		Items:                        secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItems(acceptance, generatedAt),
		AcknowledgementReceiptDigest: acceptance.ReceiptDigest,
		ManifestDigest:               acceptance.ManifestDigest,
		QueueDigest:                  acceptance.QueueDigest,
		DispatchDigest:               acceptance.DispatchDigest,
		AcceptanceDigest:             acceptance.AcceptanceDigest,
		GeneratedAt:                  generatedAt.UTC(),
	}
	for _, item := range receipt.Items {
		receipt.ReceiptCount++
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation:
			receipt.EscalationReceiptCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue:
			receipt.OverdueReceiptCount++
		default:
			receipt.AwaitingReceiptCount++
		}
		if receipt.PrimaryReceiptAction == "" {
			receipt.PrimaryReceiptAction = item.ReceiptAction
		}
	}
	receipt.Status = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus(receipt)
	receipt.AcceptanceReceiptDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptDigest(receipt)
	receipt.AcceptanceReceiptID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt:" + firstNonEmpty(receipt.Jurisdiction, "all") + ":" + receipt.AcceptanceReceiptDigest[:12]
	return receipt
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItems(
	acceptance SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem, 0, len(acceptance.Items))
	for _, acceptanceItem := range acceptance.Items {
		items = append(items, secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem(acceptanceItem, generatedAt))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Priority == items[j].Priority {
				return items[i].Sequence < items[j].Sequence
			}
			return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[i].Priority) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[j].Priority)
		}
		return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem(
	acceptanceItem SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem {
	status := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItemStatus(acceptanceItem)
	item := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem{
		AcceptanceItemID:     acceptanceItem.AcceptanceItemID,
		DispatchItemID:       acceptanceItem.DispatchItemID,
		QueueItemID:          acceptanceItem.QueueItemID,
		Sequence:             acceptanceItem.Sequence,
		Evidence:             acceptanceItem.Evidence,
		Status:               status,
		Priority:             acceptanceItem.Priority,
		AcceptingRole:        acceptanceItem.AcceptingRole,
		ReceiptAction:        secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptAction(status),
		ReceiptEvidence:      secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptEvidence(acceptanceItem, status),
		AcceptanceChannel:    acceptanceItem.AcceptanceChannel,
		EscalationTarget:     acceptanceItem.EscalationTarget,
		PendingActions:       secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptPendingActions(acceptanceItem, status),
		CellIDs:              append([]string(nil), acceptanceItem.CellIDs...),
		DueAt:                cloneTimePtr(acceptanceItem.DueAt),
		OverdueSeconds:       acceptanceItem.OverdueSeconds,
		AcceptanceItemDigest: acceptanceItem.AcceptanceDigest,
		GeneratedAt:          generatedAt.UTC(),
	}
	item.ReceiptItemDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItemDigest(item)
	item.AcceptanceReceiptItemID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-receipt-item:" + firstNonEmpty(item.AcceptingRole, "unassigned") + ":" + item.ReceiptItemDigest[:12]
	return item
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItemStatus(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusAwaiting
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptAction(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation:
		return "issue_escalated_ack_receipt_evidence_dispatch_acceptance_receipt"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue:
		return "issue_overdue_ack_receipt_evidence_dispatch_acceptance_receipt"
	default:
		return "issue_ack_receipt_evidence_dispatch_acceptance_receipt"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptEvidence(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem,
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus,
) []string {
	evidence := append([]string(nil), item.AcceptanceEvidence...)
	evidence = append(evidence, "acceptance_digest_confirmation", "accepting_role_signature", "custody_timestamp")
	if status == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue {
		evidence = append(evidence, "overdue_acceptance_receipt_reason")
	}
	if status == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation {
		evidence = append(evidence, "incident_command_receipt_authorization")
	}
	return uniqueTrimmedStrings(evidence)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptPendingActions(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem,
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus,
) []string {
	actions := append([]string(nil), item.PendingActions...)
	actions = append(actions, secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptAction(status))
	return uniqueTrimmedStrings(actions)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus {
	if receipt.EscalationReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation
	}
	if receipt.OverdueReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusAwaiting
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusRank(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus,
) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusEscalation:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusOverdue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatusAwaiting:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItemDigest(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptItem,
) string {
	core := struct {
		AcceptanceItemID     string                                                                                                                 `json:"acceptance_item_id"`
		DispatchItemID       string                                                                                                                 `json:"dispatch_item_id"`
		QueueItemID          string                                                                                                                 `json:"queue_item_id"`
		Sequence             int                                                                                                                    `json:"sequence"`
		Evidence             string                                                                                                                 `json:"evidence"`
		Status               SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus `json:"status"`
		Priority             SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority                   `json:"priority"`
		AcceptingRole        string                                                                                                                 `json:"accepting_role,omitempty"`
		ReceiptAction        string                                                                                                                 `json:"receipt_action"`
		ReceiptEvidence      []string                                                                                                               `json:"receipt_evidence,omitempty"`
		AcceptanceChannel    string                                                                                                                 `json:"acceptance_channel"`
		EscalationTarget     string                                                                                                                 `json:"escalation_target,omitempty"`
		PendingActions       []string                                                                                                               `json:"pending_actions,omitempty"`
		CellIDs              []string                                                                                                               `json:"cell_ids,omitempty"`
		DueAt                *time.Time                                                                                                             `json:"due_at,omitempty"`
		OverdueSeconds       int64                                                                                                                  `json:"overdue_seconds"`
		AcceptanceItemDigest string                                                                                                                 `json:"acceptance_item_digest"`
	}{
		AcceptanceItemID:     item.AcceptanceItemID,
		DispatchItemID:       item.DispatchItemID,
		QueueItemID:          item.QueueItemID,
		Sequence:             item.Sequence,
		Evidence:             item.Evidence,
		Status:               item.Status,
		Priority:             item.Priority,
		AcceptingRole:        item.AcceptingRole,
		ReceiptAction:        item.ReceiptAction,
		ReceiptEvidence:      item.ReceiptEvidence,
		AcceptanceChannel:    item.AcceptanceChannel,
		EscalationTarget:     item.EscalationTarget,
		PendingActions:       item.PendingActions,
		CellIDs:              item.CellIDs,
		DueAt:                item.DueAt,
		OverdueSeconds:       item.OverdueSeconds,
		AcceptanceItemDigest: item.AcceptanceItemDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptDigest(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceipt,
) string {
	itemDigests := make([]string, 0, len(receipt.Items))
	for _, item := range receipt.Items {
		itemDigests = append(itemDigests, item.ReceiptItemDigest)
	}
	core := struct {
		AcceptanceID                 string                                                                                                                 `json:"acceptance_id"`
		Status                       SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceReceiptStatus `json:"status"`
		PrimaryReceiptAction         string                                                                                                                 `json:"primary_receipt_action"`
		ItemDigests                  []string                                                                                                               `json:"item_digests,omitempty"`
		AcknowledgementReceiptDigest string                                                                                                                 `json:"acknowledgement_receipt_digest"`
		ManifestDigest               string                                                                                                                 `json:"manifest_digest"`
		QueueDigest                  string                                                                                                                 `json:"queue_digest"`
		DispatchDigest               string                                                                                                                 `json:"dispatch_digest"`
		AcceptanceDigest             string                                                                                                                 `json:"acceptance_digest"`
	}{
		AcceptanceID:                 receipt.AcceptanceID,
		Status:                       receipt.Status,
		PrimaryReceiptAction:         receipt.PrimaryReceiptAction,
		ItemDigests:                  itemDigests,
		AcknowledgementReceiptDigest: receipt.AcknowledgementReceiptDigest,
		ManifestDigest:               receipt.ManifestDigest,
		QueueDigest:                  receipt.QueueDigest,
		DispatchDigest:               receipt.DispatchDigest,
		AcceptanceDigest:             receipt.AcceptanceDigest,
	}
	return EvidenceHash(core)
}
