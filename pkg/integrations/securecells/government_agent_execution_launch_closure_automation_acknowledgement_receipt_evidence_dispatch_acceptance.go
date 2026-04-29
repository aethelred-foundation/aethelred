package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRequired           SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus = "acceptance_required"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired    SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus = "overdue_acceptance_required"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus = "escalation_acceptance_required"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem
// is one role-custody acceptance required before dispatch evidence collection can proceed.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem struct {
	AcceptanceItemID   string                                                                                                          `json:"acceptance_item_id"`
	DispatchItemID     string                                                                                                          `json:"dispatch_item_id"`
	QueueItemID        string                                                                                                          `json:"queue_item_id"`
	Sequence           int                                                                                                             `json:"sequence"`
	Evidence           string                                                                                                          `json:"evidence"`
	Status             SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus `json:"status"`
	Priority           SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority            `json:"priority"`
	AcceptingRole      string                                                                                                          `json:"accepting_role,omitempty"`
	AcceptanceAction   string                                                                                                          `json:"acceptance_action"`
	AcceptanceChannel  string                                                                                                          `json:"acceptance_channel"`
	AcceptanceEvidence []string                                                                                                        `json:"acceptance_evidence,omitempty"`
	EscalationTarget   string                                                                                                          `json:"escalation_target,omitempty"`
	PendingActions     []string                                                                                                        `json:"pending_actions,omitempty"`
	CellIDs            []string                                                                                                        `json:"cell_ids,omitempty"`
	DueAt              *time.Time                                                                                                      `json:"due_at,omitempty"`
	OverdueSeconds     int64                                                                                                           `json:"overdue_seconds"`
	DispatchItemDigest string                                                                                                          `json:"dispatch_item_digest"`
	AcceptanceDigest   string                                                                                                          `json:"acceptance_digest"`
	GeneratedAt        time.Time                                                                                                       `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance
// records the role acceptance obligations for evidence dispatch custody.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance struct {
	AcceptanceID              string                                                                                                          `json:"acceptance_id"`
	DispatchID                string                                                                                                          `json:"dispatch_id"`
	QueueID                   string                                                                                                          `json:"queue_id"`
	ManifestID                string                                                                                                          `json:"manifest_id"`
	AcknowledgementReceiptID  string                                                                                                          `json:"acknowledgement_receipt_id"`
	AcknowledgementID         string                                                                                                          `json:"acknowledgement_id"`
	DirectiveID               string                                                                                                          `json:"directive_id"`
	ClosureDispatchID         string                                                                                                          `json:"closure_dispatch_id"`
	BriefID                   string                                                                                                          `json:"brief_id"`
	RunbookID                 string                                                                                                          `json:"runbook_id"`
	PacketID                  string                                                                                                          `json:"packet_id"`
	BoardID                   string                                                                                                          `json:"board_id"`
	SummaryID                 string                                                                                                          `json:"summary_id"`
	Jurisdiction              string                                                                                                          `json:"jurisdiction,omitempty"`
	ServiceCode               string                                                                                                          `json:"service_code,omitempty"`
	ServiceTier               string                                                                                                          `json:"service_tier,omitempty"`
	EvaluatedAt               time.Time                                                                                                       `json:"evaluated_at"`
	FocusLane                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                                              `json:"focus_lane"`
	FocusAction               string                                                                                                          `json:"focus_action"`
	Severity                  SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                                          `json:"severity"`
	ReceiptStatus             SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus                           `json:"receipt_status"`
	DispatchStatus            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus           `json:"dispatch_status"`
	Status                    SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus `json:"status"`
	AcceptanceCount           int                                                                                                             `json:"acceptance_count"`
	RequiredAcceptanceCount   int                                                                                                             `json:"required_acceptance_count"`
	OverdueAcceptanceCount    int                                                                                                             `json:"overdue_acceptance_count"`
	EscalationAcceptanceCount int                                                                                                             `json:"escalation_acceptance_count"`
	PrimaryAcceptanceAction   string                                                                                                          `json:"primary_acceptance_action"`
	Items                     []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem `json:"items"`
	ReceiptDigest             string                                                                                                          `json:"receipt_digest"`
	ManifestDigest            string                                                                                                          `json:"manifest_digest"`
	QueueDigest               string                                                                                                          `json:"queue_digest"`
	DispatchDigest            string                                                                                                          `json:"dispatch_digest"`
	AcceptanceDigest          string                                                                                                          `json:"acceptance_digest"`
	GeneratedAt               time.Time                                                                                                       `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance
// returns role acceptance obligations for the evidence dispatch surface.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance: service is required")
	}
	dispatch, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(ctx, filter)
	if err != nil {
		return nil, err
	}
	acceptance := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(*dispatch, time.Now().UTC())
	return &acceptance, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance {
	acceptance := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance{
		DispatchID:               dispatch.DispatchID,
		QueueID:                  dispatch.QueueID,
		ManifestID:               dispatch.ManifestID,
		AcknowledgementReceiptID: dispatch.AcknowledgementReceiptID,
		AcknowledgementID:        dispatch.AcknowledgementID,
		DirectiveID:              dispatch.DirectiveID,
		ClosureDispatchID:        dispatch.ClosureDispatchID,
		BriefID:                  dispatch.BriefID,
		RunbookID:                dispatch.RunbookID,
		PacketID:                 dispatch.PacketID,
		BoardID:                  dispatch.BoardID,
		SummaryID:                dispatch.SummaryID,
		Jurisdiction:             dispatch.Jurisdiction,
		ServiceCode:              dispatch.ServiceCode,
		ServiceTier:              dispatch.ServiceTier,
		EvaluatedAt:              dispatch.EvaluatedAt.UTC(),
		FocusLane:                dispatch.FocusLane,
		FocusAction:              dispatch.FocusAction,
		Severity:                 dispatch.Severity,
		ReceiptStatus:            dispatch.ReceiptStatus,
		DispatchStatus:           dispatch.Status,
		Items:                    secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItems(dispatch, generatedAt),
		ReceiptDigest:            dispatch.ReceiptDigest,
		ManifestDigest:           dispatch.ManifestDigest,
		QueueDigest:              dispatch.QueueDigest,
		DispatchDigest:           dispatch.DispatchDigest,
		GeneratedAt:              generatedAt.UTC(),
	}
	for _, item := range acceptance.Items {
		acceptance.AcceptanceCount++
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired:
			acceptance.EscalationAcceptanceCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired:
			acceptance.OverdueAcceptanceCount++
		default:
			acceptance.RequiredAcceptanceCount++
		}
		if acceptance.PrimaryAcceptanceAction == "" {
			acceptance.PrimaryAcceptanceAction = item.AcceptanceAction
		}
	}
	acceptance.Status = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus(acceptance)
	acceptance.AcceptanceDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceDigest(acceptance)
	acceptance.AcceptanceID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance:" + firstNonEmpty(acceptance.Jurisdiction, "all") + ":" + acceptance.AcceptanceDigest[:12]
	return acceptance
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItems(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem, 0, len(dispatch.Items))
	for _, dispatchItem := range dispatch.Items {
		items = append(items, secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem(dispatchItem, generatedAt))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Priority == items[j].Priority {
				return items[i].Sequence < items[j].Sequence
			}
			return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[i].Priority) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[j].Priority)
		}
		return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem(
	dispatchItem SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem {
	status := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItemStatus(dispatchItem)
	item := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem{
		DispatchItemID:     dispatchItem.DispatchItemID,
		QueueItemID:        dispatchItem.QueueItemID,
		Sequence:           dispatchItem.Sequence,
		Evidence:           dispatchItem.Evidence,
		Status:             status,
		Priority:           dispatchItem.Priority,
		AcceptingRole:      dispatchItem.ResponsibleRole,
		AcceptanceAction:   secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceAction(status),
		AcceptanceChannel:  secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceChannel(status),
		AcceptanceEvidence: secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceEvidence(status),
		EscalationTarget:   secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceEscalationTarget(status, dispatchItem),
		PendingActions:     secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptancePendingActions(dispatchItem, status),
		CellIDs:            append([]string(nil), dispatchItem.CellIDs...),
		DueAt:              cloneTimePtr(dispatchItem.DueAt),
		OverdueSeconds:     dispatchItem.OverdueSeconds,
		DispatchItemDigest: dispatchItem.DispatchItemDigest,
		GeneratedAt:        generatedAt.UTC(),
	}
	item.AcceptanceDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItemDigest(item)
	item.AcceptanceItemID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-acceptance-item:" + firstNonEmpty(item.AcceptingRole, "unassigned") + ":" + item.AcceptanceDigest[:12]
	return item
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItemStatus(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRequired
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceAction(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired:
		return "accept_escalated_ack_receipt_evidence_dispatch"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired:
		return "accept_overdue_ack_receipt_evidence_dispatch"
	default:
		return "accept_ack_receipt_evidence_dispatch"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceChannel(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired:
		return "incident_command_acceptance"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired:
		return "operator_recovery_acceptance"
	default:
		return "operator_acceptance"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceEvidence(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus,
) []string {
	evidence := []string{
		"dispatch_digest_confirmation",
		"role_assignment_acceptance",
		"evidence_binding_acknowledgement",
	}
	if status == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired {
		evidence = append(evidence, "overdue_dispatch_acceptance_explanation")
	}
	if status == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired {
		evidence = append(evidence, "incident_command_acceptance_authorization")
	}
	return uniqueTrimmedStrings(evidence)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceEscalationTarget(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus,
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired:
		return firstNonEmpty(item.EscalationTarget, "incident_commander")
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired:
		return firstNonEmpty(item.EscalationTarget, item.ResponsibleRole, "workflow_coordinator")
	default:
		return ""
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptancePendingActions(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem,
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus,
) []string {
	actions := append([]string(nil), item.PendingActions...)
	actions = append(actions, secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceAction(status))
	return uniqueTrimmedStrings(actions)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus(
	acceptance SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus {
	if acceptance.EscalationAcceptanceCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired
	}
	if acceptance.OverdueAcceptanceCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRequired
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRank(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus,
) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusEscalationRequired:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusOverdueRequired:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatusRequired:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItemDigest(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceItem,
) string {
	core := struct {
		DispatchItemID     string                                                                                                          `json:"dispatch_item_id"`
		QueueItemID        string                                                                                                          `json:"queue_item_id"`
		Sequence           int                                                                                                             `json:"sequence"`
		Evidence           string                                                                                                          `json:"evidence"`
		Status             SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus `json:"status"`
		Priority           SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority            `json:"priority"`
		AcceptingRole      string                                                                                                          `json:"accepting_role,omitempty"`
		AcceptanceAction   string                                                                                                          `json:"acceptance_action"`
		AcceptanceChannel  string                                                                                                          `json:"acceptance_channel"`
		AcceptanceEvidence []string                                                                                                        `json:"acceptance_evidence,omitempty"`
		EscalationTarget   string                                                                                                          `json:"escalation_target,omitempty"`
		PendingActions     []string                                                                                                        `json:"pending_actions,omitempty"`
		CellIDs            []string                                                                                                        `json:"cell_ids,omitempty"`
		DueAt              *time.Time                                                                                                      `json:"due_at,omitempty"`
		OverdueSeconds     int64                                                                                                           `json:"overdue_seconds"`
		DispatchItemDigest string                                                                                                          `json:"dispatch_item_digest"`
	}{
		DispatchItemID:     item.DispatchItemID,
		QueueItemID:        item.QueueItemID,
		Sequence:           item.Sequence,
		Evidence:           item.Evidence,
		Status:             item.Status,
		Priority:           item.Priority,
		AcceptingRole:      item.AcceptingRole,
		AcceptanceAction:   item.AcceptanceAction,
		AcceptanceChannel:  item.AcceptanceChannel,
		AcceptanceEvidence: item.AcceptanceEvidence,
		EscalationTarget:   item.EscalationTarget,
		PendingActions:     item.PendingActions,
		CellIDs:            item.CellIDs,
		DueAt:              item.DueAt,
		OverdueSeconds:     item.OverdueSeconds,
		DispatchItemDigest: item.DispatchItemDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceDigest(
	acceptance SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptance,
) string {
	itemDigests := make([]string, 0, len(acceptance.Items))
	for _, item := range acceptance.Items {
		itemDigests = append(itemDigests, item.AcceptanceDigest)
	}
	core := struct {
		DispatchID              string                                                                                                          `json:"dispatch_id"`
		Status                  SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchAcceptanceStatus `json:"status"`
		PrimaryAcceptanceAction string                                                                                                          `json:"primary_acceptance_action"`
		ItemDigests             []string                                                                                                        `json:"item_digests,omitempty"`
		ReceiptDigest           string                                                                                                          `json:"receipt_digest"`
		ManifestDigest          string                                                                                                          `json:"manifest_digest"`
		QueueDigest             string                                                                                                          `json:"queue_digest"`
		DispatchDigest          string                                                                                                          `json:"dispatch_digest"`
	}{
		DispatchID:              acceptance.DispatchID,
		Status:                  acceptance.Status,
		PrimaryAcceptanceAction: acceptance.PrimaryAcceptanceAction,
		ItemDigests:             itemDigests,
		ReceiptDigest:           acceptance.ReceiptDigest,
		ManifestDigest:          acceptance.ManifestDigest,
		QueueDigest:             acceptance.QueueDigest,
		DispatchDigest:          acceptance.DispatchDigest,
	}
	return EvidenceHash(core)
}
