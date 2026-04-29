package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusReady      SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus = "ready"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue    SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus = "overdue"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus = "escalation"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem
// is a role-owned dispatch created from an evidence queue item.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem struct {
	DispatchItemID     string                                                                                                `json:"dispatch_item_id"`
	QueueItemID        string                                                                                                `json:"queue_item_id"`
	Sequence           int                                                                                                   `json:"sequence"`
	Evidence           string                                                                                                `json:"evidence"`
	Status             SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus `json:"status"`
	Priority           SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority  `json:"priority"`
	ResponsibleRole    string                                                                                                `json:"responsible_role,omitempty"`
	DispatchChannel    string                                                                                                `json:"dispatch_channel"`
	OperatorCommand    string                                                                                                `json:"operator_command"`
	EscalationTarget   string                                                                                                `json:"escalation_target,omitempty"`
	PendingActions     []string                                                                                              `json:"pending_actions,omitempty"`
	CellIDs            []string                                                                                              `json:"cell_ids,omitempty"`
	DueAt              *time.Time                                                                                            `json:"due_at,omitempty"`
	OverdueSeconds     int64                                                                                                 `json:"overdue_seconds"`
	EvidenceBindingID  string                                                                                                `json:"evidence_binding_id"`
	QueueItemDigest    string                                                                                                `json:"queue_item_digest"`
	DispatchItemDigest string                                                                                                `json:"dispatch_item_digest"`
	GeneratedAt        time.Time                                                                                             `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch
// makes evidence queue work executable by assigning each item to a dispatch channel.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch struct {
	DispatchID               string                                                                                                `json:"dispatch_id"`
	QueueID                  string                                                                                                `json:"queue_id"`
	ManifestID               string                                                                                                `json:"manifest_id"`
	AcknowledgementReceiptID string                                                                                                `json:"acknowledgement_receipt_id"`
	AcknowledgementID        string                                                                                                `json:"acknowledgement_id"`
	DirectiveID              string                                                                                                `json:"directive_id"`
	ClosureDispatchID        string                                                                                                `json:"closure_dispatch_id"`
	BriefID                  string                                                                                                `json:"brief_id"`
	RunbookID                string                                                                                                `json:"runbook_id"`
	PacketID                 string                                                                                                `json:"packet_id"`
	BoardID                  string                                                                                                `json:"board_id"`
	SummaryID                string                                                                                                `json:"summary_id"`
	Jurisdiction             string                                                                                                `json:"jurisdiction,omitempty"`
	ServiceCode              string                                                                                                `json:"service_code,omitempty"`
	ServiceTier              string                                                                                                `json:"service_tier,omitempty"`
	EvaluatedAt              time.Time                                                                                             `json:"evaluated_at"`
	FocusLane                SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                                    `json:"focus_lane"`
	FocusAction              string                                                                                                `json:"focus_action"`
	Severity                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                                `json:"severity"`
	ReceiptStatus            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus                 `json:"receipt_status"`
	ReceiptAction            string                                                                                                `json:"receipt_action"`
	Status                   SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus `json:"status"`
	DispatchCount            int                                                                                                   `json:"dispatch_count"`
	ReadyDispatchCount       int                                                                                                   `json:"ready_dispatch_count"`
	OverdueDispatchCount     int                                                                                                   `json:"overdue_dispatch_count"`
	EscalationDispatchCount  int                                                                                                   `json:"escalation_dispatch_count"`
	PrimaryOperatorCommand   string                                                                                                `json:"primary_operator_command"`
	Items                    []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem `json:"items"`
	ReceiptDigest            string                                                                                                `json:"receipt_digest"`
	ManifestDigest           string                                                                                                `json:"manifest_digest"`
	QueueDigest              string                                                                                                `json:"queue_digest"`
	DispatchDigest           string                                                                                                `json:"dispatch_digest"`
	GeneratedAt              time.Time                                                                                             `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch
// returns role-owned dispatches for the acknowledgement receipt evidence queue.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch: service is required")
	}
	queue, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(ctx, filter)
	if err != nil {
		return nil, err
	}
	dispatch := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(*queue, time.Now().UTC())
	return &dispatch, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch(
	queue SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch {
	dispatch := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch{
		QueueID:                  queue.QueueID,
		ManifestID:               queue.ManifestID,
		AcknowledgementReceiptID: queue.AcknowledgementReceiptID,
		AcknowledgementID:        queue.AcknowledgementID,
		DirectiveID:              queue.DirectiveID,
		ClosureDispatchID:        queue.DispatchID,
		BriefID:                  queue.BriefID,
		RunbookID:                queue.RunbookID,
		PacketID:                 queue.PacketID,
		BoardID:                  queue.BoardID,
		SummaryID:                queue.SummaryID,
		Jurisdiction:             queue.Jurisdiction,
		ServiceCode:              queue.ServiceCode,
		ServiceTier:              queue.ServiceTier,
		EvaluatedAt:              queue.EvaluatedAt.UTC(),
		FocusLane:                queue.FocusLane,
		FocusAction:              queue.FocusAction,
		Severity:                 queue.Severity,
		ReceiptStatus:            queue.ReceiptStatus,
		ReceiptAction:            queue.ReceiptAction,
		Items:                    secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItems(queue, generatedAt),
		ReceiptDigest:            queue.ReceiptDigest,
		ManifestDigest:           queue.ManifestDigest,
		QueueDigest:              queue.QueueDigest,
		GeneratedAt:              generatedAt.UTC(),
	}
	for _, item := range dispatch.Items {
		dispatch.DispatchCount++
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation:
			dispatch.EscalationDispatchCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue:
			dispatch.OverdueDispatchCount++
		default:
			dispatch.ReadyDispatchCount++
		}
		if dispatch.PrimaryOperatorCommand == "" {
			dispatch.PrimaryOperatorCommand = item.OperatorCommand
		}
	}
	dispatch.Status = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus(dispatch)
	dispatch.DispatchDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchDigest(dispatch)
	dispatch.DispatchID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch:" + firstNonEmpty(dispatch.Jurisdiction, "all") + ":" + dispatch.DispatchDigest[:12]
	return dispatch
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItems(
	queue SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem, 0, len(queue.Items))
	for _, queueItem := range queue.Items {
		items = append(items, secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem(queueItem, generatedAt))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Priority == items[j].Priority {
				return items[i].Sequence < items[j].Sequence
			}
			return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[i].Priority) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[j].Priority)
		}
		return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem(
	queueItem SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem {
	status := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItemStatus(queueItem)
	item := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem{
		QueueItemID:       queueItem.QueueItemID,
		Sequence:          queueItem.Sequence,
		Evidence:          queueItem.Evidence,
		Status:            status,
		Priority:          queueItem.Priority,
		ResponsibleRole:   queueItem.ResponsibleRole,
		DispatchChannel:   secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchChannel(status),
		OperatorCommand:   secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchCommand(status, queueItem),
		EscalationTarget:  secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchEscalationTarget(status, queueItem),
		PendingActions:    append([]string(nil), queueItem.PendingActions...),
		CellIDs:           append([]string(nil), queueItem.CellIDs...),
		DueAt:             cloneTimePtr(queueItem.DueAt),
		OverdueSeconds:    queueItem.OverdueSeconds,
		EvidenceBindingID: queueItem.QueueItemID,
		QueueItemDigest:   queueItem.ItemDigest,
		GeneratedAt:       generatedAt.UTC(),
	}
	item.DispatchItemDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItemDigest(item)
	item.DispatchItemID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-dispatch-item:" + firstNonEmpty(item.ResponsibleRole, "unassigned") + ":" + item.DispatchItemDigest[:12]
	return item
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItemStatus(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusReady
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchChannel(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation:
		return "incident_command_channel"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue:
		return "operator_recovery_channel"
	default:
		return "operator_evidence_channel"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchCommand(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus,
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation:
		return "dispatch_escalation_ack_receipt_evidence_collection"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue:
		return "dispatch_overdue_ack_receipt_evidence_collection"
	default:
		return firstNonEmpty(item.Action, "dispatch_ack_receipt_evidence_collection")
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchEscalationTarget(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus,
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation:
		return "incident_commander"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue:
		return firstNonEmpty(item.ResponsibleRole, "workflow_coordinator")
	default:
		return ""
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus {
	if dispatch.EscalationDispatchCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation
	}
	if dispatch.OverdueDispatchCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusReady
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusRank(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus,
) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusEscalation:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusOverdue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatusReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItemDigest(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchItem,
) string {
	core := struct {
		QueueItemID       string                                                                                                `json:"queue_item_id"`
		Sequence          int                                                                                                   `json:"sequence"`
		Evidence          string                                                                                                `json:"evidence"`
		Status            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus `json:"status"`
		Priority          SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority  `json:"priority"`
		ResponsibleRole   string                                                                                                `json:"responsible_role,omitempty"`
		DispatchChannel   string                                                                                                `json:"dispatch_channel"`
		OperatorCommand   string                                                                                                `json:"operator_command"`
		EscalationTarget  string                                                                                                `json:"escalation_target,omitempty"`
		PendingActions    []string                                                                                              `json:"pending_actions,omitempty"`
		CellIDs           []string                                                                                              `json:"cell_ids,omitempty"`
		DueAt             *time.Time                                                                                            `json:"due_at,omitempty"`
		OverdueSeconds    int64                                                                                                 `json:"overdue_seconds"`
		EvidenceBindingID string                                                                                                `json:"evidence_binding_id"`
		QueueItemDigest   string                                                                                                `json:"queue_item_digest"`
	}{
		QueueItemID:       item.QueueItemID,
		Sequence:          item.Sequence,
		Evidence:          item.Evidence,
		Status:            item.Status,
		Priority:          item.Priority,
		ResponsibleRole:   item.ResponsibleRole,
		DispatchChannel:   item.DispatchChannel,
		OperatorCommand:   item.OperatorCommand,
		EscalationTarget:  item.EscalationTarget,
		PendingActions:    item.PendingActions,
		CellIDs:           item.CellIDs,
		DueAt:             item.DueAt,
		OverdueSeconds:    item.OverdueSeconds,
		EvidenceBindingID: item.EvidenceBindingID,
		QueueItemDigest:   item.QueueItemDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchDigest(
	dispatch SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatch,
) string {
	itemDigests := make([]string, 0, len(dispatch.Items))
	for _, item := range dispatch.Items {
		itemDigests = append(itemDigests, item.DispatchItemDigest)
	}
	core := struct {
		QueueID                string                                                                                                `json:"queue_id"`
		Status                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceDispatchStatus `json:"status"`
		PrimaryOperatorCommand string                                                                                                `json:"primary_operator_command"`
		ItemDigests            []string                                                                                              `json:"item_digests,omitempty"`
		ReceiptDigest          string                                                                                                `json:"receipt_digest"`
		ManifestDigest         string                                                                                                `json:"manifest_digest"`
		QueueDigest            string                                                                                                `json:"queue_digest"`
	}{
		QueueID:                dispatch.QueueID,
		Status:                 dispatch.Status,
		PrimaryOperatorCommand: dispatch.PrimaryOperatorCommand,
		ItemDigests:            itemDigests,
		ReceiptDigest:          dispatch.ReceiptDigest,
		ManifestDigest:         dispatch.ManifestDigest,
		QueueDigest:            dispatch.QueueDigest,
	}
	return EvidenceHash(core)
}
