package securecells

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusDue        SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus = "due"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue    SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus = "overdue"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus = "escalation"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityMedium   SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority = "medium"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityHigh     SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority = "high"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityCritical SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority = "critical"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem
// is one operator-ownable evidence collection task derived from a receipt manifest.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem struct {
	QueueItemID              string                                                                                               `json:"queue_item_id"`
	Sequence                 int                                                                                                  `json:"sequence"`
	ManifestID               string                                                                                               `json:"manifest_id"`
	AcknowledgementReceiptID string                                                                                               `json:"acknowledgement_receipt_id"`
	AcknowledgementID        string                                                                                               `json:"acknowledgement_id"`
	DirectiveID              string                                                                                               `json:"directive_id"`
	Evidence                 string                                                                                               `json:"evidence"`
	Status                   SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus   `json:"status"`
	Priority                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority `json:"priority"`
	Action                   string                                                                                               `json:"action"`
	ResponsibleRole          string                                                                                               `json:"responsible_role,omitempty"`
	PendingActions           []string                                                                                             `json:"pending_actions,omitempty"`
	CellIDs                  []string                                                                                             `json:"cell_ids,omitempty"`
	DueAt                    *time.Time                                                                                           `json:"due_at,omitempty"`
	OverdueSeconds           int64                                                                                                `json:"overdue_seconds"`
	ReceiptDigest            string                                                                                               `json:"receipt_digest"`
	ManifestDigest           string                                                                                               `json:"manifest_digest"`
	ItemDigest               string                                                                                               `json:"item_digest"`
	GeneratedAt              time.Time                                                                                            `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue
// turns receipt evidence obligations into a queryable operator work queue.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue struct {
	QueueID                  string                                                                                             `json:"queue_id"`
	ManifestID               string                                                                                             `json:"manifest_id"`
	AcknowledgementReceiptID string                                                                                             `json:"acknowledgement_receipt_id"`
	AcknowledgementID        string                                                                                             `json:"acknowledgement_id"`
	DirectiveID              string                                                                                             `json:"directive_id"`
	DispatchID               string                                                                                             `json:"dispatch_id"`
	BriefID                  string                                                                                             `json:"brief_id"`
	RunbookID                string                                                                                             `json:"runbook_id"`
	PacketID                 string                                                                                             `json:"packet_id"`
	BoardID                  string                                                                                             `json:"board_id"`
	SummaryID                string                                                                                             `json:"summary_id"`
	Jurisdiction             string                                                                                             `json:"jurisdiction,omitempty"`
	ServiceCode              string                                                                                             `json:"service_code,omitempty"`
	ServiceTier              string                                                                                             `json:"service_tier,omitempty"`
	EvaluatedAt              time.Time                                                                                          `json:"evaluated_at"`
	FocusLane                SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                                 `json:"focus_lane"`
	FocusAction              string                                                                                             `json:"focus_action"`
	Severity                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                             `json:"severity"`
	ReceiptStatus            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus              `json:"receipt_status"`
	ReceiptAction            string                                                                                             `json:"receipt_action"`
	Status                   SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus `json:"status"`
	ItemCount                int                                                                                                `json:"item_count"`
	DueCount                 int                                                                                                `json:"due_count"`
	OverdueCount             int                                                                                                `json:"overdue_count"`
	EscalationCount          int                                                                                                `json:"escalation_count"`
	Items                    []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem `json:"items"`
	ReceiptDigest            string                                                                                             `json:"receipt_digest"`
	ManifestDigest           string                                                                                             `json:"manifest_digest"`
	QueueDigest              string                                                                                             `json:"queue_digest"`
	GeneratedAt              time.Time                                                                                          `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue
// returns the operator evidence queue for matching acknowledgement receipt manifests.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-queue: service is required")
	}
	manifest, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(ctx, filter)
	if err != nil {
		return nil, err
	}
	queue := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(*manifest, time.Now().UTC())
	return &queue, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue(
	manifest SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue {
	queue := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue{
		ManifestID:               manifest.ManifestID,
		AcknowledgementReceiptID: manifest.AcknowledgementReceiptID,
		AcknowledgementID:        manifest.AcknowledgementID,
		DirectiveID:              manifest.DirectiveID,
		DispatchID:               manifest.DispatchID,
		BriefID:                  manifest.BriefID,
		RunbookID:                manifest.RunbookID,
		PacketID:                 manifest.PacketID,
		BoardID:                  manifest.BoardID,
		SummaryID:                manifest.SummaryID,
		Jurisdiction:             manifest.Jurisdiction,
		ServiceCode:              manifest.ServiceCode,
		ServiceTier:              manifest.ServiceTier,
		EvaluatedAt:              manifest.EvaluatedAt.UTC(),
		FocusLane:                manifest.FocusLane,
		FocusAction:              manifest.FocusAction,
		Severity:                 manifest.Severity,
		ReceiptStatus:            manifest.ReceiptStatus,
		ReceiptAction:            manifest.ReceiptAction,
		Items:                    secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItems(manifest, generatedAt),
		ReceiptDigest:            manifest.ReceiptDigest,
		ManifestDigest:           manifest.ManifestDigest,
		GeneratedAt:              generatedAt.UTC(),
	}
	for _, item := range queue.Items {
		queue.ItemCount++
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation:
			queue.EscalationCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue:
			queue.OverdueCount++
		default:
			queue.DueCount++
		}
	}
	queue.Status = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus(queue)
	queue.QueueDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueDigest(queue)
	queue.QueueID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence-queue:" + firstNonEmpty(queue.Jurisdiction, "all") + ":" + queue.QueueDigest[:12]
	return queue
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItems(
	manifest SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem, 0, len(manifest.Items))
	for _, manifestItem := range manifest.Items {
		item := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem(manifest, manifestItem, generatedAt)
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			if items[i].Priority == items[j].Priority {
				if items[i].DueAt == nil || items[j].DueAt == nil {
					if items[i].DueAt == nil && items[j].DueAt != nil {
						return false
					}
					if items[i].DueAt != nil && items[j].DueAt == nil {
						return true
					}
					return items[i].Sequence < items[j].Sequence
				}
				if items[i].DueAt.Equal(*items[j].DueAt) {
					return items[i].Sequence < items[j].Sequence
				}
				return items[i].DueAt.Before(*items[j].DueAt)
			}
			return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[i].Priority) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(items[j].Priority)
		}
		return secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusRank(items[i].Status) < secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusRank(items[j].Status)
	})
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem(
	manifest SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest,
	manifestItem SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem {
	status := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItemStatus(manifestItem)
	item := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem{
		Sequence:                 manifestItem.Sequence,
		ManifestID:               manifest.ManifestID,
		AcknowledgementReceiptID: manifest.AcknowledgementReceiptID,
		AcknowledgementID:        manifest.AcknowledgementID,
		DirectiveID:              manifest.DirectiveID,
		Evidence:                 manifestItem.Evidence,
		Status:                   status,
		Priority:                 secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority(status),
		Action:                   secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueAction(status),
		ResponsibleRole:          manifestItem.ResponsibleRole,
		PendingActions:           secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePendingActions(manifestItem, status),
		CellIDs:                  append([]string(nil), manifestItem.CellIDs...),
		DueAt:                    cloneTimePtr(manifest.ReceiptDueAt),
		ReceiptDigest:            manifest.ReceiptDigest,
		ManifestDigest:           manifest.ManifestDigest,
		GeneratedAt:              generatedAt.UTC(),
	}
	if status != SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusDue {
		item.OverdueSeconds = manifest.ReceiptOverdueSeconds
	}
	item.ItemDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItemDigest(item)
	item.QueueItemID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-evidence:" + firstNonEmpty(manifest.Jurisdiction, "all") + ":" + item.ItemDigest[:12]
	return item
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItemStatus(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus {
	switch item.Status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusEscalationRequired:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusOverdueRequired:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusDue
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityCritical
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityHigh
	default:
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityMedium
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueAction(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus,
) string {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation:
		return "collect_escalation_ack_receipt_evidence"
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue:
		return "collect_overdue_ack_receipt_evidence"
	default:
		return "collect_ack_receipt_evidence"
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePendingActions(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem,
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus,
) []string {
	actions := append([]string(nil), item.PendingActions...)
	if len(actions) == 0 {
		actions = append(actions, secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueAction(status))
	}
	return uniqueTrimmedStrings(actions)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus(
	queue SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus {
	if queue.EscalationCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation
	}
	if queue.OverdueCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusDue
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusRank(
	status SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus,
) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusEscalation:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusOverdue:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatusDue:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityRank(
	priority SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority,
) int {
	switch priority {
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityCritical:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityHigh:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriorityMedium:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItemDigest(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueItem,
) string {
	core := struct {
		Sequence        int                                                                                                  `json:"sequence"`
		ManifestID      string                                                                                               `json:"manifest_id"`
		Evidence        string                                                                                               `json:"evidence"`
		Status          SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus   `json:"status"`
		Priority        SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueuePriority `json:"priority"`
		Action          string                                                                                               `json:"action"`
		ResponsibleRole string                                                                                               `json:"responsible_role,omitempty"`
		PendingActions  []string                                                                                             `json:"pending_actions,omitempty"`
		CellIDs         []string                                                                                             `json:"cell_ids,omitempty"`
		DueAt           *time.Time                                                                                           `json:"due_at,omitempty"`
		OverdueSeconds  int64                                                                                                `json:"overdue_seconds"`
		ReceiptDigest   string                                                                                               `json:"receipt_digest"`
		ManifestDigest  string                                                                                               `json:"manifest_digest"`
	}{
		Sequence:        item.Sequence,
		ManifestID:      item.ManifestID,
		Evidence:        item.Evidence,
		Status:          item.Status,
		Priority:        item.Priority,
		Action:          item.Action,
		ResponsibleRole: item.ResponsibleRole,
		PendingActions:  item.PendingActions,
		CellIDs:         item.CellIDs,
		DueAt:           item.DueAt,
		OverdueSeconds:  item.OverdueSeconds,
		ReceiptDigest:   item.ReceiptDigest,
		ManifestDigest:  item.ManifestDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueDigest(
	queue SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueue,
) string {
	itemDigests := make([]string, 0, len(queue.Items))
	for _, item := range queue.Items {
		itemDigests = append(itemDigests, item.ItemDigest)
	}
	core := struct {
		ManifestID     string                                                                                             `json:"manifest_id"`
		Status         SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidenceQueueStatus `json:"status"`
		ReceiptStatus  SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus              `json:"receipt_status"`
		ItemDigests    []string                                                                                           `json:"item_digests,omitempty"`
		ReceiptDigest  string                                                                                             `json:"receipt_digest"`
		ManifestDigest string                                                                                             `json:"manifest_digest"`
	}{
		ManifestID:     queue.ManifestID,
		Status:         queue.Status,
		ReceiptStatus:  queue.ReceiptStatus,
		ItemDigests:    itemDigests,
		ReceiptDigest:  queue.ReceiptDigest,
		ManifestDigest: queue.ManifestDigest,
	}
	return EvidenceHash(core)
}
