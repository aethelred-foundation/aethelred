package securecells

import (
	"context"
	"fmt"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusRequired           SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus = "required"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusOverdueRequired    SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus = "overdue_required"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusEscalationRequired SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus = "escalation_required"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem
// is one evidence obligation that must be collected for an acknowledgement receipt.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem struct {
	Sequence        int                                                                                               `json:"sequence"`
	Evidence        string                                                                                            `json:"evidence"`
	Status          SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus `json:"status"`
	ResponsibleRole string                                                                                            `json:"responsible_role,omitempty"`
	PendingActions  []string                                                                                          `json:"pending_actions,omitempty"`
	CellIDs         []string                                                                                          `json:"cell_ids,omitempty"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest
// itemizes the evidence required to close or recover an acknowledgement receipt.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest struct {
	ManifestID               string                                                                                        `json:"manifest_id"`
	AcknowledgementReceiptID string                                                                                        `json:"acknowledgement_receipt_id"`
	AcknowledgementID        string                                                                                        `json:"acknowledgement_id"`
	DirectiveID              string                                                                                        `json:"directive_id"`
	DispatchID               string                                                                                        `json:"dispatch_id"`
	BriefID                  string                                                                                        `json:"brief_id"`
	RunbookID                string                                                                                        `json:"runbook_id"`
	PacketID                 string                                                                                        `json:"packet_id"`
	BoardID                  string                                                                                        `json:"board_id"`
	SummaryID                string                                                                                        `json:"summary_id"`
	Jurisdiction             string                                                                                        `json:"jurisdiction,omitempty"`
	ServiceCode              string                                                                                        `json:"service_code,omitempty"`
	ServiceTier              string                                                                                        `json:"service_tier,omitempty"`
	EvaluatedAt              time.Time                                                                                     `json:"evaluated_at"`
	FocusLane                SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                            `json:"focus_lane"`
	FocusAction              string                                                                                        `json:"focus_action"`
	Severity                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                        `json:"severity"`
	ReceiptStatus            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus         `json:"receipt_status"`
	ReceiptAction            string                                                                                        `json:"receipt_action"`
	ReceiptDueAt             *time.Time                                                                                    `json:"receipt_due_at,omitempty"`
	ReceiptOverdueSeconds    int64                                                                                         `json:"receipt_overdue_seconds"`
	EvidenceCount            int                                                                                           `json:"evidence_count"`
	OverdueEvidenceCount     int                                                                                           `json:"overdue_evidence_count"`
	EscalationEvidenceCount  int                                                                                           `json:"escalation_evidence_count"`
	Items                    []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem `json:"items"`
	ReceiptDigest            string                                                                                        `json:"receipt_digest"`
	ManifestDigest           string                                                                                        `json:"manifest_digest"`
	GeneratedAt              time.Time                                                                                     `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest returns
// the evidence manifest for matching acknowledgement receipts.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement-receipt-manifest: service is required")
	}
	receipt, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(ctx, filter)
	if err != nil {
		return nil, err
	}
	manifest := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(*receipt, time.Now().UTC())
	return &manifest, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest {
	manifest := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest{
		AcknowledgementReceiptID: receipt.AcknowledgementReceiptID,
		AcknowledgementID:        receipt.AcknowledgementID,
		DirectiveID:              receipt.DirectiveID,
		DispatchID:               receipt.DispatchID,
		BriefID:                  receipt.BriefID,
		RunbookID:                receipt.RunbookID,
		PacketID:                 receipt.PacketID,
		BoardID:                  receipt.BoardID,
		SummaryID:                receipt.SummaryID,
		Jurisdiction:             receipt.Jurisdiction,
		ServiceCode:              receipt.ServiceCode,
		ServiceTier:              receipt.ServiceTier,
		EvaluatedAt:              receipt.EvaluatedAt.UTC(),
		FocusLane:                receipt.FocusLane,
		FocusAction:              receipt.FocusAction,
		Severity:                 receipt.Severity,
		ReceiptStatus:            receipt.ReceiptStatus,
		ReceiptAction:            receipt.ReceiptAction,
		ReceiptDueAt:             receipt.ReceiptDueAt,
		ReceiptOverdueSeconds:    receipt.ReceiptOverdueSeconds,
		Items:                    secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItems(receipt),
		ReceiptDigest:            receipt.ReceiptDigest,
		GeneratedAt:              generatedAt.UTC(),
	}
	manifest.EvidenceCount = len(manifest.Items)
	for _, item := range manifest.Items {
		switch item.Status {
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusOverdueRequired:
			manifest.OverdueEvidenceCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusEscalationRequired:
			manifest.EscalationEvidenceCount++
		}
	}
	manifest.ManifestDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestDigest(manifest)
	manifest.ManifestID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt-manifest:" + firstNonEmpty(manifest.Jurisdiction, "all") + ":" + manifest.ManifestDigest[:12]
	return manifest
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItems(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt,
) []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem {
	items := make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem, 0, len(receipt.ReceiptEvidence))
	cellIDs := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestCellIDs(receipt.Assignments)
	for _, evidence := range receipt.ReceiptEvidence {
		item := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem{
			Sequence:        len(items) + 1,
			Evidence:        evidence,
			Status:          secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus(receipt, evidence),
			ResponsibleRole: secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestRole(receipt, evidence),
			PendingActions:  secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestPendingActions(receipt, evidence),
			CellIDs:         append([]string(nil), cellIDs...),
		}
		items = append(items, item)
	}
	return items
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt,
	evidence string,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatus {
	if evidence == "escalation_owner_confirmation" {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusEscalationRequired
	}
	if receipt.ReceiptStatus == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue || evidence == "overdue_acknowledgement_explanation" {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusOverdueRequired
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItemStatusRequired
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestRole(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt,
	evidence string,
) string {
	switch evidence {
	case "assignment_acceptance_receipt":
		return firstNonEmpty(receipt.RequiredRoles...)
	case "escalation_owner_confirmation":
		return "incident_commander"
	default:
		return firstNonEmpty(receipt.LeadRole, firstNonEmpty(receipt.RequiredRoles...))
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestPendingActions(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt,
	evidence string,
) []string {
	switch evidence {
	case "directive_digest_confirmation", "lead_role_acknowledgement":
		return []string{receipt.ReceiptAction}
	default:
		return append([]string(nil), receipt.RequiredPendingActions...)
	}
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestCellIDs(
	assignments []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment,
) []string {
	cellIDs := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		cellIDs = append(cellIDs, assignment.CellIDs...)
	}
	return uniqueTrimmedStrings(cellIDs)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestDigest(
	manifest SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifest,
) string {
	core := struct {
		AcknowledgementReceiptID string                                                                                        `json:"acknowledgement_receipt_id"`
		AcknowledgementID        string                                                                                        `json:"acknowledgement_id"`
		FocusLane                SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                            `json:"focus_lane"`
		FocusAction              string                                                                                        `json:"focus_action"`
		Severity                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                        `json:"severity"`
		ReceiptStatus            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus         `json:"receipt_status"`
		ReceiptAction            string                                                                                        `json:"receipt_action"`
		ReceiptDueAt             *time.Time                                                                                    `json:"receipt_due_at,omitempty"`
		ReceiptOverdueSeconds    int64                                                                                         `json:"receipt_overdue_seconds"`
		Items                    []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptManifestItem `json:"items"`
		ReceiptDigest            string                                                                                        `json:"receipt_digest"`
	}{
		AcknowledgementReceiptID: manifest.AcknowledgementReceiptID,
		AcknowledgementID:        manifest.AcknowledgementID,
		FocusLane:                manifest.FocusLane,
		FocusAction:              manifest.FocusAction,
		Severity:                 manifest.Severity,
		ReceiptStatus:            manifest.ReceiptStatus,
		ReceiptAction:            manifest.ReceiptAction,
		ReceiptDueAt:             manifest.ReceiptDueAt,
		ReceiptOverdueSeconds:    manifest.ReceiptOverdueSeconds,
		Items:                    manifest.Items,
		ReceiptDigest:            manifest.ReceiptDigest,
	}
	return EvidenceHash(core)
}
