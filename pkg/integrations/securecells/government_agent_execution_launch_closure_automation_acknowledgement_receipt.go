package securecells

import (
	"context"
	"fmt"
	"time"
)

type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusAwaiting SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus = "awaiting_acknowledgement"
	SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue  SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus = "acknowledgement_overdue"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt
// is the evidence checklist for collecting or recovering directive acknowledgement.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt struct {
	AcknowledgementReceiptID string                                                                                `json:"acknowledgement_receipt_id"`
	AcknowledgementID        string                                                                                `json:"acknowledgement_id"`
	DirectiveID              string                                                                                `json:"directive_id"`
	DispatchID               string                                                                                `json:"dispatch_id"`
	BriefID                  string                                                                                `json:"brief_id"`
	RunbookID                string                                                                                `json:"runbook_id"`
	PacketID                 string                                                                                `json:"packet_id"`
	BoardID                  string                                                                                `json:"board_id"`
	SummaryID                string                                                                                `json:"summary_id"`
	Jurisdiction             string                                                                                `json:"jurisdiction,omitempty"`
	ServiceCode              string                                                                                `json:"service_code,omitempty"`
	ServiceTier              string                                                                                `json:"service_tier,omitempty"`
	EvaluatedAt              time.Time                                                                             `json:"evaluated_at"`
	FocusLane                SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                    `json:"focus_lane"`
	FocusAction              string                                                                                `json:"focus_action"`
	Severity                 SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                `json:"severity"`
	AckStatus                SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus        `json:"ack_status"`
	AckAction                string                                                                                `json:"ack_action"`
	ReceiptStatus            SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus `json:"receipt_status"`
	ReceiptAction            string                                                                                `json:"receipt_action"`
	ReceiptDueAt             *time.Time                                                                            `json:"receipt_due_at,omitempty"`
	ReceiptOverdueSeconds    int64                                                                                 `json:"receipt_overdue_seconds"`
	ReceiptEvidence          []string                                                                              `json:"receipt_evidence,omitempty"`
	LeadRole                 string                                                                                `json:"lead_role"`
	RequiredRoles            []string                                                                              `json:"required_roles,omitempty"`
	RequiredPendingActions   []string                                                                              `json:"required_pending_actions,omitempty"`
	EscalationRequired       bool                                                                                  `json:"escalation_required"`
	AssignmentCount          int                                                                                   `json:"assignment_count"`
	Assignments              []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment         `json:"assignments"`
	Items                    []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem                  `json:"items"`
	AcknowledgementDigest    string                                                                                `json:"acknowledgement_digest"`
	ReceiptDigest            string                                                                                `json:"receipt_digest"`
	GeneratedAt              time.Time                                                                             `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt returns
// the acknowledgement receipt checklist for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-acknowledgement-receipt: service is required")
	}
	acknowledgement, err := s.GetGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement(ctx, filter)
	if err != nil {
		return nil, err
	}
	receipt := secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(*acknowledgement, time.Now().UTC())
	return &receipt, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt(
	acknowledgement SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt {
	receipt := SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt{
		AcknowledgementID:      acknowledgement.AcknowledgementID,
		DirectiveID:            acknowledgement.DirectiveID,
		DispatchID:             acknowledgement.DispatchID,
		BriefID:                acknowledgement.BriefID,
		RunbookID:              acknowledgement.RunbookID,
		PacketID:               acknowledgement.PacketID,
		BoardID:                acknowledgement.BoardID,
		SummaryID:              acknowledgement.SummaryID,
		Jurisdiction:           acknowledgement.Jurisdiction,
		ServiceCode:            acknowledgement.ServiceCode,
		ServiceTier:            acknowledgement.ServiceTier,
		EvaluatedAt:            acknowledgement.EvaluatedAt.UTC(),
		FocusLane:              acknowledgement.FocusLane,
		FocusAction:            acknowledgement.FocusAction,
		Severity:               acknowledgement.Severity,
		AckStatus:              acknowledgement.AckStatus,
		AckAction:              acknowledgement.AckAction,
		ReceiptStatus:          secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus(acknowledgement),
		ReceiptAction:          secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptAction(acknowledgement),
		ReceiptDueAt:           acknowledgement.AckDueAt,
		ReceiptOverdueSeconds:  acknowledgement.AckOverdueSeconds,
		ReceiptEvidence:        secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidence(acknowledgement),
		LeadRole:               acknowledgement.LeadRole,
		RequiredRoles:          append([]string(nil), acknowledgement.RequiredRoles...),
		RequiredPendingActions: append([]string(nil), acknowledgement.RequiredPendingActions...),
		EscalationRequired:     acknowledgement.EscalationRequired,
		AssignmentCount:        acknowledgement.AssignmentCount,
		Assignments:            append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment(nil), acknowledgement.Assignments...),
		Items:                  append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem(nil), acknowledgement.Items...),
		AcknowledgementDigest:  acknowledgement.AcknowledgementDigest,
		GeneratedAt:            generatedAt.UTC(),
	}
	receipt.ReceiptDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptDigest(receipt)
	receipt.AcknowledgementReceiptID = "government-agent-execution-launch-closure-automation-acknowledgement-receipt:" + firstNonEmpty(receipt.Jurisdiction, "all") + ":" + receipt.ReceiptDigest[:12]
	return receipt
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus(
	acknowledgement SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus {
	if acknowledgement.AckStatus == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue {
		return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusOverdue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatusAwaiting
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptAction(
	acknowledgement SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement,
) string {
	if acknowledgement.AckStatus == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue {
		if acknowledgement.EscalationRequired {
			return "escalate_missing_launch_closure_ack_receipt"
		}
		return "recover_missing_launch_closure_ack_receipt"
	}
	return "collect_launch_closure_ack_receipt"
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptEvidence(
	acknowledgement SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgement,
) []string {
	evidence := []string{
		"directive_digest_confirmation",
		"lead_role_acknowledgement",
		"assignment_acceptance_receipt",
	}
	if acknowledgement.AckStatus == SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatusOverdue {
		evidence = append(evidence, "overdue_acknowledgement_explanation")
	}
	if acknowledgement.EscalationRequired {
		evidence = append(evidence, "escalation_owner_confirmation")
	}
	return uniqueTrimmedStrings(evidence)
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptDigest(
	receipt SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceipt,
) string {
	core := struct {
		AcknowledgementID      string                                                                                `json:"acknowledgement_id"`
		DirectiveID            string                                                                                `json:"directive_id"`
		FocusLane              SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardLane                    `json:"focus_lane"`
		FocusAction            string                                                                                `json:"focus_action"`
		Severity               SecureCellGovernmentAgentExecutionLaunchClosureAutomationBriefSeverity                `json:"severity"`
		AckStatus              SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementStatus        `json:"ack_status"`
		AckAction              string                                                                                `json:"ack_action"`
		ReceiptStatus          SecureCellGovernmentAgentExecutionLaunchClosureAutomationAcknowledgementReceiptStatus `json:"receipt_status"`
		ReceiptAction          string                                                                                `json:"receipt_action"`
		ReceiptDueAt           *time.Time                                                                            `json:"receipt_due_at,omitempty"`
		ReceiptOverdueSeconds  int64                                                                                 `json:"receipt_overdue_seconds"`
		ReceiptEvidence        []string                                                                              `json:"receipt_evidence,omitempty"`
		LeadRole               string                                                                                `json:"lead_role"`
		RequiredRoles          []string                                                                              `json:"required_roles,omitempty"`
		RequiredPendingActions []string                                                                              `json:"required_pending_actions,omitempty"`
		EscalationRequired     bool                                                                                  `json:"escalation_required"`
		Assignments            []SecureCellGovernmentAgentExecutionLaunchClosureAutomationDispatchAssignment         `json:"assignments"`
		Items                  []SecureCellGovernmentAgentExecutionLaunchClosureAutomationBoardItem                  `json:"items"`
		AcknowledgementDigest  string                                                                                `json:"acknowledgement_digest"`
	}{
		AcknowledgementID:      receipt.AcknowledgementID,
		DirectiveID:            receipt.DirectiveID,
		FocusLane:              receipt.FocusLane,
		FocusAction:            receipt.FocusAction,
		Severity:               receipt.Severity,
		AckStatus:              receipt.AckStatus,
		AckAction:              receipt.AckAction,
		ReceiptStatus:          receipt.ReceiptStatus,
		ReceiptAction:          receipt.ReceiptAction,
		ReceiptDueAt:           receipt.ReceiptDueAt,
		ReceiptOverdueSeconds:  receipt.ReceiptOverdueSeconds,
		ReceiptEvidence:        receipt.ReceiptEvidence,
		LeadRole:               receipt.LeadRole,
		RequiredRoles:          receipt.RequiredRoles,
		RequiredPendingActions: receipt.RequiredPendingActions,
		EscalationRequired:     receipt.EscalationRequired,
		Assignments:            receipt.Assignments,
		Items:                  receipt.Items,
		AcknowledgementDigest:  receipt.AcknowledgementDigest,
	}
	return EvidenceHash(core)
}
