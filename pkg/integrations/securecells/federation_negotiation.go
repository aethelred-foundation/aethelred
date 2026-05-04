package securecells

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationCounterproposalStatus tracks one replayable invitation
// negotiation proposal before cross-org acceptance.
type SecureCellFederationCounterproposalStatus string

const (
	SecureCellFederationCounterproposalStatusPending    SecureCellFederationCounterproposalStatus = "pending"
	SecureCellFederationCounterproposalStatusApproved   SecureCellFederationCounterproposalStatus = "approved"
	SecureCellFederationCounterproposalStatusRejected   SecureCellFederationCounterproposalStatus = "rejected"
	SecureCellFederationCounterproposalStatusSuperseded SecureCellFederationCounterproposalStatus = "superseded"
)

type SecureCellFederationCounterproposalVoteChoice string

const (
	SecureCellFederationCounterproposalVoteChoiceApprove SecureCellFederationCounterproposalVoteChoice = "approve"
	SecureCellFederationCounterproposalVoteChoiceReject  SecureCellFederationCounterproposalVoteChoice = "reject"
)

// SecureCellFederationEscalationTier defines one timed approver expansion tier
// for a pending federation counterproposal.
type SecureCellFederationEscalationTier struct {
	TierID    string            `json:"tier_id,omitempty"`
	TargetDID string            `json:"target_did,omitempty"`
	DueAt     *time.Time        `json:"due_at,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationCounterproposalVote captures one evidence-bearing
// approval or rejection recorded against a pending counterproposal.
type SecureCellFederationCounterproposalVote struct {
	ID                string                                        `json:"id"`
	CounterproposalID string                                        `json:"counterproposal_id"`
	ActorDID          string                                        `json:"actor_did"`
	Choice            SecureCellFederationCounterproposalVoteChoice `json:"choice"`
	Reason            string                                        `json:"reason,omitempty"`
	PolicyReceiptID   string                                        `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                        `json:"policy_receipt_hash,omitempty"`
	CreatedAt         time.Time                                     `json:"created_at,omitempty"`
	Metadata          map[string]string                             `json:"metadata,omitempty"`
}

// SecureCellFederationCounterproposal captures one counterparty-offered policy
// narrowing proposal against a pending federation invitation.
type SecureCellFederationCounterproposal struct {
	ID                        string                                    `json:"id"`
	InvitationID              string                                    `json:"invitation_id"`
	OrganizationID            string                                    `json:"organization_id"`
	SponsorOfRecord           string                                    `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                    `json:"organization_name,omitempty"`
	Jurisdiction              string                                    `json:"jurisdiction,omitempty"`
	Status                    SecureCellFederationCounterproposalStatus `json:"status"`
	OfferedSessionScopeIDs    []string                                  `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses        []string                                  `json:"offered_data_classes,omitempty"`
	OfferedComputeZones       []string                                  `json:"offered_compute_zones,omitempty"`
	OfferedActions            []string                                  `json:"offered_actions,omitempty"`
	NegotiatedSessionScopeIDs []string                                  `json:"negotiated_session_scope_ids,omitempty"`
	NegotiatedDataClasses     []string                                  `json:"negotiated_data_classes,omitempty"`
	NegotiatedComputeZones    []string                                  `json:"negotiated_compute_zones,omitempty"`
	NegotiatedActions         []string                                  `json:"negotiated_actions,omitempty"`
	NegotiationDiffs          []SecureCellFederationPolicyDiff          `json:"negotiation_diffs,omitempty"`
	GovernanceTemplate        string                                    `json:"governance_template,omitempty"`
	ApprovalThreshold         int                                       `json:"approval_threshold,omitempty"`
	EligibleApproverDIDs      []string                                  `json:"eligible_approver_dids,omitempty"`
	ApprovalVotes             []SecureCellFederationCounterproposalVote `json:"approval_votes,omitempty"`
	EscalationLadder          []SecureCellFederationEscalationTier      `json:"escalation_ladder,omitempty"`
	EscalatedTierIDs          []string                                  `json:"escalated_tier_ids,omitempty"`
	ResolutionDueAt           *time.Time                                `json:"resolution_due_at,omitempty"`
	AutoSuspendOnOverdue      bool                                      `json:"auto_suspend_on_overdue,omitempty"`
	Resource                  string                                    `json:"resource,omitempty"`
	SubmittedBy               string                                    `json:"submitted_by,omitempty"`
	ApprovedBy                string                                    `json:"approved_by,omitempty"`
	RejectedBy                string                                    `json:"rejected_by,omitempty"`
	SupersededBy              string                                    `json:"superseded_by,omitempty"`
	Reason                    string                                    `json:"reason,omitempty"`
	CreatedAt                 time.Time                                 `json:"created_at,omitempty"`
	ApprovedAt                *time.Time                                `json:"approved_at,omitempty"`
	RejectedAt                *time.Time                                `json:"rejected_at,omitempty"`
	SupersededAt              *time.Time                                `json:"superseded_at,omitempty"`
	UpdatedAt                 time.Time                                 `json:"updated_at,omitempty"`
	Metadata                  map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationCounterproposalRequest submits one replayable
// counterproposal against a pending federation invitation.
type SecureCellFederationCounterproposalRequest struct {
	ActorDID               string            `json:"actor_did,omitempty"`
	OfferedSessionScopeIDs []string          `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string          `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string          `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string          `json:"offered_actions,omitempty"`
	Resource               string            `json:"resource,omitempty"`
	Reason                 string            `json:"reason,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationCounterproposalFilter narrows operator queries across
// invitation counterproposal history.
type SecureCellFederationCounterproposalFilter struct {
	CellID          string                                    `json:"cell_id,omitempty"`
	OrganizationID  string                                    `json:"organization_id,omitempty"`
	InvitationID    string                                    `json:"invitation_id,omitempty"`
	Status          SecureCellFederationCounterproposalStatus `json:"status,omitempty"`
	SponsorOfRecord string                                    `json:"sponsor_of_record,omitempty"`
	SubmittedBy     string                                    `json:"submitted_by,omitempty"`
	UpdatedAfter    *time.Time                                `json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time                                `json:"updated_before,omitempty"`
	Limit           int                                       `json:"limit,omitempty"`
}

// SecureCellFederationCounterproposalSummary is the operator-facing summary of
// one replayable invitation negotiation proposal.
type SecureCellFederationCounterproposalSummary struct {
	CellID                    string                                    `json:"cell_id"`
	CellName                  string                                    `json:"cell_name,omitempty"`
	CellStatus                SecureCellStatus                          `json:"cell_status"`
	Jurisdiction              string                                    `json:"jurisdiction,omitempty"`
	CounterproposalID         string                                    `json:"counterproposal_id"`
	InvitationID              string                                    `json:"invitation_id"`
	OrganizationID            string                                    `json:"organization_id"`
	SponsorOfRecord           string                                    `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                    `json:"organization_name,omitempty"`
	Status                    SecureCellFederationCounterproposalStatus `json:"status"`
	OfferedSessionScopeIDs    []string                                  `json:"offered_session_scope_ids,omitempty"`
	OfferedSessionScopeCount  int                                       `json:"offered_session_scope_count"`
	OfferedDataClasses        []string                                  `json:"offered_data_classes,omitempty"`
	OfferedDataClassCount     int                                       `json:"offered_data_class_count"`
	OfferedComputeZones       []string                                  `json:"offered_compute_zones,omitempty"`
	OfferedComputeZoneCount   int                                       `json:"offered_compute_zone_count"`
	OfferedActions            []string                                  `json:"offered_actions,omitempty"`
	OfferedActionCount        int                                       `json:"offered_action_count"`
	NegotiatedSessionScopeIDs []string                                  `json:"negotiated_session_scope_ids,omitempty"`
	NegotiatedSessionCount    int                                       `json:"negotiated_session_scope_count"`
	NegotiatedDataClasses     []string                                  `json:"negotiated_data_classes,omitempty"`
	NegotiatedDataClassCount  int                                       `json:"negotiated_data_class_count"`
	NegotiatedComputeZones    []string                                  `json:"negotiated_compute_zones,omitempty"`
	NegotiatedComputeCount    int                                       `json:"negotiated_compute_zone_count"`
	NegotiatedActions         []string                                  `json:"negotiated_actions,omitempty"`
	NegotiatedActionCount     int                                       `json:"negotiated_action_count"`
	NegotiationDiffs          []SecureCellFederationPolicyDiff          `json:"negotiation_diffs,omitempty"`
	NegotiationDiffCount      int                                       `json:"negotiation_diff_count"`
	GovernanceTemplate        string                                    `json:"governance_template,omitempty"`
	ApprovalThreshold         int                                       `json:"approval_threshold,omitempty"`
	EligibleApproverCount     int                                       `json:"eligible_approver_count"`
	ApprovalVoteCount         int                                       `json:"approval_vote_count"`
	ApproveVoteCount          int                                       `json:"approve_vote_count"`
	RejectVoteCount           int                                       `json:"reject_vote_count"`
	ThresholdSatisfied        bool                                      `json:"threshold_satisfied"`
	EscalationTierCount       int                                       `json:"escalation_tier_count"`
	EscalatedTierCount        int                                       `json:"escalated_tier_count"`
	ResolutionDueAt           *time.Time                                `json:"resolution_due_at,omitempty"`
	AutoSuspendOnOverdue      bool                                      `json:"auto_suspend_on_overdue"`
	Resource                  string                                    `json:"resource,omitempty"`
	SubmittedBy               string                                    `json:"submitted_by,omitempty"`
	ApprovedBy                string                                    `json:"approved_by,omitempty"`
	RejectedBy                string                                    `json:"rejected_by,omitempty"`
	SupersededBy              string                                    `json:"superseded_by,omitempty"`
	Reason                    string                                    `json:"reason,omitempty"`
	ControlLedgerID           string                                    `json:"control_ledger_id,omitempty"`
	PortablePackageHash       string                                    `json:"portable_package_hash,omitempty"`
	PortablePackageSigned     bool                                      `json:"portable_package_signed"`
	PortablePackageAnchored   bool                                      `json:"portable_package_anchored"`
	CreatedAt                 time.Time                                 `json:"created_at,omitempty"`
	ApprovedAt                *time.Time                                `json:"approved_at,omitempty"`
	RejectedAt                *time.Time                                `json:"rejected_at,omitempty"`
	SupersededAt              *time.Time                                `json:"superseded_at,omitempty"`
	UpdatedAt                 time.Time                                 `json:"updated_at,omitempty"`
}

// SecureCellOverdueFederationCounterproposalFilter narrows operator queries
// over federation proposals that have crossed a governance deadline.
type SecureCellOverdueFederationCounterproposalFilter struct {
	CellID          string     `json:"cell_id,omitempty"`
	OrganizationID  string     `json:"organization_id,omitempty"`
	InvitationID    string     `json:"invitation_id,omitempty"`
	SponsorOfRecord string     `json:"sponsor_of_record,omitempty"`
	SubmittedBy     string     `json:"submitted_by,omitempty"`
	Before          *time.Time `json:"before,omitempty"`
	Limit           int        `json:"limit,omitempty"`
}

// SecureCellOverdueFederationCounterproposal projects one pending proposal
// whose next governance milestone has gone overdue.
type SecureCellOverdueFederationCounterproposal struct {
	CellID               string                                    `json:"cell_id"`
	CellName             string                                    `json:"cell_name,omitempty"`
	Jurisdiction         string                                    `json:"jurisdiction,omitempty"`
	CellStatus           SecureCellStatus                          `json:"cell_status"`
	OrganizationID       string                                    `json:"organization_id"`
	InvitationID         string                                    `json:"invitation_id"`
	CounterproposalID    string                                    `json:"counterproposal_id"`
	Status               SecureCellFederationCounterproposalStatus `json:"status"`
	GovernanceTemplate   string                                    `json:"governance_template,omitempty"`
	AutomationAction     string                                    `json:"automation_action"`
	OverdueReason        string                                    `json:"overdue_reason"`
	TierID               string                                    `json:"tier_id,omitempty"`
	TargetDID            string                                    `json:"target_did,omitempty"`
	DueAt                time.Time                                 `json:"due_at"`
	OverdueSeconds       int64                                     `json:"overdue_seconds"`
	ResolutionDueAt      *time.Time                                `json:"resolution_due_at,omitempty"`
	AutoSuspendOnOverdue bool                                      `json:"auto_suspend_on_overdue"`
	UpdatedAt            time.Time                                 `json:"updated_at"`
}

// SecureCellFederationAutomationActionFilter narrows operator queries over
// automated federation governance actions already applied to secure cells.
type SecureCellFederationAutomationActionFilter struct {
	CellID            string     `json:"cell_id,omitempty"`
	OrganizationID    string     `json:"organization_id,omitempty"`
	InvitationID      string     `json:"invitation_id,omitempty"`
	CounterproposalID string     `json:"counterproposal_id,omitempty"`
	ContractID        string     `json:"contract_id,omitempty"`
	Action            string     `json:"action,omitempty"`
	Since             *time.Time `json:"since,omitempty"`
	Until             *time.Time `json:"until,omitempty"`
	Limit             int        `json:"limit,omitempty"`
}

// SecureCellFederationAutomationActionRecord projects one automated
// escalation, rejection, or suspension action from the federation trail.
type SecureCellFederationAutomationActionRecord struct {
	CellID                      string                                    `json:"cell_id"`
	CellName                    string                                    `json:"cell_name,omitempty"`
	Jurisdiction                string                                    `json:"jurisdiction,omitempty"`
	CellStatus                  SecureCellStatus                          `json:"cell_status"`
	OrganizationID              string                                    `json:"organization_id,omitempty"`
	InvitationID                string                                    `json:"invitation_id,omitempty"`
	CounterproposalID           string                                    `json:"counterproposal_id,omitempty"`
	CounterproposalStatusBefore SecureCellFederationCounterproposalStatus `json:"counterproposal_status_before,omitempty"`
	CounterproposalStatusAfter  SecureCellFederationCounterproposalStatus `json:"counterproposal_status_after,omitempty"`
	ContractID                  string                                    `json:"contract_id,omitempty"`
	ContractStatusBefore        SecureCellFederationContractStatus        `json:"contract_status_before,omitempty"`
	ContractStatusAfter         SecureCellFederationContractStatus        `json:"contract_status_after,omitempty"`
	Action                      string                                    `json:"action"`
	TierID                      string                                    `json:"tier_id,omitempty"`
	TargetDID                   string                                    `json:"target_did,omitempty"`
	Trigger                     string                                    `json:"trigger,omitempty"`
	DueAt                       *time.Time                                `json:"due_at,omitempty"`
	Actor                       string                                    `json:"actor"`
	AutomatedActor              string                                    `json:"automated_actor,omitempty"`
	Reason                      string                                    `json:"reason,omitempty"`
	TransitionID                string                                    `json:"transition_id"`
	OccurredAt                  time.Time                                 `json:"occurred_at"`
	Metadata                    map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationGovernanceSweepResult summarizes one federation
// governance automation sweep across live secure cells.
type SecureCellFederationGovernanceSweepResult struct {
	At                        time.Time `json:"at"`
	CellsScanned              int       `json:"cells_scanned"`
	CounterproposalsScanned   int       `json:"counterproposals_scanned"`
	CellsMutated              int       `json:"cells_mutated"`
	CounterproposalsEscalated int       `json:"counterproposals_escalated"`
	CounterproposalsRejected  int       `json:"counterproposals_rejected"`
	ContractsSuspended        int       `json:"contracts_suspended"`
	CellIDs                   []string  `json:"cell_ids,omitempty"`
}

// ListFederationCounterproposals returns operator-facing negotiation summaries
// across the current secure-cell set.
func (s *Service) ListFederationCounterproposals(_ context.Context, filter SecureCellFederationCounterproposalFilter) ([]SecureCellFederationCounterproposalSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationCounterproposalSummary
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, proposal := range run.result.FederationCounterproposals {
			summary := secureCellFederationCounterproposalSummaryFromRun(run, proposal)
			if !matchesSecureCellFederationCounterproposalFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// SubmitFederationCounterproposal records one replayable narrowing proposal
// against a pending federation invitation.
func (s *Service) SubmitFederationCounterproposal(ctx context.Context, cellID string, invitationID string, request SecureCellFederationCounterproposalRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit federation negotiation while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	inviteIdx, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, invitationID)
	if invitation == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationInvitationNotFound, invitationID)
	}
	if invitation.Status != SecureCellFederationInvitationStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation invitation %q is %s", ErrFederationInvitationImmutable, invitationID, invitation.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(request.ActorDID), strings.TrimSpace(invitation.ExpectedDID))
	if !secureCellFederationCounterproposalActorAllowed(run, *invitation, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to counterpropose federation terms", ErrPolicyDenied, actorDID)
	}

	invitationTerms := secureCellInvitationTerms(*invitation)
	offeredTerms, err := secureCellFederationOfferedTerms(run.result.Sessions, request.OfferedSessionScopeIDs, request.OfferedDataClasses, request.OfferedComputeZones, request.OfferedActions)
	if err != nil {
		return nil, err
	}
	negotiatedTerms, diffs, err := secureCellNegotiateFederationTerms(invitationTerms, offeredTerms)
	if err != nil {
		return nil, err
	}
	if err := secureCellValidateNegotiatedFederationTerms(run.request.Policy, negotiatedTerms); err != nil {
		return nil, err
	}

	resource := firstNonEmpty(strings.TrimSpace(request.Resource), strings.TrimSpace(invitation.Resource))
	receipt, err := s.evaluateStage(ctx, run.request, "counterpropose_federation_invitation", lastReceiptHash(run.result), map[string]string{
		"federation_invitation_id":          invitation.ID,
		"federation_organization_id":        invitation.OrganizationID,
		"federation_sponsor_of_record":      invitation.SponsorOfRecord,
		"federation_offered_session_scopes": strings.Join(uniqueTrimmedStrings(offeredTerms.SessionScopeIDs), ","),
		"federation_offered_data_classes":   strings.Join(uniqueTrimmedStrings(offeredTerms.DataClasses), ","),
		"federation_offered_compute_zones":  strings.Join(uniqueTrimmedStrings(offeredTerms.ComputeZones), ","),
		"federation_offered_actions":        strings.Join(uniqueTrimmedStrings(offeredTerms.AllowedActions), ","),
		"federation_session_scopes":         strings.Join(uniqueTrimmedStrings(negotiatedTerms.SessionScopeIDs), ","),
		"federation_data_classes":           strings.Join(uniqueTrimmedStrings(negotiatedTerms.DataClasses), ","),
		"federation_compute_zones":          strings.Join(uniqueTrimmedStrings(negotiatedTerms.ComputeZones), ","),
		"federation_allowed_actions":        strings.Join(uniqueTrimmedStrings(negotiatedTerms.AllowedActions), ","),
		"federation_policy_diffs":           secureCellFederationPolicyDiffsSummary(diffs),
		"transition_reason":                 strings.TrimSpace(request.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	counterproposal := SecureCellFederationCounterproposal{
		ID:                        secureCellFederationCounterproposalID(run.request, *invitation, actorDID, len(run.result.FederationCounterproposals), resource, offeredTerms),
		InvitationID:              invitation.ID,
		OrganizationID:            invitation.OrganizationID,
		SponsorOfRecord:           invitation.SponsorOfRecord,
		OrganizationName:          invitation.OrganizationName,
		Jurisdiction:              firstNonEmpty(strings.TrimSpace(invitation.Jurisdiction), run.request.Jurisdiction),
		Status:                    SecureCellFederationCounterproposalStatusPending,
		OfferedSessionScopeIDs:    append([]string(nil), uniqueTrimmedStrings(offeredTerms.SessionScopeIDs)...),
		OfferedDataClasses:        append([]string(nil), uniqueTrimmedStrings(offeredTerms.DataClasses)...),
		OfferedComputeZones:       append([]string(nil), uniqueTrimmedStrings(offeredTerms.ComputeZones)...),
		OfferedActions:            append([]string(nil), uniqueTrimmedStrings(offeredTerms.AllowedActions)...),
		NegotiatedSessionScopeIDs: append([]string(nil), uniqueTrimmedStrings(negotiatedTerms.SessionScopeIDs)...),
		NegotiatedDataClasses:     append([]string(nil), uniqueTrimmedStrings(negotiatedTerms.DataClasses)...),
		NegotiatedComputeZones:    append([]string(nil), uniqueTrimmedStrings(negotiatedTerms.ComputeZones)...),
		NegotiatedActions:         append([]string(nil), uniqueTrimmedStrings(negotiatedTerms.AllowedActions)...),
		NegotiationDiffs:          cloneSecureCellFederationPolicyDiffs(diffs),
		GovernanceTemplate:        strings.TrimSpace(invitation.CounterproposalGovernanceTemplate),
		ApprovalThreshold:         secureCellMaxInt(1, invitation.CounterproposalApprovalThreshold),
		EligibleApproverDIDs:      append([]string(nil), uniqueTrimmedStrings(invitation.CounterproposalEligibleApproverDIDs)...),
		EscalationLadder:          cloneSecureCellFederationEscalationTiers(invitation.CounterproposalEscalationLadder),
		ResolutionDueAt:           cloneTimePtr(invitation.CounterproposalResolutionDueAt),
		AutoSuspendOnOverdue:      invitation.CounterproposalAutoSuspendOnOverdue,
		Resource:                  strings.TrimSpace(resource),
		SubmittedBy:               actorDID,
		Reason:                    strings.TrimSpace(request.Reason),
		CreatedAt:                 now,
		UpdatedAt:                 now,
		Metadata:                  cloneStringMap(request.Metadata),
	}
	run.result.FederationCounterproposals = append(run.result.FederationCounterproposals, counterproposal)
	run.result.FederationInvitations[inviteIdx].Metadata = mergeStringMaps(run.result.FederationInvitations[inviteIdx].Metadata, map[string]string{
		"last_counterproposal_id": counterproposal.ID,
	})
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_counterproposed", counterproposal.ID),
		Action:           "secure_cell.federation_counterproposed",
		Actor:            actorDID,
		TargetType:       "federation_counterproposal",
		TargetDID:        counterproposal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           counterproposal.Reason,
		Metadata: mergeStringMaps(counterproposal.Metadata, map[string]string{
			"federation_counterproposal_id":                 counterproposal.ID,
			"federation_invitation_id":                      counterproposal.InvitationID,
			"federation_organization_id":                    counterproposal.OrganizationID,
			"federation_sponsor_of_record":                  counterproposal.SponsorOfRecord,
			"federation_counterproposal_approval_threshold": fmt.Sprintf("%d", counterproposal.ApprovalThreshold),
			"federation_counterproposal_eligible_approvers": strings.Join(counterproposal.EligibleApproverDIDs, ","),
			"federation_counterproposal_escalation_tiers":   strings.Join(secureCellFederationEscalationTierIDs(counterproposal.EscalationLadder), ","),
			"federation_offered_actions":                    strings.Join(counterproposal.OfferedActions, ","),
			"federation_offered_scopes":                     strings.Join(counterproposal.OfferedSessionScopeIDs, ","),
			"federation_policy_diffs":                       secureCellFederationPolicyDiffsSummary(counterproposal.NegotiationDiffs),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ApproveFederationCounterproposal marks one pending proposal as the approved
// negotiation posture for a pending invitation.
func (s *Service) ApproveFederationCounterproposal(ctx context.Context, cellID string, counterproposalID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	idx, proposal := findSecureCellFederationCounterproposal(run.result.FederationCounterproposals, counterproposalID)
	if proposal == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationCounterproposalNotFound, counterproposalID)
	}
	if proposal.Status != SecureCellFederationCounterproposalStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation counterproposal %q is %s", ErrFederationCounterproposalImmutable, counterproposalID, proposal.Status)
	}
	inviteIdx, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, proposal.InvitationID)
	if invitation == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationInvitationNotFound, proposal.InvitationID)
	}
	if invitation.Status != SecureCellFederationInvitationStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation invitation %q is %s", ErrFederationInvitationImmutable, proposal.InvitationID, invitation.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationCounterproposalApproverAllowed(*proposal, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to approve federation counterproposals", ErrPolicyDenied, actorDID)
	}
	if secureCellFederationCounterproposalHasVote(*proposal, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q already reviewed federation counterproposal %q", ErrFederationCounterproposalImmutable, actorDID, counterproposalID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "approve_federation_counterproposal", lastReceiptHash(run.result), map[string]string{
		"federation_counterproposal_id": counterproposalID,
		"federation_invitation_id":      proposal.InvitationID,
		"federation_organization_id":    proposal.OrganizationID,
		"federation_sponsor_of_record":  proposal.SponsorOfRecord,
		"federation_offered_actions":    strings.Join(uniqueTrimmedStrings(proposal.OfferedActions), ","),
		"federation_session_scopes":     strings.Join(uniqueTrimmedStrings(proposal.NegotiatedSessionScopeIDs), ","),
		"federation_data_classes":       strings.Join(uniqueTrimmedStrings(proposal.NegotiatedDataClasses), ","),
		"federation_compute_zones":      strings.Join(uniqueTrimmedStrings(proposal.NegotiatedComputeZones), ","),
		"federation_allowed_actions":    strings.Join(uniqueTrimmedStrings(proposal.NegotiatedActions), ","),
		"federation_policy_diffs":       secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
		"transition_reason":             strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	statusBefore := proposal.Status
	vote := SecureCellFederationCounterproposalVote{
		ID:                secureCellFederationCounterproposalVoteID(proposal.ID, actorDID, SecureCellFederationCounterproposalVoteChoiceApprove, len(run.result.FederationCounterproposals[idx].ApprovalVotes)),
		CounterproposalID: proposal.ID,
		ActorDID:          actorDID,
		Choice:            SecureCellFederationCounterproposalVoteChoiceApprove,
		Reason:            strings.TrimSpace(lifecycle.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(lifecycle.Metadata),
	}
	run.result.FederationCounterproposals[idx].ApprovalVotes = append(run.result.FederationCounterproposals[idx].ApprovalVotes, vote)
	run.result.FederationCounterproposals[idx].UpdatedAt = now
	run.result.FederationCounterproposals[idx].Metadata = mergeStringMaps(run.result.FederationCounterproposals[idx].Metadata, lifecycle.Metadata)
	approvalCount, _ := secureCellFederationCounterproposalVoteCounts(run.result.FederationCounterproposals[idx])
	thresholdSatisfied := approvalCount >= secureCellMaxInt(1, run.result.FederationCounterproposals[idx].ApprovalThreshold)
	transitionAction := "secure_cell.federation_counterproposal_vote_recorded"
	transitionReason := firstNonEmpty(strings.TrimSpace(lifecycle.Reason), proposal.Reason)
	if thresholdSatisfied {
		transitionAction = "secure_cell.federation_counterproposal_approved"
		for proposalIdx := range run.result.FederationCounterproposals {
			item := &run.result.FederationCounterproposals[proposalIdx]
			if strings.TrimSpace(item.InvitationID) != proposal.InvitationID || item.Status != SecureCellFederationCounterproposalStatusApproved || item.ID == proposal.ID {
				continue
			}
			item.Status = SecureCellFederationCounterproposalStatusSuperseded
			item.SupersededBy = proposal.ID
			item.SupersededAt = cloneTimePtr(&now)
			item.UpdatedAt = now
			item.Metadata = mergeStringMaps(item.Metadata, map[string]string{"superseded_by_counterproposal_id": proposal.ID})
		}
		run.result.FederationCounterproposals[idx].Status = SecureCellFederationCounterproposalStatusApproved
		run.result.FederationCounterproposals[idx].ApprovedBy = actorDID
		run.result.FederationCounterproposals[idx].ApprovedAt = cloneTimePtr(&now)
		run.result.FederationInvitations[inviteIdx].ApprovedCounterproposalID = proposal.ID
		run.result.FederationInvitations[inviteIdx].Metadata = mergeStringMaps(run.result.FederationInvitations[inviteIdx].Metadata, map[string]string{
			"approved_counterproposal_id": proposal.ID,
		})
	}
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, strings.TrimPrefix(transitionAction, "secure_cell."), proposal.ID),
		Action:           transitionAction,
		Actor:            actorDID,
		TargetType:       "federation_counterproposal",
		TargetDID:        proposal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           transitionReason,
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_counterproposal_id":            proposal.ID,
			"federation_counterproposal_status_before": string(statusBefore),
			"federation_counterproposal_status_after":  string(run.result.FederationCounterproposals[idx].Status),
			"federation_invitation_id":                 proposal.InvitationID,
			"federation_organization_id":               proposal.OrganizationID,
			"federation_sponsor_of_record":             proposal.SponsorOfRecord,
			"federation_vote_id":                       vote.ID,
			"federation_vote_choice":                   string(vote.Choice),
			"federation_approval_threshold":            fmt.Sprintf("%d", run.result.FederationCounterproposals[idx].ApprovalThreshold),
			"federation_approval_votes":                fmt.Sprintf("%d", approvalCount),
			"federation_threshold_satisfied":           fmt.Sprintf("%t", thresholdSatisfied),
			"federation_offered_actions":               strings.Join(proposal.OfferedActions, ","),
			"federation_policy_diffs":                  secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RejectFederationCounterproposal marks one pending proposal as rejected while
// preserving its replayable negotiation evidence.
func (s *Service) RejectFederationCounterproposal(ctx context.Context, cellID string, counterproposalID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	idx, proposal := findSecureCellFederationCounterproposal(run.result.FederationCounterproposals, counterproposalID)
	if proposal == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationCounterproposalNotFound, counterproposalID)
	}
	if proposal.Status != SecureCellFederationCounterproposalStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation counterproposal %q is %s", ErrFederationCounterproposalImmutable, counterproposalID, proposal.Status)
	}
	if _, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, proposal.InvitationID); invitation == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationInvitationNotFound, proposal.InvitationID)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationOwnerActorAllowed(run, actorDID) && !secureCellFederationCounterproposalApproverAllowed(*proposal, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to reject federation counterproposals", ErrPolicyDenied, actorDID)
	}
	if secureCellFederationCounterproposalHasVote(*proposal, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q already reviewed federation counterproposal %q", ErrFederationCounterproposalImmutable, actorDID, counterproposalID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "reject_federation_counterproposal", lastReceiptHash(run.result), map[string]string{
		"federation_counterproposal_id": counterproposalID,
		"federation_invitation_id":      proposal.InvitationID,
		"federation_organization_id":    proposal.OrganizationID,
		"federation_sponsor_of_record":  proposal.SponsorOfRecord,
		"federation_offered_actions":    strings.Join(uniqueTrimmedStrings(proposal.OfferedActions), ","),
		"federation_policy_diffs":       secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
		"transition_reason":             strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	statusBefore := proposal.Status
	vote := SecureCellFederationCounterproposalVote{
		ID:                secureCellFederationCounterproposalVoteID(proposal.ID, actorDID, SecureCellFederationCounterproposalVoteChoiceReject, len(run.result.FederationCounterproposals[idx].ApprovalVotes)),
		CounterproposalID: proposal.ID,
		ActorDID:          actorDID,
		Choice:            SecureCellFederationCounterproposalVoteChoiceReject,
		Reason:            strings.TrimSpace(lifecycle.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(lifecycle.Metadata),
	}
	run.result.FederationCounterproposals[idx].ApprovalVotes = append(run.result.FederationCounterproposals[idx].ApprovalVotes, vote)
	run.result.FederationCounterproposals[idx].Status = SecureCellFederationCounterproposalStatusRejected
	run.result.FederationCounterproposals[idx].RejectedBy = actorDID
	run.result.FederationCounterproposals[idx].RejectedAt = cloneTimePtr(&now)
	run.result.FederationCounterproposals[idx].UpdatedAt = now
	run.result.FederationCounterproposals[idx].Reason = firstNonEmpty(strings.TrimSpace(lifecycle.Reason), run.result.FederationCounterproposals[idx].Reason)
	run.result.FederationCounterproposals[idx].Metadata = mergeStringMaps(run.result.FederationCounterproposals[idx].Metadata, lifecycle.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_counterproposal_rejected", proposal.ID),
		Action:           "secure_cell.federation_counterproposal_rejected",
		Actor:            actorDID,
		TargetType:       "federation_counterproposal",
		TargetDID:        proposal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(lifecycle.Reason), proposal.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_counterproposal_id":            proposal.ID,
			"federation_counterproposal_status_before": string(statusBefore),
			"federation_counterproposal_status_after":  string(run.result.FederationCounterproposals[idx].Status),
			"federation_invitation_id":                 proposal.InvitationID,
			"federation_organization_id":               proposal.OrganizationID,
			"federation_sponsor_of_record":             proposal.SponsorOfRecord,
			"federation_vote_id":                       vote.ID,
			"federation_vote_choice":                   string(vote.Choice),
			"federation_offered_actions":               strings.Join(proposal.OfferedActions, ","),
			"federation_policy_diffs":                  secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationCounterproposalID(req SecureCellRequest, invitation SecureCellFederationInvitation, actorDID string, ordinal int, resource string, offeredTerms secureCellFederationTerms) string {
	seed := fmt.Sprintf(
		"%s|%s|%s|%s|%d|%s|%s|%s|%s|%s",
		cellID(req),
		invitation.ID,
		invitation.OrganizationID,
		strings.TrimSpace(actorDID),
		ordinal+1,
		strings.TrimSpace(resource),
		strings.Join(uniqueTrimmedStrings(offeredTerms.SessionScopeIDs), ","),
		strings.Join(uniqueTrimmedStrings(offeredTerms.DataClasses), ","),
		strings.Join(uniqueTrimmedStrings(offeredTerms.ComputeZones), ","),
		strings.Join(uniqueTrimmedStrings(offeredTerms.AllowedActions), ","),
	)
	return fmt.Sprintf("%s-federation-counterproposal-%x", cellID(req), sha256.Sum256([]byte(seed)))
}

func findSecureCellFederationCounterproposal(items []SecureCellFederationCounterproposal, counterproposalID string) (int, *SecureCellFederationCounterproposal) {
	counterproposalID = strings.TrimSpace(counterproposalID)
	for idx := range items {
		if strings.TrimSpace(items[idx].ID) == counterproposalID {
			return idx, &items[idx]
		}
	}
	return -1, nil
}

func secureCellFederationCounterproposalForInvitation(items []SecureCellFederationCounterproposal, invitationID string, status SecureCellFederationCounterproposalStatus) *SecureCellFederationCounterproposal {
	var best *SecureCellFederationCounterproposal
	for idx := range items {
		item := &items[idx]
		if strings.TrimSpace(item.InvitationID) != strings.TrimSpace(invitationID) {
			continue
		}
		if status != "" && item.Status != status {
			continue
		}
		if best == nil || secureCellFederationCounterproposalUpdatedAt(*item).After(secureCellFederationCounterproposalUpdatedAt(*best)) {
			best = item
		}
	}
	return best
}

func secureCellFederationCounterproposalUpdatedAt(item SecureCellFederationCounterproposal) time.Time {
	switch {
	case item.SupersededAt != nil && !item.SupersededAt.IsZero():
		return item.SupersededAt.UTC()
	case item.RejectedAt != nil && !item.RejectedAt.IsZero():
		return item.RejectedAt.UTC()
	case item.ApprovedAt != nil && !item.ApprovedAt.IsZero():
		return item.ApprovedAt.UTC()
	case !item.UpdatedAt.IsZero():
		return item.UpdatedAt.UTC()
	default:
		return item.CreatedAt.UTC()
	}
}

func secureCellFederationCounterproposalActorAllowed(run *secureCellRun, invitation SecureCellFederationInvitation, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	if secureCellActorAllowed(run, actorDID, false) {
		return true
	}
	if expected := strings.TrimSpace(invitation.ExpectedDID); expected != "" && expected == actorDID {
		return true
	}
	return false
}

func secureCellFederationOwnerActorAllowed(run *secureCellRun, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	return run != nil && run.request.OwnerIdentity != nil && actorDID != "" && run.request.OwnerIdentity.AgentID() == actorDID
}

func secureCellFederationCounterproposalSummaryFromRun(run *secureCellRun, proposal SecureCellFederationCounterproposal) SecureCellFederationCounterproposalSummary {
	approveVotes, rejectVotes := secureCellFederationCounterproposalVoteCounts(proposal)
	summary := SecureCellFederationCounterproposalSummary{
		CellID:                    safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                  safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                safeSecureCellStatus(run),
		Jurisdiction:              firstNonEmpty(strings.TrimSpace(proposal.Jurisdiction), safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) })),
		CounterproposalID:         strings.TrimSpace(proposal.ID),
		InvitationID:              strings.TrimSpace(proposal.InvitationID),
		OrganizationID:            strings.TrimSpace(proposal.OrganizationID),
		SponsorOfRecord:           strings.TrimSpace(proposal.SponsorOfRecord),
		OrganizationName:          strings.TrimSpace(proposal.OrganizationName),
		Status:                    proposal.Status,
		OfferedSessionScopeIDs:    append([]string(nil), uniqueTrimmedStrings(proposal.OfferedSessionScopeIDs)...),
		OfferedSessionScopeCount:  len(uniqueTrimmedStrings(proposal.OfferedSessionScopeIDs)),
		OfferedDataClasses:        append([]string(nil), uniqueTrimmedStrings(proposal.OfferedDataClasses)...),
		OfferedDataClassCount:     len(uniqueTrimmedStrings(proposal.OfferedDataClasses)),
		OfferedComputeZones:       append([]string(nil), uniqueTrimmedStrings(proposal.OfferedComputeZones)...),
		OfferedComputeZoneCount:   len(uniqueTrimmedStrings(proposal.OfferedComputeZones)),
		OfferedActions:            append([]string(nil), uniqueTrimmedStrings(proposal.OfferedActions)...),
		OfferedActionCount:        len(uniqueTrimmedStrings(proposal.OfferedActions)),
		NegotiatedSessionScopeIDs: append([]string(nil), uniqueTrimmedStrings(proposal.NegotiatedSessionScopeIDs)...),
		NegotiatedSessionCount:    len(uniqueTrimmedStrings(proposal.NegotiatedSessionScopeIDs)),
		NegotiatedDataClasses:     append([]string(nil), uniqueTrimmedStrings(proposal.NegotiatedDataClasses)...),
		NegotiatedDataClassCount:  len(uniqueTrimmedStrings(proposal.NegotiatedDataClasses)),
		NegotiatedComputeZones:    append([]string(nil), uniqueTrimmedStrings(proposal.NegotiatedComputeZones)...),
		NegotiatedComputeCount:    len(uniqueTrimmedStrings(proposal.NegotiatedComputeZones)),
		NegotiatedActions:         append([]string(nil), uniqueTrimmedStrings(proposal.NegotiatedActions)...),
		NegotiatedActionCount:     len(uniqueTrimmedStrings(proposal.NegotiatedActions)),
		NegotiationDiffs:          cloneSecureCellFederationPolicyDiffs(proposal.NegotiationDiffs),
		NegotiationDiffCount:      len(proposal.NegotiationDiffs),
		GovernanceTemplate:        strings.TrimSpace(proposal.GovernanceTemplate),
		ApprovalThreshold:         secureCellMaxInt(1, proposal.ApprovalThreshold),
		EligibleApproverCount:     len(uniqueTrimmedStrings(proposal.EligibleApproverDIDs)),
		ApprovalVoteCount:         len(proposal.ApprovalVotes),
		ApproveVoteCount:          approveVotes,
		RejectVoteCount:           rejectVotes,
		ThresholdSatisfied:        approveVotes >= secureCellMaxInt(1, proposal.ApprovalThreshold),
		EscalationTierCount:       len(proposal.EscalationLadder),
		EscalatedTierCount:        len(uniqueTrimmedStrings(proposal.EscalatedTierIDs)),
		ResolutionDueAt:           cloneTimePtr(proposal.ResolutionDueAt),
		AutoSuspendOnOverdue:      proposal.AutoSuspendOnOverdue,
		Resource:                  strings.TrimSpace(proposal.Resource),
		SubmittedBy:               strings.TrimSpace(proposal.SubmittedBy),
		ApprovedBy:                strings.TrimSpace(proposal.ApprovedBy),
		RejectedBy:                strings.TrimSpace(proposal.RejectedBy),
		SupersededBy:              strings.TrimSpace(proposal.SupersededBy),
		Reason:                    strings.TrimSpace(proposal.Reason),
		CreatedAt:                 proposal.CreatedAt.UTC(),
		ApprovedAt:                cloneTimePtr(proposal.ApprovedAt),
		RejectedAt:                cloneTimePtr(proposal.RejectedAt),
		SupersededAt:              cloneTimePtr(proposal.SupersededAt),
		UpdatedAt:                 secureCellFederationCounterproposalUpdatedAt(proposal),
	}
	if run.result.ControlLedger != nil {
		summary.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
	}
	if run.result.PortablePackage != nil {
		summary.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		summary.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		summary.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return summary
}

func matchesSecureCellFederationCounterproposalFilter(summary SecureCellFederationCounterproposalSummary, filter SecureCellFederationCounterproposalFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(summary.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.InvitationID != "" && !strings.EqualFold(summary.InvitationID, strings.TrimSpace(filter.InvitationID)) {
		return false
	}
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.SponsorOfRecord != "" && !strings.EqualFold(summary.SponsorOfRecord, strings.TrimSpace(filter.SponsorOfRecord)) {
		return false
	}
	if filter.SubmittedBy != "" && !strings.EqualFold(summary.SubmittedBy, strings.TrimSpace(filter.SubmittedBy)) {
		return false
	}
	if filter.UpdatedAfter != nil && summary.UpdatedAt.Before(filter.UpdatedAfter.UTC()) {
		return false
	}
	if filter.UpdatedBefore != nil && summary.UpdatedAt.After(filter.UpdatedBefore.UTC()) {
		return false
	}
	return true
}

func secureCellFederationCounterproposalsForOrganization(run *secureCellRun, organizationID string) []SecureCellFederationCounterproposalSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationCounterproposalSummary, 0)
	for _, proposal := range run.result.FederationCounterproposals {
		if strings.TrimSpace(proposal.OrganizationID) != strings.TrimSpace(organizationID) {
			continue
		}
		items = append(items, secureCellFederationCounterproposalSummaryFromRun(run, proposal))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func secureCellFederationCounterproposalsForInvitation(run *secureCellRun, invitationID string) []SecureCellFederationCounterproposalSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationCounterproposalSummary, 0)
	for _, proposal := range run.result.FederationCounterproposals {
		if strings.TrimSpace(proposal.InvitationID) != strings.TrimSpace(invitationID) {
			continue
		}
		items = append(items, secureCellFederationCounterproposalSummaryFromRun(run, proposal))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func secureCellFederationCounterproposalsByStatus(items []SecureCellFederationCounterproposal, status SecureCellFederationCounterproposalStatus) []SecureCellFederationCounterproposal {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationCounterproposal, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func secureCellFederationCounterproposalVoteCounts(item SecureCellFederationCounterproposal) (int, int) {
	approveVotes := 0
	rejectVotes := 0
	for _, vote := range item.ApprovalVotes {
		switch vote.Choice {
		case SecureCellFederationCounterproposalVoteChoiceApprove:
			approveVotes++
		case SecureCellFederationCounterproposalVoteChoiceReject:
			rejectVotes++
		}
	}
	return approveVotes, rejectVotes
}

func secureCellFederationCounterproposalHasVote(item SecureCellFederationCounterproposal, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, vote := range item.ApprovalVotes {
		if strings.EqualFold(strings.TrimSpace(vote.ActorDID), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationCounterproposalApproverAllowed(item SecureCellFederationCounterproposal, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, candidate := range item.EligibleApproverDIDs {
		if strings.EqualFold(strings.TrimSpace(candidate), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationCounterproposalVoteID(counterproposalID string, actorDID string, choice SecureCellFederationCounterproposalVoteChoice, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(counterproposalID), strings.TrimSpace(actorDID), string(choice), ordinal+1)
	return fmt.Sprintf("%s-vote-%x", strings.TrimSpace(counterproposalID), sha256.Sum256([]byte(seed)))
}

func normalizeSecureCellFederationApproverDIDs(ownerDID string, candidates []string) []string {
	items := uniqueTrimmedStrings(candidates)
	if len(items) == 0 && strings.TrimSpace(ownerDID) != "" {
		return []string{strings.TrimSpace(ownerDID)}
	}
	return items
}

func normalizeSecureCellFederationEscalationLadder(items []SecureCellFederationEscalationTier, resolutionDueAt *time.Time) ([]SecureCellFederationEscalationTier, error) {
	if len(items) == 0 {
		return nil, nil
	}
	normalized := make([]SecureCellFederationEscalationTier, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	var previous time.Time
	for idx, item := range items {
		targetDID := strings.TrimSpace(item.TargetDID)
		if targetDID == "" {
			return nil, fmt.Errorf("securecells/service: federation escalation ladder tier %d target_did is required", idx+1)
		}
		if item.DueAt == nil || item.DueAt.IsZero() {
			return nil, fmt.Errorf("securecells/service: federation escalation ladder tier %d due_at is required", idx+1)
		}
		tierID := firstNonEmpty(strings.TrimSpace(item.TierID), fmt.Sprintf("tier-%d", idx+1))
		if _, ok := seen[tierID]; ok {
			return nil, fmt.Errorf("securecells/service: duplicate federation escalation ladder tier_id %q", tierID)
		}
		seen[tierID] = struct{}{}
		dueAt := item.DueAt.UTC()
		if !previous.IsZero() && !dueAt.After(previous) {
			return nil, fmt.Errorf("securecells/service: federation escalation ladder due_at values must be increasing")
		}
		if resolutionDueAt != nil && !resolutionDueAt.IsZero() && !resolutionDueAt.UTC().After(dueAt) {
			return nil, fmt.Errorf("securecells/service: federation resolution due time must be after escalation due time")
		}
		normalized = append(normalized, SecureCellFederationEscalationTier{
			TierID:    tierID,
			TargetDID: targetDID,
			DueAt:     cloneTimePtr(&dueAt),
			Reason:    strings.TrimSpace(item.Reason),
			Metadata:  cloneStringMap(item.Metadata),
		})
		previous = dueAt
	}
	return normalized, nil
}

func cloneSecureCellFederationEscalationTiers(items []SecureCellFederationEscalationTier) []SecureCellFederationEscalationTier {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationEscalationTier, 0, len(items))
	for _, item := range items {
		out = append(out, SecureCellFederationEscalationTier{
			TierID:    strings.TrimSpace(item.TierID),
			TargetDID: strings.TrimSpace(item.TargetDID),
			DueAt:     cloneTimePtr(item.DueAt),
			Reason:    strings.TrimSpace(item.Reason),
			Metadata:  cloneStringMap(item.Metadata),
		})
	}
	return out
}

func secureCellFederationEscalationTierIDs(items []SecureCellFederationEscalationTier) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if tierID := strings.TrimSpace(item.TierID); tierID != "" {
			out = append(out, tierID)
		}
	}
	return out
}

func secureCellFederationEscalationTierTargets(items []SecureCellFederationEscalationTier) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if targetDID := strings.TrimSpace(item.TargetDID); targetDID != "" {
			out = append(out, targetDID)
		}
	}
	return out
}

func secureCellFederationNextDueEscalationTier(item SecureCellFederationCounterproposal, at time.Time) (SecureCellFederationEscalationTier, bool) {
	if len(item.EscalationLadder) == 0 {
		return SecureCellFederationEscalationTier{}, false
	}
	escalated := make(map[string]struct{}, len(item.EscalatedTierIDs))
	for _, tierID := range item.EscalatedTierIDs {
		if trimmed := strings.TrimSpace(tierID); trimmed != "" {
			escalated[trimmed] = struct{}{}
		}
	}
	for _, tier := range item.EscalationLadder {
		if tier.DueAt == nil || tier.DueAt.IsZero() {
			continue
		}
		if _, ok := escalated[strings.TrimSpace(tier.TierID)]; ok {
			continue
		}
		if !tier.DueAt.After(at) {
			return tier, true
		}
	}
	return SecureCellFederationEscalationTier{}, false
}

func secureCellFederationOverdueAction(item SecureCellFederationCounterproposal, at time.Time) (string, string, string, string, time.Time, bool) {
	if item.Status != SecureCellFederationCounterproposalStatusPending {
		return "", "", "", "", time.Time{}, false
	}
	if item.ResolutionDueAt != nil && !item.ResolutionDueAt.IsZero() && !item.ResolutionDueAt.After(at) {
		action := "reject"
		if item.AutoSuspendOnOverdue {
			action = "reject_and_suspend"
		}
		return action, "counterproposal review deadline reached", "", "", item.ResolutionDueAt.UTC(), true
	}
	if tier, ok := secureCellFederationNextDueEscalationTier(item, at); ok && tier.DueAt != nil && !tier.DueAt.IsZero() {
		return "escalate", firstNonEmpty(strings.TrimSpace(tier.Reason), "counterproposal escalation deadline reached"), strings.TrimSpace(tier.TierID), strings.TrimSpace(tier.TargetDID), tier.DueAt.UTC(), true
	}
	return "", "", "", "", time.Time{}, false
}

// ListOverdueFederationCounterproposals returns operator-facing projections for
// pending federation counterproposals that have crossed their next governance milestone.
func (s *Service) ListOverdueFederationCounterproposals(_ context.Context, filter SecureCellOverdueFederationCounterproposalFilter) ([]SecureCellOverdueFederationCounterproposal, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	invitationID := strings.TrimSpace(filter.InvitationID)
	sponsorOfRecord := strings.TrimSpace(filter.SponsorOfRecord)
	submittedBy := strings.TrimSpace(filter.SubmittedBy)
	items := make([]SecureCellOverdueFederationCounterproposal, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, proposal := range run.result.FederationCounterproposals {
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(proposal.OrganizationID), organizationID) {
				continue
			}
			if invitationID != "" && !strings.EqualFold(strings.TrimSpace(proposal.InvitationID), invitationID) {
				continue
			}
			if sponsorOfRecord != "" && !strings.EqualFold(strings.TrimSpace(proposal.SponsorOfRecord), sponsorOfRecord) {
				continue
			}
			if submittedBy != "" && !strings.EqualFold(strings.TrimSpace(proposal.SubmittedBy), submittedBy) {
				continue
			}
			action, reason, tierID, targetDID, dueAt, ok := secureCellFederationOverdueAction(proposal, at)
			if !ok {
				continue
			}
			items = append(items, SecureCellOverdueFederationCounterproposal{
				CellID:               run.result.CellID,
				CellName:             run.result.Name,
				Jurisdiction:         run.request.Jurisdiction,
				CellStatus:           run.result.Status,
				OrganizationID:       proposal.OrganizationID,
				InvitationID:         proposal.InvitationID,
				CounterproposalID:    proposal.ID,
				Status:               proposal.Status,
				GovernanceTemplate:   proposal.GovernanceTemplate,
				AutomationAction:     action,
				OverdueReason:        reason,
				TierID:               tierID,
				TargetDID:            targetDID,
				DueAt:                dueAt,
				OverdueSeconds:       int64(at.Sub(dueAt).Seconds()),
				ResolutionDueAt:      cloneTimePtr(proposal.ResolutionDueAt),
				AutoSuspendOnOverdue: proposal.AutoSuspendOnOverdue,
				UpdatedAt:            secureCellFederationCounterproposalUpdatedAt(proposal),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].CounterproposalID < items[j].CounterproposalID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellTransitionAutomatedFederationAction(transition SecureCellTransition) bool {
	if transition.Action == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_sweep_mode"]), "automated") {
		return true
	}
	return false
}

// ListFederationAutomationActions returns automated federation governance actions already
// applied by SLA sweeps.
func (s *Service) ListFederationAutomationActions(_ context.Context, filter SecureCellFederationAutomationActionFilter) ([]SecureCellFederationAutomationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	invitationID := strings.TrimSpace(filter.InvitationID)
	counterproposalID := strings.TrimSpace(filter.CounterproposalID)
	contractID := strings.TrimSpace(filter.ContractID)
	action := strings.TrimSpace(filter.Action)
	var since time.Time
	if filter.Since != nil && !filter.Since.IsZero() {
		since = filter.Since.UTC()
	}
	var until time.Time
	if filter.Until != nil && !filter.Until.IsZero() {
		until = filter.Until.UTC()
	}
	items := make([]SecureCellFederationAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationAction(transition) {
				continue
			}
			if action != "" && !strings.EqualFold(strings.TrimSpace(transition.Action), action) {
				continue
			}
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_organization_id"]), organizationID) {
				continue
			}
			if invitationID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_invitation_id"]), invitationID) {
				continue
			}
			if counterproposalID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_counterproposal_id"]), counterproposalID) {
				continue
			}
			if contractID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_contract_id"]), contractID) {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			items = append(items, SecureCellFederationAutomationActionRecord{
				CellID:                      run.result.CellID,
				CellName:                    run.result.Name,
				Jurisdiction:                run.request.Jurisdiction,
				CellStatus:                  run.result.Status,
				OrganizationID:              strings.TrimSpace(transition.Metadata["federation_organization_id"]),
				InvitationID:                strings.TrimSpace(transition.Metadata["federation_invitation_id"]),
				CounterproposalID:           strings.TrimSpace(transition.Metadata["federation_counterproposal_id"]),
				CounterproposalStatusBefore: SecureCellFederationCounterproposalStatus(strings.TrimSpace(transition.Metadata["federation_counterproposal_status_before"])),
				CounterproposalStatusAfter:  SecureCellFederationCounterproposalStatus(strings.TrimSpace(transition.Metadata["federation_counterproposal_status_after"])),
				ContractID:                  strings.TrimSpace(transition.Metadata["federation_contract_id"]),
				ContractStatusBefore:        SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_before"])),
				ContractStatusAfter:         SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_after"])),
				Action:                      transition.Action,
				TierID:                      strings.TrimSpace(transition.Metadata["automation_tier_id"]),
				TargetDID:                   strings.TrimSpace(transition.Metadata["automation_target_did"]),
				Trigger:                     strings.TrimSpace(transition.Metadata["federation_sweep_trigger"]),
				DueAt:                       parseSecureCellTransitionDueAt(transition.Metadata),
				Actor:                       transition.Actor,
				AutomatedActor:              strings.TrimSpace(transition.Metadata["automated_actor"]),
				Reason:                      transition.Reason,
				TransitionID:                transition.ID,
				OccurredAt:                  occurredAt,
				Metadata:                    cloneStringMap(transition.Metadata),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].TransitionID > items[j].TransitionID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// EscalateFederationCounterproposal expands the eligible approver set for a pending
// counterproposal using one configured escalation tier.
func (s *Service) EscalateFederationCounterproposal(ctx context.Context, cellID string, counterproposalID string, tierID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	idx, proposal := findSecureCellFederationCounterproposal(run.result.FederationCounterproposals, counterproposalID)
	if proposal == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationCounterproposalNotFound, counterproposalID)
	}
	if proposal.Status != SecureCellFederationCounterproposalStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation counterproposal %q is %s", ErrFederationCounterproposalImmutable, counterproposalID, proposal.Status)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationOwnerActorAllowed(run, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to escalate federation counterproposals", ErrPolicyDenied, actorDID)
	}
	var tier *SecureCellFederationEscalationTier
	for tierIdx := range proposal.EscalationLadder {
		item := &proposal.EscalationLadder[tierIdx]
		if strings.EqualFold(strings.TrimSpace(item.TierID), strings.TrimSpace(tierID)) {
			tier = item
			break
		}
	}
	if tier == nil {
		return nil, fmt.Errorf("securecells/service: %w: federation escalation tier %q is not configured", ErrFederationCounterproposalImmutable, tierID)
	}
	for _, escalatedTierID := range proposal.EscalatedTierIDs {
		if strings.EqualFold(strings.TrimSpace(escalatedTierID), strings.TrimSpace(tierID)) {
			return nil, fmt.Errorf("securecells/service: %w: federation escalation tier %q already applied", ErrFederationCounterproposalImmutable, tierID)
		}
	}

	receipt, err := s.evaluateStage(ctx, run.request, "escalate_federation_counterproposal", lastReceiptHash(run.result), map[string]string{
		"federation_counterproposal_id": counterproposalID,
		"federation_invitation_id":      proposal.InvitationID,
		"federation_organization_id":    proposal.OrganizationID,
		"federation_sponsor_of_record":  proposal.SponsorOfRecord,
		"automation_tier_id":            strings.TrimSpace(tier.TierID),
		"automation_target_did":         strings.TrimSpace(tier.TargetDID),
		"transition_reason":             strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	run.result.FederationCounterproposals[idx].EligibleApproverDIDs = uniqueTrimmedStrings(append(run.result.FederationCounterproposals[idx].EligibleApproverDIDs, strings.TrimSpace(tier.TargetDID)))
	run.result.FederationCounterproposals[idx].EscalatedTierIDs = uniqueTrimmedStrings(append(run.result.FederationCounterproposals[idx].EscalatedTierIDs, strings.TrimSpace(tier.TierID)))
	run.result.FederationCounterproposals[idx].UpdatedAt = now
	run.result.FederationCounterproposals[idx].Metadata = mergeStringMaps(run.result.FederationCounterproposals[idx].Metadata, lifecycle.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_counterproposal_escalated", proposal.ID),
		Action:           "secure_cell.federation_counterproposal_escalated",
		Actor:            actorDID,
		TargetType:       "federation_counterproposal",
		TargetDID:        proposal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(lifecycle.Reason), strings.TrimSpace(tier.Reason), proposal.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_counterproposal_id":            proposal.ID,
			"federation_counterproposal_status_before": string(proposal.Status),
			"federation_counterproposal_status_after":  string(run.result.FederationCounterproposals[idx].Status),
			"federation_invitation_id":                 proposal.InvitationID,
			"federation_organization_id":               proposal.OrganizationID,
			"federation_sponsor_of_record":             proposal.SponsorOfRecord,
			"automation_tier_id":                       strings.TrimSpace(tier.TierID),
			"automation_target_did":                    strings.TrimSpace(tier.TargetDID),
			"federation_eligible_approvers":            strings.Join(run.result.FederationCounterproposals[idx].EligibleApproverDIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if tier.DueAt != nil && !tier.DueAt.IsZero() {
		transition.Metadata["federation_sweep_due_at"] = tier.DueAt.UTC().Format(time.RFC3339Nano)
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// SweepFederationGovernance applies automated escalation, rejection, and contract
// suspension rules to pending federation counterproposals across every secure cell.
func (s *Service) SweepFederationGovernance(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationGovernanceSweepResult, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.RLock()
	cellIDs := make([]string, 0, len(s.runs))
	for cellID := range s.runs {
		cellIDs = append(cellIDs, cellID)
	}
	s.mu.RUnlock()
	sort.Strings(cellIDs)

	report := &SecureCellFederationGovernanceSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutated := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		report.CounterproposalsScanned += len(run.result.FederationCounterproposals)
		pending := append([]SecureCellFederationCounterproposal(nil), run.result.FederationCounterproposals...)
		for _, proposal := range pending {
			action, reason, tierID, _, dueAt, ok := secureCellFederationOverdueAction(proposal, at)
			if !ok {
				continue
			}
			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_sweep_mode":         "automated",
				"federation_sweep_action":       action,
				"federation_sweep_trigger":      firstNonEmpty(tierID, "resolution_due"),
				"federation_counterproposal_id": proposal.ID,
				"federation_invitation_id":      proposal.InvitationID,
				"federation_organization_id":    proposal.OrganizationID,
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				baseMetadata["automated_actor"] = automatedActor
			}
			baseMetadata["federation_sweep_due_at"] = dueAt.UTC().Format(time.RFC3339Nano)
			switch action {
			case "escalate":
				if _, err := s.EscalateFederationCounterproposal(ctx, cellID, proposal.ID, tierID, SecureCellLifecycleRequest{
					ActorDID: run.request.OwnerIdentity.AgentID(),
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), reason),
					Metadata: baseMetadata,
				}); err != nil {
					return nil, err
				}
				report.CounterproposalsEscalated++
				mutated[cellID] = struct{}{}
			case "reject", "reject_and_suspend":
				if action == "reject_and_suspend" {
					for _, contract := range activeFederationContractsForOrganization(run.result.FederationContracts, proposal.OrganizationID) {
						if _, err := s.SuspendFederationContract(ctx, cellID, contract.ID, SecureCellLifecycleRequest{
							ActorDID: run.request.OwnerIdentity.AgentID(),
							Reason:   "automated federation counterproposal deadline breach",
							Metadata: mergeStringMaps(baseMetadata, map[string]string{
								"federation_sweep_trigger":          "resolution_due",
								"federation_contract_id":            contract.ID,
								"federation_contract_status_before": string(contract.Status),
								"federation_contract_status_after":  string(SecureCellFederationContractStatusSuspended),
							}),
						}); err != nil {
							return nil, err
						}
						report.ContractsSuspended++
						mutated[cellID] = struct{}{}
					}
				}
				if _, err := s.RejectFederationCounterproposal(ctx, cellID, proposal.ID, SecureCellLifecycleRequest{
					ActorDID: run.request.OwnerIdentity.AgentID(),
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), reason),
					Metadata: baseMetadata,
				}); err != nil {
					return nil, err
				}
				report.CounterproposalsRejected++
				mutated[cellID] = struct{}{}
			}
		}
	}

	report.CellsMutated = len(mutated)
	if len(mutated) > 0 {
		report.CellIDs = make([]string, 0, len(mutated))
		for cellID := range mutated {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
	}
	return report, nil
}

func activeFederationContractsForOrganization(items []SecureCellFederationContract, organizationID string) []SecureCellFederationContract {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationContract, 0)
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(organizationID)) {
			continue
		}
		if item.Status == SecureCellFederationContractStatusActive {
			out = append(out, item)
		}
	}
	return out
}
