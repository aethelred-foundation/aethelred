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

// SecureCellFederationCounterproposal captures one counterparty-offered policy
// narrowing proposal against a pending federation invitation.
type SecureCellFederationCounterproposal struct {
	ID                        string                                   `json:"id"`
	InvitationID              string                                   `json:"invitation_id"`
	OrganizationID            string                                   `json:"organization_id"`
	SponsorOfRecord           string                                   `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                   `json:"organization_name,omitempty"`
	Jurisdiction              string                                   `json:"jurisdiction,omitempty"`
	Status                    SecureCellFederationCounterproposalStatus `json:"status"`
	OfferedSessionScopeIDs    []string                                 `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses        []string                                 `json:"offered_data_classes,omitempty"`
	OfferedComputeZones       []string                                 `json:"offered_compute_zones,omitempty"`
	OfferedActions            []string                                 `json:"offered_actions,omitempty"`
	NegotiatedSessionScopeIDs []string                                 `json:"negotiated_session_scope_ids,omitempty"`
	NegotiatedDataClasses     []string                                 `json:"negotiated_data_classes,omitempty"`
	NegotiatedComputeZones    []string                                 `json:"negotiated_compute_zones,omitempty"`
	NegotiatedActions         []string                                 `json:"negotiated_actions,omitempty"`
	NegotiationDiffs          []SecureCellFederationPolicyDiff         `json:"negotiation_diffs,omitempty"`
	Resource                  string                                   `json:"resource,omitempty"`
	SubmittedBy               string                                   `json:"submitted_by,omitempty"`
	ApprovedBy                string                                   `json:"approved_by,omitempty"`
	RejectedBy                string                                   `json:"rejected_by,omitempty"`
	SupersededBy              string                                   `json:"superseded_by,omitempty"`
	Reason                    string                                   `json:"reason,omitempty"`
	CreatedAt                 time.Time                                `json:"created_at,omitempty"`
	ApprovedAt                *time.Time                               `json:"approved_at,omitempty"`
	RejectedAt                *time.Time                               `json:"rejected_at,omitempty"`
	SupersededAt              *time.Time                               `json:"superseded_at,omitempty"`
	UpdatedAt                 time.Time                                `json:"updated_at,omitempty"`
	Metadata                  map[string]string                        `json:"metadata,omitempty"`
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
	CellID          string                                   `json:"cell_id,omitempty"`
	OrganizationID  string                                   `json:"organization_id,omitempty"`
	InvitationID    string                                   `json:"invitation_id,omitempty"`
	Status          SecureCellFederationCounterproposalStatus `json:"status,omitempty"`
	SponsorOfRecord string                                   `json:"sponsor_of_record,omitempty"`
	SubmittedBy     string                                   `json:"submitted_by,omitempty"`
	UpdatedAfter    *time.Time                               `json:"updated_after,omitempty"`
	UpdatedBefore   *time.Time                               `json:"updated_before,omitempty"`
	Limit           int                                      `json:"limit,omitempty"`
}

// SecureCellFederationCounterproposalSummary is the operator-facing summary of
// one replayable invitation negotiation proposal.
type SecureCellFederationCounterproposalSummary struct {
	CellID                    string                                   `json:"cell_id"`
	CellName                  string                                   `json:"cell_name,omitempty"`
	CellStatus                SecureCellStatus                         `json:"cell_status"`
	Jurisdiction              string                                   `json:"jurisdiction,omitempty"`
	CounterproposalID         string                                   `json:"counterproposal_id"`
	InvitationID              string                                   `json:"invitation_id"`
	OrganizationID            string                                   `json:"organization_id"`
	SponsorOfRecord           string                                   `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                   `json:"organization_name,omitempty"`
	Status                    SecureCellFederationCounterproposalStatus `json:"status"`
	OfferedSessionScopeIDs    []string                                 `json:"offered_session_scope_ids,omitempty"`
	OfferedSessionScopeCount  int                                      `json:"offered_session_scope_count"`
	OfferedDataClasses        []string                                 `json:"offered_data_classes,omitempty"`
	OfferedDataClassCount     int                                      `json:"offered_data_class_count"`
	OfferedComputeZones       []string                                 `json:"offered_compute_zones,omitempty"`
	OfferedComputeZoneCount   int                                      `json:"offered_compute_zone_count"`
	OfferedActions            []string                                 `json:"offered_actions,omitempty"`
	OfferedActionCount        int                                      `json:"offered_action_count"`
	NegotiatedSessionScopeIDs []string                                 `json:"negotiated_session_scope_ids,omitempty"`
	NegotiatedSessionCount    int                                      `json:"negotiated_session_scope_count"`
	NegotiatedDataClasses     []string                                 `json:"negotiated_data_classes,omitempty"`
	NegotiatedDataClassCount  int                                      `json:"negotiated_data_class_count"`
	NegotiatedComputeZones    []string                                 `json:"negotiated_compute_zones,omitempty"`
	NegotiatedComputeCount    int                                      `json:"negotiated_compute_zone_count"`
	NegotiatedActions         []string                                 `json:"negotiated_actions,omitempty"`
	NegotiatedActionCount     int                                      `json:"negotiated_action_count"`
	NegotiationDiffs          []SecureCellFederationPolicyDiff         `json:"negotiation_diffs,omitempty"`
	NegotiationDiffCount      int                                      `json:"negotiation_diff_count"`
	Resource                  string                                   `json:"resource,omitempty"`
	SubmittedBy               string                                   `json:"submitted_by,omitempty"`
	ApprovedBy                string                                   `json:"approved_by,omitempty"`
	RejectedBy                string                                   `json:"rejected_by,omitempty"`
	SupersededBy              string                                   `json:"superseded_by,omitempty"`
	Reason                    string                                   `json:"reason,omitempty"`
	ControlLedgerID           string                                   `json:"control_ledger_id,omitempty"`
	PortablePackageHash       string                                   `json:"portable_package_hash,omitempty"`
	PortablePackageSigned     bool                                     `json:"portable_package_signed"`
	PortablePackageAnchored   bool                                     `json:"portable_package_anchored"`
	CreatedAt                 time.Time                                `json:"created_at,omitempty"`
	ApprovedAt                *time.Time                               `json:"approved_at,omitempty"`
	RejectedAt                *time.Time                               `json:"rejected_at,omitempty"`
	SupersededAt              *time.Time                               `json:"superseded_at,omitempty"`
	UpdatedAt                 time.Time                                `json:"updated_at,omitempty"`
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
			"federation_counterproposal_id": counterproposal.ID,
			"federation_invitation_id":      counterproposal.InvitationID,
			"federation_organization_id":    counterproposal.OrganizationID,
			"federation_sponsor_of_record":  counterproposal.SponsorOfRecord,
			"federation_offered_actions":    strings.Join(counterproposal.OfferedActions, ","),
			"federation_offered_scopes":     strings.Join(counterproposal.OfferedSessionScopeIDs, ","),
			"federation_policy_diffs":       secureCellFederationPolicyDiffsSummary(counterproposal.NegotiationDiffs),
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
	if !secureCellFederationOwnerActorAllowed(run, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to approve federation counterproposals", ErrPolicyDenied, actorDID)
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
	run.result.FederationCounterproposals[idx].UpdatedAt = now
	run.result.FederationCounterproposals[idx].Metadata = mergeStringMaps(run.result.FederationCounterproposals[idx].Metadata, lifecycle.Metadata)
	run.result.FederationInvitations[inviteIdx].ApprovedCounterproposalID = proposal.ID
	run.result.FederationInvitations[inviteIdx].Metadata = mergeStringMaps(run.result.FederationInvitations[inviteIdx].Metadata, map[string]string{
		"approved_counterproposal_id": proposal.ID,
	})
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_counterproposal_approved", proposal.ID),
		Action:           "secure_cell.federation_counterproposal_approved",
		Actor:            actorDID,
		TargetType:       "federation_counterproposal",
		TargetDID:        proposal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_counterproposal_id": proposal.ID,
			"federation_invitation_id":      proposal.InvitationID,
			"federation_organization_id":    proposal.OrganizationID,
			"federation_sponsor_of_record":  proposal.SponsorOfRecord,
			"federation_offered_actions":    strings.Join(proposal.OfferedActions, ","),
			"federation_policy_diffs":       secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
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
	if !secureCellFederationOwnerActorAllowed(run, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to reject federation counterproposals", ErrPolicyDenied, actorDID)
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
			"federation_counterproposal_id": proposal.ID,
			"federation_invitation_id":      proposal.InvitationID,
			"federation_organization_id":    proposal.OrganizationID,
			"federation_sponsor_of_record":  proposal.SponsorOfRecord,
			"federation_offered_actions":    strings.Join(proposal.OfferedActions, ","),
			"federation_policy_diffs":       secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
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
