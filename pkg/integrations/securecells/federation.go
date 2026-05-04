package securecells

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

// SecureCellFederationOrganizationStatus tracks a collaborating organization
// inside one secure cell.
type SecureCellFederationOrganizationStatus string

const (
	SecureCellFederationOrganizationStatusPending SecureCellFederationOrganizationStatus = "pending"
	SecureCellFederationOrganizationStatusActive  SecureCellFederationOrganizationStatus = "active"
	SecureCellFederationOrganizationStatusRevoked SecureCellFederationOrganizationStatus = "revoked"
)

// SecureCellFederationInvitationStatus tracks one cross-organization join
// invitation into a secure cell.
type SecureCellFederationInvitationStatus string

const (
	SecureCellFederationInvitationStatusPending  SecureCellFederationInvitationStatus = "pending"
	SecureCellFederationInvitationStatusAccepted SecureCellFederationInvitationStatus = "accepted"
	SecureCellFederationInvitationStatusRevoked  SecureCellFederationInvitationStatus = "revoked"
)

// SecureCellFederationOrganization summarizes one participating organization.
type SecureCellFederationOrganization struct {
	OrganizationID   string                                 `json:"organization_id"`
	SponsorOfRecord  string                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName string                                 `json:"organization_name,omitempty"`
	Jurisdiction     string                                 `json:"jurisdiction,omitempty"`
	Status           SecureCellFederationOrganizationStatus `json:"status"`
	ParticipantDIDs  []string                               `json:"participant_dids,omitempty"`
	InvitationIDs    []string                               `json:"invitation_ids,omitempty"`
	CreatedAt        time.Time                              `json:"created_at,omitempty"`
	UpdatedAt        time.Time                              `json:"updated_at,omitempty"`
	Metadata         map[string]string                      `json:"metadata,omitempty"`
}

// SecureCellFederationInvitation captures one cross-organization invitation.
type SecureCellFederationInvitation struct {
	ID                     string                               `json:"id"`
	OrganizationID         string                               `json:"organization_id"`
	SponsorOfRecord        string                               `json:"sponsor_of_record,omitempty"`
	OrganizationName       string                               `json:"organization_name,omitempty"`
	Jurisdiction           string                               `json:"jurisdiction,omitempty"`
	ExpectedDID            string                               `json:"expected_did,omitempty"`
	Role                   string                               `json:"role,omitempty"`
	Status                 SecureCellFederationInvitationStatus `json:"status"`
	SessionScopeIDs        []string                             `json:"session_scope_ids,omitempty"`
	DataClasses            []string                             `json:"data_classes,omitempty"`
	ComputeZones           []string                             `json:"compute_zones,omitempty"`
	AllowedActions         []string                             `json:"allowed_actions,omitempty"`
	OfferedSessionScopeIDs []string                             `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string                             `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string                             `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string                             `json:"offered_actions,omitempty"`
	NegotiationDiffs       []SecureCellFederationPolicyDiff     `json:"negotiation_diffs,omitempty"`
	ApprovedCounterproposalID string                            `json:"approved_counterproposal_id,omitempty"`
	CounterproposalGovernanceTemplate string                    `json:"counterproposal_governance_template,omitempty"`
	CounterproposalApprovalThreshold int                        `json:"counterproposal_approval_threshold,omitempty"`
	CounterproposalEligibleApproverDIDs []string                `json:"counterproposal_eligible_approver_dids,omitempty"`
	CounterproposalEscalationLadder []SecureCellFederationEscalationTier `json:"counterproposal_escalation_ladder,omitempty"`
	CounterproposalResolutionDueAt *time.Time                   `json:"counterproposal_resolution_due_at,omitempty"`
	CounterproposalAutoSuspendOnOverdue bool                    `json:"counterproposal_auto_suspend_on_overdue,omitempty"`
	Resource               string                               `json:"resource,omitempty"`
	CreatedBy              string                               `json:"created_by,omitempty"`
	AcceptedBy             string                               `json:"accepted_by,omitempty"`
	RevokedBy              string                               `json:"revoked_by,omitempty"`
	Reason                 string                               `json:"reason,omitempty"`
	CreatedAt              time.Time                            `json:"created_at,omitempty"`
	AcceptedAt             *time.Time                           `json:"accepted_at,omitempty"`
	RevokedAt              *time.Time                           `json:"revoked_at,omitempty"`
	Metadata               map[string]string                    `json:"metadata,omitempty"`
}

// SecureCellFederationInviteRequest creates one cross-organization invitation.
type SecureCellFederationInviteRequest struct {
	ActorDID         string            `json:"actor_did,omitempty"`
	SponsorOfRecord  string            `json:"sponsor_of_record,omitempty"`
	OrganizationName string            `json:"organization_name,omitempty"`
	Jurisdiction     string            `json:"jurisdiction,omitempty"`
	ExpectedDID      string            `json:"expected_did,omitempty"`
	Role             string            `json:"role,omitempty"`
	SessionScopeIDs  []string          `json:"session_scope_ids,omitempty"`
	DataClasses      []string          `json:"data_classes,omitempty"`
	ComputeZones     []string          `json:"compute_zones,omitempty"`
	AllowedActions   []string          `json:"allowed_actions,omitempty"`
	CounterproposalGovernanceTemplate string `json:"counterproposal_governance_template,omitempty"`
	CounterproposalApprovalThreshold int `json:"counterproposal_approval_threshold,omitempty"`
	CounterproposalEligibleApproverDIDs []string `json:"counterproposal_eligible_approver_dids,omitempty"`
	CounterproposalEscalationLadder []SecureCellFederationEscalationTier `json:"counterproposal_escalation_ladder,omitempty"`
	CounterproposalResolutionDueAt *time.Time `json:"counterproposal_resolution_due_at,omitempty"`
	CounterproposalAutoSuspendOnOverdue bool `json:"counterproposal_auto_suspend_on_overdue,omitempty"`
	Resource         string            `json:"resource,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationAcceptRequest accepts one pending cross-organization
// invitation and joins the participant into the cell.
type SecureCellFederationAcceptRequest struct {
	InvitationID           string                `json:"invitation_id"`
	ActorDID               string                `json:"actor_did,omitempty"`
	Participant            SecureCellParticipant `json:"participant"`
	OfferedSessionScopeIDs []string              `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string              `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string              `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string              `json:"offered_actions,omitempty"`
	Reason                 string                `json:"reason,omitempty"`
	Metadata               map[string]string     `json:"metadata,omitempty"`
}

func deriveSecureCellFederationOrganizations(req SecureCellRequest, participants []SecureCellParticipantState) []SecureCellFederationOrganization {
	now := time.Now().UTC()
	participantByDID := make(map[string]SecureCellParticipantState, len(participants))
	for _, participant := range participants {
		participantByDID[strings.TrimSpace(participant.ParticipantDID)] = participant
	}

	orgs := make(map[string]*SecureCellFederationOrganization)
	addIdentity := func(identity *agent.AgentIdentity, participantDID string) {
		orgID, sponsor, name, jurisdiction := secureCellFederationIdentity(identity)
		if orgID == "" {
			return
		}
		org, ok := orgs[orgID]
		if !ok {
			org = &SecureCellFederationOrganization{
				OrganizationID:   orgID,
				SponsorOfRecord:  sponsor,
				OrganizationName: name,
				Jurisdiction:     jurisdiction,
				Status:           SecureCellFederationOrganizationStatusActive,
				CreatedAt:        now,
				UpdatedAt:        now,
			}
			orgs[orgID] = org
		}
		if participantDID != "" {
			org.ParticipantDIDs = append(org.ParticipantDIDs, participantDID)
			if state, ok := participantByDID[participantDID]; ok && state.Status == SecureCellParticipantStatusRevoked && org.Status != SecureCellFederationOrganizationStatusActive {
				org.Status = SecureCellFederationOrganizationStatusRevoked
			}
		}
	}

	addIdentity(req.OwnerIdentity, req.OwnerIdentity.AgentID())
	for _, participant := range req.Participants {
		if participant.Identity == nil {
			continue
		}
		addIdentity(participant.Identity, participant.Identity.AgentID())
	}

	items := make([]SecureCellFederationOrganization, 0, len(orgs))
	for _, org := range orgs {
		org.ParticipantDIDs = uniqueTrimmedStrings(org.ParticipantDIDs)
		items = append(items, *org)
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].OrganizationID < items[j].OrganizationID
	})
	return items
}

// CreateFederationInvitation creates one cross-organization onboarding
// invitation without yet mutating live membership.
func (s *Service) CreateFederationInvitation(ctx context.Context, cellID string, invite SecureCellFederationInviteRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit federation invitations while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(invite.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to create federation invitations", ErrPolicyDenied, actorDID)
	}
	sponsorOfRecord := strings.TrimSpace(invite.SponsorOfRecord)
	if sponsorOfRecord == "" {
		return nil, fmt.Errorf("securecells/service: sponsor of record is required for federation invitation")
	}
	role := firstNonEmpty(strings.TrimSpace(invite.Role), "participant")
	sessionScopeIDs, err := secureCellResolveFederationSessionScopes(run.result.Sessions, invite.SessionScopeIDs)
	if err != nil {
		return nil, err
	}
	dataClasses := uniqueTrimmedStrings(firstNonEmptySlice(invite.DataClasses, run.request.Policy.DataClasses))
	computeZones := uniqueTrimmedStrings(firstNonEmptySlice(invite.ComputeZones, run.request.Policy.ComputeZones))
	allowedActions, err := secureCellNormalizeFederationActions(invite.AllowedActions)
	if err != nil {
		return nil, err
	}
	if len(allowedActions) == 0 {
		allowedActions = secureCellDefaultFederationContractActions()
	}
	counterproposalGovernanceTemplate := strings.TrimSpace(invite.CounterproposalGovernanceTemplate)
	counterproposalApprovalThreshold := invite.CounterproposalApprovalThreshold
	if counterproposalApprovalThreshold <= 0 {
		counterproposalApprovalThreshold = 1
	}
	counterproposalEligibleApproverDIDs := normalizeSecureCellFederationApproverDIDs(run.request.OwnerIdentity.AgentID(), invite.CounterproposalEligibleApproverDIDs)
	counterproposalEscalationLadder, err := normalizeSecureCellFederationEscalationLadder(invite.CounterproposalEscalationLadder, invite.CounterproposalResolutionDueAt)
	if err != nil {
		return nil, err
	}
	orgID := secureCellFederationOrganizationID(sponsorOfRecord)
	resource := firstNonEmpty(strings.TrimSpace(invite.Resource), fmt.Sprintf("secure-cell:%s:federation:%s", run.result.CellID, orgID))

	orgIdx, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, orgID)
	if org == nil {
		run.result.FederationOrganizations = append(run.result.FederationOrganizations, SecureCellFederationOrganization{
			OrganizationID:   orgID,
			SponsorOfRecord:  sponsorOfRecord,
			OrganizationName: strings.TrimSpace(invite.OrganizationName),
			Jurisdiction:     firstNonEmpty(strings.TrimSpace(invite.Jurisdiction), run.request.Jurisdiction),
			Status:           SecureCellFederationOrganizationStatusPending,
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
			Metadata:         cloneStringMap(invite.Metadata),
		})
		orgIdx = len(run.result.FederationOrganizations) - 1
		org = &run.result.FederationOrganizations[orgIdx]
	}

	invitation := SecureCellFederationInvitation{
		ID:               secureCellFederationInvitationID(run.request, sponsorOfRecord, invite.ExpectedDID, role, len(run.result.FederationInvitations)),
		OrganizationID:   orgID,
		SponsorOfRecord:  sponsorOfRecord,
		OrganizationName: firstNonEmpty(strings.TrimSpace(invite.OrganizationName), org.OrganizationName),
		Jurisdiction:     firstNonEmpty(strings.TrimSpace(invite.Jurisdiction), org.Jurisdiction, run.request.Jurisdiction),
		ExpectedDID:      strings.TrimSpace(invite.ExpectedDID),
		Role:             role,
		Status:           SecureCellFederationInvitationStatusPending,
		SessionScopeIDs:  sessionScopeIDs,
		DataClasses:      dataClasses,
		ComputeZones:     computeZones,
		AllowedActions:   allowedActions,
		CounterproposalGovernanceTemplate: counterproposalGovernanceTemplate,
		CounterproposalApprovalThreshold: counterproposalApprovalThreshold,
		CounterproposalEligibleApproverDIDs: counterproposalEligibleApproverDIDs,
		CounterproposalEscalationLadder: cloneSecureCellFederationEscalationTiers(counterproposalEscalationLadder),
		CounterproposalResolutionDueAt: cloneTimePtr(invite.CounterproposalResolutionDueAt),
		CounterproposalAutoSuspendOnOverdue: invite.CounterproposalAutoSuspendOnOverdue,
		Resource:         resource,
		CreatedBy:        actorDID,
		Reason:           strings.TrimSpace(invite.Reason),
		CreatedAt:        time.Now().UTC(),
		Metadata:         cloneStringMap(invite.Metadata),
	}

	receipt, err := s.evaluateStage(ctx, run.request, "invite_federation_member", lastReceiptHash(run.result), map[string]string{
		"federation_invitation_id":     invitation.ID,
		"federation_organization_id":   invitation.OrganizationID,
		"federation_sponsor_of_record": invitation.SponsorOfRecord,
		"federation_expected_did":      invitation.ExpectedDID,
		"federation_role":              invitation.Role,
		"federation_session_scopes":    strings.Join(invitation.SessionScopeIDs, ","),
		"federation_allowed_actions":   strings.Join(invitation.AllowedActions, ","),
		"federation_counterproposal_governance_template": invitation.CounterproposalGovernanceTemplate,
		"federation_counterproposal_approval_threshold": fmt.Sprintf("%d", invitation.CounterproposalApprovalThreshold),
		"federation_counterproposal_eligible_approvers": strings.Join(invitation.CounterproposalEligibleApproverDIDs, ","),
		"federation_counterproposal_escalation_tiers": strings.Join(secureCellFederationEscalationTierIDs(invitation.CounterproposalEscalationLadder), ","),
		"cell_status_before":           string(run.result.Status),
		"transition_reason":            invitation.Reason,
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.result.FederationInvitations = append(run.result.FederationInvitations, invitation)
	run.result.FederationOrganizations[orgIdx].InvitationIDs = append(run.result.FederationOrganizations[orgIdx].InvitationIDs, invitation.ID)
	run.result.FederationOrganizations[orgIdx].UpdatedAt = time.Now().UTC()
	run.result.UpdatedAt = run.result.FederationOrganizations[orgIdx].UpdatedAt

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_invited", invitation.ID),
		Action:           "secure_cell.federation_invited",
		Actor:            actorDID,
		TargetType:       "federation_invitation",
		TargetDID:        invitation.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           invitation.Reason,
		Metadata: mergeStringMaps(invitation.Metadata, map[string]string{
			"federation_invitation_id":     invitation.ID,
			"federation_organization_id":   invitation.OrganizationID,
			"federation_sponsor_of_record": invitation.SponsorOfRecord,
			"federation_expected_did":      invitation.ExpectedDID,
			"federation_role":              invitation.Role,
			"federation_session_scopes":    strings.Join(invitation.SessionScopeIDs, ","),
			"federation_allowed_actions":   strings.Join(invitation.AllowedActions, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// AcceptFederationInvitation accepts a pending invitation and joins the
// participant into the cell under the invited sponsor-of-record.
func (s *Service) AcceptFederationInvitation(ctx context.Context, cellID string, acceptance SecureCellFederationAcceptRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not accept federation joins while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}
	if acceptance.Participant.Identity == nil {
		return nil, fmt.Errorf("securecells/service: participant identity is required")
	}
	if err := agent.VerifyIdentity(acceptance.Participant.Identity); err != nil {
		return nil, fmt.Errorf("securecells/service: invalid participant identity: %w", err)
	}

	inviteIdx, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, acceptance.InvitationID)
	if invitation == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationInvitationNotFound, acceptance.InvitationID)
	}
	if invitation.Status != SecureCellFederationInvitationStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation invitation %q is %s", ErrFederationInvitationImmutable, acceptance.InvitationID, invitation.Status)
	}
	participantDID := acceptance.Participant.Identity.AgentID()
	if invitation.ExpectedDID != "" && invitation.ExpectedDID != participantDID {
		return nil, fmt.Errorf("securecells/service: federation invitation %q expects %q, got %q", invitation.ID, invitation.ExpectedDID, participantDID)
	}
	if _, existing := findParticipantState(run.result.Participants, participantDID); existing != nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrParticipantExists, participantDID)
	}
	participantSponsor := secureCellFederationSponsor(acceptance.Participant.Identity)
	if participantSponsor == "" || participantSponsor != invitation.SponsorOfRecord {
		return nil, fmt.Errorf("securecells/service: federation participant sponsor %q does not match invitation sponsor %q", participantSponsor, invitation.SponsorOfRecord)
	}
	if len(activeOrQuarantinedParticipants(run.result.Participants))+1 > run.request.Policy.MaxParticipants {
		return nil, fmt.Errorf("securecells/service: participant count would exceed max participants %d", run.request.Policy.MaxParticipants)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(acceptance.ActorDID), participantDID)
	invitationTerms := secureCellInvitationTerms(*invitation)
	var (
		offeredTerms    secureCellFederationTerms
		negotiatedTerms secureCellFederationTerms
		diffs           []SecureCellFederationPolicyDiff
	)
	if approvedCounterproposalID := strings.TrimSpace(invitation.ApprovedCounterproposalID); approvedCounterproposalID != "" {
		approvedProposal := secureCellFederationCounterproposalForInvitation(run.result.FederationCounterproposals, invitation.ID, SecureCellFederationCounterproposalStatusApproved)
		if approvedProposal == nil || strings.TrimSpace(approvedProposal.ID) != approvedCounterproposalID {
			return nil, fmt.Errorf("securecells/service: %w: approved federation counterproposal %q is unavailable", ErrFederationNegotiationConflict, approvedCounterproposalID)
		}
		requestedOfferedTerms, err := secureCellFederationOfferedTerms(run.result.Sessions, acceptance.OfferedSessionScopeIDs, acceptance.OfferedDataClasses, acceptance.OfferedComputeZones, acceptance.OfferedActions)
		if err != nil {
			return nil, err
		}
		if !secureCellFederationTermsEmpty(requestedOfferedTerms) && !secureCellFederationTermsEqual(requestedOfferedTerms, secureCellFederationTerms{
			SessionScopeIDs: approvedProposal.OfferedSessionScopeIDs,
			DataClasses:     approvedProposal.OfferedDataClasses,
			ComputeZones:    approvedProposal.OfferedComputeZones,
			AllowedActions:  approvedProposal.OfferedActions,
		}) {
			return nil, fmt.Errorf("securecells/service: %w: acceptance terms do not match approved counterproposal %q", ErrFederationNegotiationConflict, approvedCounterproposalID)
		}
		offeredTerms = secureCellFederationTerms{
			SessionScopeIDs: append([]string(nil), approvedProposal.OfferedSessionScopeIDs...),
			DataClasses:     append([]string(nil), approvedProposal.OfferedDataClasses...),
			ComputeZones:    append([]string(nil), approvedProposal.OfferedComputeZones...),
			AllowedActions:  append([]string(nil), approvedProposal.OfferedActions...),
		}
		negotiatedTerms, diffs, err = secureCellNegotiateFederationTerms(invitationTerms, offeredTerms)
		if err != nil {
			return nil, err
		}
		if err := secureCellValidateNegotiatedFederationTerms(run.request.Policy, negotiatedTerms); err != nil {
			return nil, err
		}
	} else {
		offeredTerms, err = secureCellFederationOfferedTerms(run.result.Sessions, acceptance.OfferedSessionScopeIDs, acceptance.OfferedDataClasses, acceptance.OfferedComputeZones, acceptance.OfferedActions)
		if err != nil {
			return nil, err
		}
		negotiatedTerms, diffs, err = secureCellNegotiateFederationTerms(invitationTerms, offeredTerms)
		if err != nil {
			return nil, err
		}
		if err := secureCellValidateNegotiatedFederationTerms(run.request.Policy, negotiatedTerms); err != nil {
			return nil, err
		}
	}

	negotiatedStates, sessionIDs, err := s.negotiateParticipants(ctx, SecureCellRequest{
		OwnerIdentity: run.request.OwnerIdentity,
		Name:          run.request.Name,
		Purpose:       run.request.Purpose,
		Resource:      firstNonEmpty(strings.TrimSpace(invitation.Resource), run.request.Resource),
		Jurisdiction:  firstNonEmpty(strings.TrimSpace(invitation.Jurisdiction), run.request.Jurisdiction),
		Participants: []SecureCellParticipant{{
			Identity: acceptance.Participant.Identity,
			Role:     firstNonEmpty(strings.TrimSpace(acceptance.Participant.Role), invitation.Role, "participant"),
			Metadata: cloneStringMap(acceptance.Participant.Metadata),
		}},
		Policy:   run.request.Policy,
		Metadata: run.request.Metadata,
	})
	if err != nil {
		return nil, err
	}
	newState := negotiatedStates[0]
	newState.Status = SecureCellParticipantStatusActive
	newState.AddedAt = time.Now().UTC()
	newState.UpdatedAt = newState.AddedAt
	newState.Reason = strings.TrimSpace(acceptance.Reason)
	newState.Metadata = mergeStringMaps(newState.Metadata, acceptance.Metadata)

	receipt, err := s.evaluateStage(ctx, run.request, "accept_federation_invitation", lastReceiptHash(run.result), map[string]string{
		"federation_invitation_id":          invitation.ID,
		"federation_organization_id":        invitation.OrganizationID,
		"federation_sponsor_of_record":      invitation.SponsorOfRecord,
		"federation_session_scopes":         strings.Join(uniqueTrimmedStrings(negotiatedTerms.SessionScopeIDs), ","),
		"federation_data_classes":           strings.Join(uniqueTrimmedStrings(negotiatedTerms.DataClasses), ","),
		"federation_compute_zones":          strings.Join(uniqueTrimmedStrings(negotiatedTerms.ComputeZones), ","),
		"federation_allowed_actions":        strings.Join(uniqueTrimmedStrings(negotiatedTerms.AllowedActions), ","),
		"federation_offered_session_scopes": strings.Join(uniqueTrimmedStrings(offeredTerms.SessionScopeIDs), ","),
		"federation_offered_data_classes":   strings.Join(uniqueTrimmedStrings(offeredTerms.DataClasses), ","),
		"federation_offered_compute_zones":  strings.Join(uniqueTrimmedStrings(offeredTerms.ComputeZones), ","),
		"federation_offered_actions":        strings.Join(uniqueTrimmedStrings(offeredTerms.AllowedActions), ","),
		"federation_policy_diffs":           secureCellFederationPolicyDiffsSummary(diffs),
		"target_participant_did":            participantDID,
		"target_role":                       newState.Role,
		"cell_status_before":                string(run.result.Status),
		"participant_status_after":          string(newState.Status),
		"transition_reason":                 strings.TrimSpace(acceptance.Reason),
	}, actorDID)
	if err != nil {
		s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		s.markNegotiationsFailed(ctx, sessionIDs, "federation invitation acceptance denied by policy")
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.request.Participants = append(cloneParticipants(run.request.Participants), SecureCellParticipant{
		Identity: acceptance.Participant.Identity,
		Role:     newState.Role,
		Metadata: cloneStringMap(acceptance.Participant.Metadata),
	})
	run.result.Participants = append(run.result.Participants, newState)
	run.result.Status = recalculateCellStatus(run.result.Participants)
	acceptedAt := time.Now().UTC()
	run.result.FederationInvitations[inviteIdx].Status = SecureCellFederationInvitationStatusAccepted
	run.result.FederationInvitations[inviteIdx].AcceptedBy = actorDID
	run.result.FederationInvitations[inviteIdx].AcceptedAt = &acceptedAt
	run.result.FederationInvitations[inviteIdx].ExpectedDID = participantDID
	run.result.FederationInvitations[inviteIdx].OfferedSessionScopeIDs = append([]string(nil), uniqueTrimmedStrings(offeredTerms.SessionScopeIDs)...)
	run.result.FederationInvitations[inviteIdx].OfferedDataClasses = append([]string(nil), uniqueTrimmedStrings(offeredTerms.DataClasses)...)
	run.result.FederationInvitations[inviteIdx].OfferedComputeZones = append([]string(nil), uniqueTrimmedStrings(offeredTerms.ComputeZones)...)
	run.result.FederationInvitations[inviteIdx].OfferedActions = append([]string(nil), uniqueTrimmedStrings(offeredTerms.AllowedActions)...)
	run.result.FederationInvitations[inviteIdx].NegotiationDiffs = cloneSecureCellFederationPolicyDiffs(diffs)
	run.result.FederationInvitations[inviteIdx].Metadata = mergeStringMaps(run.result.FederationInvitations[inviteIdx].Metadata, acceptance.Metadata)
	if approvedCounterproposalID := strings.TrimSpace(invitation.ApprovedCounterproposalID); approvedCounterproposalID != "" {
		run.result.FederationInvitations[inviteIdx].Metadata = mergeStringMaps(run.result.FederationInvitations[inviteIdx].Metadata, map[string]string{
			"approved_counterproposal_id": approvedCounterproposalID,
		})
	}
	contract := newActivatedFederationContract(run.request, run.result.FederationInvitations[inviteIdx], newState, negotiatedTerms, offeredTerms, diffs, run.result.FederationInvitations[inviteIdx].Resource, receipt, actorDID, strings.TrimSpace(acceptance.Reason), acceptance.Metadata, nil)
	run.result.FederationContracts = append(run.result.FederationContracts, contract)
	orgIdx, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, invitation.OrganizationID)
	if org == nil {
		run.result.FederationOrganizations = append(run.result.FederationOrganizations, SecureCellFederationOrganization{
			OrganizationID:   invitation.OrganizationID,
			SponsorOfRecord:  invitation.SponsorOfRecord,
			OrganizationName: invitation.OrganizationName,
			Jurisdiction:     invitation.Jurisdiction,
			Status:           SecureCellFederationOrganizationStatusActive,
			ParticipantDIDs:  []string{participantDID},
			InvitationIDs:    []string{invitation.ID},
			CreatedAt:        acceptedAt,
			UpdatedAt:        acceptedAt,
			Metadata:         cloneStringMap(acceptance.Metadata),
		})
	} else {
		run.result.FederationOrganizations[orgIdx].Status = SecureCellFederationOrganizationStatusActive
		run.result.FederationOrganizations[orgIdx].ParticipantDIDs = append(run.result.FederationOrganizations[orgIdx].ParticipantDIDs, participantDID)
		run.result.FederationOrganizations[orgIdx].InvitationIDs = uniqueTrimmedStrings(append(run.result.FederationOrganizations[orgIdx].InvitationIDs, invitation.ID))
		run.result.FederationOrganizations[orgIdx].UpdatedAt = acceptedAt
	}
	run.result.UpdatedAt = acceptedAt

	transition := SecureCellTransition{
		ID:                      transitionID(run.request, "federation_joined", invitation.ID+"-"+participantDID),
		Action:                  "secure_cell.federation_joined",
		Actor:                   actorDID,
		TargetType:              "federation_invitation",
		TargetDID:               invitation.ID,
		CellStatusBefore:        SecureCellStatusActive,
		CellStatusAfter:         run.result.Status,
		ParticipantStatusBefore: "",
		ParticipantStatusAfter:  newState.Status,
		NegotiationID:           newState.NegotiationID,
		CredentialID:            newState.CredentialID,
		PolicyReceipt:           cloneSignedPolicyReceipt(receipt),
		Reason:                  strings.TrimSpace(acceptance.Reason),
		Metadata: mergeStringMaps(acceptance.Metadata, map[string]string{
			"federation_invitation_id":     invitation.ID,
			"federation_organization_id":   invitation.OrganizationID,
			"federation_sponsor_of_record": invitation.SponsorOfRecord,
			"federation_contract_id":       contract.ID,
			"federation_contract_revision": fmt.Sprintf("%d", contract.Revision),
			"federation_contract_actions":  strings.Join(contract.AllowedActions, ","),
			"federation_contract_scopes":   strings.Join(contract.SessionScopeIDs, ","),
			"federation_offered_actions":   strings.Join(contract.OfferedActions, ","),
			"federation_policy_diffs":      secureCellFederationPolicyDiffsSummary(contract.NegotiationDiffs),
			"approved_counterproposal_id":  strings.TrimSpace(invitation.ApprovedCounterproposalID),
			"target_participant_did":       participantDID,
			"target_role":                  newState.Role,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		s.markNegotiationsFailed(ctx, sessionIDs, err.Error())
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RevokeFederationInvitation revokes a pending federation invitation.
func (s *Service) RevokeFederationInvitation(ctx context.Context, cellID string, invitationID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}

	inviteIdx, invitation := findSecureCellFederationInvitation(run.result.FederationInvitations, invitationID)
	if invitation == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrFederationInvitationNotFound, invitationID)
	}
	if invitation.Status != SecureCellFederationInvitationStatusPending {
		return nil, fmt.Errorf("securecells/service: %w: federation invitation %q is %s", ErrFederationInvitationImmutable, invitationID, invitation.Status)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to revoke federation invitations", ErrPolicyDenied, actorDID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "revoke_federation_invitation", lastReceiptHash(run.result), map[string]string{
		"federation_invitation_id":     invitation.ID,
		"federation_organization_id":   invitation.OrganizationID,
		"federation_sponsor_of_record": invitation.SponsorOfRecord,
		"cell_status_before":           string(run.result.Status),
		"transition_reason":            strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	revokedAt := time.Now().UTC()
	run.result.FederationInvitations[inviteIdx].Status = SecureCellFederationInvitationStatusRevoked
	run.result.FederationInvitations[inviteIdx].RevokedBy = actorDID
	run.result.FederationInvitations[inviteIdx].RevokedAt = &revokedAt
	run.result.FederationInvitations[inviteIdx].Metadata = mergeStringMaps(run.result.FederationInvitations[inviteIdx].Metadata, lifecycle.Metadata)
	if orgIdx, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, invitation.OrganizationID); org != nil {
		if len(org.ParticipantDIDs) == 0 {
			run.result.FederationOrganizations[orgIdx].Status = SecureCellFederationOrganizationStatusRevoked
		}
		run.result.FederationOrganizations[orgIdx].UpdatedAt = revokedAt
	}
	run.result.UpdatedAt = revokedAt

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_invitation_revoked", invitation.ID),
		Action:           "secure_cell.federation_invitation_revoked",
		Actor:            actorDID,
		TargetType:       "federation_invitation",
		TargetDID:        invitation.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_invitation_id":     invitation.ID,
			"federation_organization_id":   invitation.OrganizationID,
			"federation_sponsor_of_record": invitation.SponsorOfRecord,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIdentity(identity *agent.AgentIdentity) (organizationID, sponsorOfRecord, organizationName, jurisdiction string) {
	if identity == nil {
		return "", "", "", ""
	}
	sponsorOfRecord = secureCellFederationSponsor(identity)
	if sponsorOfRecord == "" {
		sponsorOfRecord = identity.AgentID()
	}
	organizationID = secureCellFederationOrganizationID(sponsorOfRecord)
	organizationName = secureCellFederationOrganizationName(identity)
	jurisdiction = firstNonEmpty(firstString(identity.JurisdictionTags), secureCellFederationSponsorJurisdiction(identity))
	return organizationID, sponsorOfRecord, organizationName, jurisdiction
}

func secureCellFederationOrganizationID(sponsorOfRecord string) string {
	sponsorOfRecord = strings.TrimSpace(sponsorOfRecord)
	if sponsorOfRecord == "" {
		return ""
	}
	return fmt.Sprintf("federation-org-%x", sha256.Sum256([]byte(sponsorOfRecord)))
}

func secureCellFederationInvitationID(req SecureCellRequest, sponsorOfRecord, expectedDID, role string, existing int) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%d", cellID(req), sponsorOfRecord, expectedDID, role, existing+1)
	return fmt.Sprintf("%s-federation-%x", cellID(req), sha256.Sum256([]byte(seed)))
}

func secureCellFederationSponsor(identity *agent.AgentIdentity) string {
	if identity == nil {
		return ""
	}
	if identity.Liability != nil && strings.TrimSpace(identity.Liability.SponsorOfRecord) != "" {
		return strings.TrimSpace(identity.Liability.SponsorOfRecord)
	}
	if len(identity.SponsorChain) > 0 {
		return strings.TrimSpace(identity.SponsorChain[0].SponsorDID)
	}
	return ""
}

func secureCellFederationSponsorJurisdiction(identity *agent.AgentIdentity) string {
	if identity == nil || len(identity.SponsorChain) == 0 {
		return ""
	}
	return strings.TrimSpace(identity.SponsorChain[0].Jurisdiction)
}

func secureCellFederationOrganizationName(identity *agent.AgentIdentity) string {
	if identity == nil {
		return ""
	}
	if identity.Liability != nil && strings.TrimSpace(identity.Liability.BusinessUnit) != "" {
		return strings.TrimSpace(identity.Liability.BusinessUnit)
	}
	if len(identity.SponsorChain) > 0 && strings.TrimSpace(identity.SponsorChain[0].SponsorName) != "" {
		return strings.TrimSpace(identity.SponsorChain[0].SponsorName)
	}
	if identity.Metadata != nil {
		if name := strings.TrimSpace(identity.Metadata["organization_name"]); name != "" {
			return name
		}
	}
	return ""
}

func findSecureCellFederationOrganization(orgs []SecureCellFederationOrganization, organizationID string) (int, *SecureCellFederationOrganization) {
	organizationID = strings.TrimSpace(organizationID)
	for idx := range orgs {
		if strings.TrimSpace(orgs[idx].OrganizationID) == organizationID {
			return idx, &orgs[idx]
		}
	}
	return -1, nil
}

func findSecureCellFederationInvitation(items []SecureCellFederationInvitation, invitationID string) (int, *SecureCellFederationInvitation) {
	invitationID = strings.TrimSpace(invitationID)
	for idx := range items {
		if strings.TrimSpace(items[idx].ID) == invitationID {
			return idx, &items[idx]
		}
	}
	return -1, nil
}

func secureCellResolveFederationSessionScopes(sessions []SecureCellSession, requested []string) ([]string, error) {
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		return nil, nil
	}
	valid := make(map[string]struct{}, len(sessions))
	for _, session := range sessions {
		valid[session.ID] = struct{}{}
	}
	for _, sessionID := range requested {
		if _, ok := valid[sessionID]; !ok {
			return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
		}
	}
	return requested, nil
}

func firstString(items []string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func firstNonEmptySlice(primary []string, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}
