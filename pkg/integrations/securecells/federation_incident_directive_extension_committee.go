package securecells

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

func secureCellFederationIncidentDirectiveExtensionReviewThreshold(extension SecureCellFederationIncidentDirectiveExtension) int {
	return normalizeSecureCellThreshold(extension.ReviewApprovalThreshold)
}

func secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute SecureCellFederationIncidentDirectiveExtensionDispute) int {
	return normalizeSecureCellThreshold(dispute.ResolutionThreshold)
}

type secureCellFederationIncidentDirectiveExtensionCommitteeState struct {
	threshold              int
	memberCount            int
	delegationCount        int
	recordedVoteCount      int
	outstandingMemberCount int
	missingQuorumCount     int
	quorumSatisfied        bool
}

func secureCellFederationIncidentDirectiveExtensionReviewVoteCounts(extension SecureCellFederationIncidentDirectiveExtension) (approveVotes, rejectVotes int) {
	for _, vote := range extension.ReviewVotes {
		switch vote.Choice {
		case SecureCellFederationIncidentDirectiveExtensionReviewVoteChoiceApprove:
			approveVotes++
		case SecureCellFederationIncidentDirectiveExtensionReviewVoteChoiceReject:
			rejectVotes++
		}
	}
	return approveVotes, rejectVotes
}

func secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteCounts(dispute SecureCellFederationIncidentDirectiveExtensionDispute) (upholdVotes, reverseVotes int) {
	for _, vote := range dispute.ResolutionVotes {
		switch vote.Choice {
		case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoiceUphold:
			upholdVotes++
		case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoiceReverse:
			reverseVotes++
		}
	}
	return upholdVotes, reverseVotes
}

func secureCellFederationIncidentDirectiveExtensionHasReviewVote(extension SecureCellFederationIncidentDirectiveExtension, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, vote := range extension.ReviewVotes {
		if strings.EqualFold(strings.TrimSpace(vote.ActorDID), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionDisputeHasResolutionVote(dispute SecureCellFederationIncidentDirectiveExtensionDispute, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, vote := range dispute.ResolutionVotes {
		if strings.EqualFold(strings.TrimSpace(vote.ActorDID), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionReviewerAllowed(extension SecureCellFederationIncidentDirectiveExtension, actorDID string) bool {
	if len(extension.EligibleReviewerDIDs) == 0 {
		return true
	}
	return secureCellStringSliceContains(extension.EligibleReviewerDIDs, actorDID)
}

func secureCellFederationIncidentDirectiveExtensionResolverAllowed(dispute SecureCellFederationIncidentDirectiveExtensionDispute, actorDID string) bool {
	if len(dispute.EligibleResolverDIDs) == 0 {
		return true
	}
	return secureCellStringSliceContains(dispute.EligibleResolverDIDs, actorDID)
}

func secureCellFederationIncidentDirectiveExtensionHasDelegatedReviewer(extension SecureCellFederationIncidentDirectiveExtension, targetDID string) bool {
	targetDID = strings.TrimSpace(targetDID)
	for _, delegation := range extension.ReviewDelegations {
		if strings.EqualFold(strings.TrimSpace(delegation.ToActorDID), targetDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionDisputeHasDelegatedResolver(dispute SecureCellFederationIncidentDirectiveExtensionDispute, targetDID string) bool {
	targetDID = strings.TrimSpace(targetDID)
	for _, delegation := range dispute.ResolutionDelegations {
		if strings.EqualFold(strings.TrimSpace(delegation.ToActorDID), targetDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionReviewCommitteeMemberDIDs(extension SecureCellFederationIncidentDirectiveExtension) []string {
	items := append([]string(nil), uniqueTrimmedStrings(extension.EligibleReviewerDIDs)...)
	for _, delegation := range extension.ReviewDelegations {
		if target := strings.TrimSpace(delegation.ToActorDID); target != "" {
			items = append(items, target)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionDisputeCommitteeMemberDIDs(dispute SecureCellFederationIncidentDirectiveExtensionDispute) []string {
	items := append([]string(nil), uniqueTrimmedStrings(dispute.EligibleResolverDIDs)...)
	for _, delegation := range dispute.ResolutionDelegations {
		if target := strings.TrimSpace(delegation.ToActorDID); target != "" {
			items = append(items, target)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionRecordedReviewVoterDIDs(extension SecureCellFederationIncidentDirectiveExtension) []string {
	items := make([]string, 0, len(extension.ReviewVotes))
	for _, vote := range extension.ReviewVotes {
		if actor := strings.TrimSpace(vote.ActorDID); actor != "" {
			items = append(items, actor)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionRecordedResolutionVoterDIDs(dispute SecureCellFederationIncidentDirectiveExtensionDispute) []string {
	items := make([]string, 0, len(dispute.ResolutionVotes))
	for _, vote := range dispute.ResolutionVotes {
		if actor := strings.TrimSpace(vote.ActorDID); actor != "" {
			items = append(items, actor)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionUsesCommitteeGovernance(extension SecureCellFederationIncidentDirectiveExtension) bool {
	return secureCellFederationIncidentDirectiveExtensionReviewThreshold(extension) > 1 || len(secureCellFederationIncidentDirectiveExtensionReviewCommitteeMemberDIDs(extension)) > 0 || len(extension.ReviewDelegations) > 0
}

func secureCellFederationIncidentDirectiveExtensionDisputeUsesCommitteeGovernance(dispute SecureCellFederationIncidentDirectiveExtensionDispute) bool {
	return secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute) > 1 || len(secureCellFederationIncidentDirectiveExtensionDisputeCommitteeMemberDIDs(dispute)) > 0 || len(dispute.ResolutionDelegations) > 0
}

func secureCellFederationIncidentDirectiveExtensionReviewCommitteeState(extension SecureCellFederationIncidentDirectiveExtension) secureCellFederationIncidentDirectiveExtensionCommitteeState {
	approveVotes, rejectVotes := secureCellFederationIncidentDirectiveExtensionReviewVoteCounts(extension)
	recordedVoteCount := len(secureCellFederationIncidentDirectiveExtensionRecordedReviewVoterDIDs(extension))
	memberCount := len(secureCellFederationIncidentDirectiveExtensionReviewCommitteeMemberDIDs(extension))
	threshold := secureCellFederationIncidentDirectiveExtensionReviewThreshold(extension)
	bestVoteCount := approveVotes
	if rejectVotes > bestVoteCount {
		bestVoteCount = rejectVotes
	}
	missingQuorumCount := threshold - bestVoteCount
	if missingQuorumCount < 0 {
		missingQuorumCount = 0
	}
	outstandingMemberCount := memberCount - recordedVoteCount
	if outstandingMemberCount < 0 {
		outstandingMemberCount = 0
	}
	return secureCellFederationIncidentDirectiveExtensionCommitteeState{
		threshold:              threshold,
		memberCount:            memberCount,
		delegationCount:        len(extension.ReviewDelegations),
		recordedVoteCount:      recordedVoteCount,
		outstandingMemberCount: outstandingMemberCount,
		missingQuorumCount:     missingQuorumCount,
		quorumSatisfied:        bestVoteCount >= threshold,
	}
}

func secureCellFederationIncidentDirectiveExtensionDisputeCommitteeState(dispute SecureCellFederationIncidentDirectiveExtensionDispute) secureCellFederationIncidentDirectiveExtensionCommitteeState {
	upholdVotes, reverseVotes := secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteCounts(dispute)
	recordedVoteCount := len(secureCellFederationIncidentDirectiveExtensionRecordedResolutionVoterDIDs(dispute))
	memberCount := len(secureCellFederationIncidentDirectiveExtensionDisputeCommitteeMemberDIDs(dispute))
	threshold := secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute)
	bestVoteCount := upholdVotes
	if reverseVotes > bestVoteCount {
		bestVoteCount = reverseVotes
	}
	missingQuorumCount := threshold - bestVoteCount
	if missingQuorumCount < 0 {
		missingQuorumCount = 0
	}
	outstandingMemberCount := memberCount - recordedVoteCount
	if outstandingMemberCount < 0 {
		outstandingMemberCount = 0
	}
	return secureCellFederationIncidentDirectiveExtensionCommitteeState{
		threshold:              threshold,
		memberCount:            memberCount,
		delegationCount:        len(dispute.ResolutionDelegations),
		recordedVoteCount:      recordedVoteCount,
		outstandingMemberCount: outstandingMemberCount,
		missingQuorumCount:     missingQuorumCount,
		quorumSatisfied:        bestVoteCount >= threshold,
	}
}

func secureCellFederationIncidentDirectiveExtensionCommitteeTarget(run *secureCellRun, response SecureCellFederationIncidentResponse, party SecureCellFederationIncidentResponseParty, excluded []string) (targetDID string, tierID string, source string) {
	excludedSet := make(map[string]struct{}, len(excluded))
	for _, item := range excluded {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			excludedSet[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	for _, tier := range response.EscalationLadder {
		target := strings.TrimSpace(tier.TargetDID)
		if target == "" {
			continue
		}
		if _, blocked := excludedSet[strings.ToLower(target)]; blocked {
			continue
		}
		if secureCellFederationIncidentResponsePartyAllowed(run, response, target, party) {
			return target, strings.TrimSpace(tier.TierID), "response_escalation_tier"
		}
	}

	candidates := make([]string, 0)
	if run != nil && run.request.OwnerIdentity != nil {
		if owner := strings.TrimSpace(run.request.OwnerIdentity.AgentID()); owner != "" {
			candidates = append(candidates, owner)
		}
	}
	if run != nil && run.result != nil {
		switch secureCellNormalizedFederationIncidentResponseParty(party) {
		case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
			if _, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, response.OrganizationID); org != nil {
				candidates = append(candidates, uniqueTrimmedStrings(org.ParticipantDIDs)...)
			}
		default:
			for _, participant := range run.result.Participants {
				if participant.Status == SecureCellParticipantStatusActive {
					if did := strings.TrimSpace(participant.ParticipantDID); did != "" {
						candidates = append(candidates, did)
					}
				}
			}
		}
	}
	for _, candidate := range uniqueTrimmedStrings(candidates) {
		if _, blocked := excludedSet[strings.ToLower(candidate)]; blocked {
			continue
		}
		if secureCellFederationIncidentResponsePartyAllowed(run, response, candidate, party) {
			return candidate, "", "party_participant"
		}
	}
	return "", "", ""
}

func secureCellFederationIncidentDirectiveExtensionReviewVoteID(extensionID string, actorDID string, choice SecureCellFederationIncidentDirectiveExtensionReviewVoteChoice, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(extensionID), strings.TrimSpace(actorDID), string(choice), ordinal+1)
	return fmt.Sprintf("%s-review-vote-%x", strings.TrimSpace(extensionID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteID(disputeID string, actorDID string, choice SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoice, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(disputeID), strings.TrimSpace(actorDID), string(choice), ordinal+1)
	return fmt.Sprintf("%s-resolution-vote-%x", strings.TrimSpace(disputeID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionDelegationID(parentID string, scope string, actorDID string, targetDID string, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%d", strings.TrimSpace(parentID), strings.TrimSpace(scope), strings.TrimSpace(actorDID), strings.TrimSpace(targetDID), ordinal+1)
	return fmt.Sprintf("%s-delegation-%x", strings.TrimSpace(parentID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionEligibleResolvers(run *secureCellRun, response SecureCellFederationIncidentResponse, extension SecureCellFederationIncidentDirectiveExtension, respondingParty SecureCellFederationIncidentResponseParty) []string {
	if len(extension.EligibleResolverDIDs) == 0 {
		return nil
	}
	items := make([]string, 0, len(extension.EligibleResolverDIDs))
	for _, candidate := range uniqueTrimmedStrings(extension.EligibleResolverDIDs) {
		if secureCellFederationIncidentResponsePartyAllowed(run, response, candidate, respondingParty) {
			items = append(items, candidate)
		}
	}
	return items
}

func secureCellFederationIncidentDirectiveExtensionReviewThresholdSatisfied(extension SecureCellFederationIncidentDirectiveExtension, choice SecureCellFederationIncidentDirectiveExtensionReviewVoteChoice) bool {
	approveVotes, rejectVotes := secureCellFederationIncidentDirectiveExtensionReviewVoteCounts(extension)
	switch choice {
	case SecureCellFederationIncidentDirectiveExtensionReviewVoteChoiceApprove:
		return approveVotes >= secureCellFederationIncidentDirectiveExtensionReviewThreshold(extension)
	case SecureCellFederationIncidentDirectiveExtensionReviewVoteChoiceReject:
		return rejectVotes >= secureCellFederationIncidentDirectiveExtensionReviewThreshold(extension)
	default:
		return false
	}
}

func secureCellFederationIncidentDirectiveExtensionDisputeResolutionThresholdSatisfied(dispute SecureCellFederationIncidentDirectiveExtensionDispute, choice SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoice) bool {
	upholdVotes, reverseVotes := secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteCounts(dispute)
	switch choice {
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoiceUphold:
		return upholdVotes >= secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute)
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoiceReverse:
		return reverseVotes >= secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute)
	default:
		return false
	}
}

// DelegateFederationIncidentDirectiveExtensionReview broadens the eligible
// reviewer committee for a pending directive exception.
func (s *Service) DelegateFederationIncidentDirectiveExtensionReview(ctx context.Context, cellID string, extensionID string, req SecureCellFederationIncidentDirectiveExtensionDelegationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	responseIdx, directiveIdx, extensionIdx, response, directive, extension := findSecureCellFederationIncidentDirectiveExtension(run.result.FederationIncidentResponses, extensionID)
	if response == nil || directive == nil || extension == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: %q", ErrFederationIncidentDirectiveNotFound, extensionID)
	}
	if extension.Status != SecureCellFederationIncidentDirectiveExtensionStatusPendingReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: extension %q is not awaiting review", ErrFederationIncidentDirectiveImmutable, extensionID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, extension.ReviewingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: actor %q is not permitted to delegate review for extension %q", ErrPolicyDenied, actorDID, extensionID)
	}
	targetDID := strings.TrimSpace(req.TargetDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: target_did is required")
	}
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, targetDID, extension.ReviewingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: target %q is not permitted to review extension %q", ErrPolicyDenied, targetDID, extensionID)
	}
	if secureCellStringSliceContains(extension.EligibleReviewerDIDs, targetDID) || secureCellFederationIncidentDirectiveExtensionHasDelegatedReviewer(*extension, targetDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: target %q is already eligible to review extension %q", ErrFederationIncidentDirectiveImmutable, targetDID, extensionID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "delegate_federation_incident_directive_extension_review", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                response.ID,
		"federation_organization_id":                     response.OrganizationID,
		"federation_sponsor_of_record":                   response.SponsorOfRecord,
		"federation_incident_id":                         response.IncidentID,
		"federation_incident_directive_id":               directive.ID,
		"federation_incident_directive_extension_id":     extension.ID,
		"federation_incident_directive_extension_status": string(extension.Status),
		"federation_incident_directive_extension_target": targetDID,
		"transition_reason":                              firstNonEmpty(strings.TrimSpace(req.Reason), "delegate directive extension review"),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	delegation := SecureCellFederationIncidentDirectiveExtensionDelegation{
		ID:                secureCellFederationIncidentDirectiveExtensionDelegationID(updatedExtension.ID, "review", actorDID, targetDID, len(updatedExtension.ReviewDelegations)),
		FromActorDID:      actorDID,
		ToActorDID:        targetDID,
		Scope:             "review",
		Reason:            strings.TrimSpace(req.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	updatedExtension.ReviewDelegations = append(updatedExtension.ReviewDelegations, delegation)
	if len(updatedExtension.EligibleReviewerDIDs) > 0 {
		updatedExtension.EligibleReviewerDIDs = uniqueTrimmedStrings(append(updatedExtension.EligibleReviewerDIDs, targetDID))
	}
	updatedExtension.UpdatedAt = now
	updatedExtension.Metadata = mergeStringMaps(updatedExtension.Metadata, req.Metadata)
	updatedDirective.Extensions[extensionIdx] = updatedExtension
	updatedDirective.UpdatedAt = now
	updatedDirective.Metadata = mergeStringMaps(updatedDirective.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updatedDirective
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	approveVotes, rejectVotes := secureCellFederationIncidentDirectiveExtensionReviewVoteCounts(updatedExtension)
	committeeState := secureCellFederationIncidentDirectiveExtensionReviewCommitteeState(updatedExtension)
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_review_delegated", delegation.ID),
		Action:           "secure_cell.federation_incident_directive_extension_review_delegated",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension",
		TargetDID:        updatedExtension.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), "delegate directive extension review"),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                           response.ID,
			"federation_organization_id":                                response.OrganizationID,
			"federation_sponsor_of_record":                              response.SponsorOfRecord,
			"federation_incident_id":                                    response.IncidentID,
			"federation_incident_directive_id":                          directive.ID,
			"federation_incident_directive_title":                       directive.Title,
			"federation_incident_directive_status_before":               string(directive.Status),
			"federation_incident_directive_status_after":                string(directive.Status),
			"federation_incident_directive_extension_id":                updatedExtension.ID,
			"federation_incident_directive_extension_status_before":     string(extension.Status),
			"federation_incident_directive_extension_status_after":      string(updatedExtension.Status),
			"federation_incident_directive_extension_request_party":     string(updatedExtension.RequestingParty),
			"federation_incident_directive_extension_review_party":      string(updatedExtension.ReviewingParty),
			"federation_incident_directive_extension_delegation_id":     delegation.ID,
			"federation_incident_directive_extension_delegation_scope":  delegation.Scope,
			"federation_incident_directive_extension_delegated_to":      targetDID,
			"federation_incident_directive_extension_review_threshold":  fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionReviewThreshold(updatedExtension)),
			"federation_incident_directive_extension_approve_votes":     fmt.Sprintf("%d", approveVotes),
			"federation_incident_directive_extension_reject_votes":      fmt.Sprintf("%d", rejectVotes),
			"federation_incident_directive_extension_committee_members": fmt.Sprintf("%d", committeeState.memberCount),
			"federation_incident_directive_extension_vote_count":        fmt.Sprintf("%d", committeeState.recordedVoteCount),
			"federation_incident_directive_extension_missing_quorum":    fmt.Sprintf("%d", committeeState.missingQuorumCount),
			"federation_incident_directive_extension_outstanding_votes": fmt.Sprintf("%d", committeeState.outstandingMemberCount),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// DelegateFederationIncidentDirectiveExtensionDisputeResolution broadens the
// resolver committee for one pending directive exception dispute.
func (s *Service) DelegateFederationIncidentDirectiveExtensionDisputeResolution(ctx context.Context, cellID string, disputeID string, req SecureCellFederationIncidentDirectiveExtensionDelegationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	responseIdx, directiveIdx, extensionIdx, disputeIdx, response, directive, extension, dispute := findSecureCellFederationIncidentDirectiveExtensionDispute(run.result.FederationIncidentResponses, disputeID)
	if response == nil || directive == nil || extension == nil || dispute == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: %q", ErrFederationIncidentDirectiveNotFound, disputeID)
	}
	if dispute.Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: dispute %q is not pending resolution", ErrFederationIncidentDirectiveImmutable, disputeID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, dispute.RespondingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: actor %q is not permitted to delegate dispute resolution for %q", ErrPolicyDenied, actorDID, disputeID)
	}
	targetDID := strings.TrimSpace(req.TargetDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: target_did is required")
	}
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, targetDID, dispute.RespondingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: target %q is not permitted to resolve dispute %q", ErrPolicyDenied, targetDID, disputeID)
	}
	if secureCellStringSliceContains(dispute.EligibleResolverDIDs, targetDID) || secureCellFederationIncidentDirectiveExtensionDisputeHasDelegatedResolver(*dispute, targetDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: target %q is already eligible to resolve dispute %q", ErrFederationIncidentDirectiveImmutable, targetDID, disputeID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "delegate_federation_incident_directive_extension_dispute_resolution", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                        response.ID,
		"federation_organization_id":                             response.OrganizationID,
		"federation_sponsor_of_record":                           response.SponsorOfRecord,
		"federation_incident_id":                                 response.IncidentID,
		"federation_incident_directive_id":                       directive.ID,
		"federation_incident_directive_extension_id":             extension.ID,
		"federation_incident_directive_extension_dispute_id":     dispute.ID,
		"federation_incident_directive_extension_dispute_status": string(dispute.Status),
		"federation_incident_directive_extension_target":         targetDID,
		"transition_reason":                                      firstNonEmpty(strings.TrimSpace(req.Reason), "delegate directive extension dispute resolution"),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	updatedDispute := updatedExtension.Disputes[disputeIdx]
	delegation := SecureCellFederationIncidentDirectiveExtensionDelegation{
		ID:                secureCellFederationIncidentDirectiveExtensionDelegationID(updatedDispute.ID, "dispute_resolution", actorDID, targetDID, len(updatedDispute.ResolutionDelegations)),
		FromActorDID:      actorDID,
		ToActorDID:        targetDID,
		Scope:             "dispute_resolution",
		Reason:            strings.TrimSpace(req.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	updatedDispute.ResolutionDelegations = append(updatedDispute.ResolutionDelegations, delegation)
	if len(updatedDispute.EligibleResolverDIDs) > 0 {
		updatedDispute.EligibleResolverDIDs = uniqueTrimmedStrings(append(updatedDispute.EligibleResolverDIDs, targetDID))
	}
	updatedDispute.UpdatedAt = now
	updatedDispute.Metadata = mergeStringMaps(updatedDispute.Metadata, req.Metadata)
	updatedExtension.Disputes[disputeIdx] = updatedDispute
	updatedExtension.UpdatedAt = now
	updatedExtension.Metadata = mergeStringMaps(updatedExtension.Metadata, req.Metadata)
	updatedDirective.Extensions[extensionIdx] = updatedExtension
	updatedDirective.UpdatedAt = now
	updatedDirective.Metadata = mergeStringMaps(updatedDirective.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updatedDirective
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	upholdVotes, reverseVotes := secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteCounts(updatedDispute)
	committeeState := secureCellFederationIncidentDirectiveExtensionDisputeCommitteeState(updatedDispute)
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_dispute_resolution_delegated", delegation.ID),
		Action:           "secure_cell.federation_incident_directive_extension_dispute_resolution_delegated",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_dispute",
		TargetDID:        updatedDispute.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), "delegate directive extension dispute resolution"),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                               response.ID,
			"federation_organization_id":                                    response.OrganizationID,
			"federation_sponsor_of_record":                                  response.SponsorOfRecord,
			"federation_incident_id":                                        response.IncidentID,
			"federation_incident_directive_id":                              directive.ID,
			"federation_incident_directive_title":                           directive.Title,
			"federation_incident_directive_status_before":                   string(directive.Status),
			"federation_incident_directive_status_after":                    string(directive.Status),
			"federation_incident_directive_extension_id":                    updatedExtension.ID,
			"federation_incident_directive_extension_status_before":         string(extension.Status),
			"federation_incident_directive_extension_status_after":          string(updatedExtension.Status),
			"federation_incident_directive_extension_dispute_id":            updatedDispute.ID,
			"federation_incident_directive_extension_dispute_status_before": string(dispute.Status),
			"federation_incident_directive_extension_dispute_status_after":  string(updatedDispute.Status),
			"federation_incident_directive_extension_disputing_party":       string(updatedDispute.ChallengingParty),
			"federation_incident_directive_extension_responding_party":      string(updatedDispute.RespondingParty),
			"federation_incident_directive_extension_delegation_id":         delegation.ID,
			"federation_incident_directive_extension_delegation_scope":      delegation.Scope,
			"federation_incident_directive_extension_delegated_to":          targetDID,
			"federation_incident_directive_extension_resolution_threshold":  fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(updatedDispute)),
			"federation_incident_directive_extension_uphold_votes":          fmt.Sprintf("%d", upholdVotes),
			"federation_incident_directive_extension_reverse_votes":         fmt.Sprintf("%d", reverseVotes),
			"federation_incident_directive_extension_committee_members":     fmt.Sprintf("%d", committeeState.memberCount),
			"federation_incident_directive_extension_vote_count":            fmt.Sprintf("%d", committeeState.recordedVoteCount),
			"federation_incident_directive_extension_missing_quorum":        fmt.Sprintf("%d", committeeState.missingQuorumCount),
			"federation_incident_directive_extension_outstanding_votes":     fmt.Sprintf("%d", committeeState.outstandingMemberCount),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}
