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

type secureCellFederationIncidentDirectiveExtensionAppealCommitteeState struct {
	threshold              int
	memberCount            int
	delegationCount        int
	recordedVoteCount      int
	outstandingMemberCount int
	missingQuorumCount     int
	quorumSatisfied        bool
}

func secureCellNormalizedFederationIncidentDirectiveExtensionAppealRuling(value SecureCellFederationIncidentDirectiveExtensionAppealRuling) SecureCellFederationIncidentDirectiveExtensionAppealRuling {
	switch SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) int {
	return normalizeSecureCellThreshold(appeal.BoardReviewThreshold)
}

func secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) (ratifyVotes, overturnVotes int) {
	for _, vote := range appeal.BoardVotes {
		switch vote.Choice {
		case SecureCellFederationIncidentDirectiveExtensionAppealVoteChoiceRatify:
			ratifyVotes++
		case SecureCellFederationIncidentDirectiveExtensionAppealVoteChoiceOverturn:
			overturnVotes++
		}
	}
	return ratifyVotes, overturnVotes
}

func secureCellFederationIncidentDirectiveExtensionAppealRecordedVoterDIDs(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) []string {
	items := make([]string, 0, len(appeal.BoardVotes))
	for _, vote := range appeal.BoardVotes {
		if actor := strings.TrimSpace(vote.ActorDID); actor != "" {
			items = append(items, actor)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionAppealCommitteeMemberDIDs(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) []string {
	items := append([]string(nil), uniqueTrimmedStrings(appeal.EligibleBoardReviewerDIDs)...)
	for _, delegation := range appeal.BoardDelegations {
		if target := strings.TrimSpace(delegation.ToActorDID); target != "" {
			items = append(items, target)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionAppealCommitteeSnapshot(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) secureCellFederationIncidentDirectiveExtensionAppealCommitteeState {
	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(appeal)
	recordedVoteCount := len(secureCellFederationIncidentDirectiveExtensionAppealRecordedVoterDIDs(appeal))
	memberCount := len(secureCellFederationIncidentDirectiveExtensionAppealCommitteeMemberDIDs(appeal))
	threshold := secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal)
	bestVoteCount := ratifyVotes
	if overturnVotes > bestVoteCount {
		bestVoteCount = overturnVotes
	}
	missingQuorumCount := threshold - bestVoteCount
	if missingQuorumCount < 0 {
		missingQuorumCount = 0
	}
	outstandingMemberCount := memberCount - recordedVoteCount
	if outstandingMemberCount < 0 {
		outstandingMemberCount = 0
	}
	return secureCellFederationIncidentDirectiveExtensionAppealCommitteeState{
		threshold:              threshold,
		memberCount:            memberCount,
		delegationCount:        len(appeal.BoardDelegations),
		recordedVoteCount:      recordedVoteCount,
		outstandingMemberCount: outstandingMemberCount,
		missingQuorumCount:     missingQuorumCount,
		quorumSatisfied:        bestVoteCount >= threshold,
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealVoteID(appealID string, actorDID string, choice SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(appealID), strings.TrimSpace(actorDID), string(choice), ordinal+1)
	return fmt.Sprintf("%s-board-vote-%x", strings.TrimSpace(appealID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionAppealID(dispute SecureCellFederationIncidentDirectiveExtensionDispute, actorDID string, createdAt time.Time, ordinal int) string {
	return fmt.Sprintf("%s-appeal-%x",
		strings.TrimSpace(dispute.ID),
		sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(dispute.ID), strings.TrimSpace(actorDID), createdAt.UTC().Format(time.RFC3339Nano), ordinal+1))),
	)
}

func secureCellFederationIncidentDirectiveExtensionAppealHasVote(appeal SecureCellFederationIncidentDirectiveExtensionAppeal, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, vote := range appeal.BoardVotes {
		if strings.EqualFold(strings.TrimSpace(vote.ActorDID), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealReviewerAllowed(appeal SecureCellFederationIncidentDirectiveExtensionAppeal, actorDID string) bool {
	if len(appeal.EligibleBoardReviewerDIDs) == 0 {
		return true
	}
	return secureCellStringSliceContains(appeal.EligibleBoardReviewerDIDs, actorDID)
}

func secureCellFederationIncidentDirectiveExtensionAppealHasDelegatedReviewer(appeal SecureCellFederationIncidentDirectiveExtensionAppeal, targetDID string) bool {
	targetDID = strings.TrimSpace(targetDID)
	for _, delegation := range appeal.BoardDelegations {
		if strings.EqualFold(strings.TrimSpace(delegation.ToActorDID), targetDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealThresholdSatisfied(appeal SecureCellFederationIncidentDirectiveExtensionAppeal, choice SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice) bool {
	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(appeal)
	switch choice {
	case SecureCellFederationIncidentDirectiveExtensionAppealVoteChoiceRatify:
		return ratifyVotes >= secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal)
	case SecureCellFederationIncidentDirectiveExtensionAppealVoteChoiceOverturn:
		return overturnVotes >= secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal)
	default:
		return false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealDefaultAppealingParty(dispute SecureCellFederationIncidentDirectiveExtensionDispute) SecureCellFederationIncidentResponseParty {
	switch dispute.Resolution {
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold:
		return dispute.ChallengingParty
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse:
		return dispute.RespondingParty
	default:
		return dispute.ChallengingParty
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealBoardParty(appealingParty SecureCellFederationIncidentResponseParty, dispute SecureCellFederationIncidentDirectiveExtensionDispute) SecureCellFederationIncidentResponseParty {
	if opposite := secureCellFederationIncidentDirectiveOppositeParty(appealingParty); opposite != "" {
		return opposite
	}
	if dispute.RespondingParty != "" && dispute.RespondingParty != appealingParty {
		return dispute.RespondingParty
	}
	return dispute.ChallengingParty
}

func secureCellFederationIncidentDirectiveExtensionAppealDefaultSummary(dispute SecureCellFederationIncidentDirectiveExtensionDispute) string {
	switch dispute.Resolution {
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold:
		return "appeal upheld directive extension dispute ruling"
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse:
		return "appeal reversed directive extension dispute ruling"
	default:
		return "appeal directive extension dispute ruling"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealRulingSummary(dispute SecureCellFederationIncidentDirectiveExtensionDispute, ruling SecureCellFederationIncidentDirectiveExtensionAppealRuling) string {
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return "appeal board ratified directive extension dispute ruling"
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return "appeal board overturned directive extension dispute ruling"
	default:
		return secureCellFederationIncidentDirectiveExtensionAppealDefaultSummary(dispute)
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealEnforcementSummary(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) string {
	switch appeal.Ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return "appeal ruling ratification acknowledged for enforcement"
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return "appeal ruling overturn acknowledged for enforcement"
	default:
		return "appeal ruling acknowledged for enforcement"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealOpen(dispute SecureCellFederationIncidentDirectiveExtensionDispute) *SecureCellFederationIncidentDirectiveExtensionAppeal {
	for idx := len(dispute.Appeals) - 1; idx >= 0; idx-- {
		switch dispute.Appeals[idx].Status {
		case SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview,
			SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified,
			SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned:
			return &dispute.Appeals[idx]
		}
	}
	return nil
}

func secureCellLatestFederationIncidentDirectiveExtensionAppeal(dispute SecureCellFederationIncidentDirectiveExtensionDispute) *SecureCellFederationIncidentDirectiveExtensionAppeal {
	if len(dispute.Appeals) == 0 {
		return nil
	}
	latest := &dispute.Appeals[0]
	for idx := 1; idx < len(dispute.Appeals); idx++ {
		if dispute.Appeals[idx].UpdatedAt.After(latest.UpdatedAt) {
			latest = &dispute.Appeals[idx]
		}
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealThresholdStatusForRuling(ruling SecureCellFederationIncidentDirectiveExtensionAppealRuling) SecureCellFederationIncidentDirectiveExtensionAppealStatus {
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified
	}
}

func secureCellOppositeFederationIncidentDirectiveExtensionDisputeResolution(resolution SecureCellFederationIncidentDirectiveExtensionDisputeResolution) SecureCellFederationIncidentDirectiveExtensionDisputeResolution {
	switch resolution {
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold:
		return SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse:
		return SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold
	default:
		return SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealEffectiveResolution(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) SecureCellFederationIncidentDirectiveExtensionDisputeResolution {
	if appeal.Ruling == SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn {
		return secureCellOppositeFederationIncidentDirectiveExtensionDisputeResolution(appeal.ChallengedResolution)
	}
	return appeal.ChallengedResolution
}

func secureCellFederationIncidentDirectiveExtensionAppealEffectiveStatus(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) SecureCellFederationIncidentDirectiveExtensionStatus {
	if appeal.Ruling == SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn {
		return secureCellFederationIncidentDirectiveExtensionResolvedStatus(appeal.ChallengedExtensionStatus, secureCellOppositeFederationIncidentDirectiveExtensionDisputeResolution(appeal.ChallengedResolution))
	}
	return appeal.ChallengedExtensionStatus
}

func secureCellFederationIncidentParticipantsForParty(run *secureCellRun, response SecureCellFederationIncidentResponse, party SecureCellFederationIncidentResponseParty) []string {
	items := make([]string, 0)
	if run != nil && run.request.OwnerIdentity != nil {
		if owner := strings.TrimSpace(run.request.OwnerIdentity.AgentID()); owner != "" && secureCellFederationIncidentResponsePartyAllowed(run, response, owner, party) {
			items = append(items, owner)
		}
	}
	if run == nil || run.result == nil {
		return uniqueTrimmedStrings(items)
	}
	switch secureCellNormalizedFederationIncidentResponseParty(party) {
	case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
		if _, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, response.OrganizationID); org != nil {
			for _, did := range uniqueTrimmedStrings(org.ParticipantDIDs) {
				if secureCellFederationIncidentResponsePartyAllowed(run, response, did, party) {
					items = append(items, did)
				}
			}
		}
	default:
		for _, participant := range run.result.Participants {
			if participant.Status != SecureCellParticipantStatusActive {
				continue
			}
			if did := strings.TrimSpace(participant.ParticipantDID); did != "" && secureCellFederationIncidentResponsePartyAllowed(run, response, did, party) {
				items = append(items, did)
			}
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionAppealEligibleReviewers(run *secureCellRun, response SecureCellFederationIncidentResponse, boardParty SecureCellFederationIncidentResponseParty, requested []string) []string {
	if len(requested) > 0 {
		items := make([]string, 0, len(requested))
		for _, candidate := range uniqueTrimmedStrings(requested) {
			if secureCellFederationIncidentResponsePartyAllowed(run, response, candidate, boardParty) {
				items = append(items, candidate)
			}
		}
		return uniqueTrimmedStrings(items)
	}
	return secureCellFederationIncidentParticipantsForParty(run, response, boardParty)
}

// AppealFederationIncidentDirectiveExtensionDispute opens one bilateral appeal
// board review over a resolved directive-exception dispute.
func (s *Service) AppealFederationIncidentDirectiveExtensionDispute(ctx context.Context, cellID string, disputeID string, req SecureCellFederationIncidentDirectiveExtensionAppealRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: %q", ErrFederationIncidentDirectiveNotFound, disputeID)
	}
	if dispute.Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusUpheld && dispute.Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusReversed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: dispute %q is not appealable", ErrFederationIncidentDirectiveImmutable, disputeID)
	}
	if open := secureCellFederationIncidentDirectiveExtensionAppealOpen(*dispute); open != nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: dispute %q already has open appeal %q", ErrFederationIncidentDirectiveImmutable, disputeID, open.ID)
	}

	appealingParty := secureCellNormalizedFederationIncidentResponseParty(req.AppealingParty)
	if appealingParty == "" {
		appealingParty = secureCellFederationIncidentDirectiveExtensionAppealDefaultAppealingParty(*dispute)
	}
	if appealingParty != dispute.ChallengingParty && appealingParty != dispute.RespondingParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: invalid appealing party %q", ErrPolicyDenied, appealingParty)
	}
	boardParty := secureCellFederationIncidentDirectiveExtensionAppealBoardParty(appealingParty, *dispute)
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, appealingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q is not permitted to appeal dispute %q", ErrPolicyDenied, actorDID, disputeID)
	}

	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		summary = secureCellFederationIncidentDirectiveExtensionAppealDefaultSummary(*dispute)
	}
	eligibleReviewers := secureCellFederationIncidentDirectiveExtensionAppealEligibleReviewers(run, *response, boardParty, req.EligibleBoardReviewerDIDs)
	receipt, err := s.evaluateStage(ctx, run.request, "appeal_federation_incident_directive_extension_dispute", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                              response.ID,
		"federation_organization_id":                                   response.OrganizationID,
		"federation_sponsor_of_record":                                 response.SponsorOfRecord,
		"federation_incident_id":                                       response.IncidentID,
		"federation_incident_directive_id":                             directive.ID,
		"federation_incident_directive_extension_id":                   extension.ID,
		"federation_incident_directive_extension_dispute_id":           dispute.ID,
		"federation_incident_directive_extension_dispute_status":       string(dispute.Status),
		"federation_incident_directive_extension_appealing_party":      string(appealingParty),
		"federation_incident_directive_extension_appeal_board_party":   string(boardParty),
		"federation_incident_directive_extension_appeal_board_members": strings.Join(eligibleReviewers, ","),
		"transition_reason":                                            firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	updatedDispute := updatedExtension.Disputes[disputeIdx]
	appeal := SecureCellFederationIncidentDirectiveExtensionAppeal{
		ID:                              secureCellFederationIncidentDirectiveExtensionAppealID(updatedDispute, actorDID, now, len(updatedDispute.Appeals)),
		ResponseID:                      response.ID,
		DirectiveID:                     directive.ID,
		ExtensionID:                     extension.ID,
		DisputeID:                       dispute.ID,
		OrganizationID:                  response.OrganizationID,
		SponsorOfRecord:                 response.SponsorOfRecord,
		IncidentID:                      response.IncidentID,
		AppealingParty:                  appealingParty,
		BoardParty:                      boardParty,
		EnforcementAcknowledgementParty: appealingParty,
		ChallengedDisputeStatus:         dispute.Status,
		ChallengedResolution:            dispute.Resolution,
		ChallengedExtensionStatus:       extension.Status,
		AppealedBy:                      actorDID,
		Summary:                         summary,
		Description:                     strings.TrimSpace(req.Description),
		EvidenceIDs:                     append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		BoardReviewThreshold:            normalizeSecureCellThreshold(req.BoardReviewThreshold),
		EligibleBoardReviewerDIDs:       append([]string(nil), eligibleReviewers...),
		Status:                          SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview,
		RequestReceiptID:                receipt.ID,
		RequestReceiptHash:              receipt.ContentHash,
		CreatedAt:                       now,
		UpdatedAt:                       now,
		Metadata:                        cloneStringMap(req.Metadata),
	}
	updatedDispute.Appeals = append(updatedDispute.Appeals, appeal)
	updatedDispute.UpdatedAt = now
	updatedDispute.Metadata = mergeStringMaps(updatedDispute.Metadata, map[string]string{"latest_appeal_id": appeal.ID})
	updatedExtension.Disputes[disputeIdx] = updatedDispute
	updatedExtension.UpdatedAt = now
	updatedExtension.Metadata = mergeStringMaps(updatedExtension.Metadata, map[string]string{"latest_appeal_id": appeal.ID})
	updatedDirective.Extensions[extensionIdx] = updatedExtension
	updatedDirective.UpdatedAt = now
	updatedDirective.Metadata = mergeStringMaps(updatedDirective.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updatedDirective
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_dispute_appealed", appeal.ID),
		Action:           "secure_cell.federation_incident_directive_extension_dispute_appealed",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal",
		TargetDID:        appeal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                                response.ID,
			"federation_organization_id":                                     response.OrganizationID,
			"federation_sponsor_of_record":                                   response.SponsorOfRecord,
			"federation_incident_id":                                         response.IncidentID,
			"federation_incident_directive_id":                               directive.ID,
			"federation_incident_directive_title":                            directive.Title,
			"federation_incident_directive_status_before":                    string(directive.Status),
			"federation_incident_directive_status_after":                     string(directive.Status),
			"federation_incident_directive_extension_id":                     updatedExtension.ID,
			"federation_incident_directive_extension_status_before":          string(extension.Status),
			"federation_incident_directive_extension_status_after":           string(updatedExtension.Status),
			"federation_incident_directive_extension_dispute_id":             updatedDispute.ID,
			"federation_incident_directive_extension_dispute_status_before":  string(dispute.Status),
			"federation_incident_directive_extension_dispute_status_after":   string(updatedDispute.Status),
			"federation_incident_directive_extension_appeal_id":              appeal.ID,
			"federation_incident_directive_extension_appeal_status_before":   "",
			"federation_incident_directive_extension_appeal_status_after":    string(appeal.Status),
			"federation_incident_directive_extension_appealing_party":        string(appeal.AppealingParty),
			"federation_incident_directive_extension_appeal_board_party":     string(appeal.BoardParty),
			"federation_incident_directive_extension_appeal_board_threshold": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal)),
			"federation_incident_directive_extension_appeal_board_members":   strings.Join(appeal.EligibleBoardReviewerDIDs, ","),
			"federation_incident_directive_extension_appeal_pending_action":  "board_review",
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RuleFederationIncidentDirectiveExtensionAppeal records one appeal-board vote
// or final ruling over a directive exception dispute.
func (s *Service) RuleFederationIncidentDirectiveExtensionAppeal(ctx context.Context, cellID string, appealID string, req SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	responseIdx, directiveIdx, extensionIdx, disputeIdx, appealIdx, response, directive, extension, dispute, appeal := findSecureCellFederationIncidentDirectiveExtensionAppeal(run.result.FederationIncidentResponses, appealID)
	if response == nil || directive == nil || extension == nil || dispute == nil || appeal == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: %q", ErrFederationIncidentDirectiveNotFound, appealID)
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: appeal %q is not pending board review", ErrFederationIncidentDirectiveImmutable, appealID)
	}
	ruling := secureCellNormalizedFederationIncidentDirectiveExtensionAppealRuling(req.Ruling)
	if ruling == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: ruling is required")
	}
	boardParty := secureCellNormalizedFederationIncidentResponseParty(req.BoardParty)
	if boardParty == "" {
		boardParty = appeal.BoardParty
	}
	if boardParty != appeal.BoardParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: appeal %q must be ruled by %q", ErrPolicyDenied, appealID, appeal.BoardParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, boardParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q is not permitted to review appeal %q", ErrPolicyDenied, actorDID, appealID)
	}
	if !secureCellFederationIncidentDirectiveExtensionAppealReviewerAllowed(*appeal, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q is not an eligible board reviewer for appeal %q", ErrPolicyDenied, actorDID, appealID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealHasVote(*appeal, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q has already voted on appeal %q", ErrFederationIncidentDirectiveImmutable, actorDID, appealID)
	}

	summary := strings.TrimSpace(req.RulingSummary)
	if summary == "" {
		summary = secureCellFederationIncidentDirectiveExtensionAppealRulingSummary(*dispute, ruling)
	}
	beforeDueAt := cloneTimePtr(directive.DueAt)
	effectiveResolution := appeal.ChallengedResolution
	effectiveStatus := appeal.ChallengedExtensionStatus
	if ruling == SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn {
		effectiveResolution = secureCellOppositeFederationIncidentDirectiveExtensionDisputeResolution(appeal.ChallengedResolution)
		effectiveStatus = secureCellFederationIncidentDirectiveExtensionResolvedStatus(appeal.ChallengedExtensionStatus, effectiveResolution)
	}
	afterDueAt := secureCellFederationIncidentDirectiveExtensionDueAtForStatus(*extension, effectiveStatus)

	receipt, err := s.evaluateStage(ctx, run.request, "rule_federation_incident_directive_extension_appeal", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                       response.ID,
		"federation_organization_id":                            response.OrganizationID,
		"federation_sponsor_of_record":                          response.SponsorOfRecord,
		"federation_incident_id":                                response.IncidentID,
		"federation_incident_directive_id":                      directive.ID,
		"federation_incident_directive_extension_id":            extension.ID,
		"federation_incident_directive_extension_dispute_id":    dispute.ID,
		"federation_incident_directive_extension_appeal_id":     appeal.ID,
		"federation_incident_directive_extension_appeal_status": string(appeal.Status),
		"federation_incident_directive_extension_appeal_ruling": string(ruling),
		"federation_incident_directive_extension_status_after":  string(effectiveStatus),
		"federation_incident_directive_due_at_before":           secureCellFormatTime(beforeDueAt),
		"federation_incident_directive_due_at_after":            secureCellFormatTime(afterDueAt),
		"transition_reason":                                     firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	beforeStatus := updatedExtension.Status
	updatedDispute := updatedExtension.Disputes[disputeIdx]
	updatedAppeal := updatedDispute.Appeals[appealIdx]
	voteChoice := SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice(ruling)
	vote := SecureCellFederationIncidentDirectiveExtensionAppealVote{
		ID:                secureCellFederationIncidentDirectiveExtensionAppealVoteID(updatedAppeal.ID, actorDID, voteChoice, len(updatedAppeal.BoardVotes)),
		AppealID:          updatedAppeal.ID,
		ActorDID:          actorDID,
		Choice:            voteChoice,
		Reason:            firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	updatedAppeal.BoardVotes = append(updatedAppeal.BoardVotes, vote)
	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(updatedAppeal)
	thresholdSatisfied := secureCellFederationIncidentDirectiveExtensionAppealThresholdSatisfied(updatedAppeal, voteChoice)
	transitionAction := "secure_cell.federation_incident_directive_extension_appeal_vote_recorded"
	if thresholdSatisfied {
		updatedAppeal.Status = secureCellFederationIncidentDirectiveExtensionAppealThresholdStatusForRuling(ruling)
		updatedAppeal.Ruling = ruling
		updatedAppeal.RulingReceiptID = receipt.ID
		updatedAppeal.RulingReceiptHash = receipt.ContentHash
		updatedAppeal.RulingSummary = summary
		updatedAppeal.RulingDescription = strings.TrimSpace(req.RulingDescription)
		updatedAppeal.RulingEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
		updatedAppeal.RuledBy = actorDID
		updatedAppeal.RuledAt = cloneTimePtr(&now)
		updatedExtension.Status = effectiveStatus
		updatedDirective.DueAt = cloneTimePtr(afterDueAt)
		transitionAction = "secure_cell.federation_incident_directive_extension_appeal_ruled"
	}
	updatedAppeal.UpdatedAt = now
	updatedAppeal.Metadata = mergeStringMaps(updatedAppeal.Metadata, req.Metadata)
	updatedDispute.Appeals[appealIdx] = updatedAppeal
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

	transition := SecureCellTransition{
		ID:               transitionID(run.request, strings.TrimPrefix(transitionAction, "secure_cell."), updatedAppeal.ID),
		Action:           transitionAction,
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal",
		TargetDID:        updatedAppeal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                                    response.ID,
			"federation_organization_id":                                         response.OrganizationID,
			"federation_sponsor_of_record":                                       response.SponsorOfRecord,
			"federation_incident_id":                                             response.IncidentID,
			"federation_incident_directive_id":                                   directive.ID,
			"federation_incident_directive_title":                                directive.Title,
			"federation_incident_directive_status_before":                        string(directive.Status),
			"federation_incident_directive_status_after":                         string(directive.Status),
			"federation_incident_directive_due_at_before":                        secureCellFormatTime(beforeDueAt),
			"federation_incident_directive_due_at_after":                         secureCellFormatTime(updatedDirective.DueAt),
			"federation_incident_directive_extension_id":                         updatedExtension.ID,
			"federation_incident_directive_extension_status_before":              string(beforeStatus),
			"federation_incident_directive_extension_status_after":               string(updatedExtension.Status),
			"federation_incident_directive_extension_dispute_id":                 updatedDispute.ID,
			"federation_incident_directive_extension_dispute_status_before":      string(dispute.Status),
			"federation_incident_directive_extension_dispute_status_after":       string(updatedDispute.Status),
			"federation_incident_directive_extension_appeal_id":                  updatedAppeal.ID,
			"federation_incident_directive_extension_appeal_status_before":       string(appeal.Status),
			"federation_incident_directive_extension_appeal_status_after":        string(updatedAppeal.Status),
			"federation_incident_directive_extension_appeal_vote_id":             vote.ID,
			"federation_incident_directive_extension_appeal_vote_choice":         string(voteChoice),
			"federation_incident_directive_extension_appeal_board_threshold":     fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealThreshold(updatedAppeal)),
			"federation_incident_directive_extension_appeal_ratify_votes":        fmt.Sprintf("%d", ratifyVotes),
			"federation_incident_directive_extension_appeal_overturn_votes":      fmt.Sprintf("%d", overturnVotes),
			"federation_incident_directive_extension_appeal_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
			"federation_incident_directive_extension_appeal_ruling":              string(updatedAppeal.Ruling),
			"federation_incident_directive_extension_appeal_board_party":         string(updatedAppeal.BoardParty),
			"federation_incident_directive_extension_appealing_party":            string(updatedAppeal.AppealingParty),
			"federation_incident_directive_extension_appeal_pending_action": firstNonEmpty(func() string {
				if updatedAppeal.Status == SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview {
					return "board_review"
				}
				if updatedAppeal.Status == SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified || updatedAppeal.Status == SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned {
					return "acknowledge_enforcement"
				}
				return ""
			}()),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// DelegateFederationIncidentDirectiveExtensionAppealReview broadens the
// appeal-board reviewer set for one pending directive extension appeal.
func (s *Service) DelegateFederationIncidentDirectiveExtensionAppealReview(ctx context.Context, cellID string, appealID string, req SecureCellFederationIncidentDirectiveExtensionDelegationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	responseIdx, directiveIdx, extensionIdx, disputeIdx, appealIdx, response, directive, extension, dispute, appeal := findSecureCellFederationIncidentDirectiveExtensionAppeal(run.result.FederationIncidentResponses, appealID)
	if response == nil || directive == nil || extension == nil || dispute == nil || appeal == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: %q", ErrFederationIncidentDirectiveNotFound, appealID)
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: appeal %q is not awaiting board review", ErrFederationIncidentDirectiveImmutable, appealID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, appeal.BoardParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q is not permitted to delegate review for appeal %q", ErrPolicyDenied, actorDID, appealID)
	}
	targetDID := strings.TrimSpace(req.TargetDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: target_did is required")
	}
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, targetDID, appeal.BoardParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: target %q is not permitted to review appeal %q", ErrPolicyDenied, targetDID, appealID)
	}
	if secureCellStringSliceContains(appeal.EligibleBoardReviewerDIDs, targetDID) || secureCellFederationIncidentDirectiveExtensionAppealHasDelegatedReviewer(*appeal, targetDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: target %q is already eligible to review appeal %q", ErrFederationIncidentDirectiveImmutable, targetDID, appealID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "delegate_federation_incident_directive_extension_appeal_review", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                       response.ID,
		"federation_organization_id":                            response.OrganizationID,
		"federation_sponsor_of_record":                          response.SponsorOfRecord,
		"federation_incident_id":                                response.IncidentID,
		"federation_incident_directive_id":                      directive.ID,
		"federation_incident_directive_extension_id":            extension.ID,
		"federation_incident_directive_extension_dispute_id":    dispute.ID,
		"federation_incident_directive_extension_appeal_id":     appeal.ID,
		"federation_incident_directive_extension_appeal_status": string(appeal.Status),
		"federation_incident_directive_extension_target":        targetDID,
		"transition_reason":                                     firstNonEmpty(strings.TrimSpace(req.Reason), "delegate directive extension appeal review"),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	updatedDispute := updatedExtension.Disputes[disputeIdx]
	updatedAppeal := updatedDispute.Appeals[appealIdx]
	delegation := SecureCellFederationIncidentDirectiveExtensionDelegation{
		ID:                secureCellFederationIncidentDirectiveExtensionDelegationID(updatedAppeal.ID, "appeal_review", actorDID, targetDID, len(updatedAppeal.BoardDelegations)),
		FromActorDID:      actorDID,
		ToActorDID:        targetDID,
		Scope:             "appeal_review",
		Reason:            strings.TrimSpace(req.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	updatedAppeal.BoardDelegations = append(updatedAppeal.BoardDelegations, delegation)
	if len(updatedAppeal.EligibleBoardReviewerDIDs) > 0 {
		updatedAppeal.EligibleBoardReviewerDIDs = uniqueTrimmedStrings(append(updatedAppeal.EligibleBoardReviewerDIDs, targetDID))
	}
	updatedAppeal.UpdatedAt = now
	updatedAppeal.Metadata = mergeStringMaps(updatedAppeal.Metadata, req.Metadata)
	updatedDispute.Appeals[appealIdx] = updatedAppeal
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

	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(updatedAppeal)
	committeeState := secureCellFederationIncidentDirectiveExtensionAppealCommitteeSnapshot(updatedAppeal)
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_review_delegated", delegation.ID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_review_delegated",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal",
		TargetDID:        updatedAppeal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), "delegate directive extension appeal review"),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                                  response.ID,
			"federation_organization_id":                                       response.OrganizationID,
			"federation_sponsor_of_record":                                     response.SponsorOfRecord,
			"federation_incident_id":                                           response.IncidentID,
			"federation_incident_directive_id":                                 directive.ID,
			"federation_incident_directive_title":                              directive.Title,
			"federation_incident_directive_extension_id":                       updatedExtension.ID,
			"federation_incident_directive_extension_dispute_id":               updatedDispute.ID,
			"federation_incident_directive_extension_appeal_id":                updatedAppeal.ID,
			"federation_incident_directive_extension_appeal_status_before":     string(appeal.Status),
			"federation_incident_directive_extension_appeal_status_after":      string(updatedAppeal.Status),
			"federation_incident_directive_extension_appeal_delegation_id":     delegation.ID,
			"federation_incident_directive_extension_appeal_delegated_to":      targetDID,
			"federation_incident_directive_extension_appeal_board_threshold":   fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealThreshold(updatedAppeal)),
			"federation_incident_directive_extension_appeal_ratify_votes":      fmt.Sprintf("%d", ratifyVotes),
			"federation_incident_directive_extension_appeal_overturn_votes":    fmt.Sprintf("%d", overturnVotes),
			"federation_incident_directive_extension_appeal_delegation_count":  fmt.Sprintf("%d", committeeState.delegationCount),
			"federation_incident_directive_extension_appeal_committee_members": fmt.Sprintf("%d", committeeState.memberCount),
			"federation_incident_directive_extension_appeal_vote_count":        fmt.Sprintf("%d", committeeState.recordedVoteCount),
			"federation_incident_directive_extension_appeal_missing_quorum":    fmt.Sprintf("%d", committeeState.missingQuorumCount),
			"federation_incident_directive_extension_appeal_outstanding_votes": fmt.Sprintf("%d", committeeState.outstandingMemberCount),
			"federation_incident_directive_extension_appeal_quorum_satisfied":  fmt.Sprintf("%t", committeeState.quorumSatisfied),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement records
// reciprocal acknowledgement that the final appeal ruling will be enforced.
func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement(ctx context.Context, cellID string, appealID string, req SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	responseIdx, directiveIdx, extensionIdx, disputeIdx, appealIdx, response, directive, extension, dispute, appeal := findSecureCellFederationIncidentDirectiveExtensionAppeal(run.result.FederationIncidentResponses, appealID)
	if response == nil || directive == nil || extension == nil || dispute == nil || appeal == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: %q", ErrFederationIncidentDirectiveNotFound, appealID)
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified && appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: appeal %q is not awaiting enforcement acknowledgement", ErrFederationIncidentDirectiveImmutable, appealID)
	}
	ackParty := secureCellNormalizedFederationIncidentResponseParty(req.AcknowledgingParty)
	if ackParty == "" {
		ackParty = appeal.EnforcementAcknowledgementParty
	}
	if ackParty != appeal.EnforcementAcknowledgementParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: appeal %q must be acknowledged by %q", ErrPolicyDenied, appealID, appeal.EnforcementAcknowledgementParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, ackParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w: actor %q is not permitted to acknowledge appeal %q", ErrPolicyDenied, actorDID, appealID)
	}
	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		summary = secureCellFederationIncidentDirectiveExtensionAppealEnforcementSummary(*appeal)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_directive_extension_appeal_enforcement", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                       response.ID,
		"federation_organization_id":                            response.OrganizationID,
		"federation_sponsor_of_record":                          response.SponsorOfRecord,
		"federation_incident_id":                                response.IncidentID,
		"federation_incident_directive_id":                      directive.ID,
		"federation_incident_directive_extension_id":            extension.ID,
		"federation_incident_directive_extension_dispute_id":    dispute.ID,
		"federation_incident_directive_extension_appeal_id":     appeal.ID,
		"federation_incident_directive_extension_appeal_status": string(appeal.Status),
		"federation_incident_directive_extension_appeal_ruling": string(appeal.Ruling),
		"transition_reason":                                     firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	updatedDispute := updatedExtension.Disputes[disputeIdx]
	updatedAppeal := updatedDispute.Appeals[appealIdx]
	beforeStatus := updatedAppeal.Status
	updatedAppeal.Status = SecureCellFederationIncidentDirectiveExtensionAppealStatusEnforcementAcknowledged
	updatedAppeal.EnforcementAcknowledgementReceiptID = receipt.ID
	updatedAppeal.EnforcementAcknowledgementReceiptHash = receipt.ContentHash
	updatedAppeal.EnforcementSummary = summary
	updatedAppeal.EnforcementDescription = strings.TrimSpace(req.Description)
	updatedAppeal.EnforcementEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
	updatedAppeal.EnforcementAcknowledgedBy = actorDID
	updatedAppeal.EnforcementAcknowledgedAt = cloneTimePtr(&now)
	updatedAppeal.UpdatedAt = now
	updatedAppeal.Metadata = mergeStringMaps(updatedAppeal.Metadata, req.Metadata)
	updatedDispute.Appeals[appealIdx] = updatedAppeal
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

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_enforcement_acknowledged", updatedAppeal.ID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_enforcement_acknowledged",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal",
		TargetDID:        updatedAppeal.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                               response.ID,
			"federation_organization_id":                                    response.OrganizationID,
			"federation_sponsor_of_record":                                  response.SponsorOfRecord,
			"federation_incident_id":                                        response.IncidentID,
			"federation_incident_directive_id":                              directive.ID,
			"federation_incident_directive_title":                           directive.Title,
			"federation_incident_directive_extension_id":                    updatedExtension.ID,
			"federation_incident_directive_extension_dispute_id":            updatedDispute.ID,
			"federation_incident_directive_extension_appeal_id":             updatedAppeal.ID,
			"federation_incident_directive_extension_appeal_status_before":  string(beforeStatus),
			"federation_incident_directive_extension_appeal_status_after":   string(updatedAppeal.Status),
			"federation_incident_directive_extension_appeal_ruling":         string(updatedAppeal.Ruling),
			"federation_incident_directive_extension_appealing_party":       string(updatedAppeal.AppealingParty),
			"federation_incident_directive_extension_appeal_board_party":    string(updatedAppeal.BoardParty),
			"federation_incident_directive_extension_appeal_ack_party":      string(updatedAppeal.EnforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_pending_action": "",
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ListFederationIncidentDirectiveExtensionAppeals returns appeal-board
// reviews for operator and auditor use.
func (s *Service) ListFederationIncidentDirectiveExtensionAppeals(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, directive := range response.IncidentDirectives {
				if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(directive.ID), strings.TrimSpace(filter.DirectiveID)) {
					continue
				}
				for _, extension := range directive.Extensions {
					if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(extension.ID), strings.TrimSpace(filter.ExtensionID)) {
						continue
					}
					for _, dispute := range extension.Disputes {
						if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(dispute.ID), strings.TrimSpace(filter.DisputeID)) {
							continue
						}
						for _, appeal := range dispute.Appeals {
							summary := secureCellFederationIncidentDirectiveExtensionAppealSummaryFromRun(run, response, directive, extension, dispute, appeal)
							if !matchesSecureCellFederationIncidentDirectiveExtensionAppealFilter(summary, filter) {
								continue
							}
							items = append(items, summary)
						}
					}
				}
			}
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

func findSecureCellFederationIncidentDirectiveExtensionAppeal(responses []SecureCellFederationIncidentResponse, appealID string) (int, int, int, int, int, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentDirective, *SecureCellFederationIncidentDirectiveExtension, *SecureCellFederationIncidentDirectiveExtensionDispute, *SecureCellFederationIncidentDirectiveExtensionAppeal) {
	appealID = strings.TrimSpace(appealID)
	for responseIdx := range responses {
		for directiveIdx := range responses[responseIdx].IncidentDirectives {
			for extensionIdx := range responses[responseIdx].IncidentDirectives[directiveIdx].Extensions {
				for disputeIdx := range responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes {
					for appealIdx := range responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes[disputeIdx].Appeals {
						if strings.TrimSpace(responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes[disputeIdx].Appeals[appealIdx].ID) != appealID {
							continue
						}
						return responseIdx, directiveIdx, extensionIdx, disputeIdx, appealIdx, &responses[responseIdx], &responses[responseIdx].IncidentDirectives[directiveIdx], &responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx], &responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes[disputeIdx], &responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes[disputeIdx].Appeals[appealIdx]
					}
				}
			}
		}
	}
	return -1, -1, -1, -1, -1, nil, nil, nil, nil, nil
}

func secureCellFederationIncidentDirectiveExtensionAppealSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, directive SecureCellFederationIncidentDirective, extension SecureCellFederationIncidentDirectiveExtension, dispute SecureCellFederationIncidentDirectiveExtensionDispute, appeal SecureCellFederationIncidentDirectiveExtensionAppeal) SecureCellFederationIncidentDirectiveExtensionAppealSummary {
	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(appeal)
	committeeState := secureCellFederationIncidentDirectiveExtensionAppealCommitteeSnapshot(appeal)
	return SecureCellFederationIncidentDirectiveExtensionAppealSummary{
		CellID:                          run.result.CellID,
		CellName:                        run.result.Name,
		Jurisdiction:                    run.request.Jurisdiction,
		CellStatus:                      run.result.Status,
		ResponseID:                      response.ID,
		OrganizationID:                  response.OrganizationID,
		SponsorOfRecord:                 response.SponsorOfRecord,
		IncidentID:                      response.IncidentID,
		DirectiveID:                     directive.ID,
		DirectiveTitle:                  directive.Title,
		DirectiveStatus:                 directive.Status,
		ExtensionID:                     extension.ID,
		ExtensionStatus:                 extension.Status,
		DisputeID:                       dispute.ID,
		DisputeStatus:                   dispute.Status,
		AppealID:                        appeal.ID,
		AppealingParty:                  appeal.AppealingParty,
		BoardParty:                      appeal.BoardParty,
		EnforcementAcknowledgementParty: appeal.EnforcementAcknowledgementParty,
		ChallengedResolution:            appeal.ChallengedResolution,
		ChallengedExtensionStatus:       appeal.ChallengedExtensionStatus,
		AppealedBy:                      appeal.AppealedBy,
		Summary:                         appeal.Summary,
		Description:                     appeal.Description,
		Status:                          appeal.Status,
		BoardReviewThreshold:            secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal),
		EligibleBoardReviewerCount:      len(appeal.EligibleBoardReviewerDIDs),
		BoardDelegationCount:            len(appeal.BoardDelegations),
		BoardCommitteeMemberCount:       committeeState.memberCount,
		BoardRecordedVoteCount:          committeeState.recordedVoteCount,
		BoardOutstandingVotes:           committeeState.outstandingMemberCount,
		BoardMissingQuorumCount:         committeeState.missingQuorumCount,
		RatifyVoteCount:                 ratifyVotes,
		OverturnVoteCount:               overturnVotes,
		BoardThresholdSatisfied:         ratifyVotes >= secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal) || overturnVotes >= secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal),
		Ruling:                          appeal.Ruling,
		RulingSummary:                   appeal.RulingSummary,
		RuledBy:                         appeal.RuledBy,
		RuledAt:                         cloneTimePtr(appeal.RuledAt),
		EnforcementAcknowledgedBy:       appeal.EnforcementAcknowledgedBy,
		EnforcementAcknowledgedAt:       cloneTimePtr(appeal.EnforcementAcknowledgedAt),
		CreatedAt:                       appeal.CreatedAt,
		UpdatedAt:                       appeal.UpdatedAt,
		Metadata:                        cloneStringMap(appeal.Metadata),
	}
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealFilter(item SecureCellFederationIncidentDirectiveExtensionAppealSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealFilter) bool {
	if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealID), strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.Since != nil && item.UpdatedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && item.CreatedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealCount(responses []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, response := range responses {
		for _, directive := range response.IncidentDirectives {
			for _, extension := range directive.Extensions {
				for _, dispute := range extension.Disputes {
					total += len(dispute.Appeals)
				}
			}
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionPendingAppealCount(responses []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, response := range responses {
		for _, directive := range response.IncidentDirectives {
			for _, extension := range directive.Extensions {
				for _, dispute := range extension.Disputes {
					for _, appeal := range dispute.Appeals {
						if appeal.Status == SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview {
							total++
						}
					}
				}
			}
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealStatusCount(responses []SecureCellFederationIncidentResponse, status SecureCellFederationIncidentDirectiveExtensionAppealStatus) int {
	total := 0
	for _, response := range responses {
		for _, directive := range response.IncidentDirectives {
			for _, extension := range directive.Extensions {
				for _, dispute := range extension.Disputes {
					for _, appeal := range dispute.Appeals {
						if appeal.Status == status {
							total++
						}
					}
				}
			}
		}
	}
	return total
}
