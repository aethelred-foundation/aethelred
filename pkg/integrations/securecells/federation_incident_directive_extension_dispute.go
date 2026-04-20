package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// DisputeFederationIncidentDirectiveExtension records one governed challenge
// against an approved or rejected directive deadline exception.
func (s *Service) DisputeFederationIncidentDirectiveExtension(ctx context.Context, cellID string, extensionID string, req SecureCellFederationIncidentDirectiveExtensionDisputeRequest) (*SecureCellResult, error) {
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
	responseIdx, directiveIdx, extensionIdx, response, directive, extension := findSecureCellFederationIncidentDirectiveExtension(run.result.FederationIncidentResponses, extensionID)
	if response == nil || directive == nil || extension == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: %q", ErrFederationIncidentDirectiveNotFound, extensionID)
	}
	if extension.Status != SecureCellFederationIncidentDirectiveExtensionStatusApproved && extension.Status != SecureCellFederationIncidentDirectiveExtensionStatusRejected {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: extension %q is not challengeable", ErrFederationIncidentDirectiveImmutable, extensionID)
	}
	if pending := secureCellPendingFederationIncidentDirectiveExtensionDispute(*extension); pending != nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: extension %q already has pending dispute %q", ErrFederationIncidentDirectiveImmutable, extensionID, pending.ID)
	}

	challengingParty := secureCellNormalizedFederationIncidentResponseParty(req.ChallengingParty)
	if challengingParty == "" {
		challengingParty = secureCellFederationIncidentDirectiveExtensionDefaultChallengingParty(*extension)
	}
	if challengingParty != extension.RequestingParty && challengingParty != extension.ReviewingParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: invalid challenging party %q", ErrPolicyDenied, challengingParty)
	}
	respondingParty := secureCellFederationIncidentDirectiveOppositeParty(challengingParty)
	if respondingParty == "" {
		respondingParty = secureCellFederationIncidentDirectiveExtensionDefaultRespondingParty(*extension, challengingParty)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, challengingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: actor %q is not permitted to dispute extension %q", ErrPolicyDenied, actorDID, extensionID)
	}

	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		summary = secureCellFederationIncidentDirectiveExtensionDisputeDefaultSummary(*extension)
	}
	beforeDueAt := cloneTimePtr(directive.DueAt)
	afterDueAt := secureCellFederationIncidentDirectiveDueAtDuringDispute(*extension)

	receipt, err := s.evaluateStage(ctx, run.request, "dispute_federation_incident_directive_extension", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                           response.ID,
		"federation_organization_id":                                response.OrganizationID,
		"federation_sponsor_of_record":                              response.SponsorOfRecord,
		"federation_incident_id":                                    response.IncidentID,
		"federation_incident_directive_id":                          directive.ID,
		"federation_incident_directive_extension_id":                extension.ID,
		"federation_incident_directive_extension_status":            string(extension.Status),
		"federation_incident_directive_extension_challenged_status": string(extension.Status),
		"federation_incident_directive_due_at_before":               secureCellFormatTime(beforeDueAt),
		"federation_incident_directive_due_at_after":                secureCellFormatTime(afterDueAt),
		"federation_incident_directive_extension_disputing_party":   string(challengingParty),
		"federation_incident_directive_extension_responding_party":  string(respondingParty),
		"transition_reason":                                         firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	dispute := SecureCellFederationIncidentDirectiveExtensionDispute{
		ID:                   secureCellFederationIncidentDirectiveExtensionDisputeID(*extension, actorDID, now, len(extension.Disputes)),
		ResponseID:           response.ID,
		DirectiveID:          directive.ID,
		ExtensionID:          extension.ID,
		OrganizationID:       response.OrganizationID,
		SponsorOfRecord:      response.SponsorOfRecord,
		IncidentID:           response.IncidentID,
		ChallengingParty:     challengingParty,
		RespondingParty:      respondingParty,
		ChallengedStatus:     extension.Status,
		DisputedBy:           actorDID,
		Summary:              summary,
		Description:          strings.TrimSpace(req.Description),
		EvidenceIDs:          append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		ResolutionThreshold:  normalizeSecureCellThreshold(extension.DisputeResolutionThreshold),
		EligibleResolverDIDs: secureCellFederationIncidentDirectiveExtensionEligibleResolvers(run, *response, *extension, respondingParty),
		Status:               SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution,
		RequestReceiptID:     receipt.ID,
		RequestReceiptHash:   receipt.ContentHash,
		CreatedAt:            now,
		UpdatedAt:            now,
		Metadata:             cloneStringMap(req.Metadata),
	}

	updatedDirective := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updatedExtension := updatedDirective.Extensions[extensionIdx]
	beforeStatus := updatedExtension.Status
	updatedExtension.Status = SecureCellFederationIncidentDirectiveExtensionStatusDisputed
	updatedExtension.Disputes = append(updatedExtension.Disputes, dispute)
	updatedExtension.UpdatedAt = now
	updatedExtension.Metadata = mergeStringMaps(updatedExtension.Metadata, req.Metadata)
	updatedDirective.Extensions[extensionIdx] = updatedExtension
	updatedDirective.DueAt = cloneTimePtr(afterDueAt)
	updatedDirective.UpdatedAt = now
	updatedDirective.Metadata = mergeStringMaps(updatedDirective.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updatedDirective
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_disputed", dispute.ID),
		Action:           "secure_cell.federation_incident_directive_extension_disputed",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_dispute",
		TargetDID:        dispute.ID,
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
			"federation_incident_directive_priority":                        string(directive.Priority),
			"federation_incident_directive_status_before":                   string(directive.Status),
			"federation_incident_directive_status_after":                    string(directive.Status),
			"federation_incident_directive_due_at_before":                   secureCellFormatTime(beforeDueAt),
			"federation_incident_directive_due_at_after":                    secureCellFormatTime(updatedDirective.DueAt),
			"federation_incident_directive_extension_id":                    updatedExtension.ID,
			"federation_incident_directive_extension_status_before":         string(beforeStatus),
			"federation_incident_directive_extension_status_after":          string(updatedExtension.Status),
			"federation_incident_directive_extension_challenged_status":     string(dispute.ChallengedStatus),
			"federation_incident_directive_extension_dispute_id":            dispute.ID,
			"federation_incident_directive_extension_dispute_status_before": "",
			"federation_incident_directive_extension_dispute_status_after":  string(dispute.Status),
			"federation_incident_directive_extension_disputing_party":       string(dispute.ChallengingParty),
			"federation_incident_directive_extension_responding_party":      string(dispute.RespondingParty),
			"federation_incident_directive_extension_resolution_threshold":  fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute)),
			"federation_incident_directive_extension_eligible_resolvers":    strings.Join(dispute.EligibleResolverDIDs, ","),
			"federation_incident_directive_extension_disputed_by":           dispute.DisputedBy,
			"federation_incident_directive_extension_pending_action":        "resolve_dispute",
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ResolveFederationIncidentDirectiveExtensionDispute records one final
// disposition for a challenged directive deadline exception.
func (s *Service) ResolveFederationIncidentDirectiveExtensionDispute(ctx context.Context, cellID string, disputeID string, req SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest) (*SecureCellResult, error) {
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
	if extension.Status != SecureCellFederationIncidentDirectiveExtensionStatusDisputed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: extension %q is not awaiting dispute resolution", ErrFederationIncidentDirectiveImmutable, extension.ID)
	}
	if dispute.Status != SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: dispute %q is already resolved", ErrFederationIncidentDirectiveImmutable, disputeID)
	}
	resolution := secureCellNormalizedFederationIncidentDirectiveExtensionDisputeResolution(req.Resolution)
	if resolution == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: resolution is required")
	}
	respondingParty := secureCellNormalizedFederationIncidentResponseParty(req.RespondingParty)
	if respondingParty == "" {
		respondingParty = dispute.RespondingParty
	}
	if respondingParty != dispute.RespondingParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: dispute %q must be resolved by %q", ErrPolicyDenied, disputeID, dispute.RespondingParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, respondingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: actor %q is not permitted to resolve dispute %q", ErrPolicyDenied, actorDID, disputeID)
	}
	if !secureCellFederationIncidentDirectiveExtensionResolverAllowed(*dispute, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: actor %q is not an eligible resolver for dispute %q", ErrPolicyDenied, actorDID, disputeID)
	}
	if secureCellFederationIncidentDirectiveExtensionDisputeHasResolutionVote(*dispute, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-dispute: %w: actor %q has already voted on dispute %q", ErrFederationIncidentDirectiveImmutable, actorDID, disputeID)
	}

	summary := strings.TrimSpace(req.ResolutionSummary)
	if summary == "" {
		summary = secureCellFederationIncidentDirectiveExtensionDisputeResolutionSummary(dispute.ChallengedStatus, resolution)
	}
	beforeDueAt := cloneTimePtr(directive.DueAt)
	resolvedStatus := secureCellFederationIncidentDirectiveExtensionResolvedStatus(dispute.ChallengedStatus, resolution)
	afterDueAt := secureCellFederationIncidentDirectiveExtensionDueAtForStatus(*extension, resolvedStatus)

	receipt, err := s.evaluateStage(ctx, run.request, "resolve_federation_incident_directive_extension_dispute", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                           response.ID,
		"federation_organization_id":                                response.OrganizationID,
		"federation_sponsor_of_record":                              response.SponsorOfRecord,
		"federation_incident_id":                                    response.IncidentID,
		"federation_incident_directive_id":                          directive.ID,
		"federation_incident_directive_extension_id":                extension.ID,
		"federation_incident_directive_extension_dispute_id":        dispute.ID,
		"federation_incident_directive_extension_dispute_status":    string(dispute.Status),
		"federation_incident_directive_extension_challenged_status": string(dispute.ChallengedStatus),
		"federation_incident_directive_extension_resolution":        string(resolution),
		"federation_incident_directive_extension_status_after":      string(resolvedStatus),
		"federation_incident_directive_due_at_before":               secureCellFormatTime(beforeDueAt),
		"federation_incident_directive_due_at_after":                secureCellFormatTime(afterDueAt),
		"transition_reason":                                         firstNonEmpty(strings.TrimSpace(req.Reason), summary),
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
	beforeStatus := updatedExtension.Status
	updatedDispute := updatedExtension.Disputes[disputeIdx]
	voteChoice := SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteChoice(resolution)
	vote := SecureCellFederationIncidentDirectiveExtensionDisputeResolutionVote{
		ID:                secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteID(updatedDispute.ID, actorDID, voteChoice, len(updatedDispute.ResolutionVotes)),
		DisputeID:         updatedDispute.ID,
		ActorDID:          actorDID,
		Choice:            voteChoice,
		Reason:            firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	updatedDispute.ResolutionVotes = append(updatedDispute.ResolutionVotes, vote)
	upholdVotes, reverseVotes := secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteCounts(updatedDispute)
	thresholdSatisfied := secureCellFederationIncidentDirectiveExtensionDisputeResolutionThresholdSatisfied(updatedDispute, voteChoice)
	transitionAction := "secure_cell.federation_incident_directive_extension_dispute_resolution_vote_recorded"
	transitionReason := firstNonEmpty(strings.TrimSpace(req.Reason), summary)
	if thresholdSatisfied {
		updatedDispute.Status = secureCellFederationIncidentDirectiveExtensionDisputeStatusForResolution(resolution)
		updatedDispute.Resolution = resolution
		updatedDispute.ResolutionReceiptID = receipt.ID
		updatedDispute.ResolutionReceiptHash = receipt.ContentHash
		updatedDispute.ResolutionSummary = summary
		updatedDispute.ResolutionDescription = strings.TrimSpace(req.ResolutionDescription)
		updatedDispute.ResolutionEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
		updatedDispute.ResolvedBy = actorDID
		updatedDispute.ResolvedAt = cloneTimePtr(&now)
		updatedExtension.Status = resolvedStatus
		updatedDirective.DueAt = cloneTimePtr(afterDueAt)
		transitionAction = "secure_cell.federation_incident_directive_extension_dispute_resolved"
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

	transition := SecureCellTransition{
		ID:               transitionID(run.request, strings.TrimPrefix(transitionAction, "secure_cell."), updatedDispute.ID),
		Action:           transitionAction,
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_dispute",
		TargetDID:        updatedDispute.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           transitionReason,
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                                response.ID,
			"federation_organization_id":                                     response.OrganizationID,
			"federation_sponsor_of_record":                                   response.SponsorOfRecord,
			"federation_incident_id":                                         response.IncidentID,
			"federation_incident_directive_id":                               directive.ID,
			"federation_incident_directive_title":                            directive.Title,
			"federation_incident_directive_priority":                         string(directive.Priority),
			"federation_incident_directive_status_before":                    string(directive.Status),
			"federation_incident_directive_status_after":                     string(directive.Status),
			"federation_incident_directive_due_at_before":                    secureCellFormatTime(beforeDueAt),
			"federation_incident_directive_due_at_after":                     secureCellFormatTime(afterDueAt),
			"federation_incident_directive_extension_id":                     updatedExtension.ID,
			"federation_incident_directive_extension_status_before":          string(beforeStatus),
			"federation_incident_directive_extension_status_after":           string(updatedExtension.Status),
			"federation_incident_directive_extension_challenged_status":      string(updatedDispute.ChallengedStatus),
			"federation_incident_directive_extension_dispute_id":             updatedDispute.ID,
			"federation_incident_directive_extension_dispute_status_before":  string(dispute.Status),
			"federation_incident_directive_extension_dispute_status_after":   string(updatedDispute.Status),
			"federation_incident_directive_extension_disputing_party":        string(updatedDispute.ChallengingParty),
			"federation_incident_directive_extension_responding_party":       string(updatedDispute.RespondingParty),
			"federation_incident_directive_extension_resolution_vote_id":     vote.ID,
			"federation_incident_directive_extension_resolution_vote_choice": string(voteChoice),
			"federation_incident_directive_extension_resolution_threshold":   fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(updatedDispute)),
			"federation_incident_directive_extension_uphold_votes":           fmt.Sprintf("%d", upholdVotes),
			"federation_incident_directive_extension_reverse_votes":          fmt.Sprintf("%d", reverseVotes),
			"federation_incident_directive_extension_threshold_satisfied":    fmt.Sprintf("%t", thresholdSatisfied),
			"federation_incident_directive_extension_resolution":             string(updatedDispute.Resolution),
			"federation_incident_directive_extension_resolved_by":            updatedDispute.ResolvedBy,
			"federation_incident_directive_extension_pending_action":         "",
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ListFederationIncidentDirectiveExtensionDisputes returns directive-exception
// disputes for operator and auditor use.
func (s *Service) ListFederationIncidentDirectiveExtensionDisputes(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionDisputeFilter) ([]SecureCellFederationIncidentDirectiveExtensionDisputeSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionDisputeSummary, 0)
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
						summary := secureCellFederationIncidentDirectiveExtensionDisputeSummaryFromRun(run, response, directive, extension, dispute)
						if !matchesSecureCellFederationIncidentDirectiveExtensionDisputeFilter(summary, filter) {
							continue
						}
						items = append(items, summary)
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

func findSecureCellFederationIncidentDirectiveExtensionDispute(responses []SecureCellFederationIncidentResponse, disputeID string) (int, int, int, int, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentDirective, *SecureCellFederationIncidentDirectiveExtension, *SecureCellFederationIncidentDirectiveExtensionDispute) {
	disputeID = strings.TrimSpace(disputeID)
	for responseIdx := range responses {
		for directiveIdx := range responses[responseIdx].IncidentDirectives {
			for extensionIdx := range responses[responseIdx].IncidentDirectives[directiveIdx].Extensions {
				for disputeIdx := range responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes {
					if strings.TrimSpace(responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes[disputeIdx].ID) != disputeID {
						continue
					}
					return responseIdx, directiveIdx, extensionIdx, disputeIdx, &responses[responseIdx], &responses[responseIdx].IncidentDirectives[directiveIdx], &responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx], &responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].Disputes[disputeIdx]
				}
			}
		}
	}
	return -1, -1, -1, -1, nil, nil, nil, nil
}

func secureCellFederationIncidentDirectiveExtensionDisputeID(extension SecureCellFederationIncidentDirectiveExtension, actorDID string, createdAt time.Time, ordinal int) string {
	return fmt.Sprintf("%s-dispute-%s-%s-%02d",
		strings.TrimSpace(extension.ID),
		strings.ToLower(strings.TrimSpace(string(secureCellFederationIncidentDirectiveActorPartyForID(actorDID, extension.OrganizationID)))),
		createdAt.UTC().Format("20060102150405"),
		ordinal+1,
	)
}

func secureCellPendingFederationIncidentDirectiveExtensionDispute(extension SecureCellFederationIncidentDirectiveExtension) *SecureCellFederationIncidentDirectiveExtensionDispute {
	for idx := range extension.Disputes {
		if extension.Disputes[idx].Status == SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution {
			return &extension.Disputes[idx]
		}
	}
	return nil
}

func secureCellLatestFederationIncidentDirectiveExtensionDispute(extension SecureCellFederationIncidentDirectiveExtension) *SecureCellFederationIncidentDirectiveExtensionDispute {
	if len(extension.Disputes) == 0 {
		return nil
	}
	latest := &extension.Disputes[0]
	for idx := 1; idx < len(extension.Disputes); idx++ {
		if extension.Disputes[idx].UpdatedAt.After(latest.UpdatedAt) {
			latest = &extension.Disputes[idx]
		}
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionDefaultChallengingParty(extension SecureCellFederationIncidentDirectiveExtension) SecureCellFederationIncidentResponseParty {
	switch extension.Status {
	case SecureCellFederationIncidentDirectiveExtensionStatusApproved:
		return extension.ReviewingParty
	case SecureCellFederationIncidentDirectiveExtensionStatusRejected:
		return extension.RequestingParty
	default:
		return extension.RequestingParty
	}
}

func secureCellFederationIncidentDirectiveExtensionDefaultRespondingParty(extension SecureCellFederationIncidentDirectiveExtension, challengingParty SecureCellFederationIncidentResponseParty) SecureCellFederationIncidentResponseParty {
	if responding := secureCellFederationIncidentDirectiveOppositeParty(challengingParty); responding != "" {
		return responding
	}
	if challengingParty == extension.RequestingParty {
		return extension.ReviewingParty
	}
	return extension.RequestingParty
}

func secureCellFederationIncidentDirectiveExtensionDisputeDefaultSummary(extension SecureCellFederationIncidentDirectiveExtension) string {
	switch extension.Status {
	case SecureCellFederationIncidentDirectiveExtensionStatusApproved:
		return "challenge approved directive deadline extension"
	case SecureCellFederationIncidentDirectiveExtensionStatusRejected:
		return "challenge rejected directive deadline extension"
	default:
		return "challenge directive deadline extension"
	}
}

func secureCellFederationIncidentDirectiveDueAtDuringDispute(extension SecureCellFederationIncidentDirectiveExtension) *time.Time {
	if extension.Status == SecureCellFederationIncidentDirectiveExtensionStatusApproved {
		return cloneTimePtr(extension.CurrentDueAt)
	}
	return secureCellFederationIncidentDirectiveExtensionDueAtForStatus(extension, extension.Status)
}

func secureCellFederationIncidentDirectiveExtensionDueAtForStatus(extension SecureCellFederationIncidentDirectiveExtension, status SecureCellFederationIncidentDirectiveExtensionStatus) *time.Time {
	switch status {
	case SecureCellFederationIncidentDirectiveExtensionStatusApproved:
		return cloneTimePtr(extension.ProposedDueAt)
	case SecureCellFederationIncidentDirectiveExtensionStatusRejected, SecureCellFederationIncidentDirectiveExtensionStatusDisputed:
		return cloneTimePtr(extension.CurrentDueAt)
	default:
		return cloneTimePtr(extension.CurrentDueAt)
	}
}

func secureCellNormalizedFederationIncidentDirectiveExtensionDisputeResolution(value SecureCellFederationIncidentDirectiveExtensionDisputeResolution) SecureCellFederationIncidentDirectiveExtensionDisputeResolution {
	switch SecureCellFederationIncidentDirectiveExtensionDisputeResolution(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold:
		return SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold
	case SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse:
		return SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveExtensionResolvedStatus(challengedStatus SecureCellFederationIncidentDirectiveExtensionStatus, resolution SecureCellFederationIncidentDirectiveExtensionDisputeResolution) SecureCellFederationIncidentDirectiveExtensionStatus {
	if resolution == SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold {
		return challengedStatus
	}
	switch challengedStatus {
	case SecureCellFederationIncidentDirectiveExtensionStatusApproved:
		return SecureCellFederationIncidentDirectiveExtensionStatusRejected
	case SecureCellFederationIncidentDirectiveExtensionStatusRejected:
		return SecureCellFederationIncidentDirectiveExtensionStatusApproved
	default:
		return challengedStatus
	}
}

func secureCellFederationIncidentDirectiveExtensionDisputeStatusForResolution(resolution SecureCellFederationIncidentDirectiveExtensionDisputeResolution) SecureCellFederationIncidentDirectiveExtensionDisputeStatus {
	if resolution == SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse {
		return SecureCellFederationIncidentDirectiveExtensionDisputeStatusReversed
	}
	return SecureCellFederationIncidentDirectiveExtensionDisputeStatusUpheld
}

func secureCellFederationIncidentDirectiveExtensionDisputeResolutionSummary(challengedStatus SecureCellFederationIncidentDirectiveExtensionStatus, resolution SecureCellFederationIncidentDirectiveExtensionDisputeResolution) string {
	if resolution == SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse {
		return "directive deadline extension dispute reversed prior decision"
	}
	switch challengedStatus {
	case SecureCellFederationIncidentDirectiveExtensionStatusApproved:
		return "directive deadline extension approval upheld"
	case SecureCellFederationIncidentDirectiveExtensionStatusRejected:
		return "directive deadline extension rejection upheld"
	default:
		return "directive deadline extension dispute upheld"
	}
}

func secureCellFederationIncidentDirectiveExtensionDisputeSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, directive SecureCellFederationIncidentDirective, extension SecureCellFederationIncidentDirectiveExtension, dispute SecureCellFederationIncidentDirectiveExtensionDispute) SecureCellFederationIncidentDirectiveExtensionDisputeSummary {
	upholdVotes, reverseVotes := secureCellFederationIncidentDirectiveExtensionDisputeResolutionVoteCounts(dispute)
	committeeState := secureCellFederationIncidentDirectiveExtensionDisputeCommitteeState(dispute)
	return SecureCellFederationIncidentDirectiveExtensionDisputeSummary{
		CellID:                         strings.TrimSpace(run.result.CellID),
		CellName:                       strings.TrimSpace(run.result.Name),
		Jurisdiction:                   strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:                     run.result.Status,
		ResponseID:                     strings.TrimSpace(response.ID),
		OrganizationID:                 strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:                strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:                     strings.TrimSpace(response.IncidentID),
		DirectiveID:                    strings.TrimSpace(directive.ID),
		DirectiveTitle:                 strings.TrimSpace(directive.Title),
		DirectiveStatus:                directive.Status,
		ExtensionID:                    strings.TrimSpace(extension.ID),
		ExtensionStatus:                extension.Status,
		DisputeID:                      strings.TrimSpace(dispute.ID),
		ChallengingParty:               dispute.ChallengingParty,
		RespondingParty:                dispute.RespondingParty,
		ChallengedStatus:               dispute.ChallengedStatus,
		DisputedBy:                     strings.TrimSpace(dispute.DisputedBy),
		Summary:                        strings.TrimSpace(dispute.Summary),
		Description:                    strings.TrimSpace(dispute.Description),
		Status:                         dispute.Status,
		ResolutionThreshold:            secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute),
		EligibleResolverCount:          len(uniqueTrimmedStrings(dispute.EligibleResolverDIDs)),
		ResolutionDelegationCount:      len(dispute.ResolutionDelegations),
		ResolutionCommitteeMemberCount: committeeState.memberCount,
		ResolutionRecordedVoteCount:    committeeState.recordedVoteCount,
		ResolutionOutstandingVotes:     committeeState.outstandingMemberCount,
		ResolutionMissingQuorumCount:   committeeState.missingQuorumCount,
		UpholdVoteCount:                upholdVotes,
		ReverseVoteCount:               reverseVotes,
		ResolutionThresholdSatisfied:   upholdVotes >= secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute) || reverseVotes >= secureCellFederationIncidentDirectiveExtensionDisputeResolutionThreshold(dispute),
		Resolution:                     dispute.Resolution,
		ResolutionSummary:              strings.TrimSpace(dispute.ResolutionSummary),
		ResolvedBy:                     strings.TrimSpace(dispute.ResolvedBy),
		ResolvedAt:                     cloneTimePtr(dispute.ResolvedAt),
		CreatedAt:                      dispute.CreatedAt.UTC(),
		UpdatedAt:                      dispute.UpdatedAt.UTC(),
		Metadata:                       cloneStringMap(dispute.Metadata),
	}
}

func matchesSecureCellFederationIncidentDirectiveExtensionDisputeFilter(item SecureCellFederationIncidentDirectiveExtensionDisputeSummary, filter SecureCellFederationIncidentDirectiveExtensionDisputeFilter) bool {
	if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(item.DisputeID), strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.Since != nil && item.UpdatedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && item.UpdatedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}
