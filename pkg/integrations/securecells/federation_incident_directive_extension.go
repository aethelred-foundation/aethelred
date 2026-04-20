package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// RequestFederationIncidentDirectiveExtension opens one governed deadline
// exception request for a bilateral incident directive.
func (s *Service) RequestFederationIncidentDirectiveExtension(ctx context.Context, cellID string, directiveID string, req SecureCellFederationIncidentDirectiveExtensionRequest) (*SecureCellResult, error) {
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
	responseIdx, directiveIdx, response, directive := findSecureCellFederationIncidentDirective(run.result.FederationIncidentResponses, directiveID)
	if response == nil || directive == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: %q", ErrFederationIncidentDirectiveNotFound, directiveID)
	}
	if directive.Status == SecureCellFederationIncidentDirectiveStatusVerified {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: directive %q is already verified", ErrFederationIncidentDirectiveImmutable, directiveID)
	}
	if directive.DueAt == nil || directive.DueAt.IsZero() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: directive %q does not have a due_at", directiveID)
	}
	if pending := secureCellPendingFederationIncidentDirectiveExtension(*directive); pending != nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: directive %q already has pending extension %q", ErrFederationIncidentDirectiveImmutable, directiveID, pending.ID)
	}
	if req.ProposedDueAt == nil || req.ProposedDueAt.IsZero() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: proposed_due_at is required")
	}
	currentDueAt := directive.DueAt.UTC()
	proposedDueAt := req.ProposedDueAt.UTC()
	if !proposedDueAt.After(currentDueAt) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: proposed_due_at must be after current due_at")
	}

	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: summary is required")
	}
	requestingParty := secureCellNormalizedFederationIncidentResponseParty(req.RequestingParty)
	if requestingParty == "" {
		requestingParty = directive.AssigneeParty
	}
	if requestingParty != directive.AssigneeParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: only the assignee party may request an extension", ErrPolicyDenied)
	}
	reviewingParty := secureCellFederationIncidentDirectiveOppositeParty(requestingParty)
	if reviewingParty == "" {
		reviewingParty = directive.ReviewerParty
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, requestingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: actor %q is not permitted to request an extension for directive %q", ErrPolicyDenied, actorDID, directiveID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "request_federation_incident_directive_extension", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                         response.ID,
		"federation_organization_id":                              response.OrganizationID,
		"federation_sponsor_of_record":                            response.SponsorOfRecord,
		"federation_incident_id":                                  response.IncidentID,
		"federation_incident_directive_id":                        directive.ID,
		"federation_incident_directive_status":                    string(directive.Status),
		"federation_incident_directive_due_at":                    currentDueAt.Format(time.RFC3339Nano),
		"federation_incident_directive_extension_request_party":   string(requestingParty),
		"federation_incident_directive_extension_review_party":    string(reviewingParty),
		"federation_incident_directive_extension_proposed_due_at": proposedDueAt.Format(time.RFC3339Nano),
		"transition_reason":                                       firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	extension := SecureCellFederationIncidentDirectiveExtension{
		ID:                 secureCellFederationIncidentDirectiveExtensionID(*directive, actorDID, now, len(directive.Extensions)),
		ResponseID:         response.ID,
		DirectiveID:        directive.ID,
		OrganizationID:     response.OrganizationID,
		SponsorOfRecord:    response.SponsorOfRecord,
		IncidentID:         response.IncidentID,
		RequestingParty:    requestingParty,
		ReviewingParty:     reviewingParty,
		RequestedBy:        actorDID,
		Summary:            summary,
		Description:        strings.TrimSpace(req.Description),
		EvidenceIDs:        append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		CurrentDueAt:       cloneTimePtr(&currentDueAt),
		ProposedDueAt:      cloneTimePtr(&proposedDueAt),
		Status:             SecureCellFederationIncidentDirectiveExtensionStatusPendingReview,
		RequestReceiptID:   receipt.ID,
		RequestReceiptHash: receipt.ContentHash,
		CreatedAt:          now,
		UpdatedAt:          now,
		Metadata:           cloneStringMap(req.Metadata),
	}
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	updated.Extensions = append(updated.Extensions, extension)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_requested", extension.ID),
		Action:           "secure_cell.federation_incident_directive_extension_requested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension",
		TargetDID:        extension.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                         response.ID,
			"federation_organization_id":                              response.OrganizationID,
			"federation_sponsor_of_record":                            response.SponsorOfRecord,
			"federation_incident_id":                                  response.IncidentID,
			"federation_incident_directive_id":                        directive.ID,
			"federation_incident_directive_title":                     directive.Title,
			"federation_incident_directive_priority":                  string(directive.Priority),
			"federation_incident_directive_status_before":             string(directive.Status),
			"federation_incident_directive_status_after":              string(directive.Status),
			"federation_incident_directive_due_at_before":             currentDueAt.Format(time.RFC3339Nano),
			"federation_incident_directive_due_at_after":              currentDueAt.Format(time.RFC3339Nano),
			"federation_incident_directive_extension_id":              extension.ID,
			"federation_incident_directive_extension_status_before":   "",
			"federation_incident_directive_extension_status_after":    string(extension.Status),
			"federation_incident_directive_extension_request_party":   string(extension.RequestingParty),
			"federation_incident_directive_extension_review_party":    string(extension.ReviewingParty),
			"federation_incident_directive_extension_requested_by":    extension.RequestedBy,
			"federation_incident_directive_extension_current_due_at":  currentDueAt.Format(time.RFC3339Nano),
			"federation_incident_directive_extension_proposed_due_at": proposedDueAt.Format(time.RFC3339Nano),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ApproveFederationIncidentDirectiveExtension grants one governed deadline
// exception for a bilateral incident directive.
func (s *Service) ApproveFederationIncidentDirectiveExtension(ctx context.Context, cellID string, extensionID string, req SecureCellFederationIncidentDirectiveExtensionApproveRequest) (*SecureCellResult, error) {
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
	if directive.Status == SecureCellFederationIncidentDirectiveStatusVerified {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: directive %q is already verified", ErrFederationIncidentDirectiveImmutable, directive.ID)
	}
	reviewingParty := secureCellNormalizedFederationIncidentResponseParty(req.ReviewingParty)
	if reviewingParty == "" {
		reviewingParty = extension.ReviewingParty
	}
	if reviewingParty != extension.ReviewingParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: extension %q must be reviewed by %q", ErrPolicyDenied, extensionID, extension.ReviewingParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, reviewingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: actor %q is not permitted to approve extension %q", ErrPolicyDenied, actorDID, extensionID)
	}
	if extension.ProposedDueAt == nil || extension.ProposedDueAt.IsZero() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: extension %q does not carry a proposed due_at", extensionID)
	}

	summary := strings.TrimSpace(req.DecisionSummary)
	if summary == "" {
		summary = firstNonEmpty(strings.TrimSpace(extension.Summary), "approve directive deadline extension")
	}
	currentDueAt := cloneTimePtr(directive.DueAt)
	proposedDueAt := cloneTimePtr(extension.ProposedDueAt)
	receipt, err := s.evaluateStage(ctx, run.request, "approve_federation_incident_directive_extension", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                         response.ID,
		"federation_organization_id":                              response.OrganizationID,
		"federation_sponsor_of_record":                            response.SponsorOfRecord,
		"federation_incident_id":                                  response.IncidentID,
		"federation_incident_directive_id":                        directive.ID,
		"federation_incident_directive_extension_id":              extension.ID,
		"federation_incident_directive_extension_status":          string(extension.Status),
		"federation_incident_directive_due_at":                    secureCellFormatTime(currentDueAt),
		"federation_incident_directive_extension_proposed_due_at": secureCellFormatTime(proposedDueAt),
		"transition_reason":                                       firstNonEmpty(strings.TrimSpace(req.Reason), summary),
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
	beforeStatus := updatedExtension.Status
	beforeDueAt := cloneTimePtr(updatedDirective.DueAt)
	updatedExtension.Status = SecureCellFederationIncidentDirectiveExtensionStatusApproved
	updatedExtension.DecisionReceiptID = receipt.ID
	updatedExtension.DecisionReceiptHash = receipt.ContentHash
	updatedExtension.DecisionSummary = summary
	updatedExtension.DecisionDescription = strings.TrimSpace(req.DecisionDescription)
	updatedExtension.DecisionEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
	updatedExtension.ReviewedBy = actorDID
	updatedExtension.ReviewedAt = cloneTimePtr(&now)
	updatedExtension.UpdatedAt = now
	updatedExtension.Metadata = mergeStringMaps(updatedExtension.Metadata, req.Metadata)
	updatedDirective.Extensions[extensionIdx] = updatedExtension
	updatedDirective.DueAt = cloneTimePtr(updatedExtension.ProposedDueAt)
	updatedDirective.UpdatedAt = now
	updatedDirective.Metadata = mergeStringMaps(updatedDirective.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updatedDirective
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_approved", updatedExtension.ID),
		Action:           "secure_cell.federation_incident_directive_extension_approved",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension",
		TargetDID:        updatedExtension.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                         response.ID,
			"federation_organization_id":                              response.OrganizationID,
			"federation_sponsor_of_record":                            response.SponsorOfRecord,
			"federation_incident_id":                                  response.IncidentID,
			"federation_incident_directive_id":                        updatedDirective.ID,
			"federation_incident_directive_title":                     updatedDirective.Title,
			"federation_incident_directive_priority":                  string(updatedDirective.Priority),
			"federation_incident_directive_status_before":             string(updatedDirective.Status),
			"federation_incident_directive_status_after":              string(updatedDirective.Status),
			"federation_incident_directive_due_at_before":             secureCellFormatTime(beforeDueAt),
			"federation_incident_directive_due_at_after":              secureCellFormatTime(updatedDirective.DueAt),
			"federation_incident_directive_extension_id":              updatedExtension.ID,
			"federation_incident_directive_extension_status_before":   string(beforeStatus),
			"federation_incident_directive_extension_status_after":    string(updatedExtension.Status),
			"federation_incident_directive_extension_request_party":   string(updatedExtension.RequestingParty),
			"federation_incident_directive_extension_review_party":    string(updatedExtension.ReviewingParty),
			"federation_incident_directive_extension_requested_by":    updatedExtension.RequestedBy,
			"federation_incident_directive_extension_reviewed_by":     updatedExtension.ReviewedBy,
			"federation_incident_directive_extension_current_due_at":  secureCellFormatTime(updatedExtension.CurrentDueAt),
			"federation_incident_directive_extension_proposed_due_at": secureCellFormatTime(updatedExtension.ProposedDueAt),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RejectFederationIncidentDirectiveExtension denies one governed deadline
// exception request for a bilateral incident directive.
func (s *Service) RejectFederationIncidentDirectiveExtension(ctx context.Context, cellID string, extensionID string, req SecureCellFederationIncidentDirectiveExtensionRejectRequest) (*SecureCellResult, error) {
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
	reviewingParty := secureCellNormalizedFederationIncidentResponseParty(req.ReviewingParty)
	if reviewingParty == "" {
		reviewingParty = extension.ReviewingParty
	}
	if reviewingParty != extension.ReviewingParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: extension %q must be reviewed by %q", ErrPolicyDenied, extensionID, extension.ReviewingParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, reviewingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension: %w: actor %q is not permitted to reject extension %q", ErrPolicyDenied, actorDID, extensionID)
	}

	summary := strings.TrimSpace(req.DecisionSummary)
	if summary == "" {
		summary = "directive deadline extension rejected"
	}
	receipt, err := s.evaluateStage(ctx, run.request, "reject_federation_incident_directive_extension", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":                         response.ID,
		"federation_organization_id":                              response.OrganizationID,
		"federation_sponsor_of_record":                            response.SponsorOfRecord,
		"federation_incident_id":                                  response.IncidentID,
		"federation_incident_directive_id":                        directive.ID,
		"federation_incident_directive_extension_id":              extension.ID,
		"federation_incident_directive_extension_status":          string(extension.Status),
		"federation_incident_directive_due_at":                    secureCellFormatTime(directive.DueAt),
		"federation_incident_directive_extension_proposed_due_at": secureCellFormatTime(extension.ProposedDueAt),
		"transition_reason":                                       firstNonEmpty(strings.TrimSpace(req.Reason), summary),
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
	beforeStatus := updatedExtension.Status
	updatedExtension.Status = SecureCellFederationIncidentDirectiveExtensionStatusRejected
	updatedExtension.DecisionReceiptID = receipt.ID
	updatedExtension.DecisionReceiptHash = receipt.ContentHash
	updatedExtension.DecisionSummary = summary
	updatedExtension.DecisionDescription = strings.TrimSpace(req.DecisionDescription)
	updatedExtension.DecisionEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
	updatedExtension.ReviewedBy = actorDID
	updatedExtension.ReviewedAt = cloneTimePtr(&now)
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
		ID:               transitionID(run.request, "federation_incident_directive_extension_rejected", updatedExtension.ID),
		Action:           "secure_cell.federation_incident_directive_extension_rejected",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension",
		TargetDID:        updatedExtension.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":                         response.ID,
			"federation_organization_id":                              response.OrganizationID,
			"federation_sponsor_of_record":                            response.SponsorOfRecord,
			"federation_incident_id":                                  response.IncidentID,
			"federation_incident_directive_id":                        updatedDirective.ID,
			"federation_incident_directive_title":                     updatedDirective.Title,
			"federation_incident_directive_priority":                  string(updatedDirective.Priority),
			"federation_incident_directive_status_before":             string(updatedDirective.Status),
			"federation_incident_directive_status_after":              string(updatedDirective.Status),
			"federation_incident_directive_due_at_before":             secureCellFormatTime(updatedDirective.DueAt),
			"federation_incident_directive_due_at_after":              secureCellFormatTime(updatedDirective.DueAt),
			"federation_incident_directive_extension_id":              updatedExtension.ID,
			"federation_incident_directive_extension_status_before":   string(beforeStatus),
			"federation_incident_directive_extension_status_after":    string(updatedExtension.Status),
			"federation_incident_directive_extension_request_party":   string(updatedExtension.RequestingParty),
			"federation_incident_directive_extension_review_party":    string(updatedExtension.ReviewingParty),
			"federation_incident_directive_extension_requested_by":    updatedExtension.RequestedBy,
			"federation_incident_directive_extension_reviewed_by":     updatedExtension.ReviewedBy,
			"federation_incident_directive_extension_current_due_at":  secureCellFormatTime(updatedExtension.CurrentDueAt),
			"federation_incident_directive_extension_proposed_due_at": secureCellFormatTime(updatedExtension.ProposedDueAt),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ListFederationIncidentDirectiveExtensions returns directive deadline
// exception records for operator and auditor use.
func (s *Service) ListFederationIncidentDirectiveExtensions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionFilter) ([]SecureCellFederationIncidentDirectiveExtensionSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionSummary, 0)
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
					summary := secureCellFederationIncidentDirectiveExtensionSummaryFromRun(run, response, directive, extension)
					if !matchesSecureCellFederationIncidentDirectiveExtensionFilter(summary, filter) {
						continue
					}
					items = append(items, summary)
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

func findSecureCellFederationIncidentDirectiveExtension(responses []SecureCellFederationIncidentResponse, extensionID string) (int, int, int, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentDirective, *SecureCellFederationIncidentDirectiveExtension) {
	extensionID = strings.TrimSpace(extensionID)
	for responseIdx := range responses {
		for directiveIdx := range responses[responseIdx].IncidentDirectives {
			for extensionIdx := range responses[responseIdx].IncidentDirectives[directiveIdx].Extensions {
				if strings.TrimSpace(responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx].ID) != extensionID {
					continue
				}
				return responseIdx, directiveIdx, extensionIdx, &responses[responseIdx], &responses[responseIdx].IncidentDirectives[directiveIdx], &responses[responseIdx].IncidentDirectives[directiveIdx].Extensions[extensionIdx]
			}
		}
	}
	return -1, -1, -1, nil, nil, nil
}

func secureCellFederationIncidentDirectiveExtensionID(directive SecureCellFederationIncidentDirective, actorDID string, createdAt time.Time, ordinal int) string {
	return fmt.Sprintf("%s-extension-%s-%s-%02d",
		strings.TrimSpace(directive.ID),
		strings.ToLower(strings.TrimSpace(string(secureCellFederationIncidentDirectiveActorPartyForID(actorDID, directive.OrganizationID)))),
		createdAt.UTC().Format("20060102150405"),
		ordinal+1,
	)
}

func secureCellPendingFederationIncidentDirectiveExtension(directive SecureCellFederationIncidentDirective) *SecureCellFederationIncidentDirectiveExtension {
	for idx := range directive.Extensions {
		if directive.Extensions[idx].Status == SecureCellFederationIncidentDirectiveExtensionStatusPendingReview {
			return &directive.Extensions[idx]
		}
	}
	return nil
}

func secureCellNormalizedFederationIncidentDirectiveExtensionStatus(value SecureCellFederationIncidentDirectiveExtensionStatus) SecureCellFederationIncidentDirectiveExtensionStatus {
	switch SecureCellFederationIncidentDirectiveExtensionStatus(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentDirectiveExtensionStatusPendingReview:
		return SecureCellFederationIncidentDirectiveExtensionStatusPendingReview
	case SecureCellFederationIncidentDirectiveExtensionStatusApproved:
		return SecureCellFederationIncidentDirectiveExtensionStatusApproved
	case SecureCellFederationIncidentDirectiveExtensionStatusRejected:
		return SecureCellFederationIncidentDirectiveExtensionStatusRejected
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveExtensionPendingCount(extensions []SecureCellFederationIncidentDirectiveExtension) int {
	count := 0
	for _, extension := range extensions {
		if extension.Status == SecureCellFederationIncidentDirectiveExtensionStatusPendingReview {
			count++
		}
	}
	return count
}

func secureCellFederationIncidentDirectiveLatestExtension(extensions []SecureCellFederationIncidentDirectiveExtension) *SecureCellFederationIncidentDirectiveExtension {
	if len(extensions) == 0 {
		return nil
	}
	latest := &extensions[0]
	for idx := 1; idx < len(extensions); idx++ {
		if extensions[idx].UpdatedAt.After(latest.UpdatedAt) {
			latest = &extensions[idx]
		}
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionStatusCount(responses []SecureCellFederationIncidentResponse, status SecureCellFederationIncidentDirectiveExtensionStatus) int {
	total := 0
	for _, response := range responses {
		for _, directive := range response.IncidentDirectives {
			for _, extension := range directive.Extensions {
				if extension.Status == status {
					total++
				}
			}
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionTotal(responses []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, response := range responses {
		for _, directive := range response.IncidentDirectives {
			total += len(directive.Extensions)
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, directive SecureCellFederationIncidentDirective, extension SecureCellFederationIncidentDirectiveExtension) SecureCellFederationIncidentDirectiveExtensionSummary {
	return SecureCellFederationIncidentDirectiveExtensionSummary{
		CellID:          strings.TrimSpace(run.result.CellID),
		CellName:        strings.TrimSpace(run.result.Name),
		Jurisdiction:    strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:      run.result.Status,
		ResponseID:      strings.TrimSpace(response.ID),
		OrganizationID:  strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord: strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:      strings.TrimSpace(response.IncidentID),
		DirectiveID:     strings.TrimSpace(directive.ID),
		DirectiveTitle:  strings.TrimSpace(directive.Title),
		DirectiveStatus: directive.Status,
		ExtensionID:     strings.TrimSpace(extension.ID),
		RequestingParty: extension.RequestingParty,
		ReviewingParty:  extension.ReviewingParty,
		RequestedBy:     strings.TrimSpace(extension.RequestedBy),
		Summary:         strings.TrimSpace(extension.Summary),
		Description:     strings.TrimSpace(extension.Description),
		CurrentDueAt:    cloneTimePtr(extension.CurrentDueAt),
		ProposedDueAt:   cloneTimePtr(extension.ProposedDueAt),
		Status:          extension.Status,
		DecisionSummary: strings.TrimSpace(extension.DecisionSummary),
		ReviewedBy:      strings.TrimSpace(extension.ReviewedBy),
		ReviewedAt:      cloneTimePtr(extension.ReviewedAt),
		CreatedAt:       extension.CreatedAt.UTC(),
		UpdatedAt:       extension.UpdatedAt.UTC(),
		Metadata:        cloneStringMap(extension.Metadata),
	}
}

func matchesSecureCellFederationIncidentDirectiveExtensionFilter(item SecureCellFederationIncidentDirectiveExtensionSummary, filter SecureCellFederationIncidentDirectiveExtensionFilter) bool {
	if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(item.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
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
