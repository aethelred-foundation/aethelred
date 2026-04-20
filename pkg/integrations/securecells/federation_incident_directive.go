package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

func (s *Service) CreateFederationIncidentDirective(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentDirectiveCreateRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	responseIdx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive: directive title is required")
	}
	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive: directive summary is required")
	}
	if req.DueAt == nil || req.DueAt.IsZero() {
		return nil, fmt.Errorf("securecells/federation-incident-directive: directive due_at is required")
	}

	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	issuingParty := secureCellFederationIncidentDirectiveActorParty(run, *response, actorDID)
	if issuingParty == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: actor %q is not permitted to issue directives for response %q", ErrPolicyDenied, actorDID, responseID)
	}

	assigneeParty := secureCellNormalizedFederationIncidentResponseParty(req.AssigneeParty)
	if assigneeParty == "" {
		assigneeParty = secureCellFederationIncidentDirectiveDefaultAssigneeParty(*response)
	}
	reviewerParty := secureCellNormalizedFederationIncidentResponseParty(req.ReviewerParty)
	if reviewerParty == "" {
		reviewerParty = secureCellFederationIncidentDirectiveOppositeParty(assigneeParty)
	}
	if assigneeParty == "" || reviewerParty == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive: bilateral assignee and reviewer parties are required")
	}

	priority := secureCellNormalizedFederationIncidentDirectivePriority(req.Priority)
	if priority == "" {
		priority = secureCellFederationIncidentDirectiveDefaultPriority(*response)
	}
	dueAt := req.DueAt.UTC()

	receipt, err := s.evaluateStage(ctx, run.request, "issue_federation_incident_directive", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":        response.ID,
		"federation_organization_id":             response.OrganizationID,
		"federation_sponsor_of_record":           response.SponsorOfRecord,
		"federation_incident_id":                 response.IncidentID,
		"federation_incident_directive_title":    title,
		"federation_incident_directive_type":     strings.TrimSpace(req.DirectiveType),
		"federation_incident_directive_priority": string(priority),
		"federation_incident_directive_assignee": string(assigneeParty),
		"federation_incident_directive_reviewer": string(reviewerParty),
		"federation_incident_directive_due_at":   dueAt.Format(time.RFC3339Nano),
		"transition_reason":                      firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	directive := SecureCellFederationIncidentDirective{
		ID:                  secureCellFederationIncidentDirectiveID(*response, actorDID, now, len(run.result.FederationIncidentResponses[responseIdx].IncidentDirectives)),
		ResponseID:          response.ID,
		OrganizationID:      response.OrganizationID,
		SponsorOfRecord:     response.SponsorOfRecord,
		IncidentID:          response.IncidentID,
		DirectiveType:       strings.TrimSpace(req.DirectiveType),
		Title:               title,
		Summary:             summary,
		Description:         strings.TrimSpace(req.Description),
		Priority:            priority,
		Status:              SecureCellFederationIncidentDirectiveStatusIssued,
		IssuingParty:        issuingParty,
		AssigneeParty:       assigneeParty,
		ReviewerParty:       reviewerParty,
		AssigneeDID:         strings.TrimSpace(req.AssigneeDID),
		ReviewerDID:         strings.TrimSpace(req.ReviewerDID),
		RelatedReportIDs:    append([]string(nil), uniqueTrimmedStrings(req.RelatedReportIDs)...),
		RelatedAmendmentIDs: append([]string(nil), uniqueTrimmedStrings(req.RelatedAmendmentIDs)...),
		EvidenceIDs:         append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		DueAt:               cloneTimePtr(&dueAt),
		CreatedBy:           actorDID,
		CreatedAt:           now,
		UpdatedAt:           now,
		Metadata:            cloneStringMap(req.Metadata),
	}
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives = append(run.result.FederationIncidentResponses[responseIdx].IncidentDirectives, directive)
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_issued", directive.ID),
		Action:           "secure_cell.federation_incident_directive_issued",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive",
		TargetDID:        directive.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":              response.ID,
			"federation_organization_id":                   response.OrganizationID,
			"federation_sponsor_of_record":                 response.SponsorOfRecord,
			"federation_incident_id":                       response.IncidentID,
			"federation_incident_directive_id":             directive.ID,
			"federation_incident_directive_type":           directive.DirectiveType,
			"federation_incident_directive_title":          directive.Title,
			"federation_incident_directive_priority":       string(directive.Priority),
			"federation_incident_directive_status_before":  "",
			"federation_incident_directive_status_after":   string(directive.Status),
			"federation_incident_directive_issuing_party":  string(directive.IssuingParty),
			"federation_incident_directive_assignee_party": string(directive.AssigneeParty),
			"federation_incident_directive_reviewer_party": string(directive.ReviewerParty),
			"federation_incident_directive_assignee_did":   directive.AssigneeDID,
			"federation_incident_directive_reviewer_did":   directive.ReviewerDID,
			"federation_incident_directive_due_at":         dueAt.Format(time.RFC3339Nano),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AcknowledgeFederationIncidentDirective(ctx context.Context, cellID string, directiveID string, req SecureCellFederationIncidentDirectiveAcknowledgeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: %q", ErrFederationIncidentDirectiveNotFound, directiveID)
	}
	if directive.Status != SecureCellFederationIncidentDirectiveStatusIssued {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: directive %q is not awaiting acknowledgement", ErrFederationIncidentDirectiveImmutable, directiveID)
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.AcknowledgingParty)
	if party == "" {
		party = directive.AssigneeParty
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: actor %q is not permitted to acknowledge directive %q", ErrPolicyDenied, actorDID, directiveID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_directive", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":         response.ID,
		"federation_organization_id":              response.OrganizationID,
		"federation_sponsor_of_record":            response.SponsorOfRecord,
		"federation_incident_id":                  response.IncidentID,
		"federation_incident_directive_id":        directive.ID,
		"federation_incident_directive_status":    string(directive.Status),
		"federation_incident_directive_assignee":  string(directive.AssigneeParty),
		"federation_incident_directive_ack_party": string(party),
		"transition_reason":                       firstNonEmpty(strings.TrimSpace(req.Reason), directive.Summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	before := updated.Status
	updated.Status = SecureCellFederationIncidentDirectiveStatusAcknowledged
	updated.AcknowledgementReceiptID = receipt.ID
	updated.AcknowledgementReceiptHash = receipt.ContentHash
	updated.AcknowledgedBy = actorDID
	updated.AcknowledgedAt = cloneTimePtr(&now)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_acknowledged", updated.ID),
		Action:           "secure_cell.federation_incident_directive_acknowledged",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive",
		TargetDID:        updated.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), updated.Summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":              response.ID,
			"federation_organization_id":                   response.OrganizationID,
			"federation_sponsor_of_record":                 response.SponsorOfRecord,
			"federation_incident_id":                       response.IncidentID,
			"federation_incident_directive_id":             updated.ID,
			"federation_incident_directive_title":          updated.Title,
			"federation_incident_directive_priority":       string(updated.Priority),
			"federation_incident_directive_status_before":  string(before),
			"federation_incident_directive_status_after":   string(updated.Status),
			"federation_incident_directive_assignee_party": string(updated.AssigneeParty),
			"federation_incident_directive_reviewer_party": string(updated.ReviewerParty),
			"federation_incident_directive_due_at":         secureCellFormatTime(updated.DueAt),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) CompleteFederationIncidentDirective(ctx context.Context, cellID string, directiveID string, req SecureCellFederationIncidentDirectiveCompleteRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: %q", ErrFederationIncidentDirectiveNotFound, directiveID)
	}
	if directive.Status != SecureCellFederationIncidentDirectiveStatusAcknowledged {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: directive %q must be acknowledged before completion", ErrFederationIncidentDirectiveImmutable, directiveID)
	}
	summary := strings.TrimSpace(req.CompletionSummary)
	if summary == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive: completion_summary is required")
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.CompletingParty)
	if party == "" {
		party = directive.AssigneeParty
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: actor %q is not permitted to complete directive %q", ErrPolicyDenied, actorDID, directiveID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "complete_federation_incident_directive", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":        response.ID,
		"federation_organization_id":             response.OrganizationID,
		"federation_sponsor_of_record":           response.SponsorOfRecord,
		"federation_incident_id":                 response.IncidentID,
		"federation_incident_directive_id":       directive.ID,
		"federation_incident_directive_status":   string(directive.Status),
		"federation_incident_directive_assignee": string(directive.AssigneeParty),
		"federation_incident_directive_due_at":   secureCellFormatTime(directive.DueAt),
		"transition_reason":                      firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	before := updated.Status
	updated.Status = SecureCellFederationIncidentDirectiveStatusCompleted
	updated.CompletionReceiptID = receipt.ID
	updated.CompletionReceiptHash = receipt.ContentHash
	updated.CompletionSummary = summary
	updated.CompletionDescription = strings.TrimSpace(req.CompletionDescription)
	updated.CompletionEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
	updated.CompletedBy = actorDID
	updated.CompletedAt = cloneTimePtr(&now)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_completed", updated.ID),
		Action:           "secure_cell.federation_incident_directive_completed",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive",
		TargetDID:        updated.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":              response.ID,
			"federation_organization_id":                   response.OrganizationID,
			"federation_sponsor_of_record":                 response.SponsorOfRecord,
			"federation_incident_id":                       response.IncidentID,
			"federation_incident_directive_id":             updated.ID,
			"federation_incident_directive_title":          updated.Title,
			"federation_incident_directive_priority":       string(updated.Priority),
			"federation_incident_directive_status_before":  string(before),
			"federation_incident_directive_status_after":   string(updated.Status),
			"federation_incident_directive_assignee_party": string(updated.AssigneeParty),
			"federation_incident_directive_reviewer_party": string(updated.ReviewerParty),
			"federation_incident_directive_due_at":         secureCellFormatTime(updated.DueAt),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) VerifyFederationIncidentDirective(ctx context.Context, cellID string, directiveID string, req SecureCellFederationIncidentDirectiveVerifyRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
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
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: %q", ErrFederationIncidentDirectiveNotFound, directiveID)
	}
	if directive.Status != SecureCellFederationIncidentDirectiveStatusCompleted {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: directive %q must be completed before verification", ErrFederationIncidentDirectiveImmutable, directiveID)
	}
	decision := secureCellNormalizedFederationIncidentDirectiveVerificationDecision(req.Decision)
	if decision == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive: verification decision is required")
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.ReviewingParty)
	if party == "" {
		party = directive.ReviewerParty
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: actor %q is not permitted to verify directive %q", ErrPolicyDenied, actorDID, directiveID)
	}
	summary := strings.TrimSpace(req.VerificationSummary)
	if summary == "" {
		summary = strings.TrimSpace(directive.Summary)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "verify_federation_incident_directive", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":            response.ID,
		"federation_organization_id":                 response.OrganizationID,
		"federation_sponsor_of_record":               response.SponsorOfRecord,
		"federation_incident_id":                     response.IncidentID,
		"federation_incident_directive_id":           directive.ID,
		"federation_incident_directive_status":       string(directive.Status),
		"federation_incident_directive_verification": string(decision),
		"federation_incident_directive_reviewer":     string(party),
		"transition_reason":                          firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	updated := run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx]
	before := updated.Status
	updated.VerificationDecision = decision
	updated.VerificationReceiptID = receipt.ID
	updated.VerificationReceiptHash = receipt.ContentHash
	updated.VerificationSummary = summary
	updated.VerificationDescription = strings.TrimSpace(req.VerificationDescription)
	updated.VerificationEvidenceIDs = append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...)
	updated.VerifiedBy = actorDID
	updated.VerifiedAt = cloneTimePtr(&now)
	updated.UpdatedAt = now
	updated.Metadata = mergeStringMaps(updated.Metadata, req.Metadata)
	if decision == SecureCellFederationIncidentDirectiveVerificationDecisionAccepted {
		updated.Status = SecureCellFederationIncidentDirectiveStatusVerified
	} else {
		updated.Status = SecureCellFederationIncidentDirectiveStatusAcknowledged
	}
	run.result.FederationIncidentResponses[responseIdx].IncidentDirectives[directiveIdx] = updated
	run.result.FederationIncidentResponses[responseIdx].UpdatedAt = now
	run.result.FederationIncidentResponses[responseIdx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[responseIdx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_verified", updated.ID),
		Action:           "secure_cell.federation_incident_directive_verified",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive",
		TargetDID:        updated.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":              response.ID,
			"federation_organization_id":                   response.OrganizationID,
			"federation_sponsor_of_record":                 response.SponsorOfRecord,
			"federation_incident_id":                       response.IncidentID,
			"federation_incident_directive_id":             updated.ID,
			"federation_incident_directive_title":          updated.Title,
			"federation_incident_directive_priority":       string(updated.Priority),
			"federation_incident_directive_status_before":  string(before),
			"federation_incident_directive_status_after":   string(updated.Status),
			"federation_incident_directive_verification":   string(updated.VerificationDecision),
			"federation_incident_directive_assignee_party": string(updated.AssigneeParty),
			"federation_incident_directive_reviewer_party": string(updated.ReviewerParty),
			"federation_incident_directive_due_at":         secureCellFormatTime(updated.DueAt),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) GetFederationIncidentDirective(_ context.Context, cellID string, directiveID string) (*SecureCellFederationIncidentDirective, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	_, _, _, directive := findSecureCellFederationIncidentDirective(run.result.FederationIncidentResponses, directiveID)
	if directive == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: %w: %q", ErrFederationIncidentDirectiveNotFound, directiveID)
	}
	cloned := *directive
	cloned.RelatedReportIDs = append([]string(nil), directive.RelatedReportIDs...)
	cloned.RelatedAmendmentIDs = append([]string(nil), directive.RelatedAmendmentIDs...)
	cloned.EvidenceIDs = append([]string(nil), directive.EvidenceIDs...)
	cloned.CompletionEvidenceIDs = append([]string(nil), directive.CompletionEvidenceIDs...)
	cloned.VerificationEvidenceIDs = append([]string(nil), directive.VerificationEvidenceIDs...)
	cloned.Metadata = cloneStringMap(directive.Metadata)
	cloned.DueAt = cloneTimePtr(directive.DueAt)
	cloned.AcknowledgedAt = cloneTimePtr(directive.AcknowledgedAt)
	cloned.CompletedAt = cloneTimePtr(directive.CompletedAt)
	cloned.VerifiedAt = cloneTimePtr(directive.VerifiedAt)
	return &cloned, nil
}

func (s *Service) ListFederationIncidentDirectives(_ context.Context, filter SecureCellFederationIncidentDirectiveFilter) ([]SecureCellFederationIncidentDirectiveSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveSummary, 0)
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
				summary := secureCellFederationIncidentDirectiveSummaryFromRun(run, response, directive)
				if !matchesSecureCellFederationIncidentDirectiveFilter(summary, filter) {
					continue
				}
				items = append(items, summary)
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

func (s *Service) ListOverdueFederationIncidentDirectives(_ context.Context, filter SecureCellOverdueFederationIncidentDirectiveFilter) ([]SecureCellOverdueFederationIncidentDirective, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentDirective, 0)
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
				item, ok := secureCellOverdueFederationIncidentDirectiveFromRun(run, response, directive, at)
				if !ok {
					continue
				}
				if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
					continue
				}
				items = append(items, item)
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			return items[i].DirectiveID > items[j].DirectiveID
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentDirectiveActions(_ context.Context, filter SecureCellFederationIncidentDirectiveActionFilter) ([]SecureCellFederationIncidentDirectiveActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].TransitionID > items[j].TransitionID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func findSecureCellFederationIncidentDirective(responses []SecureCellFederationIncidentResponse, directiveID string) (int, int, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentDirective) {
	directiveID = strings.TrimSpace(directiveID)
	for responseIdx := range responses {
		for directiveIdx := range responses[responseIdx].IncidentDirectives {
			if strings.TrimSpace(responses[responseIdx].IncidentDirectives[directiveIdx].ID) != directiveID {
				continue
			}
			return responseIdx, directiveIdx, &responses[responseIdx], &responses[responseIdx].IncidentDirectives[directiveIdx]
		}
	}
	return -1, -1, nil, nil
}

func secureCellFederationIncidentDirectiveID(response SecureCellFederationIncidentResponse, actorDID string, createdAt time.Time, ordinal int) string {
	return fmt.Sprintf("%s-directive-%s-%s-%02d",
		strings.TrimSpace(response.ID),
		strings.ToLower(strings.TrimSpace(string(secureCellFederationIncidentDirectiveActorPartyForID(actorDID, response.OrganizationID)))),
		createdAt.UTC().Format("20060102150405"),
		ordinal+1,
	)
}

func secureCellFederationIncidentDirectiveActorParty(run *secureCellRun, response SecureCellFederationIncidentResponse, actorDID string) SecureCellFederationIncidentResponseParty {
	actorDID = strings.TrimSpace(actorDID)
	if secureCellFederationIncidentResponsePartyAllowed(run, response, actorDID, SecureCellFederationIncidentResponsePartyLocalOrg) {
		return SecureCellFederationIncidentResponsePartyLocalOrg
	}
	if secureCellFederationIncidentResponsePartyAllowed(run, response, actorDID, SecureCellFederationIncidentResponsePartyCounterpartyOrg) {
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	}
	return ""
}

func secureCellFederationIncidentDirectiveActorPartyForID(actorDID string, organizationID string) SecureCellFederationIncidentResponseParty {
	if strings.Contains(strings.ToLower(strings.TrimSpace(actorDID)), "counterparty") || strings.Contains(strings.ToLower(strings.TrimSpace(actorDID)), strings.ToLower(strings.TrimSpace(organizationID))) {
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	}
	return SecureCellFederationIncidentResponsePartyLocalOrg
}

func secureCellFederationIncidentDirectiveDefaultAssigneeParty(response SecureCellFederationIncidentResponse) SecureCellFederationIncidentResponseParty {
	if party := secureCellNormalizedFederationIncidentResponseParty(response.ExpectedRemediationFrom); party != "" {
		return party
	}
	if party := secureCellNormalizedFederationIncidentResponseParty(response.RequiredAcknowledgement); party != "" {
		return party
	}
	return SecureCellFederationIncidentResponsePartyCounterpartyOrg
}

func secureCellFederationIncidentDirectiveOppositeParty(party SecureCellFederationIncidentResponseParty) SecureCellFederationIncidentResponseParty {
	switch secureCellNormalizedFederationIncidentResponseParty(party) {
	case SecureCellFederationIncidentResponsePartyLocalOrg:
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
		return SecureCellFederationIncidentResponsePartyLocalOrg
	default:
		return ""
	}
}

func secureCellNormalizedFederationIncidentDirectivePriority(value SecureCellFederationIncidentDirectivePriority) SecureCellFederationIncidentDirectivePriority {
	switch SecureCellFederationIncidentDirectivePriority(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentDirectivePriorityLow:
		return SecureCellFederationIncidentDirectivePriorityLow
	case SecureCellFederationIncidentDirectivePriorityMedium:
		return SecureCellFederationIncidentDirectivePriorityMedium
	case SecureCellFederationIncidentDirectivePriorityHigh:
		return SecureCellFederationIncidentDirectivePriorityHigh
	case SecureCellFederationIncidentDirectivePriorityCritical:
		return SecureCellFederationIncidentDirectivePriorityCritical
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveDefaultPriority(response SecureCellFederationIncidentResponse) SecureCellFederationIncidentDirectivePriority {
	switch response.IncidentSeverity {
	case SecureCellFederationIncidentSeverityCritical:
		return SecureCellFederationIncidentDirectivePriorityCritical
	case SecureCellFederationIncidentSeverityHigh:
		return SecureCellFederationIncidentDirectivePriorityHigh
	default:
		return SecureCellFederationIncidentDirectivePriorityMedium
	}
}

func secureCellNormalizedFederationIncidentDirectiveVerificationDecision(value SecureCellFederationIncidentDirectiveVerificationDecision) SecureCellFederationIncidentDirectiveVerificationDecision {
	switch SecureCellFederationIncidentDirectiveVerificationDecision(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentDirectiveVerificationDecisionAccepted:
		return SecureCellFederationIncidentDirectiveVerificationDecisionAccepted
	case SecureCellFederationIncidentDirectiveVerificationDecisionRejected:
		return SecureCellFederationIncidentDirectiveVerificationDecisionRejected
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectivePendingCount(directives []SecureCellFederationIncidentDirective) int {
	count := 0
	for _, directive := range directives {
		if directive.Status != SecureCellFederationIncidentDirectiveStatusVerified {
			count++
		}
	}
	return count
}

func secureCellFederationIncidentResponseDirectiveTotal(responses []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, response := range responses {
		total += len(response.IncidentDirectives)
	}
	return total
}

func secureCellFederationIncidentResponseDirectiveStatusTotal(responses []SecureCellFederationIncidentResponse, status SecureCellFederationIncidentDirectiveStatus) int {
	total := 0
	for _, response := range responses {
		for _, directive := range response.IncidentDirectives {
			if directive.Status == status {
				total++
			}
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveOverdueCount(directives []SecureCellFederationIncidentDirective, at time.Time) int {
	count := 0
	for _, directive := range directives {
		if secureCellFederationIncidentDirectiveIsOverdue(directive, at) {
			count++
		}
	}
	return count
}

func secureCellFederationIncidentDirectiveNextDueAt(directives []SecureCellFederationIncidentDirective, at time.Time) *time.Time {
	var next *time.Time
	for _, directive := range directives {
		if directive.Status == SecureCellFederationIncidentDirectiveStatusVerified || directive.DueAt == nil || directive.DueAt.IsZero() {
			continue
		}
		dueAt := directive.DueAt.UTC()
		if next == nil || dueAt.Before(*next) {
			next = &dueAt
		}
	}
	return next
}

func secureCellFederationIncidentDirectiveIsOverdue(directive SecureCellFederationIncidentDirective, at time.Time) bool {
	if directive.Status == SecureCellFederationIncidentDirectiveStatusVerified || directive.DueAt == nil || directive.DueAt.IsZero() {
		return false
	}
	return directive.DueAt.UTC().Before(at.UTC())
}

func secureCellFederationIncidentDirectivePendingAction(directive SecureCellFederationIncidentDirective) string {
	switch directive.Status {
	case SecureCellFederationIncidentDirectiveStatusIssued:
		return "acknowledge"
	case SecureCellFederationIncidentDirectiveStatusAcknowledged:
		return "complete"
	case SecureCellFederationIncidentDirectiveStatusCompleted:
		return "verify"
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, directive SecureCellFederationIncidentDirective) SecureCellFederationIncidentDirectiveSummary {
	return SecureCellFederationIncidentDirectiveSummary{
		CellID:               strings.TrimSpace(run.result.CellID),
		CellName:             strings.TrimSpace(run.result.Name),
		Jurisdiction:         strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:           run.result.Status,
		ResponseID:           strings.TrimSpace(response.ID),
		OrganizationID:       strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:      strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:           strings.TrimSpace(response.IncidentID),
		DirectiveID:          strings.TrimSpace(directive.ID),
		DirectiveType:        strings.TrimSpace(directive.DirectiveType),
		Title:                strings.TrimSpace(directive.Title),
		Summary:              strings.TrimSpace(directive.Summary),
		Description:          strings.TrimSpace(directive.Description),
		Priority:             directive.Priority,
		Status:               directive.Status,
		IssuingParty:         directive.IssuingParty,
		AssigneeParty:        directive.AssigneeParty,
		ReviewerParty:        directive.ReviewerParty,
		AssigneeDID:          strings.TrimSpace(directive.AssigneeDID),
		ReviewerDID:          strings.TrimSpace(directive.ReviewerDID),
		RelatedReportIDs:     append([]string(nil), directive.RelatedReportIDs...),
		RelatedAmendmentIDs:  append([]string(nil), directive.RelatedAmendmentIDs...),
		EvidenceIDs:          append([]string(nil), directive.EvidenceIDs...),
		DueAt:                cloneTimePtr(directive.DueAt),
		Overdue:              secureCellFederationIncidentDirectiveIsOverdue(directive, time.Now().UTC()),
		AcknowledgedBy:       strings.TrimSpace(directive.AcknowledgedBy),
		AcknowledgedAt:       cloneTimePtr(directive.AcknowledgedAt),
		CompletedBy:          strings.TrimSpace(directive.CompletedBy),
		CompletedAt:          cloneTimePtr(directive.CompletedAt),
		VerificationDecision: directive.VerificationDecision,
		VerifiedBy:           strings.TrimSpace(directive.VerifiedBy),
		VerifiedAt:           cloneTimePtr(directive.VerifiedAt),
		CreatedBy:            strings.TrimSpace(directive.CreatedBy),
		CreatedAt:            directive.CreatedAt.UTC(),
		UpdatedAt:            directive.UpdatedAt.UTC(),
		Metadata:             cloneStringMap(directive.Metadata),
	}
}

func secureCellOverdueFederationIncidentDirectiveFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, directive SecureCellFederationIncidentDirective, at time.Time) (SecureCellOverdueFederationIncidentDirective, bool) {
	if !secureCellFederationIncidentDirectiveIsOverdue(directive, at) || directive.DueAt == nil || directive.DueAt.IsZero() {
		return SecureCellOverdueFederationIncidentDirective{}, false
	}
	dueAt := directive.DueAt.UTC()
	return SecureCellOverdueFederationIncidentDirective{
		CellID:          strings.TrimSpace(run.result.CellID),
		CellName:        strings.TrimSpace(run.result.Name),
		Jurisdiction:    strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:      run.result.Status,
		ResponseID:      strings.TrimSpace(response.ID),
		OrganizationID:  strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord: strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:      strings.TrimSpace(response.IncidentID),
		DirectiveID:     strings.TrimSpace(directive.ID),
		Title:           strings.TrimSpace(directive.Title),
		Priority:        directive.Priority,
		Status:          directive.Status,
		AssigneeParty:   directive.AssigneeParty,
		ReviewerParty:   directive.ReviewerParty,
		PendingAction:   secureCellFederationIncidentDirectivePendingAction(directive),
		DueAt:           dueAt,
		OverdueSeconds:  int64(at.UTC().Sub(dueAt).Seconds()),
		UpdatedAt:       directive.UpdatedAt.UTC(),
	}, true
}

func secureCellFederationIncidentDirectiveActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveActionRecord, bool) {
	if strings.TrimSpace(transition.Metadata["federation_incident_directive_id"]) == "" {
		return SecureCellFederationIncidentDirectiveActionRecord{}, false
	}
	return SecureCellFederationIncidentDirectiveActionRecord{
		CellID:          strings.TrimSpace(run.result.CellID),
		CellName:        strings.TrimSpace(run.result.Name),
		Jurisdiction:    strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:      run.result.Status,
		OrganizationID:  strings.TrimSpace(transition.Metadata["federation_organization_id"]),
		SponsorOfRecord: strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
		IncidentID:      strings.TrimSpace(transition.Metadata["federation_incident_id"]),
		ResponseID:      strings.TrimSpace(transition.Metadata["federation_incident_response_id"]),
		DirectiveID:     strings.TrimSpace(transition.Metadata["federation_incident_directive_id"]),
		StatusBefore:    SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_status_before"])),
		StatusAfter:     SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_status_after"])),
		Action:          transition.Action,
		Actor:           transition.Actor,
		Reason:          strings.TrimSpace(transition.Reason),
		TransitionID:    strings.TrimSpace(transition.ID),
		OccurredAt:      transition.OccurredAt.UTC(),
		Metadata:        cloneStringMap(transition.Metadata),
	}, true
}

func matchesSecureCellFederationIncidentDirectiveFilter(item SecureCellFederationIncidentDirectiveSummary, filter SecureCellFederationIncidentDirectiveFilter) bool {
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.AssigneeParty != "" && item.AssigneeParty != filter.AssigneeParty {
		return false
	}
	if filter.ReviewerParty != "" && item.ReviewerParty != filter.ReviewerParty {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.Priority != "" && item.Priority != filter.Priority {
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

func matchesSecureCellFederationIncidentDirectiveActionFilter(item SecureCellFederationIncidentDirectiveActionRecord, filter SecureCellFederationIncidentDirectiveActionFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseID), strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.Action != "" && !strings.EqualFold(strings.TrimSpace(item.Action), strings.TrimSpace(filter.Action)) {
		return false
	}
	if filter.Since != nil && item.OccurredAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && item.OccurredAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFormatTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
