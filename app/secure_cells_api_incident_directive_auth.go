package app

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/aethelred/aethelred/pkg/audit"
)

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveIssue(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveCreateRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveComplete(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveCompleteRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveVerify(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveVerifyRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionRequest(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionApprove(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionApproveRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionReject(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionRejectRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDispute(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDisputeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionResolve(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDisputeResolveRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDelegateReview(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDelegateResolution(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppeal(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRule(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealRulingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealDelegateReview(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRecuse(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealRecuseRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRehear(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealRehearingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationDispute(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolve(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationRule(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseIntake(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRule(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDelegateReview(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuse(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehear(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledge(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeCounterparty(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDisputeCounterparty(r *http.Request, _ string, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealIntake(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalate(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r *http.Request, _ string, _ string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest) (*secureCellAuthContext, error) {
	if req == nil {
		return a.AuthorizeCreate(r, nil)
	}
	return a.authorizeWithOptionalActor(r, req.ActorIdentity)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveIssue(r *http.Request, cellID string, responseID string, req *secureCellFederationIncidentDirectiveCreateRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveIssue(r, cellID, responseID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveAcknowledge(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveAcknowledgeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveAcknowledge(r, cellID, directiveID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveComplete(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveCompleteRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveComplete(r, cellID, directiveID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveVerify(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveVerifyRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveVerify(r, cellID, directiveID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionRequest(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveExtensionRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionRequest(r, cellID, directiveID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionApprove(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionApproveRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionApprove(r, cellID, extensionID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionReject(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionRejectRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionReject(r, cellID, extensionID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDispute(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionDisputeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionDispute(r, cellID, extensionID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionResolve(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionDisputeResolveRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionResolve(r, cellID, disputeID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDelegateReview(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionDelegateReview(r, cellID, extensionID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDelegateResolution(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionDelegateResolution(r, cellID, disputeID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppeal(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionAppealRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppeal(r, cellID, disputeID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRule(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRulingRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealRule(r, cellID, appealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealDelegateReview(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealDelegateReview(r, cellID, appealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRecuse(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRecuseRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealRecuse(r, cellID, appealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRehear(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRehearingRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealRehear(r, cellID, appealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealAcknowledge(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealAcknowledge(r, cellID, appealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationDispute(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationDispute(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolve(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolve(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationRule(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationRule(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r, cellID, challengeAppealID, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest) (*secureCellAuthContext, error) {
	for _, strategy := range a.strategies {
		return strategy.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r, cellID, comparisonKey, req)
	}
	return nil, fmt.Errorf("securecells/auth: %w: no request authorizer is configured", audit.ErrWriteDisabled)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveIssue(r *http.Request, cellID string, responseID string, req *secureCellFederationIncidentDirectiveCreateRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(responseID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and response ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveIssueAction,
		resourceCandidatesForSecureCellFederationIncidentResponseAction(cellID, responseID, "directives"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveAcknowledge(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(directiveID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and directive ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveAction(cellID, directiveID, "acknowledge"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveComplete(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveCompleteRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(directiveID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and directive ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive complete request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveCompleteAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveAction(cellID, directiveID, "complete"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveVerify(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveVerifyRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(directiveID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and directive ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive verify request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveVerifyAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveAction(cellID, directiveID, "verify"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionRequest(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveExtensionRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(directiveID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and directive ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionRequestAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveAction(cellID, directiveID, "extensions"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionApprove(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionApproveRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(extensionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and extension ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension approve request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionApproveAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAction(cellID, extensionID, "approve"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionReject(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionRejectRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(extensionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and extension ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension reject request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionRejectAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAction(cellID, extensionID, "reject"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDispute(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionDisputeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(extensionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and extension ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension dispute request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionDisputeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAction(cellID, extensionID, "dispute"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionResolve(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionDisputeResolveRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(disputeID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and dispute ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension dispute resolve request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionResolveAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionDisputeAction(cellID, disputeID, "resolve"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDelegateReview(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(extensionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and extension ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension review delegation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionDelegateReviewAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAction(cellID, extensionID, "delegate-review"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionDelegateResolution(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(disputeID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and dispute ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension dispute delegation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionDelegateResolutionAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionDisputeAction(cellID, disputeID, "delegate-resolution"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppeal(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionAppealRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(disputeID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and dispute ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionDisputeAction(cellID, disputeID, "appeal"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRule(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRulingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(appealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal ruling request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealRuleAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealAction(cellID, appealID, "rule"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealDelegateReview(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(appealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal delegation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealDelegateReviewAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealAction(cellID, appealID, "delegate-review"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRecuse(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRecuseRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(appealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal recusal request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealRecuseAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealAction(cellID, appealID, "recuse"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealRehear(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRehearingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(appealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal rehearing request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealRehearAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealAction(cellID, appealID, "rehear"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealAcknowledge(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(appealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal acknowledgement request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealAction(cellID, appealID, "acknowledge-enforcement"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "acknowledge"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationDispute(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation dispute request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationDisputeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "dispute"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolve(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation resolve request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationResolveAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "resolve"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "challenge"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationRule(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation rule request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationRuleAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "rule"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "appeal"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal rule request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRuleAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "rule"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal delegation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReviewAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "delegate-review"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal recuse request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "recuse"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal rehearing request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "rehear"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "acknowledge-enforcement"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "acknowledge-alignment"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment dispute request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "dispute-alignment"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment automation acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "acknowledge-alignment-automation"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDispute(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment automation dispute request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "dispute-alignment-automation"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttest(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment correction attestation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "attest-alignment-correction"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttest(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment resolution attestation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(cellID, challengeAppealID, "attest-alignment-resolution"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and challenge appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, "", "open"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRule(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal ruling request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRuleAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "rule"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDelegateReview(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal delegation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDelegateReviewAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "delegate-review"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuse(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal recuse request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "recuse"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehear(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal rehearing request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "rehear"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseIntake(r *http.Request, cellID string, organizationID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and organization ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response bundle intake request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseIntakeAction,
		resourceCandidatesForSecureCellFederationOrganizationAction(cellID, organizationID, "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundles/intake"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledge(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "acknowledge-enforcement"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeCounterparty(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeCounterpartyAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "acknowledge-counterparty-ruling"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDisputeCounterparty(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(challengeAppealID) == "" || strings.TrimSpace(responseAppealID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID, challenge appeal ID, and response appeal ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty dispute request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDisputeCounterpartyAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAction(cellID, challengeAppealID, responseAppealID, "dispute-counterparty-ruling"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealIntake(r *http.Request, cellID string, organizationID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and organization ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal bundle intake request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealIntakeAction,
		resourceCandidatesForSecureCellFederationOrganizationAction(cellID, organizationID, "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundles/intake"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledge(r *http.Request, cellID string, snapshotID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(snapshotID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and snapshot ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAction(cellID, snapshotID, "acknowledge-counterparty-ruling"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(r *http.Request, cellID string, snapshotID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(snapshotID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and snapshot ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal dispute request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAction(cellID, snapshotID, "dispute-counterparty-ruling"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalate(r *http.Request, cellID string, snapshotID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(snapshotID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and snapshot ID are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal dispute escalation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalateAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAction(cellID, snapshotID, "escalate-counterparty-dispute"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation counterparty acknowledge request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "acknowledge-dispute"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation correction attestation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "attest-correction"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(comparisonKey) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID and comparison key are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell federation incident directive extension appeal reconciliation resolution attestation request is required", audit.ErrInvalidInput)
	}
	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		secureCellsAuthFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestAction,
		resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAction(cellID, comparisonKey, "attest-resolution"),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveIssue(r *http.Request, cellID string, responseID string, req *secureCellFederationIncidentDirectiveCreateRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveIssue(r, cellID, responseID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveAcknowledge(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveAcknowledge(r, cellID, directiveID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveComplete(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveCompleteRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveComplete(r, cellID, directiveID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveVerify(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveVerifyRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveVerify(r, cellID, directiveID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionRequest(r *http.Request, cellID string, directiveID string, req *secureCellFederationIncidentDirectiveExtensionRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionRequest(r, cellID, directiveID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionApprove(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionApproveRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionApprove(r, cellID, extensionID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionReject(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionRejectRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionReject(r, cellID, extensionID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionDispute(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionDisputeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionDispute(r, cellID, extensionID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionResolve(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionDisputeResolveRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionResolve(r, cellID, disputeID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionDelegateReview(r *http.Request, cellID string, extensionID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionDelegateReview(r, cellID, extensionID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionDelegateResolution(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionDelegateResolution(r, cellID, disputeID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppeal(r *http.Request, cellID string, disputeID string, req *secureCellFederationIncidentDirectiveExtensionAppealRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppeal(r, cellID, disputeID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealRule(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRulingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealRule(r, cellID, appealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealDelegateReview(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealDelegateReview(r, cellID, appealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealRecuse(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRecuseRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealRecuse(r, cellID, appealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealRehear(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealRehearingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealRehear(r, cellID, appealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealAcknowledge(r *http.Request, cellID string, appealID string, req *secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealAcknowledge(r, cellID, appealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationDispute(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationDispute(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolve(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolve(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationRule(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationRule(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledge(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledge(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDispute(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDispute(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttest(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttest(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttest(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttest(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseIntake(r *http.Request, cellID string, organizationID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseIntake(r, cellID, organizationID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r *http.Request, cellID string, challengeAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r, cellID, challengeAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRule(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRule(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDelegateReview(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionDelegationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDelegateReview(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuse(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuse(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehear(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehear(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledge(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledge(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeCounterparty(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeCounterparty(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDisputeCounterparty(r *http.Request, cellID string, challengeAppealID string, responseAppealID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDisputeCounterparty(r, cellID, challengeAppealID, responseAppealID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealIntake(r *http.Request, cellID string, organizationID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealIntake(r, cellID, organizationID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledge(r *http.Request, cellID string, snapshotID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledge(r, cellID, snapshotID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(r *http.Request, cellID string, snapshotID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(r, cellID, snapshotID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalate(r *http.Request, cellID string, snapshotID string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalate(r, cellID, snapshotID, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r, cellID, comparisonKey, req)
}

func (app *AethelredApp) authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r *http.Request, cellID string, comparisonKey string, req *secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell authorizer is not configured", audit.ErrWriteDisabled)
	}
	return app.secureCellAuth.AuthorizeFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r, cellID, comparisonKey, req)
}

func resourceCandidatesForSecureCellFederationIncidentDirectiveAction(cellID, directiveID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	directiveID = strings.TrimSpace(directiveID)
	action = strings.TrimSpace(action)
	candidates := []string{
		cellID,
		"secure-cell:" + cellID,
		"federation-incident-directive:" + directiveID,
		directiveID,
	}
	if directiveID != "" {
		candidates = append(candidates, secureCellsItemPrefix+cellID+"/federation/incident-directives/"+directiveID)
	}
	if directiveID != "" && action != "" {
		candidates = append(candidates,
			secureCellsItemPrefix+cellID+"/federation/incident-directives/"+directiveID+"/"+action,
			"secure-cell:"+cellID+":federation:incident-directive:"+directiveID+":"+action,
		)
	}
	return candidates
}

func resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAction(cellID, extensionID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	extensionID = strings.TrimSpace(extensionID)
	action = strings.TrimSpace(action)
	candidates := []string{
		cellID,
		"secure-cell:" + cellID,
		"federation-incident-directive-extension:" + extensionID,
		extensionID,
	}
	if extensionID != "" {
		candidates = append(candidates, secureCellsItemPrefix+cellID+"/federation/incident-directive-extensions/"+extensionID)
	}
	if extensionID != "" && action != "" {
		candidates = append(candidates,
			secureCellsItemPrefix+cellID+"/federation/incident-directive-extensions/"+extensionID+"/"+action,
			"secure-cell:"+cellID+":federation:incident-directive-extension:"+extensionID+":"+action,
		)
	}
	return candidates
}

func resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionDisputeAction(cellID, disputeID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	disputeID = strings.TrimSpace(disputeID)
	action = strings.TrimSpace(action)
	candidates := []string{
		cellID,
		"secure-cell:" + cellID,
		"federation-incident-directive-extension-dispute:" + disputeID,
		disputeID,
	}
	if disputeID != "" {
		candidates = append(candidates, secureCellsItemPrefix+cellID+"/federation/incident-directive-extension-disputes/"+disputeID)
	}
	if disputeID != "" && action != "" {
		candidates = append(candidates,
			secureCellsItemPrefix+cellID+"/federation/incident-directive-extension-disputes/"+disputeID+"/"+action,
			"secure-cell:"+cellID+":federation:incident-directive-extension-dispute:"+disputeID+":"+action,
		)
	}
	return candidates
}

func resourceCandidatesForSecureCellFederationIncidentDirectiveExtensionAppealAction(cellID, appealID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	appealID = strings.TrimSpace(appealID)
	action = strings.TrimSpace(action)
	candidates := []string{
		cellID,
		"secure-cell:" + cellID,
		"federation-incident-directive-extension-appeal:" + appealID,
		appealID,
	}
	if appealID != "" {
		candidates = append(candidates, secureCellsItemPrefix+cellID+"/federation/incident-directive-extension-appeals/"+appealID)
	}
	if appealID != "" && action != "" {
		candidates = append(candidates,
			secureCellsItemPrefix+cellID+"/federation/incident-directive-extension-appeals/"+appealID+"/"+action,
			"secure-cell:"+cellID+":federation:incident-directive-extension-appeal:"+appealID+":"+action,
		)
	}
	return candidates
}
