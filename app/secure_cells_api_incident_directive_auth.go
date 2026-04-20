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
