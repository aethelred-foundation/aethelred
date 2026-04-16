package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

const (
	secureCellsAuthDefaultResource               = "cell:regulated-collaboration"
	secureCellsAuthRequestAction                 = "secure_cells.create"
	secureCellsAuthSessionStartAction            = "secure_cells.session.start"
	secureCellsAuthSessionThreadStartAction      = "secure_cells.session.thread.start"
	secureCellsAuthSessionShareAction            = "secure_cells.session.share"
	secureCellsAuthSessionExchangeAction         = "secure_cells.session.exchange"
	secureCellsAuthSessionThreadMessageAction    = "secure_cells.session.thread.message"
	secureCellsAuthSessionCloseAction            = "secure_cells.session.close"
	secureCellsAuthSessionPauseAction            = "secure_cells.session.pause"
	secureCellsAuthSessionResumeAction           = "secure_cells.session.resume"
	secureCellsAuthSessionQuarantineAction       = "secure_cells.session.quarantine"
	secureCellsAuthSessionThreadCloseAction      = "secure_cells.session.thread.close"
	secureCellsAuthSessionThreadResumeAction     = "secure_cells.session.thread.resume"
	secureCellsAuthSessionThreadQuarantineAction = "secure_cells.session.thread.quarantine"
	secureCellsAuthSessionMemberAdmitAction      = "secure_cells.session.member.admit"
	secureCellsAuthSessionMemberRemoveAction     = "secure_cells.session.member.remove"
	secureCellsAuthAdmitAction                   = "secure_cells.member.admit"
	secureCellsAuthReleaseAction                 = "secure_cells.member.release"
	secureCellsAuthQuarantineAction              = "secure_cells.member.quarantine"
	secureCellsAuthRevokeAction                  = "secure_cells.member.revoke"
	secureCellsAuthExpireAction                  = "secure_cells.quarantine.expire"
	secureCellsAuthPauseAction                   = "secure_cells.pause"
	secureCellsAuthResumeAction                  = "secure_cells.resume"
	secureCellsAuthTerminateAction               = "secure_cells.terminate"
	secureCellsAuthRequiredTool                  = "secure_cells"
	secureCellsEnterpriseActionModeBase          = "enterprise_policy_receipt"
)

type secureCellAuthContext struct {
	Mode                   string
	ActorIdentity          *agent.AgentIdentity
	PolicyReceipt          *policy.SignedPolicyReceipt
	ActorDID               string
	PolicyReceiptID        string
	PolicySigner           string
	RequiredAction         string
	RequiredJurisdiction   string
	SponsorOfRecord        string
	TrustSource            string
	TrustProvider          string
	TrustRegistryVersion   string
	TrustRegistryUpdatedAt string
	PolicySignerStatus     string
	SponsorStatus          string
}

type secureCellRequestAuthorizer interface {
	AuthorizeCreate(r *http.Request, req *secureCellCreateRequest) (*secureCellAuthContext, error)
	AuthorizeStart(r *http.Request, cellID string, req *secureCellSessionStartRequest) (*secureCellAuthContext, error)
	AuthorizeThreadStart(r *http.Request, cellID string, sessionID string, req *secureCellSessionThreadStartRequest) (*secureCellAuthContext, error)
	AuthorizeShare(r *http.Request, cellID string, sessionID string, req *secureCellSessionShareRequest) (*secureCellAuthContext, error)
	AuthorizeExchange(r *http.Request, cellID string, sessionID string, req *secureCellSessionExchangeRequest) (*secureCellAuthContext, error)
	AuthorizeThreadMessage(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellThreadMessageRequest) (*secureCellAuthContext, error)
	AuthorizeClose(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeSessionPause(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeSessionResume(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeSessionQuarantine(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeThreadClose(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeThreadResume(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeThreadQuarantine(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeSessionMemberAdmit(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error)
	AuthorizeSessionMemberRemove(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error)
	AuthorizeAdmit(r *http.Request, cellID string, req *secureCellAdmitMemberRequest) (*secureCellAuthContext, error)
	AuthorizeRelease(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error)
	AuthorizeQuarantine(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error)
	AuthorizeRevoke(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error)
	AuthorizeExpire(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizePause(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeResume(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
	AuthorizeTerminate(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error)
}

type secureCellGenericRequestAuthorizer struct {
	requestAuthorizer audit.RequestAuthorizer
	mode              string
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeCreate(r *http.Request, _ *secureCellCreateRequest) (*secureCellAuthContext, error) {
	if a == nil || a.requestAuthorizer == nil {
		return nil, fmt.Errorf("securecells/auth: %w: request authorizer is not configured", audit.ErrWriteDisabled)
	}
	if err := a.requestAuthorizer.AuthorizeRequest(r); err != nil {
		return nil, err
	}
	return &secureCellAuthContext{Mode: strings.TrimSpace(a.mode)}, nil
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeAdmit(r *http.Request, _ string, _ *secureCellAdmitMemberRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeStart(r *http.Request, _ string, _ *secureCellSessionStartRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeThreadStart(r *http.Request, _ string, _ string, _ *secureCellSessionThreadStartRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeShare(r *http.Request, _ string, _ string, _ *secureCellSessionShareRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeExchange(r *http.Request, _ string, _ string, _ *secureCellSessionExchangeRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeThreadMessage(r *http.Request, _ string, _ string, _ string, _ *secureCellThreadMessageRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeClose(r *http.Request, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeSessionPause(r *http.Request, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeSessionResume(r *http.Request, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeSessionQuarantine(r *http.Request, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeThreadClose(r *http.Request, _ string, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeThreadResume(r *http.Request, _ string, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeThreadQuarantine(r *http.Request, _ string, _ string, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeSessionMemberAdmit(r *http.Request, _ string, _ string, _ *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeSessionMemberRemove(r *http.Request, _ string, _ string, _ *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeRelease(r *http.Request, _ string, _ *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeQuarantine(r *http.Request, _ string, _ *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeRevoke(r *http.Request, _ string, _ *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeExpire(r *http.Request, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizePause(r *http.Request, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeResume(r *http.Request, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

func (a *secureCellGenericRequestAuthorizer) AuthorizeTerminate(r *http.Request, _ string, _ *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.AuthorizeCreate(r, nil)
}

type secureCellAnyOfRequestAuthorizer struct {
	strategies []secureCellRequestAuthorizer
}

func newSecureCellAnyOfRequestAuthorizer(strategies ...secureCellRequestAuthorizer) *secureCellAnyOfRequestAuthorizer {
	filtered := make([]secureCellRequestAuthorizer, 0, len(strategies))
	for _, strategy := range strategies {
		if strategy != nil {
			filtered = append(filtered, strategy)
		}
	}
	return &secureCellAnyOfRequestAuthorizer{strategies: filtered}
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeCreate(r *http.Request, req *secureCellCreateRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeCreate(r, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeAdmit(r *http.Request, cellID string, req *secureCellAdmitMemberRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeAdmit(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeStart(r *http.Request, cellID string, req *secureCellSessionStartRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeStart(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeThreadStart(r *http.Request, cellID string, sessionID string, req *secureCellSessionThreadStartRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeThreadStart(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeShare(r *http.Request, cellID string, sessionID string, req *secureCellSessionShareRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeShare(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeExchange(r *http.Request, cellID string, sessionID string, req *secureCellSessionExchangeRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeExchange(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeThreadMessage(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellThreadMessageRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeThreadMessage(r, cellID, sessionID, threadID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeClose(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeClose(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeSessionPause(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeSessionPause(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeSessionResume(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeSessionResume(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeSessionQuarantine(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeSessionQuarantine(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeThreadClose(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeThreadClose(r, cellID, sessionID, threadID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeThreadResume(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeThreadResume(r, cellID, sessionID, threadID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeThreadQuarantine(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeThreadQuarantine(r, cellID, sessionID, threadID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeSessionMemberAdmit(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeSessionMemberAdmit(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeSessionMemberRemove(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeSessionMemberRemove(r, cellID, sessionID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeRelease(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeRelease(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeQuarantine(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeQuarantine(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeRevoke(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeRevoke(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeExpire(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeExpire(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizePause(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizePause(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeResume(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeResume(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) AuthorizeTerminate(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorize(func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error) {
		return strategy.AuthorizeTerminate(r, cellID, req)
	})
}

func (a *secureCellAnyOfRequestAuthorizer) authorize(fn func(strategy secureCellRequestAuthorizer) (*secureCellAuthContext, error)) (*secureCellAuthContext, error) {
	if a == nil || len(a.strategies) == 0 {
		return nil, fmt.Errorf("securecells/auth: %w: no authorization strategies configured", audit.ErrWriteDisabled)
	}

	var unauthorizedErr error
	var disabledErr error
	for _, strategy := range a.strategies {
		authCtx, err := fn(strategy)
		if err == nil {
			return authCtx, nil
		}
		switch {
		case errors.Is(err, audit.ErrUnauthorized):
			unauthorizedErr = err
		case errors.Is(err, audit.ErrWriteDisabled):
			disabledErr = err
		default:
			unauthorizedErr = err
		}
	}

	if unauthorizedErr != nil {
		return nil, unauthorizedErr
	}
	if disabledErr != nil {
		return nil, disabledErr
	}
	return nil, fmt.Errorf("securecells/auth: %w: authorization failed", audit.ErrUnauthorized)
}

type secureCellEnterpriseRequestAuthorizer struct {
	trustSource          audit.EnterpriseControlLedgerTrustSource
	requiredTool         string
	requiredAction       string
	requiredJurisdiction string
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeCreate(r *http.Request, req *secureCellCreateRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell request is required", audit.ErrInvalidInput)
	}

	actorIdentity, err := decodeFinanceAgentIdentity(req.Identity)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}

	resource := strings.TrimSpace(req.Resource)
	if resource == "" {
		resource = secureCellsAuthDefaultResource
	}
	jurisdiction := resolveSecureCellAuthJurisdiction(strings.TrimSpace(req.Jurisdiction), actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction))
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		req.PolicyReceipt,
		strings.TrimSpace(a.requiredAction),
		resourceCandidatesForSecureCellCreate(resource),
		jurisdiction,
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeAdmit(r *http.Request, cellID string, req *secureCellAdmitMemberRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID is required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell admission request is required", audit.ErrInvalidInput)
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
		secureCellsAuthAdmitAction,
		resourceCandidatesForSecureCellAdmit(cellID, participantIdentityDID(req.Participant.Identity)),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeStart(r *http.Request, cellID string, req *secureCellSessionStartRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMutation(r, cellID, "", req, secureCellsAuthSessionStartAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeThreadStart(r *http.Request, cellID string, sessionID string, req *secureCellSessionThreadStartRequest) (*secureCellAuthContext, error) {
	return a.authorizeThreadStart(r, cellID, sessionID, req, secureCellsAuthSessionThreadStartAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeShare(r *http.Request, cellID string, sessionID string, req *secureCellSessionShareRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell and session IDs are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell session share request is required", audit.ErrInvalidInput)
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
		secureCellsAuthSessionShareAction,
		resourceCandidatesForSecureCellSessionShare(cellID, sessionID),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeExchange(r *http.Request, cellID string, sessionID string, req *secureCellSessionExchangeRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell and session IDs are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell session exchange request is required", audit.ErrInvalidInput)
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
		secureCellsAuthSessionExchangeAction,
		resourceCandidatesForSecureCellSessionExchange(cellID, sessionID),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeThreadMessage(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellThreadMessageRequest) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(threadID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell, session, and thread IDs are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell thread message request is required", audit.ErrInvalidInput)
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
		secureCellsAuthSessionThreadMessageAction,
		resourceCandidatesForSecureCellSessionThreadMessage(cellID, sessionID, threadID),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeClose(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMutation(r, cellID, sessionID, req, secureCellsAuthSessionCloseAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeSessionPause(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMutation(r, cellID, sessionID, req, secureCellsAuthSessionPauseAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeSessionResume(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMutation(r, cellID, sessionID, req, secureCellsAuthSessionResumeAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeSessionQuarantine(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMutation(r, cellID, sessionID, req, secureCellsAuthSessionQuarantineAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeThreadClose(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeThreadLifecycleMutation(r, cellID, sessionID, threadID, req, secureCellsAuthSessionThreadCloseAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeThreadResume(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeThreadLifecycleMutation(r, cellID, sessionID, threadID, req, secureCellsAuthSessionThreadResumeAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeThreadQuarantine(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeThreadLifecycleMutation(r, cellID, sessionID, threadID, req, secureCellsAuthSessionThreadQuarantineAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeSessionMemberAdmit(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMemberMutation(r, cellID, sessionID, req, secureCellsAuthSessionMemberAdmitAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeSessionMemberRemove(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorizeSessionMemberMutation(r, cellID, sessionID, req, secureCellsAuthSessionMemberRemoveAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeRelease(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorizeMemberMutation(r, cellID, req, secureCellsAuthReleaseAction, resourceCandidatesForSecureCellMemberAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeQuarantine(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorizeMemberMutation(r, cellID, req, secureCellsAuthQuarantineAction, resourceCandidatesForSecureCellMemberAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeRevoke(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	return a.authorizeMemberMutation(r, cellID, req, secureCellsAuthRevokeAction, resourceCandidatesForSecureCellMemberAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeExpire(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeLifecycleMutation(r, cellID, req, secureCellsAuthExpireAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizePause(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeLifecycleMutation(r, cellID, req, secureCellsAuthPauseAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeResume(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeLifecycleMutation(r, cellID, req, secureCellsAuthResumeAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) AuthorizeTerminate(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	return a.authorizeLifecycleMutation(r, cellID, req, secureCellsAuthTerminateAction)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeMemberMutation(
	r *http.Request,
	cellID string,
	req *secureCellMemberMutationRequest,
	requiredAction string,
	resourceFn func(string, string, string) []string,
) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID is required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell member mutation request is required", audit.ErrInvalidInput)
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
		requiredAction,
		resourceFn(cellID, strings.TrimSpace(req.ParticipantDID), memberActionFromRequiredAction(requiredAction)),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeSessionMutation(
	r *http.Request,
	cellID string,
	sessionID string,
	req any,
	requiredAction string,
) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID is required", audit.ErrInvalidInput)
	}
	var (
		actorIdentity *agent.AgentIdentity
		receipt       *policy.SignedPolicyReceipt
		err           error
	)
	switch typed := req.(type) {
	case *secureCellSessionStartRequest:
		if typed == nil {
			return nil, fmt.Errorf("securecells/auth: %w: secure cell session start request is required", audit.ErrInvalidInput)
		}
		actorIdentity, err = decodeFinanceAgentIdentity(typed.ActorIdentity)
		receipt = typed.PolicyReceipt
	case *secureCellLifecycleRequest:
		if typed == nil {
			return nil, fmt.Errorf("securecells/auth: %w: secure cell session lifecycle request is required", audit.ErrInvalidInput)
		}
		actorIdentity, err = decodeFinanceAgentIdentity(typed.ActorIdentity)
		receipt = typed.PolicyReceipt
	default:
		return nil, fmt.Errorf("securecells/auth: %w: unsupported session request type", audit.ErrInvalidInput)
	}
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if receipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}
	resourceCandidates := resourceCandidatesForSecureCellSessionLifecycle(cellID, sessionID, sessionLifecycleActionFromRequiredAction(requiredAction))
	if requiredAction == secureCellsAuthSessionStartAction {
		resourceCandidates = resourceCandidatesForSecureCellSessionStart(cellID)
	}
	return a.authorizeEnterpriseMutation(
		requestContextOrBackground(r),
		actorIdentity,
		receipt,
		requiredAction,
		resourceCandidates,
		resolveSecureCellAuthJurisdiction("", actorIdentity, receipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeThreadStart(
	r *http.Request,
	cellID string,
	sessionID string,
	req *secureCellSessionThreadStartRequest,
	requiredAction string,
) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell and session IDs are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell session thread start request is required", audit.ErrInvalidInput)
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
		requiredAction,
		resourceCandidatesForSecureCellSessionThreadStart(cellID, sessionID),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeSessionMemberMutation(
	r *http.Request,
	cellID string,
	sessionID string,
	req *secureCellSessionMemberMutationRequest,
	requiredAction string,
) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell and session IDs are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell session member mutation request is required", audit.ErrInvalidInput)
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
		requiredAction,
		resourceCandidatesForSecureCellSessionMemberAction(cellID, sessionID, strings.TrimSpace(req.ParticipantDID), sessionMemberActionFromRequiredAction(requiredAction)),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeThreadLifecycleMutation(
	r *http.Request,
	cellID string,
	sessionID string,
	threadID string,
	req *secureCellLifecycleRequest,
	requiredAction string,
) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(threadID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell, session, and thread IDs are required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell thread lifecycle request is required", audit.ErrInvalidInput)
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
		requiredAction,
		resourceCandidatesForSecureCellSessionThreadLifecycle(cellID, sessionID, threadID, threadLifecycleActionFromRequiredAction(requiredAction)),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeLifecycleMutation(
	r *http.Request,
	cellID string,
	req *secureCellLifecycleRequest,
	requiredAction string,
) (*secureCellAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("securecells/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(cellID) == "" {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell ID is required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("securecells/auth: %w: secure cell lifecycle request is required", audit.ErrInvalidInput)
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
		requiredAction,
		resourceCandidatesForSecureCellLifecycle(cellID, lifecycleActionFromRequiredAction(requiredAction)),
		resolveSecureCellAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction)),
	)
}

func (a *secureCellEnterpriseRequestAuthorizer) authorizeEnterpriseMutation(
	ctx context.Context,
	actorIdentity *agent.AgentIdentity,
	receipt *policy.SignedPolicyReceipt,
	requiredAction string,
	resourceCandidates []string,
	requestJurisdiction string,
) (*secureCellAuthContext, error) {
	if actorIdentity == nil {
		return nil, fmt.Errorf("securecells/auth: %w: actor identity is required", audit.ErrUnauthorized)
	}
	if receipt == nil {
		return nil, fmt.Errorf("securecells/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}

	snapshot, err := a.trustSource.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: load enterprise trust snapshot: %v", audit.ErrWriteDisabled, err)
	}

	if err := agent.VerifyIdentity(actorIdentity); err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: invalid actor identity: %v", audit.ErrUnauthorized, err)
	}
	if actorIdentity.AgentID() != receipt.Actor {
		return nil, fmt.Errorf("securecells/auth: %w: receipt actor %q does not match passport DID %q", audit.ErrUnauthorized, receipt.Actor, actorIdentity.AgentID())
	}
	if !strings.EqualFold(receipt.Decision, policy.Allow.String()) {
		return nil, fmt.Errorf("securecells/auth: %w: policy decision %q does not authorize secure cell writes", audit.ErrUnauthorized, receipt.Decision)
	}
	if receipt.Action != requiredAction {
		return nil, fmt.Errorf("securecells/auth: %w: policy action %q does not match required action %q", audit.ErrUnauthorized, receipt.Action, requiredAction)
	}

	requiredTool := strings.TrimSpace(a.requiredTool)
	if requiredTool != "" && !actorIdentity.AllowsTool(requiredTool) && !actorIdentity.HasCapability(requiredTool) && !actorIdentity.HasCapability(requiredAction) {
		return nil, fmt.Errorf("securecells/auth: %w: actor passport does not allow tool %q", audit.ErrUnauthorized, requiredTool)
	}

	requiredJurisdiction := strings.TrimSpace(a.requiredJurisdiction)
	if requiredJurisdiction == "" {
		requiredJurisdiction = strings.TrimSpace(snapshot.RequiredJurisdiction)
	}
	if requiredJurisdiction != "" {
		if !actorIdentity.HasJurisdiction(requiredJurisdiction) {
			return nil, fmt.Errorf("securecells/auth: %w: actor passport does not allow jurisdiction %q", audit.ErrUnauthorized, requiredJurisdiction)
		}
		if requestJurisdiction != "" && requestJurisdiction != requiredJurisdiction {
			return nil, fmt.Errorf("securecells/auth: %w: request jurisdiction %q does not match required jurisdiction %q", audit.ErrUnauthorized, requestJurisdiction, requiredJurisdiction)
		}
	}

	sponsorOfRecord := ""
	if actorIdentity.Liability != nil {
		sponsorOfRecord = strings.TrimSpace(actorIdentity.Liability.SponsorOfRecord)
	}
	if sponsorOfRecord == "" {
		return nil, fmt.Errorf("securecells/auth: %w: sponsor_of_record is required", audit.ErrUnauthorized)
	}

	var sponsorTrustEntry *audit.EnterpriseAllowedSponsor
	if len(snapshot.AllowedSponsors) > 0 {
		entry, ok := snapshot.AllowedSponsors[sponsorOfRecord]
		if !ok {
			return nil, fmt.Errorf("securecells/auth: %w: sponsor_of_record %q is not allowed", audit.ErrUnauthorized, sponsorOfRecord)
		}
		if entry.Status != audit.TrustRegistryEntryStatusActive {
			return nil, fmt.Errorf("securecells/auth: %w: sponsor_of_record %q is not active", audit.ErrUnauthorized, sponsorOfRecord)
		}
		if !secureCellTrustScopeAllowsAction(entry.Actions, requiredAction) {
			return nil, fmt.Errorf("securecells/auth: %w: sponsor_of_record %q is not trusted for action %q", audit.ErrUnauthorized, sponsorOfRecord, requiredAction)
		}
		if !secureCellTrustScopeAllowsJurisdiction(entry.Jurisdictions, requestJurisdiction) {
			return nil, fmt.Errorf("securecells/auth: %w: sponsor_of_record %q is not trusted for jurisdiction %q", audit.ErrUnauthorized, sponsorOfRecord, requestJurisdiction)
		}
		sponsorTrustEntry = &entry
	}

	signerTrustEntry, ok := snapshot.PolicySigners[receipt.Signer]
	if !ok {
		return nil, fmt.Errorf("securecells/auth: %w: untrusted policy signer %q", audit.ErrUnauthorized, receipt.Signer)
	}
	if signerTrustEntry.Status != audit.TrustRegistryEntryStatusActive {
		return nil, fmt.Errorf("securecells/auth: %w: policy signer %q is not active", audit.ErrUnauthorized, receipt.Signer)
	}
	if !secureCellTrustScopeAllowsAction(signerTrustEntry.Actions, requiredAction) {
		return nil, fmt.Errorf("securecells/auth: %w: policy signer %q is not trusted for action %q", audit.ErrUnauthorized, receipt.Signer, requiredAction)
	}
	if !secureCellTrustScopeAllowsJurisdiction(signerTrustEntry.Jurisdictions, requestJurisdiction) {
		return nil, fmt.Errorf("securecells/auth: %w: policy signer %q is not trusted for jurisdiction %q", audit.ErrUnauthorized, receipt.Signer, requestJurisdiction)
	}
	if err := policy.VerifySignedPolicyReceipt(receipt, signerTrustEntry.PublicKey); err != nil {
		return nil, fmt.Errorf("securecells/auth: %w: invalid signed policy receipt: %v", audit.ErrUnauthorized, err)
	}
	if !secureCellPolicyReceiptAuthorizesAnyResource(receipt.Resource, resourceCandidates...) {
		return nil, fmt.Errorf("securecells/auth: %w: policy receipt resource %q does not authorize the requested secure cell", audit.ErrUnauthorized, receipt.Resource)
	}

	authCtx := &secureCellAuthContext{
		ActorIdentity:        actorIdentity,
		PolicyReceipt:        receipt,
		Mode:                 secureCellsEnterpriseActionModeBase,
		ActorDID:             actorIdentity.AgentID(),
		PolicyReceiptID:      receipt.ID,
		PolicySigner:         receipt.Signer,
		RequiredAction:       requiredAction,
		RequiredJurisdiction: requiredJurisdiction,
		SponsorOfRecord:      sponsorOfRecord,
		PolicySignerStatus:   string(signerTrustEntry.Status),
	}
	if sponsorTrustEntry != nil {
		authCtx.SponsorStatus = string(sponsorTrustEntry.Status)
	}
	if snapshot != nil {
		if trustProvider := strings.TrimSpace(snapshot.Metadata["provider"]); trustProvider != "" {
			authCtx.TrustProvider = trustProvider
		}
		authCtx.TrustSource = strings.TrimSpace(snapshot.Source)
		authCtx.TrustRegistryVersion = strings.TrimSpace(snapshot.Version)
		authCtx.TrustRegistryUpdatedAt = strings.TrimSpace(snapshot.UpdatedAt)
	}
	return authCtx, nil
}

func resolveSecureCellAuthorizer(app *AethelredApp, appOpts servertypes.AppOptions) (secureCellRequestAuthorizer, string, string) {
	if allowUnauthenticatedSecureCellWrites(appOpts) {
		return nil, "unauthenticated", "secure cell writes are enabled without authentication"
	}

	strategies := make([]secureCellRequestAuthorizer, 0, 2)
	authModes := make([]string, 0, 2)
	authMessages := make([]string, 0, 2)

	if enterpriseAuthorizer, authMode, authMessage, err := resolveSecureCellEnterpriseAuthorizer(app, appOpts); err != nil {
		return &secureCellGenericRequestAuthorizer{
			requestAuthorizer: audit.NewDisabledRequestAuthorizer("invalid secure cell enterprise policy-receipt authorization configuration"),
			mode:              "disabled",
		}, "disabled", err.Error()
	} else if enterpriseAuthorizer != nil {
		strategies = append(strategies, enterpriseAuthorizer)
		authModes = append(authModes, authMode)
		authMessages = append(authMessages, authMessage)
	}

	writeToken := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.api.write_token")),
		cast.ToString(appOpts.Get("secure_cells.api.write_token")),
		os.Getenv("AETHELRED_SECURE_CELLS_API_WRITE_TOKEN"),
	)
	if writeToken != "" {
		requestAuthorizer, err := audit.NewStaticBearerTokenRequestAuthorizer(writeToken)
		if err != nil {
			return &secureCellGenericRequestAuthorizer{
				requestAuthorizer: audit.NewDisabledRequestAuthorizer("invalid secure cell write-token configuration"),
				mode:              "disabled",
			}, "disabled", err.Error()
		}
		strategies = append(strategies, &secureCellGenericRequestAuthorizer{
			requestAuthorizer: requestAuthorizer,
			mode:              "bearer_token",
		})
		authModes = append(authModes, "bearer_token")
		authMessages = append(authMessages, "secure cell writes accept Authorization: Bearer <token>")
	}

	switch len(strategies) {
	case 0:
		return &secureCellGenericRequestAuthorizer{
			requestAuthorizer: audit.NewDisabledRequestAuthorizer("configure secure cell write auth to enable secure cell mutations"),
			mode:              "disabled",
		}, "disabled", "secure cell writes are disabled until a bearer token, keeper-backed enterprise trust, enterprise trust registry, or enterprise signer configuration is configured"
	case 1:
		return strategies[0], authModes[0], authMessages[0]
	default:
		return newSecureCellAnyOfRequestAuthorizer(strategies...), strings.Join(authModes, "+"), strings.Join(authMessages, "; ")
	}
}

func resolveSecureCellEnterpriseAuthorizer(app *AethelredApp, appOpts servertypes.AppOptions) (secureCellRequestAuthorizer, string, string, error) {
	var fallbackSource audit.EnterpriseControlLedgerTrustSource
	authModes := make([]string, 0, 3)
	authMessages := make([]string, 0, 3)

	if trustRegistryPath := resolveSecureCellEnterpriseTrustRegistryPath(appOpts); trustRegistryPath != "" {
		trustSource, err := audit.NewFileEnterpriseControlLedgerTrustSource(trustRegistryPath)
		if err != nil {
			return nil, "", "", err
		}
		if _, err := trustSource.Snapshot(context.Background()); err != nil {
			return nil, "", "", err
		}
		fallbackSource = trustSource
		authModes = append(authModes, "trust_registry_file")
		authMessages = append(authMessages, "bootstrap secure cell trust from registry: "+trustRegistryPath)
	} else {
		staticSource, hasStaticConfig, err := resolveSecureCellEnterpriseStaticTrustSource(appOpts)
		if err != nil {
			return nil, "", "", err
		}
		if hasStaticConfig {
			fallbackSource = staticSource
			authModes = append(authModes, "startup_config")
			authMessages = append(authMessages, "bootstrap secure cell trust from configured signer and sponsor allowlists")
		}
	}

	hasKeeperRegistry, err := hasKeeperBackedEnterpriseAuditTrust(app)
	if err != nil {
		return nil, "", "", err
	}
	trustRegistryAdminTokenConfigured := auditTrustRegistryAdminToken(appOpts) != ""
	if app == nil && !hasKeeperRegistry && fallbackSource == nil {
		return nil, "", "", nil
	}
	if app != nil && !hasKeeperRegistry && fallbackSource == nil && !trustRegistryAdminTokenConfigured {
		return nil, "", "", nil
	}

	trustSource := fallbackSource
	if app != nil {
		keeperSource, err := audit.NewPouwKeeperEnterpriseControlLedgerTrustSource(
			&app.PouwKeeper,
			func() context.Context { return safeAuditKeeperContext(app) },
			fallbackSource,
		)
		if err != nil {
			return nil, "", "", err
		}
		trustSource = keeperSource
		if hasKeeperRegistry {
			authModes = append([]string{"pouw_keeper"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust is the active source of truth for secure cell writes"}, authMessages...)
		} else if fallbackSource == nil {
			authModes = append([]string{"pouw_keeper_waiting"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust will activate secure cell writes once the registry is populated"}, authMessages...)
		} else {
			authModes = append([]string{"pouw_keeper_preferred"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust will override bootstrap secure cell trust once populated"}, authMessages...)
		}
	}

	requiredJurisdiction := resolveSecureCellEnterpriseRequiredJurisdiction(appOpts)
	authorizer := &secureCellEnterpriseRequestAuthorizer{
		trustSource:          trustSource,
		requiredTool:         resolveSecureCellEnterpriseRequiredTool(appOpts),
		requiredAction:       resolveSecureCellEnterpriseRequiredAction(appOpts),
		requiredJurisdiction: requiredJurisdiction,
	}

	mode := secureCellsEnterpriseActionModeBase
	if len(authModes) > 0 {
		mode += "+" + strings.Join(authModes, "+")
	}
	message := "secure cell writes require enterprise policy receipts validated against the active enterprise trust source"
	if len(authMessages) > 0 {
		message += "; " + strings.Join(authMessages, "; ")
	}
	if requiredJurisdiction != "" {
		message += "; required jurisdiction: " + requiredJurisdiction
	}
	return authorizer, mode, message, nil
}

func resolveSecureCellEnterpriseStaticTrustSource(appOpts servertypes.AppOptions) (audit.EnterpriseControlLedgerTrustSource, bool, error) {
	trustedPolicySignersConfig := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.api.enterprise_policy_signers")),
		cast.ToString(appOpts.Get("secure_cells.api.enterprise_policy_signers")),
		os.Getenv("AETHELRED_SECURE_CELLS_ENTERPRISE_POLICY_SIGNERS"),
	)
	if trustedPolicySignersConfig == "" {
		return resolveAuditEnterpriseStaticTrustSource(appOpts)
	}

	trustedPolicySigners, err := parseAuditPolicySignerConfig(trustedPolicySignersConfig)
	if err != nil {
		return nil, false, err
	}

	trustSource, err := audit.NewEnterpriseControlLedgerTrustSourceFromConfig(audit.EnterpriseControlLedgerWriteConfig{
		TrustedPolicySigners: trustedPolicySigners,
		RequiredAction:       resolveSecureCellEnterpriseRequiredAction(appOpts),
		RequiredJurisdiction: resolveSecureCellEnterpriseRequiredJurisdiction(appOpts),
		AllowedSponsors: parseAuditCSVList(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.secure_cells.api.enterprise_allowed_sponsors")),
			cast.ToString(appOpts.Get("secure_cells.api.enterprise_allowed_sponsors")),
			os.Getenv("AETHELRED_SECURE_CELLS_ENTERPRISE_ALLOWED_SPONSORS"),
		)),
	})
	if err != nil {
		return nil, false, err
	}
	return trustSource, true, nil
}

func resolveSecureCellEnterpriseTrustRegistryPath(appOpts servertypes.AppOptions) string {
	configuredPath := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.api.enterprise_trust_registry_path")),
		cast.ToString(appOpts.Get("secure_cells.api.enterprise_trust_registry_path")),
		os.Getenv("AETHELRED_SECURE_CELLS_ENTERPRISE_TRUST_REGISTRY_PATH"),
	)
	if configuredPath != "" {
		return filepath.Clean(configuredPath)
	}
	return resolveAuditEnterpriseTrustRegistryPath(appOpts)
}

func resolveSecureCellEnterpriseRequiredJurisdiction(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.api.enterprise_required_jurisdiction")),
		cast.ToString(appOpts.Get("secure_cells.api.enterprise_required_jurisdiction")),
		os.Getenv("AETHELRED_SECURE_CELLS_ENTERPRISE_REQUIRED_JURISDICTION"),
		cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_required_jurisdiction")),
		cast.ToString(appOpts.Get("audit.api.enterprise_required_jurisdiction")),
		os.Getenv("AETHELRED_AUDIT_ENTERPRISE_REQUIRED_JURISDICTION"),
	))
}

func resolveSecureCellEnterpriseRequiredAction(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.api.enterprise_required_action")),
		cast.ToString(appOpts.Get("secure_cells.api.enterprise_required_action")),
		os.Getenv("AETHELRED_SECURE_CELLS_ENTERPRISE_REQUIRED_ACTION"),
		secureCellsAuthRequestAction,
	))
}

func resolveSecureCellEnterpriseRequiredTool(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.api.enterprise_required_tool")),
		cast.ToString(appOpts.Get("secure_cells.api.enterprise_required_tool")),
		os.Getenv("AETHELRED_SECURE_CELLS_ENTERPRISE_REQUIRED_TOOL"),
		secureCellsAuthRequiredTool,
	))
}

func allowUnauthenticatedSecureCellWrites(appOpts servertypes.AppOptions) bool {
	if cast.ToBool(appOpts.Get("aethelred.secure_cells.api.allow_unauthenticated_writes")) {
		return true
	}
	if cast.ToBool(appOpts.Get("secure_cells.api.allow_unauthenticated_writes")) {
		return true
	}
	return cast.ToBool(os.Getenv("AETHELRED_SECURE_CELLS_ALLOW_UNAUTHENTICATED_WRITES"))
}

func (app *AethelredApp) authorizeSecureCellCreate(r *http.Request, req *secureCellCreateRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeCreate(r, req)
}

func (app *AethelredApp) authorizeSecureCellSessionStart(r *http.Request, cellID string, req *secureCellSessionStartRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeStart(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionThreadStart(r *http.Request, cellID string, sessionID string, req *secureCellSessionThreadStartRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeThreadStart(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionShare(r *http.Request, cellID string, sessionID string, req *secureCellSessionShareRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeShare(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionExchange(r *http.Request, cellID string, sessionID string, req *secureCellSessionExchangeRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeExchange(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionThreadMessage(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellThreadMessageRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeThreadMessage(r, cellID, sessionID, threadID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionClose(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeClose(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionPause(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeSessionPause(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionResume(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeSessionResume(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionQuarantine(r *http.Request, cellID string, sessionID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeSessionQuarantine(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionThreadClose(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeThreadClose(r, cellID, sessionID, threadID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionThreadResume(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeThreadResume(r, cellID, sessionID, threadID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionThreadQuarantine(r *http.Request, cellID string, sessionID string, threadID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeThreadQuarantine(r, cellID, sessionID, threadID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionMemberAdmit(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeSessionMemberAdmit(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellSessionMemberRemove(r *http.Request, cellID string, sessionID string, req *secureCellSessionMemberMutationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeSessionMemberRemove(r, cellID, sessionID, req)
}

func (app *AethelredApp) authorizeSecureCellAdmit(r *http.Request, cellID string, req *secureCellAdmitMemberRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeAdmit(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellRelease(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeRelease(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellQuarantine(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeQuarantine(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellRevoke(r *http.Request, cellID string, req *secureCellMemberMutationRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeRevoke(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellExpire(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeExpire(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellPause(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizePause(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellResume(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeResume(r, cellID, req)
}

func (app *AethelredApp) authorizeSecureCellTerminate(r *http.Request, cellID string, req *secureCellLifecycleRequest) (*secureCellAuthContext, error) {
	if app == nil || app.secureCellAuth == nil {
		return nil, nil
	}
	return app.secureCellAuth.AuthorizeTerminate(r, cellID, req)
}

func secureCellAuthorizationStatus(err error, fallback int) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, audit.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, audit.ErrWriteDisabled):
		return http.StatusServiceUnavailable
	default:
		return fallback
	}
}

func secureCellRequestMetadataWithAuthContext(metadata map[string]string, authCtx *secureCellAuthContext) map[string]string {
	if authCtx == nil {
		return metadata
	}
	out := cloneFinanceMetadata(metadata)
	out["auth.mode"] = strings.TrimSpace(authCtx.Mode)
	if authCtx.ActorDID != "" {
		out["auth.actor_did"] = authCtx.ActorDID
	}
	if authCtx.PolicyReceiptID != "" {
		out["auth.policy_receipt_id"] = authCtx.PolicyReceiptID
	}
	if authCtx.PolicySigner != "" {
		out["auth.policy_signer"] = authCtx.PolicySigner
	}
	if authCtx.RequiredAction != "" {
		out["auth.required_action"] = authCtx.RequiredAction
	}
	if authCtx.RequiredJurisdiction != "" {
		out["auth.required_jurisdiction"] = authCtx.RequiredJurisdiction
	}
	if authCtx.SponsorOfRecord != "" {
		out["auth.sponsor_of_record"] = authCtx.SponsorOfRecord
	}
	if authCtx.TrustSource != "" {
		out["auth.trust_source"] = authCtx.TrustSource
	}
	if authCtx.TrustProvider != "" {
		out["auth.trust_provider"] = authCtx.TrustProvider
	}
	if authCtx.TrustRegistryVersion != "" {
		out["auth.trust_registry_version"] = authCtx.TrustRegistryVersion
	}
	if authCtx.TrustRegistryUpdatedAt != "" {
		out["auth.trust_registry_updated_at"] = authCtx.TrustRegistryUpdatedAt
	}
	if authCtx.PolicySignerStatus != "" {
		out["auth.policy_signer_status"] = authCtx.PolicySignerStatus
	}
	if authCtx.SponsorStatus != "" {
		out["auth.sponsor_status"] = authCtx.SponsorStatus
	}
	return out
}

func resourceCandidatesForSecureCellCreate(resource string) []string {
	resource = strings.TrimSpace(resource)
	candidates := []string{secureCellsCollectionRoute}
	if resource != "" {
		candidates = append(candidates, resource, "resource:"+resource)
	}
	return candidates
}

func resourceCandidatesForSecureCellAdmit(cellID, participantDID string) []string {
	cellID = strings.TrimSpace(cellID)
	candidates := []string{
		secureCellsItemPrefix + cellID + "/members",
		"secure-cell:" + cellID,
		cellID,
	}
	if participantDID = strings.TrimSpace(participantDID); participantDID != "" {
		candidates = append(candidates, "participant:"+participantDID)
	}
	return candidates
}

func resourceCandidatesForSecureCellSessionStart(cellID string) []string {
	cellID = strings.TrimSpace(cellID)
	return []string{
		cellID,
		"secure-cell:" + cellID,
		secureCellsItemPrefix + cellID + "/sessions",
		"secure-cell:" + cellID + ":session:start",
	}
}

func resourceCandidatesForSecureCellSessionThreadStart(cellID, sessionID string) []string {
	cellID = strings.TrimSpace(cellID)
	sessionID = strings.TrimSpace(sessionID)
	return []string{
		cellID,
		"secure-cell:" + cellID,
		"secure-cell:" + cellID + ":session:" + sessionID,
		sessionID,
		secureCellsItemPrefix + cellID + "/sessions/" + sessionID + "/threads",
		"secure-cell:" + cellID + ":session:" + sessionID + ":thread:start",
	}
}

func resourceCandidatesForSecureCellSessionLifecycle(cellID, sessionID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	sessionID = strings.TrimSpace(sessionID)
	action = strings.TrimSpace(action)
	base := []string{
		cellID,
		"secure-cell:" + cellID,
		"secure-cell:" + cellID + ":session:" + sessionID,
		sessionID,
	}
	if sessionID != "" && action != "" {
		base = append(base,
			secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/"+action,
			"secure-cell:"+cellID+":session:"+sessionID+":"+action,
		)
	}
	return base
}

func resourceCandidatesForSecureCellSessionShare(cellID, sessionID string) []string {
	return resourceCandidatesForSecureCellSessionLifecycle(cellID, sessionID, "share")
}

func resourceCandidatesForSecureCellSessionExchange(cellID, sessionID string) []string {
	return resourceCandidatesForSecureCellSessionLifecycle(cellID, sessionID, "exchange")
}

func resourceCandidatesForSecureCellSessionThreadLifecycle(cellID, sessionID, threadID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	sessionID = strings.TrimSpace(sessionID)
	threadID = strings.TrimSpace(threadID)
	action = strings.TrimSpace(action)
	base := []string{
		cellID,
		"secure-cell:" + cellID,
		"secure-cell:" + cellID + ":session:" + sessionID,
		sessionID,
		"secure-cell:" + cellID + ":session:" + sessionID + ":thread:" + threadID,
		threadID,
	}
	if threadID != "" && action != "" {
		base = append(base,
			secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/"+action,
			"secure-cell:"+cellID+":session:"+sessionID+":thread:"+threadID+":"+action,
		)
	}
	return base
}

func resourceCandidatesForSecureCellSessionThreadMessage(cellID, sessionID, threadID string) []string {
	return resourceCandidatesForSecureCellSessionThreadLifecycle(cellID, sessionID, threadID, "messages")
}

func resourceCandidatesForSecureCellSessionMemberAction(cellID, sessionID, participantDID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	sessionID = strings.TrimSpace(sessionID)
	participantDID = strings.TrimSpace(participantDID)
	action = strings.TrimSpace(action)
	base := []string{
		cellID,
		"secure-cell:" + cellID,
		"secure-cell:" + cellID + ":session:" + sessionID,
		sessionID,
	}
	if participantDID != "" {
		base = append(base, "participant:"+participantDID)
	}
	if participantDID != "" && action != "" {
		base = append(base,
			secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/members/"+participantDID+"/"+action,
			"secure-cell:"+cellID+":session:"+sessionID+":participant:"+participantDID+":"+action,
		)
	}
	if action == "admit" {
		base = append(base, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/members")
	}
	return base
}

func resourceCandidatesForSecureCellMemberAction(cellID, participantDID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	participantDID = strings.TrimSpace(participantDID)
	action = strings.TrimSpace(action)
	base := []string{
		cellID,
		"secure-cell:" + cellID,
	}
	if participantDID != "" && action != "" {
		base = append(base,
			secureCellsItemPrefix+cellID+"/members/"+participantDID+"/"+action,
			"secure-cell:"+cellID+":participant:"+participantDID+":"+action,
		)
	}
	return base
}

func resourceCandidatesForSecureCellLifecycle(cellID, action string) []string {
	cellID = strings.TrimSpace(cellID)
	action = strings.TrimSpace(action)
	base := []string{
		cellID,
		"secure-cell:" + cellID,
	}
	if action != "" {
		base = append(base,
			secureCellsItemPrefix+cellID+"/"+action,
			"secure-cell:"+cellID+":"+action,
		)
	}
	if action == "expire" {
		base = append(base, secureCellsItemPrefix+cellID+"/quarantine/expire")
	}
	return base
}

func resolveSecureCellAuthJurisdiction(explicit string, actorIdentity *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, fallback string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	if receipt != nil {
		if jurisdiction := strings.TrimSpace(receipt.Context["jurisdiction"]); jurisdiction != "" {
			return jurisdiction
		}
		if jurisdiction := strings.TrimSpace(receipt.Metadata["jurisdiction"]); jurisdiction != "" {
			return jurisdiction
		}
	}
	if actorIdentity != nil && len(actorIdentity.JurisdictionTags) > 0 {
		if jurisdiction := strings.TrimSpace(actorIdentity.JurisdictionTags[0]); jurisdiction != "" {
			return jurisdiction
		}
	}
	return strings.TrimSpace(fallback)
}

func secureCellPolicyReceiptAuthorizesAnyResource(resource string, candidates ...string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return false
	}
	for _, candidate := range candidates {
		normalized := strings.TrimSpace(candidate)
		if normalized == "" {
			continue
		}
		if resource == normalized {
			return true
		}
	}
	return false
}

func secureCellTrustScopeAllowsAction(allowedActions []string, action string) bool {
	action = strings.TrimSpace(action)
	if len(allowedActions) == 0 || action == "" {
		return true
	}
	for _, candidate := range allowedActions {
		if strings.TrimSpace(candidate) == action {
			return true
		}
	}
	return false
}

func secureCellTrustScopeAllowsJurisdiction(allowedJurisdictions []string, jurisdiction string) bool {
	jurisdiction = strings.TrimSpace(jurisdiction)
	if len(allowedJurisdictions) == 0 || jurisdiction == "" {
		return true
	}
	for _, candidate := range allowedJurisdictions {
		if strings.TrimSpace(candidate) == jurisdiction {
			return true
		}
	}
	return false
}

func participantIdentityDID(identity *agent.AgentIdentity) string {
	if identity == nil {
		return ""
	}
	return identity.AgentID()
}

func memberActionFromRequiredAction(requiredAction string) string {
	switch strings.TrimSpace(requiredAction) {
	case secureCellsAuthReleaseAction:
		return "release"
	case secureCellsAuthQuarantineAction:
		return "quarantine"
	case secureCellsAuthRevokeAction:
		return "revoke"
	default:
		return "mutate"
	}
}

func sessionMemberActionFromRequiredAction(requiredAction string) string {
	switch strings.TrimSpace(requiredAction) {
	case secureCellsAuthSessionMemberAdmitAction:
		return "admit"
	case secureCellsAuthSessionMemberRemoveAction:
		return "remove"
	default:
		return "member"
	}
}

func lifecycleActionFromRequiredAction(requiredAction string) string {
	switch strings.TrimSpace(requiredAction) {
	case secureCellsAuthPauseAction:
		return "pause"
	case secureCellsAuthResumeAction:
		return "resume"
	case secureCellsAuthTerminateAction:
		return "terminate"
	case secureCellsAuthExpireAction:
		return "expire"
	default:
		return "lifecycle"
	}
}

func sessionLifecycleActionFromRequiredAction(requiredAction string) string {
	switch strings.TrimSpace(requiredAction) {
	case secureCellsAuthSessionStartAction:
		return "start"
	case secureCellsAuthSessionCloseAction:
		return "close"
	case secureCellsAuthSessionPauseAction:
		return "pause"
	case secureCellsAuthSessionResumeAction:
		return "resume"
	case secureCellsAuthSessionQuarantineAction:
		return "quarantine"
	case secureCellsAuthSessionExchangeAction:
		return "exchange"
	default:
		return "session"
	}
}

func threadLifecycleActionFromRequiredAction(requiredAction string) string {
	switch strings.TrimSpace(requiredAction) {
	case secureCellsAuthSessionThreadCloseAction:
		return "close"
	case secureCellsAuthSessionThreadResumeAction:
		return "resume"
	case secureCellsAuthSessionThreadQuarantineAction:
		return "quarantine"
	default:
		return "thread"
	}
}

func secureCellEnterpriseEnabled(appOpts servertypes.AppOptions) bool {
	if path := resolveSecureCellEnterpriseTrustRegistryPath(appOpts); path != "" {
		return true
	}
	if _, hasStaticConfig, _ := resolveSecureCellEnterpriseStaticTrustSource(appOpts); hasStaticConfig {
		return true
	}
	return false
}

func secureCellNotFound(err error) bool {
	return errors.Is(err, securecellsintegration.ErrCellNotFound)
}
