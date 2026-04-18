package agent

import (
	"context"
	"fmt"
)

// ---------------------------------------------------------------------------
// Authorization context and result
// ---------------------------------------------------------------------------

// AuthorizationContext encapsulates all information needed to authorize an
// inter-agent action.
type AuthorizationContext struct {
	// Actor is the identity of the agent performing the action.
	Actor *AgentIdentity

	// Action is the operation being performed.
	Action string

	// Resource is the target of the action.
	Resource string

	// Delegation is the delegation chain authorizing this action (nil for direct).
	Delegation *DelegationChain

	// Credentials are verifiable credentials presented by the actor.
	Credentials []*AgentCredential

	// PolicyContext provides additional context for policy evaluation.
	PolicyContext map[string]string
}

// AuthorizationResult is the outcome of an authorization evaluation.
type AuthorizationResult struct {
	// Authorized is true if the action is permitted.
	Authorized bool `json:"authorized"`

	// Reason explains why the action was allowed or denied.
	Reason string `json:"reason"`

	// MatchedPolicies lists the policy IDs that contributed to the decision.
	MatchedPolicies []string `json:"matched_policies,omitempty"`

	// RequiredCredentials lists any additional credentials needed.
	RequiredCredentials []CredentialType `json:"required_credentials,omitempty"`
}

// AuthorizationPolicy defines the rules for authorizing inter-agent actions.
type AuthorizationPolicy struct {
	// RequiredCredentials lists credential types that the actor must present.
	RequiredCredentials []CredentialType `json:"required_credentials"`

	// AllowedActions lists the actions that are permitted under this policy.
	AllowedActions []string `json:"allowed_actions"`

	// DelegationRules defines constraints on delegation-based authorization.
	DelegationRules *DelegationAuthRules `json:"delegation_rules,omitempty"`
}

// DelegationAuthRules defines how delegations are evaluated for authorization.
type DelegationAuthRules struct {
	// AllowDelegation controls whether delegated actions are permitted at all.
	AllowDelegation bool `json:"allow_delegation"`

	// MaxDepth is the maximum delegation depth accepted.
	MaxDepth int `json:"max_depth"`

	// RequireChainVerification requires the full delegation chain to be valid.
	RequireChainVerification bool `json:"require_chain_verification"`
}

// ---------------------------------------------------------------------------
// Authorization engine
// ---------------------------------------------------------------------------

// Authorizer evaluates authorization requests against policies.
type Authorizer struct {
	policies          []*AuthorizationPolicy
	delegationManager *DelegationManager
}

// NewAuthorizer creates a new Authorizer.
func NewAuthorizer(policies []*AuthorizationPolicy, dm *DelegationManager) *Authorizer {
	return &Authorizer{
		policies:          policies,
		delegationManager: dm,
	}
}

// Authorize evaluates whether an inter-agent action is authorized.
func (a *Authorizer) Authorize(ctx context.Context, authCtx *AuthorizationContext) (*AuthorizationResult, error) {
	if authCtx == nil {
		return nil, fmt.Errorf("authorization context cannot be nil")
	}
	if authCtx.Actor == nil {
		return nil, fmt.Errorf("actor identity is required")
	}
	if authCtx.Action == "" {
		return nil, fmt.Errorf("action is required")
	}

	// Step 1: Verify actor identity.
	if err := VerifyIdentity(authCtx.Actor); err != nil {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     fmt.Sprintf("actor identity verification failed: %v", err),
		}, nil
	}

	// Step 2: Check delegation if present.
	if authCtx.Delegation != nil {
		if !IsDelegationValid(authCtx.Delegation) {
			return &AuthorizationResult{
				Authorized: false,
				Reason:     "delegation is invalid or expired",
			}, nil
		}

		// Verify delegation covers the action.
		if a.delegationManager != nil {
			valid, err := a.delegationManager.VerifyDelegation(ctx, authCtx.Delegation.ID, authCtx.Action)
			if err != nil {
				return &AuthorizationResult{
					Authorized: false,
					Reason:     fmt.Sprintf("delegation verification failed: %v", err),
				}, nil
			}
			if !valid {
				return &AuthorizationResult{
					Authorized: false,
					Reason:     "delegation does not cover this action",
				}, nil
			}
		}
	}

	// Step 3: Evaluate policies.
	var matchedPolicies []string
	var missingCreds []CredentialType

	for _, policy := range a.policies {
		// Check required credentials.
		for _, reqCred := range policy.RequiredCredentials {
			if !hasCredential(authCtx.Credentials, reqCred) {
				missingCreds = append(missingCreds, reqCred)
			}
		}

		// Check allowed actions.
		if len(policy.AllowedActions) > 0 {
			actionAllowed := false
			for _, allowed := range policy.AllowedActions {
				if allowed == authCtx.Action || allowed == "*" {
					actionAllowed = true
					break
				}
			}
			if !actionAllowed {
				return &AuthorizationResult{
					Authorized: false,
					Reason:     fmt.Sprintf("action %q is not in the allowed actions list", authCtx.Action),
				}, nil
			}
		}

		// Check delegation rules.
		if authCtx.Delegation != nil && policy.DelegationRules != nil {
			rules := policy.DelegationRules
			if !rules.AllowDelegation {
				return &AuthorizationResult{
					Authorized: false,
					Reason:     "delegated actions are not permitted by policy",
				}, nil
			}
			if rules.MaxDepth > 0 && authCtx.Delegation.Depth > rules.MaxDepth {
				return &AuthorizationResult{
					Authorized: false,
					Reason:     fmt.Sprintf("delegation depth %d exceeds policy maximum of %d", authCtx.Delegation.Depth, rules.MaxDepth),
				}, nil
			}
		}

		matchedPolicies = append(matchedPolicies, fmt.Sprintf("policy-%d", len(matchedPolicies)))
	}

	if len(missingCreds) > 0 {
		return &AuthorizationResult{
			Authorized:          false,
			Reason:              "missing required credentials",
			RequiredCredentials: missingCreds,
			MatchedPolicies:     matchedPolicies,
		}, nil
	}

	return &AuthorizationResult{
		Authorized:      true,
		Reason:          "all policy checks passed",
		MatchedPolicies: matchedPolicies,
	}, nil
}

// RequireCredential checks whether an agent has a specific credential type.
func RequireCredential(_ context.Context, credentials []*AgentCredential, credType CredentialType) error {
	if !hasCredential(credentials, credType) {
		return fmt.Errorf("missing required credential of type %s", credType)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func hasCredential(creds []*AgentCredential, credType CredentialType) bool {
	for _, c := range creds {
		if c.Type == credType && c.IsValid() {
			return true
		}
	}
	return false
}
