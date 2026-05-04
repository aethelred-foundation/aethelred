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
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

const (
	financeTreasuryReleaseAuthDefaultResource      = "acct:treasury-main"
	financeTreasuryReleaseAuthRequestAction        = "payments.release.request"
	financeTreasuryReleaseAuthApproveAction        = "payments.release.approve"
	financeTreasuryReleaseAuthRequiredTool         = "payments.release"
	financeTreasuryReleaseEnterpriseActionModeBase = "enterprise_policy_receipt"
)

type financeTreasuryReleaseAuthContext struct {
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

type financeTreasuryReleaseRequestAuthorizer interface {
	AuthorizeInitiate(r *http.Request, req *financeTreasuryReleaseInitiateRequest) (*financeTreasuryReleaseAuthContext, error)
	AuthorizeApprove(r *http.Request, workflowID string, req *financeTreasuryReleaseApproveRequest) (*financeTreasuryReleaseAuthContext, error)
}

type financeGenericTreasuryReleaseRequestAuthorizer struct {
	requestAuthorizer audit.RequestAuthorizer
	mode              string
}

func (a *financeGenericTreasuryReleaseRequestAuthorizer) AuthorizeInitiate(r *http.Request, _ *financeTreasuryReleaseInitiateRequest) (*financeTreasuryReleaseAuthContext, error) {
	if a == nil || a.requestAuthorizer == nil {
		return nil, fmt.Errorf("finance/auth: %w: request authorizer is not configured", audit.ErrWriteDisabled)
	}
	if err := a.requestAuthorizer.AuthorizeRequest(r); err != nil {
		return nil, err
	}
	return &financeTreasuryReleaseAuthContext{Mode: strings.TrimSpace(a.mode)}, nil
}

func (a *financeGenericTreasuryReleaseRequestAuthorizer) AuthorizeApprove(r *http.Request, _ string, _ *financeTreasuryReleaseApproveRequest) (*financeTreasuryReleaseAuthContext, error) {
	if a == nil || a.requestAuthorizer == nil {
		return nil, fmt.Errorf("finance/auth: %w: request authorizer is not configured", audit.ErrWriteDisabled)
	}
	if err := a.requestAuthorizer.AuthorizeRequest(r); err != nil {
		return nil, err
	}
	return &financeTreasuryReleaseAuthContext{Mode: strings.TrimSpace(a.mode)}, nil
}

type financeAnyOfTreasuryReleaseRequestAuthorizer struct {
	strategies []financeTreasuryReleaseRequestAuthorizer
}

func newFinanceAnyOfTreasuryReleaseRequestAuthorizer(strategies ...financeTreasuryReleaseRequestAuthorizer) *financeAnyOfTreasuryReleaseRequestAuthorizer {
	filtered := make([]financeTreasuryReleaseRequestAuthorizer, 0, len(strategies))
	for _, strategy := range strategies {
		if strategy != nil {
			filtered = append(filtered, strategy)
		}
	}
	return &financeAnyOfTreasuryReleaseRequestAuthorizer{strategies: filtered}
}

func (a *financeAnyOfTreasuryReleaseRequestAuthorizer) AuthorizeInitiate(r *http.Request, req *financeTreasuryReleaseInitiateRequest) (*financeTreasuryReleaseAuthContext, error) {
	if a == nil || len(a.strategies) == 0 {
		return nil, fmt.Errorf("finance/auth: %w: no authorization strategies configured", audit.ErrWriteDisabled)
	}

	var unauthorizedErr error
	var disabledErr error
	for _, strategy := range a.strategies {
		authCtx, err := strategy.AuthorizeInitiate(r, req)
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
	return nil, fmt.Errorf("finance/auth: %w: authorization failed", audit.ErrUnauthorized)
}

func (a *financeAnyOfTreasuryReleaseRequestAuthorizer) AuthorizeApprove(r *http.Request, workflowID string, req *financeTreasuryReleaseApproveRequest) (*financeTreasuryReleaseAuthContext, error) {
	if a == nil || len(a.strategies) == 0 {
		return nil, fmt.Errorf("finance/auth: %w: no authorization strategies configured", audit.ErrWriteDisabled)
	}

	var unauthorizedErr error
	var disabledErr error
	for _, strategy := range a.strategies {
		authCtx, err := strategy.AuthorizeApprove(r, workflowID, req)
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
	return nil, fmt.Errorf("finance/auth: %w: authorization failed", audit.ErrUnauthorized)
}

type financeEnterpriseTreasuryReleaseRequestAuthorizer struct {
	trustSource           audit.EnterpriseControlLedgerTrustSource
	requiredTool          string
	requiredRequestAction string
	requiredApproveAction string
	requiredJurisdiction  string
}

func (a *financeEnterpriseTreasuryReleaseRequestAuthorizer) AuthorizeInitiate(r *http.Request, req *financeTreasuryReleaseInitiateRequest) (*financeTreasuryReleaseAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("finance/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if req == nil {
		return nil, fmt.Errorf("finance/auth: %w: treasury release request is required", audit.ErrInvalidInput)
	}

	actorIdentity, err := decodeFinanceAgentIdentity(req.Identity)
	if err != nil {
		return nil, fmt.Errorf("finance/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("finance/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}

	resource := strings.TrimSpace(req.Resource)
	if resource == "" {
		resource = financeTreasuryReleaseAuthDefaultResource
	}
	jurisdiction := resolveFinanceAuthJurisdiction(strings.TrimSpace(req.Jurisdiction), actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction))
	return a.authorizeEnterpriseMutation(requestContextOrBackground(r), actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredRequestAction), resourceCandidatesForFinanceInitiate(resource), jurisdiction)
}

func (a *financeEnterpriseTreasuryReleaseRequestAuthorizer) AuthorizeApprove(r *http.Request, workflowID string, req *financeTreasuryReleaseApproveRequest) (*financeTreasuryReleaseAuthContext, error) {
	if a == nil || a.trustSource == nil {
		return nil, fmt.Errorf("finance/auth: %w: enterprise authorizer is not configured", audit.ErrWriteDisabled)
	}
	if strings.TrimSpace(workflowID) == "" {
		return nil, fmt.Errorf("finance/auth: %w: treasury release workflow ID is required", audit.ErrInvalidInput)
	}
	if req == nil {
		return nil, fmt.Errorf("finance/auth: %w: treasury approval request is required", audit.ErrInvalidInput)
	}

	actorIdentity, err := decodeFinanceAgentIdentity(req.ActorIdentity)
	if err != nil {
		return nil, fmt.Errorf("finance/auth: %w: %s", audit.ErrUnauthorized, err.Error())
	}
	if req.PolicyReceipt == nil {
		return nil, fmt.Errorf("finance/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}

	jurisdiction := resolveFinanceAuthJurisdiction("", actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredJurisdiction))
	return a.authorizeEnterpriseMutation(requestContextOrBackground(r), actorIdentity, req.PolicyReceipt, strings.TrimSpace(a.requiredApproveAction), resourceCandidatesForFinanceApproval(workflowID), jurisdiction)
}

func (a *financeEnterpriseTreasuryReleaseRequestAuthorizer) authorizeEnterpriseMutation(
	ctx context.Context,
	actorIdentity *agent.AgentIdentity,
	receipt *policy.SignedPolicyReceipt,
	requiredAction string,
	resourceCandidates []string,
	requestJurisdiction string,
) (*financeTreasuryReleaseAuthContext, error) {
	if actorIdentity == nil {
		return nil, fmt.Errorf("finance/auth: %w: actor identity is required", audit.ErrUnauthorized)
	}
	if receipt == nil {
		return nil, fmt.Errorf("finance/auth: %w: signed policy receipt is required", audit.ErrUnauthorized)
	}

	snapshot, err := a.trustSource.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("finance/auth: %w: load enterprise trust snapshot: %v", audit.ErrWriteDisabled, err)
	}

	if err := agent.VerifyIdentity(actorIdentity); err != nil {
		return nil, fmt.Errorf("finance/auth: %w: invalid actor identity: %v", audit.ErrUnauthorized, err)
	}
	if actorIdentity.AgentID() != receipt.Actor {
		return nil, fmt.Errorf("finance/auth: %w: receipt actor %q does not match passport DID %q", audit.ErrUnauthorized, receipt.Actor, actorIdentity.AgentID())
	}
	if !strings.EqualFold(receipt.Decision, policy.Allow.String()) {
		return nil, fmt.Errorf("finance/auth: %w: policy decision %q does not authorize treasury release writes", audit.ErrUnauthorized, receipt.Decision)
	}
	if receipt.Action != requiredAction {
		return nil, fmt.Errorf("finance/auth: %w: policy action %q does not match required action %q", audit.ErrUnauthorized, receipt.Action, requiredAction)
	}

	requiredTool := strings.TrimSpace(a.requiredTool)
	if requiredTool != "" && !actorIdentity.AllowsTool(requiredTool) && !actorIdentity.HasCapability(requiredTool) && !actorIdentity.HasCapability(requiredAction) {
		return nil, fmt.Errorf("finance/auth: %w: actor passport does not allow tool %q", audit.ErrUnauthorized, requiredTool)
	}

	requiredJurisdiction := strings.TrimSpace(a.requiredJurisdiction)
	if requiredJurisdiction == "" {
		requiredJurisdiction = strings.TrimSpace(snapshot.RequiredJurisdiction)
	}
	if requiredJurisdiction != "" {
		if !actorIdentity.HasJurisdiction(requiredJurisdiction) {
			return nil, fmt.Errorf("finance/auth: %w: actor passport does not allow jurisdiction %q", audit.ErrUnauthorized, requiredJurisdiction)
		}
		if requestJurisdiction != "" && requestJurisdiction != requiredJurisdiction {
			return nil, fmt.Errorf("finance/auth: %w: request jurisdiction %q does not match required jurisdiction %q", audit.ErrUnauthorized, requestJurisdiction, requiredJurisdiction)
		}
	}

	sponsorOfRecord := ""
	if actorIdentity.Liability != nil {
		sponsorOfRecord = strings.TrimSpace(actorIdentity.Liability.SponsorOfRecord)
	}
	if sponsorOfRecord == "" {
		return nil, fmt.Errorf("finance/auth: %w: sponsor_of_record is required", audit.ErrUnauthorized)
	}

	var sponsorTrustEntry *audit.EnterpriseAllowedSponsor
	if len(snapshot.AllowedSponsors) > 0 {
		entry, ok := snapshot.AllowedSponsors[sponsorOfRecord]
		if !ok {
			return nil, fmt.Errorf("finance/auth: %w: sponsor_of_record %q is not allowed", audit.ErrUnauthorized, sponsorOfRecord)
		}
		if entry.Status != audit.TrustRegistryEntryStatusActive {
			return nil, fmt.Errorf("finance/auth: %w: sponsor_of_record %q is not active", audit.ErrUnauthorized, sponsorOfRecord)
		}
		if !financeTrustScopeAllowsAction(entry.Actions, requiredAction) {
			return nil, fmt.Errorf("finance/auth: %w: sponsor_of_record %q is not trusted for action %q", audit.ErrUnauthorized, sponsorOfRecord, requiredAction)
		}
		if !financeTrustScopeAllowsJurisdiction(entry.Jurisdictions, requestJurisdiction) {
			return nil, fmt.Errorf("finance/auth: %w: sponsor_of_record %q is not trusted for jurisdiction %q", audit.ErrUnauthorized, sponsorOfRecord, requestJurisdiction)
		}
		sponsorTrustEntry = &entry
	}

	signerTrustEntry, ok := snapshot.PolicySigners[receipt.Signer]
	if !ok {
		return nil, fmt.Errorf("finance/auth: %w: untrusted policy signer %q", audit.ErrUnauthorized, receipt.Signer)
	}
	if signerTrustEntry.Status != audit.TrustRegistryEntryStatusActive {
		return nil, fmt.Errorf("finance/auth: %w: policy signer %q is not active", audit.ErrUnauthorized, receipt.Signer)
	}
	if !financeTrustScopeAllowsAction(signerTrustEntry.Actions, requiredAction) {
		return nil, fmt.Errorf("finance/auth: %w: policy signer %q is not trusted for action %q", audit.ErrUnauthorized, receipt.Signer, requiredAction)
	}
	if !financeTrustScopeAllowsJurisdiction(signerTrustEntry.Jurisdictions, requestJurisdiction) {
		return nil, fmt.Errorf("finance/auth: %w: policy signer %q is not trusted for jurisdiction %q", audit.ErrUnauthorized, receipt.Signer, requestJurisdiction)
	}
	if err := policy.VerifySignedPolicyReceipt(receipt, signerTrustEntry.PublicKey); err != nil {
		return nil, fmt.Errorf("finance/auth: %w: invalid signed policy receipt: %v", audit.ErrUnauthorized, err)
	}
	if !financePolicyReceiptAuthorizesAnyResource(receipt.Resource, resourceCandidates...) {
		return nil, fmt.Errorf("finance/auth: %w: policy receipt resource %q does not authorize the requested treasury release", audit.ErrUnauthorized, receipt.Resource)
	}

	authCtx := &financeTreasuryReleaseAuthContext{
		ActorIdentity:        actorIdentity,
		PolicyReceipt:        receipt,
		Mode:                 financeTreasuryReleaseEnterpriseActionModeBase,
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

func resolveFinanceTreasuryReleaseAuthorizer(app *AethelredApp, appOpts servertypes.AppOptions) (financeTreasuryReleaseRequestAuthorizer, string, string) {
	if allowUnauthenticatedFinanceWrites(appOpts) {
		return nil, "unauthenticated", "finance treasury release writes are enabled without authentication"
	}

	strategies := make([]financeTreasuryReleaseRequestAuthorizer, 0, 2)
	authModes := make([]string, 0, 2)
	authMessages := make([]string, 0, 2)

	if enterpriseAuthorizer, authMode, authMessage, err := resolveFinanceEnterpriseReleaseAuthorizer(app, appOpts); err != nil {
		return &financeGenericTreasuryReleaseRequestAuthorizer{
			requestAuthorizer: audit.NewDisabledRequestAuthorizer("invalid finance enterprise policy-receipt authorization configuration"),
			mode:              "disabled",
		}, "disabled", err.Error()
	} else if enterpriseAuthorizer != nil {
		strategies = append(strategies, enterpriseAuthorizer)
		authModes = append(authModes, authMode)
		authMessages = append(authMessages, authMessage)
	}

	writeToken := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.write_token")),
		cast.ToString(appOpts.Get("finance.api.write_token")),
		os.Getenv("AETHELRED_FINANCE_API_WRITE_TOKEN"),
	)
	if writeToken != "" {
		requestAuthorizer, err := audit.NewStaticBearerTokenRequestAuthorizer(writeToken)
		if err != nil {
			return &financeGenericTreasuryReleaseRequestAuthorizer{
				requestAuthorizer: audit.NewDisabledRequestAuthorizer("invalid finance write-token configuration"),
				mode:              "disabled",
			}, "disabled", err.Error()
		}
		strategies = append(strategies, &financeGenericTreasuryReleaseRequestAuthorizer{
			requestAuthorizer: requestAuthorizer,
			mode:              "bearer_token",
		})
		authModes = append(authModes, "bearer_token")
		authMessages = append(authMessages, "finance treasury release writes accept Authorization: Bearer <token>")
	}

	switch len(strategies) {
	case 0:
		return &financeGenericTreasuryReleaseRequestAuthorizer{
			requestAuthorizer: audit.NewDisabledRequestAuthorizer("configure finance write auth to enable treasury release mutations"),
			mode:              "disabled",
		}, "disabled", "finance treasury release writes are disabled until a bearer token, keeper-backed enterprise trust, enterprise trust registry, or enterprise signer configuration is configured"
	case 1:
		return strategies[0], authModes[0], authMessages[0]
	default:
		return newFinanceAnyOfTreasuryReleaseRequestAuthorizer(strategies...), strings.Join(authModes, "+"), strings.Join(authMessages, "; ")
	}
}

func resolveFinanceEnterpriseReleaseAuthorizer(app *AethelredApp, appOpts servertypes.AppOptions) (financeTreasuryReleaseRequestAuthorizer, string, string, error) {
	var fallbackSource audit.EnterpriseControlLedgerTrustSource
	authModes := make([]string, 0, 3)
	authMessages := make([]string, 0, 3)

	if trustRegistryPath := resolveFinanceEnterpriseTrustRegistryPath(appOpts); trustRegistryPath != "" {
		trustSource, err := audit.NewFileEnterpriseControlLedgerTrustSource(trustRegistryPath)
		if err != nil {
			return nil, "", "", err
		}
		if _, err := trustSource.Snapshot(context.Background()); err != nil {
			return nil, "", "", err
		}
		fallbackSource = trustSource
		authModes = append(authModes, "trust_registry_file")
		authMessages = append(authMessages, "bootstrap finance trust from registry: "+trustRegistryPath)
	} else {
		staticSource, hasStaticConfig, err := resolveFinanceEnterpriseStaticTrustSource(appOpts)
		if err != nil {
			return nil, "", "", err
		}
		if hasStaticConfig {
			fallbackSource = staticSource
			authModes = append(authModes, "startup_config")
			authMessages = append(authMessages, "bootstrap finance trust from configured signer and sponsor allowlists")
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
			authMessages = append([]string{"keeper-backed enterprise trust is the active source of truth for finance writes"}, authMessages...)
		} else if fallbackSource == nil {
			authModes = append([]string{"pouw_keeper_waiting"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust will activate finance writes once the registry is populated"}, authMessages...)
		} else {
			authModes = append([]string{"pouw_keeper_preferred"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust will override bootstrap finance trust once populated"}, authMessages...)
		}
	}

	requiredJurisdiction := resolveFinanceEnterpriseRequiredJurisdiction(appOpts)
	authorizer := &financeEnterpriseTreasuryReleaseRequestAuthorizer{
		trustSource:           trustSource,
		requiredTool:          resolveFinanceEnterpriseRequiredTool(appOpts),
		requiredRequestAction: resolveFinanceEnterpriseRequiredRequestAction(appOpts),
		requiredApproveAction: resolveFinanceEnterpriseRequiredApproveAction(appOpts),
		requiredJurisdiction:  requiredJurisdiction,
	}

	mode := financeTreasuryReleaseEnterpriseActionModeBase
	if len(authModes) > 0 {
		mode += "+" + strings.Join(authModes, "+")
	}
	message := "finance treasury release writes require enterprise policy receipts validated against the active enterprise trust source"
	if len(authMessages) > 0 {
		message += "; " + strings.Join(authMessages, "; ")
	}
	if requiredJurisdiction != "" {
		message += "; required jurisdiction: " + requiredJurisdiction
	}
	return authorizer, mode, message, nil
}

func resolveFinanceEnterpriseStaticTrustSource(appOpts servertypes.AppOptions) (audit.EnterpriseControlLedgerTrustSource, bool, error) {
	trustedPolicySignersConfig := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_policy_signers")),
		cast.ToString(appOpts.Get("finance.api.enterprise_policy_signers")),
		os.Getenv("AETHELRED_FINANCE_ENTERPRISE_POLICY_SIGNERS"),
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
		RequiredJurisdiction: resolveFinanceEnterpriseRequiredJurisdiction(appOpts),
		AllowedSponsors: parseAuditCSVList(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_allowed_sponsors")),
			cast.ToString(appOpts.Get("finance.api.enterprise_allowed_sponsors")),
			os.Getenv("AETHELRED_FINANCE_ENTERPRISE_ALLOWED_SPONSORS"),
		)),
	})
	if err != nil {
		return nil, false, err
	}
	return trustSource, true, nil
}

func resolveFinanceEnterpriseTrustRegistryPath(appOpts servertypes.AppOptions) string {
	configuredPath := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_trust_registry_path")),
		cast.ToString(appOpts.Get("finance.api.enterprise_trust_registry_path")),
		os.Getenv("AETHELRED_FINANCE_ENTERPRISE_TRUST_REGISTRY_PATH"),
	)
	if configuredPath != "" {
		return filepath.Clean(configuredPath)
	}
	return resolveAuditEnterpriseTrustRegistryPath(appOpts)
}

func resolveFinanceEnterpriseRequiredJurisdiction(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_required_jurisdiction")),
		cast.ToString(appOpts.Get("finance.api.enterprise_required_jurisdiction")),
		os.Getenv("AETHELRED_FINANCE_ENTERPRISE_REQUIRED_JURISDICTION"),
		cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_required_jurisdiction")),
		cast.ToString(appOpts.Get("audit.api.enterprise_required_jurisdiction")),
		os.Getenv("AETHELRED_AUDIT_ENTERPRISE_REQUIRED_JURISDICTION"),
	))
}

func resolveFinanceEnterpriseRequiredRequestAction(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_required_request_action")),
		cast.ToString(appOpts.Get("finance.api.enterprise_required_request_action")),
		os.Getenv("AETHELRED_FINANCE_ENTERPRISE_REQUIRED_REQUEST_ACTION"),
		financeTreasuryReleaseAuthRequestAction,
	))
}

func resolveFinanceEnterpriseRequiredApproveAction(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_required_approve_action")),
		cast.ToString(appOpts.Get("finance.api.enterprise_required_approve_action")),
		os.Getenv("AETHELRED_FINANCE_ENTERPRISE_REQUIRED_APPROVE_ACTION"),
		financeTreasuryReleaseAuthApproveAction,
	))
}

func resolveFinanceEnterpriseRequiredTool(appOpts servertypes.AppOptions) string {
	return strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.api.enterprise_required_tool")),
		cast.ToString(appOpts.Get("finance.api.enterprise_required_tool")),
		os.Getenv("AETHELRED_FINANCE_ENTERPRISE_REQUIRED_TOOL"),
		financeTreasuryReleaseAuthRequiredTool,
	))
}

func allowUnauthenticatedFinanceWrites(appOpts servertypes.AppOptions) bool {
	if cast.ToBool(appOpts.Get("aethelred.finance.api.allow_unauthenticated_writes")) {
		return true
	}
	if cast.ToBool(appOpts.Get("finance.api.allow_unauthenticated_writes")) {
		return true
	}
	return cast.ToBool(os.Getenv("AETHELRED_FINANCE_ALLOW_UNAUTHENTICATED_WRITES"))
}

func (app *AethelredApp) authorizeFinanceTreasuryReleaseInitiate(r *http.Request, req *financeTreasuryReleaseInitiateRequest) (*financeTreasuryReleaseAuthContext, error) {
	if app == nil || app.financeTreasuryReleaseAuth == nil {
		return nil, nil
	}
	return app.financeTreasuryReleaseAuth.AuthorizeInitiate(r, req)
}

func (app *AethelredApp) authorizeFinanceTreasuryReleaseApprove(r *http.Request, workflowID string, req *financeTreasuryReleaseApproveRequest) (*financeTreasuryReleaseAuthContext, error) {
	if app == nil || app.financeTreasuryReleaseAuth == nil {
		return nil, nil
	}
	return app.financeTreasuryReleaseAuth.AuthorizeApprove(r, workflowID, req)
}

func financeAuthorizationStatus(err error, fallback int) int {
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

func financeRequestMetadataWithAuthContext(metadata map[string]string, authCtx *financeTreasuryReleaseAuthContext) map[string]string {
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

func financeApprovalCommentWithAuthContext(comment string, authCtx *financeTreasuryReleaseAuthContext) string {
	trimmedComment := strings.TrimSpace(comment)
	if authCtx == nil || authCtx.Mode != financeTreasuryReleaseEnterpriseActionModeBase {
		return trimmedComment
	}

	annotationParts := []string{"auth=enterprise_policy_receipt"}
	if authCtx.ActorDID != "" {
		annotationParts = append(annotationParts, "actor="+authCtx.ActorDID)
	}
	if authCtx.PolicyReceiptID != "" {
		annotationParts = append(annotationParts, "receipt="+authCtx.PolicyReceiptID)
	}
	annotation := strings.Join(annotationParts, " ")
	if trimmedComment == "" {
		return annotation
	}
	if authCtx.PolicyReceiptID != "" && strings.Contains(trimmedComment, authCtx.PolicyReceiptID) {
		return trimmedComment
	}
	return trimmedComment + " [" + annotation + "]"
}

func financeApprovalMetadataWithAuthContext(metadata map[string]string, authCtx *financeTreasuryReleaseAuthContext) map[string]string {
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
	return out
}

func cloneFinanceMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func resourceCandidatesForFinanceInitiate(resource string) []string {
	resource = strings.TrimSpace(resource)
	candidates := []string{
		financeTreasuryReleaseCollectionRoute,
	}
	if resource != "" {
		candidates = append(candidates, resource, "resource:"+resource)
	}
	return candidates
}

func resourceCandidatesForFinanceApproval(workflowID string) []string {
	workflowID = strings.TrimSpace(workflowID)
	if workflowID == "" {
		return nil
	}
	return []string{
		workflowID,
		"treasury-release:" + workflowID,
		financeTreasuryReleaseItemPrefix + workflowID,
		financeTreasuryReleaseItemPrefix + workflowID + "/approve",
	}
}

func requestContextOrBackground(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}

func resolveFinanceAuthJurisdiction(explicit string, actorIdentity *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, fallback string) string {
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

func financePolicyReceiptAuthorizesAnyResource(resource string, candidates ...string) bool {
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

func financeTrustScopeAllowsAction(allowedActions []string, action string) bool {
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

func financeTrustScopeAllowsJurisdiction(allowedJurisdictions []string, jurisdiction string) bool {
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
