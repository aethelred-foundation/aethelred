package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

const defaultEnterpriseControlLedgerWriteAction = "audit.control_ledger.write"

// EnterpriseControlLedgerWriteConfig configures policy-receipt-backed write
// authorization for control-ledger ingestion.
type EnterpriseControlLedgerWriteConfig struct {
	TrustSource          EnterpriseControlLedgerTrustSource
	TrustedPolicySigners map[string]string
	RequiredAction       string
	RequiredJurisdiction string
	AllowedSponsors      []string
}

// EnterpriseControlLedgerWriteAuthorizer authorizes a control-ledger write
// using an enterprise agent passport and a signed policy receipt from a
// trusted policy signer.
type EnterpriseControlLedgerWriteAuthorizer struct {
	trustSource EnterpriseControlLedgerTrustSource
}

// NewEnterpriseControlLedgerWriteAuthorizer creates an enterprise authorizer.
func NewEnterpriseControlLedgerWriteAuthorizer(cfg EnterpriseControlLedgerWriteConfig) (*EnterpriseControlLedgerWriteAuthorizer, error) {
	trustSource := cfg.TrustSource
	if trustSource == nil {
		var err error
		trustSource, err = NewEnterpriseControlLedgerTrustSourceFromConfig(cfg)
		if err != nil {
			return nil, err
		}
	}

	return &EnterpriseControlLedgerWriteAuthorizer{trustSource: trustSource}, nil
}

// NewEnterpriseControlLedgerTrustSourceFromConfig builds a static trust source
// from startup configuration.
func NewEnterpriseControlLedgerTrustSourceFromConfig(cfg EnterpriseControlLedgerWriteConfig) (EnterpriseControlLedgerTrustSource, error) {
	if cfg.TrustSource != nil {
		return cfg.TrustSource, nil
	}
	return newEnterpriseControlLedgerTrustSourceFromConfig(cfg)
}

func newEnterpriseControlLedgerTrustSourceFromConfig(cfg EnterpriseControlLedgerWriteConfig) (EnterpriseControlLedgerTrustSource, error) {
	if len(cfg.TrustedPolicySigners) == 0 {
		return nil, fmt.Errorf("audit/auth: %w: at least one trusted policy signer is required", ErrInvalidInput)
	}

	policySigners := make(map[string]EnterpriseTrustedPolicySigner, len(cfg.TrustedPolicySigners))
	for signerDID, publicKeyHex := range cfg.TrustedPolicySigners {
		normalizedSignerDID := strings.TrimSpace(signerDID)
		if normalizedSignerDID == "" {
			return nil, fmt.Errorf("audit/auth: %w: trusted signer DID cannot be empty", ErrInvalidInput)
		}
		pubKey, err := parseCompressedP256PublicKeyHex(publicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("audit/auth: invalid public key for trusted signer %q: %w", normalizedSignerDID, err)
		}
		policySigners[normalizedSignerDID] = EnterpriseTrustedPolicySigner{
			DID:       normalizedSignerDID,
			PublicKey: pubKey,
			Status:    TrustRegistryEntryStatusActive,
		}
	}

	allowedSponsors := make(map[string]EnterpriseAllowedSponsor, len(cfg.AllowedSponsors))
	for _, sponsor := range cfg.AllowedSponsors {
		normalizedSponsor := strings.TrimSpace(sponsor)
		if normalizedSponsor == "" {
			continue
		}
		allowedSponsors[normalizedSponsor] = EnterpriseAllowedSponsor{
			DID:    normalizedSponsor,
			Status: TrustRegistryEntryStatusActive,
		}
	}

	snapshot := &EnterpriseControlLedgerTrustSnapshot{
		Version:              "bootstrap-static-config",
		Source:               "startup_config",
		RequiredAction:       normalizeEnterpriseControlLedgerWriteAction(cfg.RequiredAction),
		RequiredJurisdiction: strings.TrimSpace(cfg.RequiredJurisdiction),
		PolicySigners:        policySigners,
		AllowedSponsors:      allowedSponsors,
	}
	return NewStaticEnterpriseControlLedgerTrustSource(snapshot)
}

// Authorize validates enterprise write claims and enriches the stored control
// ledger with verified passport and policy evidence.
func (a *EnterpriseControlLedgerWriteAuthorizer) Authorize(r *http.Request, req *PutControlLedgerRequest) error {
	if a == nil {
		return fmt.Errorf("audit/auth: %w: authorizer is nil", ErrInvalidInput)
	}
	if req == nil || req.Ledger == nil || req.Ledger.Bundle == nil {
		return fmt.Errorf("audit/auth: %w: control ledger is required", ErrInvalidInput)
	}
	if req.EnterpriseAuth == nil {
		return fmt.Errorf("audit/auth: %w: enterprise authorization claims are required", ErrUnauthorized)
	}
	if req.EnterpriseAuth.ActorIdentity == nil {
		return fmt.Errorf("audit/auth: %w: actor identity is required", ErrUnauthorized)
	}
	if req.EnterpriseAuth.PolicyReceipt == nil {
		return fmt.Errorf("audit/auth: %w: signed policy receipt is required", ErrUnauthorized)
	}

	actorIdentity := req.EnterpriseAuth.ActorIdentity
	receipt := req.EnterpriseAuth.PolicyReceipt

	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	snapshot, err := a.trustSource.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("audit/auth: %w: load enterprise trust snapshot: %v", ErrWriteDisabled, err)
	}
	requiredAction := normalizeEnterpriseControlLedgerWriteAction(snapshot.RequiredAction)
	requiredJurisdiction := strings.TrimSpace(snapshot.RequiredJurisdiction)
	requestJurisdiction := resolveEnterpriseWriteJurisdiction(req.Ledger, actorIdentity, receipt, requiredJurisdiction)

	if err := agent.VerifyIdentity(actorIdentity); err != nil {
		return fmt.Errorf("audit/auth: %w: invalid actor identity: %v", ErrUnauthorized, err)
	}

	if actorIdentity.AgentID() != receipt.Actor {
		return fmt.Errorf("audit/auth: %w: receipt actor %q does not match passport DID %q", ErrUnauthorized, receipt.Actor, actorIdentity.AgentID())
	}

	if !strings.EqualFold(receipt.Decision, policy.Allow.String()) {
		return fmt.Errorf("audit/auth: %w: policy decision %q does not authorize control-ledger writes", ErrUnauthorized, receipt.Decision)
	}
	if receipt.Action != requiredAction {
		return fmt.Errorf("audit/auth: %w: policy action %q does not match required action %q", ErrUnauthorized, receipt.Action, requiredAction)
	}
	if !actorIdentity.AllowsTool(requiredAction) && !actorIdentity.HasCapability(requiredAction) {
		return fmt.Errorf("audit/auth: %w: actor passport does not allow tool %q", ErrUnauthorized, requiredAction)
	}

	if requiredJurisdiction != "" {
		if !actorIdentity.HasJurisdiction(requiredJurisdiction) {
			return fmt.Errorf("audit/auth: %w: actor passport does not allow jurisdiction %q", ErrUnauthorized, requiredJurisdiction)
		}
		if ledgerJurisdiction := strings.TrimSpace(req.Ledger.Metadata["jurisdiction"]); ledgerJurisdiction != "" && ledgerJurisdiction != requiredJurisdiction {
			return fmt.Errorf("audit/auth: %w: ledger jurisdiction %q does not match required jurisdiction %q", ErrUnauthorized, ledgerJurisdiction, requiredJurisdiction)
		}
	}

	sponsorOfRecord := ""
	if actorIdentity.Liability != nil {
		sponsorOfRecord = strings.TrimSpace(actorIdentity.Liability.SponsorOfRecord)
	}
	if sponsorOfRecord == "" {
		return fmt.Errorf("audit/auth: %w: sponsor_of_record is required", ErrUnauthorized)
	}
	var sponsorTrustEntry *EnterpriseAllowedSponsor
	if len(snapshot.AllowedSponsors) > 0 {
		entry, ok := snapshot.AllowedSponsors[sponsorOfRecord]
		if !ok {
			return fmt.Errorf("audit/auth: %w: sponsor_of_record %q is not allowed", ErrUnauthorized, sponsorOfRecord)
		}
		if !trustRegistryEntryAllowsWrites(entry.Status) {
			return fmt.Errorf("audit/auth: %w: sponsor_of_record %q is not active", ErrUnauthorized, sponsorOfRecord)
		}
		if !trustScopeAllowsAction(entry.Actions, requiredAction) {
			return fmt.Errorf("audit/auth: %w: sponsor_of_record %q is not trusted for action %q", ErrUnauthorized, sponsorOfRecord, requiredAction)
		}
		if !trustScopeAllowsJurisdiction(entry.Jurisdictions, requestJurisdiction) {
			return fmt.Errorf("audit/auth: %w: sponsor_of_record %q is not trusted for jurisdiction %q", ErrUnauthorized, sponsorOfRecord, requestJurisdiction)
		}
		sponsorTrustEntry = &entry
	}

	signerTrustEntry, ok := snapshot.PolicySigners[receipt.Signer]
	if !ok {
		return fmt.Errorf("audit/auth: %w: untrusted policy signer %q", ErrUnauthorized, receipt.Signer)
	}
	if !trustRegistryEntryAllowsWrites(signerTrustEntry.Status) {
		return fmt.Errorf("audit/auth: %w: policy signer %q is not active", ErrUnauthorized, receipt.Signer)
	}
	if !trustScopeAllowsAction(signerTrustEntry.Actions, requiredAction) {
		return fmt.Errorf("audit/auth: %w: policy signer %q is not trusted for action %q", ErrUnauthorized, receipt.Signer, requiredAction)
	}
	if !trustScopeAllowsJurisdiction(signerTrustEntry.Jurisdictions, requestJurisdiction) {
		return fmt.Errorf("audit/auth: %w: policy signer %q is not trusted for jurisdiction %q", ErrUnauthorized, receipt.Signer, requestJurisdiction)
	}
	if err := policy.VerifySignedPolicyReceipt(receipt, signerTrustEntry.PublicKey); err != nil {
		return fmt.Errorf("audit/auth: %w: invalid signed policy receipt: %v", ErrUnauthorized, err)
	}
	if !policyReceiptAuthorizesLedger(receipt.Resource, req.Ledger.Bundle.ID) {
		return fmt.Errorf("audit/auth: %w: policy receipt resource %q does not authorize ledger %q", ErrUnauthorized, receipt.Resource, req.Ledger.Bundle.ID)
	}

	if err := enrichLedgerWithEnterpriseAuthorization(req.Ledger, actorIdentity, receipt, snapshot, signerTrustEntry, sponsorTrustEntry, requiredAction, requiredJurisdiction, sponsorOfRecord); err != nil {
		return fmt.Errorf("audit/auth: %w", err)
	}

	return nil
}

func normalizeEnterpriseControlLedgerWriteAction(action string) string {
	normalized := strings.TrimSpace(action)
	if normalized == "" {
		return defaultEnterpriseControlLedgerWriteAction
	}
	return normalized
}

func resolveEnterpriseWriteJurisdiction(ledger *evidence.ControlLedger, actorIdentity *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, requiredJurisdiction string) string {
	if strings.TrimSpace(requiredJurisdiction) != "" {
		return strings.TrimSpace(requiredJurisdiction)
	}
	if ledger != nil {
		if jurisdiction := strings.TrimSpace(ledger.Metadata["jurisdiction"]); jurisdiction != "" {
			return jurisdiction
		}
	}
	if receipt != nil {
		if jurisdiction := strings.TrimSpace(receipt.Context["jurisdiction"]); jurisdiction != "" {
			return jurisdiction
		}
	}
	if actorIdentity != nil {
		for _, jurisdiction := range actorIdentity.JurisdictionTags {
			if normalized := strings.TrimSpace(jurisdiction); normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func trustRegistryEntryAllowsWrites(status TrustRegistryEntryStatus) bool {
	switch strings.ToLower(strings.TrimSpace(string(status))) {
	case "", string(TrustRegistryEntryStatusActive):
		return true
	default:
		return false
	}
}

func trustScopeAllowsAction(allowedActions []string, action string) bool {
	if len(allowedActions) == 0 || strings.TrimSpace(action) == "" {
		return true
	}
	for _, candidate := range allowedActions {
		if strings.TrimSpace(candidate) == action {
			return true
		}
	}
	return false
}

func trustScopeAllowsJurisdiction(allowedJurisdictions []string, jurisdiction string) bool {
	if len(allowedJurisdictions) == 0 || strings.TrimSpace(jurisdiction) == "" {
		return true
	}
	for _, candidate := range allowedJurisdictions {
		if strings.TrimSpace(candidate) == jurisdiction {
			return true
		}
	}
	return false
}

func enrichLedgerWithEnterpriseAuthorization(ledger *evidence.ControlLedger, actorIdentity *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, snapshot *EnterpriseControlLedgerTrustSnapshot, signerTrustEntry EnterpriseTrustedPolicySigner, sponsorTrustEntry *EnterpriseAllowedSponsor, requiredAction string, requiredJurisdiction string, sponsorOfRecord string) error {
	if ledger == nil || ledger.Bundle == nil {
		return fmt.Errorf("audit/auth: %w: control ledger is required", ErrInvalidInput)
	}

	hasPassport := false
	for _, passport := range ledger.Bundle.AgentPassports {
		if passport.DID == actorIdentity.AgentID() {
			hasPassport = true
			break
		}
	}
	if !hasPassport {
		passportEvidence, err := evidence.NewAgentPassportEvidence(actorIdentity)
		if err != nil {
			return fmt.Errorf("audit/auth: create passport evidence: %w", err)
		}
		ledger.AddAgentPassport(passportEvidence)
	}

	hasReceipt := false
	for _, existingReceipt := range ledger.Bundle.PolicyReceipts {
		if existingReceipt.ID == receipt.ID {
			hasReceipt = true
			break
		}
	}
	if !hasReceipt {
		receiptEvidence, err := evidence.NewPolicyReceiptEvidence(receipt)
		if err != nil {
			return fmt.Errorf("audit/auth: create policy receipt evidence: %w", err)
		}
		ledger.AddPolicyReceipt(receiptEvidence)
	}

	ledger.WithMetadata("auth.mode", "enterprise_policy_receipt")
	ledger.WithMetadata("auth.actor_did", actorIdentity.AgentID())
	ledger.WithMetadata("auth.policy_receipt_id", receipt.ID)
	ledger.WithMetadata("auth.policy_signer", receipt.Signer)
	ledger.WithMetadata("auth.required_action", requiredAction)
	ledger.WithMetadata("auth.sponsor_of_record", sponsorOfRecord)
	ledger.WithMetadata("auth.policy_signer_status", string(signerTrustEntry.Status))
	if snapshot != nil {
		if trustProvider := strings.TrimSpace(snapshot.Metadata[trustRegistryMetadataProviderKey]); trustProvider != "" {
			ledger.WithMetadata("auth.trust_provider", trustProvider)
		}
		if snapshot.Source != "" {
			ledger.WithMetadata("auth.trust_source", snapshot.Source)
		}
		if snapshot.Version != "" {
			ledger.WithMetadata("auth.trust_registry_version", snapshot.Version)
		}
		if snapshot.UpdatedAt != "" {
			ledger.WithMetadata("auth.trust_registry_updated_at", snapshot.UpdatedAt)
		}
	}
	if sponsorTrustEntry != nil && sponsorTrustEntry.Status != "" {
		ledger.WithMetadata("auth.sponsor_status", string(sponsorTrustEntry.Status))
	}
	if requiredJurisdiction != "" {
		ledger.WithMetadata("auth.required_jurisdiction", requiredJurisdiction)
		if strings.TrimSpace(ledger.Metadata["jurisdiction"]) == "" {
			ledger.WithMetadata("jurisdiction", requiredJurisdiction)
		}
	}
	if !receipt.EvaluatedAt.IsZero() {
		ledger.WithMetadata("auth.policy_evaluated_at", receipt.EvaluatedAt.Format(time.RFC3339Nano))
	}

	return nil
}

func policyReceiptAuthorizesLedger(resource string, ledgerID string) bool {
	resource = strings.TrimSpace(resource)
	ledgerID = strings.TrimSpace(ledgerID)
	if resource == "" || ledgerID == "" {
		return false
	}
	return resource == ledgerID ||
		resource == "control-ledger:"+ledgerID ||
		resource == "control-ledgers/"+ledgerID ||
		resource == "/api/v1/audit/control-ledgers/"+ledgerID
}

func parseCompressedP256PublicKeyHex(publicKeyHex string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid compressed P-256 public key encoding")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
