package audit

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// PouwKeeperEnterpriseControlLedgerTrustSource resolves enterprise audit trust
// from keeper-backed state, with an optional fallback source for bootstrap or
// file-based deployments.
type PouwKeeperEnterpriseControlLedgerTrustSource struct {
	keeper          *pouwkeeper.Keeper
	contextProvider func() context.Context
	fallback        EnterpriseControlLedgerTrustSource
}

const (
	enterpriseTrustBootstrapModeLazyFallbackPromotion      = "lazy_fallback_promotion"
	enterpriseTrustBootstrapReasonLazyFallbackPromotion    = "promote fallback enterprise trust registry into governed keeper state"
	enterpriseTrustBootstrapRequestedByLazyFallbackPromote = "audit_trust_source_promotion"
)

func NewPouwKeeperEnterpriseControlLedgerTrustSource(
	keeper *pouwkeeper.Keeper,
	contextProvider func() context.Context,
	fallback EnterpriseControlLedgerTrustSource,
) (*PouwKeeperEnterpriseControlLedgerTrustSource, error) {
	if keeper == nil {
		return nil, fmt.Errorf("audit/trust: %w: pouw keeper is required", ErrInvalidInput)
	}
	if contextProvider == nil {
		return nil, fmt.Errorf("audit/trust: %w: context provider is required", ErrInvalidInput)
	}
	return &PouwKeeperEnterpriseControlLedgerTrustSource{
		keeper:          keeper,
		contextProvider: contextProvider,
		fallback:        fallback,
	}, nil
}

func (s *PouwKeeperEnterpriseControlLedgerTrustSource) Snapshot(ctx context.Context) (*EnterpriseControlLedgerTrustSnapshot, error) {
	if s == nil || s.keeper == nil || s.contextProvider == nil {
		return nil, fmt.Errorf("audit/trust: %w: keeper-backed trust source is not configured", ErrInvalidInput)
	}

	keeperCtx := s.contextProvider()
	if keeperCtx == nil {
		if s.fallback != nil {
			return s.fallback.Snapshot(ctx)
		}
		return nil, fmt.Errorf("audit/trust: %w: keeper context is unavailable", ErrWriteDisabled)
	}

	registry, err := s.keeper.GetEnterpriseAuditTrustRegistry(keeperCtx)
	if err == nil {
		return convertPouwEnterpriseAuditTrustRegistry(registry)
	}
	if errors.Is(err, pouwkeeper.ErrEnterpriseAuditTrustRegistryNotConfigured) {
		if s.fallback != nil {
			fallbackSnapshot, fallbackErr := s.fallback.Snapshot(ctx)
			if fallbackErr != nil {
				return nil, fallbackErr
			}
			promoted, promoteErr := PromoteEnterpriseTrustSnapshotToGovernedKeeper(
				s.keeper,
				keeperCtx,
				fallbackSnapshot,
				enterpriseTrustBootstrapModeLazyFallbackPromotion,
				enterpriseTrustBootstrapReasonLazyFallbackPromotion,
				enterpriseTrustBootstrapRequestedByLazyFallbackPromote,
			)
			if promoteErr != nil {
				return nil, promoteErr
			}
			return convertPouwEnterpriseAuditTrustRegistry(promoted)
		}
		return nil, fmt.Errorf("audit/trust: %w: no keeper-backed or fallback enterprise trust registry is configured", ErrWriteDisabled)
	}
	return nil, fmt.Errorf("audit/trust: load pouw enterprise trust registry: %w", err)
}

func convertPouwEnterpriseAuditTrustRegistry(registry *pouwkeeper.EnterpriseAuditTrustRegistry) (*EnterpriseControlLedgerTrustSnapshot, error) {
	if registry == nil {
		return nil, fmt.Errorf("audit/trust: %w: pouw enterprise trust registry is required", ErrInvalidInput)
	}

	snapshot := &EnterpriseControlLedgerTrustSnapshot{
		Version:              strings.TrimSpace(registry.Version),
		Source:               strings.TrimSpace(registry.Source),
		UpdatedAt:            strings.TrimSpace(registry.UpdatedAt),
		RequiredAction:       normalizeEnterpriseControlLedgerWriteAction(registry.RequiredAction),
		RequiredJurisdiction: strings.TrimSpace(registry.RequiredJurisdiction),
		PolicySigners:        make(map[string]EnterpriseTrustedPolicySigner, len(registry.PolicySigners)),
		AllowedSponsors:      make(map[string]EnterpriseAllowedSponsor, len(registry.AllowedSponsors)),
		Metadata:             cloneStringMapPreserve(registry.Metadata),
	}
	if snapshot.Source == "" {
		snapshot.Source = "pouw_keeper"
	}
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string, 1)
	}
	snapshot.Metadata[trustRegistryMetadataProviderKey] = "pouw_keeper"

	for _, signer := range registry.PolicySigners {
		normalizedDID := strings.TrimSpace(signer.DID)
		if normalizedDID == "" {
			return nil, fmt.Errorf("audit/trust: %w: pouw policy signer DID cannot be empty", ErrInvalidInput)
		}
		publicKey, err := parseCompressedP256PublicKeyHex(signer.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("audit/trust: invalid pouw policy signer %q public key: %w", normalizedDID, err)
		}
		status, err := normalizeTrustRegistryEntryStatus(TrustRegistryEntryStatus(signer.Status))
		if err != nil {
			return nil, fmt.Errorf("audit/trust: invalid pouw policy signer %q status: %w", normalizedDID, err)
		}
		snapshot.PolicySigners[normalizedDID] = EnterpriseTrustedPolicySigner{
			DID:           normalizedDID,
			PublicKey:     publicKey,
			Status:        status,
			Actions:       normalizeTrustScopeValues(signer.Actions),
			Jurisdictions: normalizeTrustScopeValues(signer.Jurisdictions),
			Metadata:      cloneStringMapPreserve(signer.Metadata),
		}
	}

	for _, sponsor := range registry.AllowedSponsors {
		normalizedDID := strings.TrimSpace(sponsor.DID)
		if normalizedDID == "" {
			return nil, fmt.Errorf("audit/trust: %w: pouw sponsor DID cannot be empty", ErrInvalidInput)
		}
		status, err := normalizeTrustRegistryEntryStatus(TrustRegistryEntryStatus(sponsor.Status))
		if err != nil {
			return nil, fmt.Errorf("audit/trust: invalid pouw sponsor %q status: %w", normalizedDID, err)
		}
		snapshot.AllowedSponsors[normalizedDID] = EnterpriseAllowedSponsor{
			DID:           normalizedDID,
			Status:        status,
			Actions:       normalizeTrustScopeValues(sponsor.Actions),
			Jurisdictions: normalizeTrustScopeValues(sponsor.Jurisdictions),
			Metadata:      cloneStringMapPreserve(sponsor.Metadata),
		}
	}

	if err := validateEnterpriseControlLedgerTrustSnapshot(snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func convertEnterpriseTrustSnapshotToPouwRegistry(snapshot *EnterpriseControlLedgerTrustSnapshot) *pouwkeeper.EnterpriseAuditTrustRegistry {
	if snapshot == nil {
		return nil
	}
	registry := &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              strings.TrimSpace(snapshot.Version),
		Source:               strings.TrimSpace(snapshot.Source),
		UpdatedAt:            strings.TrimSpace(snapshot.UpdatedAt),
		RequiredAction:       strings.TrimSpace(snapshot.RequiredAction),
		RequiredJurisdiction: strings.TrimSpace(snapshot.RequiredJurisdiction),
		PolicySigners:        make([]pouwkeeper.EnterpriseAuditPolicySignerTrustEntry, 0, len(snapshot.PolicySigners)),
		AllowedSponsors:      make([]pouwkeeper.EnterpriseAuditSponsorTrustEntry, 0, len(snapshot.AllowedSponsors)),
		Metadata:             cloneStringMapPreserve(snapshot.Metadata),
	}

	for did, signer := range snapshot.PolicySigners {
		if signer.PublicKey == nil || signer.PublicKey.X == nil || signer.PublicKey.Y == nil {
			return nil
		}
		registry.PolicySigners = append(registry.PolicySigners, pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{
			DID:           did,
			PublicKeyHex:  hex.EncodeToString(elliptic.MarshalCompressed(signer.PublicKey.Curve, signer.PublicKey.X, signer.PublicKey.Y)),
			Status:        pouwkeeper.EnterpriseAuditTrustEntryStatus(signer.Status),
			Actions:       append([]string(nil), signer.Actions...),
			Jurisdictions: append([]string(nil), signer.Jurisdictions...),
			Metadata:      cloneStringMapPreserve(signer.Metadata),
		})
	}
	for did, sponsor := range snapshot.AllowedSponsors {
		registry.AllowedSponsors = append(registry.AllowedSponsors, pouwkeeper.EnterpriseAuditSponsorTrustEntry{
			DID:           did,
			Status:        pouwkeeper.EnterpriseAuditTrustEntryStatus(sponsor.Status),
			Actions:       append([]string(nil), sponsor.Actions...),
			Jurisdictions: append([]string(nil), sponsor.Jurisdictions...),
			Metadata:      cloneStringMapPreserve(sponsor.Metadata),
		})
	}
	return registry
}
