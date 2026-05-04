package audit

import (
	"context"
	"fmt"
	"strings"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// PromoteEnterpriseAuditTrustRegistryToGovernedKeeper persists an enterprise
// trust registry through the keeper's authority-gated governance path so the
// activation itself becomes part of the audited trust chain.
func PromoteEnterpriseAuditTrustRegistryToGovernedKeeper(
	keeper *pouwkeeper.Keeper,
	ctx context.Context,
	registry *pouwkeeper.EnterpriseAuditTrustRegistry,
	bootstrapMode string,
	reason string,
	requestedBy string,
) (*pouwkeeper.EnterpriseAuditTrustRegistry, error) {
	if keeper == nil {
		return nil, fmt.Errorf("audit/trust: %w: pouw keeper is required", ErrInvalidInput)
	}
	if ctx == nil {
		return nil, fmt.Errorf("audit/trust: %w: keeper context is required", ErrInvalidInput)
	}
	if registry == nil {
		return nil, fmt.Errorf("audit/trust: %w: enterprise trust registry is required", ErrInvalidInput)
	}

	prepared := clonePouwEnterpriseAuditTrustRegistry(registry)
	annotateGovernedBootstrapMetadata(prepared, bootstrapMode)

	if _, err := keeper.SetEnterpriseAuditTrustRegistryByAuthority(
		ctx,
		keeper.GetAuthority(),
		prepared,
		reason,
		requestedBy,
	); err != nil {
		return nil, fmt.Errorf("audit/trust: promote enterprise trust registry into governed keeper state: %w", err)
	}

	promoted, err := keeper.GetEnterpriseAuditTrustRegistry(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit/trust: reload promoted enterprise trust registry: %w", err)
	}
	return promoted, nil
}

// PromoteEnterpriseTrustSnapshotToGovernedKeeper converts a runtime trust
// snapshot into keeper registry state and persists it through governance.
func PromoteEnterpriseTrustSnapshotToGovernedKeeper(
	keeper *pouwkeeper.Keeper,
	ctx context.Context,
	snapshot *EnterpriseControlLedgerTrustSnapshot,
	bootstrapMode string,
	reason string,
	requestedBy string,
) (*pouwkeeper.EnterpriseAuditTrustRegistry, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("audit/trust: %w: enterprise trust snapshot is required", ErrInvalidInput)
	}
	registry := convertEnterpriseTrustSnapshotToPouwRegistry(snapshot)
	if registry == nil {
		return nil, fmt.Errorf("audit/trust: %w: fallback trust snapshot could not be converted", ErrInvalidInput)
	}
	return PromoteEnterpriseAuditTrustRegistryToGovernedKeeper(keeper, ctx, registry, bootstrapMode, reason, requestedBy)
}

func annotateGovernedBootstrapMetadata(registry *pouwkeeper.EnterpriseAuditTrustRegistry, bootstrapMode string) {
	if registry == nil {
		return
	}
	if registry.Metadata == nil {
		registry.Metadata = make(map[string]string, 4)
	}
	if trimmedMode := strings.TrimSpace(bootstrapMode); trimmedMode != "" {
		registry.Metadata["bootstrap_mode"] = trimmedMode
	}
	if declaredSource := strings.TrimSpace(registry.Source); declaredSource != "" {
		registry.Metadata["bootstrap_declared_source"] = declaredSource
	}
	if declaredProvider := strings.TrimSpace(registry.Metadata[trustRegistryMetadataProviderKey]); declaredProvider != "" {
		registry.Metadata["bootstrap_declared_provider"] = declaredProvider
	}
}

func clonePouwEnterpriseAuditTrustRegistry(registry *pouwkeeper.EnterpriseAuditTrustRegistry) *pouwkeeper.EnterpriseAuditTrustRegistry {
	if registry == nil {
		return nil
	}
	out := &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySigners:        make([]pouwkeeper.EnterpriseAuditPolicySignerTrustEntry, 0, len(registry.PolicySigners)),
		AllowedSponsors:      make([]pouwkeeper.EnterpriseAuditSponsorTrustEntry, 0, len(registry.AllowedSponsors)),
		Metadata:             cloneStringMapPreserve(registry.Metadata),
	}
	for _, signer := range registry.PolicySigners {
		out.PolicySigners = append(out.PolicySigners, pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{
			DID:           signer.DID,
			PublicKeyHex:  signer.PublicKeyHex,
			Status:        signer.Status,
			Actions:       cloneStringSlicePreserve(signer.Actions),
			Jurisdictions: cloneStringSlicePreserve(signer.Jurisdictions),
			Metadata:      cloneStringMapPreserve(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, pouwkeeper.EnterpriseAuditSponsorTrustEntry{
			DID:           sponsor.DID,
			Status:        sponsor.Status,
			Actions:       cloneStringSlicePreserve(sponsor.Actions),
			Jurisdictions: cloneStringSlicePreserve(sponsor.Jurisdictions),
			Metadata:      cloneStringMapPreserve(sponsor.Metadata),
		})
	}
	return out
}
