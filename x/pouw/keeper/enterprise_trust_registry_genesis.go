package keeper

import (
	"context"
	"errors"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	enterpriseAuditTrustGenesisBootstrapMode  = "genesis_init"
	enterpriseAuditTrustGenesisBootstrapActor = "pouw_genesis"
	enterpriseAuditTrustGenesisBootstrapCause = "initialize enterprise audit trust registry from genesis"
)

// InitManagedGenesis initializes standard pouw state plus the optional
// enterprise audit trust registry carried in the JSON-managed genesis document.
func (k Keeper) InitManagedGenesis(ctx context.Context, gs *types.ManagedGenesisState) error {
	if gs == nil {
		gs = types.DefaultManagedGenesis()
	}
	if err := k.InitGenesis(ctx, gs.BaseGenesisState()); err != nil {
		return err
	}
	if gs.EnterpriseAuditTrustRegistry != nil {
		if err := k.importEnterpriseAuditTrustRegistryGenesis(ctx, gs.EnterpriseAuditTrustRegistry); err != nil {
			return err
		}
	}
	return nil
}

// ExportManagedGenesis exports standard pouw state plus the optional enterprise
// audit trust registry in JSON-managed form.
func (k Keeper) ExportManagedGenesis(ctx context.Context) (*types.ManagedGenesisState, error) {
	base, err := k.ExportGenesis(ctx)
	if err != nil {
		return nil, err
	}
	registry, err := k.exportEnterpriseAuditTrustRegistryGenesis(ctx)
	if err != nil {
		return nil, err
	}
	return types.NewManagedGenesisState(base, registry), nil
}

func (k Keeper) importEnterpriseAuditTrustRegistryGenesis(ctx context.Context, registry *types.EnterpriseAuditTrustRegistryGenesis) error {
	if registry == nil {
		return nil
	}
	keeperRegistry := enterpriseAuditTrustRegistryFromGenesis(registry)
	if keeperRegistry.Metadata == nil {
		keeperRegistry.Metadata = make(map[string]string, 2)
	}
	keeperRegistry.Metadata["bootstrap_mode"] = enterpriseAuditTrustGenesisBootstrapMode
	if declaredSource := keeperRegistry.Source; declaredSource != "" {
		keeperRegistry.Metadata["bootstrap_declared_source"] = declaredSource
	}
	_, err := k.SetEnterpriseAuditTrustRegistryByAuthority(
		ctx,
		k.GetAuthority(),
		keeperRegistry,
		enterpriseAuditTrustGenesisBootstrapCause,
		enterpriseAuditTrustGenesisBootstrapActor,
	)
	return err
}

func (k Keeper) exportEnterpriseAuditTrustRegistryGenesis(ctx context.Context) (*types.EnterpriseAuditTrustRegistryGenesis, error) {
	registry, err := k.GetEnterpriseAuditTrustRegistry(ctx)
	if err != nil {
		if errors.Is(err, ErrEnterpriseAuditTrustRegistryNotConfigured) {
			return nil, nil
		}
		return nil, err
	}
	return enterpriseAuditTrustRegistryToGenesis(registry), nil
}

func enterpriseAuditTrustRegistryFromGenesis(registry *types.EnterpriseAuditTrustRegistryGenesis) *EnterpriseAuditTrustRegistry {
	if registry == nil {
		return nil
	}
	out := &EnterpriseAuditTrustRegistry{
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySigners:        make([]EnterpriseAuditPolicySignerTrustEntry, 0, len(registry.PolicySigners)),
		AllowedSponsors:      make([]EnterpriseAuditSponsorTrustEntry, 0, len(registry.AllowedSponsors)),
		Metadata:             cloneEnterpriseAuditTrustStringMap(registry.Metadata),
	}
	for _, signer := range registry.PolicySigners {
		out.PolicySigners = append(out.PolicySigners, EnterpriseAuditPolicySignerTrustEntry{
			DID:           signer.DID,
			PublicKeyHex:  signer.PublicKeyHex,
			Status:        EnterpriseAuditTrustEntryStatus(signer.Status),
			Actions:       append([]string(nil), signer.Actions...),
			Jurisdictions: append([]string(nil), signer.Jurisdictions...),
			Metadata:      cloneEnterpriseAuditTrustStringMap(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, EnterpriseAuditSponsorTrustEntry{
			DID:           sponsor.DID,
			Status:        EnterpriseAuditTrustEntryStatus(sponsor.Status),
			Actions:       append([]string(nil), sponsor.Actions...),
			Jurisdictions: append([]string(nil), sponsor.Jurisdictions...),
			Metadata:      cloneEnterpriseAuditTrustStringMap(sponsor.Metadata),
		})
	}
	return out
}

func enterpriseAuditTrustRegistryToGenesis(registry *EnterpriseAuditTrustRegistry) *types.EnterpriseAuditTrustRegistryGenesis {
	if registry == nil {
		return nil
	}
	out := &types.EnterpriseAuditTrustRegistryGenesis{
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySigners:        make([]types.EnterpriseAuditPolicySignerTrustEntryGenesis, 0, len(registry.PolicySigners)),
		AllowedSponsors:      make([]types.EnterpriseAuditSponsorTrustEntryGenesis, 0, len(registry.AllowedSponsors)),
		Metadata:             cloneEnterpriseAuditTrustStringMap(registry.Metadata),
	}
	for _, signer := range registry.PolicySigners {
		out.PolicySigners = append(out.PolicySigners, types.EnterpriseAuditPolicySignerTrustEntryGenesis{
			DID:           signer.DID,
			PublicKeyHex:  signer.PublicKeyHex,
			Status:        types.EnterpriseAuditTrustRegistryEntryStatus(signer.Status),
			Actions:       append([]string(nil), signer.Actions...),
			Jurisdictions: append([]string(nil), signer.Jurisdictions...),
			Metadata:      cloneEnterpriseAuditTrustStringMap(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, types.EnterpriseAuditSponsorTrustEntryGenesis{
			DID:           sponsor.DID,
			Status:        types.EnterpriseAuditTrustRegistryEntryStatus(sponsor.Status),
			Actions:       append([]string(nil), sponsor.Actions...),
			Jurisdictions: append([]string(nil), sponsor.Jurisdictions...),
			Metadata:      cloneEnterpriseAuditTrustStringMap(sponsor.Metadata),
		})
	}
	return out
}
