package audit

import (
	"context"
	"errors"
	"fmt"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// EnterpriseTrustRegistryService exposes managed enterprise trust-registry
// operations for the audit API.
type EnterpriseTrustRegistryService interface {
	GetEnterpriseTrustRegistry(ctx context.Context, req *GetEnterpriseTrustRegistryRequest) (*GetEnterpriseTrustRegistryResponse, error)
	GetEnterpriseTrustRegistryStatus(ctx context.Context, req *GetEnterpriseTrustRegistryStatusRequest) (*GetEnterpriseTrustRegistryStatusResponse, error)
	PutEnterpriseTrustRegistry(ctx context.Context, req *PutEnterpriseTrustRegistryRequest) (*PutEnterpriseTrustRegistryResponse, error)
	DeleteEnterpriseTrustRegistry(ctx context.Context, req *DeleteEnterpriseTrustRegistryRequest) (*DeleteEnterpriseTrustRegistryResponse, error)
}

// PouwKeeperEnterpriseTrustRegistryService manages the live enterprise trust
// registry stored in the PoUW keeper.
type PouwKeeperEnterpriseTrustRegistryService struct {
	keeper              *pouwkeeper.Keeper
	contextProvider     func() context.Context
	auditLoggerProvider func() *pouwkeeper.AuditLogger
}

// NewPouwKeeperEnterpriseTrustRegistryService creates a keeper-backed trust
// registry management service.
func NewPouwKeeperEnterpriseTrustRegistryService(
	keeper *pouwkeeper.Keeper,
	contextProvider func() context.Context,
	auditLoggerProvider func() *pouwkeeper.AuditLogger,
) (*PouwKeeperEnterpriseTrustRegistryService, error) {
	if keeper == nil {
		return nil, fmt.Errorf("audit/trust-registry: %w: pouw keeper is required", ErrInvalidInput)
	}
	if contextProvider == nil {
		return nil, fmt.Errorf("audit/trust-registry: %w: context provider is required", ErrInvalidInput)
	}
	return &PouwKeeperEnterpriseTrustRegistryService{
		keeper:              keeper,
		contextProvider:     contextProvider,
		auditLoggerProvider: auditLoggerProvider,
	}, nil
}

// GetEnterpriseTrustRegistry returns the normalized active trust registry.
func (s *PouwKeeperEnterpriseTrustRegistryService) GetEnterpriseTrustRegistry(_ context.Context, _ *GetEnterpriseTrustRegistryRequest) (*GetEnterpriseTrustRegistryResponse, error) {
	runtimeCtx, err := s.runtimeContext()
	if err != nil {
		return nil, err
	}

	registry, err := s.keeper.GetEnterpriseAuditTrustRegistry(runtimeCtx)
	if err != nil {
		if errors.Is(err, pouwkeeper.ErrEnterpriseAuditTrustRegistryNotConfigured) {
			return nil, fmt.Errorf("audit/trust-registry: %w", ErrTrustRegistryNotConfigured)
		}
		return nil, fmt.Errorf("audit/trust-registry: load registry: %w", err)
	}
	return &GetEnterpriseTrustRegistryResponse{
		Registry: enterpriseTrustRegistryFromPouw(registry),
	}, nil
}

// GetEnterpriseTrustRegistryStatus returns a normalized status summary for the
// active trust registry.
func (s *PouwKeeperEnterpriseTrustRegistryService) GetEnterpriseTrustRegistryStatus(_ context.Context, _ *GetEnterpriseTrustRegistryStatusRequest) (*GetEnterpriseTrustRegistryStatusResponse, error) {
	runtimeCtx, err := s.runtimeContext()
	if err != nil {
		return nil, err
	}

	status, err := s.keeper.GetEnterpriseAuditTrustRegistryStatus(runtimeCtx)
	if err != nil {
		return nil, fmt.Errorf("audit/trust-registry: load status: %w", err)
	}
	return &GetEnterpriseTrustRegistryStatusResponse{
		Status: enterpriseTrustRegistryStatusFromPouw(status),
	}, nil
}

// PutEnterpriseTrustRegistry validates, persists, and audits a trust-registry
// update.
func (s *PouwKeeperEnterpriseTrustRegistryService) PutEnterpriseTrustRegistry(_ context.Context, req *PutEnterpriseTrustRegistryRequest) (*PutEnterpriseTrustRegistryResponse, error) {
	if req == nil || req.Registry == nil {
		return nil, fmt.Errorf("audit/trust-registry: %w: registry is required", ErrInvalidInput)
	}

	runtimeCtx, err := s.runtimeContext()
	if err != nil {
		return nil, err
	}

	if _, err := s.keeper.SetEnterpriseAuditTrustRegistryByAuthority(
		runtimeCtx,
		s.keeper.GetAuthority(),
		enterpriseTrustRegistryToPouw(req.Registry),
		req.Reason,
		req.Actor,
	); err != nil {
		return nil, fmt.Errorf("audit/trust-registry: persist registry: %w", err)
	}

	registry, err := s.keeper.GetEnterpriseAuditTrustRegistry(runtimeCtx)
	if err != nil {
		return nil, fmt.Errorf("audit/trust-registry: reload registry: %w", err)
	}
	status, err := s.keeper.GetEnterpriseAuditTrustRegistryStatus(runtimeCtx)
	if err != nil {
		return nil, fmt.Errorf("audit/trust-registry: reload status: %w", err)
	}

	return &PutEnterpriseTrustRegistryResponse{
		Registry: enterpriseTrustRegistryFromPouw(registry),
		Status:   enterpriseTrustRegistryStatusFromPouw(status),
	}, nil
}

// DeleteEnterpriseTrustRegistry clears the active trust registry and records an
// immutable governance audit event.
func (s *PouwKeeperEnterpriseTrustRegistryService) DeleteEnterpriseTrustRegistry(_ context.Context, req *DeleteEnterpriseTrustRegistryRequest) (*DeleteEnterpriseTrustRegistryResponse, error) {
	runtimeCtx, err := s.runtimeContext()
	if err != nil {
		return nil, err
	}

	var previousRegistry *pouwkeeper.EnterpriseAuditTrustRegistry

	if registry, registryErr := s.keeper.GetEnterpriseAuditTrustRegistry(runtimeCtx); registryErr == nil {
		previousRegistry = registry
	}

	status, err := s.keeper.ClearEnterpriseAuditTrustRegistryByAuthority(
		runtimeCtx,
		s.keeper.GetAuthority(),
		req.Reason,
		req.Actor,
	)
	if err != nil {
		return nil, fmt.Errorf("audit/trust-registry: clear registry: %w", err)
	}

	return &DeleteEnterpriseTrustRegistryResponse{
		Cleared: previousRegistry != nil,
		Status:  enterpriseTrustRegistryStatusFromPouw(status),
	}, nil
}

func (s *PouwKeeperEnterpriseTrustRegistryService) runtimeContext() (context.Context, error) {
	if s == nil || s.contextProvider == nil {
		return nil, fmt.Errorf("audit/trust-registry: %w: context provider is required", ErrInvalidInput)
	}
	runtimeCtx := s.contextProvider()
	if runtimeCtx == nil {
		return nil, fmt.Errorf("audit/trust-registry: %w: keeper context is unavailable", ErrWriteDisabled)
	}
	return runtimeCtx, nil
}

func enterpriseTrustRegistryFromPouw(registry *pouwkeeper.EnterpriseAuditTrustRegistry) *EnterpriseControlLedgerTrustRegistry {
	if registry == nil {
		return nil
	}
	out := &EnterpriseControlLedgerTrustRegistry{
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySigners:        make([]EnterprisePolicySignerTrustEntry, 0, len(registry.PolicySigners)),
		AllowedSponsors:      make([]EnterpriseSponsorTrustEntry, 0, len(registry.AllowedSponsors)),
		Metadata:             cloneStringMapPreserve(registry.Metadata),
	}
	for _, signer := range registry.PolicySigners {
		out.PolicySigners = append(out.PolicySigners, EnterprisePolicySignerTrustEntry{
			DID:           signer.DID,
			PublicKeyHex:  signer.PublicKeyHex,
			Status:        TrustRegistryEntryStatus(signer.Status),
			Actions:       append([]string(nil), signer.Actions...),
			Jurisdictions: append([]string(nil), signer.Jurisdictions...),
			Metadata:      cloneStringMapPreserve(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, EnterpriseSponsorTrustEntry{
			DID:           sponsor.DID,
			Status:        TrustRegistryEntryStatus(sponsor.Status),
			Actions:       append([]string(nil), sponsor.Actions...),
			Jurisdictions: append([]string(nil), sponsor.Jurisdictions...),
			Metadata:      cloneStringMapPreserve(sponsor.Metadata),
		})
	}
	return out
}

func enterpriseTrustRegistryToPouw(registry *EnterpriseControlLedgerTrustRegistry) *pouwkeeper.EnterpriseAuditTrustRegistry {
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
			Status:        pouwkeeper.EnterpriseAuditTrustEntryStatus(signer.Status),
			Actions:       append([]string(nil), signer.Actions...),
			Jurisdictions: append([]string(nil), signer.Jurisdictions...),
			Metadata:      cloneStringMapPreserve(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, pouwkeeper.EnterpriseAuditSponsorTrustEntry{
			DID:           sponsor.DID,
			Status:        pouwkeeper.EnterpriseAuditTrustEntryStatus(sponsor.Status),
			Actions:       append([]string(nil), sponsor.Actions...),
			Jurisdictions: append([]string(nil), sponsor.Jurisdictions...),
			Metadata:      cloneStringMapPreserve(sponsor.Metadata),
		})
	}
	return out
}

func enterpriseTrustRegistryStatusFromPouw(status *pouwkeeper.EnterpriseAuditTrustRegistryStatus) *EnterpriseControlLedgerTrustRegistryStatus {
	if status == nil {
		return &EnterpriseControlLedgerTrustRegistryStatus{}
	}
	return &EnterpriseControlLedgerTrustRegistryStatus{
		Configured:              status.Configured,
		Version:                 status.Version,
		Source:                  status.Source,
		UpdatedAt:               status.UpdatedAt,
		RequiredAction:          status.RequiredAction,
		RequiredJurisdiction:    status.RequiredJurisdiction,
		PolicySignerCount:       status.PolicySignerCount,
		ActivePolicySignerCount: status.ActivePolicySignerCount,
		AllowedSponsorCount:     status.AllowedSponsorCount,
		ActiveSponsorCount:      status.ActiveSponsorCount,
	}
}
