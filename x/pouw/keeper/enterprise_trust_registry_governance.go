package keeper

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// MsgUpdateEnterpriseAuditTrustRegistry -- manually defined until proto is
// regenerated. Once the proto toolchain produces this message, delete these
// types and import the generated ones instead.
// ---------------------------------------------------------------------------

// MsgUpdateEnterpriseAuditTrustRegistry defines a governance-controlled update
// for the enterprise audit trust registry.
type MsgUpdateEnterpriseAuditTrustRegistry struct {
	Authority   string
	Registry    *EnterpriseAuditTrustRegistry
	Clear       bool
	Reason      string
	RequestedBy string
}

// MsgUpdateEnterpriseAuditTrustRegistryResponse reports the normalized
// configured state after applying the update.
type MsgUpdateEnterpriseAuditTrustRegistryResponse struct {
	Configured              bool
	Version                 string
	Source                  string
	UpdatedAt               string
	RequiredAction          string
	RequiredJurisdiction    string
	PolicySignerCount       uint32
	ActivePolicySignerCount uint32
	AllowedSponsorCount     uint32
	ActiveSponsorCount      uint32
}

// SetEnterpriseAuditTrustRegistryByAuthority validates governance authority,
// persists the registry, and emits governance-grade audit evidence.
func (k Keeper) SetEnterpriseAuditTrustRegistryByAuthority(
	ctx context.Context,
	authority string,
	registry *EnterpriseAuditTrustRegistry,
	reason string,
	requestedBy string,
) (*EnterpriseAuditTrustRegistryStatus, error) {
	if err := k.validateEnterpriseAuditTrustAuthority(authority); err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, fmt.Errorf("enterprise audit trust registry cannot be nil")
	}

	registryToStore := cloneEnterpriseAuditTrustRegistryForGovernance(registry)
	registryToStore.Source = "pouw_governance"

	if err := k.SetEnterpriseAuditTrustRegistry(ctx, registryToStore); err != nil {
		return nil, err
	}

	status, err := k.GetEnterpriseAuditTrustRegistryStatus(ctx)
	if err != nil {
		return nil, err
	}

	if sdkCtx, ok := ctx.(sdk.Context); ok {
		k.emitEnterpriseAuditTrustRegistryGovernanceEvent(sdkCtx, "enterprise_audit_trust_registry_updated", authority, requestedBy, status)
		k.auditEnterpriseAuditTrustRegistryGovernanceChange(sdkCtx, "enterprise_audit_trust_registry_updated", authority, reason, requestedBy, registryToStore, status)
	}

	return status, nil
}

// ClearEnterpriseAuditTrustRegistryByAuthority validates governance authority,
// clears the registry, and emits governance-grade audit evidence.
func (k Keeper) ClearEnterpriseAuditTrustRegistryByAuthority(
	ctx context.Context,
	authority string,
	reason string,
	requestedBy string,
) (*EnterpriseAuditTrustRegistryStatus, error) {
	if err := k.validateEnterpriseAuditTrustAuthority(authority); err != nil {
		return nil, err
	}

	var previousRegistry *EnterpriseAuditTrustRegistry
	var previousStatus *EnterpriseAuditTrustRegistryStatus

	if registry, err := k.GetEnterpriseAuditTrustRegistry(ctx); err == nil {
		previousRegistry = registry
	}
	if status, err := k.GetEnterpriseAuditTrustRegistryStatus(ctx); err == nil {
		previousStatus = status
	}

	if err := k.ClearEnterpriseAuditTrustRegistry(ctx); err != nil {
		return nil, err
	}

	status := &EnterpriseAuditTrustRegistryStatus{}
	if sdkCtx, ok := ctx.(sdk.Context); ok {
		k.emitEnterpriseAuditTrustRegistryGovernanceEvent(sdkCtx, "enterprise_audit_trust_registry_cleared", authority, requestedBy, status)
		k.auditEnterpriseAuditTrustRegistryGovernanceChange(sdkCtx, "enterprise_audit_trust_registry_cleared", authority, reason, requestedBy, previousRegistry, previousStatus)
	}

	return status, nil
}

func (k Keeper) validateEnterpriseAuditTrustAuthority(authority string) error {
	if strings.TrimSpace(authority) != k.GetAuthority() {
		return fmt.Errorf("unauthorized: expected authority %s, got %s", k.GetAuthority(), authority)
	}
	return nil
}

func (k Keeper) emitEnterpriseAuditTrustRegistryGovernanceEvent(
	ctx sdk.Context,
	action string,
	authority string,
	requestedBy string,
	status *EnterpriseAuditTrustRegistryStatus,
) {
	if status == nil {
		status = &EnterpriseAuditTrustRegistryStatus{}
	}
	attrs := []sdk.Attribute{
		sdk.NewAttribute("authority", authority),
		sdk.NewAttribute("configured", strconv.FormatBool(status.Configured)),
		sdk.NewAttribute("version", status.Version),
		sdk.NewAttribute("required_action", status.RequiredAction),
		sdk.NewAttribute("required_jurisdiction", status.RequiredJurisdiction),
		sdk.NewAttribute("policy_signer_count", strconv.Itoa(status.PolicySignerCount)),
		sdk.NewAttribute("allowed_sponsor_count", strconv.Itoa(status.AllowedSponsorCount)),
		sdk.NewAttribute("block_height", strconv.FormatInt(ctx.BlockHeight(), 10)),
	}
	if trimmedRequestedBy := strings.TrimSpace(requestedBy); trimmedRequestedBy != "" {
		attrs = append(attrs, sdk.NewAttribute("requested_by", trimmedRequestedBy))
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(action, attrs...))
}

func (k Keeper) auditEnterpriseAuditTrustRegistryGovernanceChange(
	ctx sdk.Context,
	action string,
	authority string,
	reason string,
	requestedBy string,
	registry *EnterpriseAuditTrustRegistry,
	status *EnterpriseAuditTrustRegistryStatus,
) {
	if k.auditLogger == nil {
		return
	}

	details := make(map[string]string)
	if registry != nil {
		details["version"] = strings.TrimSpace(registry.Version)
		details["source"] = strings.TrimSpace(registry.Source)
		details["required_action"] = strings.TrimSpace(registry.RequiredAction)
		details["required_jurisdiction"] = strings.TrimSpace(registry.RequiredJurisdiction)
		details["policy_signer_count"] = strconv.Itoa(len(registry.PolicySigners))
		details["allowed_sponsor_count"] = strconv.Itoa(len(registry.AllowedSponsors))
	}
	if status != nil {
		details["configured"] = strconv.FormatBool(status.Configured)
		if status.Version != "" {
			details["effective_version"] = status.Version
		}
		if status.UpdatedAt != "" {
			details["updated_at"] = status.UpdatedAt
		}
		details["active_policy_signer_count"] = strconv.Itoa(status.ActivePolicySignerCount)
		details["active_sponsor_count"] = strconv.Itoa(status.ActiveSponsorCount)
	}
	if trimmedReason := strings.TrimSpace(reason); trimmedReason != "" {
		details["reason"] = trimmedReason
	}
	if trimmedRequestedBy := strings.TrimSpace(requestedBy); trimmedRequestedBy != "" {
		details["requested_by"] = trimmedRequestedBy
	}

	k.auditLogger.Record(ctx, AuditCategoryGovernance, AuditSeverityWarning, action, authority, details)
}

func cloneEnterpriseAuditTrustRegistryForGovernance(registry *EnterpriseAuditTrustRegistry) *EnterpriseAuditTrustRegistry {
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
			Status:        signer.Status,
			Actions:       append([]string(nil), signer.Actions...),
			Jurisdictions: append([]string(nil), signer.Jurisdictions...),
			Metadata:      cloneEnterpriseAuditTrustStringMap(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, EnterpriseAuditSponsorTrustEntry{
			DID:           sponsor.DID,
			Status:        sponsor.Status,
			Actions:       append([]string(nil), sponsor.Actions...),
			Jurisdictions: append([]string(nil), sponsor.Jurisdictions...),
			Metadata:      cloneEnterpriseAuditTrustStringMap(sponsor.Metadata),
		})
	}
	return out
}

// UpdateEnterpriseAuditTrustRegistry handles governance-driven trust-registry
// updates. Only the module authority may invoke this handler.
func (k msgServer) UpdateEnterpriseAuditTrustRegistry(
	goCtx context.Context,
	msg *MsgUpdateEnterpriseAuditTrustRegistry,
) (*MsgUpdateEnterpriseAuditTrustRegistryResponse, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil UpdateEnterpriseAuditTrustRegistry message")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)

	var (
		status *EnterpriseAuditTrustRegistryStatus
		err    error
	)
	if msg.Clear {
		status, err = k.Keeper.ClearEnterpriseAuditTrustRegistryByAuthority(ctx, msg.Authority, msg.Reason, msg.RequestedBy)
	} else {
		status, err = k.Keeper.SetEnterpriseAuditTrustRegistryByAuthority(ctx, msg.Authority, msg.Registry, msg.Reason, msg.RequestedBy)
	}
	if err != nil {
		return nil, err
	}

	return &MsgUpdateEnterpriseAuditTrustRegistryResponse{
		Configured:              status.Configured,
		Version:                 status.Version,
		Source:                  status.Source,
		UpdatedAt:               status.UpdatedAt,
		RequiredAction:          status.RequiredAction,
		RequiredJurisdiction:    status.RequiredJurisdiction,
		PolicySignerCount:       uint32(status.PolicySignerCount),
		ActivePolicySignerCount: uint32(status.ActivePolicySignerCount),
		AllowedSponsorCount:     uint32(status.AllowedSponsorCount),
		ActiveSponsorCount:      uint32(status.ActiveSponsorCount),
	}, nil
}
