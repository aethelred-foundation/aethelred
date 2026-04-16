package keeper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cosmossdk.io/collections"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const defaultEnterpriseAuditTrustRequiredAction = "audit.control_ledger.write"

var ErrEnterpriseAuditTrustRegistryNotConfigured = errors.New("enterprise audit trust registry not configured")

type EnterpriseAuditTrustEntryStatus string

const (
	EnterpriseAuditTrustEntryStatusActive     EnterpriseAuditTrustEntryStatus = "active"
	EnterpriseAuditTrustEntryStatusRevoked    EnterpriseAuditTrustEntryStatus = "revoked"
	EnterpriseAuditTrustEntryStatusDeprecated EnterpriseAuditTrustEntryStatus = "deprecated"
)

// EnterpriseAuditTrustRegistry captures the keeper-backed trust policy used by
// enterprise audit/control-ledger authorization.
type EnterpriseAuditTrustRegistry struct {
	Version              string                                  `json:"version,omitempty"`
	Source               string                                  `json:"source,omitempty"`
	UpdatedAt            string                                  `json:"updated_at,omitempty"`
	RequiredAction       string                                  `json:"required_action,omitempty"`
	RequiredJurisdiction string                                  `json:"required_jurisdiction,omitempty"`
	PolicySigners        []EnterpriseAuditPolicySignerTrustEntry `json:"policy_signers"`
	AllowedSponsors      []EnterpriseAuditSponsorTrustEntry      `json:"allowed_sponsors,omitempty"`
	Metadata             map[string]string                       `json:"metadata,omitempty"`
}

type EnterpriseAuditPolicySignerTrustEntry struct {
	DID           string                          `json:"did"`
	PublicKeyHex  string                          `json:"public_key"`
	Status        EnterpriseAuditTrustEntryStatus `json:"status,omitempty"`
	Actions       []string                        `json:"actions,omitempty"`
	Jurisdictions []string                        `json:"jurisdictions,omitempty"`
	Metadata      map[string]string               `json:"metadata,omitempty"`
}

type EnterpriseAuditSponsorTrustEntry struct {
	DID           string                          `json:"did"`
	Status        EnterpriseAuditTrustEntryStatus `json:"status,omitempty"`
	Actions       []string                        `json:"actions,omitempty"`
	Jurisdictions []string                        `json:"jurisdictions,omitempty"`
	Metadata      map[string]string               `json:"metadata,omitempty"`
}

type EnterpriseAuditTrustRegistryStatus struct {
	Configured              bool   `json:"configured"`
	Version                 string `json:"version,omitempty"`
	Source                  string `json:"source,omitempty"`
	UpdatedAt               string `json:"updated_at,omitempty"`
	RequiredAction          string `json:"required_action,omitempty"`
	RequiredJurisdiction    string `json:"required_jurisdiction,omitempty"`
	PolicySignerCount       int    `json:"policy_signer_count"`
	ActivePolicySignerCount int    `json:"active_policy_signer_count"`
	AllowedSponsorCount     int    `json:"allowed_sponsor_count"`
	ActiveSponsorCount      int    `json:"active_sponsor_count"`
}

func (k Keeper) HasEnterpriseAuditTrustRegistry(ctx context.Context) (bool, error) {
	raw, err := k.enterpriseAuditTrustRegistryItem().Get(ctx)
	if err == nil {
		return strings.TrimSpace(raw) != "", nil
	}
	if errors.Is(err, collections.ErrNotFound) {
		return false, nil
	}
	return false, err
}

func (k Keeper) GetEnterpriseAuditTrustRegistry(ctx context.Context) (*EnterpriseAuditTrustRegistry, error) {
	raw, err := k.enterpriseAuditTrustRegistryItem().Get(ctx)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, ErrEnterpriseAuditTrustRegistryNotConfigured
		}
		return nil, fmt.Errorf("get enterprise audit trust registry: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, ErrEnterpriseAuditTrustRegistryNotConfigured
	}

	var registry EnterpriseAuditTrustRegistry
	if err := json.Unmarshal([]byte(raw), &registry); err != nil {
		return nil, fmt.Errorf("decode enterprise audit trust registry: %w", err)
	}
	normalized, err := normalizeEnterpriseAuditTrustRegistry(&registry, nil)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func (k Keeper) SetEnterpriseAuditTrustRegistry(ctx context.Context, registry *EnterpriseAuditTrustRegistry) error {
	normalized, err := normalizeEnterpriseAuditTrustRegistry(registry, ctx)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("encode enterprise audit trust registry: %w", err)
	}
	return k.enterpriseAuditTrustRegistryItem().Set(ctx, string(payload))
}

func (k Keeper) ClearEnterpriseAuditTrustRegistry(ctx context.Context) error {
	if err := k.enterpriseAuditTrustRegistryItem().Remove(ctx); err != nil && !errors.Is(err, collections.ErrNotFound) {
		return err
	}
	return nil
}

func (k Keeper) GetEnterpriseAuditTrustRegistryStatus(ctx context.Context) (*EnterpriseAuditTrustRegistryStatus, error) {
	registry, err := k.GetEnterpriseAuditTrustRegistry(ctx)
	if err != nil {
		if errors.Is(err, ErrEnterpriseAuditTrustRegistryNotConfigured) {
			return &EnterpriseAuditTrustRegistryStatus{}, nil
		}
		return nil, err
	}

	status := &EnterpriseAuditTrustRegistryStatus{
		Configured:           true,
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySignerCount:    len(registry.PolicySigners),
		AllowedSponsorCount:  len(registry.AllowedSponsors),
	}
	for _, signer := range registry.PolicySigners {
		if signer.Status == EnterpriseAuditTrustEntryStatusActive {
			status.ActivePolicySignerCount++
		}
	}
	for _, sponsor := range registry.AllowedSponsors {
		if sponsor.Status == EnterpriseAuditTrustEntryStatusActive {
			status.ActiveSponsorCount++
		}
	}
	return status, nil
}

func (k Keeper) enterpriseAuditTrustRegistryItem() collections.Item[string] {
	return k.EnterpriseAuditTrustRegistry
}

func normalizeEnterpriseAuditTrustRegistry(registry *EnterpriseAuditTrustRegistry, ctx context.Context) (*EnterpriseAuditTrustRegistry, error) {
	if registry == nil {
		return nil, fmt.Errorf("enterprise audit trust registry cannot be nil")
	}

	normalized := &EnterpriseAuditTrustRegistry{
		Version:              strings.TrimSpace(registry.Version),
		Source:               strings.TrimSpace(registry.Source),
		UpdatedAt:            strings.TrimSpace(registry.UpdatedAt),
		RequiredAction:       normalizeEnterpriseAuditTrustRequiredAction(registry.RequiredAction),
		RequiredJurisdiction: strings.TrimSpace(registry.RequiredJurisdiction),
		PolicySigners:        make([]EnterpriseAuditPolicySignerTrustEntry, 0, len(registry.PolicySigners)),
		AllowedSponsors:      make([]EnterpriseAuditSponsorTrustEntry, 0, len(registry.AllowedSponsors)),
		Metadata:             cloneEnterpriseAuditTrustStringMap(registry.Metadata),
	}
	if normalized.Source == "" {
		normalized.Source = "pouw_keeper"
	}
	if normalized.UpdatedAt == "" {
		if sdkCtx, ok := ctx.(sdk.Context); ok && !sdkCtx.BlockTime().IsZero() {
			normalized.UpdatedAt = sdkCtx.BlockTime().UTC().Format(time.RFC3339Nano)
		}
	}

	seenSigners := make(map[string]struct{}, len(registry.PolicySigners))
	for _, signer := range registry.PolicySigners {
		normalizedDID := strings.TrimSpace(signer.DID)
		if normalizedDID == "" {
			return nil, fmt.Errorf("enterprise audit trust registry policy signer DID cannot be empty")
		}
		if _, exists := seenSigners[normalizedDID]; exists {
			return nil, fmt.Errorf("enterprise audit trust registry policy signer %q is duplicated", normalizedDID)
		}
		seenSigners[normalizedDID] = struct{}{}
		if _, err := parseCompressedP256PublicKeyHexForEnterpriseTrust(strings.TrimSpace(signer.PublicKeyHex)); err != nil {
			return nil, fmt.Errorf("enterprise audit trust registry policy signer %q public key is invalid: %w", normalizedDID, err)
		}
		status, err := normalizeEnterpriseAuditTrustEntryStatus(signer.Status)
		if err != nil {
			return nil, fmt.Errorf("enterprise audit trust registry policy signer %q status is invalid: %w", normalizedDID, err)
		}
		normalized.PolicySigners = append(normalized.PolicySigners, EnterpriseAuditPolicySignerTrustEntry{
			DID:           normalizedDID,
			PublicKeyHex:  strings.TrimSpace(signer.PublicKeyHex),
			Status:        status,
			Actions:       normalizeEnterpriseAuditTrustScopeValues(signer.Actions),
			Jurisdictions: normalizeEnterpriseAuditTrustScopeValues(signer.Jurisdictions),
			Metadata:      cloneEnterpriseAuditTrustStringMap(signer.Metadata),
		})
	}
	if len(normalized.PolicySigners) == 0 {
		return nil, fmt.Errorf("enterprise audit trust registry requires at least one policy signer")
	}

	seenSponsors := make(map[string]struct{}, len(registry.AllowedSponsors))
	for _, sponsor := range registry.AllowedSponsors {
		normalizedDID := strings.TrimSpace(sponsor.DID)
		if normalizedDID == "" {
			return nil, fmt.Errorf("enterprise audit trust registry sponsor DID cannot be empty")
		}
		if _, exists := seenSponsors[normalizedDID]; exists {
			return nil, fmt.Errorf("enterprise audit trust registry sponsor %q is duplicated", normalizedDID)
		}
		seenSponsors[normalizedDID] = struct{}{}
		status, err := normalizeEnterpriseAuditTrustEntryStatus(sponsor.Status)
		if err != nil {
			return nil, fmt.Errorf("enterprise audit trust registry sponsor %q status is invalid: %w", normalizedDID, err)
		}
		normalized.AllowedSponsors = append(normalized.AllowedSponsors, EnterpriseAuditSponsorTrustEntry{
			DID:           normalizedDID,
			Status:        status,
			Actions:       normalizeEnterpriseAuditTrustScopeValues(sponsor.Actions),
			Jurisdictions: normalizeEnterpriseAuditTrustScopeValues(sponsor.Jurisdictions),
			Metadata:      cloneEnterpriseAuditTrustStringMap(sponsor.Metadata),
		})
	}

	return normalized, nil
}

func normalizeEnterpriseAuditTrustRequiredAction(action string) string {
	normalized := strings.TrimSpace(action)
	if normalized == "" {
		return defaultEnterpriseAuditTrustRequiredAction
	}
	return normalized
}

func normalizeEnterpriseAuditTrustEntryStatus(status EnterpriseAuditTrustEntryStatus) (EnterpriseAuditTrustEntryStatus, error) {
	switch strings.ToLower(strings.TrimSpace(string(status))) {
	case "", string(EnterpriseAuditTrustEntryStatusActive):
		return EnterpriseAuditTrustEntryStatusActive, nil
	case string(EnterpriseAuditTrustEntryStatusRevoked):
		return EnterpriseAuditTrustEntryStatusRevoked, nil
	case string(EnterpriseAuditTrustEntryStatusDeprecated):
		return EnterpriseAuditTrustEntryStatusDeprecated, nil
	default:
		return "", fmt.Errorf("unsupported status %q", status)
	}
}

func normalizeEnterpriseAuditTrustScopeValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneEnterpriseAuditTrustStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func parseCompressedP256PublicKeyHexForEnterpriseTrust(publicKeyHex string) (*ecdsa.PublicKey, error) {
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
