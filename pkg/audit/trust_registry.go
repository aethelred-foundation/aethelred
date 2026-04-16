package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// TrustRegistryEntryStatus captures the lifecycle state of a trust-registry
// entry.
type TrustRegistryEntryStatus string

const (
	TrustRegistryEntryStatusActive     TrustRegistryEntryStatus = "active"
	TrustRegistryEntryStatusRevoked    TrustRegistryEntryStatus = "revoked"
	TrustRegistryEntryStatusDeprecated TrustRegistryEntryStatus = "deprecated"
)

const trustRegistryMetadataProviderKey = "provider"

// EnterprisePolicySignerTrustEntry describes a trusted policy signer.
type EnterprisePolicySignerTrustEntry struct {
	DID           string                   `json:"did"`
	PublicKeyHex  string                   `json:"public_key"`
	Status        TrustRegistryEntryStatus `json:"status,omitempty"`
	Actions       []string                 `json:"actions,omitempty"`
	Jurisdictions []string                 `json:"jurisdictions,omitempty"`
	Metadata      map[string]string        `json:"metadata,omitempty"`
}

// EnterpriseSponsorTrustEntry describes an allowed sponsor-of-record.
type EnterpriseSponsorTrustEntry struct {
	DID           string                   `json:"did"`
	Status        TrustRegistryEntryStatus `json:"status,omitempty"`
	Actions       []string                 `json:"actions,omitempty"`
	Jurisdictions []string                 `json:"jurisdictions,omitempty"`
	Metadata      map[string]string        `json:"metadata,omitempty"`
}

// EnterpriseControlLedgerTrustRegistry is the persisted JSON schema for the
// enterprise control-ledger trust policy.
type EnterpriseControlLedgerTrustRegistry struct {
	Version              string                             `json:"version,omitempty"`
	Source               string                             `json:"source,omitempty"`
	UpdatedAt            string                             `json:"updated_at,omitempty"`
	RequiredAction       string                             `json:"required_action,omitempty"`
	RequiredJurisdiction string                             `json:"required_jurisdiction,omitempty"`
	PolicySigners        []EnterprisePolicySignerTrustEntry `json:"policy_signers"`
	AllowedSponsors      []EnterpriseSponsorTrustEntry      `json:"allowed_sponsors,omitempty"`
	Metadata             map[string]string                  `json:"metadata,omitempty"`
}

// EnterpriseTrustedPolicySigner is the runtime-ready trusted signer entry.
type EnterpriseTrustedPolicySigner struct {
	DID           string
	PublicKey     *ecdsa.PublicKey
	Status        TrustRegistryEntryStatus
	Actions       []string
	Jurisdictions []string
	Metadata      map[string]string
}

// EnterpriseAllowedSponsor is the runtime-ready sponsor trust entry.
type EnterpriseAllowedSponsor struct {
	DID           string
	Status        TrustRegistryEntryStatus
	Actions       []string
	Jurisdictions []string
	Metadata      map[string]string
}

// EnterpriseControlLedgerTrustSnapshot is the runtime form consumed by the
// enterprise control-ledger authorizer.
type EnterpriseControlLedgerTrustSnapshot struct {
	Version              string
	Source               string
	UpdatedAt            string
	RequiredAction       string
	RequiredJurisdiction string
	PolicySigners        map[string]EnterpriseTrustedPolicySigner
	AllowedSponsors      map[string]EnterpriseAllowedSponsor
	Metadata             map[string]string
}

// EnterpriseControlLedgerTrustSource resolves the active enterprise trust
// policy used to authorize mutating control-ledger writes.
type EnterpriseControlLedgerTrustSource interface {
	Snapshot(ctx context.Context) (*EnterpriseControlLedgerTrustSnapshot, error)
}

// StaticEnterpriseControlLedgerTrustSource uses a precomputed in-memory trust
// snapshot.
type StaticEnterpriseControlLedgerTrustSource struct {
	snapshot *EnterpriseControlLedgerTrustSnapshot
}

// NewStaticEnterpriseControlLedgerTrustSource creates a static trust source.
func NewStaticEnterpriseControlLedgerTrustSource(snapshot *EnterpriseControlLedgerTrustSnapshot) (*StaticEnterpriseControlLedgerTrustSource, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("audit/trust: %w: trust snapshot is required", ErrInvalidInput)
	}
	if err := validateEnterpriseControlLedgerTrustSnapshot(snapshot); err != nil {
		return nil, err
	}
	cloned, err := cloneEnterpriseControlLedgerTrustSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	ensureEnterpriseTrustSnapshotProvider(cloned, "static_source")
	return &StaticEnterpriseControlLedgerTrustSource{snapshot: cloned}, nil
}

// Snapshot returns a defensive copy of the static trust snapshot.
func (s *StaticEnterpriseControlLedgerTrustSource) Snapshot(_ context.Context) (*EnterpriseControlLedgerTrustSnapshot, error) {
	if s == nil || s.snapshot == nil {
		return nil, fmt.Errorf("audit/trust: %w: trust snapshot is not configured", ErrWriteDisabled)
	}
	return cloneEnterpriseControlLedgerTrustSnapshot(s.snapshot)
}

// FileEnterpriseControlLedgerTrustSource loads trust policy from a JSON file
// and hot-reloads it whenever the file's modtime changes.
type FileEnterpriseControlLedgerTrustSource struct {
	mu           sync.RWMutex
	path         string
	lastLoadedAt time.Time
	lastModTime  time.Time
	cached       *EnterpriseControlLedgerTrustSnapshot
}

// NewFileEnterpriseControlLedgerTrustSource creates a file-backed trust source.
func NewFileEnterpriseControlLedgerTrustSource(path string) (*FileEnterpriseControlLedgerTrustSource, error) {
	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		return nil, fmt.Errorf("audit/trust: %w: registry path is required", ErrInvalidInput)
	}
	return &FileEnterpriseControlLedgerTrustSource{path: normalizedPath}, nil
}

// Snapshot returns the current file-backed trust snapshot, reloading if needed.
func (s *FileEnterpriseControlLedgerTrustSource) Snapshot(_ context.Context) (*EnterpriseControlLedgerTrustSnapshot, error) {
	if s == nil {
		return nil, fmt.Errorf("audit/trust: %w: trust source is nil", ErrInvalidInput)
	}

	info, err := os.Stat(s.path)
	if err != nil {
		return nil, fmt.Errorf("audit/trust: load registry metadata: %w", err)
	}

	s.mu.RLock()
	if s.cached != nil && !info.ModTime().After(s.lastModTime) {
		cached, err := cloneEnterpriseControlLedgerTrustSnapshot(s.cached)
		s.mu.RUnlock()
		return cached, err
	}
	s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("audit/trust: read registry file: %w", err)
	}

	var registry EnterpriseControlLedgerTrustRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("audit/trust: decode registry file: %w", err)
	}

	snapshot, err := registry.ToSnapshot()
	if err != nil {
		return nil, err
	}
	if snapshot.UpdatedAt == "" {
		snapshot.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	ensureEnterpriseTrustSnapshotProvider(snapshot, "file_registry")

	s.mu.Lock()
	s.cached = snapshot
	s.lastLoadedAt = time.Now().UTC()
	s.lastModTime = info.ModTime()
	s.mu.Unlock()

	return cloneEnterpriseControlLedgerTrustSnapshot(snapshot)
}

// LoadEnterpriseControlLedgerTrustRegistry reads and validates a registry file.
func LoadEnterpriseControlLedgerTrustRegistry(path string) (*EnterpriseControlLedgerTrustRegistry, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("audit/trust: read registry file: %w", err)
	}
	var registry EnterpriseControlLedgerTrustRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("audit/trust: decode registry file: %w", err)
	}
	if _, err := registry.ToSnapshot(); err != nil {
		return nil, err
	}
	return &registry, nil
}

// ToSnapshot validates and converts the registry file schema into a runtime
// snapshot.
func (r *EnterpriseControlLedgerTrustRegistry) ToSnapshot() (*EnterpriseControlLedgerTrustSnapshot, error) {
	if r == nil {
		return nil, fmt.Errorf("audit/trust: %w: registry is required", ErrInvalidInput)
	}

	snapshot := &EnterpriseControlLedgerTrustSnapshot{
		Version:              strings.TrimSpace(r.Version),
		Source:               strings.TrimSpace(r.Source),
		UpdatedAt:            strings.TrimSpace(r.UpdatedAt),
		RequiredAction:       normalizeEnterpriseControlLedgerWriteAction(r.RequiredAction),
		RequiredJurisdiction: strings.TrimSpace(r.RequiredJurisdiction),
		PolicySigners:        make(map[string]EnterpriseTrustedPolicySigner, len(r.PolicySigners)),
		AllowedSponsors:      make(map[string]EnterpriseAllowedSponsor, len(r.AllowedSponsors)),
		Metadata:             cloneStringMapPreserve(r.Metadata),
	}
	if snapshot.Source == "" {
		snapshot.Source = "file_registry"
	}

	for _, signer := range r.PolicySigners {
		normalizedDID := strings.TrimSpace(signer.DID)
		if normalizedDID == "" {
			return nil, fmt.Errorf("audit/trust: %w: policy signer DID cannot be empty", ErrInvalidInput)
		}
		publicKey, err := parseCompressedP256PublicKeyHex(signer.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("audit/trust: invalid policy signer %q public key: %w", normalizedDID, err)
		}
		status, err := normalizeTrustRegistryEntryStatus(signer.Status)
		if err != nil {
			return nil, fmt.Errorf("audit/trust: invalid policy signer %q status: %w", normalizedDID, err)
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

	if len(snapshot.PolicySigners) == 0 {
		return nil, fmt.Errorf("audit/trust: %w: at least one policy signer is required", ErrInvalidInput)
	}

	for _, sponsor := range r.AllowedSponsors {
		normalizedDID := strings.TrimSpace(sponsor.DID)
		if normalizedDID == "" {
			return nil, fmt.Errorf("audit/trust: %w: sponsor DID cannot be empty", ErrInvalidInput)
		}
		status, err := normalizeTrustRegistryEntryStatus(sponsor.Status)
		if err != nil {
			return nil, fmt.Errorf("audit/trust: invalid sponsor %q status: %w", normalizedDID, err)
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

func validateEnterpriseControlLedgerTrustSnapshot(snapshot *EnterpriseControlLedgerTrustSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("audit/trust: %w: trust snapshot is required", ErrInvalidInput)
	}
	if len(snapshot.PolicySigners) == 0 {
		return fmt.Errorf("audit/trust: %w: trust snapshot requires at least one policy signer", ErrInvalidInput)
	}
	for signerDID, signer := range snapshot.PolicySigners {
		if strings.TrimSpace(signerDID) == "" || signer.PublicKey == nil {
			return fmt.Errorf("audit/trust: %w: invalid policy signer entry", ErrInvalidInput)
		}
		if _, err := normalizeTrustRegistryEntryStatus(signer.Status); err != nil {
			return fmt.Errorf("audit/trust: %w: invalid policy signer entry status", ErrInvalidInput)
		}
	}
	for sponsorDID, sponsor := range snapshot.AllowedSponsors {
		if strings.TrimSpace(sponsorDID) == "" {
			return fmt.Errorf("audit/trust: %w: invalid sponsor entry", ErrInvalidInput)
		}
		if _, err := normalizeTrustRegistryEntryStatus(sponsor.Status); err != nil {
			return fmt.Errorf("audit/trust: %w: invalid sponsor entry status", ErrInvalidInput)
		}
	}
	return nil
}

func cloneEnterpriseControlLedgerTrustSnapshot(snapshot *EnterpriseControlLedgerTrustSnapshot) (*EnterpriseControlLedgerTrustSnapshot, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("audit/trust: %w: trust snapshot is required", ErrInvalidInput)
	}
	cloned := &EnterpriseControlLedgerTrustSnapshot{
		Version:              snapshot.Version,
		Source:               snapshot.Source,
		UpdatedAt:            snapshot.UpdatedAt,
		RequiredAction:       snapshot.RequiredAction,
		RequiredJurisdiction: snapshot.RequiredJurisdiction,
		PolicySigners:        make(map[string]EnterpriseTrustedPolicySigner, len(snapshot.PolicySigners)),
		AllowedSponsors:      make(map[string]EnterpriseAllowedSponsor, len(snapshot.AllowedSponsors)),
		Metadata:             cloneStringMapPreserve(snapshot.Metadata),
	}
	for did, signer := range snapshot.PolicySigners {
		cloned.PolicySigners[did] = EnterpriseTrustedPolicySigner{
			DID:           signer.DID,
			PublicKey:     cloneP256PublicKey(signer.PublicKey),
			Status:        signer.Status,
			Actions:       cloneStringSlicePreserve(signer.Actions),
			Jurisdictions: cloneStringSlicePreserve(signer.Jurisdictions),
			Metadata:      cloneStringMapPreserve(signer.Metadata),
		}
	}
	for did, sponsor := range snapshot.AllowedSponsors {
		cloned.AllowedSponsors[did] = EnterpriseAllowedSponsor{
			DID:           sponsor.DID,
			Status:        sponsor.Status,
			Actions:       cloneStringSlicePreserve(sponsor.Actions),
			Jurisdictions: cloneStringSlicePreserve(sponsor.Jurisdictions),
			Metadata:      cloneStringMapPreserve(sponsor.Metadata),
		}
	}
	return cloned, nil
}

func ensureEnterpriseTrustSnapshotProvider(snapshot *EnterpriseControlLedgerTrustSnapshot, provider string) {
	if snapshot == nil {
		return
	}
	normalizedProvider := strings.TrimSpace(provider)
	if normalizedProvider == "" {
		return
	}
	if snapshot.Metadata == nil {
		snapshot.Metadata = make(map[string]string, 1)
	}
	if strings.TrimSpace(snapshot.Metadata[trustRegistryMetadataProviderKey]) == "" {
		snapshot.Metadata[trustRegistryMetadataProviderKey] = normalizedProvider
	}
}

func cloneP256PublicKey(in *ecdsa.PublicKey) *ecdsa.PublicKey {
	if in == nil {
		return nil
	}
	x := (*big.Int)(nil)
	y := (*big.Int)(nil)
	if in.X != nil {
		x = new(big.Int).Set(in.X)
	}
	if in.Y != nil {
		y = new(big.Int).Set(in.Y)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}

func cloneStringSlicePreserve(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneStringMapPreserve(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeTrustRegistryEntryStatus(status TrustRegistryEntryStatus) (TrustRegistryEntryStatus, error) {
	switch strings.ToLower(strings.TrimSpace(string(status))) {
	case "", string(TrustRegistryEntryStatusActive):
		return TrustRegistryEntryStatusActive, nil
	case string(TrustRegistryEntryStatusRevoked):
		return TrustRegistryEntryStatusRevoked, nil
	case string(TrustRegistryEntryStatusDeprecated):
		return TrustRegistryEntryStatusDeprecated, nil
	default:
		return "", fmt.Errorf("%w: unsupported entry status %q", ErrInvalidInput, status)
	}
}

func normalizeTrustScopeValues(values []string) []string {
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
