package types

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"strings"
)

type EnterpriseAuditTrustRegistryEntryStatus string

const (
	EnterpriseAuditTrustRegistryEntryStatusActive     EnterpriseAuditTrustRegistryEntryStatus = "active"
	EnterpriseAuditTrustRegistryEntryStatusRevoked    EnterpriseAuditTrustRegistryEntryStatus = "revoked"
	EnterpriseAuditTrustRegistryEntryStatusDeprecated EnterpriseAuditTrustRegistryEntryStatus = "deprecated"
)

// EnterpriseAuditPolicySignerTrustEntryGenesis captures a trusted policy signer
// inside the JSON-managed pouw genesis document.
type EnterpriseAuditPolicySignerTrustEntryGenesis struct {
	DID           string                                  `json:"did"`
	PublicKeyHex  string                                  `json:"public_key"`
	Status        EnterpriseAuditTrustRegistryEntryStatus `json:"status,omitempty"`
	Actions       []string                                `json:"actions,omitempty"`
	Jurisdictions []string                                `json:"jurisdictions,omitempty"`
	Metadata      map[string]string                       `json:"metadata,omitempty"`
}

// EnterpriseAuditSponsorTrustEntryGenesis captures an allowed sponsor-of-record
// entry inside the JSON-managed pouw genesis document.
type EnterpriseAuditSponsorTrustEntryGenesis struct {
	DID           string                                  `json:"did"`
	Status        EnterpriseAuditTrustRegistryEntryStatus `json:"status,omitempty"`
	Actions       []string                                `json:"actions,omitempty"`
	Jurisdictions []string                                `json:"jurisdictions,omitempty"`
	Metadata      map[string]string                       `json:"metadata,omitempty"`
}

// EnterpriseAuditTrustRegistryGenesis is the JSON-managed genesis schema for
// the enterprise audit trust registry.
type EnterpriseAuditTrustRegistryGenesis struct {
	Version              string                                         `json:"version,omitempty"`
	Source               string                                         `json:"source,omitempty"`
	UpdatedAt            string                                         `json:"updated_at,omitempty"`
	RequiredAction       string                                         `json:"required_action,omitempty"`
	RequiredJurisdiction string                                         `json:"required_jurisdiction,omitempty"`
	PolicySigners        []EnterpriseAuditPolicySignerTrustEntryGenesis `json:"policy_signers"`
	AllowedSponsors      []EnterpriseAuditSponsorTrustEntryGenesis      `json:"allowed_sponsors,omitempty"`
	Metadata             map[string]string                              `json:"metadata,omitempty"`
}

// ManagedGenesisState is the JSON-managed pouw genesis document. It mirrors
// the generated GenesisState and adds enterprise trust-registry state without
// requiring protobuf regeneration.
type ManagedGenesisState struct {
	Jobs                         []*ComputeJob                        `json:"jobs,omitempty"`
	RegisteredModels             []*RegisteredModel                   `json:"registered_models,omitempty"`
	ValidatorStats               []*ValidatorStats                    `json:"validator_stats,omitempty"`
	ValidatorCapabilities        []*ValidatorCapability               `json:"validator_capabilities,omitempty"`
	Params                       *Params                              `json:"params,omitempty"`
	CurrentEpoch                 uint64                               `json:"current_epoch,omitempty"`
	TotalUwu                     uint64                               `json:"total_uwu,omitempty"`
	EnterpriseAuditTrustRegistry *EnterpriseAuditTrustRegistryGenesis `json:"enterprise_audit_trust_registry,omitempty"`
}

// NewManagedGenesisState wraps a generated GenesisState with optional managed
// enterprise trust-registry state.
func NewManagedGenesisState(base *GenesisState, registry *EnterpriseAuditTrustRegistryGenesis) *ManagedGenesisState {
	if base == nil {
		base = DefaultGenesis()
	}
	return &ManagedGenesisState{
		Jobs:                         base.Jobs,
		RegisteredModels:             base.RegisteredModels,
		ValidatorStats:               base.ValidatorStats,
		ValidatorCapabilities:        base.ValidatorCapabilities,
		Params:                       base.Params,
		CurrentEpoch:                 base.CurrentEpoch,
		TotalUwu:                     base.TotalUwu,
		EnterpriseAuditTrustRegistry: cloneEnterpriseAuditTrustRegistryGenesis(registry),
	}
}

// BaseGenesisState returns the generated GenesisState view of the managed
// genesis document.
func (gs *ManagedGenesisState) BaseGenesisState() *GenesisState {
	if gs == nil {
		return DefaultGenesis()
	}
	return &GenesisState{
		Jobs:                  gs.Jobs,
		RegisteredModels:      gs.RegisteredModels,
		ValidatorStats:        gs.ValidatorStats,
		ValidatorCapabilities: gs.ValidatorCapabilities,
		Params:                gs.Params,
		CurrentEpoch:          gs.CurrentEpoch,
		TotalUwu:              gs.TotalUwu,
	}
}

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Jobs:                  []*ComputeJob{},
		RegisteredModels:      []*RegisteredModel{},
		ValidatorStats:        []*ValidatorStats{},
		ValidatorCapabilities: []*ValidatorCapability{},
		Params:                DefaultParams(),
	}
}

// DefaultManagedGenesis returns the default JSON-managed genesis state.
func DefaultManagedGenesis() *ManagedGenesisState {
	return NewManagedGenesisState(DefaultGenesis(), nil)
}

// DefaultParams returns default module parameters
func DefaultParams() *Params {
	return &Params{
		MinValidators:                  3,
		ConsensusThreshold:             67,  // 2/3 majority
		JobTimeoutBlocks:               100, // ~10 minutes with 6s blocks
		BaseJobFee:                     "1000uaethel",
		VerificationReward:             "100uaethel",
		SlashingPenalty:                "10000uaethel",
		MaxJobsPerBlock:                10,
		AllowedProofTypes:              []string{"tee", "zkml", "hybrid"},
		RequireTeeAttestation:          true,
		AllowZkmlFallback:              true,
		AllowSimulated:                 false,
		VoteExtensionMaxPastSkewSecs:   600, // 10 minutes
		VoteExtensionMaxFutureSkewSecs: 60,  // 1 minute
	}
}

// EnterpriseParams returns locked enterprise-mode parameters.
// Enterprise mode enforces hybrid-only verification with no fallback.
func EnterpriseParams() *Params {
	return &Params{
		MinValidators:                  3,
		ConsensusThreshold:             67,  // 2/3 majority
		JobTimeoutBlocks:               100, // ~10 minutes with 6s blocks
		BaseJobFee:                     "1000uaethel",
		VerificationReward:             "100uaethel",
		SlashingPenalty:                "10000uaethel",
		MaxJobsPerBlock:                10,
		AllowedProofTypes:              []string{"hybrid"},
		RequireTeeAttestation:          true,
		AllowZkmlFallback:              false,
		AllowSimulated:                 false,
		VoteExtensionMaxPastSkewSecs:   600, // 10 minutes
		VoteExtensionMaxFutureSkewSecs: 60,  // 1 minute
	}
}

// EnterpriseGenesis returns a genesis state configured for enterprise mode.
func EnterpriseGenesis() *GenesisState {
	return &GenesisState{
		Jobs:                  []*ComputeJob{},
		RegisteredModels:      []*RegisteredModel{},
		ValidatorStats:        []*ValidatorStats{},
		ValidatorCapabilities: []*ValidatorCapability{},
		Params:                EnterpriseParams(),
	}
}

// EnterpriseManagedGenesis returns a managed genesis state configured for
// enterprise-mode parameters.
func EnterpriseManagedGenesis() *ManagedGenesisState {
	return NewManagedGenesisState(EnterpriseGenesis(), nil)
}

// ValidateEnterprise performs enterprise-mode genesis validation.
// In enterprise mode:
//   - AllowZkmlFallback must be false
//   - AllowedProofTypes must only contain "hybrid"
//   - AllowSimulated must be false
func ValidateEnterprise(gs *GenesisState) error {
	if gs.Params == nil {
		return fmt.Errorf("enterprise: params must be set")
	}
	if gs.Params.AllowZkmlFallback {
		return fmt.Errorf("enterprise: AllowZkmlFallback must be false in enterprise mode")
	}
	if gs.Params.AllowSimulated {
		return fmt.Errorf("enterprise: AllowSimulated must be false in enterprise mode")
	}
	// AllowedProofTypes must only contain "hybrid"
	if len(gs.Params.AllowedProofTypes) != 1 || gs.Params.AllowedProofTypes[0] != "hybrid" {
		return fmt.Errorf("enterprise: AllowedProofTypes must be [\"hybrid\"], got %v", gs.Params.AllowedProofTypes)
	}
	return nil
}

// IsEnterpriseProofType checks whether a proof type is allowed in enterprise mode.
func IsEnterpriseProofType(proofType string) bool {
	return proofType == "hybrid"
}

// Validate performs basic genesis state validation
func (gs *GenesisState) Validate() error {
	// Validate each job
	for i, job := range gs.Jobs {
		if job == nil {
			return fmt.Errorf("job at index %d is nil", i)
		}
		if err := job.Validate(); err != nil {
			return fmt.Errorf("invalid job at index %d: %w", i, err)
		}
	}

	// Validate validator capabilities
	for i, cap := range gs.ValidatorCapabilities {
		if cap == nil || len(cap.Address) == 0 {
			return fmt.Errorf("validator capability missing address at index %d", i)
		}
	}

	// Validate params
	if gs.Params == nil {
		return fmt.Errorf("params must be set")
	}
	if gs.Params.MinValidators <= 0 {
		return fmt.Errorf("min_validators must be positive")
	}
	if gs.Params.ConsensusThreshold < 50 || gs.Params.ConsensusThreshold > 100 {
		return fmt.Errorf("consensus_threshold must be between 50 and 100")
	}
	if gs.Params.JobTimeoutBlocks <= 0 {
		return fmt.Errorf("job_timeout_blocks must be positive")
	}
	if gs.Params.MaxJobsPerBlock <= 0 {
		return fmt.Errorf("max_jobs_per_block must be positive")
	}
	if gs.Params.VoteExtensionMaxPastSkewSecs <= 0 {
		return fmt.Errorf("vote_extension_max_past_skew_secs must be positive")
	}
	if gs.Params.VoteExtensionMaxFutureSkewSecs <= 0 {
		return fmt.Errorf("vote_extension_max_future_skew_secs must be positive")
	}
	if gs.Params.VoteExtensionMaxFutureSkewSecs > gs.Params.VoteExtensionMaxPastSkewSecs {
		return fmt.Errorf("vote_extension_max_future_skew_secs cannot exceed vote_extension_max_past_skew_secs")
	}

	return nil
}

// Validate performs basic validation on the JSON-managed genesis document.
func (gs *ManagedGenesisState) Validate() error {
	if err := gs.BaseGenesisState().Validate(); err != nil {
		return err
	}
	if gs != nil && gs.EnterpriseAuditTrustRegistry != nil {
		if err := gs.EnterpriseAuditTrustRegistry.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate performs enterprise trust-registry validation for the managed
// genesis document.
func (r *EnterpriseAuditTrustRegistryGenesis) Validate() error {
	if r == nil {
		return nil
	}
	if len(r.PolicySigners) == 0 {
		return fmt.Errorf("enterprise audit trust registry requires at least one policy signer")
	}

	seenSigners := make(map[string]struct{}, len(r.PolicySigners))
	for i, signer := range r.PolicySigners {
		did := strings.TrimSpace(signer.DID)
		if did == "" {
			return fmt.Errorf("enterprise audit trust registry policy signer DID cannot be empty at index %d", i)
		}
		if _, exists := seenSigners[did]; exists {
			return fmt.Errorf("enterprise audit trust registry policy signer %q is duplicated", did)
		}
		seenSigners[did] = struct{}{}
		if strings.TrimSpace(signer.PublicKeyHex) == "" {
			return fmt.Errorf("enterprise audit trust registry policy signer %q public key cannot be empty", did)
		}
		if err := validateCompressedP256PublicKeyHex(strings.TrimSpace(signer.PublicKeyHex)); err != nil {
			return fmt.Errorf("enterprise audit trust registry policy signer %q public key is invalid: %w", did, err)
		}
		if _, err := normalizeEnterpriseAuditTrustRegistryEntryStatus(signer.Status); err != nil {
			return fmt.Errorf("enterprise audit trust registry policy signer %q status is invalid: %w", did, err)
		}
	}

	seenSponsors := make(map[string]struct{}, len(r.AllowedSponsors))
	for i, sponsor := range r.AllowedSponsors {
		did := strings.TrimSpace(sponsor.DID)
		if did == "" {
			return fmt.Errorf("enterprise audit trust registry sponsor DID cannot be empty at index %d", i)
		}
		if _, exists := seenSponsors[did]; exists {
			return fmt.Errorf("enterprise audit trust registry sponsor %q is duplicated", did)
		}
		seenSponsors[did] = struct{}{}
		if _, err := normalizeEnterpriseAuditTrustRegistryEntryStatus(sponsor.Status); err != nil {
			return fmt.Errorf("enterprise audit trust registry sponsor %q status is invalid: %w", did, err)
		}
	}

	return nil
}

func cloneEnterpriseAuditTrustRegistryGenesis(registry *EnterpriseAuditTrustRegistryGenesis) *EnterpriseAuditTrustRegistryGenesis {
	if registry == nil {
		return nil
	}
	out := &EnterpriseAuditTrustRegistryGenesis{
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySigners:        make([]EnterpriseAuditPolicySignerTrustEntryGenesis, 0, len(registry.PolicySigners)),
		AllowedSponsors:      make([]EnterpriseAuditSponsorTrustEntryGenesis, 0, len(registry.AllowedSponsors)),
		Metadata:             cloneEnterpriseAuditTrustRegistryStringMap(registry.Metadata),
	}
	for _, signer := range registry.PolicySigners {
		out.PolicySigners = append(out.PolicySigners, EnterpriseAuditPolicySignerTrustEntryGenesis{
			DID:           signer.DID,
			PublicKeyHex:  signer.PublicKeyHex,
			Status:        signer.Status,
			Actions:       cloneEnterpriseAuditTrustRegistryStringSlice(signer.Actions),
			Jurisdictions: cloneEnterpriseAuditTrustRegistryStringSlice(signer.Jurisdictions),
			Metadata:      cloneEnterpriseAuditTrustRegistryStringMap(signer.Metadata),
		})
	}
	for _, sponsor := range registry.AllowedSponsors {
		out.AllowedSponsors = append(out.AllowedSponsors, EnterpriseAuditSponsorTrustEntryGenesis{
			DID:           sponsor.DID,
			Status:        sponsor.Status,
			Actions:       cloneEnterpriseAuditTrustRegistryStringSlice(sponsor.Actions),
			Jurisdictions: cloneEnterpriseAuditTrustRegistryStringSlice(sponsor.Jurisdictions),
			Metadata:      cloneEnterpriseAuditTrustRegistryStringMap(sponsor.Metadata),
		})
	}
	return out
}

func cloneEnterpriseAuditTrustRegistryStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneEnterpriseAuditTrustRegistryStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func normalizeEnterpriseAuditTrustRegistryEntryStatus(status EnterpriseAuditTrustRegistryEntryStatus) (EnterpriseAuditTrustRegistryEntryStatus, error) {
	switch strings.ToLower(strings.TrimSpace(string(status))) {
	case "", string(EnterpriseAuditTrustRegistryEntryStatusActive):
		return EnterpriseAuditTrustRegistryEntryStatusActive, nil
	case string(EnterpriseAuditTrustRegistryEntryStatusRevoked):
		return EnterpriseAuditTrustRegistryEntryStatusRevoked, nil
	case string(EnterpriseAuditTrustRegistryEntryStatusDeprecated):
		return EnterpriseAuditTrustRegistryEntryStatusDeprecated, nil
	default:
		return "", fmt.Errorf("unsupported entry status %q", status)
	}
}

func validateCompressedP256PublicKeyHex(raw string) error {
	bytes, err := hex.DecodeString(raw)
	if err != nil {
		return fmt.Errorf("decode compressed P-256 key: %w", err)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)
	if x == nil || y == nil {
		return fmt.Errorf("compressed P-256 key is invalid")
	}
	return nil
}
