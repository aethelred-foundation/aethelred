// Package types defines the core types for the Crucible Cosmos SDK module.
//
// Crucible is a liquid staking protocol with TEE-verified validator selection,
// MEV protection, and cryptographic reward distribution.
package types

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for the vault module.
var (
	// ErrVaultPaused is returned when a mutating operation is attempted while
	// the vault is in emergency-paused state.
	ErrVaultPaused = errors.New("vault is paused: all mutating operations are blocked")

	// ErrCircuitBreakerTripped is returned when an automatic circuit breaker
	// threshold is breached.
	ErrCircuitBreakerTripped = errors.New("circuit breaker tripped: automatic pause activated")

	// ErrUnauthorized is returned when a non-authority caller attempts a
	// privileged action (pause, unpause, parameter changes).
	ErrUnauthorized = errors.New("unauthorized: caller is not the module authority")

	// ErrRelayAlreadyRegistered is returned when registering a relay for a
	// platform that already has one.
	ErrRelayAlreadyRegistered = errors.New("attestation relay already registered for this platform")

	// ErrRelayNotRegistered is returned when operating on a relay that
	// has not been registered for the given platform.
	ErrRelayNotRegistered = errors.New("attestation relay not registered for this platform")

	// ErrRelayNotActive is returned when an operation requires an active relay
	// but the relay has been revoked.
	ErrRelayNotActive = errors.New("attestation relay is not active")

	// ErrNoRotationPending is returned when finalizing or cancelling a
	// rotation that doesn't exist.
	ErrNoRotationPending = errors.New("no relay key rotation pending")

	// ErrRotationTimelockActive is returned when attempting to finalize a
	// rotation before the timelock has expired.
	ErrRotationTimelockActive = errors.New("relay rotation timelock has not expired")

	// ErrNoPendingChallenge is returned when responding to a challenge
	// that doesn't exist.
	ErrNoPendingChallenge = errors.New("no pending relay liveness challenge")

	// ErrChallengeExpired is returned when the challenge response window
	// has passed.
	ErrChallengeExpired = errors.New("relay liveness challenge has expired")

	// ErrChallengeResponseInvalid is returned when the P-256 signature
	// in a challenge response does not verify.
	ErrChallengeResponseInvalid = errors.New("relay challenge response signature is invalid")

	// ErrDirectOverrideWhileRelayActive is returned when RegisterVendorRootKey()
	// is called for a platform that has an active attestation relay. The relay's
	// governance controls (rotation timelock, liveness challenges) must not be
	// bypassed by a direct root-key write. Revoke the relay first, or use the
	// relay lifecycle methods to rotate the key.
	ErrDirectOverrideWhileRelayActive = errors.New("cannot directly set vendor root key while an active relay is registered; revoke the relay first or use relay rotation")
)

// Module name and store key.
const (
	ModuleName = "vault"
	StoreKey   = ModuleName
	RouterKey  = ModuleName

	// Staking parameters.
	MinStakeUAETH          = 32_000_000 // 32 AETHEL in uaethel (6 decimals)
	MaxStakePerTxUAETH     = 10_000_000_000_000
	UnbondingPeriodSeconds = 14 * 24 * 60 * 60 // 14 days
	EpochDurationSeconds   = 24 * 60 * 60       // 24 hours

	// Fee parameters (basis points).
	ProtocolFeeBPS     = 500  // 5%
	MEVStakerShareBPS  = 9000 // 90%
	MaxCommissionBPS   = 1000 // 10%
	BPSDenominator     = 10000

	// Validator limits.
	MaxValidators = 200
	MinValidators = 4

	// Withdrawal limits.
	MaxWithdrawalRequestsPerUser = 100
	MaxBatchWithdrawSize         = 50

	// Rate limiting.
	MaxStakePerEpochUAETH = 500_000_000_000_000

	// Circuit breaker defaults.
	DefaultMaxUnstakePerEpochPct = 25
	DefaultMaxSlashesPerEpoch    = 3

	// Telemetry freshness.
	// DefaultTelemetryMaxAgeSec is the default maximum age (in seconds) for
	// validator telemetry to be considered fresh enough for TEE scoring.
	// Validators whose TelemetryUpdatedAt is older than this are excluded
	// from BuildValidatorSelectionRequest().  Defaults to 2× epoch duration
	// to allow one missed update cycle before exclusion.
	DefaultTelemetryMaxAgeSec = 2 * EpochDurationSeconds // 48 hours

	// Telemetry quorum.
	// DefaultMinTelemetryQuorumPct is the minimum percentage (0–100) of
	// active validators that must have fresh telemetry for
	// BuildValidatorSelectionRequest() to proceed.  This prevents a
	// malicious relayer from biasing the candidate set by selectively
	// withholding UpdateValidatorTelemetry() calls for targeted validators.
	// Default 67 ≈ two-thirds supermajority.
	DefaultMinTelemetryQuorumPct = 67
)

// StakerRecord represents a user's staking position.
type StakerRecord struct {
	Address        string    `json:"address"`
	EvmAddress     string    `json:"evm_address"`      // Canonical 20-byte EVM address (hex, no 0x prefix)
	Shares         uint64    `json:"shares"`            // stAETHEL shares
	StakedAmount   uint64    `json:"staked_amount"`     // Original AETHEL staked (uaethel)
	DelegatedTo    string    `json:"delegated_to"`      // Validator address
	StakedAt       time.Time `json:"staked_at"`
	LastRewardAt   time.Time `json:"last_reward_at"`
	ReferralCode   uint64    `json:"referral_code"`
}

// ValidatorRecord represents a validator in the active set.
//
// Telemetry fields (UptimePct, AvgResponseMs, TotalJobsCompleted, CountryCode)
// are populated by an external oracle or relayer via UpdateValidatorTelemetry().
// BuildValidatorSelectionRequest() will reject validators whose telemetry has
// not been populated (TelemetryUpdatedAt is zero), preventing the TEE from
// scoring fabricated data.
type ValidatorRecord struct {
	Address              string    `json:"address"`
	DelegatedStake       uint64    `json:"delegated_stake"`
	PerformanceScore     uint32    `json:"performance_score"`      // 0-10000
	DecentralizationScore uint32   `json:"decentralization_score"` // 0-10000
	ReputationScore      uint32    `json:"reputation_score"`       // 0-10000
	CompositeScore       uint32    `json:"composite_score"`
	TEEPublicKey         []byte    `json:"tee_public_key"`
	Commission           uint32    `json:"commission"`             // Basis points
	ActiveSince          time.Time `json:"active_since"`
	SlashCount           uint32    `json:"slash_count"`
	IsActive             bool      `json:"is_active"`
	GeographicRegion     string    `json:"geographic_region"`
	OperatorID           string    `json:"operator_id"`

	// ── Telemetry (oracle-supplied) ─────────────────────────────────────
	// These fields are written by UpdateValidatorTelemetry() and read by
	// BuildValidatorSelectionRequest(). They must reflect real monitoring
	// data — the TEE scoring algorithm uses them directly for performance
	// and reputation scoring.

	// UptimePct is the validator's uptime percentage (0.0–100.0) over the
	// most recent observation window. Used for 50% of performance scoring.
	UptimePct float64 `json:"uptime_pct"`
	// AvgResponseMs is the validator's average response latency in
	// milliseconds. Lower is better. Used for 30% of performance scoring.
	AvgResponseMs float64 `json:"avg_response_ms"`
	// TotalJobsCompleted is the cumulative count of successfully completed
	// validation jobs. Used for 20% of performance and 30% of reputation.
	TotalJobsCompleted uint64 `json:"total_jobs_completed"`
	// CountryCode is the ISO 3166-1 alpha-2 country code for the
	// validator's primary location (e.g. "US", "DE", "JP").
	CountryCode string `json:"country_code"`
	// TelemetryUpdatedAt records when telemetry was last written.
	// Zero value means telemetry has never been populated.
	TelemetryUpdatedAt time.Time `json:"telemetry_updated_at"`
}

// WithdrawalRequest represents an unbonding request.
type WithdrawalRequest struct {
	ID             uint64    `json:"id"`
	Owner          string    `json:"owner"`
	Shares         uint64    `json:"shares"`
	AethelAmount   uint64    `json:"aethel_amount"`   // uaethel
	RequestTime    time.Time `json:"request_time"`
	CompletionTime time.Time `json:"completion_time"`
	Claimed        bool      `json:"claimed"`
}

// EpochSnapshot stores the state at the end of each epoch.
type EpochSnapshot struct {
	Epoch                uint64    `json:"epoch"`
	TotalPooledAethel    uint64    `json:"total_pooled_aethel"`
	TotalShares          uint64    `json:"total_shares"`
	RewardsDistributed   uint64    `json:"rewards_distributed"`
	MEVRedistributed     uint64    `json:"mev_redistributed"`
	ProtocolFee          uint64    `json:"protocol_fee"`
	RewardsMerkleRoot    []byte    `json:"rewards_merkle_root"`
	ValidatorSetHash     []byte    `json:"validator_set_hash"`
	TEEAttestationHash   []byte    `json:"tee_attestation_hash"`
	Timestamp            time.Time `json:"timestamp"`
	Finalized            bool      `json:"finalized"`
}

// RewardAllocation is an individual staker's reward for an epoch.
type RewardAllocation struct {
	Address          string `json:"address"`
	BaseReward       uint64 `json:"base_reward"`
	PerformanceBonus uint64 `json:"performance_bonus"`
	MEVShare         uint64 `json:"mev_share"`
	TotalReward      uint64 `json:"total_reward"`
}

// VaultParams stores configurable protocol parameters.
type VaultParams struct {
	MinStake             uint64 `json:"min_stake"`
	UnbondingPeriod      uint64 `json:"unbonding_period"`       // seconds
	EpochDuration        uint64 `json:"epoch_duration"`         // seconds
	ProtocolFeeBPS       uint32 `json:"protocol_fee_bps"`
	MEVStakerShareBPS    uint32 `json:"mev_staker_share_bps"`
	MaxCommission        uint32 `json:"max_commission"`
	MaxValidators        uint32 `json:"max_validators"`
	MinValidators        uint32 `json:"min_validators"`
	TEEWorkerURL         string `json:"tee_worker_url"`
	Treasury             string `json:"treasury"`
	// TelemetryMaxAgeSec is the maximum age (in seconds) for validator
	// telemetry to be considered fresh.  Validators whose
	// TelemetryUpdatedAt is older than block_time - TelemetryMaxAgeSec
	// are excluded from the TEE selection request.
	// 0 means use DefaultTelemetryMaxAgeSec.
	TelemetryMaxAgeSec   uint64 `json:"telemetry_max_age_sec"`
	// MinTelemetryQuorumPct is the minimum percentage (0–100) of active
	// validators that must have fresh telemetry before a TEE selection
	// request is built.  If fewer than this fraction have fresh telemetry
	// the request is rejected, preventing a relayer from biasing the
	// candidate set by selective telemetry omission.
	// 0 means use DefaultMinTelemetryQuorumPct.
	MinTelemetryQuorumPct uint32 `json:"min_telemetry_quorum_pct"`
}

// DefaultParams returns the default vault parameters.
func DefaultParams() VaultParams {
	return VaultParams{
		MinStake:            MinStakeUAETH,
		UnbondingPeriod:     UnbondingPeriodSeconds,
		EpochDuration:       EpochDurationSeconds,
		ProtocolFeeBPS:      ProtocolFeeBPS,
		MEVStakerShareBPS:   MEVStakerShareBPS,
		MaxCommission:       MaxCommissionBPS,
		MaxValidators:       MaxValidators,
		MinValidators:       MinValidators,
		TEEWorkerURL:        "http://localhost:8547",
		Treasury:            "",
		TelemetryMaxAgeSec:    DefaultTelemetryMaxAgeSec,
		MinTelemetryQuorumPct: DefaultMinTelemetryQuorumPct,
	}
}

// Validate checks the parameters for correctness.
func (p VaultParams) Validate() error {
	if p.MinStake == 0 {
		return fmt.Errorf("min_stake must be > 0")
	}
	if p.UnbondingPeriod == 0 {
		return fmt.Errorf("unbonding_period must be > 0")
	}
	if p.EpochDuration == 0 {
		return fmt.Errorf("epoch_duration must be > 0")
	}
	if p.ProtocolFeeBPS > 2000 {
		return fmt.Errorf("protocol_fee_bps must be <= 2000 (20%%)")
	}
	if p.MEVStakerShareBPS > BPSDenominator {
		return fmt.Errorf("mev_staker_share_bps must be <= %d", BPSDenominator)
	}
	if p.MaxCommission > 5000 {
		return fmt.Errorf("max_commission must be <= 5000 (50%%)")
	}
	if p.MaxValidators < p.MinValidators {
		return fmt.Errorf("max_validators must be >= min_validators")
	}
	if p.MinTelemetryQuorumPct > 100 {
		return fmt.Errorf("min_telemetry_quorum_pct must be <= 100")
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// TEE Attestation Types
// ─────────────────────────────────────────────────────────────────────────────

// TEEAttestation represents a TEE attestation document for on-chain verification.
// All binary fields are hex-encoded strings for deterministic JSON serialization.
type TEEAttestation struct {
	Platform         uint8  `json:"platform"`           // 0=SGX, 1=Nitro, 2=SEV
	Timestamp        int64  `json:"timestamp"`          // Unix seconds
	Nonce            string `json:"nonce"`              // hex, 32 bytes
	EnclaveHash      string `json:"enclave_hash"`       // hex, 32 bytes (MRENCLAVE / PCR0)
	SignerHash       string `json:"signer_hash"`        // hex, 32 bytes (MRSIGNER / PCR1)
	PayloadHash      string `json:"payload_hash"`       // hex, SHA-256 of the attested data
	PlatformEvidence string `json:"platform_evidence"`  // hex, ABI-encoded platform evidence
	Signature        string `json:"signature"`          // hex, 65 bytes (R‖S‖V secp256k1)
}

// EnclaveRegistration represents a registered TEE enclave configuration.
type EnclaveRegistration struct {
	EnclaveHash     string `json:"enclave_hash"`      // hex, 32 bytes (MRENCLAVE / PCR0)
	SignerHash      string `json:"signer_hash"`       // hex, 32 bytes (MRSIGNER / PCR1)
	ApplicationHash string `json:"application_hash"`  // hex, 32 bytes (Nitro PCR2; empty for SGX/SEV)
	Platform        uint8  `json:"platform"`
	Active          bool   `json:"active"`
	Description     string `json:"description"`
	PlatformKeyX    string `json:"platform_key_x"`    // P-256 public key X coordinate (hex, 32 bytes)
	PlatformKeyY    string `json:"platform_key_y"`    // P-256 public key Y coordinate (hex, 32 bytes)
	VendorAttestR   string `json:"vendor_attest_r"`   // P-256 vendor root signature R (hex, 32 bytes)
	VendorAttestS   string `json:"vendor_attest_s"`   // P-256 vendor root signature S (hex, 32 bytes)
}

// OperatorRegistration represents a registered TEE operator bound to a specific enclave.
type OperatorRegistration struct {
	PubKeyHex   string `json:"pub_key_hex"`  // compressed secp256k1 public key, hex (33 bytes)
	EnclaveID   string `json:"enclave_id"`   // hex — SHA-256(enclaveHash ‖ platform)
	Active      bool   `json:"active"`
	Description string `json:"description"`
}

// AttestationRelay represents a registered attestation relay for a TEE platform.
//
// An attestation relay is a trusted bridge service that verifies hardware
// evidence (DCAP/NSM/PSP) off-chain and signs platform key bindings with its
// P-256 signing key. The relay's key is registered as the vendor root key
// for the platform, enabling RegisterEnclave() to verify relay-signed attestations.
//
// Governance accountability controls:
//   - Identity and registration timestamp are permanently recorded
//   - Key rotation requires a time-lock delay (RelayRotationDelaySec)
//   - Governance can issue liveness challenges requiring P-256 proof-of-possession
//   - Emergency revocation immediately disables the relay
//
// This struct mirrors the AttestationRelay struct in VaultTEEVerifier.sol to
// ensure cross-network trust model consistency between the EVM and native paths.
type AttestationRelay struct {
	PublicKeyX        string `json:"public_key_x"`         // Current P-256 signing key X (hex, 32 bytes)
	PublicKeyY        string `json:"public_key_y"`         // Current P-256 signing key Y (hex, 32 bytes)
	RegisteredAt      int64  `json:"registered_at"`        // Unix timestamp of initial registration
	LastRotatedAt     int64  `json:"last_rotated_at"`      // Unix timestamp of last key rotation
	AttestationCount  uint64 `json:"attestation_count"`    // Enclaves certified by this relay
	Active            bool   `json:"active"`               // Whether the relay is currently active
	// Time-locked key rotation
	PendingKeyX       string `json:"pending_key_x"`        // Pending new key X (empty if no rotation pending)
	PendingKeyY       string `json:"pending_key_y"`        // Pending new key Y (empty if no rotation pending)
	RotationUnlocksAt int64  `json:"rotation_unlocks_at"`  // Unix timestamp when pending rotation can finalize
	// Liveness challenge
	ActiveChallenge   string `json:"active_challenge"`     // Current governance-issued challenge nonce (hex, 32 bytes)
	ChallengeDeadline int64  `json:"challenge_deadline"`   // Unix timestamp deadline for relay response
	Description       string `json:"description"`          // Human-readable relay identity
}

const (
	// MaxAttestationAgeSec is the maximum allowed attestation age (5 minutes).
	MaxAttestationAgeSec = 300

	// PlatformSGX identifies Intel SGX enclaves.
	PlatformSGX uint8 = 0
	// PlatformNitro identifies AWS Nitro Enclaves.
	PlatformNitro uint8 = 1
	// PlatformSEV identifies AMD SEV enclaves.
	PlatformSEV uint8 = 2

	// RelayRotationDelaySec is the time-lock delay for relay key rotations (48 hours).
	// Matches RELAY_ROTATION_DELAY in VaultTEEVerifier.sol.
	RelayRotationDelaySec = 48 * 60 * 60 // 48 hours

	// RelayChallengeWindowSec is the window for relay liveness challenge responses (1 hour).
	// Matches RELAY_CHALLENGE_WINDOW in VaultTEEVerifier.sol.
	RelayChallengeWindowSec = 60 * 60 // 1 hour
)

// PauseState represents the vault's emergency pause status.
// When paused, all mutating operations (Stake, Unstake, Withdraw,
// DelegateStake, ApplyValidatorSelection, SlashValidator) are blocked.
// Only governance (authority) can pause/unpause.
type PauseState struct {
	Paused    bool      `json:"paused"`
	Reason    string    `json:"reason"`      // Human-readable reason for the pause
	PausedBy  string    `json:"paused_by"`   // Authority address that triggered the pause
	PausedAt  time.Time `json:"paused_at"`   // When the pause was activated
	EventLog  []PauseEvent `json:"event_log"` // Audit trail of pause/unpause events
}

// PauseEvent is an audit log entry for pause/unpause actions.
type PauseEvent struct {
	Action    string    `json:"action"`     // "pause" or "unpause"
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	Timestamp time.Time `json:"timestamp"`
}

// CircuitBreakerConfig defines thresholds for automatic circuit-breaking.
// If any threshold is breached within a single epoch, the vault automatically
// pauses to prevent further damage pending governance intervention.
type CircuitBreakerConfig struct {
	// MaxUnstakePerEpochPct is the maximum percentage (0–100) of total pooled
	// AETHEL that can be unstaked in a single epoch before the circuit breaker
	// trips. 0 means disabled. Default: 25 (25% of TVL).
	MaxUnstakePerEpochPct uint32 `json:"max_unstake_per_epoch_pct"`
	// MaxSlashesPerEpoch is the maximum number of validator slashes allowed
	// in a single epoch before the circuit breaker trips. 0 means disabled.
	// Default: 3.
	MaxSlashesPerEpoch uint32 `json:"max_slashes_per_epoch"`
	// Enabled controls whether the circuit breaker is active.
	Enabled bool `json:"enabled"`
}

// DefaultCircuitBreakerConfig returns sensible defaults for the circuit breaker.
// The circuit breaker is disabled by default and must be explicitly enabled
// by governance after parameter tuning for the specific deployment.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxUnstakePerEpochPct: 25,
		MaxSlashesPerEpoch:    3,
		Enabled:               false,
	}
}

// OperatorAction represents an auditable operator action for the activity log.
type OperatorAction struct {
	Operator  string    `json:"operator"`   // Operator pubkey hex
	Action    string    `json:"action"`     // e.g. "register_enclave", "register_operator", etc.
	Target    string    `json:"target"`     // EnclaveID or operator key affected
	Timestamp time.Time `json:"timestamp"`
	TxHash    string    `json:"tx_hash"`    // Transaction hash for traceability
}

// VaultStatus represents the overall vault state for API responses.
type VaultStatus struct {
	TotalPooledAethel    uint64            `json:"total_pooled_aethel"`
	TotalShares          uint64            `json:"total_shares"`
	ExchangeRate         float64           `json:"exchange_rate"`
	CurrentEpoch         uint64            `json:"current_epoch"`
	ActiveValidators     uint32            `json:"active_validators"`
	TotalStakers         uint64            `json:"total_stakers"`
	PendingWithdrawals   uint64            `json:"pending_withdrawals"`
	TotalMEVRevenue      uint64            `json:"total_mev_revenue"`
	EffectiveAPY         float64           `json:"effective_apy"`
	Params               VaultParams       `json:"params"`
	Paused               bool              `json:"paused"`
	PauseReason          string            `json:"pause_reason,omitempty"`
}
