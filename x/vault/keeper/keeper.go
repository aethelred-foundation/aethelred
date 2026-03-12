// Package keeper implements the Crucible Cosmos SDK module keeper.
//
// The keeper manages state for the liquid staking vault including:
//   - Staker records and share balances
//   - Validator set (TEE-verified)
//   - Withdrawal (unbonding) queue
//   - Epoch snapshots and reward history
//   - TEE worker integration
//
// All state is persisted to the KVStore via cosmossdk.io/collections,
// ensuring determinism and crash recovery.
package keeper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/vault/types"
)

// Store key prefixes for collections.
var (
	ParamsKey            = collections.NewPrefix(0)
	StakersKey           = collections.NewPrefix(1)
	ValidatorsKey        = collections.NewPrefix(2)
	WithdrawalsKey       = collections.NewPrefix(3)
	EpochSnapshotsKey    = collections.NewPrefix(4)
	StakePerEpochKey     = collections.NewPrefix(5)
	RewardsClaimedKey    = collections.NewPrefix(6)
	TotalPooledAethelKey = collections.NewPrefix(7)
	TotalSharesKey       = collections.NewPrefix(8)
	CurrentEpochKey      = collections.NewPrefix(9)
	NextWithdrawalIDKey  = collections.NewPrefix(10)
	TotalPendingKey      = collections.NewPrefix(11)
	TotalMEVKey          = collections.NewPrefix(12)
	ActiveValidatorsKey    = collections.NewPrefix(13)
	UserWithdrawalsKey     = collections.NewPrefix(14)
	RegisteredEnclavesKey  = collections.NewPrefix(15)
	RegisteredOperatorsKey = collections.NewPrefix(16)
	UsedNoncesKey          = collections.NewPrefix(17)
	VendorRootKeysKey      = collections.NewPrefix(18)
	DelegationSnapshotsKey     = collections.NewPrefix(19)
	PauseStateKey              = collections.NewPrefix(20)
	CircuitBreakerConfigKey    = collections.NewPrefix(21)
	EpochUnstakeAccumKey       = collections.NewPrefix(22) // epoch → cumulative unstaked amount
	EpochSlashCountKey         = collections.NewPrefix(23) // epoch → number of slashes
	OperatorAuditLogKey        = collections.NewPrefix(24) // index → JSON OperatorAction
	AttestationRelaysKey       = collections.NewPrefix(25) // platformId (string) → JSON AttestationRelay
)

// Keeper manages the Crucible module state.
//
// All state is backed by the KVStore via collections.
// No in-memory maps or mutexes — Cosmos SDK guarantees single-threaded
// ABCI execution and provides crash-safe persistence.
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	authority    string

	// Store-backed scalar state.
	Params                  collections.Item[string]
	TotalPooledAethel       collections.Item[uint64]
	TotalShares             collections.Item[uint64]
	CurrentEpoch            collections.Item[uint64]
	NextWithdrawalID        collections.Item[uint64]
	TotalPendingWithdrawals collections.Item[uint64]
	TotalMEVRevenue         collections.Item[uint64]
	ActiveValidatorsList    collections.Item[string] // JSON array of validator addresses

	// Store-backed maps.
	Stakers         collections.Map[string, string] // address → JSON StakerRecord
	Validators      collections.Map[string, string] // address → JSON ValidatorRecord
	Withdrawals     collections.Map[string, string] // withdrawalID (string) → JSON WithdrawalRequest
	EpochSnapshots  collections.Map[string, string] // epoch (string) → JSON EpochSnapshot
	StakePerEpoch   collections.Map[string, uint64] // epoch (string) → total staked this epoch
	RewardsClaimed  collections.Map[string, string] // "addr:epoch" → "true"
	UserWithdrawals collections.Map[string, string] // address → JSON array of withdrawal IDs

	// TEE verification state.
	RegisteredEnclaves  collections.Map[string, string] // enclaveID (hex) → JSON EnclaveRegistration
	RegisteredOperators collections.Map[string, string] // pubKeyHex → JSON OperatorRegistration
	UsedNonces          collections.Map[string, string] // nonce (hex) → "used"

	// Vendor root P-256 public keys (hardware manufacturer root keys).
	VendorRootKeys collections.Map[string, string] // platformId (string) → JSON {X, Y}

	// Attestation relays — trusted bridge services that verify hardware evidence
	// off-chain and sign platform key bindings. Provides relay accountability:
	// identity tracking, time-locked rotation, liveness challenges, emergency revocation.
	// Mirrors the attestationRelays mapping in VaultTEEVerifier.sol.
	AttestationRelays collections.Map[string, string] // platformId (string) → JSON AttestationRelay

	// Epoch-scoped delegation snapshots.
	// Captures each staker's delegation mapping at the moment the relayer
	// freezes delegation state, ensuring temporal consistency with the
	// share distribution anchored by commitStakeSnapshot on EVM.
	DelegationSnapshots collections.Map[string, string] // epoch (string) → JSON []stakerStakeEntry

	// Emergency pause and circuit breaker state.
	PauseState          collections.Item[string]         // JSON PauseState
	CircuitBreakerCfg   collections.Item[string]         // JSON CircuitBreakerConfig
	EpochUnstakeAccum   collections.Map[string, uint64]  // epoch (string) → cumulative unstaked uaethel
	EpochSlashCount     collections.Map[string, uint64]  // epoch (string) → number of slashes
	OperatorAuditLog    collections.Map[string, string]  // auto-increment index → JSON OperatorAction
}

// NewKeeper creates a new Crucible keeper with store-backed collections.
// State initialization happens via InitializeDefaults (called from InitGenesis).
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	authority string,
) *Keeper {
	sb := collections.NewSchemaBuilder(storeService)

	k := &Keeper{
		cdc:          cdc,
		storeService: storeService,
		authority:    authority,

		Params:                  collections.NewItem(sb, ParamsKey, "params", collections.StringValue),
		TotalPooledAethel:       collections.NewItem(sb, TotalPooledAethelKey, "total_pooled_aethel", collections.Uint64Value),
		TotalShares:             collections.NewItem(sb, TotalSharesKey, "total_shares", collections.Uint64Value),
		CurrentEpoch:            collections.NewItem(sb, CurrentEpochKey, "current_epoch", collections.Uint64Value),
		NextWithdrawalID:        collections.NewItem(sb, NextWithdrawalIDKey, "next_withdrawal_id", collections.Uint64Value),
		TotalPendingWithdrawals: collections.NewItem(sb, TotalPendingKey, "total_pending_withdrawals", collections.Uint64Value),
		TotalMEVRevenue:         collections.NewItem(sb, TotalMEVKey, "total_mev_revenue", collections.Uint64Value),
		ActiveValidatorsList:    collections.NewItem(sb, ActiveValidatorsKey, "active_validators", collections.StringValue),

		Stakers:         collections.NewMap(sb, StakersKey, "stakers", collections.StringKey, collections.StringValue),
		Validators:      collections.NewMap(sb, ValidatorsKey, "validators", collections.StringKey, collections.StringValue),
		Withdrawals:     collections.NewMap(sb, WithdrawalsKey, "withdrawals", collections.StringKey, collections.StringValue),
		EpochSnapshots:  collections.NewMap(sb, EpochSnapshotsKey, "epoch_snapshots", collections.StringKey, collections.StringValue),
		StakePerEpoch:   collections.NewMap(sb, StakePerEpochKey, "stake_per_epoch", collections.StringKey, collections.Uint64Value),
		RewardsClaimed:  collections.NewMap(sb, RewardsClaimedKey, "rewards_claimed", collections.StringKey, collections.StringValue),
		UserWithdrawals: collections.NewMap(sb, UserWithdrawalsKey, "user_withdrawals", collections.StringKey, collections.StringValue),

		RegisteredEnclaves:  collections.NewMap(sb, RegisteredEnclavesKey, "registered_enclaves", collections.StringKey, collections.StringValue),
		RegisteredOperators: collections.NewMap(sb, RegisteredOperatorsKey, "registered_operators", collections.StringKey, collections.StringValue),
		UsedNonces:          collections.NewMap(sb, UsedNoncesKey, "used_nonces", collections.StringKey, collections.StringValue),
		VendorRootKeys:      collections.NewMap(sb, VendorRootKeysKey, "vendor_root_keys", collections.StringKey, collections.StringValue),
		AttestationRelays:   collections.NewMap(sb, AttestationRelaysKey, "attestation_relays", collections.StringKey, collections.StringValue),

		DelegationSnapshots: collections.NewMap(sb, DelegationSnapshotsKey, "delegation_snapshots", collections.StringKey, collections.StringValue),

		PauseState:        collections.NewItem(sb, PauseStateKey, "pause_state", collections.StringValue),
		CircuitBreakerCfg: collections.NewItem(sb, CircuitBreakerConfigKey, "circuit_breaker_config", collections.StringValue),
		EpochUnstakeAccum: collections.NewMap(sb, EpochUnstakeAccumKey, "epoch_unstake_accum", collections.StringKey, collections.Uint64Value),
		EpochSlashCount:   collections.NewMap(sb, EpochSlashCountKey, "epoch_slash_count", collections.StringKey, collections.Uint64Value),
		OperatorAuditLog:  collections.NewMap(sb, OperatorAuditLogKey, "operator_audit_log", collections.StringKey, collections.StringValue),
	}

	return k
}

// InitializeDefaults sets initial state values if not already present.
// Called from InitGenesis or module initialization.
func (k *Keeper) InitializeDefaults(ctx context.Context) error {
	if _, err := k.CurrentEpoch.Get(ctx); err != nil {
		if err := k.CurrentEpoch.Set(ctx, 1); err != nil {
			return err
		}
		if err := k.NextWithdrawalID.Set(ctx, 1); err != nil {
			return err
		}
		if err := k.TotalPooledAethel.Set(ctx, 0); err != nil {
			return err
		}
		if err := k.TotalShares.Set(ctx, 0); err != nil {
			return err
		}
		if err := k.TotalPendingWithdrawals.Set(ctx, 0); err != nil {
			return err
		}
		if err := k.TotalMEVRevenue.Set(ctx, 0); err != nil {
			return err
		}
		paramsJSON, err := json.Marshal(types.DefaultParams())
		if err != nil {
			return err
		}
		if err := k.Params.Set(ctx, string(paramsJSON)); err != nil {
			return err
		}
		if err := k.ActiveValidatorsList.Set(ctx, "[]"); err != nil {
			return err
		}
		// Initialize pause state (unpaused).
		pauseJSON, err := json.Marshal(types.PauseState{Paused: false})
		if err != nil {
			return err
		}
		if err := k.PauseState.Set(ctx, string(pauseJSON)); err != nil {
			return err
		}
		// Initialize circuit breaker config with sensible defaults.
		cbJSON, err := json.Marshal(types.DefaultCircuitBreakerConfig())
		if err != nil {
			return err
		}
		if err := k.CircuitBreakerCfg.Set(ctx, string(cbJSON)); err != nil {
			return err
		}
	}
	return nil
}

// GetAuthority returns the module authority address.
func (k *Keeper) GetAuthority() string {
	return k.authority
}

// ─────────────────────────────────────────────────────────────────────────────
// Store Helpers
// ─────────────────────────────────────────────────────────────────────────────

func (k *Keeper) getUint64(ctx context.Context, item collections.Item[uint64]) uint64 {
	val, err := item.Get(ctx)
	if err != nil {
		return 0
	}
	return val
}

func (k *Keeper) getParams(ctx context.Context) types.VaultParams {
	raw, err := k.Params.Get(ctx)
	if err != nil {
		return types.DefaultParams()
	}
	var p types.VaultParams
	if json.Unmarshal([]byte(raw), &p) != nil {
		return types.DefaultParams()
	}
	return p
}

func (k *Keeper) getStaker(ctx context.Context, address string) (*types.StakerRecord, bool) {
	raw, err := k.Stakers.Get(ctx, address)
	if err != nil {
		return nil, false
	}
	var s types.StakerRecord
	if json.Unmarshal([]byte(raw), &s) != nil {
		return nil, false
	}
	return &s, true
}

func (k *Keeper) setStaker(ctx context.Context, s *types.StakerRecord) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return k.Stakers.Set(ctx, s.Address, string(data))
}

func (k *Keeper) getValidator(ctx context.Context, address string) (*types.ValidatorRecord, bool) {
	raw, err := k.Validators.Get(ctx, address)
	if err != nil {
		return nil, false
	}
	var v types.ValidatorRecord
	if json.Unmarshal([]byte(raw), &v) != nil {
		return nil, false
	}
	return &v, true
}

func (k *Keeper) setValidator(ctx context.Context, v *types.ValidatorRecord) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return k.Validators.Set(ctx, v.Address, string(data))
}

func (k *Keeper) getWithdrawal(ctx context.Context, id uint64) (*types.WithdrawalRequest, bool) {
	raw, err := k.Withdrawals.Get(ctx, strconv.FormatUint(id, 10))
	if err != nil {
		return nil, false
	}
	var w types.WithdrawalRequest
	if json.Unmarshal([]byte(raw), &w) != nil {
		return nil, false
	}
	return &w, true
}

func (k *Keeper) setWithdrawal(ctx context.Context, w *types.WithdrawalRequest) error {
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return k.Withdrawals.Set(ctx, strconv.FormatUint(w.ID, 10), string(data))
}

func (k *Keeper) getUserWithdrawalIDs(ctx context.Context, address string) []uint64 {
	raw, err := k.UserWithdrawals.Get(ctx, address)
	if err != nil {
		return nil
	}
	var ids []uint64
	if json.Unmarshal([]byte(raw), &ids) != nil {
		return nil
	}
	return ids
}

func (k *Keeper) setUserWithdrawalIDs(ctx context.Context, address string, ids []uint64) error {
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return k.UserWithdrawals.Set(ctx, address, string(data))
}

func (k *Keeper) getActiveValidatorAddrs(ctx context.Context) []string {
	raw, err := k.ActiveValidatorsList.Get(ctx)
	if err != nil {
		return nil
	}
	var addrs []string
	if json.Unmarshal([]byte(raw), &addrs) != nil {
		return nil
	}
	return addrs
}

func (k *Keeper) setActiveValidatorAddrs(ctx context.Context, addrs []string) error {
	data, err := json.Marshal(addrs)
	if err != nil {
		return err
	}
	return k.ActiveValidatorsList.Set(ctx, string(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// Emergency Pause & Circuit Breaker
// ─────────────────────────────────────────────────────────────────────────────

// getPauseState returns the current pause state. Defaults to unpaused.
func (k *Keeper) getPauseState(ctx context.Context) types.PauseState {
	raw, err := k.PauseState.Get(ctx)
	if err != nil {
		return types.PauseState{Paused: false}
	}
	var ps types.PauseState
	if json.Unmarshal([]byte(raw), &ps) != nil {
		return types.PauseState{Paused: false}
	}
	return ps
}

// setPauseState persists the pause state.
func (k *Keeper) setPauseState(ctx context.Context, ps types.PauseState) error {
	data, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	return k.PauseState.Set(ctx, string(data))
}

// getCircuitBreakerConfig returns the circuit breaker configuration.
func (k *Keeper) getCircuitBreakerConfig(ctx context.Context) types.CircuitBreakerConfig {
	raw, err := k.CircuitBreakerCfg.Get(ctx)
	if err != nil {
		return types.DefaultCircuitBreakerConfig()
	}
	var cb types.CircuitBreakerConfig
	if json.Unmarshal([]byte(raw), &cb) != nil {
		return types.DefaultCircuitBreakerConfig()
	}
	return cb
}

// IsPaused returns true if the vault is currently paused.
func (k *Keeper) IsPaused(ctx context.Context) bool {
	return k.getPauseState(ctx).Paused
}

// requireNotPaused returns ErrVaultPaused if the vault is paused.
// Call this at the top of every mutating operation.
func (k *Keeper) requireNotPaused(ctx context.Context) error {
	ps := k.getPauseState(ctx)
	if ps.Paused {
		return fmt.Errorf("%w: %s", types.ErrVaultPaused, ps.Reason)
	}
	return nil
}

// PauseVault activates the emergency pause. Only callable by the module
// authority. While paused, Stake, Unstake, Withdraw, DelegateStake,
// ApplyValidatorSelection, and SlashValidator are all blocked.
//
// Pause events are appended to an audit log for transparency.
func (k *Keeper) PauseVault(ctx context.Context, caller string, reason string) error {
	if caller != k.authority {
		return fmt.Errorf("%w: %s is not authority %s", types.ErrUnauthorized, caller, k.authority)
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	ps := k.getPauseState(ctx)
	if ps.Paused {
		return fmt.Errorf("vault is already paused (reason: %s)", ps.Reason)
	}

	event := types.PauseEvent{
		Action:    "pause",
		Reason:    reason,
		Actor:     caller,
		Timestamp: blockTime,
	}

	ps.Paused = true
	ps.Reason = reason
	ps.PausedBy = caller
	ps.PausedAt = blockTime
	ps.EventLog = append(ps.EventLog, event)

	return k.setPauseState(ctx, ps)
}

// UnpauseVault deactivates the emergency pause. Only callable by the module
// authority.
func (k *Keeper) UnpauseVault(ctx context.Context, caller string, reason string) error {
	if caller != k.authority {
		return fmt.Errorf("%w: %s is not authority %s", types.ErrUnauthorized, caller, k.authority)
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	ps := k.getPauseState(ctx)
	if !ps.Paused {
		return fmt.Errorf("vault is not paused")
	}

	event := types.PauseEvent{
		Action:    "unpause",
		Reason:    reason,
		Actor:     caller,
		Timestamp: blockTime,
	}

	ps.Paused = false
	ps.Reason = ""
	ps.PausedBy = ""
	ps.EventLog = append(ps.EventLog, event)

	return k.setPauseState(ctx, ps)
}

// GetPauseState returns the full pause state including audit log.
func (k *Keeper) GetPauseState(ctx context.Context) types.PauseState {
	return k.getPauseState(ctx)
}

// UpdateCircuitBreakerConfig updates the circuit breaker configuration.
// Only callable by the module authority.
func (k *Keeper) UpdateCircuitBreakerConfig(ctx context.Context, caller string, cfg types.CircuitBreakerConfig) error {
	if caller != k.authority {
		return fmt.Errorf("%w: %s is not authority %s", types.ErrUnauthorized, caller, k.authority)
	}
	if cfg.MaxUnstakePerEpochPct > 100 {
		return fmt.Errorf("max_unstake_per_epoch_pct must be <= 100, got %d", cfg.MaxUnstakePerEpochPct)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return k.CircuitBreakerCfg.Set(ctx, string(data))
}

// checkCircuitBreaker evaluates circuit breaker thresholds and auto-pauses
// if any threshold is breached. Called internally after unstake and slash.
func (k *Keeper) checkCircuitBreaker(ctx context.Context, trigger string) error {
	cfg := k.getCircuitBreakerConfig(ctx)
	if !cfg.Enabled {
		return nil
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)
	epochKey := strconv.FormatUint(currentEpoch, 10)

	// Check unstake accumulator against TVL percentage threshold.
	if cfg.MaxUnstakePerEpochPct > 0 {
		totalPooled := k.getUint64(ctx, k.TotalPooledAethel)
		epochUnstaked, _ := k.EpochUnstakeAccum.Get(ctx, epochKey)
		// threshold = totalPooled * maxPct / 100  (but use total BEFORE unstake for reference)
		threshold := (totalPooled + epochUnstaked) * uint64(cfg.MaxUnstakePerEpochPct) / 100
		if threshold > 0 && epochUnstaked > threshold {
			reason := fmt.Sprintf(
				"circuit breaker: epoch %d unstake volume %d exceeds %d%% of TVL (threshold %d)",
				currentEpoch, epochUnstaked, cfg.MaxUnstakePerEpochPct, threshold,
			)
			ps := k.getPauseState(ctx)
			if !ps.Paused {
				ps.Paused = true
				ps.Reason = reason
				ps.PausedBy = "circuit_breaker"
				ps.PausedAt = blockTime
				ps.EventLog = append(ps.EventLog, types.PauseEvent{
					Action:    "pause",
					Reason:    reason,
					Actor:     "circuit_breaker:" + trigger,
					Timestamp: blockTime,
				})
				_ = k.setPauseState(ctx, ps)
			}
			return fmt.Errorf("%w: %s", types.ErrCircuitBreakerTripped, reason)
		}
	}

	// Check slash count threshold.
	if cfg.MaxSlashesPerEpoch > 0 {
		epochSlashes, _ := k.EpochSlashCount.Get(ctx, epochKey)
		if epochSlashes > uint64(cfg.MaxSlashesPerEpoch) {
			reason := fmt.Sprintf(
				"circuit breaker: epoch %d slash count %d exceeds limit %d",
				currentEpoch, epochSlashes, cfg.MaxSlashesPerEpoch,
			)
			ps := k.getPauseState(ctx)
			if !ps.Paused {
				ps.Paused = true
				ps.Reason = reason
				ps.PausedBy = "circuit_breaker"
				ps.PausedAt = blockTime
				ps.EventLog = append(ps.EventLog, types.PauseEvent{
					Action:    "pause",
					Reason:    reason,
					Actor:     "circuit_breaker:" + trigger,
					Timestamp: blockTime,
				})
				_ = k.setPauseState(ctx, ps)
			}
			return fmt.Errorf("%w: %s", types.ErrCircuitBreakerTripped, reason)
		}
	}

	return nil
}

// appendOperatorAuditLog records an operator action for traceability.
func (k *Keeper) appendOperatorAuditLog(ctx context.Context, action types.OperatorAction) {
	data, err := json.Marshal(action)
	if err != nil {
		return
	}
	// Use timestamp as key (unique enough for audit trail).
	key := fmt.Sprintf("%d_%s", action.Timestamp.UnixNano(), action.Action)
	_ = k.OperatorAuditLog.Set(ctx, key, string(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// Staking Operations
// ─────────────────────────────────────────────────────────────────────────────

// Stake processes a staking request.
func (k *Keeper) Stake(ctx context.Context, address string, amount uint64, validatorAddr string, referralCode uint64) (shares uint64, err error) {
	if err := k.requireNotPaused(ctx); err != nil {
		return 0, err
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	params := k.getParams(ctx)
	if amount < params.MinStake {
		return 0, fmt.Errorf("amount %d below minimum stake %d", amount, params.MinStake)
	}

	// Validate delegation target.
	// A non-empty validatorAddr must reference an active validator.
	// An empty validatorAddr is rejected — delegation is mandatory for
	// performance-weighted reward distribution.
	if validatorAddr == "" {
		return 0, fmt.Errorf("validatorAddr is required: delegation is mandatory for reward weighting")
	}
	val, valExists := k.getValidator(ctx, validatorAddr)
	if !valExists {
		return 0, fmt.Errorf("validator %s not found", validatorAddr)
	}
	if !val.IsActive {
		return 0, fmt.Errorf("validator %s is not active", validatorAddr)
	}

	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)

	// Rate limit check
	epochKey := strconv.FormatUint(currentEpoch, 10)
	epochStake, _ := k.StakePerEpoch.Get(ctx, epochKey)
	epochStake += amount
	if epochStake > types.MaxStakePerEpochUAETH {
		return 0, fmt.Errorf("epoch rate limit exceeded")
	}
	if err := k.StakePerEpoch.Set(ctx, epochKey, epochStake); err != nil {
		return 0, fmt.Errorf("set stake per epoch: %w", err)
	}

	totalPooled := k.getUint64(ctx, k.TotalPooledAethel)
	totalShares := k.getUint64(ctx, k.TotalShares)

	// Calculate shares
	if totalPooled == 0 {
		shares = amount // 1:1 for first staker
	} else {
		shares = (amount * totalShares) / totalPooled
	}
	if shares == 0 {
		return 0, fmt.Errorf("computed shares is zero")
	}

	// Update totals
	if err := k.TotalPooledAethel.Set(ctx, totalPooled+amount); err != nil {
		return 0, err
	}
	if err := k.TotalShares.Set(ctx, totalShares+shares); err != nil {
		return 0, err
	}

	// Resolve the canonical 20-byte EVM address for registry root compatibility.
	evmAddr, evmErr := resolveEvmAddress(address)
	if evmErr != nil {
		return 0, fmt.Errorf("resolve EVM address for staker: %w", evmErr)
	}

	// Update staker record and validator DelegatedStake accounting.
	staker, exists := k.getStaker(ctx, address)
	if exists {
		// Backfill EvmAddress for pre-existing records that lack it.
		if staker.EvmAddress == "" {
			staker.EvmAddress = evmAddr
		}
		oldDelegatedTo := staker.DelegatedTo
		oldStakedAmount := staker.StakedAmount
		staker.Shares += shares
		staker.StakedAmount += amount
		staker.DelegatedTo = validatorAddr

		if oldDelegatedTo != validatorAddr {
			// Re-delegation: move existing stake from old validator, add everything to new.
			if oldDelegatedTo != "" {
				oldVal, oldValExists := k.getValidator(ctx, oldDelegatedTo)
				if oldValExists {
					if oldVal.DelegatedStake >= oldStakedAmount {
						oldVal.DelegatedStake -= oldStakedAmount
					} else {
						oldVal.DelegatedStake = 0
					}
					if err := k.setValidator(ctx, oldVal); err != nil {
						return 0, err
					}
				}
			}
			val.DelegatedStake += oldStakedAmount + amount
		} else {
			// Same validator: just add the new amount.
			val.DelegatedStake += amount
		}
	} else {
		staker = &types.StakerRecord{
			Address:      address,
			EvmAddress:   evmAddr,
			Shares:       shares,
			StakedAmount: amount,
			DelegatedTo:  validatorAddr,
			StakedAt:     blockTime,
			ReferralCode: referralCode,
		}
		val.DelegatedStake += amount
	}
	if err := k.setValidator(ctx, val); err != nil {
		return 0, err
	}
	if err := k.setStaker(ctx, staker); err != nil {
		return 0, err
	}

	return shares, nil
}

// DelegateStake updates the validator delegation for an existing staker.
//
// The target validator must exist and be active. This allows stakers to
// re-delegate without un-staking, ensuring their performance-weighted
// reward allocation reflects the chosen validator's score.
func (k *Keeper) DelegateStake(ctx context.Context, stakerAddr string, validatorAddr string) error {
	if err := k.requireNotPaused(ctx); err != nil {
		return err
	}

	if validatorAddr == "" {
		return fmt.Errorf("validatorAddr is required: delegation cannot be empty")
	}

	staker, exists := k.getStaker(ctx, stakerAddr)
	if !exists {
		return fmt.Errorf("staker not found: %s", stakerAddr)
	}

	val, valExists := k.getValidator(ctx, validatorAddr)
	if !valExists {
		return fmt.Errorf("validator %s not found", validatorAddr)
	}
	if !val.IsActive {
		return fmt.Errorf("validator %s is not active", validatorAddr)
	}

	// Transfer DelegatedStake from old validator to new validator.
	oldDelegatedTo := staker.DelegatedTo
	if oldDelegatedTo != validatorAddr {
		if oldDelegatedTo != "" {
			oldVal, oldValExists := k.getValidator(ctx, oldDelegatedTo)
			if oldValExists {
				if oldVal.DelegatedStake >= staker.StakedAmount {
					oldVal.DelegatedStake -= staker.StakedAmount
				} else {
					oldVal.DelegatedStake = 0
				}
				if err := k.setValidator(ctx, oldVal); err != nil {
					return err
				}
			}
		}
		val.DelegatedStake += staker.StakedAmount
		if err := k.setValidator(ctx, val); err != nil {
			return err
		}
	}

	staker.DelegatedTo = validatorAddr
	return k.setStaker(ctx, staker)
}

// Unstake initiates an unbonding request.
func (k *Keeper) Unstake(ctx context.Context, address string, shares uint64) (withdrawalID uint64, aethelAmount uint64, err error) {
	if err := k.requireNotPaused(ctx); err != nil {
		return 0, 0, err
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()
	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)
	epochKey := strconv.FormatUint(currentEpoch, 10)

	staker, exists := k.getStaker(ctx, address)
	if !exists {
		return 0, 0, fmt.Errorf("staker not found: %s", address)
	}
	if staker.Shares < shares {
		return 0, 0, fmt.Errorf("insufficient shares: have %d, want %d", staker.Shares, shares)
	}

	userIDs := k.getUserWithdrawalIDs(ctx, address)
	if len(userIDs) >= types.MaxWithdrawalRequestsPerUser {
		return 0, 0, fmt.Errorf("too many withdrawal requests for %s", address)
	}

	totalPooled := k.getUint64(ctx, k.TotalPooledAethel)
	totalShares := k.getUint64(ctx, k.TotalShares)

	// Calculate AETHEL amount
	if totalShares > 0 {
		aethelAmount = (shares * totalPooled) / totalShares
	}
	if aethelAmount == 0 {
		return 0, 0, fmt.Errorf("computed aethel amount is zero")
	}

	// Update validator DelegatedStake accounting.
	// Compute proportional StakedAmount being withdrawn before modifying shares.
	if staker.DelegatedTo != "" && staker.Shares > 0 {
		stakedReduction := (shares * staker.StakedAmount) / staker.Shares
		if stakedReduction > staker.StakedAmount {
			stakedReduction = staker.StakedAmount
		}

		delegatedVal, dvExists := k.getValidator(ctx, staker.DelegatedTo)
		if dvExists {
			if delegatedVal.DelegatedStake >= stakedReduction {
				delegatedVal.DelegatedStake -= stakedReduction
			} else {
				delegatedVal.DelegatedStake = 0
			}
			if err := k.setValidator(ctx, delegatedVal); err != nil {
				return 0, 0, err
			}
		}
		staker.StakedAmount -= stakedReduction
	}

	// Update staker
	staker.Shares -= shares
	if err := k.setStaker(ctx, staker); err != nil {
		return 0, 0, err
	}

	// Update totals
	if err := k.TotalPooledAethel.Set(ctx, totalPooled-aethelAmount); err != nil {
		return 0, 0, err
	}
	if err := k.TotalShares.Set(ctx, totalShares-shares); err != nil {
		return 0, 0, err
	}

	pending := k.getUint64(ctx, k.TotalPendingWithdrawals)
	if err := k.TotalPendingWithdrawals.Set(ctx, pending+aethelAmount); err != nil {
		return 0, 0, err
	}

	// Create withdrawal request
	nextID := k.getUint64(ctx, k.NextWithdrawalID)
	withdrawalID = nextID
	if err := k.NextWithdrawalID.Set(ctx, nextID+1); err != nil {
		return 0, 0, err
	}

	params := k.getParams(ctx)
	completionTime := blockTime.Add(time.Duration(params.UnbondingPeriod) * time.Second)

	w := &types.WithdrawalRequest{
		ID:             withdrawalID,
		Owner:          address,
		Shares:         shares,
		AethelAmount:   aethelAmount,
		RequestTime:    blockTime,
		CompletionTime: completionTime,
		Claimed:        false,
	}
	if err := k.setWithdrawal(ctx, w); err != nil {
		return 0, 0, err
	}

	userIDs = append(userIDs, withdrawalID)
	if err := k.setUserWithdrawalIDs(ctx, address, userIDs); err != nil {
		return 0, 0, err
	}

	// Track cumulative unstake volume for circuit breaker evaluation.
	epochAccum, _ := k.EpochUnstakeAccum.Get(ctx, epochKey)
	if err := k.EpochUnstakeAccum.Set(ctx, epochKey, epochAccum+aethelAmount); err != nil {
		return 0, 0, err
	}
	// Evaluate circuit breaker thresholds (may auto-pause if breached).
	// The current unstake still succeeds — the pause takes effect on the NEXT operation.
	_ = k.checkCircuitBreaker(ctx, "unstake")

	return withdrawalID, aethelAmount, nil
}

// Withdraw completes an unbonding request after the period has elapsed.
func (k *Keeper) Withdraw(ctx context.Context, address string, withdrawalID uint64) (amount uint64, err error) {
	if err := k.requireNotPaused(ctx); err != nil {
		return 0, err
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	req, exists := k.getWithdrawal(ctx, withdrawalID)
	if !exists {
		return 0, fmt.Errorf("withdrawal %d not found", withdrawalID)
	}
	if req.Owner != address {
		return 0, fmt.Errorf("withdrawal %d not owned by %s", withdrawalID, address)
	}
	if req.Claimed {
		return 0, fmt.Errorf("withdrawal %d already claimed", withdrawalID)
	}
	if blockTime.Before(req.CompletionTime) {
		return 0, fmt.Errorf("withdrawal %d not ready until %s", withdrawalID, req.CompletionTime)
	}

	req.Claimed = true
	if err := k.setWithdrawal(ctx, req); err != nil {
		return 0, err
	}

	pending := k.getUint64(ctx, k.TotalPendingWithdrawals)
	if err := k.TotalPendingWithdrawals.Set(ctx, pending-req.AethelAmount); err != nil {
		return 0, err
	}

	return req.AethelAmount, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Validator Management
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Validator Set Hash
// ─────────────────────────────────────────────────────────────────────────────

// computeValidatorSetHash computes the canonical validator set hash for
// cross-layer verification.
//
// All three layers (Rust TEE producer, Solidity on-chain, Go native) compute
// this identical hash. The canonical encoding uses domain-separated SHA-256
// with uint256-padded fields, eliminating serialization mismatches.
//
// Schema (big-endian, uint256-padded):
//
//	inner_hash_i = SHA-256(
//	  pad32(address) || uint256(stake) || uint256(perf_score) ||
//	  uint256(decent_score) || uint256(rep_score) || uint256(composite_score) ||
//	  bytes32(tee_key) || uint256(commission)
//	)
//	canonical_hash = SHA-256(
//	  "CrucibleValidatorSet-v1" || be8(epoch) || be4(count) ||
//	  inner_hash_0 || inner_hash_1 || ...
//	)
//
// Matching implementations:
//   - Rust: server::compute_validator_set_hash()
//   - Solidity: Crucible._computeValidatorSetHash()
func computeValidatorSetHash(epoch uint64, validators []types.ValidatorRecord) [32]byte {
	h := sha256.New()
	h.Write([]byte("CrucibleValidatorSet-v1"))

	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], epoch)
	h.Write(epochBuf[:])

	var countBuf [4]byte
	binary.BigEndian.PutUint32(countBuf[:], uint32(len(validators)))
	h.Write(countBuf[:])

	for i := range validators {
		innerHash := computeValidatorInnerHash(&validators[i])
		h.Write(innerHash[:])
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// computeValidatorInnerHash computes the per-validator inner hash
// (8 fields × 32 bytes = 256 bytes → SHA-256).
func computeValidatorInnerHash(v *types.ValidatorRecord) [32]byte {
	inner := sha256.New()

	// address → left-pad to 32 bytes (ABI uint256 encoding of address)
	addrBytes32 := addressToBytes32(v.Address)
	inner.Write(addrBytes32[:])

	// stake as uint256 (uint64 → 32 bytes big-endian, left-padded)
	var stakePadded [32]byte
	binary.BigEndian.PutUint64(stakePadded[24:], v.DelegatedStake)
	inner.Write(stakePadded[:])

	// performance_score as uint256
	var perfPadded [32]byte
	binary.BigEndian.PutUint32(perfPadded[28:], v.PerformanceScore)
	inner.Write(perfPadded[:])

	// decentralization_score as uint256
	var decentPadded [32]byte
	binary.BigEndian.PutUint32(decentPadded[28:], v.DecentralizationScore)
	inner.Write(decentPadded[:])

	// reputation_score as uint256
	var repPadded [32]byte
	binary.BigEndian.PutUint32(repPadded[28:], v.ReputationScore)
	inner.Write(repPadded[:])

	// composite_score as uint256
	var compPadded [32]byte
	binary.BigEndian.PutUint32(compPadded[28:], v.CompositeScore)
	inner.Write(compPadded[:])

	// tee_public_key as bytes32 (left-aligned, zero-padded)
	var keyPadded [32]byte
	if len(v.TEEPublicKey) > 0 {
		n := len(v.TEEPublicKey)
		if n > 32 {
			n = 32
		}
		copy(keyPadded[:n], v.TEEPublicKey[:n])
	}
	inner.Write(keyPadded[:])

	// commission as uint256
	var commPadded [32]byte
	binary.BigEndian.PutUint32(commPadded[28:], v.Commission)
	inner.Write(commPadded[:])

	var result [32]byte
	copy(result[:], inner.Sum(nil))
	return result
}

// addressToBytes32 converts a validator address (hex or bech32) to a 32-byte
// left-padded value matching ABI uint256 encoding of an address.
func addressToBytes32(addr string) [32]byte {
	var padded [32]byte
	trimmed := strings.TrimPrefix(addr, "0x")
	if addrBytes, err := hex.DecodeString(trimmed); err == nil && len(addrBytes) <= 32 {
		// Hex address: left-pad to 32 bytes
		start := 32 - len(addrBytes)
		copy(padded[start:], addrBytes)
	} else {
		// Non-hex address (e.g., Cosmos bech32): hash to 20 bytes for determinism
		addrHash := sha256.Sum256([]byte(addr))
		copy(padded[12:], addrHash[:20]) // 12-byte zero prefix + 20 bytes = 32
	}
	return padded
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Selection Policy Hash
// ─────────────────────────────────────────────────────────────────────────────

// computeSelectionPolicyHash computes the canonical hash of a validator
// selection policy for cross-layer verification.
//
// This binds the TEE attestation to the specific scoring parameters used,
// closing the trust gap where a caller could supply arbitrary weights/thresholds
// to bias selection while still obtaining a valid attestation.
//
// Schema (domain-separated SHA-256):
//
//	policy_hash = SHA-256(
//	  "CrucibleSelectionPolicy-v1" ||
//	  float64_be(performance_weight) || float64_be(decentralization_weight) ||
//	  float64_be(reputation_weight)  || float64_be(min_uptime_pct) ||
//	  uint256(max_commission_bps)    || uint256(max_per_region) ||
//	  uint256(max_per_operator)      || uint256(min_stake)
//	)
//
// Matching implementations:
//   - Rust: server::compute_selection_policy_hash()
//   - Solidity: Crucible.selectionPolicyHash (stored, set by governance)
func computeSelectionPolicyHash(
	performanceWeight float64,
	decentralizationWeight float64,
	reputationWeight float64,
	minUptimePct float64,
	maxCommissionBps uint32,
	maxPerRegion uint64,
	maxPerOperator uint64,
	minStake *big.Int,
) [32]byte {
	h := sha256.New()

	// Domain separator
	h.Write([]byte("CrucibleSelectionPolicy-v1"))

	// Float64 fields as IEEE-754 big-endian (8 bytes each)
	var floatBuf [8]byte
	binary.BigEndian.PutUint64(floatBuf[:], math.Float64bits(performanceWeight))
	h.Write(floatBuf[:])
	binary.BigEndian.PutUint64(floatBuf[:], math.Float64bits(decentralizationWeight))
	h.Write(floatBuf[:])
	binary.BigEndian.PutUint64(floatBuf[:], math.Float64bits(reputationWeight))
	h.Write(floatBuf[:])
	binary.BigEndian.PutUint64(floatBuf[:], math.Float64bits(minUptimePct))
	h.Write(floatBuf[:])

	// max_commission_bps as uint256 (u32 → 32 bytes big-endian, left-padded)
	var commPadded [32]byte
	binary.BigEndian.PutUint32(commPadded[28:], maxCommissionBps)
	h.Write(commPadded[:])

	// max_per_region as uint256 (u64 → 32 bytes big-endian)
	var regionPadded [32]byte
	binary.BigEndian.PutUint64(regionPadded[24:], maxPerRegion)
	h.Write(regionPadded[:])

	// max_per_operator as uint256 (u64 → 32 bytes big-endian)
	var operatorPadded [32]byte
	binary.BigEndian.PutUint64(operatorPadded[24:], maxPerOperator)
	h.Write(operatorPadded[:])

	// min_stake as uint256 (big.Int → 32 bytes big-endian, left-padded)
	var stakePadded [32]byte
	if minStake != nil {
		stakeBytes := minStake.Bytes()
		if len(stakeBytes) <= 32 {
			copy(stakePadded[32-len(stakeBytes):], stakeBytes)
		}
	}
	h.Write(stakePadded[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ApplyValidatorSelection applies a TEE-attested validator set to the store.
//
// This is a deterministic state transition: the validator set and its attestation
// are submitted as an on-chain message (MsgUpdateValidatorSet) by an off-chain
// relayer that queries the TEE worker. The keeper verifies the attestation
// (signature, enclave registration, operator binding, freshness, nonce, payload
// binding) before persisting the validator set.
//
// Flow:
//  1. Off-chain relayer calls TEE worker /select-validators (non-consensus)
//  2. Relayer submits MsgUpdateValidatorSet{Validators, Attestation} on-chain
//  3. This function verifies the attestation, then persists the set
//
// This ensures all nodes deterministically agree on the same validator set.
func (k *Keeper) ApplyValidatorSelection(
	ctx context.Context,
	validators []types.ValidatorRecord,
	attestation types.TEEAttestation,
	epoch uint64,
) error {
	if err := k.requireNotPaused(ctx); err != nil {
		return err
	}

	if len(validators) == 0 {
		return fmt.Errorf("empty validator set")
	}

	// 1. Verify the TEE attestation (signature, enclave, operator, freshness, nonce)
	if err := k.verifyAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	// 2. Verify the attestation payload matches the canonical validator set hash,
	//    the approved selection policy hash, AND the eligible-universe hash.
	//
	//    The attestation payload is 96 bytes:
	//      abi.encodePacked(canonical_hash, policy_hash, universe_hash)
	//
	//    canonical_hash: domain-separated SHA-256 of (epoch, validator fields)
	//    policy_hash:    SHA-256 of the SelectionConfig weights/thresholds
	//    universe_hash:  SHA-256 of sorted eligible validator addresses
	//
	//    This binds the attestation to:
	//      (a) the selection output
	//      (b) the policy that produced it
	//      (c) the full eligible candidate universe
	//    The epoch is included in canonical_hash to prevent cross-epoch replay.
	//    The universe hash ensures a malicious relayer cannot silently omit
	//    validators from the candidate set to bias selection.
	canonicalHash := computeValidatorSetHash(epoch, validators)

	// Compute the expected policy hash from chain parameters
	params := k.getParams(ctx)
	policyHash := computeSelectionPolicyHash(
		0.4,  // performance_weight (protocol default)
		0.3,  // decentralization_weight (protocol default)
		0.3,  // reputation_weight (protocol default)
		95.0, // min_uptime_pct (protocol default)
		params.MaxCommission,
		0, // max_per_region (dynamic, 0 = no limit)
		3, // max_per_operator (protocol default)
		new(big.Int).SetUint64(params.MinStake),
	)

	// Compute the expected universe hash from on-chain telemetry state.
	//
	// We re-derive the eligible validator set using the same telemetry
	// freshness rules as BuildValidatorSelectionRequest(), then compute
	// the universe hash independently.  This catches any relayer that
	// submitted a TEE request with a truncated/fabricated candidate list.
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()
	maxAgeSec := params.TelemetryMaxAgeSec
	if maxAgeSec == 0 {
		maxAgeSec = types.DefaultTelemetryMaxAgeSec
	}
	eligibleResult := k.getValidatorInputs(ctx, blockTime, maxAgeSec)
	universeHash := computeEligibleUniverseHash(eligibleResult.eligibleAddrs)

	// Build expected 96-byte payload: canonicalHash || policyHash || universeHash
	var expectedPayload [96]byte
	copy(expectedPayload[:32], canonicalHash[:])
	copy(expectedPayload[32:64], policyHash[:])
	copy(expectedPayload[64:96], universeHash[:])

	// The attestation's PayloadHash = hex(SHA-256(payload_bytes))
	payloadHash := sha256.Sum256(expectedPayload[:])
	expectedPayloadHash := hex.EncodeToString(payloadHash[:])
	if attestation.PayloadHash != expectedPayloadHash {
		return fmt.Errorf(
			"payload hash mismatch: attestation covers %s but epoch-bound validators+policy+universe hash to %s (universe or policy may be unauthorized)",
			attestation.PayloadHash, expectedPayloadHash,
		)
	}

	// 3. Reject duplicate validator addresses.
	//
	// A duplicate-filled set would let the same validator occupy multiple
	// slots, reducing the effective validator set below the intended
	// decentralization / minimum-validator guarantees.  The TEE worker
	// already deduplicates, but we enforce uniqueness here too so that a
	// compromised or buggy worker cannot smuggle duplicates through the
	// attestation path.
	{
		seen := make(map[string]struct{}, len(validators))
		for _, v := range validators {
			if _, dup := seen[v.Address]; dup {
				return fmt.Errorf("duplicate validator address in attested set: %s", v.Address)
			}
			seen[v.Address] = struct{}{}
		}
	}

	// 4. Persist the verified validator set
	activeAddrs := make([]string, 0, len(validators))
	for i := range validators {
		v := &validators[i]
		v.IsActive = true
		if err := k.setValidator(ctx, v); err != nil {
			return fmt.Errorf("store validator %s: %w", v.Address, err)
		}
		activeAddrs = append(activeAddrs, v.Address)
	}
	return k.setActiveValidatorAddrs(ctx, activeAddrs)
}

// ─────────────────────────────────────────────────────────────────────────────
// TEE Attestation Verification
// ─────────────────────────────────────────────────────────────────────────────

// verifyAttestation performs full cryptographic verification of a TEE attestation:
//  1. Timestamp freshness (within MaxAttestationAgeSec of block time)
//  2. Nonce uniqueness (replay protection — marks nonce as used)
//  3. Enclave registration and active status
//  4. SignerHash matches the registered enclave's trusted signer identity
//  5. ECDSA signature recovery (secp256k1)
//  6. Recovered signer is a registered, active operator
//  7. Operator is bound to the specific enclave in the attestation
func (k *Keeper) verifyAttestation(ctx context.Context, att types.TEEAttestation) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	// 1. Timestamp freshness
	age := blockTime.Unix() - att.Timestamp
	if age < 0 || age > types.MaxAttestationAgeSec {
		return fmt.Errorf("attestation expired: age %ds exceeds max %ds", age, types.MaxAttestationAgeSec)
	}

	// 2. Nonce uniqueness (replay protection)
	if _, err := k.UsedNonces.Get(ctx, att.Nonce); err == nil {
		return fmt.Errorf("nonce already used: %s", att.Nonce)
	}
	if err := k.UsedNonces.Set(ctx, att.Nonce, "used"); err != nil {
		return fmt.Errorf("mark nonce used: %w", err)
	}

	// 3. Compute enclave ID = hex(SHA-256(enclaveHash ‖ platform))
	enclaveHashBytes, err := hex.DecodeString(att.EnclaveHash)
	if err != nil || len(enclaveHashBytes) != 32 {
		return fmt.Errorf("invalid enclave_hash: must be 64 hex chars (32 bytes)")
	}
	enclaveIDInput := make([]byte, 33)
	copy(enclaveIDInput[:32], enclaveHashBytes)
	enclaveIDInput[32] = att.Platform
	enclaveIDHash := sha256.Sum256(enclaveIDInput)
	enclaveID := hex.EncodeToString(enclaveIDHash[:])

	// 4. Look up enclave registration
	enclaveJSON, err := k.RegisteredEnclaves.Get(ctx, enclaveID)
	if err != nil {
		return fmt.Errorf("unregistered enclave: %s", att.EnclaveHash)
	}
	var enclave types.EnclaveRegistration
	if json.Unmarshal([]byte(enclaveJSON), &enclave) != nil {
		return fmt.Errorf("corrupt enclave registration")
	}
	if !enclave.Active {
		return fmt.Errorf("enclave revoked: %s", enclaveID)
	}

	// 5. Verify signerHash matches the registered enclave's signer identity
	if att.SignerHash != enclave.SignerHash {
		return fmt.Errorf("signer_hash mismatch: got %s, want %s", att.SignerHash, enclave.SignerHash)
	}

	// 6. Reconstruct the attestation digest and recover the ECDSA signer
	digest := computeAttestationDigest(att)

	sigBytes, err := hex.DecodeString(att.Signature)
	if err != nil || len(sigBytes) != 65 {
		return fmt.Errorf("invalid signature: must be 130 hex chars (65 bytes, R‖S‖V)")
	}

	// Convert Ethereum-style (R[32]‖S[32]‖V[1]) → btcec compact (V[1]‖R[32]‖S[32])
	v := sigBytes[64]
	if v >= 27 {
		v -= 27 // normalize recovery ID to 0 or 1
	}
	compactSig := make([]byte, 65)
	compactSig[0] = v + 27 // btcec expects 27+recid for uncompressed, 31+recid for compressed
	copy(compactSig[1:33], sigBytes[0:32])
	copy(compactSig[33:65], sigBytes[32:64])

	recoveredPub, _, err := btcecdsa.RecoverCompact(compactSig, digest[:])
	if err != nil {
		// Try compressed recovery flag (31+recid)
		compactSig[0] = v + 31
		recoveredPub, _, err = btcecdsa.RecoverCompact(compactSig, digest[:])
		if err != nil {
			return fmt.Errorf("signature recovery failed: %w", err)
		}
	}
	recoveredPubHex := hex.EncodeToString(recoveredPub.SerializeCompressed())

	// 7. Look up operator by recovered public key
	opJSON, err := k.RegisteredOperators.Get(ctx, recoveredPubHex)
	if err != nil {
		return fmt.Errorf("unregistered operator: recovered key %s", recoveredPubHex)
	}
	var operator types.OperatorRegistration
	if json.Unmarshal([]byte(opJSON), &operator) != nil {
		return fmt.Errorf("corrupt operator registration")
	}
	if !operator.Active {
		return fmt.Errorf("operator revoked: %s", recoveredPubHex)
	}

	// 8. Verify operator is bound to this specific enclave
	if operator.EnclaveID != enclaveID {
		return fmt.Errorf(
			"operator %s not authorized for enclave %s (bound to %s)",
			recoveredPubHex, enclaveID, operator.EnclaveID,
		)
	}

	// 9. Verify platform evidence (pass enclave for P-256 key verification)
	if err := k.verifyPlatformEvidence(att, digest, enclave); err != nil {
		return fmt.Errorf("platform evidence verification failed: %w", err)
	}

	return nil
}

// computeAttestationDigest builds the SHA-256 digest that the TEE operator signs.
//
// digest = SHA-256("CrucibleTEEAttestation" ‖ platform ‖ timestamp_be64 ‖
//
//	nonce ‖ enclaveHash ‖ signerHash ‖ payloadHash)
func computeAttestationDigest(att types.TEEAttestation) [32]byte {
	h := sha256.New()
	h.Write([]byte("CrucibleTEEAttestation"))
	h.Write([]byte{att.Platform})

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(att.Timestamp))
	h.Write(tsBuf[:])

	nonceBytes, _ := hex.DecodeString(att.Nonce)
	h.Write(nonceBytes)

	enclaveHashBytes, _ := hex.DecodeString(att.EnclaveHash)
	h.Write(enclaveHashBytes)

	signerHashBytes, _ := hex.DecodeString(att.SignerHash)
	h.Write(signerHashBytes)

	payloadHashBytes, _ := hex.DecodeString(att.PayloadHash)
	h.Write(payloadHashBytes)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform Evidence Verification (P-256 ECDSA)
// ─────────────────────────────────────────────────────────────────────────────

// verifyPlatformEvidence verifies that the attestation includes valid platform
// evidence (SGX quote, Nitro document, or SEV report) that:
//  1. Contains measurements matching the registered enclave
//  2. Binds to this specific attestation digest via reportData
//  3. Contains a valid P-256 ECDSA signature over the report body,
//     verified against the enclave's registered platform public key
//
// This prevents a registered operator from producing valid attestations
// outside of a real TEE environment.
func (k *Keeper) verifyPlatformEvidence(att types.TEEAttestation, digest [32]byte, enclave types.EnclaveRegistration) error {
	evidenceHex := att.PlatformEvidence
	if evidenceHex == "" {
		return fmt.Errorf("missing platform evidence")
	}

	evidenceBytes, err := hex.DecodeString(evidenceHex)
	if err != nil {
		return fmt.Errorf("invalid platform evidence hex: %w", err)
	}

	switch att.Platform {
	case types.PlatformSGX:
		return verifySgxEvidence(evidenceBytes, att.EnclaveHash, att.SignerHash, digest, enclave)
	case types.PlatformNitro:
		return verifyNitroEvidence(evidenceBytes, att.EnclaveHash, att.SignerHash, digest, enclave)
	case types.PlatformSEV:
		return verifySevEvidence(evidenceBytes, att.EnclaveHash, att.SignerHash, digest, enclave)
	default:
		return fmt.Errorf("unsupported platform: %d", att.Platform)
	}
}

// parsePlatformP256Key parses the P-256 public key from an enclave registration.
func parsePlatformP256Key(enclave types.EnclaveRegistration) (*ecdsa.PublicKey, error) {
	keyXBytes, err := hex.DecodeString(enclave.PlatformKeyX)
	if err != nil || len(keyXBytes) != 32 {
		return nil, fmt.Errorf("invalid platform key X")
	}
	keyYBytes, err := hex.DecodeString(enclave.PlatformKeyY)
	if err != nil || len(keyYBytes) != 32 {
		return nil, fmt.Errorf("invalid platform key Y")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(keyXBytes),
		Y:     new(big.Int).SetBytes(keyYBytes),
	}
	return pubKey, nil
}

// verifySgxEvidence decodes and validates SGX evidence with P-256 signature verification.
// Layout: 8 x 32 = 256 bytes
//
//	[0:32]    mrenclave (from hardware report)
//	[32:64]   mrsigner (from hardware report)
//	[64:96]   reportData (attestation digest)
//	[96:128]  isvProdId (uint16, right-aligned in 32-byte word)
//	[128:160] isvSvn (uint16, right-aligned in 32-byte word)
//	[160:192] rawReportHash (SHA-256 of fresh hardware attestation report)
//	[192:224] sigR (P-256 signature r, big-endian 32 bytes)
//	[224:256] sigS (P-256 signature s, big-endian 32 bytes)
//
// Measurement binding: the verifier computes
//
//	bindingHash = SHA-256(rawReportHash || mrenclave || mrsigner)
//
// and uses it in the P-256 signature verification, proving the measurements
// came from the specific hardware report.
//
// Report body for hashing: mrenclave(32) || mrsigner(32) || reportData(32) || isvProdId(2 BE) || isvSvn(2 BE) || bindingHash(32) = 132 bytes
func verifySgxEvidence(evidence []byte, expectedEnclaveHash, expectedSignerHash string, digest [32]byte, enclave types.EnclaveRegistration) error {
	if len(evidence) < 256 {
		return fmt.Errorf("SGX evidence too short: %d bytes (need 256)", len(evidence))
	}

	mrenclave := evidence[0:32]
	mrsigner := evidence[32:64]
	reportData := evidence[64:96]
	// isvProdId at [96:128], isvSvn at [128:160] — uint16 right-aligned in 32-byte words
	rawReportHash := evidence[160:192]
	sigR := new(big.Int).SetBytes(evidence[192:224])
	sigS := new(big.Int).SetBytes(evidence[224:256])

	// Check measurements match
	expectedEnclave, err := hex.DecodeString(expectedEnclaveHash)
	if err != nil || len(expectedEnclave) != 32 {
		return fmt.Errorf("invalid expected enclave hash")
	}
	if !bytesEqual(mrenclave, expectedEnclave) {
		return fmt.Errorf("SGX mrenclave mismatch")
	}

	expectedSigner, err := hex.DecodeString(expectedSignerHash)
	if err != nil || len(expectedSigner) != 32 {
		return fmt.Errorf("invalid expected signer hash")
	}
	if !bytesEqual(mrsigner, expectedSigner) {
		return fmt.Errorf("SGX mrsigner mismatch")
	}

	// Check data binding
	if !bytesEqual(reportData, digest[:]) {
		return fmt.Errorf("SGX reportData does not match attestation digest")
	}

	// Check raw report hash is non-zero (proves fresh hardware attestation)
	allZero := true
	for _, b := range rawReportHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("SGX rawReportHash is zero (no hardware attestation)")
	}

	// Compute binding hash: SHA-256(rawReportHash || mrenclave || mrsigner)
	// This ties the hardware report to the specific measurements in evidence.
	bindingHasher := sha256.New()
	bindingHasher.Write(rawReportHash)
	bindingHasher.Write(mrenclave)
	bindingHasher.Write(mrsigner)
	bindingHash := bindingHasher.Sum(nil)

	// Build report body with bindingHash: mrenclave(32) || mrsigner(32) || reportData(32) || isvProdId(2 BE) || isvSvn(2 BE) || bindingHash(32) = 132 bytes
	reportBody := make([]byte, 0, 132)
	reportBody = append(reportBody, mrenclave...)
	reportBody = append(reportBody, mrsigner...)
	reportBody = append(reportBody, reportData...)
	reportBody = append(reportBody, 0, 1) // isvProdId = 1
	reportBody = append(reportBody, 0, 1) // isvSvn = 1
	reportBody = append(reportBody, bindingHash...)

	reportHash := sha256.Sum256(reportBody)

	pubKey, err := parsePlatformP256Key(enclave)
	if err != nil {
		return err
	}

	if !ecdsa.Verify(pubKey, reportHash[:], sigR, sigS) {
		return fmt.Errorf("SGX P-256 signature verification failed")
	}

	return nil
}

// verifyNitroEvidence decodes and validates Nitro evidence with P-256 signature verification.
// Layout: 7 x 32 = 224 bytes
//
//	[0:32]    pcr0 (from hardware report)
//	[32:64]   pcr1 (from hardware report)
//	[64:96]   pcr2
//	[96:128]  userData (attestation digest)
//	[128:160] rawReportHash (SHA-256 of fresh Nitro attestation document)
//	[160:192] sigR (P-256 signature r, big-endian 32 bytes)
//	[192:224] sigS (P-256 signature s, big-endian 32 bytes)
//
// Measurement binding: bindingHash = SHA-256(rawReportHash || pcr0 || pcr1)
// Report body for hashing: pcr0(32) || pcr1(32) || pcr2(32) || userData(32) || bindingHash(32) = 160 bytes
func verifyNitroEvidence(evidence []byte, expectedEnclaveHash, expectedSignerHash string, digest [32]byte, enclave types.EnclaveRegistration) error {
	if len(evidence) < 224 {
		return fmt.Errorf("Nitro evidence too short: %d bytes (need 224)", len(evidence))
	}

	pcrHash0 := evidence[0:32]
	pcrHash1 := evidence[32:64]
	pcrHash2 := evidence[64:96]
	userData := evidence[96:128]
	rawReportHash := evidence[128:160]
	sigR := new(big.Int).SetBytes(evidence[160:192])
	sigS := new(big.Int).SetBytes(evidence[192:224])

	expectedEnclave, err := hex.DecodeString(expectedEnclaveHash)
	if err != nil || len(expectedEnclave) != 32 {
		return fmt.Errorf("invalid expected enclave hash")
	}
	if !bytesEqual(pcrHash0, expectedEnclave) {
		return fmt.Errorf("Nitro pcrHash0 mismatch")
	}

	expectedSigner, err := hex.DecodeString(expectedSignerHash)
	if err != nil || len(expectedSigner) != 32 {
		return fmt.Errorf("invalid expected signer hash")
	}
	if !bytesEqual(pcrHash1, expectedSigner) {
		return fmt.Errorf("Nitro pcrHash1 mismatch")
	}

	// Verify PCR2 (application hash) if the enclave registration specifies one.
	// When ApplicationHash is set (non-empty), the evidence PCR2 must match.
	if enclave.ApplicationHash != "" {
		expectedApp, err := hex.DecodeString(enclave.ApplicationHash)
		if err != nil || len(expectedApp) != 32 {
			return fmt.Errorf("invalid expected application hash (PCR2)")
		}
		if !bytesEqual(pcrHash2, expectedApp) {
			return fmt.Errorf("Nitro pcrHash2 (application hash) mismatch")
		}
	}

	if !bytesEqual(userData, digest[:]) {
		return fmt.Errorf("Nitro userData does not match attestation digest")
	}

	// Check raw report hash is non-zero (proves fresh hardware attestation)
	allZero := true
	for _, b := range rawReportHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("Nitro rawReportHash is zero (no hardware attestation)")
	}

	// Compute binding hash: SHA-256(rawReportHash || pcr0 || pcr1)
	bindingHasher := sha256.New()
	bindingHasher.Write(rawReportHash)
	bindingHasher.Write(pcrHash0)
	bindingHasher.Write(pcrHash1)
	bindingHash := bindingHasher.Sum(nil)

	// Build report body with bindingHash: pcr0(32) || pcr1(32) || pcr2(32) || userData(32) || bindingHash(32) = 160 bytes
	reportBody := make([]byte, 0, 160)
	reportBody = append(reportBody, pcrHash0...)
	reportBody = append(reportBody, pcrHash1...)
	reportBody = append(reportBody, pcrHash2...)
	reportBody = append(reportBody, userData...)
	reportBody = append(reportBody, bindingHash...)

	reportHash := sha256.Sum256(reportBody)

	pubKey, err := parsePlatformP256Key(enclave)
	if err != nil {
		return err
	}

	if !ecdsa.Verify(pubKey, reportHash[:], sigR, sigS) {
		return fmt.Errorf("Nitro P-256 signature verification failed")
	}

	return nil
}

// verifySevEvidence decodes and validates SEV-SNP evidence with P-256 signature verification.
// Layout: 7 x 32 = 224 bytes
//
//	[0:32]    measurement (from hardware report)
//	[32:64]   hostData (from hardware report)
//	[64:96]   reportData (attestation digest)
//	[96:128]  vmpl (uint8, right-aligned in 32-byte word)
//	[128:160] rawReportHash (SHA-256 of fresh SEV-SNP attestation report)
//	[160:192] sigR (P-256 signature r, big-endian 32 bytes)
//	[192:224] sigS (P-256 signature s, big-endian 32 bytes)
//
// Measurement binding: bindingHash = SHA-256(rawReportHash || measurement || hostData)
// Report body for hashing: measurement(32) || hostData(32) || reportData(32) || vmpl(1) || bindingHash(32) = 129 bytes
func verifySevEvidence(evidence []byte, expectedEnclaveHash, expectedSignerHash string, digest [32]byte, enclave types.EnclaveRegistration) error {
	if len(evidence) < 224 {
		return fmt.Errorf("SEV evidence too short: %d bytes (need 224)", len(evidence))
	}

	measurementHash := evidence[0:32]
	hostData := evidence[32:64]
	reportData := evidence[64:96]
	// vmpl at [96:128] — uint8 right-aligned in 32-byte word
	rawReportHash := evidence[128:160]
	sigR := new(big.Int).SetBytes(evidence[160:192])
	sigS := new(big.Int).SetBytes(evidence[192:224])

	expectedEnclave, err := hex.DecodeString(expectedEnclaveHash)
	if err != nil || len(expectedEnclave) != 32 {
		return fmt.Errorf("invalid expected enclave hash")
	}
	if !bytesEqual(measurementHash, expectedEnclave) {
		return fmt.Errorf("SEV measurement mismatch")
	}

	expectedSigner, err := hex.DecodeString(expectedSignerHash)
	if err != nil || len(expectedSigner) != 32 {
		return fmt.Errorf("invalid expected signer hash")
	}
	if !bytesEqual(hostData, expectedSigner) {
		return fmt.Errorf("SEV hostData mismatch")
	}

	if !bytesEqual(reportData, digest[:]) {
		return fmt.Errorf("SEV reportData does not match attestation digest")
	}

	// Check raw report hash is non-zero (proves fresh hardware attestation)
	allZero := true
	for _, b := range rawReportHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("SEV rawReportHash is zero (no hardware attestation)")
	}

	// Compute binding hash: SHA-256(rawReportHash || measurement || hostData)
	bindingHasher := sha256.New()
	bindingHasher.Write(rawReportHash)
	bindingHasher.Write(measurementHash)
	bindingHasher.Write(hostData)
	bindingHash := bindingHasher.Sum(nil)

	// Build report body with bindingHash: measurement(32) || hostData(32) || reportData(32) || vmpl(1) || bindingHash(32) = 129 bytes
	reportBody := make([]byte, 0, 129)
	reportBody = append(reportBody, measurementHash...)
	reportBody = append(reportBody, hostData...)
	reportBody = append(reportBody, reportData...)
	reportBody = append(reportBody, 0) // vmpl = 0
	reportBody = append(reportBody, bindingHash...)

	reportHash := sha256.Sum256(reportBody)

	pubKey, err := parsePlatformP256Key(enclave)
	if err != nil {
		return err
	}

	if !ecdsa.Verify(pubKey, reportHash[:], sigR, sigS) {
		return fmt.Errorf("SEV P-256 signature verification failed")
	}

	return nil
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// TEE Enclave & Operator Registration
// ─────────────────────────────────────────────────────────────────────────────

// RegisterVendorRootKey stores a direct hardware vendor P-256 public key for a TEE platform.
//
// Only for direct hardware manufacturer root keys:
//   - Platform 0 (SGX): Intel DCAP root key
//   - Platform 1 (Nitro): AWS Nitro root certificate key
//   - Platform 2 (SEV): AMD ARK/VCEK root key
//
// This function CANNOT be called while an active attestation relay is registered
// for the platform. Relay-managed keys must be changed via the relay lifecycle
// methods (InitiateRelayRotation / FinalizeRelayRotation) which enforce rotation
// timelock, liveness challenges, and audit trails. To switch from relay back to
// direct vendor keys, first call RevokeRelay().
//
// Returns ErrDirectOverrideWhileRelayActive if a relay is active.
func (k *Keeper) RegisterVendorRootKey(ctx context.Context, platform uint8, xHex, yHex string) error {
	// Prevent bypassing relay governance controls via direct override
	platformKey := strconv.Itoa(int(platform))
	if relayData, err := k.AttestationRelays.Get(ctx, platformKey); err == nil {
		var relay types.AttestationRelay
		if json.Unmarshal([]byte(relayData), &relay) == nil && relay.RegisteredAt != 0 && relay.Active {
			return types.ErrDirectOverrideWhileRelayActive
		}
	}

	return k.setVendorRootKeyInternal(ctx, platform, xHex, yHex)
}

// setVendorRootKeyInternal is the unguarded internal setter used by relay lifecycle
// methods (RegisterAttestationRelay, FinalizeRelayRotation) that have already
// validated governance controls. External callers must use RegisterVendorRootKey().
func (k *Keeper) setVendorRootKeyInternal(ctx context.Context, platform uint8, xHex, yHex string) error {
	// Validate the key coordinates
	xBytes, err := hex.DecodeString(xHex)
	if err != nil || len(xBytes) != 32 {
		return fmt.Errorf("invalid vendor root key X coordinate")
	}
	yBytes, err := hex.DecodeString(yHex)
	if err != nil || len(yBytes) != 32 {
		return fmt.Errorf("invalid vendor root key Y coordinate")
	}

	// Verify the point is on the P-256 curve
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("vendor root key is not on the P-256 curve")
	}

	type rootKey struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	data, _ := json.Marshal(rootKey{X: xHex, Y: yHex})
	return k.VendorRootKeys.Set(ctx, strconv.Itoa(int(platform)), string(data))
}

// getVendorRootKey loads the vendor root P-256 public key for a platform.
func (k *Keeper) getVendorRootKey(ctx context.Context, platform uint8) (*ecdsa.PublicKey, error) {
	data, err := k.VendorRootKeys.Get(ctx, strconv.Itoa(int(platform)))
	if err != nil {
		return nil, fmt.Errorf("vendor root key not registered for platform %d", platform)
	}

	type rootKey struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	var rk rootKey
	if err := json.Unmarshal([]byte(data), &rk); err != nil {
		return nil, fmt.Errorf("corrupt vendor root key data: %w", err)
	}

	xBytes, err := hex.DecodeString(rk.X)
	if err != nil || len(xBytes) != 32 {
		return nil, fmt.Errorf("invalid vendor root key X")
	}
	yBytes, err := hex.DecodeString(rk.Y)
	if err != nil || len(yBytes) != 32 {
		return nil, fmt.Errorf("invalid vendor root key Y")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// RegisterEnclave registers a new TEE enclave configuration.
// Only callable by the module authority (governance).
func (k *Keeper) RegisterEnclave(ctx context.Context, reg types.EnclaveRegistration) (enclaveID string, err error) {
	enclaveHashBytes, err := hex.DecodeString(reg.EnclaveHash)
	if err != nil || len(enclaveHashBytes) != 32 {
		return "", fmt.Errorf("invalid enclave_hash: must be 64 hex chars (32 bytes)")
	}

	enclaveIDInput := make([]byte, 33)
	copy(enclaveIDInput[:32], enclaveHashBytes)
	enclaveIDInput[32] = reg.Platform
	enclaveIDHash := sha256.Sum256(enclaveIDInput)
	enclaveID = hex.EncodeToString(enclaveIDHash[:])

	if _, err := k.RegisteredEnclaves.Get(ctx, enclaveID); err == nil {
		return "", fmt.Errorf("enclave already registered: %s", enclaveID)
	}

	// Verify vendor key attestation: the vendor root key must have signed this platform key.
	// This ensures the platform key was generated inside real TEE hardware,
	// not derived from the operator's key.
	vendorKey, err := k.getVendorRootKey(ctx, reg.Platform)
	if err != nil {
		return "", fmt.Errorf("vendor root key required: %w", err)
	}

	// Decode vendor attestation signature
	attestR, err := hex.DecodeString(reg.VendorAttestR)
	if err != nil || len(attestR) == 0 {
		return "", fmt.Errorf("invalid vendor attestation R")
	}
	attestS, err := hex.DecodeString(reg.VendorAttestS)
	if err != nil || len(attestS) == 0 {
		return "", fmt.Errorf("invalid vendor attestation S")
	}

	// Compute key attestation message: SHA-256(platformKeyX || platformKeyY || platformId)
	keyXBytes, err := hex.DecodeString(reg.PlatformKeyX)
	if err != nil || len(keyXBytes) != 32 {
		return "", fmt.Errorf("invalid platform key X for vendor attestation")
	}
	keyYBytes, err := hex.DecodeString(reg.PlatformKeyY)
	if err != nil || len(keyYBytes) != 32 {
		return "", fmt.Errorf("invalid platform key Y for vendor attestation")
	}

	var keyAttestData []byte
	keyAttestData = append(keyAttestData, keyXBytes...)
	keyAttestData = append(keyAttestData, keyYBytes...)
	keyAttestData = append(keyAttestData, reg.Platform)
	keyAttestHash := sha256.Sum256(keyAttestData)

	// Verify vendor P-256 signature
	sigR := new(big.Int).SetBytes(attestR)
	sigS := new(big.Int).SetBytes(attestS)
	if !ecdsa.Verify(vendorKey, keyAttestHash[:], sigR, sigS) {
		return "", fmt.Errorf("vendor key attestation verification failed: platform key is not vendor-rooted")
	}

	reg.Active = true
	data, err := json.Marshal(reg)
	if err != nil {
		return "", err
	}
	if err := k.RegisteredEnclaves.Set(ctx, enclaveID, string(data)); err != nil {
		return "", err
	}

	// Track relay attestation count if this platform uses a registered relay.
	// Mirrors the attestationCount increment in VaultTEEVerifier.sol registerEnclave().
	platformKey := strconv.Itoa(int(reg.Platform))
	if relayData, relayErr := k.AttestationRelays.Get(ctx, platformKey); relayErr == nil {
		var relay types.AttestationRelay
		if json.Unmarshal([]byte(relayData), &relay) == nil && relay.Active {
			relay.AttestationCount++
			if updatedData, mErr := json.Marshal(relay); mErr == nil {
				_ = k.AttestationRelays.Set(ctx, platformKey, string(updatedData))
			}
		}
	}

	// Audit log
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Action:    "register_enclave",
		Target:    enclaveID,
		Timestamp: sdkCtx.BlockTime(),
	})

	return enclaveID, nil
}

// RegisterOperator registers a new TEE operator bound to a specific enclave.
// Only callable by the module authority (governance).
func (k *Keeper) RegisterOperator(ctx context.Context, reg types.OperatorRegistration) error {
	// Validate the enclave exists
	if _, err := k.RegisteredEnclaves.Get(ctx, reg.EnclaveID); err != nil {
		return fmt.Errorf("enclave not registered: %s", reg.EnclaveID)
	}

	// Validate compressed public key format (33 bytes = 66 hex chars)
	pubBytes, err := hex.DecodeString(reg.PubKeyHex)
	if err != nil || len(pubBytes) != 33 {
		return fmt.Errorf("invalid compressed public key (expected 33 bytes / 66 hex chars)")
	}
	// Verify it parses as a valid secp256k1 point
	if _, err := btcec.ParsePubKey(pubBytes); err != nil {
		return fmt.Errorf("invalid secp256k1 public key: %w", err)
	}

	if _, err := k.RegisteredOperators.Get(ctx, reg.PubKeyHex); err == nil {
		return fmt.Errorf("operator already registered: %s", reg.PubKeyHex)
	}

	reg.Active = true
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	if err := k.RegisteredOperators.Set(ctx, reg.PubKeyHex, string(data)); err != nil {
		return err
	}

	// Audit log
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Operator:  reg.PubKeyHex,
		Action:    "register_operator",
		Target:    reg.EnclaveID,
		Timestamp: sdkCtx.BlockTime(),
	})

	return nil
}

// RevokeEnclave deactivates a registered enclave.
func (k *Keeper) RevokeEnclave(ctx context.Context, enclaveID string) error {
	raw, err := k.RegisteredEnclaves.Get(ctx, enclaveID)
	if err != nil {
		return fmt.Errorf("enclave not found: %s", enclaveID)
	}
	var reg types.EnclaveRegistration
	if json.Unmarshal([]byte(raw), &reg) != nil {
		return fmt.Errorf("corrupt enclave registration")
	}
	reg.Active = false
	data, _ := json.Marshal(reg)
	if err := k.RegisteredEnclaves.Set(ctx, enclaveID, string(data)); err != nil {
		return err
	}

	// Audit log
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Action:    "revoke_enclave",
		Target:    enclaveID,
		Timestamp: sdkCtx.BlockTime(),
	})

	return nil
}

// RevokeOperator deactivates a registered operator.
func (k *Keeper) RevokeOperator(ctx context.Context, pubKeyHex string) error {
	raw, err := k.RegisteredOperators.Get(ctx, pubKeyHex)
	if err != nil {
		return fmt.Errorf("operator not found: %s", pubKeyHex)
	}
	var reg types.OperatorRegistration
	if json.Unmarshal([]byte(raw), &reg) != nil {
		return fmt.Errorf("corrupt operator registration")
	}
	reg.Active = false
	data, _ := json.Marshal(reg)
	if err := k.RegisteredOperators.Set(ctx, pubKeyHex, string(data)); err != nil {
		return err
	}

	// Audit log
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Operator:  pubKeyHex,
		Action:    "revoke_operator",
		Target:    reg.EnclaveID,
		Timestamp: sdkCtx.BlockTime(),
	})

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation Relay Management
//
// These methods mirror the relay governance controls in VaultTEEVerifier.sol,
// ensuring cross-network consistency between the EVM and native attestation
// trust models. Both paths now support:
//   - Explicit relay registration with identity tracking
//   - Time-locked key rotation (48-hour delay)
//   - On-chain liveness challenges with P-256 proof-of-possession
//   - Emergency revocation
// ─────────────────────────────────────────────────────────────────────────────

// RegisterAttestationRelay registers an attestation relay as the attestation
// authority for a TEE platform. The relay's P-256 key is also stored as the
// vendor root key for backward compatibility with RegisterEnclave().
//
// After emergency revocation via RevokeRelay(), a replacement relay can be
// registered for the same platform — the revoked relay's state is fully
// overwritten. The previous relay's attestation count is not carried forward.
//
// Only callable by governance (module authority).
func (k *Keeper) RegisterAttestationRelay(ctx context.Context, platform uint8, xHex, yHex, description string) error {
	platformKey := strconv.Itoa(int(platform))

	// Check if an active relay is already registered for this platform.
	// A revoked relay (Active=false) can be replaced with a fresh registration.
	if existing, err := k.AttestationRelays.Get(ctx, platformKey); err == nil && existing != "" {
		var relay types.AttestationRelay
		if json.Unmarshal([]byte(existing), &relay) == nil && relay.RegisteredAt != 0 && relay.Active {
			return types.ErrRelayAlreadyRegistered
		}
	}

	// Validate P-256 coordinates
	xBytes, err := hex.DecodeString(xHex)
	if err != nil || len(xBytes) != 32 {
		return fmt.Errorf("invalid relay public key X coordinate")
	}
	yBytes, err := hex.DecodeString(yHex)
	if err != nil || len(yBytes) != 32 {
		return fmt.Errorf("invalid relay public key Y coordinate")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("relay public key is not on the P-256 curve")
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	now := sdkCtx.BlockTime().Unix()

	relay := types.AttestationRelay{
		PublicKeyX:       xHex,
		PublicKeyY:       yHex,
		RegisteredAt:     now,
		LastRotatedAt:    now,
		AttestationCount: 0,
		Active:           true,
		Description:      description,
	}

	data, err := json.Marshal(relay)
	if err != nil {
		return err
	}
	if err := k.AttestationRelays.Set(ctx, platformKey, string(data)); err != nil {
		return err
	}

	// Also set vendor root key for backward compatibility with RegisterEnclave().
	// Uses the internal setter to bypass the relay-active guard (we ARE the relay).
	if err := k.setVendorRootKeyInternal(ctx, platform, xHex, yHex); err != nil {
		return fmt.Errorf("failed to set vendor root key for relay: %w", err)
	}

	// Audit log
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Action:    "register_attestation_relay",
		Target:    platformKey,
		Timestamp: sdkCtx.BlockTime(),
	})

	return nil
}

// InitiateRelayRotation starts a time-locked key rotation for a platform's
// attestation relay. The new key becomes effective after RelayRotationDelaySec
// (48 hours). During the delay, governance can cancel via CancelRelayRotation().
func (k *Keeper) InitiateRelayRotation(ctx context.Context, platform uint8, newXHex, newYHex string) error {
	platformKey := strconv.Itoa(int(platform))

	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return err
	}
	if !relay.Active {
		return types.ErrRelayNotActive
	}

	// Validate the new key
	xBytes, err := hex.DecodeString(newXHex)
	if err != nil || len(xBytes) != 32 {
		return fmt.Errorf("invalid new relay key X coordinate")
	}
	yBytes, err := hex.DecodeString(newYHex)
	if err != nil || len(yBytes) != 32 {
		return fmt.Errorf("invalid new relay key Y coordinate")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("new relay key is not on the P-256 curve")
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	now := sdkCtx.BlockTime().Unix()

	relay.PendingKeyX = newXHex
	relay.PendingKeyY = newYHex
	relay.RotationUnlocksAt = now + types.RelayRotationDelaySec

	return k.setAttestationRelay(ctx, platformKey, relay)
}

// FinalizeRelayRotation completes a pending relay key rotation after the
// timelock has expired. Updates both the relay's active key and the vendor
// root key for RegisterEnclave() compatibility.
func (k *Keeper) FinalizeRelayRotation(ctx context.Context, platform uint8) error {
	platformKey := strconv.Itoa(int(platform))

	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return err
	}
	if relay.PendingKeyX == "" && relay.PendingKeyY == "" {
		return types.ErrNoRotationPending
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	now := sdkCtx.BlockTime().Unix()
	if now < relay.RotationUnlocksAt {
		return types.ErrRotationTimelockActive
	}

	// Activate the pending key
	relay.PublicKeyX = relay.PendingKeyX
	relay.PublicKeyY = relay.PendingKeyY
	relay.LastRotatedAt = now

	// Clear pending state
	relay.PendingKeyX = ""
	relay.PendingKeyY = ""
	relay.RotationUnlocksAt = 0

	if err := k.setAttestationRelay(ctx, platformKey, relay); err != nil {
		return err
	}

	// Update vendor root key for backward compatibility.
	// Uses the internal setter to bypass the relay-active guard (we ARE the relay).
	if err := k.setVendorRootKeyInternal(ctx, platform, relay.PublicKeyX, relay.PublicKeyY); err != nil {
		return fmt.Errorf("failed to update vendor root key after rotation: %w", err)
	}

	// Audit log
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Action:    "finalize_relay_rotation",
		Target:    platformKey,
		Timestamp: sdkCtx.BlockTime(),
	})

	return nil
}

// CancelRelayRotation cancels a pending relay key rotation.
func (k *Keeper) CancelRelayRotation(ctx context.Context, platform uint8) error {
	platformKey := strconv.Itoa(int(platform))

	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return err
	}
	if relay.PendingKeyX == "" && relay.PendingKeyY == "" {
		return types.ErrNoRotationPending
	}

	relay.PendingKeyX = ""
	relay.PendingKeyY = ""
	relay.RotationUnlocksAt = 0

	return k.setAttestationRelay(ctx, platformKey, relay)
}

// RevokeRelay immediately deactivates an attestation relay AND clears the
// vendor root key, preventing any further enclave registrations for this
// platform. Existing enclaves already registered remain valid.
func (k *Keeper) RevokeRelay(ctx context.Context, platform uint8) error {
	platformKey := strconv.Itoa(int(platform))

	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return err
	}

	relay.Active = false
	// Clear any pending rotation
	relay.PendingKeyX = ""
	relay.PendingKeyY = ""
	relay.RotationUnlocksAt = 0
	// Clear any pending challenge
	relay.ActiveChallenge = ""
	relay.ChallengeDeadline = 0

	if err := k.setAttestationRelay(ctx, platformKey, relay); err != nil {
		return err
	}

	// Clear vendor root key to prevent new enclave registrations
	// Store a zero key which getVendorRootKey will reject
	type rootKeyData struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	zeroKey := rootKeyData{
		X: "0000000000000000000000000000000000000000000000000000000000000000",
		Y: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	data, _ := json.Marshal(zeroKey)
	_ = k.VendorRootKeys.Set(ctx, platformKey, string(data))

	// Audit log
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	k.appendOperatorAuditLog(ctx, types.OperatorAction{
		Action:    "revoke_relay",
		Target:    platformKey,
		Timestamp: sdkCtx.BlockTime(),
	})

	return nil
}

// ChallengeRelay issues a liveness challenge to an attestation relay. The relay
// must respond within RelayChallengeWindowSec (1 hour) by providing a valid
// P-256 signature over the challenge nonce using its registered signing key.
// challengeHex is the hex-encoded 32-byte nonce for the relay to sign.
func (k *Keeper) ChallengeRelay(ctx context.Context, platform uint8, challengeHex string) error {
	platformKey := strconv.Itoa(int(platform))

	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return err
	}
	if !relay.Active {
		return types.ErrRelayNotActive
	}

	// Validate challenge nonce
	challengeBytes, err := hex.DecodeString(challengeHex)
	if err != nil || len(challengeBytes) != 32 {
		return fmt.Errorf("invalid challenge nonce: must be 64 hex chars (32 bytes)")
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	now := sdkCtx.BlockTime().Unix()

	relay.ActiveChallenge = challengeHex
	relay.ChallengeDeadline = now + types.RelayChallengeWindowSec

	return k.setAttestationRelay(ctx, platformKey, relay)
}

// RespondRelayChallenge processes a relay's response to a liveness challenge.
// The response must include a valid P-256 ECDSA signature over SHA-256(challenge)
// using the relay's registered signing key.
//
// This is permissionless — anyone can submit a valid response, since the P-256
// signature proves possession of the relay's private key.
func (k *Keeper) RespondRelayChallenge(ctx context.Context, platform uint8, sigRHex, sigSHex string) error {
	platformKey := strconv.Itoa(int(platform))

	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return err
	}
	if relay.ActiveChallenge == "" {
		return types.ErrNoPendingChallenge
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	now := sdkCtx.BlockTime().Unix()
	if now > relay.ChallengeDeadline {
		return types.ErrChallengeExpired
	}

	// Decode the challenge and compute SHA-256(challenge)
	challengeBytes, err := hex.DecodeString(relay.ActiveChallenge)
	if err != nil {
		return fmt.Errorf("corrupt active challenge data")
	}
	challengeHash := sha256.Sum256(challengeBytes)

	// Decode signature components
	sigR, err := hex.DecodeString(sigRHex)
	if err != nil || len(sigR) != 32 {
		return fmt.Errorf("invalid challenge response signature R")
	}
	sigS, err := hex.DecodeString(sigSHex)
	if err != nil || len(sigS) != 32 {
		return fmt.Errorf("invalid challenge response signature S")
	}

	// Load the relay's public key
	xBytes, _ := hex.DecodeString(relay.PublicKeyX)
	yBytes, _ := hex.DecodeString(relay.PublicKeyY)
	relayPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// Verify P-256 signature
	r := new(big.Int).SetBytes(sigR)
	s := new(big.Int).SetBytes(sigS)
	if !ecdsa.Verify(relayPubKey, challengeHash[:], r, s) {
		return types.ErrChallengeResponseInvalid
	}

	// Clear the challenge
	relay.ActiveChallenge = ""
	relay.ChallengeDeadline = 0

	return k.setAttestationRelay(ctx, platformKey, relay)
}

// IsRelayActive returns whether a platform has an active attestation relay.
func (k *Keeper) IsRelayActive(ctx context.Context, platform uint8) bool {
	platformKey := strconv.Itoa(int(platform))
	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return false
	}
	return relay.Active
}

// GetAttestationRelay returns the attestation relay for a platform (exported).
func (k *Keeper) GetAttestationRelay(ctx context.Context, platform uint8) (*types.AttestationRelay, error) {
	platformKey := strconv.Itoa(int(platform))
	relay, err := k.getAttestationRelay(ctx, platformKey)
	if err != nil {
		return nil, err
	}
	return &relay, nil
}

// getAttestationRelay loads and deserializes a relay from state.
func (k *Keeper) getAttestationRelay(ctx context.Context, platformKey string) (types.AttestationRelay, error) {
	data, err := k.AttestationRelays.Get(ctx, platformKey)
	if err != nil {
		return types.AttestationRelay{}, types.ErrRelayNotRegistered
	}
	var relay types.AttestationRelay
	if err := json.Unmarshal([]byte(data), &relay); err != nil {
		return types.AttestationRelay{}, fmt.Errorf("corrupt attestation relay data: %w", err)
	}
	if relay.RegisteredAt == 0 {
		return types.AttestationRelay{}, types.ErrRelayNotRegistered
	}
	return relay, nil
}

// setAttestationRelay serializes and stores a relay to state.
func (k *Keeper) setAttestationRelay(ctx context.Context, platformKey string, relay types.AttestationRelay) error {
	data, err := json.Marshal(relay)
	if err != nil {
		return err
	}
	return k.AttestationRelays.Set(ctx, platformKey, string(data))
}

// BuildValidatorSelectionRequest returns the JSON request body that an off-chain
// relayer should POST to the TEE worker's /select-validators endpoint.
// This is a read-only helper — it never mutates state or performs HTTP.
//
// # Fail-closed telemetry policy
//
// Validators are excluded from the request if their telemetry is missing
// (TelemetryUpdatedAt is zero) or stale (older than TelemetryMaxAgeSec).
// If the resulting candidate list is empty, the function returns an error.
//
// This prevents the TEE from scoring fabricated or outdated data and producing
// a valid attestation over synthetic / stale inputs.  The relayer MUST call
// UpdateValidatorTelemetry() for each validator every epoch.
//
// # Policy hash alignment
//
// IMPORTANT: The config values here MUST match the protocol defaults used in
// ApplyValidatorSelection's computeSelectionPolicyHash() call. If they diverge,
// the TEE attestation will contain a policy hash that doesn't match what the
// on-chain verifier expects, and updateValidatorSet() / ApplyValidatorSelection()
// will reject the attestation with a policy mismatch error.
// BuildValidatorSelectionRequest builds the JSON request body sent to the TEE
// worker's /select-validators endpoint.
//
// Security invariants enforced here:
//  1. Only active validators are considered candidates.
//  2. Validators without fresh telemetry (TelemetryUpdatedAt zero or older than
//     TelemetryMaxAgeSec) are excluded.
//  3. A quorum check (MinTelemetryQuorumPct of active validators must have fresh
//     telemetry) prevents a malicious relayer from biasing the candidate set by
//     selectively withholding UpdateValidatorTelemetry() calls.
//  4. An eligible-universe hash (SHA-256 of sorted eligible addresses) is
//     included in the request so the TEE attestation can commit to the exact
//     candidate set, making omissions detectable on-chain.
func (k *Keeper) BuildValidatorSelectionRequest(ctx context.Context) ([]byte, error) {
	params := k.getParams(ctx)
	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	maxAge := params.TelemetryMaxAgeSec
	if maxAge == 0 {
		maxAge = types.DefaultTelemetryMaxAgeSec
	}

	result := k.getValidatorInputs(ctx, blockTime, maxAge)

	if result.eligible == 0 {
		return nil, fmt.Errorf(
			"no validators with fresh telemetry (active: %d, skipped_stale: %d, max_age: %ds); "+
				"call UpdateValidatorTelemetry() before building the selection request",
			result.totalActive, result.skippedStale, maxAge,
		)
	}

	// ── Quorum check ────────────────────────────────────────────────────
	// A minimum fraction of active validators must have fresh telemetry.
	// This prevents a malicious or faulty relayer from selectively
	// withholding telemetry updates for targeted validators to bias the
	// candidate set that the TEE scores and attests.
	//
	// Cross-multiplication avoids integer-division rounding:
	//   eligible/totalActive >= quorumPct/100
	//   ⟺  eligible*100 >= quorumPct*totalActive
	quorumPct := params.MinTelemetryQuorumPct
	if quorumPct == 0 {
		quorumPct = types.DefaultMinTelemetryQuorumPct
	}
	if result.totalActive > 0 &&
		uint64(result.eligible)*100 < uint64(quorumPct)*uint64(result.totalActive) {
		actualPct := result.eligible * 100 / result.totalActive
		return nil, fmt.Errorf(
			"telemetry quorum not met: %d/%d active validators (%d%%) have fresh telemetry, "+
				"need >= %d%%; call UpdateValidatorTelemetry() for remaining validators",
			result.eligible, result.totalActive, actualPct, quorumPct,
		)
	}

	// ── Eligible-universe hash ──────────────────────────────────────────
	// SHA-256 of the sorted eligible addresses with null-byte separators.
	// Included in the request so the TEE attestation commits to the exact
	// candidate set, enabling on-chain verification that no validators
	// were omitted between BuildValidatorSelectionRequest and the TEE.
	universeHash := computeEligibleUniverseHash(result.eligibleAddrs)

	reqBody := map[string]interface{}{
		"epoch":                  currentEpoch,
		"target_count":           params.MaxValidators,
		"validators":             result.inputs,
		"eligible_universe_hash": hex.EncodeToString(universeHash[:]),
		"total_active_count":     result.totalActive,
		"eligible_count":         result.eligible,
		"skipped_stale_count":    result.skippedStale,
		"config": map[string]interface{}{
			"performance_weight":      0.4,
			"decentralization_weight": 0.3,
			"reputation_weight":       0.3,
			"min_uptime_pct":          95.0,
			"max_commission_bps":      params.MaxCommission,
			"max_per_region":          0,
			"max_per_operator":        3,
			"min_stake":               params.MinStake,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	return body, nil
}

// validatorInputsResult holds the output of getValidatorInputs.
type validatorInputsResult struct {
	inputs        []map[string]interface{} // TEE-format inputs for eligible validators
	totalActive   int                      // active validators in the store
	eligible      int                      // active with fresh telemetry (= len(inputs))
	skippedStale  int                      // active but stale/missing telemetry
	eligibleAddrs []string                 // sorted addresses of eligible validators
}

// getValidatorInputs converts stored validator records to TEE request format.
//
// Only active validators (IsActive == true) are considered; inactive validators
// are silently ignored since they are not part of the candidate universe.
// Among active validators, those without fresh telemetry (TelemetryUpdatedAt is
// zero or older than maxAgeSec) are excluded and counted as skippedStale.
//
// The returned eligibleAddrs are sorted for deterministic universe-hash
// computation.
func (k *Keeper) getValidatorInputs(ctx context.Context, blockTime time.Time, maxAgeSec uint64) validatorInputsResult {
	var result validatorInputsResult
	cutoff := blockTime.Add(-time.Duration(maxAgeSec) * time.Second)

	_ = k.Validators.Walk(ctx, nil, func(_ string, raw string) (bool, error) {
		var v types.ValidatorRecord
		if json.Unmarshal([]byte(raw), &v) != nil {
			return false, nil
		}

		// Skip inactive validators — they are not part of the candidate universe.
		if !v.IsActive {
			return false, nil
		}
		result.totalActive++

		// Fail-closed: exclude active validators without real telemetry or with
		// stale telemetry older than the configured max age.
		if v.TelemetryUpdatedAt.IsZero() || v.TelemetryUpdatedAt.Before(cutoff) {
			result.skippedStale++
			return false, nil
		}

		result.eligibleAddrs = append(result.eligibleAddrs, v.Address)
		result.inputs = append(result.inputs, map[string]interface{}{
			"address":              v.Address,
			"stake":                v.DelegatedStake,
			"uptime_pct":           v.UptimePct,
			"avg_response_ms":      v.AvgResponseMs,
			"geographic_region":    v.GeographicRegion,
			"country_code":         v.CountryCode,
			"operator_id":          v.OperatorID,
			"slash_count":          v.SlashCount,
			"total_jobs_completed": v.TotalJobsCompleted,
			"tee_public_key":       fmt.Sprintf("%x", v.TEEPublicKey),
			"commission_bps":       v.Commission,
		})
		return false, nil
	})

	result.eligible = len(result.inputs)
	sort.Strings(result.eligibleAddrs)
	return result
}

// computeEligibleUniverseHash computes SHA-256 over the sorted eligible
// validator addresses with null-byte separators, producing a deterministic
// commitment to the exact candidate set submitted to the TEE.
func computeEligibleUniverseHash(sortedAddrs []string) [32]byte {
	h := sha256.New()
	for _, addr := range sortedAddrs {
		h.Write([]byte(addr))
		h.Write([]byte{0}) // null separator for domain separation
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// UpdateValidatorTelemetry updates the telemetry fields for a validator.
//
// This MUST be called by the oracle / relayer with real monitoring data before
// calling BuildValidatorSelectionRequest().  Validators whose telemetry is
// missing or older than TelemetryMaxAgeSec (default 48 h) are excluded from
// the TEE selection request.  The relayer should call this at least once per
// epoch to keep validators eligible.
//
// Fields updated: UptimePct, AvgResponseMs, TotalJobsCompleted, CountryCode.
func (k *Keeper) UpdateValidatorTelemetry(
	ctx context.Context,
	address string,
	uptimePct float64,
	avgResponseMs float64,
	totalJobsCompleted uint64,
	countryCode string,
) error {
	v, exists := k.getValidator(ctx, address)
	if !exists {
		return fmt.Errorf("validator %s not found", address)
	}
	if uptimePct < 0 || uptimePct > 100 {
		return fmt.Errorf("uptime_pct must be in [0, 100], got %f", uptimePct)
	}
	if avgResponseMs < 0 {
		return fmt.Errorf("avg_response_ms must be >= 0, got %f", avgResponseMs)
	}

	v.UptimePct = uptimePct
	v.AvgResponseMs = avgResponseMs
	v.TotalJobsCompleted = totalJobsCompleted
	v.CountryCode = countryCode

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	v.TelemetryUpdatedAt = sdkCtx.BlockTime()

	return k.setValidator(ctx, v)
}

// SlashValidator removes a validator from the active set.
func (k *Keeper) SlashValidator(ctx context.Context, validatorAddr string, reason string) error {
	if err := k.requireNotPaused(ctx); err != nil {
		return err
	}

	v, exists := k.getValidator(ctx, validatorAddr)
	if !exists || !v.IsActive {
		return fmt.Errorf("validator %s not active", validatorAddr)
	}

	v.IsActive = false
	v.SlashCount++
	if err := k.setValidator(ctx, v); err != nil {
		return err
	}

	// Remove from active list
	activeAddrs := k.getActiveValidatorAddrs(ctx)
	for i, addr := range activeAddrs {
		if addr == validatorAddr {
			activeAddrs = append(activeAddrs[:i], activeAddrs[i+1:]...)
			break
		}
	}
	if err := k.setActiveValidatorAddrs(ctx, activeAddrs); err != nil {
		return err
	}

	// Track slash count for circuit breaker evaluation.
	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)
	epochKey := strconv.FormatUint(currentEpoch, 10)
	epochSlashes, _ := k.EpochSlashCount.Get(ctx, epochKey)
	if err := k.EpochSlashCount.Set(ctx, epochKey, epochSlashes+1); err != nil {
		return err
	}
	// Evaluate circuit breaker (may auto-pause).
	_ = k.checkCircuitBreaker(ctx, "slash:"+validatorAddr)

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// View Functions
// ─────────────────────────────────────────────────────────────────────────────

// GetVaultStatus returns the current vault state.
func (k *Keeper) GetVaultStatus(ctx context.Context) types.VaultStatus {
	totalPooled := k.getUint64(ctx, k.TotalPooledAethel)
	totalShares := k.getUint64(ctx, k.TotalShares)

	var exchangeRate float64
	if totalShares > 0 {
		exchangeRate = float64(totalPooled) / float64(totalShares)
	} else {
		exchangeRate = 1.0
	}

	activeAddrs := k.getActiveValidatorAddrs(ctx)

	// Count stakers by walking the map
	var totalStakers uint64
	_ = k.Stakers.Walk(ctx, nil, func(_ string, _ string) (bool, error) {
		totalStakers++
		return false, nil
	})

	ps := k.getPauseState(ctx)

	return types.VaultStatus{
		TotalPooledAethel:  totalPooled,
		TotalShares:        totalShares,
		ExchangeRate:       exchangeRate,
		CurrentEpoch:       k.getUint64(ctx, k.CurrentEpoch),
		ActiveValidators:   uint32(len(activeAddrs)),
		TotalStakers:       totalStakers,
		PendingWithdrawals: k.getUint64(ctx, k.TotalPendingWithdrawals),
		TotalMEVRevenue:    k.getUint64(ctx, k.TotalMEVRevenue),
		Params:             k.getParams(ctx),
		Paused:             ps.Paused,
		PauseReason:        ps.Reason,
	}
}

// GetStaker returns a staker's record.
func (k *Keeper) GetStaker(ctx context.Context, address string) (*types.StakerRecord, error) {
	staker, exists := k.getStaker(ctx, address)
	if !exists {
		return nil, fmt.Errorf("staker not found: %s", address)
	}
	return staker, nil
}

// GetExchangeRate returns the current AETHEL/stAETHEL rate.
func (k *Keeper) GetExchangeRate(ctx context.Context) float64 {
	totalShares := k.getUint64(ctx, k.TotalShares)
	if totalShares == 0 {
		return 1.0
	}
	totalPooled := k.getUint64(ctx, k.TotalPooledAethel)
	return float64(totalPooled) / float64(totalShares)
}

// GetActiveValidators returns the current active validator set.
func (k *Keeper) GetActiveValidators(ctx context.Context) []types.ValidatorRecord {
	activeAddrs := k.getActiveValidatorAddrs(ctx)
	result := make([]types.ValidatorRecord, 0, len(activeAddrs))
	for _, addr := range activeAddrs {
		if v, exists := k.getValidator(ctx, addr); exists {
			result = append(result, *v)
		}
	}
	return result
}

// GetUserWithdrawals returns a user's pending withdrawal requests.
func (k *Keeper) GetUserWithdrawals(ctx context.Context, address string) []types.WithdrawalRequest {
	ids := k.getUserWithdrawalIDs(ctx, address)
	result := make([]types.WithdrawalRequest, 0, len(ids))
	for _, id := range ids {
		if req, exists := k.getWithdrawal(ctx, id); exists {
			result = append(result, *req)
		}
	}
	return result
}

// GetEpochSnapshot returns the snapshot for a specific epoch.
func (k *Keeper) GetEpochSnapshot(ctx context.Context, epoch uint64) (*types.EpochSnapshot, error) {
	raw, err := k.EpochSnapshots.Get(ctx, strconv.FormatUint(epoch, 10))
	if err != nil {
		return nil, fmt.Errorf("epoch %d not found", epoch)
	}
	var snap types.EpochSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return nil, fmt.Errorf("unmarshal epoch %d: %w", epoch, err)
	}
	return &snap, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation Attestation Request Builder
// ─────────────────────────────────────────────────────────────────────────────

// stakerStakeEntry represents a staker's stake data for TEE request formatting.
// JSON tags match the Rust StakerStake struct expected by /attest-delegation.
type stakerStakeEntry struct {
	Address     string `json:"address"`
	Shares      uint64 `json:"shares"`
	DelegatedTo string `json:"delegated_to"`
}

// SnapshotDelegationState freezes the current delegation mapping for the
// current epoch, storing it in the DelegationSnapshots store.
//
// The relayer MUST call this at the same block where commitStakeSnapshot()
// anchors the share distribution on EVM. This ensures the delegation topology
// used for performance-weighted rewards corresponds to the exact share
// distribution that was committed — preventing post-snapshot re-delegations
// from influencing reward settlement.
//
// Calling this more than once for the same epoch is an error (the snapshot
// is immutable once created).
//
// ## Delegation integrity validation
//
// Every staker's DelegatedTo must refer to a known (active or inactive)
// validator.  This fail-closed check prevents the keeper from snapshotting
// delegation state that includes fabricated or stale validator targets,
// which would corrupt performance-weighted reward allocation on EVM.
// The Rust TEE applies the same validation before computing the delegation
// root (reject empty or unknown delegation targets).
func (k *Keeper) SnapshotDelegationState(ctx context.Context) error {
	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)
	epochKey := strconv.FormatUint(currentEpoch, 10)

	// Check if a snapshot already exists for this epoch.
	if _, err := k.DelegationSnapshots.Get(ctx, epochKey); err == nil {
		return fmt.Errorf("delegation snapshot already exists for epoch %d", currentEpoch)
	}

	entries, err := k.collectStakerEntries(ctx)
	if err != nil {
		return fmt.Errorf("snapshot delegation state: %w", err)
	}

	// Validate delegation integrity: every staker's delegation target must
	// be a known validator.  This mirrors the Rust TEE's fail-closed check
	// and prevents snapshotting fabricated delegation targets.
	for _, entry := range entries {
		if entry.DelegatedTo == "" {
			return fmt.Errorf(
				"staker %s has empty delegation target: "+
					"delegation is mandatory for reward weighting", entry.Address)
		}
		if _, exists := k.getValidator(ctx, entry.DelegatedTo); !exists {
			return fmt.Errorf(
				"staker %s delegates to unknown validator %s: "+
					"delegation target must be a registered validator",
				entry.Address, entry.DelegatedTo)
		}
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal delegation snapshot: %w", err)
	}

	return k.DelegationSnapshots.Set(ctx, epochKey, string(data))
}

// GetDelegationSnapshotStakerCount returns the number of stakers in the
// frozen delegation snapshot for the given epoch.  This is the cardinality
// anchor that must be committed alongside the delegation root on EVM to
// allow off-chain monitors to detect omission attacks.
func (k *Keeper) GetDelegationSnapshotStakerCount(ctx context.Context, epoch uint64) (uint64, error) {
	epochKey := strconv.FormatUint(epoch, 10)
	raw, err := k.DelegationSnapshots.Get(ctx, epochKey)
	if err != nil {
		return 0, fmt.Errorf("no delegation snapshot for epoch %d", epoch)
	}
	var entries []stakerStakeEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return 0, fmt.Errorf("unmarshal delegation snapshot for epoch %d: %w", epoch, err)
	}
	return uint64(len(entries)), nil
}

// collectStakerEntries walks the live staker store and returns all stakers
// with non-zero shares as normalized stakerStakeEntry values.
func (k *Keeper) collectStakerEntries(ctx context.Context) ([]stakerStakeEntry, error) {
	var entries []stakerStakeEntry
	seen := make(map[string]bool)
	var walkErr error

	_ = k.Stakers.Walk(ctx, nil, func(_ string, raw string) (bool, error) {
		var s types.StakerRecord
		if json.Unmarshal([]byte(raw), &s) != nil {
			return false, nil // skip malformed records
		}
		if s.Shares == 0 {
			return false, nil
		}

		// Use the canonical EVM address for registry root compatibility.
		// This must be a 20-byte hex string (no 0x prefix) that matches
		// the EVM StAETHEL accumulator's address representation.
		evmAddr := s.EvmAddress
		if evmAddr == "" {
			// Backfill: resolve from the stored address.
			resolved, err := resolveEvmAddress(s.Address)
			if err != nil {
				walkErr = fmt.Errorf("resolve EVM address for staker %s: %w", s.Address, err)
				return true, nil
			}
			evmAddr = resolved
		}
		evmAddr = strings.ToLower(evmAddr)

		if seen[evmAddr] {
			walkErr = fmt.Errorf("duplicate staker EVM address in store: %s (from %s)", evmAddr, s.Address)
			return true, nil // stop iteration
		}
		seen[evmAddr] = true
		entries = append(entries, stakerStakeEntry{
			Address:     evmAddr,
			Shares:      s.Shares,
			DelegatedTo: strings.ToLower(s.DelegatedTo),
		})
		return false, nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	return entries, nil
}

// BuildDelegationAttestationRequest reads the epoch-scoped delegation snapshot
// and builds a JSON request body for the Rust TEE worker's /attest-delegation
// endpoint.
//
// The relayer must call SnapshotDelegationState() first to freeze the
// delegation mapping for the current epoch. This ensures temporal consistency:
// the delegation topology matches the share distribution anchored by
// commitStakeSnapshot() on EVM.
//
// The request includes:
//   - epoch: the current epoch
//   - staker_stakes: array of {address, shares, delegated_to} from the frozen snapshot
//   - staker_registry_root: XOR-based commitment to the staker set (hex-encoded)
//
// ## Trust model
//
// The delegation bridge pipeline has nine defense-in-depth layers:
//
//  1. This keeper snapshots native-chain delegation state (validator targets).
//     Fail-closed: every delegation target must be a registered validator.
//  2. The Rust TEE independently recomputes the staker registry root and
//     delegation registry root from the staker data, rejecting mismatches.
//  3. The EVM verifies the TEE attestation and cross-checks the staker
//     registry root against the on-chain StAETHEL XOR accumulator.
//  4. A 1-hour challenge period allows off-chain watchers to detect and
//     request guardian revocation of incorrect delegation commitments.
//  5. A 6-hour max-age guard prevents stale commitments from being consumed.
//  6. A cardinality anchor (staker count) is committed alongside the root
//     to detect omission of stakers from the delegation snapshot.
//  7. Multi-attestor quorum (DELEGATION_QUORUM = 2): when enabled, multiple
//     independent attestors (each running their own keeper + TEE) must agree
//     on the same delegation root.  No single operator can fabricate state.
//  8. Keeper bond & slash (KEEPER_BOND_MINIMUM = 100K AETHEL): keepers must
//     post an economic bond that the guardian can seize if delegation fraud
//     is proven during the challenge period.
//  9. Permissionless challenge (DELEGATION_CHALLENGE_THRESHOLD = 3): any
//     address can flag a delegation commitment; enough flags auto-revoke
//     without guardian intervention.
//
// Residual assumption: the keeper provides the delegated_to field for each
// staker.  The TEE validates the staker set (via registry root) but cannot
// independently read native-chain delegation state.  This is an inherent
// property of cross-chain bridging without light-client proofs.  The nine
// layers above make exploitation require compromising multiple independent
// TEE operators, posting substantial slashable collateral, and avoiding
// detection by all off-chain watchers during the challenge period.
//
// This mirrors BuildValidatorSelectionRequest for the validator-selection flow
// and completes the native keeper → TEE → EVM pipeline for delegation attestation.
func (k *Keeper) BuildDelegationAttestationRequest(ctx context.Context) ([]byte, error) {
	currentEpoch := k.getUint64(ctx, k.CurrentEpoch)
	epochKey := strconv.FormatUint(currentEpoch, 10)

	// Read the frozen delegation snapshot for this epoch.
	raw, err := k.DelegationSnapshots.Get(ctx, epochKey)
	if err != nil {
		return nil, fmt.Errorf(
			"no delegation snapshot for epoch %d; call SnapshotDelegationState() "+
				"at the same block as commitStakeSnapshot() before building the "+
				"attestation request", currentEpoch,
		)
	}

	var entries []stakerStakeEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("unmarshal delegation snapshot for epoch %d: %w", currentEpoch, err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("delegation snapshot for epoch %d contains no stakers", currentEpoch)
	}

	// Compute the staker registry root — XOR of keccak256(address, shares)
	// for each staker. This matches the Rust and Solidity implementations.
	registryRoot := computeStakerRegistryRoot(entries)

	reqBody := map[string]interface{}{
		"epoch":                 currentEpoch,
		"staker_stakes":        entries,
		"staker_registry_root": hex.EncodeToString(registryRoot[:]),
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal delegation attestation request: %w", err)
	}
	return body, nil
}

// computeStakerRegistryRoot computes the XOR-based staker registry root from
// a set of staker entries.
//
// For each staker with non-zero shares:
//
//	keccak256(abi.encodePacked(address_20bytes, shares_uint256))
//
// is XORed into a 32-byte accumulator.
//
// The computation matches the Rust compute_staker_registry_root() and the
// Solidity on-chain stakerRegistryRoot exactly:
//   - Address: parsed to 20 bytes (0x-hex → decode; fallback → SHA-256 first 20)
//   - Shares:  encoded as uint256 (32 bytes big-endian, matching Solidity)
//   - Hash:    Keccak-256 (Ethereum's flavour, via sha3.NewLegacyKeccak256)
//   - Combine: XOR accumulator
func computeStakerRegistryRoot(entries []stakerStakeEntry) [32]byte {
	var accumulator [32]byte

	for _, e := range entries {
		if e.Shares == 0 {
			continue
		}

		// Address as 20 bytes, matching Solidity abi.encodePacked(address).
		addrBytes := parseAddressBytes(e.Address)

		// Shares as uint256 (32 bytes big-endian), matching Solidity uint256.
		// Uses big.Int for explicit uint256 encoding — correct for any value
		// width (uint64 today, but future-proof if shares type is ever widened
		// to match Rust u128 or Solidity uint256).
		sharesBig := new(big.Int).SetUint64(e.Shares)
		var sharesBE [32]byte
		sharesBytes := sharesBig.Bytes() // big-endian, minimal encoding
		copy(sharesBE[32-len(sharesBytes):], sharesBytes)

		// keccak256(abi.encodePacked(address, shares))
		h := sha3.NewLegacyKeccak256()
		h.Write(addrBytes[:])
		h.Write(sharesBE[:])
		hash := h.Sum(nil)

		for i := 0; i < 32; i++ {
			accumulator[i] ^= hash[i]
		}
	}

	return accumulator
}

// parseAddressBytes converts an address string to 20 bytes, matching the Rust
// parse_address_bytes implementation:
//   - 0x-prefixed hex → strip prefix, decode to bytes
//   - Decoded length == 20 → use as-is
//   - Decoded length < 20 → left-pad with zeros
//   - Decode failure or length > 20 → SHA-256(address), take first 20 bytes
//
// The SHA-256 fallback handles bech32 Cosmos addresses (e.g. aethel1...)
// which are not valid hex. Both Rust and Go produce the same 20-byte
// representation for any given address string.
//
// Callers should normalize addresses to lowercase before calling to ensure
// cross-language consistency (BuildDelegationAttestationRequest does this).
func parseAddressBytes(addr string) [20]byte {
	hexAddr := strings.TrimPrefix(strings.ToLower(addr), "0x")
	decoded, err := hex.DecodeString(hexAddr)
	if err == nil && len(decoded) == 20 {
		var result [20]byte
		copy(result[:], decoded)
		return result
	}
	if err == nil && len(decoded) < 20 {
		var result [20]byte
		copy(result[20-len(decoded):], decoded) // left-pad
		return result
	}
	// No SHA-256 fallback — all addresses must resolve to canonical 20-byte
	// EVM form via resolveEvmAddress before reaching this point.
	// If we get here, it's a programming error.
	var result [20]byte
	return result
}

// resolveEvmAddress converts an address string to a canonical 20-byte EVM
// address (lowercase hex, no 0x prefix). This ensures the Go keeper and Rust
// TEE producer use the same 20-byte representation that the EVM StAETHEL
// accumulator uses for the stakerRegistryRoot.
//
// Supported formats:
//   - 0x-prefixed hex (e.g. "0xAbC123...") → strip prefix, lowercase
//   - Raw hex (e.g. "abc123...") → lowercase
//   - Bech32 (e.g. "aethel1abc...") → decode raw bytes → hex
//
// Returns an error if the address cannot be resolved to exactly 20 bytes.
func resolveEvmAddress(addr string) (string, error) {
	// Try hex decode first (handles both 0x-prefixed and raw hex).
	hexAddr := strings.TrimPrefix(strings.ToLower(addr), "0x")
	decoded, err := hex.DecodeString(hexAddr)
	if err == nil && len(decoded) == 20 {
		return hexAddr, nil
	}

	// Try bech32 decode (Cosmos SDK / Ethermint addresses).
	bech32Bytes, bech32Err := sdk.AccAddressFromBech32(addr)
	if bech32Err == nil && len(bech32Bytes) == 20 {
		return hex.EncodeToString(bech32Bytes), nil
	}

	return "", fmt.Errorf(
		"cannot resolve address %q to 20-byte EVM form: "+
			"hex decode: %v (len=%d), bech32 decode: %v",
		addr, err, len(decoded), bech32Err,
	)
}
