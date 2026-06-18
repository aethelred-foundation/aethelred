package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/crypto/pqc"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// BuildSealValidatorSet combines registered validator hybrid keys with their
// current voting power into the structure used for Digital Seal quorum
// verification. Validators without a registered hybrid key are omitted (they
// cannot contribute a hybrid signature); a validator missing from powerByAddr
// defaults to zero power.
func BuildSealValidatorSet(hybridKeys map[string][]byte, powerByAddr map[string]int64) map[string]sealtypes.ValidatorVotingInfo {
	set := make(map[string]sealtypes.ValidatorVotingInfo, len(hybridKeys))
	for addr, key := range hybridKeys {
		set[addr] = sealtypes.ValidatorVotingInfo{
			HybridPubKey: key,
			Power:        powerByAddr[addr],
		}
	}
	return set
}

// VerifyJobSealQuorum verifies that a power-weighted 2/3+ quorum of registered
// validators produced valid hybrid signatures over the seal claim.
//
// The hybrid public keys are read from module state; voting power is supplied by
// the caller, which holds the live validator set (e.g. the consensus handler in
// ProcessProposal/FinalizeBlock). Keeping power as an input avoids coupling this
// verification to a particular address-resolution convention and keeps it pure.
func (k Keeper) VerifyJobSealQuorum(
	ctx context.Context,
	claim sealtypes.SealClaim,
	sigs []sealtypes.SealSignature,
	powerByAddr map[string]int64,
	thresholdPercent int,
) (sealtypes.SealQuorumResult, error) {
	hybridKeys, err := k.GetAllValidatorHybridKeys(ctx)
	if err != nil {
		return sealtypes.SealQuorumResult{}, err
	}
	validatorSet := BuildSealValidatorSet(hybridKeys, powerByAddr)
	return sealtypes.VerifySealQuorum(claim, sigs, validatorSet, thresholdPercent)
}

// StoreSealQuorumSignatures persists the validator-quorum hybrid signatures for a
// seal, keyed by seal ID.
func (k Keeper) StoreSealQuorumSignatures(ctx context.Context, sealID string, sigs []sealtypes.SealSignature) error {
	if sealID == "" {
		return fmt.Errorf("seal ID is required")
	}
	encoded, err := json.Marshal(sigs)
	if err != nil {
		return fmt.Errorf("failed to encode seal quorum signatures: %w", err)
	}
	return k.SealQuorumSignatures.Set(ctx, sealID, encoded)
}

// GetSealQuorumSignatures returns the validator-quorum hybrid signatures attached
// to a seal, or nil if none are stored.
func (k Keeper) GetSealQuorumSignatures(ctx context.Context, sealID string) ([]sealtypes.SealSignature, error) {
	encoded, err := k.SealQuorumSignatures.Get(ctx, sealID)
	if err != nil {
		return nil, nil // none stored
	}
	var sigs []sealtypes.SealSignature
	if err := json.Unmarshal(encoded, &sigs); err != nil {
		return nil, fmt.Errorf("failed to decode seal quorum signatures: %w", err)
	}
	return sigs, nil
}

// AttachSealQuorumSignatures verifies each validator's hybrid seal-claim
// signature against its registered hybrid public key and persists the valid ones
// onto the seal. It is best-effort: it never fails seal creation. Signatures that
// are absent, from unregistered validators, or that fail verification are
// omitted; each validator is counted at most once. The power-weighted threshold
// is enforced upstream (aggregation + ValidateSealTransaction); these stored
// signatures are the durable, offline-verifiable artifact.
func (k Keeper) AttachSealQuorumSignatures(
	ctx context.Context,
	sealID string,
	claim sealtypes.SealClaim,
	results []ValidatorResult,
	ts time.Time,
) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	msg := claim.SigningBytes()
	seen := make(map[string]bool)
	var valid []sealtypes.SealSignature

	for _, r := range results {
		if len(r.SealClaimSignature) == 0 {
			continue
		}
		// Resolve the account identity the validator's hybrid key is registered
		// under (consensus address -> operator -> account, via staking).
		accAddr, ok := k.resolveValidatorAccount(sdkCtx, r)
		if !ok || seen[accAddr] {
			continue
		}
		pub, err := k.GetValidatorHybridKey(ctx, accAddr)
		if err != nil {
			continue
		}
		valid2, err := pqc.VerifyHybrid(pub, msg, r.SealClaimSignature)
		if err != nil || !valid2 {
			continue
		}
		seen[accAddr] = true
		valid = append(valid, sealtypes.NewValidatorSealSignature(accAddr, pub, r.SealClaimSignature, ts))
	}

	if len(valid) == 0 {
		return
	}
	if err := k.StoreSealQuorumSignatures(ctx, sealID, valid); err != nil {
		sdkCtx.Logger().Error("failed to store seal quorum signatures",
			"seal_id", sealID, "error", err)
	}
}

// resolveValidatorAccount maps a validator result to the account address its
// hybrid key is registered under. It prefers the consensus address (resolved to
// the operator's account via staking, the authoritative on-chain identity); if
// that is unavailable it falls back to treating ValidatorAddress as an account
// bech32 directly (used by direct/genesis registration and tests).
func (k Keeper) resolveValidatorAccount(ctx sdk.Context, r ValidatorResult) (string, bool) {
	if r.ConsensusAddress != "" && k.stakingKeeper != nil {
		if consAddr, err := sdk.ConsAddressFromBech32(r.ConsensusAddress); err == nil {
			if val, err := k.stakingKeeper.GetValidatorByConsAddr(ctx, consAddr); err == nil {
				if valAddr, err := sdk.ValAddressFromBech32(val.OperatorAddress); err == nil {
					return sdk.AccAddress(valAddr).String(), true
				}
			}
		}
	}
	if _, err := sdk.AccAddressFromBech32(r.ValidatorAddress); err == nil {
		return r.ValidatorAddress, true
	}
	return "", false
}

// consensusAddressString returns the bech32 consensus address for raw CometBFT
// consensus address bytes, or "" when empty.
func consensusAddressString(addr []byte) string {
	if len(addr) == 0 {
		return ""
	}
	return sdk.ConsAddress(addr).String()
}
