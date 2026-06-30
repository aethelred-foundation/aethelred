package keeper

import (
	"context"
	"fmt"

	"github.com/aethelred/aethelred/crypto/pqc"
)

// RegisterValidatorHybridKey stores a validator's hybrid (secp256k1 + ML-DSA)
// public key. This key is used to verify the validator's signatures over Digital
// Seal claims contributed via vote extensions.
//
// The key bytes must be a well-formed compact hybrid public key. Authorization
// (proving the caller controls validatorAddr) is enforced by the message handler
// that invokes this; the storage primitive only validates the key structure.
func (k Keeper) RegisterValidatorHybridKey(ctx context.Context, validatorAddr string, hybridPubKey []byte) error {
	if validatorAddr == "" {
		return fmt.Errorf("validator address is required")
	}
	if err := pqc.ValidateHybridPublicKey(hybridPubKey); err != nil {
		return fmt.Errorf("invalid hybrid public key: %w", err)
	}
	return k.ValidatorHybridKeys.Set(ctx, validatorAddr, hybridPubKey)
}

// GetValidatorHybridKey returns a validator's registered hybrid public key, or an
// error if none is registered.
func (k Keeper) GetValidatorHybridKey(ctx context.Context, validatorAddr string) ([]byte, error) {
	key, err := k.ValidatorHybridKeys.Get(ctx, validatorAddr)
	if err != nil {
		return nil, fmt.Errorf("hybrid key not registered for validator %s", validatorAddr)
	}
	return key, nil
}

// HasValidatorHybridKey reports whether a validator has a registered hybrid key.
func (k Keeper) HasValidatorHybridKey(ctx context.Context, validatorAddr string) bool {
	ok, err := k.ValidatorHybridKeys.Has(ctx, validatorAddr)
	return err == nil && ok
}

// GetAllValidatorHybridKeys returns a copy of every registered validator hybrid
// public key, keyed by validator address.
func (k Keeper) GetAllValidatorHybridKeys(ctx context.Context) (map[string][]byte, error) {
	out := make(map[string][]byte)
	err := k.ValidatorHybridKeys.Walk(ctx, nil, func(addr string, key []byte) (bool, error) {
		cp := make([]byte, len(key))
		copy(cp, key)
		out[addr] = cp
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
