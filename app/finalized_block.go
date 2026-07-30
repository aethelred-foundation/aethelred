package app

import (
	"encoding/binary"
	"fmt"

	"github.com/cometbft/cometbft/crypto/tmhash"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

const finalizedBlockRecordSize = 8 + tmhash.Size

// persistFinalizedBlock records the hash CometBFT supplied in FinalizeBlock.
// It must only be called after all application pre-block processing succeeds,
// so a failed FinalizeBlock cannot advance the binding.
func (app *AethelredApp) persistFinalizedBlock(
	ctx sdk.Context,
	height int64,
	blockHash []byte,
) error {
	if height <= 0 {
		return fmt.Errorf("finalized block height must be positive: %d", height)
	}
	if ctx.BlockHeight() != height {
		return fmt.Errorf(
			"finalized block context height mismatch: got %d, expected %d",
			ctx.BlockHeight(),
			height,
		)
	}
	if len(blockHash) != tmhash.Size {
		return fmt.Errorf(
			"finalized block hash has invalid length: got %d, expected %d",
			len(blockHash),
			tmhash.Size,
		)
	}

	record := make([]byte, finalizedBlockRecordSize)
	binary.BigEndian.PutUint64(record[:8], uint64(height))
	copy(record[8:], blockHash)
	ctx.KVStore(app.keys[pouwtypes.StoreKey]).Set(
		pouwtypes.LastFinalizedBlockKey,
		record,
	)
	return nil
}

// lastFinalizedBlock returns the deterministic binding committed by the
// previous successful FinalizeBlock. Missing state is distinct from malformed
// state so the first height after enabling this feature can omit optional seal
// transactions while malformed consensus state always fails closed.
func (app *AethelredApp) lastFinalizedBlock(
	ctx sdk.Context,
) (height int64, blockHash []byte, found bool, err error) {
	record := ctx.KVStore(app.keys[pouwtypes.StoreKey]).Get(
		pouwtypes.LastFinalizedBlockKey,
	)
	if len(record) == 0 {
		return 0, nil, false, nil
	}
	if len(record) != finalizedBlockRecordSize {
		return 0, nil, false, fmt.Errorf(
			"malformed finalized block record length: got %d, expected %d",
			len(record),
			finalizedBlockRecordSize,
		)
	}

	decodedHeight := binary.BigEndian.Uint64(record[:8])
	if decodedHeight == 0 || decodedHeight > uint64(^uint64(0)>>1) {
		return 0, nil, false, fmt.Errorf(
			"malformed finalized block record height: %d",
			decodedHeight,
		)
	}
	return int64(decodedHeight), append([]byte(nil), record[8:]...), true, nil
}

func (app *AethelredApp) previousFinalizedBlockHash(
	ctx sdk.Context,
	currentHeight int64,
) (blockHash []byte, found bool, err error) {
	if currentHeight <= 0 {
		return nil, false, fmt.Errorf(
			"current block height must be positive: %d",
			currentHeight,
		)
	}
	height, blockHash, found, err := app.lastFinalizedBlock(ctx)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	if currentHeight == 1 {
		return nil, false, fmt.Errorf(
			"unexpected finalized block binding at initial height 1",
		)
	}
	if height != currentHeight-1 {
		return nil, false, fmt.Errorf(
			"finalized block binding height mismatch: got %d, expected %d",
			height,
			currentHeight-1,
		)
	}
	return blockHash, true, nil
}
