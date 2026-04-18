package app

import (
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

func makeStrictVoteExtensionForABCI(t *testing.T, height int64, validatorAddr []byte, ts time.Time) []byte {
	t.Helper()

	ve := NewVoteExtensionAtBlockTime(height, validatorAddr, ts)
	ve.Signature = make([]byte, 64)

	bz, err := ve.Marshal()
	require.NoError(t, err)
	return bz
}

func TestVerifyVoteExtensionHandlerRejectsMismatchedValidatorAddress(t *testing.T) {
	t.Parallel()

	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).
		WithBlockHeight(42).
		WithBlockTime(time.Unix(1_700_000_042, 0).UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))
	app.persistLastBlockTime(ctx)

	reqValidatorAddr := []byte("validator-consensus-addr")
	embeddedValidatorAddr := []byte("different-validator-addr")
	req := &abci.RequestVerifyVoteExtension{
		Height:           42,
		ValidatorAddress: reqValidatorAddr,
		VoteExtension:    makeStrictVoteExtensionForABCI(t, 42, embeddedValidatorAddr, ctx.BlockTime()),
	}

	resp, err := app.VerifyVoteExtensionHandler()(ctx, req)
	require.NoError(t, err)
	require.Equal(t, abci.ResponseVerifyVoteExtension_REJECT, resp.Status)
}

func TestVerifyVoteExtensionHandlerRejectsMismatchedHeight(t *testing.T) {
	t.Parallel()

	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).
		WithBlockHeight(42).
		WithBlockTime(time.Unix(1_700_000_042, 0).UTC())

	require.NoError(t, app.PouwKeeper.SetParams(ctx, pouwtypes.DefaultParams()))
	app.persistLastBlockTime(ctx)

	reqValidatorAddr := []byte("validator-consensus-addr")
	req := &abci.RequestVerifyVoteExtension{
		Height:           42,
		ValidatorAddress: reqValidatorAddr,
		VoteExtension:    makeStrictVoteExtensionForABCI(t, 41, reqValidatorAddr, ctx.BlockTime()),
	}

	resp, err := app.VerifyVoteExtensionHandler()(ctx, req)
	require.NoError(t, err)
	require.Equal(t, abci.ResponseVerifyVoteExtension_REJECT, resp.Status)
}
