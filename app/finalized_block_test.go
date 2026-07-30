package app

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/stretchr/testify/require"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

func TestFinalizedBlockBindingRoundTrip(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(7)
	blockHash := sha256.Sum256([]byte("decided-block-seven"))

	require.NoError(t, app.persistFinalizedBlock(ctx, 7, blockHash[:]))

	height, gotHash, found, err := app.lastFinalizedBlock(ctx)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(7), height)
	require.Equal(t, blockHash[:], gotHash)

	// Callers cannot mutate the consensus-state value through the returned
	// slice.
	gotHash[0] ^= 0xff
	_, gotHashAgain, found, err := app.lastFinalizedBlock(ctx)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, blockHash[:], gotHashAgain)
}

func TestFinalizedBlockBindingFailsClosedOnMalformedState(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).WithBlockHeight(2)
	ctx.KVStore(app.keys[pouwtypes.StoreKey]).Set(
		pouwtypes.LastFinalizedBlockKey,
		[]byte("malformed"),
	)

	_, _, _, err := app.lastFinalizedBlock(ctx)
	require.ErrorContains(t, err, "malformed finalized block record length")
	_, _, err = app.previousFinalizedBlockHash(ctx, 2)
	require.ErrorContains(t, err, "malformed finalized block record length")
}

func TestProcessProposalRejectsValidEvidenceForNonFinalizedFork(t *testing.T) {
	signedForkHash := sha256.Sum256([]byte("valid-earlier-round-fork"))
	finalizedHash := sha256.Sum256([]byte("actually-decided-block"))
	scenario := buildSignedSealScenarioWithBlockHashes(
		t,
		"job-finalized-fork-replay",
		signedForkHash[:],
		finalizedHash[:],
	)

	// The compact validator signatures, job, quorum, and last-commit
	// membership are all valid. Only their signed block hash belongs to a
	// non-finalized proposal at the same height.
	err := scenario.app.validateSelfContainedSealEvidence(
		scenario.ctx,
		scenario.sealTxs[0],
		scenario.commit,
		scenario.finalizedHash,
	)
	require.ErrorContains(t, err, "does not attest the finalized block")

	resp, err := scenario.app.ProcessProposalHandler()(
		scenario.ctx,
		&abci.RequestProcessProposal{
			Height:             2,
			Txs:                scenario.sealTxs,
			ProposedLastCommit: scenario.commit,
		},
	)
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, resp.Status)
}

func TestProcessProposalUsesPersistedBindingWithoutVoteExtensionCache(t *testing.T) {
	scenario := buildSignedSealScenario(t, "job-persisted-binding-restart")

	// Simulate fresh process-local state after a validator restart. Consensus
	// acceptance still uses the persisted finalized-block record.
	scenario.app.voteExtensionCache = NewVoteExtensionCache(
		4,
		scenario.ctx.ChainID(),
	)
	resp, err := scenario.app.ProcessProposalHandler()(
		scenario.ctx,
		&abci.RequestProcessProposal{
			Height:             2,
			Txs:                scenario.sealTxs,
			ProposedLastCommit: scenario.commit,
		},
	)
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)
}

func TestMissingFinalizedBindingAllowsSealFreeBootstrap(t *testing.T) {
	app := newTestApp(t)
	ctx := app.BaseApp.NewContext(true).
		WithBlockHeight(12).
		WithBlockTime(time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)).
		WithChainID("aethelred-test-1")

	resp, err := app.ProcessProposalHandler()(ctx, &abci.RequestProcessProposal{
		Height: 12,
		Txs:    nil,
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_ACCEPT, resp.Status)

	app.ModuleManager = module.NewManager()
	decidedHash := sha256.Sum256([]byte("bootstrap-decided-block"))
	_, err = app.PreBlocker(ctx, &abci.RequestFinalizeBlock{
		Height: 12,
		Hash:   decidedHash[:],
	})
	require.NoError(t, err)

	height, gotHash, found, err := app.lastFinalizedBlock(ctx)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(12), height)
	require.Equal(t, decidedHash[:], gotHash)
}

func TestInvalidFinalizedBindingFailsClosedWithoutSeals(t *testing.T) {
	tests := []struct {
		name    string
		install func(*AethelredApp, sdk.Context)
		wantErr string
	}{
		{
			name: "malformed",
			install: func(app *AethelredApp, ctx sdk.Context) {
				ctx.KVStore(app.keys[pouwtypes.StoreKey]).Set(
					pouwtypes.LastFinalizedBlockKey,
					[]byte("malformed"),
				)
			},
			wantErr: "malformed finalized block record length",
		},
		{
			name: "stale height",
			install: func(app *AethelredApp, ctx sdk.Context) {
				staleHash := sha256.Sum256([]byte("stale-decided-block"))
				require.NoError(t, app.persistFinalizedBlock(
					ctx.WithBlockHeight(7),
					7,
					staleHash[:],
				))
			},
			wantErr: "finalized block binding height mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(t)
			app.ModuleManager = module.NewManager()
			ctx := app.BaseApp.NewContext(true).
				WithBlockHeight(9).
				WithBlockTime(time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)).
				WithChainID("aethelred-test-1")
			tt.install(app, ctx)

			prepareResp, prepareErr := app.PrepareProposalHandler()(
				ctx,
				&abci.RequestPrepareProposal{
					Height:     9,
					MaxTxBytes: -1,
				},
			)
			require.Nil(t, prepareResp)
			require.ErrorContains(t, prepareErr, tt.wantErr)

			processResp, processErr := app.ProcessProposalHandler()(
				ctx,
				&abci.RequestProcessProposal{
					Height: 9,
					Txs:    nil,
				},
			)
			require.NoError(t, processErr)
			require.Equal(t, abci.ResponseProcessProposal_REJECT, processResp.Status)

			currentHash := sha256.Sum256([]byte("current-decided-block"))
			_, preBlockErr := app.PreBlocker(
				ctx,
				&abci.RequestFinalizeBlock{
					Height: 9,
					Hash:   currentHash[:],
					Txs:    nil,
				},
			)
			require.ErrorContains(t, preBlockErr, tt.wantErr)
		})
	}
}

func TestPrepareProposalFinalizedBlockBinding(t *testing.T) {
	t.Run("matching persisted binding includes seal", func(t *testing.T) {
		scenario := buildSignedSealScenario(t, "job-prepare-bound")
		resp, err := scenario.app.PrepareProposalHandler()(
			scenario.ctx,
			&abci.RequestPrepareProposal{
				Height:          2,
				MaxTxBytes:      -1,
				LocalLastCommit: abci.ExtendedCommitInfo{Votes: scenario.extendedVotes},
			},
		)
		require.NoError(t, err)
		require.Len(t, resp.Txs, 1)
		require.True(t, IsInjectedVoteExtensionTx(resp.Txs[0]))
	})

	t.Run("missing binding bootstraps without optional seal", func(t *testing.T) {
		scenario := buildSignedSealScenario(t, "job-prepare-bootstrap")
		scenario.ctx.KVStore(
			scenario.app.keys[pouwtypes.StoreKey],
		).Delete(pouwtypes.LastFinalizedBlockKey)

		resp, err := scenario.app.PrepareProposalHandler()(
			scenario.ctx,
			&abci.RequestPrepareProposal{
				Height:          2,
				MaxTxBytes:      -1,
				LocalLastCommit: abci.ExtendedCommitInfo{Votes: scenario.extendedVotes},
			},
		)
		require.NoError(t, err)
		require.Empty(t, resp.Txs)
	})
}

func TestPreBlockPersistsDecidedHashWithoutSeal(t *testing.T) {
	app := newTestApp(t)
	app.ModuleManager = module.NewManager()
	ctx := app.BaseApp.NewContext(true).
		WithBlockHeight(1).
		WithBlockTime(time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)).
		WithChainID("aethelred-test-1")
	decidedHash := sha256.Sum256([]byte("decided-block-one"))

	_, err := app.PreBlocker(ctx, &abci.RequestFinalizeBlock{
		Height: 1,
		Hash:   decidedHash[:],
	})
	require.NoError(t, err)

	height, gotHash, found, err := app.lastFinalizedBlock(ctx)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(1), height)
	require.Equal(t, decidedHash[:], gotHash)
}

func TestPreBlockRejectsValidEvidenceForNonFinalizedFork(t *testing.T) {
	signedForkHash := sha256.Sum256([]byte("valid-preblock-fork"))
	finalizedHash := sha256.Sum256([]byte("decided-preblock-parent"))
	scenario := buildSignedSealScenarioWithBlockHashes(
		t,
		"job-preblock-fork-replay",
		signedForkHash[:],
		finalizedHash[:],
	)
	scenario.app.ModuleManager = module.NewManager()
	currentHash := sha256.Sum256([]byte("decided-current-block"))

	_, err := scenario.app.PreBlocker(
		scenario.ctx,
		&abci.RequestFinalizeBlock{
			Height:            2,
			Hash:              currentHash[:],
			Txs:               scenario.sealTxs,
			DecidedLastCommit: scenario.commit,
		},
	)
	require.ErrorContains(t, err, "does not attest the finalized block")

	// Rejection must not advance the persisted binding.
	height, gotHash, found, loadErr := scenario.app.lastFinalizedBlock(scenario.ctx)
	require.NoError(t, loadErr)
	require.True(t, found)
	require.Equal(t, int64(1), height)
	require.True(t, bytes.Equal(finalizedHash[:], gotHash))
}
