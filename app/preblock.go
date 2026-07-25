package app

import (
	"fmt"

	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	maxInjectedSealTxsPerBlock = 50
	maxInjectedProofBytes      = 5 * 1024 * 1024
)

// PreBlocker runs upgrade handling and applies consensus-created seal
// transactions atomically before ordinary BeginBlock processing.
func (app *AethelredApp) PreBlocker(
	ctx sdk.Context,
	req *abci.RequestFinalizeBlock,
) (resp *sdk.ResponsePreBlock, err error) {
	defer app.recoverABCI("PreBlocker", &err)

	if req == nil {
		return nil, fmt.Errorf("nil finalize-block request")
	}
	if app.ModuleManager == nil {
		return nil, fmt.Errorf("module manager is not configured")
	}
	if req.Height != ctx.BlockHeight() {
		return nil, fmt.Errorf(
			"finalize-block height mismatch: request=%d context=%d",
			req.Height,
			ctx.BlockHeight(),
		)
	}
	if len(req.Hash) != 32 {
		return nil, fmt.Errorf(
			"finalize-block hash has invalid length: got %d, expected 32",
			len(req.Hash),
		)
	}

	injectedTxs := make([][]byte, 0)
	jobIDs := make([]string, 0)
	totalProofBytes := 0
	for _, txBytes := range req.Txs {
		if !IsInjectedVoteExtensionTx(txBytes) {
			continue
		}
		totalProofBytes += len(txBytes)
		injectedTxs = append(injectedTxs, txBytes)
	}
	if len(injectedTxs) > maxInjectedSealTxsPerBlock {
		return nil, fmt.Errorf(
			"injected seal transaction quota exceeded: got %d, max %d",
			len(injectedTxs),
			maxInjectedSealTxsPerBlock,
		)
	}
	if totalProofBytes > maxInjectedProofBytes {
		return nil, fmt.Errorf(
			"finalize-block transaction bytes exceed consensus proof budget: got %d, max %d",
			totalProofBytes,
			maxInjectedProofBytes,
		)
	}

	expectedVoteBlockHash, bindingFound, bindingErr :=
		app.previousFinalizedBlockHash(ctx, req.Height)
	if bindingErr != nil {
		return nil, fmt.Errorf(
			"load prior finalized block binding: %w",
			bindingErr,
		)
	}
	if len(injectedTxs) > 0 && !bindingFound {
		return nil, fmt.Errorf(
			"finalized block binding is unavailable for injected seals at height %d",
			req.Height-1,
		)
	}

	resp, err = app.ModuleManager.PreBlock(ctx)
	if err != nil {
		return resp, fmt.Errorf("module pre-block failed: %w", err)
	}

	if len(injectedTxs) == 0 {
		if err := app.persistFinalizedBlock(ctx, req.Height, req.Hash); err != nil {
			return resp, fmt.Errorf("persist finalized block binding: %w", err)
		}
		return resp, nil
	}
	if app.consensusHandler == nil {
		return resp, fmt.Errorf("consensus handler is not configured")
	}

	consensusThreshold := app.getConsensusThreshold(ctx)
	audit := AuditProposalConsensusEvidence(req.Txs, req.DecidedLastCommit, consensusThreshold)
	if !audit.Passed() {
		return resp, fmt.Errorf("committed consensus evidence audit failed: %s", audit.Error())
	}

	// Prevalidate every transaction against the same unchanged state. This
	// catches duplicates and malformed evidence before any write is attempted.
	seenJobs := make(map[string]struct{}, len(injectedTxs))
	for _, txBytes := range injectedTxs {
		if err := app.consensusHandler.ValidateSealTransaction(ctx, txBytes); err != nil {
			return resp, fmt.Errorf("invalid committed seal transaction: %w", err)
		}
		if err := app.validateSelfContainedSealEvidence(
			ctx,
			txBytes,
			req.DecidedLastCommit,
			expectedVoteBlockHash,
		); err != nil {
			return resp, fmt.Errorf("invalid committed seal evidence: %w", err)
		}
		tx, err := parseInjectedConsensusTx(txBytes)
		if err != nil {
			return resp, fmt.Errorf("parse committed seal transaction: %w", err)
		}
		if _, duplicate := seenJobs[tx.JobID]; duplicate {
			return resp, fmt.Errorf("duplicate committed seal transaction for job %s", tx.JobID)
		}
		seenJobs[tx.JobID] = struct{}{}
		jobIDs = append(jobIDs, tx.JobID)
	}

	// All seal/job/economic writes share one cache. A failure processing any
	// transaction discards every prior transaction in this batch.
	cacheCtx, write := ctx.CacheContext()
	for _, txBytes := range injectedTxs {
		if err := app.consensusHandler.ProcessSealTransaction(cacheCtx, txBytes); err != nil {
			return resp, fmt.Errorf("process committed seal transaction: %w", err)
		}
	}
	write()

	// The scheduler is in-memory state and cannot participate in CacheContext.
	// Mutate it only after all consensus state has committed successfully.
	if scheduler := app.consensusHandler.Scheduler(); scheduler != nil {
		for _, jobID := range jobIDs {
			scheduler.MarkJobCompleteWithContext(ctx, jobID)
		}
	}

	if err := app.persistFinalizedBlock(ctx, req.Height, req.Hash); err != nil {
		return resp, fmt.Errorf("persist finalized block binding: %w", err)
	}

	return resp, nil
}
