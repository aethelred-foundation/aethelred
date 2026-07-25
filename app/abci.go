package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"fmt"
	"math"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// NOTE: All vote extension types (VoteExtension, ComputeVerification,
// TEEAttestationData, ZKProofData, AggregatedVerification, etc.) are
// defined in vote_extension.go. This file only contains ABCI++ handlers.

// ExtendVoteHandler returns the ABCI++ ExtendVote handler for Proof-of-Useful-Work.
// This is called during the consensus voting phase, allowing validators to
// include compute verification results in their votes.
//
// CRITICAL: This handler includes panic recovery to prevent a single validator
// panic from halting consensus. Any panic is logged and results in an empty
// vote extension rather than crashing the node.
func (app *AethelredApp) ExtendVoteHandler() sdk.ExtendVoteHandler {
	return func(ctx sdk.Context, req *abci.RequestExtendVote) (resp *abci.ResponseExtendVote, err error) {
		// CRITICAL: Panic recovery for consensus safety
		// A panic in ExtendVote should not crash the validator node
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in ExtendVoteHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// Return empty extension on panic - consensus continues
				resp = &abci.ResponseExtendVote{VoteExtension: nil}
				err = nil // Don't propagate error to consensus
			}
		}()

		app.Logger().Info("ExtendVote called for Proof-of-Useful-Work",
			"height", req.Height,
			"round", 0,
		)

		validatorAddr := app.validatorConsAddr
		if len(validatorAddr) == 0 {
			var addrErr error
			validatorAddr, addrErr = app.validatorConsensusAddress()
			if addrErr != nil {
				app.Logger().Error("Failed to derive validator consensus address for vote extension",
					"height", req.Height,
					"error", addrErr,
				)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
		}

		// Resolve assigned jobs for this validator via the scheduler.
		assignedJobs, validatorAccountAddr, jobsErr := app.assignedJobsForValidator(ctx, validatorAddr)
		if jobsErr != nil {
			app.Logger().Error("Failed to resolve assigned jobs for validator",
				"height", req.Height,
				"error", jobsErr,
			)
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}
		if len(assignedJobs) == 0 {
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}

		// Create vote extension using deterministic block time.
		blockTime := req.Time
		if blockTime.IsZero() {
			blockTime = ctx.BlockTime()
		}
		voteExt := NewVoteExtensionAtBlockTime(req.Height, validatorAddr, blockTime)
		voteExt.ChainID = ctx.ChainID()
		extensionNonce, nonceErr := generateNonce()
		if nonceErr != nil {
			app.Logger().Error("Failed to generate vote extension nonce", "error", nonceErr)
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}
		voteExt.Nonce = extensionNonce

		// ── EV-05/EV-06: Bounded verification loop ──
		// Cap both count (MaxVerificationsPerExtension) and wall-clock time
		// to prevent the verification work from stalling consensus.
		// If we exceed the time budget, we stop early and return a partial extension.
		const maxExtendVoteWallTime = 10 * time.Second // EV-05: hard wall-time cap
		extendDeadline := time.Now().Add(maxExtendVoteWallTime)

		for _, job := range assignedJobs {
			// EV-06: Count cap.
			if len(voteExt.Verifications) >= MaxVerificationsPerExtension {
				app.Logger().Warn("Max verifications per extension reached; truncating",
					"max", MaxVerificationsPerExtension,
				)
				break
			}
			// EV-05: Wall-time cap.
			if time.Now().After(extendDeadline) {
				app.Logger().Warn("ExtendVote time budget exhausted; returning partial extension",
					"completed", len(voteExt.Verifications),
					"remaining", len(assignedJobs)-len(voteExt.Verifications),
				)
				break
			}
			verificationContext, cancelVerification := context.WithDeadline(
				ctx.Context(),
				extendDeadline,
			)
			verification := app.executeAssignedVerification(
				ctx.WithContext(verificationContext),
				job,
				validatorAccountAddr,
			)
			cancelVerification()
			verification.ValidatorSignatureVersion = ComputeVerificationSignatureVersion
			verification.VoteBlockHash = append([]byte(nil), req.Hash...)
			verification.ExtensionNonce = append([]byte(nil), voteExt.Nonce...)
			if app.validatorPrivKey != nil {
				if signErr := signComputeVerification(
					&verification,
					req.Height,
					ctx.ChainID(),
					validatorAddr,
					voteExt.Timestamp,
					ed25519.PrivateKey(app.validatorPrivKey),
				); signErr != nil {
					app.Logger().Error(
						"Failed to sign compute verification",
						"job_id", job.Id,
						"error", signErr,
					)
					return &abci.ResponseExtendVote{VoteExtension: nil}, nil
				}
			}
			voteExt.AddVerification(verification)
		}

		// ── EV-11: Sort verifications deterministically before signing ──
		// Two validators with the same job set but different iteration orders
		// MUST produce identical extension bytes/hashes.
		voteExt.SortVerifications()

		validationMode := app.voteExtensionValidationMode(ctx)

		// Sign the vote extension with validator's ed25519 private key
		// This is CRITICAL for production security - unsigned extensions are rejected
		if app.validatorPrivKey != nil {
			if err := SignVoteExtension(voteExt, app.validatorPrivKey); err != nil {
				app.Logger().Error("Failed to sign vote extension", "error", err)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
		} else {
			if validationMode == ValidationModeStrict {
				app.Logger().Error("SECURITY: validator private key not configured in strict mode; refusing unsigned vote extension",
					"height", req.Height,
				)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
			// Dev/test mode only.
			app.Logger().Warn("SECURITY WARNING: Vote extension created without signature - " +
				"validator private key not configured. This is only acceptable for testing.")
		}

		extBytes, err := voteExt.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vote extension: %w", err)
		}

		// Enforce size limit (trim from end if needed).
		// EV-08: Guard against nil privKey during re-sign; clear stale signature
		// when trimming in permissive mode.
		// EV-10: Guaranteed convergence - each iteration removes one verification,
		// and an empty verifications list produces a small fixed-size extension.
		originalCount := len(voteExt.Verifications)
		for len(extBytes) > MaxVoteExtensionSizeBytes && len(voteExt.Verifications) > 0 {
			voteExt.Verifications = voteExt.Verifications[:len(voteExt.Verifications)-1]
			if app.validatorPrivKey != nil {
				if signErr := SignVoteExtension(voteExt, app.validatorPrivKey); signErr != nil {
					app.Logger().Error("Failed to re-sign vote extension after trimming", "error", signErr)
					return &abci.ResponseExtendVote{VoteExtension: nil}, nil
				}
			} else {
				// EV-08: Clear stale signature when privKey is nil (permissive mode).
				// Without this, the hash/signature would be inconsistent with the
				// trimmed content.
				voteExt.Signature = nil
			}
			var marshalErr error
			extBytes, marshalErr = voteExt.Marshal()
			if marshalErr != nil {
				// EV-09: Marshal errors are handled explicitly - never ignored.
				app.Logger().Error("Failed to marshal vote extension after trimming", "error", marshalErr)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
		}

		if originalCount != len(voteExt.Verifications) {
			app.Logger().Warn("Vote extension trimmed to satisfy size limit",
				"original", originalCount,
				"final", len(voteExt.Verifications),
				"size_bytes", len(extBytes),
			)
		}

		if len(extBytes) > MaxVoteExtensionSizeBytes {
			app.Logger().Error("Vote extension exceeds size limit after trimming",
				"size_bytes", len(extBytes),
			)
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}

		app.Logger().Info("Vote extension created",
			"num_verifications", len(voteExt.Verifications),
			"extension_size", len(extBytes),
		)

		// CometBFT does not invoke VerifyVoteExtension for the local
		// validator's own vote. Cache the final post-trimming bytes here so
		// ProcessProposal can reconstruct the complete verified quorum.
		if app.voteExtensionCache != nil {
			app.voteExtensionCache.Store(req.Height, validatorAddr, extBytes)
		}

		return &abci.ResponseExtendVote{
			VoteExtension: extBytes,
		}, nil
	}
}

// VerifyVoteExtensionHandler returns the ABCI++ VerifyVoteExtension handler.
// This validates that vote extensions from other validators are well-formed
// and contain valid verification data.
//
// In production mode (AllowSimulated=false on either x/pouw or x/verify params):
//   - Unsigned extensions are REJECTED
//   - Simulated TEE platforms are REJECTED
//   - Extension hash MUST be present
//
// In dev mode (AllowSimulated=true): permissive validation is used.
//
// CRITICAL: This handler includes panic recovery. A panic during verification
// results in REJECT to maintain safety without crashing the node.
func (app *AethelredApp) VerifyVoteExtensionHandler() sdk.VerifyVoteExtensionHandler {
	return func(ctx sdk.Context, req *abci.RequestVerifyVoteExtension) (resp *abci.ResponseVerifyVoteExtension, err error) {
		// CRITICAL: Panic recovery for consensus safety
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in VerifyVoteExtensionHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// REJECT on panic - safer than accepting potentially malformed data
				if metrics := app.PouwKeeper.Metrics(); metrics != nil {
					metrics.VoteExtensionsRejected.Inc()
				}
				resp = &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}
				err = nil
			}
		}()

		// Empty extensions are always valid (no jobs to verify)
		if len(req.VoteExtension) == 0 {
			if app.voteExtensionCache != nil && len(req.ValidatorAddress) > 0 {
				app.voteExtensionCache.Store(req.Height, req.ValidatorAddress, []byte{})
			}
			return &abci.ResponseVerifyVoteExtension{
				Status: abci.ResponseVerifyVoteExtension_ACCEPT,
			}, nil
		}

		if len(req.VoteExtension) > MaxVoteExtensionSizeBytes {
			app.Logger().Error("Vote extension too large",
				"size_bytes", len(req.VoteExtension),
			)
			return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}, nil
		}

		metrics := app.PouwKeeper.Metrics()
		if metrics != nil {
			metrics.VoteExtensionsProcessed.Inc()
		}
		reject := func() *abci.ResponseVerifyVoteExtension {
			if metrics != nil {
				metrics.VoteExtensionsRejected.Inc()
			}
			return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}
		}

		// Determine validation mode based on module params.
		// If EITHER x/pouw or x/verify has AllowSimulated=false, use strict mode.
		validationMode := app.voteExtensionValidationMode(ctx)

		// Parse the vote extension
		voteExt, err := UnmarshalVoteExtension(req.VoteExtension)
		if err != nil {
			app.Logger().Error("Failed to unmarshal vote extension", "error", err)
			return reject(), nil
		}

		if len(voteExt.Verifications) > MaxVerificationsPerExtension {
			app.Logger().Error("Vote extension exceeds max verifications",
				"count", len(voteExt.Verifications),
			)
			return reject(), nil
		}

		if voteExt.Height != req.Height {
			app.Logger().Error("Vote extension height mismatch",
				"request_height", req.Height,
				"extension_height", voteExt.Height,
			)
			return reject(), nil
		}
		if voteExt.ChainID != ctx.ChainID() || voteExt.ChainID == "" {
			app.Logger().Error("Vote extension chain ID mismatch",
				"request_chain_id", ctx.ChainID(),
				"extension_chain_id", voteExt.ChainID,
			)
			return reject(), nil
		}
		if validationMode == ValidationModeStrict {
			if len(req.Hash) != 32 {
				app.Logger().Error("Vote-extension request has an invalid proposal hash length")
				return reject(), nil
			}
			if len(voteExt.Nonce) != 32 {
				app.Logger().Error("Vote extension has an invalid extension nonce length")
				return reject(), nil
			}
		}

		if !bytes.Equal(voteExt.ValidatorAddress, req.ValidatorAddress) {
			app.Logger().Error("Vote extension validator identity mismatch",
				"request_validator_address", fmt.Sprintf("%X", req.ValidatorAddress),
				"extension_validator_address", fmt.Sprintf("%X", voteExt.ValidatorAddress),
			)
			return reject(), nil
		}

		// Validate the vote extension using mode-appropriate validation.
		// Strict mode rejects unsigned extensions, simulated TEE, missing hashes.
		// RequestVerifyVoteExtension does not expose the current proposal time.
		// Validating against the prior persisted block time creates a permanent
		// liveness failure after downtime. Height/hash/chain are authenticated
		// here; freshness is checked deterministically against the committed
		// block time when the compact evidence is proposed as a seal.
		now := time.Time{}
		maxPastSkew, maxFutureSkew := app.voteExtensionTimeBounds(ctx)
		if validationMode == ValidationModeStrict {
			if err := voteExt.validateAtWithWindow(validationMode, now, maxPastSkew, maxFutureSkew); err != nil {
				app.Logger().Error("Vote extension strict validation failed",
					"error", err,
					"mode", "production",
				)
				return reject(), nil
			}
			if err := voteExt.validateAttestationDomain(ctx.ChainID()); err != nil {
				app.Logger().Error("Vote extension attestation domain validation failed", "error", err)
				return reject(), nil
			}
		} else {
			if err := voteExt.validateAtWithWindow(validationMode, now, maxPastSkew, maxFutureSkew); err != nil {
				app.Logger().Error("Vote extension validation failed", "error", err)
				return reject(), nil
			}
		}

		// Strict boundary check: validate TEE quote schema at ABCI layer before aggregation.
		if validationMode == ValidationModeStrict {
			if err := app.validateVoteExtensionTEESchemas(voteExt); err != nil {
				app.Logger().Error("Vote extension TEE schema validation failed", "error", err)
				return reject(), nil
			}
		}

		seenJobs := make(map[string]struct{}, len(voteExt.Verifications))
		validatorAccountAddress := ""
		for i := range voteExt.Verifications {
			verification := &voteExt.Verifications[i]
			if _, duplicate := seenJobs[verification.JobID]; duplicate {
				app.Logger().Error("Duplicate job in vote extension", "job_id", verification.JobID)
				return reject(), nil
			}
			seenJobs[verification.JobID] = struct{}{}
			if !verification.Success {
				continue
			}
			if verification.ValidatorSignatureVersion != ComputeVerificationSignatureVersion {
				app.Logger().Error(
					"Vote verification has an unsupported compact signature version",
					"index", i,
					"version", verification.ValidatorSignatureVersion,
				)
				return reject(), nil
			}
			if !bytes.Equal(verification.VoteBlockHash, req.Hash) {
				app.Logger().Error(
					"Vote verification proposal hash mismatch",
					"index", i,
					"job_id", verification.JobID,
				)
				return reject(), nil
			}
			if !bytes.Equal(verification.ExtensionNonce, voteExt.Nonce) {
				app.Logger().Error(
					"Vote verification extension nonce mismatch",
					"index", i,
					"job_id", verification.JobID,
				)
				return reject(), nil
			}

			job, err := app.PouwKeeper.GetJob(ctx, verification.JobID)
			if err != nil {
				app.Logger().Error("Vote extension references unknown job",
					"index", i,
					"job_id", verification.JobID,
				)
				return reject(), nil
			}
			if job.Status != pouwtypes.JobStatusProcessing {
				app.Logger().Error("Vote extension references ineligible job",
					"index", i,
					"job_id", verification.JobID,
					"status", job.Status.String(),
				)
				return reject(), nil
			}
			if validatorAccountAddress == "" {
				validatorAccountAddress, err = app.validatorAccountAddress(
					ctx,
					voteExt.ValidatorAddress,
				)
				if err != nil {
					app.Logger().Error(
						"Cannot map vote-extension signer to validator account",
						"error", err,
					)
					return reject(), nil
				}
			}
			assigned, err := pouwkeeper.IsValidatorAssigned(job, validatorAccountAddress)
			if err != nil || !assigned {
				app.Logger().Error(
					"Validator is not assigned to vote-extension job",
					"index", i,
					"job_id", verification.JobID,
					"validator", validatorAccountAddress,
					"error", err,
				)
				return reject(), nil
			}
			if !bytes.Equal(job.ModelHash, verification.ModelHash) ||
				!bytes.Equal(job.InputHash, verification.InputHash) {
				app.Logger().Error("Vote extension hashes do not match canonical job",
					"index", i,
					"job_id", verification.JobID,
				)
				return reject(), nil
			}
		}

		// Verify signature on vote extension using validator's ed25519 public key.
		// In strict mode, the signature is guaranteed present by ValidateStrict().
		// In permissive mode, we still verify if a signature IS provided.
		if len(voteExt.Signature) > 0 {
			// Look up validator public key from staking keeper via consensus address
			consAddr := sdk.ConsAddress(voteExt.ValidatorAddress)
			validator, err := app.validatorByConsensusAddress(ctx, consAddr)
			if err != nil {
				app.Logger().Error("Unknown validator in vote extension",
					"cons_addr", consAddr.String(),
				)
				return reject(), nil
			}

			// Get the validator's consensus public key
			pubKey, err := validator.ConsPubKey()
			if err != nil {
				app.Logger().Error("Failed to get validator public key", "error", err)
				return reject(), nil
			}

			// Verify ed25519 signature
			if !VerifyVoteExtensionSignature(voteExt, pubKey.Bytes()) {
				app.Logger().Error("Vote extension signature verification failed",
					"validator", consAddr.String(),
				)
				return reject(), nil
			}
			for i := range voteExt.Verifications {
				verification := voteExt.Verifications[i]
				if !verification.Success {
					continue
				}
				if len(verification.ValidatorSignature) == 0 {
					if validationMode == ValidationModeStrict {
						app.Logger().Error(
							"Successful verification is missing its compact validator signature",
							"index", i,
							"job_id", verification.JobID,
						)
						return reject(), nil
					}
					continue
				}
				if !verifyComputeVerificationSignature(
					verification,
					voteExt.Height,
					voteExt.ChainID,
					voteExt.ValidatorAddress,
					voteExt.Timestamp,
					ed25519.PublicKey(pubKey.Bytes()),
				) {
					app.Logger().Error(
						"Compute verification signature verification failed",
						"index", i,
						"job_id", verification.JobID,
					)
					return reject(), nil
				}
			}
		} else if validationMode == ValidationModeStrict {
			app.Logger().Error("SECURITY: unsigned vote extension rejected in strict mode")
			return reject(), nil
		}

		if app.voteExtensionCache != nil {
			app.voteExtensionCache.Store(req.Height, req.ValidatorAddress, req.VoteExtension)
		}

		return &abci.ResponseVerifyVoteExtension{
			Status: abci.ResponseVerifyVoteExtension_ACCEPT,
		}, nil
	}
}

// PrepareProposalHandler returns the ABCI++ PrepareProposal handler.
// This aggregates vote extensions from validators and includes verified
// computation results in the block proposal.
//
// CRITICAL: This handler includes panic recovery. A panic during proposal
// preparation results in returning the original transactions without any
// injected seal transactions.
func (app *AethelredApp) PrepareProposalHandler() sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestPrepareProposal) (resp *abci.ResponsePrepareProposal, err error) {
		// CRITICAL: Panic recovery for consensus safety
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in PrepareProposalHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// Return original transactions on panic - block can still be proposed
				resp = &abci.ResponsePrepareProposal{Txs: req.Txs}
				err = nil
			}
		}()

		app.Logger().Info("PrepareProposal called",
			"height", req.Height,
			"num_local_votes", len(req.LocalLastCommit.Votes),
		)

		// Process encrypted mempool transactions: decrypt eligible transactions
		// before proposal assembly to prevent front-running and censorship.
		mempoolTxs := req.Txs
		if app.encryptedMempoolBridge != nil {
			mempoolTxs = app.encryptedMempoolBridge.ProcessProposalTxs(ctx, req)
		}

		sealTxs := make([][]byte, 0)

		if app.consensusHandler != nil {
			expectedVoteBlockHash, bindingFound, bindingErr :=
				app.previousFinalizedBlockHash(ctx, req.Height)
			if bindingErr != nil {
				return nil, fmt.Errorf(
					"load prior finalized block binding at height %d: %w",
					req.Height,
					bindingErr,
				)
			}
			if !bindingFound {
				// Seal certificates are optional. On the first height after
				// this state binding is introduced there is no prior record
				// yet, so omit seals and let FinalizeBlock bootstrap it.
				app.Logger().Info(
					"Skipping seal transactions while bootstrapping finalized block binding",
					"height", req.Height,
				)
			} else {
				// PP-08: Canonical consensus pipeline uses
				// req.LocalLastCommit.Votes (the consensus-provided input), NOT
				// the local vote extension cache.
				results := app.consensusHandler.AggregateVoteExtensions(
					ctx,
					req.LocalLastCommit.Votes,
				)
				for jobID, result := range results {
					if !aggregatedResultBindsToFinalizedBlock(
						result,
						expectedVoteBlockHash,
					) {
						app.Logger().Warn(
							"Skipping seal evidence not bound to the finalized block",
							"height", req.Height,
							"job_id", jobID,
						)
						delete(results, jobID)
					}
				}
				sealTxs = app.consensusHandler.CreateSealTransactions(ctx, results)
			}
		} else {
			// Legacy fallback (dev/test only).
			var extensions []VoteExtensionWithPower
			for _, vote := range req.LocalLastCommit.Votes {
				if len(vote.VoteExtension) == 0 {
					continue
				}
				ext, err := UnmarshalVoteExtension(vote.VoteExtension)
				if err != nil {
					app.Logger().Warn("Failed to unmarshal vote extension in PrepareProposal", "error", err)
					continue
				}
				extensions = append(extensions, VoteExtensionWithPower{
					Extension: ext,
					Power:     vote.Validator.Power,
				})
			}

			consensusThreshold := app.getConsensusThreshold(ctx)
			allowSimulated := app.allowSimulated(ctx)
			aggregatedResults := AggregateVoteExtensions(ctx, extensions, consensusThreshold, allowSimulated)
			for _, agg := range aggregatedResults {
				if !agg.HasConsensus {
					continue
				}
				injectedTx := NewInjectedVoteExtensionTx(agg, req.Height)
				txBytes, err := injectedTx.Marshal()
				if err != nil {
					app.Logger().Error("Failed to marshal injected tx", "error", err)
					continue
				}
				sealTxs = append(sealTxs, txBytes)
			}
		}

		return &abci.ResponsePrepareProposal{
			Txs: packProposalTransactions(sealTxs, mempoolTxs, req.MaxTxBytes),
		}, nil
	}
}

// packProposalTransactions deterministically prioritizes canonical consensus
// seals, then preserves mempool order within both the ABCI MaxTxBytes limit and
// the application proof/count limits. Seals that do not fit are deferred to a
// later height; a proposer must never construct a block its own validator
// rejects.
func packProposalTransactions(sealTxs, mempoolTxs [][]byte, maxTxBytes int64) [][]byte {
	totalLimit := int64(math.MaxInt64)
	if maxTxBytes >= 0 {
		totalLimit = maxTxBytes
	}
	proposal := make([][]byte, 0, len(sealTxs)+len(mempoolTxs))
	totalBytes := int64(0)
	injectedBytes := int64(0)
	injectedCount := 0

	for _, txBytes := range sealTxs {
		txSize := int64(len(txBytes))
		if injectedCount >= maxInjectedSealTxsPerBlock ||
			injectedBytes+txSize > int64(maxInjectedProofBytes) ||
			totalBytes+txSize > totalLimit {
			continue
		}
		proposal = append(proposal, txBytes)
		totalBytes += txSize
		injectedBytes += txSize
		injectedCount++
	}
	for _, txBytes := range mempoolTxs {
		txSize := int64(len(txBytes))
		if totalBytes+txSize > totalLimit {
			continue
		}
		proposal = append(proposal, txBytes)
		totalBytes += txSize
	}
	return proposal
}

// ProcessProposalHandler returns the ABCI++ ProcessProposal handler.
// This validates that the proposed block contains valid verification results
// with sufficient validator agreement.
//
// CRITICAL: This handler includes panic recovery. A panic during proposal
// processing results in REJECT to prevent potentially invalid blocks from
// being accepted.
func (app *AethelredApp) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (resp *abci.ResponseProcessProposal, err error) {
		// CRITICAL: Panic recovery for consensus safety
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in ProcessProposalHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// REJECT on panic - safer than accepting potentially invalid proposal
				resp = &abci.ResponseProcessProposal{
					Status: abci.ResponseProcessProposal_REJECT,
				}
				err = nil
			}
		}()

		app.Logger().Info("ProcessProposal called",
			"height", req.Height,
			"num_txs", len(req.Txs),
		)

		// PR-10: Use IsProductionBuild() as primary guard, then fall back to
		// param-based check. This prevents governance attacks from disabling
		// production mode via AllowSimulated param changes.
		isProductionCtx := IsProductionBuild() || !app.allowSimulated(ctx)
		if isProductionCtx {
			if app.consensusHandler == nil {
				app.Logger().Error("SECURITY: consensus handler not configured in production mode")
				return &abci.ResponseProcessProposal{
					Status: abci.ResponseProcessProposal_REJECT,
				}, nil
			}
		}
		consensusThreshold := app.getConsensusThreshold(ctx)
		audit := AuditProposalConsensusEvidence(req.Txs, req.ProposedLastCommit, consensusThreshold)
		if !audit.Passed() {
			app.Logger().Error("Injected consensus evidence audit failed", "error", audit.Error())
			return &abci.ResponseProcessProposal{
				Status: abci.ResponseProcessProposal_REJECT,
			}, nil
		}

		// ── PR-02 / PR-17 / H-4: Hard caps before heavy verification work ──
		// Enforce per-block quotas on injected transactions and total proof bytes
		// to prevent a malicious proposer from flooding ProcessProposal with
		// expensive-to-verify payloads.
		injectedCount := 0
		injectedProofBytes := 0
		for _, txBytes := range req.Txs {
			if IsInjectedVoteExtensionTx(txBytes) {
				injectedCount++
				injectedProofBytes += len(txBytes)
			}
		}
		if injectedCount > maxInjectedSealTxsPerBlock {
			app.Logger().Error("Block exceeds max injected tx quota (H-4/PR-17)",
				"injected", injectedCount, "max", maxInjectedSealTxsPerBlock)
			return &abci.ResponseProcessProposal{
				Status: abci.ResponseProcessProposal_REJECT,
			}, nil
		}
		if injectedProofBytes > maxInjectedProofBytes {
			app.Logger().Error("Block exceeds max total proof bytes (H-4/PR-02)",
				"bytes", injectedProofBytes, "max", maxInjectedProofBytes)
			return &abci.ResponseProcessProposal{
				Status: abci.ResponseProcessProposal_REJECT,
			}, nil
		}

		expectedVoteBlockHash, bindingFound, bindingErr :=
			app.previousFinalizedBlockHash(ctx, req.Height)
		if bindingErr != nil {
			app.Logger().Error(
				"Invalid prior finalized block binding",
				"height", req.Height,
				"error", bindingErr,
			)
			return &abci.ResponseProcessProposal{
				Status: abci.ResponseProcessProposal_REJECT,
			}, nil
		}
		if injectedCount > 0 && !bindingFound {
			app.Logger().Error(
				"Injected seal lacks a prior finalized block binding",
				"height", req.Height,
			)
			return &abci.ResponseProcessProposal{
				Status: abci.ResponseProcessProposal_REJECT,
			}, nil
		}

		// Validate all transactions in the proposal
		for _, txBytes := range req.Txs {
			// Check if this is an injected vote extension transaction
			if IsInjectedVoteExtensionTx(txBytes) {
				// Prefer keeper-based validation to avoid pipeline divergence.
				if app.consensusHandler != nil {
					if err := app.consensusHandler.ValidateSealTransaction(ctx, txBytes); err != nil {
						app.Logger().Error("Injected tx validation failed", "error", err)
						return &abci.ResponseProcessProposal{
							Status: abci.ResponseProcessProposal_REJECT,
						}, nil
					}
					if err := app.validateSelfContainedSealEvidence(
						ctx,
						txBytes,
						req.ProposedLastCommit,
						expectedVoteBlockHash,
					); err != nil {
						app.Logger().Error(
							"Self-contained seal evidence validation failed",
							"error", err,
						)
						return &abci.ResponseProcessProposal{
							Status: abci.ResponseProcessProposal_REJECT,
						}, nil
					}
					continue
				}

				tx, err := UnmarshalInjectedVoteExtensionTx(txBytes)
				if err != nil {
					app.Logger().Error("Invalid injected tx in proposal", "error", err)
					return &abci.ResponseProcessProposal{
						Status: abci.ResponseProcessProposal_REJECT,
					}, nil
				}

				if err := app.validateInjectedTx(ctx, tx); err != nil {
					app.Logger().Error("Injected tx validation failed", "error", err)
					return &abci.ResponseProcessProposal{
						Status: abci.ResponseProcessProposal_REJECT,
					}, nil
				}
			}
		}

		return &abci.ResponseProcessProposal{
			Status: abci.ResponseProcessProposal_ACCEPT,
		}, nil
	}
}

// validateInjectedTx validates an injected vote extension transaction
func (app *AethelredApp) validateInjectedTx(ctx sdk.Context, tx *InjectedVoteExtensionTx) error {
	if err := validateInjectedConsensusTxFormat(tx); err != nil {
		return err
	}

	// Validate job exists
	job, err := app.PouwKeeper.GetJob(ctx, tx.JobID)
	if err != nil {
		return fmt.Errorf("job not found: %s", tx.JobID)
	}

	// Validate that consensus threshold was met
	// Get threshold from on-chain params (BFT-safe, minimum 67%)
	consensusThreshold := app.getConsensusThreshold(ctx)
	if err := validateConsensusEvidenceThreshold(
		tx.ValidatorCount,
		tx.TotalVotes,
		tx.AgreementPower,
		tx.TotalPower,
		consensusThreshold,
		app.allowSimulated(ctx),
	); err != nil {
		return err
	}

	_ = job // used for validation above
	return nil
}

// getConsensusThreshold returns the consensus threshold from on-chain params.
// This ensures the threshold is always read from governance params rather than
// a hardcoded value, while maintaining BFT safety with a minimum of 67%.
func (app *AethelredApp) getConsensusThreshold(ctx sdk.Context) int {
	params, err := app.PouwKeeper.GetParams(ctx)
	if err == nil && params != nil && params.ConsensusThreshold >= 67 {
		return int(params.ConsensusThreshold)
	}
	// Default to BFT-safe 67% if params unavailable or invalid
	return 67
}

// allowSimulated returns true ONLY if both:
//  1. The binary was NOT compiled with -tags production (VV-04/PR-10), AND
//  2. The x/pouw module param AllowSimulated is explicitly true.
//
// In production builds, this always returns false regardless of on-chain params,
// preventing governance attacks that attempt to toggle simulated mode.
func (app *AethelredApp) allowSimulated(ctx sdk.Context) bool {
	// ── VV-04/PR-10: Compile-time override - production builds NEVER allow simulated ──
	if IsProductionBuild() {
		return false
	}

	params, err := app.PouwKeeper.GetParams(ctx)
	if err != nil || params == nil {
		return false
	}
	return params.AllowSimulated
}

// verifyAllowSimulated returns true ONLY if both:
//  1. The binary was NOT compiled with -tags production, AND
//  2. The x/verify module param AllowSimulated is explicitly true.
func (app *AethelredApp) verifyAllowSimulated(ctx sdk.Context) bool {
	// ── VV-04/PR-10: Compile-time override ──
	if IsProductionBuild() {
		return false
	}

	defer func() {
		_ = recover() // Fail closed on panic.
	}()

	params, err := app.VerifyKeeper.GetParams(ctx)
	if err != nil || params == nil {
		return false
	}
	return params.AllowSimulated
}

// voteExtensionValidationMode determines whether to use strict or permissive
// validation for vote extensions.
//
// VV-04: In production builds (compiled with -tags production), this always
// returns ValidationModeStrict regardless of module parameters. This prevents
// governance-based attacks that attempt to weaken validation via param changes.
//
// In dev builds, strict mode is used if EITHER x/pouw or x/verify has
// AllowSimulated=false (conservative OR logic).
func (app *AethelredApp) voteExtensionValidationMode(ctx sdk.Context) ValidationMode {
	// Production builds always use strict mode.
	if IsProductionBuild() {
		return ValidationModeStrict
	}

	if !app.allowSimulated(ctx) || !app.verifyAllowSimulated(ctx) {
		return ValidationModeStrict
	}
	return ValidationModePermissive
}

func (app *AethelredApp) validateVoteExtensionTEESchemas(ve *VoteExtension) error {
	if ve == nil {
		return fmt.Errorf("vote extension is nil")
	}
	for i := range ve.Verifications {
		ver := ve.Verifications[i]
		if ver.AttestationType != AttestationTypeTEE && ver.AttestationType != AttestationTypeHybrid {
			continue
		}
		if ver.TEEAttestation == nil {
			return fmt.Errorf("verification %d missing TEE attestation", i)
		}
		if err := validateTEEQuoteSchema(ver.TEEAttestation); err != nil {
			return fmt.Errorf("verification %d: %w", i, err)
		}
	}
	return nil
}

// generateNonce creates a cryptographic nonce for replay protection
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := cryptoRand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}
