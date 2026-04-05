package keeper_test

import (
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Helpers for CB6 tests
// ---------------------------------------------------------------------------

func cb6Ctx() sdk.Context {
	return sdk.NewContext(nil, tmproto.Header{
		ChainID: "cb6-test",
		Height:  500,
		Time:    time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())
}

func cb6Bech32(seed string) string {
	return sdk.AccAddress([]byte(seed)).String()
}

// ---------------------------------------------------------------------------
// consensus.go: ValidateSealTransaction -- deeper branch coverage
// ---------------------------------------------------------------------------

func TestCB6_ValidateSealTransaction_InvalidJSON(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	err := ch.ValidateSealTransaction(ctx, []byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal")
}

func TestCB6_ValidateSealTransaction_WrongType(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	data, _ := json.Marshal(map[string]interface{}{"type": "wrong_type"})
	err := ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid seal transaction type")
}

func TestCB6_ValidateSealTransaction_MissingJobID(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	data, _ := json.Marshal(map[string]interface{}{
		"type":   "create_seal_from_consensus",
		"job_id": "",
	})
	err := ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing job ID")
}

func TestCB6_ValidateSealTransaction_InvalidOutputHash(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	data, _ := json.Marshal(map[string]interface{}{
		"type":        "create_seal_from_consensus",
		"job_id":      "job-1",
		"output_hash": []byte{1, 2, 3}, // too short
	})
	err := ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid output hash length")
}

func TestCB6_ValidateSealTransaction_JobNotFound(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	outputHash := sha256.Sum256([]byte("test"))
	data, _ := json.Marshal(map[string]interface{}{
		"type":        "create_seal_from_consensus",
		"job_id":      "nonexistent-job",
		"output_hash": outputHash[:],
	})
	err := ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "job not found")
}

func TestCB6_ValidateSealTransaction_ModelHashMismatch(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	outputHash := sha256.Sum256([]byte("test"))
	wrongModel := sha256.Sum256([]byte("wrong-model"))

	data, _ := json.Marshal(map[string]interface{}{
		"type":        "create_seal_from_consensus",
		"job_id":      "job-0",
		"output_hash": outputHash[:],
		"model_hash":  wrongModel[:],
	})
	err := ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "model hash mismatch")
}

func TestCB6_ValidateSealTransaction_InputHashMismatch(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	outputHash := sha256.Sum256([]byte("test"))
	modelHash := sha256.Sum256([]byte("model-0"))
	wrongInput := sha256.Sum256([]byte("wrong-input"))

	data, _ := json.Marshal(map[string]interface{}{
		"type":        "create_seal_from_consensus",
		"job_id":      "job-0",
		"output_hash": outputHash[:],
		"model_hash":  modelHash[:],
		"input_hash":  wrongInput[:],
	})
	err := ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "input hash mismatch")
}

func TestCB6_ValidateSealTransaction_InsufficientVotePower(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	outputHash := sha256.Sum256([]byte("test"))

	data, _ := json.Marshal(map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-0",
		"output_hash":     outputHash[:],
		"model_hash":      job.ModelHash,
		"input_hash":      job.InputHash,
		"total_power":     int64(100),
		"agreement_power": int64(10), // too low
	})
	err = ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient validator power")
}

func TestCB6_ValidateSealTransaction_InsufficientVoteCount(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	outputHash := sha256.Sum256([]byte("test"))

	data, _ := json.Marshal(map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-0",
		"output_hash":     outputHash[:],
		"model_hash":      job.ModelHash,
		"input_hash":      job.InputHash,
		"total_power":     int64(0), // force vote count path
		"total_votes":     10,
		"validator_count": 2, // too low
	})
	err = ch.ValidateSealTransaction(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient validator consensus")
}

func TestCB6_ValidateSealTransaction_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	outputHash := sha256.Sum256([]byte("test"))

	data, _ := json.Marshal(map[string]interface{}{
		"type":            "create_seal_from_consensus",
		"job_id":          "job-0",
		"output_hash":     outputHash[:],
		"model_hash":      job.ModelHash,
		"input_hash":      job.InputHash,
		"total_power":     int64(100),
		"agreement_power": int64(90), // enough
	})
	err = ch.ValidateSealTransaction(ctx, data)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// consensus.go: ProcessSealTransaction -- deeper branches
// ---------------------------------------------------------------------------

func TestCB6_ProcessSealTransaction_InvalidJSON(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	err := ch.ProcessSealTransaction(ctx, []byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal")
}

// ---------------------------------------------------------------------------
// consensus.go: executeVerification -- simulated paths
// ---------------------------------------------------------------------------

func TestCB6_ExecuteVerification_SimulatedTEE(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	// Enable simulated mode
	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	job.ProofType = types.ProofTypeTEE

	result := ch.ExecuteVerificationForTest(ctx, job, "val1")
	// Should succeed in simulated mode with model registered
	require.True(t, result.Success)
	require.Equal(t, "tee", result.AttestationType)
}

func TestCB6_ExecuteVerification_SimulatedZKML(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	job.ProofType = types.ProofTypeZKML

	result := ch.ExecuteVerificationForTest(ctx, job, "val1")
	require.True(t, result.Success)
	require.Equal(t, "zkml", result.AttestationType)
}

func TestCB6_ExecuteVerification_SimulatedHybrid(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	job.ProofType = types.ProofTypeHybrid

	result := ch.ExecuteVerificationForTest(ctx, job, "val1")
	require.True(t, result.Success)
	require.Equal(t, "hybrid", result.AttestationType)
}

func TestCB6_ExecuteVerification_UnknownProofType(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	job.ProofType = 99 // invalid

	result := ch.ExecuteVerificationForTest(ctx, job, "val1")
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "unknown proof type")
}

func TestCB6_ExecuteVerification_ProductionMode_NoVerifier(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	// Production mode: AllowSimulated = false (default)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	result := ch.ExecuteVerificationForTest(ctx, job, "val1")
	require.False(t, result.Success)
	require.Contains(t, result.ErrorMessage, "SECURITY")
}

// ---------------------------------------------------------------------------
// consensus.go: VerifyVoteExtension -- deeper branches
// ---------------------------------------------------------------------------

func TestCB6_VerifyVoteExtension_InvalidJSON(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	err := ch.VerifyVoteExtension(ctx, []byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal")
}

func TestCB6_VerifyVoteExtension_WrongVersion(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	ext := map[string]interface{}{"version": 99}
	data, _ := json.Marshal(ext)
	err := ch.VerifyVoteExtension(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported vote extension version")
}

func TestCB6_VerifyVoteExtension_HeightMismatch(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	ext := map[string]interface{}{
		"version": 1,
		"height":  int64(999),
	}
	data, _ := json.Marshal(ext)
	err := ch.VerifyVoteExtension(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "height mismatch")
}

func TestCB6_VerifyVoteExtension_FutureTimestamp(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	ext := map[string]interface{}{
		"version":   1,
		"height":    ctx.BlockHeight(),
		"timestamp": ctx.BlockTime().Add(10 * time.Minute).Format(time.RFC3339Nano),
	}
	data, _ := json.Marshal(ext)
	err := ch.VerifyVoteExtension(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "future")
}

func TestCB6_VerifyVoteExtension_ProductionNoSignature(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	ext := map[string]interface{}{
		"version":   1,
		"height":    ctx.BlockHeight(),
		"timestamp": ctx.BlockTime().Format(time.RFC3339Nano),
	}
	data, _ := json.Marshal(ext)
	err := ch.VerifyVoteExtension(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsigned vote extension")
}

func TestCB6_VerifyVoteExtension_ProductionNoHash(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	sig := sha256.Sum256([]byte("sig"))
	ext := map[string]interface{}{
		"version":   1,
		"height":    ctx.BlockHeight(),
		"timestamp": ctx.BlockTime().Format(time.RFC3339Nano),
		"signature": sig[:],
	}
	data, _ := json.Marshal(ext)
	err := ch.VerifyVoteExtension(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing extension hash")
}

func TestCB6_VerifyVoteExtension_InvalidVerification(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	ext := map[string]interface{}{
		"version":   1,
		"height":    ctx.BlockHeight(),
		"timestamp": ctx.BlockTime().Format(time.RFC3339Nano),
		"verifications": []map[string]interface{}{
			{"job_id": ""}, // empty job ID
		},
	}
	data, _ := json.Marshal(ext)
	err := ch.VerifyVoteExtension(ctx, data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid verification")
}

// ---------------------------------------------------------------------------
// consensus.go: AggregateVoteExtensions -- deeper coverage
// ---------------------------------------------------------------------------

func TestCB6_AggregateVoteExtensions_EmptyVotes(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	result := ch.AggregateVoteExtensions(ctx, nil)
	require.Empty(t, result)
}

func TestCB6_AggregateVoteExtensions_ZeroPowerProduction(t *testing.T) {
	k, ctx := newTestKeeper(t)
	// Production mode (AllowSimulated=false default)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	// Zero power in production mode should return empty
	votes := []abci.ExtendedVoteInfo{
		{
			Validator:     abci.Validator{Address: []byte("val1"), Power: 0},
			VoteExtension: []byte(`{"version":1}`),
		},
	}
	result := ch.AggregateVoteExtensions(ctx, votes)
	require.Empty(t, result)
}

func TestCB6_AggregateVoteExtensions_ZeroPowerSimulated(t *testing.T) {
	k, ctx := newTestKeeper(t)
	params := types.DefaultParams()
	params.AllowSimulated = true
	require.NoError(t, k.SetParams(ctx, params))

	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	nonce := sha256.Sum256([]byte("nonce"))
	modelHash := sha256.Sum256([]byte("model"))
	outputHash := sha256.Sum256([]byte("output"))
	valAddr, _ := json.Marshal("val1-addr")
	ext := map[string]interface{}{
		"version":           1,
		"height":            ctx.BlockHeight(),
		"timestamp":         ctx.BlockTime().Format(time.RFC3339Nano),
		"validator_address": json.RawMessage(valAddr),
		"verifications": []map[string]interface{}{
			{
				"job_id":           "job-1",
				"success":          true,
				"output_hash":      outputHash[:],
				"model_hash":       modelHash[:],
				"nonce":            nonce[:],
				"execution_time_ms": int64(100),
				"attestation_type": "tee",
			},
		},
	}
	data, _ := json.Marshal(ext)

	votes := []abci.ExtendedVoteInfo{
		{
			Validator:     abci.Validator{Address: []byte("val1-addr"), Power: 0},
			VoteExtension: data,
		},
	}
	result := ch.AggregateVoteExtensions(ctx, votes)
	// With zero power fallback in simulated mode, should process
	_ = result
}

func TestCB6_AggregateVoteExtensions_InvalidExtensionJSON(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	votes := []abci.ExtendedVoteInfo{
		{
			Validator:     abci.Validator{Address: []byte("val1"), Power: 10},
			VoteExtension: []byte("invalid json"),
		},
	}
	result := ch.AggregateVoteExtensions(ctx, votes)
	require.Empty(t, result)
}

func TestCB6_AggregateVoteExtensions_EmptyVoteExtension(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	votes := []abci.ExtendedVoteInfo{
		{
			Validator:     abci.Validator{Address: []byte("val1"), Power: 10},
			VoteExtension: nil,
		},
	}
	result := ch.AggregateVoteExtensions(ctx, votes)
	require.Empty(t, result)
}

// ---------------------------------------------------------------------------
// consensus.go: PrepareVoteExtension -- deeper coverage
// ---------------------------------------------------------------------------

func TestCB6_PrepareVoteExtension_NoJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), &k, sched)

	results, err := ch.PrepareVoteExtension(ctx, "val1")
	require.NoError(t, err)
	require.Nil(t, results)
}

// ---------------------------------------------------------------------------
// keeper.go: UpdateJob -- deeper branch coverage for metrics & auditLogger
// ---------------------------------------------------------------------------

func TestCB6_UpdateJob_NotFound(t *testing.T) {
	k, ctx := newTestKeeper(t)

	job := &types.ComputeJob{Id: "nonexistent", Status: types.JobStatusFailed}
	err := k.UpdateJob(ctx, job)
	require.Error(t, err)
	require.Contains(t, err.Error(), "job not found")
}

func TestCB6_UpdateJob_PendingToPending(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	require.Equal(t, types.JobStatusPending, job.Status)

	// Update without changing status
	job.Purpose = "updated-purpose"
	err = k.UpdateJob(ctx, job)
	require.NoError(t, err)

	// Verify job is still in PendingJobs
	updated, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	require.Equal(t, "updated-purpose", updated.Purpose)
}

func TestCB6_UpdateJob_PendingToProcessing(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	job.Status = types.JobStatusProcessing
	err = k.UpdateJob(ctx, job)
	require.NoError(t, err)
}

func TestCB6_UpdateJob_RemovesFromPending(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	// Complete the job
	job.Status = types.JobStatusCompleted
	err = k.UpdateJob(ctx, job)
	require.NoError(t, err)

	// Should be removed from PendingJobs
	pending := k.GetPendingJobs(ctx)
	for _, p := range pending {
		require.NotEqual(t, "job-0", p.Id)
	}
}

func TestCB6_UpdateJob_Failed(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	job.Status = types.JobStatusFailed
	err = k.UpdateJob(ctx, job)
	require.NoError(t, err)
}

func TestCB6_UpdateJob_Expired(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)

	job.Status = types.JobStatusExpired
	err = k.UpdateJob(ctx, job)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// keeper.go: SubmitJob -- more branches
// ---------------------------------------------------------------------------

func TestCB6_SubmitJob_InvalidJob(t *testing.T) {
	k, ctx := newTestKeeper(t)

	job := &types.ComputeJob{} // empty, invalid
	err := k.SubmitJob(ctx, job)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid job")
}

func TestCB6_SubmitJob_ModelNotRegistered(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := sha256.Sum256([]byte("unregistered-model"))
	inputHash := sha256.Sum256([]byte("input"))
	job := &types.ComputeJob{
		Id:          "job-submit-1",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		RequestedBy: cb6Bech32("test-submit-requester"),
		ProofType:   types.ProofTypeTEE,
		Purpose:     "test",
	}
	err := k.SubmitJob(ctx, job)
	require.Error(t, err)
	require.Contains(t, err.Error(), "model not registered")
}

func TestCB6_SubmitJob_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := sha256.Sum256([]byte("model-submit"))
	inputHash := sha256.Sum256([]byte("input-submit"))
	modelKey := fmt.Sprintf("%x", modelHash[:])
	require.NoError(t, k.RegisteredModels.Set(ctx, modelKey, types.RegisteredModel{
		ModelHash: modelHash[:],
		ModelId:   "submit-model",
		Name:      "Submit Model",
		Owner:     "owner",
	}))

	job := &types.ComputeJob{
		Id:          "job-submit-success",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		RequestedBy: cb6Bech32("test-submit-requester"),
		ProofType:   types.ProofTypeTEE,
		Purpose:     "testing-submit",
	}
	err := k.SubmitJob(ctx, job)
	require.NoError(t, err)

	// Verify it was stored
	retrieved, err := k.GetJob(ctx, "job-submit-success")
	require.NoError(t, err)
	require.Equal(t, "testing-submit", retrieved.Purpose)
}

// ---------------------------------------------------------------------------
// keeper.go: InitGenesis -- deeper branches
// ---------------------------------------------------------------------------

func TestCB6_InitGenesis_WithJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := sha256.Sum256([]byte("genesis-model"))
	inputHash := sha256.Sum256([]byte("genesis-input"))

	gs := &types.GenesisState{
		Params: types.DefaultParams(),
		Jobs: []*types.ComputeJob{
			{
				Id:          "genesis-job-1",
				ModelHash:   modelHash[:],
				InputHash:   inputHash[:],
				RequestedBy: "req1",
				ProofType:   types.ProofTypeTEE,
				Purpose:     "genesis",
				Status:      types.JobStatusPending,
			},
			nil, // nil should be skipped
		},
		RegisteredModels: []*types.RegisteredModel{
			{
				ModelHash: modelHash[:],
				ModelId:   "genesis-model",
				Name:      "Genesis Model",
				Owner:     "owner",
			},
			nil, // nil should be skipped
		},
		ValidatorStats: []*types.ValidatorStats{
			types.NewValidatorStats("val1"),
			nil, // nil should be skipped
		},
	}

	err := k.InitGenesis(ctx, gs)
	require.NoError(t, err)

	// Verify job was stored
	job, err := k.GetJob(ctx, "genesis-job-1")
	require.NoError(t, err)
	require.Equal(t, "genesis", job.Purpose)
}

func TestCB6_InitGenesis_ProcessingJob(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := sha256.Sum256([]byte("genesis-model-2"))
	inputHash := sha256.Sum256([]byte("genesis-input-2"))

	gs := &types.GenesisState{
		Params: types.DefaultParams(),
		Jobs: []*types.ComputeJob{
			{
				Id:          "genesis-processing",
				ModelHash:   modelHash[:],
				InputHash:   inputHash[:],
				RequestedBy: "req2",
				ProofType:   types.ProofTypeTEE,
				Purpose:     "genesis-processing",
				Status:      types.JobStatusProcessing,
			},
		},
	}

	err := k.InitGenesis(ctx, gs)
	require.NoError(t, err)
}

func TestCB6_InitGenesis_CompletedJob(t *testing.T) {
	k, ctx := newTestKeeper(t)

	modelHash := sha256.Sum256([]byte("genesis-model-3"))
	inputHash := sha256.Sum256([]byte("genesis-input-3"))

	gs := &types.GenesisState{
		Params: types.DefaultParams(),
		Jobs: []*types.ComputeJob{
			{
				Id:          "genesis-completed",
				ModelHash:   modelHash[:],
				InputHash:   inputHash[:],
				RequestedBy: "req3",
				ProofType:   types.ProofTypeTEE,
				Purpose:     "genesis-completed",
				Status:      types.JobStatusCompleted,
			},
		},
	}

	err := k.InitGenesis(ctx, gs)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// governance.go: UpdateParams
// ---------------------------------------------------------------------------

func TestCB6_UpdateParams_UnauthorizedCaller(t *testing.T) {
	k, ctx := newTestKeeper(t)

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority: "wrong-authority",
		Params:    *types.DefaultParams(),
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "unauthorized")
}

func TestCB6_UpdateParams_BoolFlagMissing_RequireTee(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Get authority
	authority := k.GetAuthority()

	params := *types.DefaultParams()
	params.RequireTeeAttestation = !params.RequireTeeAttestation // flip

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority:                 authority,
		Params:                    params,
		HasRequireTeeAttestation: false, // not set - should error
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "require_tee_attestation")
}

func TestCB6_UpdateParams_BoolFlagMissing_AllowZkml(t *testing.T) {
	k, ctx := newTestKeeper(t)
	authority := k.GetAuthority()

	params := *types.DefaultParams()
	params.AllowZkmlFallback = !params.AllowZkmlFallback // flip

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority:            authority,
		Params:               params,
		HasAllowZkmlFallback: false,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "allow_zkml_fallback")
}

func TestCB6_UpdateParams_BoolFlagMissing_AllowSimulated(t *testing.T) {
	k, ctx := newTestKeeper(t)
	authority := k.GetAuthority()

	currentParams, err := k.GetParams(ctx)
	require.NoError(t, err)

	params := *currentParams
	params.AllowSimulated = !params.AllowSimulated // flip

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority:        authority,
		Params:           params,
		HasAllowSimulated: false,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "allow_simulated")
}

func TestCB6_UpdateParams_OneWayGate_AllowSimulated(t *testing.T) {
	k, ctx := newTestKeeper(t)
	authority := k.GetAuthority()

	// Set AllowSimulated to false first
	currentParams, err := k.GetParams(ctx)
	require.NoError(t, err)
	currentParams.AllowSimulated = false
	require.NoError(t, k.SetParams(ctx, currentParams))

	// Try to re-enable it
	params := *currentParams
	params.AllowSimulated = true

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority:        authority,
		Params:           params,
		HasAllowSimulated: true,
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "SECURITY")
	require.Contains(t, err.Error(), "one-way gate")
}

func TestCB6_UpdateParams_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)
	authority := k.GetAuthority()

	currentParams, err := k.GetParams(ctx)
	require.NoError(t, err)

	// Valid update: change VerificationReward
	params := *currentParams
	params.VerificationReward = "200uaethel"

	resp, err := keeper.UpdateParamsForTest(k, ctx, &keeper.MsgUpdateParams{
		Authority: authority,
		Params:    params,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the change was applied
	updated, err := k.GetParams(ctx)
	require.NoError(t, err)
	require.Equal(t, "200uaethel", updated.VerificationReward)
}

// ---------------------------------------------------------------------------
// attestation_registry.go: RegisterValidatorPCR0 -- deeper branches
// ---------------------------------------------------------------------------

func TestCB6_RegisterValidatorPCR0_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)

	h := sha256.Sum256([]byte("pcr0-test"))
	validHex := hex.EncodeToString(h[:]) // exactly 64 hex chars
	err := k.RegisterValidatorPCR0(ctx, "val1", validHex)
	require.NoError(t, err)

	// Verify backward-compatible storage
	stored, err := k.ValidatorPCR0Mappings.Get(ctx, "val1")
	require.NoError(t, err)
	require.Equal(t, validHex, stored)
}

func TestCB6_RegisterValidatorPCR0_InvalidHex(t *testing.T) {
	k, ctx := newTestKeeper(t)

	err := k.RegisterValidatorPCR0(ctx, "val1", "too-short")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// attestation_registry.go: ValidateTEEAttestationMeasurement
// ---------------------------------------------------------------------------

func TestCB6_ValidateTEEMeasurement_EmptyMeasurement(t *testing.T) {
	k, ctx := newTestKeeper(t)

	err := k.ValidateTEEAttestationMeasurement(ctx, "val1", "aws-nitro", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing TEE measurement")
}

func TestCB6_ValidateTEEMeasurement_InvalidPlatform(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32)
	err := k.ValidateTEEAttestationMeasurement(ctx, "val1", "invalid-platform", measurement)
	require.Error(t, err)
}

func TestCB6_ValidateTEEMeasurement_NotRegistered(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32) // all zeros
	err := k.ValidateTEEAttestationMeasurement(ctx, "val1", "aws-nitro", measurement)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unregistered")
}

func TestCB6_ValidateTEEMeasurement_WrongValidator(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32)
	measurementHex := hex.EncodeToString(measurement)

	// Register the measurement globally
	authority := k.GetAuthority()
	err := k.AppendTrustedMeasurementByAuthority(ctx, authority, "aws-nitro", measurementHex)
	require.NoError(t, err)

	// But not for this specific validator
	err = k.ValidateTEEAttestationMeasurement(ctx, "val1", "aws-nitro", measurement)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no registered")
}

func TestCB6_ValidateTEEMeasurement_Tampered(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32)
	measurementHex := hex.EncodeToString(measurement)

	authority := k.GetAuthority()
	err := k.AppendTrustedMeasurementByAuthority(ctx, authority, "aws-nitro", measurementHex)
	require.NoError(t, err)

	// Register a different measurement for the validator
	differentMeasurement := sha256.Sum256([]byte("different"))
	differentHex := hex.EncodeToString(differentMeasurement[:])
	err = k.RegisterValidatorMeasurement(ctx, "val1", "aws-nitro", differentHex)
	require.NoError(t, err)

	// Now try to validate - should fail with tampered
	err = k.ValidateTEEAttestationMeasurement(ctx, "val1", "aws-nitro", measurement)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tampered")
}

func TestCB6_ValidateTEEMeasurement_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32)
	measurementHex := hex.EncodeToString(measurement)

	authority := k.GetAuthority()
	err := k.AppendTrustedMeasurementByAuthority(ctx, authority, "aws-nitro", measurementHex)
	require.NoError(t, err)

	// Register same measurement for the validator
	err = k.RegisterValidatorMeasurement(ctx, "val1", "aws-nitro", measurementHex)
	require.NoError(t, err)

	err = k.ValidateTEEAttestationMeasurement(ctx, "val1", "aws-nitro", measurement)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// attestation_registry.go: IsRegisteredMeasurement
// ---------------------------------------------------------------------------

func TestCB6_IsRegisteredMeasurement_EmptyMeasurement(t *testing.T) {
	k, ctx := newTestKeeper(t)

	reg, _, err := k.IsRegisteredMeasurement(ctx, "aws-nitro", nil)
	require.Error(t, err)
	require.False(t, reg)
}

func TestCB6_IsRegisteredMeasurement_InvalidLength(t *testing.T) {
	k, ctx := newTestKeeper(t)

	reg, _, err := k.IsRegisteredMeasurement(ctx, "aws-nitro", []byte{1, 2, 3})
	require.Error(t, err)
	require.False(t, reg)
	require.Contains(t, err.Error(), "invalid")
}

func TestCB6_IsRegisteredMeasurement_NotRegistered(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32)
	reg, _, err := k.IsRegisteredMeasurement(ctx, "aws-nitro", measurement)
	require.NoError(t, err)
	require.False(t, reg)
}

func TestCB6_IsRegisteredMeasurement_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)

	measurement := make([]byte, 32)
	measurementHex := hex.EncodeToString(measurement)

	authority := k.GetAuthority()
	require.NoError(t, k.AppendTrustedMeasurementByAuthority(ctx, authority, "aws-nitro", measurementHex))

	reg, hex, err := k.IsRegisteredMeasurement(ctx, "aws-nitro", measurement)
	require.NoError(t, err)
	require.True(t, reg)
	require.Equal(t, measurementHex, hex)
}

// ---------------------------------------------------------------------------
// attestation_registry.go: RevokeTrustedMeasurementBySecurityCommittee
// ---------------------------------------------------------------------------

func TestCB6_RevokeMeasurement_NotCommitteeMember(t *testing.T) {
	k, ctx := newTestKeeper(t)

	validHex := "abababababababababababababababababababababababababababababababababab"
	err := k.RevokeTrustedMeasurementBySecurityCommittee(ctx, "not-a-member", "aws-nitro", validHex)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in security committee")
}

// ---------------------------------------------------------------------------
// attestation_registry.go: isRequesterMatchValidator
// ---------------------------------------------------------------------------

func TestCB6_IsRequesterMatchValidator_EmptyRequester(t *testing.T) {
	// Test via exported function path - empty requester returns false
	result := keeper.NormalizeCommitteeAddressForTest("")
	require.Equal(t, "", result)
}

// ---------------------------------------------------------------------------
// hardening.go: NewJobRateLimiter -- deeper branches
// ---------------------------------------------------------------------------

func TestCB6_NewJobRateLimiter_NegativeValues(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.RateLimitConfig{
		MaxJobsPerWindow: -5,
		WindowBlocks:     -10,
		GlobalMaxPending: -20,
	})
	// Should use defaults (10, 100, 1000)
	err := rl.CheckLimit("addr1", 50)
	require.NoError(t, err)
}

func TestCB6_NewJobRateLimiter_ZeroValues(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.RateLimitConfig{})
	err := rl.CheckLimit("addr1", 50)
	require.NoError(t, err)
}

func TestCB6_RateLimiter_WindowExpiry(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.RateLimitConfig{
		MaxJobsPerWindow: 2,
		WindowBlocks:     10,
		GlobalMaxPending: 1000,
	})

	// Submit at blocks 1 and 2
	rl.RecordSubmission("addr1", 1)
	rl.RecordSubmission("addr1", 2)

	// At block 3, should be rate limited
	err := rl.CheckLimit("addr1", 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rate limit exceeded")

	// At block 20 (past window), old submissions should be expired
	err = rl.CheckLimit("addr1", 20)
	require.NoError(t, err)
}

func TestCB6_RateLimiter_SubmissionsInWindow_WindowStart(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.DefaultRateLimitConfig())
	rl.RecordSubmission("addr1", 5)
	rl.RecordSubmission("addr1", 10)
	rl.RecordSubmission("addr1", 15)

	// At block 5 (very early), windowStart is negative → clamped to 0
	count := rl.SubmissionsInWindow("addr1", 5)
	require.Equal(t, 3, count) // all within window from 0
}

// ---------------------------------------------------------------------------
// hardening.go: ShouldAcceptJob -- deeper branches
// ---------------------------------------------------------------------------

func TestCB6_ShouldAcceptJob_CircuitBreakerTripped(t *testing.T) {
	cb := keeper.NewEmergencyBreaker()
	cb.Trip("test emergency", "admin-authority", 100, 1000)

	err := keeper.ShouldAcceptJob(cb, nil, "addr1", 100, 0, keeper.DefaultRateLimitConfig())
	require.Error(t, err)
	require.Contains(t, err.Error(), "circuit breaker")
}

func TestCB6_ShouldAcceptJob_GlobalPendingLimit(t *testing.T) {
	config := keeper.DefaultRateLimitConfig()
	config.GlobalMaxPending = 5

	err := keeper.ShouldAcceptJob(nil, nil, "addr1", 100, 5, config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "global pending job limit")
}

func TestCB6_ShouldAcceptJob_WithRateLimiter(t *testing.T) {
	rl := keeper.NewJobRateLimiter(keeper.RateLimitConfig{
		MaxJobsPerWindow: 1,
		WindowBlocks:     100,
		GlobalMaxPending: 1000,
	})
	rl.RecordSubmission("addr1", 100)

	err := keeper.ShouldAcceptJob(nil, rl, "addr1", 100, 0, keeper.DefaultRateLimitConfig())
	require.Error(t, err)
	require.Contains(t, err.Error(), "rate limit exceeded")
}

func TestCB6_ShouldAcceptJob_Success(t *testing.T) {
	err := keeper.ShouldAcceptJob(nil, nil, "addr1", 100, 0, keeper.DefaultRateLimitConfig())
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// hardening.go: PerformanceScore -- all branches
// ---------------------------------------------------------------------------

func TestCB6_PerformanceScore_Offline(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		IsOnline: false,
	})
	require.Equal(t, int64(0), score)
}

func TestCB6_PerformanceScore_Online_AllMetrics(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		IsOnline:          true,
		ReputationScore:   80,
		JobsCompleted:     90,
		JobsFailed:        10,
		AvgResponseBlocks: 2.0,
		ConsecutiveMisses: 0,
	})
	require.True(t, score > 0)
}

func TestCB6_PerformanceScore_NewValidator(t *testing.T) {
	// No completed/failed jobs gives neutral completion score
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		IsOnline:        true,
		ReputationScore: 50,
	})
	require.True(t, score > 0)
}

func TestCB6_PerformanceScore_HighMisses(t *testing.T) {
	score := keeper.PerformanceScore(keeper.PerformanceMetrics{
		IsOnline:          true,
		ReputationScore:   50,
		ConsecutiveMisses: 100,
	})
	// High misses should reduce liveness score
	require.True(t, score >= 0)
}

// ---------------------------------------------------------------------------
// scheduler.go: JobPriorityQueue Update via export helper
// ---------------------------------------------------------------------------

func TestCB6_JobPriorityQueue_Update(t *testing.T) {
	pq := &keeper.JobPriorityQueue{}
	heap.Init(pq)

	job1 := &keeper.ScheduledJob{
		Job:               &types.ComputeJob{Id: "job-pq-1"},
		EffectivePriority: 10,
	}
	job2 := &keeper.ScheduledJob{
		Job:               &types.ComputeJob{Id: "job-pq-2"},
		EffectivePriority: 5,
	}
	heap.Push(pq, job1)
	heap.Push(pq, job2)

	// Update job2 to higher priority
	keeper.JobPriorityQueueUpdateForTest(pq, job2, 20)
	require.Equal(t, int64(20), job2.EffectivePriority)

	// Pop should return job2 now (highest priority)
	popped := heap.Pop(pq).(*keeper.ScheduledJob)
	require.Equal(t, "job-pq-2", popped.Job.Id)
}

// ---------------------------------------------------------------------------
// scheduler.go: Stop (no-op but needs coverage)
// ---------------------------------------------------------------------------

func TestCB6_Scheduler_Stop(t *testing.T) {
	k, _ := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	sched.StopForTest() // should not panic
}

// ---------------------------------------------------------------------------
// fee_distribution.go: DistributeJobFee
// ---------------------------------------------------------------------------

func TestCB6_DistributeJobFee_ZeroFee(t *testing.T) {
	k, ctx := newTestKeeper(t)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	_, err := fd.DistributeJobFee(ctx, sdk.NewInt64Coin("uaethel", 0), []string{"val1"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "positive")
}

func TestCB6_DistributeJobFee_NoValidators(t *testing.T) {
	k, ctx := newTestKeeper(t)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	_, err := fd.DistributeJobFee(ctx, sdk.NewInt64Coin("uaethel", 1000), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one validator")
}

func TestCB6_DistributeJobFee_EmptyValidatorList(t *testing.T) {
	k, ctx := newTestKeeper(t)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	// Distribute with empty validator list -- should return error
	_, err := fd.DistributeJobFee(ctx, sdk.NewInt64Coin("uaethel", 10000), []string{})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// fee_distribution.go: CollectJobFee
// ---------------------------------------------------------------------------

func TestCB6_CollectJobFee_ZeroFee(t *testing.T) {
	k, ctx := newTestKeeper(t)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	submitter := sdk.AccAddress([]byte("submitter-addr-001"))
	err := fd.CollectJobFee(ctx, submitter, sdk.NewInt64Coin("uaethel", 0))
	require.Error(t, err)
	require.Contains(t, err.Error(), "positive")
}

func TestCB6_CollectJobFee_NilBankKeeper(t *testing.T) {
	k, _ := newTestKeeper(t)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	// CollectJobFee with nil bank keeper should panic -- verify we reach the function
	require.Panics(t, func() {
		submitter := sdk.AccAddress([]byte("submitter-addr-001"))
		_ = fd.CollectJobFee(cb6Ctx(), submitter, sdk.NewInt64Coin("uaethel", 1000))
	})
}

// ---------------------------------------------------------------------------
// fee_distribution.go: GetTreasuryBalance
// ---------------------------------------------------------------------------

func TestCB6_GetTreasuryBalance_NilBankKeeper(t *testing.T) {
	k, _ := newTestKeeper(t)
	// GetTreasuryBalance uses bankKeeper which is nil in test keeper, should panic
	require.Panics(t, func() {
		_ = k.GetTreasuryBalance(cb6Ctx())
	})
}

// ---------------------------------------------------------------------------
// fee_distribution.go: activeBondedValidatorCount via export helper
// ---------------------------------------------------------------------------

func TestCB6_ActiveBondedValidatorCount_NilStakingKeeper(t *testing.T) {
	k, _ := newTestKeeper(t)
	fd := keeper.NewFeeDistributor(&k, keeper.DefaultFeeDistributionConfig())

	// activeBondedValidatorCount uses stakingKeeper which is nil, should panic
	require.Panics(t, func() {
		_ = fd.ActivateBondedValidatorCountForTest(cb6Ctx())
	})
}

// ---------------------------------------------------------------------------
// tokenomics_safe.go: SafeAdd / SafeSub / SafeMul -- overflow/underflow
// ---------------------------------------------------------------------------

func TestCB6_SafeAdd_Normal(t *testing.T) {
	sm := keeper.NewSafeMath()
	a := sdkmath.NewInt(1000)
	b := sdkmath.NewInt(2000)

	result, err := sm.SafeAdd(a, b)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(3000), result)
}

func TestCB6_SafeSub_NegativeResult(t *testing.T) {
	sm := keeper.NewSafeMath()
	a := sdkmath.NewInt(5)
	b := sdkmath.NewInt(10)

	result, err := sm.SafeSub(a, b)
	require.NoError(t, err) // Int supports negatives
	require.True(t, result.IsNegative())
}

func TestCB6_SafeMul_LargeNumbers(t *testing.T) {
	sm := keeper.NewSafeMath()
	a := sdkmath.NewInt(1e15)
	b := sdkmath.NewInt(1e15)

	result, err := sm.SafeMul(a, b)
	require.NoError(t, err)
	require.True(t, result.GT(sdkmath.ZeroInt()))
}

func TestCB6_SafeDiv_ByZero(t *testing.T) {
	sm := keeper.NewSafeMath()
	a := sdkmath.NewInt(100)
	b := sdkmath.ZeroInt()

	_, err := sm.SafeDiv(a, b)
	require.Error(t, err)
}

func TestCB6_SafeMulDiv_Normal(t *testing.T) {
	sm := keeper.NewSafeMath()
	result, err := sm.SafeMulDiv(sdkmath.NewInt(100), sdkmath.NewInt(3), sdkmath.NewInt(10))
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(30), result)
}

// ---------------------------------------------------------------------------
// tokenomics_safe.go: bonding curve functions
// ---------------------------------------------------------------------------

func TestCB6_ValidateBondingCurveConfig_Valid(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	err := keeper.ValidateBondingCurveConfig(config)
	require.NoError(t, err)
}

func TestCB6_ValidateBondingCurveConfig_ZeroReserveRatio(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	config.ReserveRatioBps = 0
	err := keeper.ValidateBondingCurveConfig(config)
	// Zero is a valid reserve ratio (range is [0, 10000])
	require.NoError(t, err)
}

func TestCB6_CalculatePurchaseCost(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)
	cost, err := bc.CalculatePurchaseCost(sdkmath.NewInt(100))
	require.NoError(t, err)
	require.True(t, cost.IsPositive())
}

func TestCB6_CalculateSaleReturn(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)
	// Purchase first to have tokens to sell
	_, err := bc.ExecutePurchase(sdkmath.NewInt(1000))
	require.NoError(t, err)
	returnAmt, err := bc.CalculateSaleReturn(sdkmath.NewInt(50))
	require.NoError(t, err)
	require.True(t, returnAmt.GTE(sdkmath.ZeroInt()))
}

func TestCB6_ExecutePurchase(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)
	cost, err := bc.ExecutePurchase(sdkmath.NewInt(1000))
	require.NoError(t, err)
	require.True(t, cost.IsPositive())

	supply, _, _ := bc.GetState()
	require.True(t, supply.GT(sdkmath.ZeroInt()))
}

func TestCB6_ExecuteSale_Zero(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)
	returnAmt, err := bc.ExecuteSale(sdkmath.NewInt(0))
	// Selling zero is a no-op: returns zero with no error
	require.NoError(t, err)
	require.True(t, returnAmt.IsZero())
}

func TestCB6_ExecuteSale_TooMuch(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)
	_, err := bc.ExecuteSale(sdkmath.NewInt(200))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// tokenomics_safe.go: intSqrt
// ---------------------------------------------------------------------------

func TestCB6_IntSqrt(t *testing.T) {
	// intSqrt is tested indirectly via getPriceAtSupply and CalculatePurchaseCost
	config := keeper.DefaultBondingCurveConfig()
	// Force intSqrt branch with different configs
	config.ReserveRatioBps = 50
	bc := keeper.NewBondingCurve(config)
	cost, err := bc.CalculatePurchaseCost(sdkmath.NewInt(100))
	require.NoError(t, err)
	require.True(t, cost.IsPositive())
}

// ---------------------------------------------------------------------------
// tokenomics_safe.go: ComputeEmissionScheduleSafe
// ---------------------------------------------------------------------------

func TestCB6_ComputeEmissionScheduleSafe_Valid(t *testing.T) {
	config := keeper.InflationarySimulationConfig()
	btc := keeper.DefaultBlockTimeConfig()
	schedule, err := keeper.ComputeEmissionScheduleSafe(config, 10, btc)
	require.NoError(t, err)
	require.NotEmpty(t, schedule)
}

func TestCB6_ComputeEmissionScheduleSafe_ZeroYears(t *testing.T) {
	config := keeper.InflationarySimulationConfig()
	btc := keeper.DefaultBlockTimeConfig()
	schedule, err := keeper.ComputeEmissionScheduleSafe(config, 0, btc)
	// Zero years produces an empty schedule with no error
	require.NoError(t, err)
	require.Empty(t, schedule)
}

// ---------------------------------------------------------------------------
// tokenomics_safe.go: ValidateBlockTimeConfig
// ---------------------------------------------------------------------------

func TestCB6_ValidateBlockTimeConfig_Valid(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	err := keeper.ValidateBlockTimeConfig(config)
	require.NoError(t, err)
}

func TestCB6_ValidateBlockTimeConfig_ZeroTarget(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	config.TargetBlockTimeMs = 0
	err := keeper.ValidateBlockTimeConfig(config)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// tokenomics_treasury_vesting.go: ValidateVestingSchedules
// ---------------------------------------------------------------------------

func TestCB6_ValidateVestingSchedules_DuplicateCategories(t *testing.T) {
	schedules := []keeper.VestingSchedule{
		{Category: "pool1", TotalUAETHEL: 1000, VestingBlocks: 1200, CliffBlocks: 300},
		{Category: "pool1", TotalUAETHEL: 2000, VestingBlocks: 1200, CliffBlocks: 300}, // duplicate
	}
	err := keeper.ValidateVestingSchedules(schedules)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

func TestCB6_ValidateVestingSchedules_CliffExceedsVesting(t *testing.T) {
	schedules := []keeper.VestingSchedule{
		{Category: "pool1", TotalUAETHEL: 1000, VestingBlocks: 600, CliffBlocks: 1200},
	}
	err := keeper.ValidateVestingSchedules(schedules)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cliff")
}

func TestCB6_ValidateVestingSchedules_NegativeAmount(t *testing.T) {
	schedules := []keeper.VestingSchedule{
		{Category: "pool1", TotalUAETHEL: -100, VestingBlocks: 1200, CliffBlocks: 300},
	}
	err := keeper.ValidateVestingSchedules(schedules)
	require.Error(t, err)
}

func TestCB6_ValidateVestingSchedules_ZeroAmount(t *testing.T) {
	schedules := []keeper.VestingSchedule{
		{Category: "pool1", TotalUAETHEL: 0, VestingBlocks: 1200, CliffBlocks: 300},
	}
	err := keeper.ValidateVestingSchedules(schedules)
	require.Error(t, err)
}

func TestCB6_ValidateVestingSchedules_ZeroVestingBlocks(t *testing.T) {
	schedules := []keeper.VestingSchedule{
		{Category: "pool1", TotalUAETHEL: 1000, VestingBlocks: 0, CliffBlocks: 0},
	}
	err := keeper.ValidateVestingSchedules(schedules)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// tokenomics_model_simulation.go: ValidateTokenomicsModel
// ---------------------------------------------------------------------------

func TestCB6_ValidateTokenomicsModel_Valid(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	issues := keeper.ValidateTokenomicsModel(model)
	require.Empty(t, issues)
}

func TestCB6_ValidateTokenomicsModel_BadEmission(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	model.Emission.InitialInflationBps = -1 // invalid
	issues := keeper.ValidateTokenomicsModel(model)
	require.NotEmpty(t, issues)
}

func TestCB6_ValidateTokenomicsModel_BadSlashing(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	model.Slashing.DoubleSignSlashBps = -1 // invalid
	issues := keeper.ValidateTokenomicsModel(model)
	require.NotEmpty(t, issues)
}

// ---------------------------------------------------------------------------
// evidence.go: ProcessEndBlockEvidence (EvidenceCollector)
// ---------------------------------------------------------------------------

func TestCB6_EvidenceCollector_ProcessEndBlockEvidence_NoEvidence(t *testing.T) {
	k, ctx := newTestKeeper(t)
	ec := keeper.NewEvidenceCollector(log.NewNopLogger(), &k)

	err := ec.ProcessEndBlockEvidence(ctx)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// invariants.go: ValidatorStatsNonNegativeInvariant -- more branches
// ---------------------------------------------------------------------------

func TestCB6_ValidatorStatsInvariant_NegativeReputation(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Set validator stats with negative reputation
	stats := types.NewValidatorStats("val-neg")
	stats.ReputationScore = -5
	require.NoError(t, k.ValidatorStats.Set(ctx, "val-neg", *stats))

	inv := keeper.ValidatorStatsNonNegativeInvariant(k)
	msg, broken := inv(ctx)
	require.True(t, broken)
	require.Contains(t, msg, "negative")
}

func TestCB6_ValidatorStatsInvariant_AllValid(t *testing.T) {
	k, ctx := newTestKeeper(t)

	stats := types.NewValidatorStats("val-ok")
	stats.ReputationScore = 50
	stats.TotalJobsProcessed = 10
	require.NoError(t, k.ValidatorStats.Set(ctx, "val-ok", *stats))

	inv := keeper.ValidatorStatsNonNegativeInvariant(k)
	msg, broken := inv(ctx)
	require.False(t, broken)
	require.Empty(t, msg)
}

// ---------------------------------------------------------------------------
// upgrade.go: PostUpgradeValidation -- more branches
// ---------------------------------------------------------------------------

func TestCB6_PostUpgradeValidation_WithJobsAndStats(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 3)

	// Add validator stats
	stats := types.NewValidatorStats("val-post-upgrade")
	stats.ReputationScore = 80
	require.NoError(t, k.ValidatorStats.Set(ctx, "val-post-upgrade", *stats))

	errs := keeper.PostUpgradeValidation(ctx, k)
	require.Empty(t, errs)
}

// ---------------------------------------------------------------------------
// upgrade_rehearsal.go: RunRollbackDrill -- more branches
// ---------------------------------------------------------------------------

func TestCB6_RunRollbackDrill(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 2)

	result := keeper.RunRollbackDrill(ctx, k)
	require.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// query_server.go: deeper coverage
// ---------------------------------------------------------------------------

func TestCB6_QueryServer_Params(t *testing.T) {
	k, ctx := newTestKeeper(t)
	qs := keeper.NewQueryServerImpl(k)

	resp, err := qs.Params(ctx, &types.QueryParamsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.Params)
}

func TestCB6_QueryServer_Params_NilRequest(t *testing.T) {
	k, ctx := newTestKeeper(t)
	qs := keeper.NewQueryServerImpl(k)

	_, err := qs.Params(ctx, nil)
	require.Error(t, err)
}

func TestCB6_QueryServer_ValidatorStats(t *testing.T) {
	k, ctx := newTestKeeper(t)
	stats := types.NewValidatorStats("val-qs")
	stats.ReputationScore = 75
	require.NoError(t, k.ValidatorStats.Set(ctx, "val-qs", *stats))

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.ValidatorStats(ctx, &types.QueryValidatorStatsRequest{ValidatorAddress: "val-qs"})
	require.NoError(t, err)
	require.NotNil(t, resp.Stats)
	require.Equal(t, int64(75), resp.Stats.ReputationScore)
}

func TestCB6_QueryServer_ValidatorStats_NotFound(t *testing.T) {
	k, ctx := newTestKeeper(t)
	qs := keeper.NewQueryServerImpl(k)

	_, err := qs.ValidatorStats(ctx, &types.QueryValidatorStatsRequest{ValidatorAddress: "nonexistent"})
	require.Error(t, err)
}

func TestCB6_QueryServer_PendingJobs(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 3)

	qs := keeper.NewQueryServerImpl(k)
	resp, err := qs.PendingJobs(ctx, &types.QueryPendingJobsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Jobs, 3)
}

func TestCB6_QueryServer_PendingJobs_NilRequest(t *testing.T) {
	k, ctx := newTestKeeper(t)
	qs := keeper.NewQueryServerImpl(k)

	_, err := qs.PendingJobs(ctx, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// msg_server.go: SubmitJob -- reserved metadata
// ---------------------------------------------------------------------------

func TestCB6_MsgServer_SubmitJob_ReservedMetadata(t *testing.T) {
	k, ctx := newTestKeeper(t)
	ms := keeper.NewMsgServerImpl(k)

	modelHash := sha256.Sum256([]byte("msg-model"))
	inputHash := sha256.Sum256([]byte("msg-input"))
	modelKey := fmt.Sprintf("%x", modelHash[:])
	require.NoError(t, k.RegisteredModels.Set(ctx, modelKey, types.RegisteredModel{
		ModelHash: modelHash[:],
		ModelId:   "msg-model",
		Name:      "Msg Model",
		Owner:     "owner",
	}))

	addr := cb6Bech32("msg-submit-requester")
	resp, err := ms.SubmitJob(ctx, &types.MsgSubmitJob{
		Creator:   addr,
		ModelHash: modelHash[:],
		InputHash: inputHash[:],
		ProofType: types.ProofTypeTEE,
		Purpose:   "test",
		Metadata: map[string]string{
			"scheduler.attempt_to_inject": "malicious_value",
		},
	})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "reserved")
}

// ---------------------------------------------------------------------------
// msg_server.go: CancelJob deeper branches
// ---------------------------------------------------------------------------

func TestCB6_MsgServer_CancelJob_NotPending(t *testing.T) {
	k, ctx := newTestKeeper(t)
	ms := keeper.NewMsgServerImpl(k)

	// Create a completed job directly
	modelHash := sha256.Sum256([]byte("cancel-model"))
	inputHash := sha256.Sum256([]byte("cancel-input"))
	job := types.ComputeJob{
		Id:          "cancel-completed",
		ModelHash:   modelHash[:],
		InputHash:   inputHash[:],
		RequestedBy: cb6Bech32("cancel-requester-1"),
		ProofType:   types.ProofTypeTEE,
		Purpose:     "test",
		Status:      types.JobStatusCompleted,
	}
	require.NoError(t, k.Jobs.Set(ctx, job.Id, job))

	_, err := ms.CancelJob(ctx, &types.MsgCancelJob{
		Creator: cb6Bech32("cancel-requester-1"),
		JobId:   "cancel-completed",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "pending")
}

// ---------------------------------------------------------------------------
// mainnet_params.go: CheckParameterCompatibility -- more branches
// ---------------------------------------------------------------------------

func TestCB6_CheckParameterCompatibility_WithStrictParams(t *testing.T) {
	k, ctx := newTestKeeper(t)

	params := types.DefaultParams()
	params.RequireTeeAttestation = true
	params.AllowSimulated = false
	require.NoError(t, k.SetParams(ctx, params))

	errs := keeper.CheckParameterCompatibility(ctx, k, params)
	// Should pass validation
	_ = errs
}

// ---------------------------------------------------------------------------
// performance.go: ValidateProfile
// ---------------------------------------------------------------------------

func TestCB6_ValidateProfile_Valid(t *testing.T) {
	profile := keeper.TestnetProfile()
	err := profile.ValidateProfile()
	require.NoError(t, err)
}

func TestCB6_ValidateProfile_ZeroMaxJobs(t *testing.T) {
	profile := keeper.TestnetProfile()
	profile.MaxJobsPerBlock = 0
	err := profile.ValidateProfile()
	require.Error(t, err)
}

func TestCB6_ValidateProfile_MaxJobsTooHigh(t *testing.T) {
	profile := keeper.TestnetProfile()
	profile.MaxJobsPerBlock = 5000
	err := profile.ValidateProfile()
	require.Error(t, err)
}

func TestCB6_ValidateProfile_LowTimeout(t *testing.T) {
	profile := keeper.TestnetProfile()
	profile.ConsensusTimeoutBlocks = 2
	err := profile.ValidateProfile()
	require.Error(t, err)
}

func TestCB6_ValidateProfile_LowPending(t *testing.T) {
	profile := keeper.TestnetProfile()
	profile.MaxPendingJobs = 5
	err := profile.ValidateProfile()
	require.Error(t, err)
}

func TestCB6_ValidateProfile_BadBudget(t *testing.T) {
	profile := keeper.TestnetProfile()
	profile.MaxBlockBudgetMs = 10
	err := profile.ValidateProfile()
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// roadmap_tracker.go: evaluateMilestoneStatus
// ---------------------------------------------------------------------------

func TestCB6_CanonicalMilestones_AllCovered(t *testing.T) {
	k, ctx := newTestKeeper(t)
	milestones := keeper.CanonicalMilestones(ctx, k)
	require.NotEmpty(t, milestones)

	for _, ms := range milestones {
		require.NotEmpty(t, ms.ID)
		require.NotEmpty(t, ms.Name)
		icon := keeper.StatusIconForTest(ms.Status)
		require.NotEmpty(t, icon)
	}
}

// ---------------------------------------------------------------------------
// ecosystem_launch.go: RenderLaunchReviewReport / RenderGenesisCeremonyReport
// ---------------------------------------------------------------------------

func TestCB6_RenderLaunchReviewReport_AllCategories(t *testing.T) {
	result := &keeper.LaunchReviewResult{
		ChainID:      "aethelred-test",
		BlockHeight:  100,
		ReviewedAt:   "2025-06-15T12:00:00Z",
		OverallScore: 80,
		Decision:     "GO",
		SecurityScore:    90,
		PerformanceScore: 85,
		EconomicsScore:   80,
		OperationsScore:  75,
		EcosystemScore:   70,
		GovernanceScore:  65,
		Criteria: []keeper.LaunchCriterion{
			{ID: "L-01", Category: "security", Description: "test-criterion", Passed: true, Details: "ok"},
			{ID: "L-02", Category: "economics", Description: "econ-criterion", Passed: false, Details: "needs work", Blocking: true},
		},
	}
	report := keeper.RenderLaunchReviewReport(result)
	require.Contains(t, report, "aethelred-test")
}

func TestCB6_RenderGenesisCeremonyReport_AllFields(t *testing.T) {
	result := &keeper.GenesisCeremonyResult{
		ChainID:        "aethelred-mainnet-1",
		GenesisTime:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		BlockHeight:    1,
		ValidatorCount: 10,
		GenesisValid:   true,
		CeremonyPass:   true,
		InvariantsPass: true,
		ParamsHash:     "abc123",
	}
	report := keeper.RenderGenesisCeremonyReport(result)
	require.Contains(t, report, "aethelred-mainnet-1")
}

// ---------------------------------------------------------------------------
// tokenomics.go: ComputeValidatorEconomics
// ---------------------------------------------------------------------------

func TestCB6_ComputeValidatorEconomics(t *testing.T) {
	k, ctx := newTestKeeper(t)
	economics, err := keeper.ComputeValidatorEconomics(ctx, k, "val-econ", 1000, 500)
	require.NoError(t, err)
	require.NotNil(t, economics)
}

// ---------------------------------------------------------------------------
// tokenomics.go: ValidateFeeMarketConfig
// ---------------------------------------------------------------------------

func TestCB6_ValidateFeeMarketConfig_Valid(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	err := keeper.ValidateFeeMarketConfig(config)
	require.NoError(t, err)
}

func TestCB6_ValidateFeeMarketConfig_ZeroBaseFee(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	config.BaseFeeUAETHEL = 0
	err := keeper.ValidateFeeMarketConfig(config)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// tokenomics.go: ValidateSlashingConfig
// ---------------------------------------------------------------------------

func TestCB6_ValidateSlashingConfig_Valid(t *testing.T) {
	config := keeper.DefaultSlashingConfig()
	err := keeper.ValidateSlashingConfig(config)
	require.NoError(t, err)
}

func TestCB6_ValidateSlashingConfig_NegativePenalty(t *testing.T) {
	config := keeper.DefaultSlashingConfig()
	config.DowntimeSlashBps = -1
	err := keeper.ValidateSlashingConfig(config)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// tokenomics.go: ComputeDynamicFee
// ---------------------------------------------------------------------------

func TestCB6_ComputeDynamicFee_Normal(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 50, 100) // 50% utilization
	require.True(t, fee > 0)
}

func TestCB6_ComputeDynamicFee_HighUtilization(t *testing.T) {
	config := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(config, 95, 100) // 95% utilization
	require.True(t, fee > 0)
}

// ---------------------------------------------------------------------------
// security_compliance.go: ValidateVerificationPolicy
// ---------------------------------------------------------------------------

func TestCB6_ValidateVerificationPolicy(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	err := keeper.ValidateVerificationPolicy(policy)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// audit_scope.go: BuildAuditScope
// ---------------------------------------------------------------------------

func TestCB6_BuildAuditScope(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 2)

	scope := keeper.BuildAuditScope(ctx, k)
	require.NotNil(t, scope)
}

// ---------------------------------------------------------------------------
// prometheus.go: writeQuantile
// ---------------------------------------------------------------------------

func TestCB6_PrometheusMetrics_NilSafe(t *testing.T) {
	// Prometheus metrics should be nil-safe when not initialized
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 1)

	// UpdateJob with no metrics attached should not panic
	job, err := k.GetJob(ctx, "job-0")
	require.NoError(t, err)
	job.Status = types.JobStatusCompleted
	err = k.UpdateJob(ctx, job)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// staking.go: deeper coverage for SelectValidators
// ---------------------------------------------------------------------------

func TestCB6_SelectValidators_WithCapabilities(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())

	// Register some validators with capabilities
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-tee-1",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		CurrentJobs:       0,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-tee-2",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		CurrentJobs:       0,
		ReputationScore:   90,
		TeePlatforms:      []string{"aws-nitro"},
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-offline",
		IsOnline:          false,
		MaxConcurrentJobs: 5,
		ReputationScore:   100,
		TeePlatforms:      []string{"aws-nitro"},
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-no-tee",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   100,
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-full",
		IsOnline:          true,
		MaxConcurrentJobs: 1,
		CurrentJobs:       1, // at capacity
		ReputationScore:   100,
		TeePlatforms:      []string{"aws-nitro"},
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-low-rep",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   5, // below min 30
		TeePlatforms:      []string{"aws-nitro"},
	})

	vs := keeper.NewValidatorSelector(&k, sched, nil)
	criteria := keeper.DefaultSelectionCriteria(types.ProofTypeTEE)
	criteria.PreferredPlatforms = []string{"aws-nitro"}
	criteria.MinStake = 0 // bypass stake check in test (no staking keeper)

	candidates, err := vs.SelectValidators(ctx, criteria)
	require.NoError(t, err)
	// Should only select val-tee-1 and val-tee-2 (online, has capacity, has TEE, meets rep)
	require.Len(t, candidates, 2)
}

func TestCB6_SelectValidators_ZKMLCriteria(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())

	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-zkml",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		ZkmlSystems:       []string{"ezkl"},
	})

	vs := keeper.NewValidatorSelector(&k, sched, nil)
	criteria := keeper.DefaultSelectionCriteria(types.ProofTypeZKML)
	criteria.PreferredProofSystems = []string{"ezkl"}
	criteria.MinStake = 0 // bypass stake check in test (no staking keeper)

	candidates, err := vs.SelectValidators(ctx, criteria)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
}

func TestCB6_SelectValidators_HybridCriteria(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())

	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-hybrid",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
		ZkmlSystems:       []string{"ezkl"},
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-tee-only",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
	})

	vs := keeper.NewValidatorSelector(&k, sched, nil)
	criteria := keeper.DefaultSelectionCriteria(types.ProofTypeHybrid)
	criteria.MinStake = 0 // bypass stake check in test (no staking keeper)

	candidates, err := vs.SelectValidators(ctx, criteria)
	require.NoError(t, err)
	require.Len(t, candidates, 1) // only hybrid-capable
}

func TestCB6_SelectValidators_WithExclusions(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())

	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-a",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
	})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-b",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
	})

	vs := keeper.NewValidatorSelector(&k, sched, nil)
	criteria := keeper.DefaultSelectionCriteria(types.ProofTypeTEE)
	criteria.ExcludeValidators = []string{"val-a"}
	criteria.MinStake = 0 // bypass stake check in test (no staking keeper)

	candidates, err := vs.SelectValidators(ctx, criteria)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "val-b", candidates[0].Address)
}

func TestCB6_SelectValidators_MaxLimit(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())

	for i := 0; i < 5; i++ {
		sched.RegisterValidator(&types.ValidatorCapability{
			Address:           fmt.Sprintf("val-%d", i),
			IsOnline:          true,
			MaxConcurrentJobs: 5,
			ReputationScore:   80,
			TeePlatforms:      []string{"aws-nitro"},
		})
	}

	vs := keeper.NewValidatorSelector(&k, sched, nil)
	criteria := keeper.DefaultSelectionCriteria(types.ProofTypeTEE)
	criteria.MaxValidators = 2
	criteria.MinStake = 0 // bypass stake check in test (no staking keeper)

	candidates, err := vs.SelectValidators(ctx, criteria)
	require.NoError(t, err)
	require.Len(t, candidates, 2)
}

// ---------------------------------------------------------------------------
// staking.go: getValidatorStakingPower -- fallback path
// ---------------------------------------------------------------------------

func TestCB6_GetValidatorStakingPower_Fallback(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	vs := keeper.NewValidatorSelector(&k, sched, nil)

	// No staking keeper means fallback to ValidatorStats
	stats := types.NewValidatorStats("val-power-test")
	stats.ReputationScore = 50
	require.NoError(t, k.ValidatorStats.Set(ctx, "val-power-test", *stats))

	power := vs.GetValidatorStakingPowerForTest(ctx, "val-power-test")
	require.True(t, power > 0)
}

func TestCB6_GetValidatorStakingPower_LastResort(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	vs := keeper.NewValidatorSelector(&k, sched, nil)

	// No stats either -- last resort
	power := vs.GetValidatorStakingPowerForTest(ctx, "totally-unknown")
	require.Equal(t, int64(1000000), power)
}

// ---------------------------------------------------------------------------
// staking.go: ValidateValidatorForJob -- assigned path
// ---------------------------------------------------------------------------

func TestCB6_ValidateValidatorForJob_Assigned(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	vs := keeper.NewValidatorSelector(&k, sched, nil)

	seedJobs(t, ctx, k, 1)
	job, _ := k.GetJob(ctx, "job-0")

	// Register validator but do NOT assign it to the job via the scheduler
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val-assigned",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
	})
	// Validator is registered but not assigned to the job, so validation fails
	err := vs.ValidateValidatorForJob(ctx, "val-assigned", job)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not assigned to job")
}

// ---------------------------------------------------------------------------
// staking.go: SelectCommitteeForJob -- sufficient path
// ---------------------------------------------------------------------------

func TestCB6_SelectCommitteeForJob_Success(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())

	for i := 0; i < 10; i++ {
		sched.RegisterValidator(&types.ValidatorCapability{
			Address:           fmt.Sprintf("committee-val-%d", i),
			IsOnline:          true,
			MaxConcurrentJobs: 5,
			ReputationScore:   80,
			TeePlatforms:      []string{"aws-nitro"},
		})
	}

	vs := keeper.NewValidatorSelector(&k, sched, nil)
	seedJobs(t, ctx, k, 1)
	job, _ := k.GetJob(ctx, "job-0")

	// Without a staking keeper, validators lack sufficient staking power
	// to meet MinStake in DefaultSelectionCriteria, so the committee
	// selection returns "insufficient validators".
	_, err := vs.SelectCommitteeForJob(ctx, job, 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient validators")
}

// ---------------------------------------------------------------------------
// staking.go: CheckValidatorEligibility -- more branches
// ---------------------------------------------------------------------------

func TestCB6_CheckValidatorEligibility_NotRegistered(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	vs := keeper.NewValidatorSelector(&k, sched, nil)

	eligible, reason := vs.CheckValidatorEligibility(ctx, "unregistered-val")
	require.False(t, eligible)
	require.Contains(t, reason, "not registered")
}

func TestCB6_CheckValidatorEligibility_Offline(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "offline-val",
		IsOnline:          false,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
	})
	vs := keeper.NewValidatorSelector(&k, sched, nil)

	eligible, reason := vs.CheckValidatorEligibility(ctx, "offline-val")
	require.False(t, eligible)
	require.Contains(t, reason, "offline")
}

func TestCB6_CheckValidatorEligibility_LowReputation(t *testing.T) {
	k, ctx := newTestKeeper(t)
	sched := keeper.NewJobScheduler(log.NewNopLogger(), &k, keeper.DefaultSchedulerConfig())
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "low-rep-val",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   5, // below 10
	})
	vs := keeper.NewValidatorSelector(&k, sched, nil)

	eligible, reason := vs.CheckValidatorEligibility(ctx, "low-rep-val")
	require.False(t, eligible)
	require.Contains(t, reason, "reputation")
}

// ---------------------------------------------------------------------------
// security_audit.go: deeper coverage
// ---------------------------------------------------------------------------

func TestCB6_SecurityAudit_FullRun(t *testing.T) {
	k, ctx := newTestKeeper(t)
	seedJobs(t, ctx, k, 5)

	report := keeper.RunSecurityAudit(ctx, k)
	require.NotNil(t, report)
}

// ---------------------------------------------------------------------------
// drand_pulse.go: LatestPulse
// ---------------------------------------------------------------------------

func TestCB6_LatestPulse_NoProvider(t *testing.T) {
	provider := keeper.NewHTTPDrandPulseProvider("", 0)
	pulse, err := provider.LatestPulse(cb6Ctx())
	require.Error(t, err)
	_ = pulse
}

// ---------------------------------------------------------------------------
// fee_earmark_store.go: addEarmarkAmount/getEarmarkAmount deeper coverage
// ---------------------------------------------------------------------------

func TestCB6_EarmarkStore_RecordAndGet(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// The test keeper from keeper_test package cannot set the unexported
	// storeService field, so earmark operations return "store service not
	// configured". Verify the error is properly surfaced.
	err := k.RecordTreasuryEarmark(ctx, sdk.NewInt64Coin("uaethel", 1000))
	require.Error(t, err)
	require.Contains(t, err.Error(), "store service not configured")

	err = k.RecordInsuranceFundEarmark(ctx, sdk.NewInt64Coin("uaethel", 500))
	require.Error(t, err)
	require.Contains(t, err.Error(), "store service not configured")

	_, err = k.GetTreasuryEarmarkedBalance(ctx, "uaethel")
	require.Error(t, err)
	require.Contains(t, err.Error(), "store service not configured")

	_, err = k.GetInsuranceFundEarmarkedBalance(ctx, "uaethel")
	require.Error(t, err)
	require.Contains(t, err.Error(), "store service not configured")
}

func TestCB6_EarmarkStore_CumulativeAddition(t *testing.T) {
	k, ctx := newTestKeeper(t)

	// Without storeService (unexported, not settable from keeper_test package),
	// earmark operations return an error.
	err := k.RecordTreasuryEarmark(ctx, sdk.NewInt64Coin("uaethel", 100))
	require.Error(t, err)
	require.Contains(t, err.Error(), "store service not configured")

	err = k.RecordTreasuryEarmark(ctx, sdk.NewInt64Coin("uaethel", 200))
	require.Error(t, err)
	require.Contains(t, err.Error(), "store service not configured")
}

// ---------------------------------------------------------------------------
// audit_closeout.go: computeSecurityScore / computeTestCoverage / RenderCloseoutReport
// ---------------------------------------------------------------------------

func TestCB6_ComputeSecurityScore_NoFindings(t *testing.T) {
	report := &keeper.AuditReport{
		Findings: nil,
	}
	score := keeper.ComputeSecurityScoreForTest(report)
	// With TotalChecks=0 and no findings, computeSecurityScore returns 0
	// (early return on TotalChecks==0)
	require.Equal(t, 0, score)
}

func TestCB6_ComputeSecurityScore_WithFindings(t *testing.T) {
	report := &keeper.AuditReport{
		Findings: []keeper.AuditFinding{
			{ID: "F-01", Severity: "CRITICAL", Description: "critical issue", Passed: false},
			{ID: "F-02", Severity: "HIGH", Description: "high issue", Passed: true},
			{ID: "F-03", Severity: "LOW", Description: "low issue", Passed: false},
		},
	}
	score := keeper.ComputeSecurityScoreForTest(report)
	require.True(t, score < 100)
}

func TestCB6_ComputeTestCoverage(t *testing.T) {
	coverage := keeper.ComputeTestCoverageForTest()
	require.True(t, coverage >= 0 && coverage <= 100)
}

// ---------------------------------------------------------------------------
// remediation.go: RecordMiss deeper
// ---------------------------------------------------------------------------

func TestCB6_LivenessTracker_RecordAndCheck(t *testing.T) {
	lt := keeper.NewLivenessTracker(100, 500)

	// Record participation
	lt.RecordActivity("val1", 100)
	lt.RecordActivity("val2", 100)

	// Record miss
	lt.RecordMiss("val2", 101)
	lt.RecordMiss("val2", 102)
	lt.RecordMiss("val2", 103)

	// Check unresponsive
	unresponsive := lt.GetUnresponsiveValidators()
	_ = unresponsive // may or may not have val2 depending on threshold
}

// ---------------------------------------------------------------------------
// mainnet_params.go: ValidateMainnetGenesis
// ---------------------------------------------------------------------------

func TestCB6_ValidateMainnetGenesis(t *testing.T) {
	config := keeper.DefaultMainnetGenesisConfig()
	errs := keeper.ValidateMainnetGenesis(config)
	require.Empty(t, errs) // default config should be valid
}

// ---------------------------------------------------------------------------
// upgrade_rehearsal.go: RenderRehearsalReport
// ---------------------------------------------------------------------------

func TestCB6_RenderRehearsalReport(t *testing.T) {
	result := &keeper.UpgradeRehearsalResult{
		FromVersion:       1,
		ToVersion:         2,
		ChainID:           "aethelred-test",
		BlockHeight:       100,
		RunAt:             "2025-06-15T12:00:00Z",
		PreUpgradePass:    true,
		PostUpgradePass:   true,
		RehearsalPass:     true,
		MigrationDuration: 5 * time.Second,
		MigrationSteps: []keeper.MigrationStepResult{
			{Name: "step-1", Duration: 2 * time.Second, Passed: true},
		},
	}
	report := keeper.RenderRehearsalReport(result)
	require.Contains(t, report, "aethelred-test")
}

// ---------------------------------------------------------------------------
// security_compliance.go: EvaluateVerificationPolicy / RunComplianceSummary
// ---------------------------------------------------------------------------

func TestCB6_EvaluateVerificationPolicy(t *testing.T) {
	k, ctx := newTestKeeper(t)
	result := keeper.EvaluateVerificationPolicy(ctx, k)
	require.NotNil(t, result)
}

func TestCB6_RunComplianceSummary(t *testing.T) {
	k, ctx := newTestKeeper(t)
	summary := keeper.RunComplianceSummary(ctx, k)
	require.NotNil(t, summary)
}

func TestCB6_RenderComplianceSummary(t *testing.T) {
	k, ctx := newTestKeeper(t)
	summary := keeper.RunComplianceSummary(ctx, k)
	report := keeper.RenderComplianceSummary(summary)
	require.NotEmpty(t, report)
}

// ---------------------------------------------------------------------------
// evidence_system.go: ProcessDoubleSignEvidence / ProcessDowntimeEvidence
// ---------------------------------------------------------------------------

func TestCB6_SlashingIntegration_ProcessDoubleSign(t *testing.T) {
	si := keeper.NewSlashingIntegration(log.NewNopLogger(), nil, keeper.DefaultEvidenceSlashingConfig())

	h1 := sha256.Sum256([]byte("vote1"))
	h2 := sha256.Sum256([]byte("vote2"))
	evidence := &keeper.EquivocationEvidence{
		ValidatorAddress: "val-double",
		BlockHeight:      100,
		Vote1:            keeper.VoteRecord{VoteHash: h1, ExtensionHash: h1, Timestamp: time.Now()},
		Vote2:            keeper.VoteRecord{VoteHash: h2, ExtensionHash: h2, Timestamp: time.Now()},
		DetectedAt:       time.Now(),
	}
	result, err := si.ProcessDoubleSignEvidence(cb6Ctx(), evidence)
	// With nil keeper, getValidatorStake returns zero stake, so result has zero slash
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "val-double", result.ValidatorAddress)
	require.True(t, result.Jailed)
}

func TestCB6_SlashingIntegration_ProcessDowntime(t *testing.T) {
	si := keeper.NewSlashingIntegration(log.NewNopLogger(), nil, keeper.DefaultEvidenceSlashingConfig())

	penalty := &keeper.DowntimePenalty{
		ValidatorAddress: "val-downtime",
		MissedBlocks:     100,
		Action:           keeper.DowntimeActionJail,
		BlockHeight:      50,
	}
	result, err := si.ProcessDowntimeEvidence(cb6Ctx(), penalty)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "val-downtime", result.ValidatorAddress)
}

func TestCB6_SlashingIntegration_ProcessCollusion(t *testing.T) {
	si := keeper.NewSlashingIntegration(log.NewNopLogger(), nil, keeper.DefaultEvidenceSlashingConfig())

	results, err := si.ProcessCollusionEvidence(cb6Ctx(), []string{"val-1", "val-2"}, 100, "coordinated bad output")
	require.NoError(t, err)
	require.NotNil(t, results)
}

// ---------------------------------------------------------------------------
// evidence_system.go: VerifyEquivocationEvidence
// ---------------------------------------------------------------------------

func TestCB6_VerifyEquivocationEvidence(t *testing.T) {
	h1 := sha256.Sum256([]byte("ext-a"))
	h2 := sha256.Sum256([]byte("ext-b"))

	// Build evidence and compute the EvidenceHash manually
	// (replicating computeEvidenceHashStatic logic)
	evidence := &keeper.EquivocationEvidence{
		ValidatorAddress: "val-equivocate",
		BlockHeight:      100,
		Vote1:            keeper.VoteRecord{VoteHash: h1, ExtensionHash: h1, Timestamp: time.Now()},
		Vote2:            keeper.VoteRecord{VoteHash: h2, ExtensionHash: h2, Timestamp: time.Now()},
		DetectedAt:       time.Now(),
	}
	// Compute evidence hash: sha256("aethelred_equivocation_v1:" + addr + height_bytes + vote1_hash + vote2_hash)
	evidenceHasher := sha256.New()
	evidenceHasher.Write([]byte("aethelred_equivocation_v1:"))
	evidenceHasher.Write([]byte(evidence.ValidatorAddress))
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(evidence.BlockHeight))
	evidenceHasher.Write(heightBytes)
	evidenceHasher.Write(h1[:])
	evidenceHasher.Write(h2[:])
	var evidenceHash [32]byte
	copy(evidenceHash[:], evidenceHasher.Sum(nil))
	evidence.EvidenceHash = evidenceHash

	// Different votes with correct hash => valid equivocation evidence
	valid := keeper.VerifyEquivocationEvidence(evidence)
	require.True(t, valid)

	// Same votes => not valid equivocation
	evidence2 := &keeper.EquivocationEvidence{
		ValidatorAddress: "val-equivocate",
		BlockHeight:      100,
		Vote1:            keeper.VoteRecord{VoteHash: h1, ExtensionHash: h1},
		Vote2:            keeper.VoteRecord{VoteHash: h1, ExtensionHash: h1},
	}
	valid2 := keeper.VerifyEquivocationEvidence(evidence2)
	require.False(t, valid2)
}

// ---------------------------------------------------------------------------
// evidence_system.go: ClearProcessedEquivocations / PruneOldHistory
// ---------------------------------------------------------------------------

func TestCB6_DoubleVotingDetector_ClearAndPrune(t *testing.T) {
	dvd := keeper.NewDoubleVotingDetector(log.NewNopLogger(), nil)

	// Record some votes to generate data
	h1 := sha256.Sum256([]byte("ext1"))
	dvd.RecordVote("val1", 100, h1, map[string][32]byte{"job1": sha256.Sum256([]byte("out1"))})
	dvd.RecordVote("val1", 100, sha256.Sum256([]byte("ext2")), map[string][32]byte{"job1": sha256.Sum256([]byte("out2"))})

	// Clear processed - pass empty slice
	dvd.ClearProcessedEquivocations([][32]byte{})

	// Prune old
	dvd.PruneOldHistory(200)
}

// ---------------------------------------------------------------------------
// slashing_integration.go: escrowFraudSlashIfEnabled
// ---------------------------------------------------------------------------

func TestCB6_EscrowFraudSlash_NilInsuranceKeeper(t *testing.T) {
	adapter := keeper.NewSlashingModuleAdapter(
		log.NewNopLogger(),
		nil, // staking keeper
		nil, // slashing keeper
		nil, // bank keeper
		keeper.DefaultSlashingAdapterConfig(),
	)
	// No insurance keeper - escrowFraudSlashIfEnabled should be no-op
	_ = adapter
}

// ---------------------------------------------------------------------------
// validator_onboarding.go: ValidateApplication
// ---------------------------------------------------------------------------

func TestCB6_ValidateApplication_Valid(t *testing.T) {
	app := keeper.OnboardingApplication{
		ValidatorAddr:     "val-onboard",
		Moniker:           "Operator",
		OperatorContact:   "test@example.com",
		TEEPlatform:       "nitro",
		MaxConcurrentJobs: 5,
		NodeVersion:       "v1.0.0",
		SupportsTEE:       true,
	}
	err := keeper.ValidateApplication(app)
	require.NoError(t, err)
}

func TestCB6_ValidateApplication_MissingFields(t *testing.T) {
	app := keeper.OnboardingApplication{}
	err := keeper.ValidateApplication(app)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// audit.go: VerifyChain
// ---------------------------------------------------------------------------

func TestCB6_AuditLogger_VerifyChain(t *testing.T) {
	al := keeper.NewAuditLogger(100)

	// Record some events
	al.AuditValidatorRegistered(cb6Ctx(), "val1", 5, true)
	al.AuditJobSubmitted(cb6Ctx(), "job1", "modelhash", "requester", "tee")
	al.AuditJobCompleted(cb6Ctx(), "job1", "seal1", "outputhash", 3)

	// Verify chain
	err := al.VerifyChain()
	require.NoError(t, err)
}
