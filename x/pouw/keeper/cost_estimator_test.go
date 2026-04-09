package keeper_test

import (
	"fmt"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Cost Estimator Test Helpers
// ---------------------------------------------------------------------------

// registerTestModel stores a model in the keeper's RegisteredModels collection.
func registerTestModel(t *testing.T, k keeper.Keeper, ctx sdk.Context, modelHash []byte, name string, baseUWU uint64) {
	t.Helper()
	model := types.RegisteredModel{
		ModelHash:    modelHash,
		ModelId:      "model-" + name,
		Name:         name,
		Description:  "test model for cost estimation",
		Version:      "v1.0",
		Architecture: "transformer",
		Owner:        "cosmos1testowner",
		IsActive:     true,
		BaseUwuValue: baseUWU,
	}
	modelHashKey := fmt.Sprintf("%x", modelHash)
	require.NoError(t, k.RegisteredModels.Set(ctx, modelHashKey, model))
}

// costTestModelHash returns a deterministic 32-byte hash for testing.
func costTestModelHash(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestEstimateJobCost_TEECheapest(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x01)
	registerTestModel(t, k, ctx, modelHash, "small-bert", 100)

	estimator := keeper.NewCostEstimator(&k)

	teeCost, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)

	hybridCost, err := estimator.EstimateJobCost(ctx, modelHash, "hybrid", 0)
	require.NoError(t, err)

	zkmlCost, err := estimator.EstimateJobCost(ctx, modelHash, "zkml", 0)
	require.NoError(t, err)

	require.True(t, teeCost.TotalEstimate.Amount.LT(hybridCost.TotalEstimate.Amount),
		"TEE (%s) should be cheaper than Hybrid (%s)", teeCost.TotalEstimate, hybridCost.TotalEstimate)
	require.True(t, teeCost.TotalEstimate.Amount.LT(zkmlCost.TotalEstimate.Amount),
		"TEE (%s) should be cheaper than zkML (%s)", teeCost.TotalEstimate, zkmlCost.TotalEstimate)
	require.Equal(t, "high", teeCost.Confidence, "registered model should have high confidence")
}

func TestEstimateJobCost_ZKMLMostExpensive(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x02)
	registerTestModel(t, k, ctx, modelHash, "gpt-large", 500)

	estimator := keeper.NewCostEstimator(&k)

	teeCost, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)
	hybridCost, err := estimator.EstimateJobCost(ctx, modelHash, "hybrid", 0)
	require.NoError(t, err)
	zkmlCost, err := estimator.EstimateJobCost(ctx, modelHash, "zkml", 0)
	require.NoError(t, err)

	require.True(t, zkmlCost.TotalEstimate.Amount.GT(hybridCost.TotalEstimate.Amount),
		"zkML (%s) should be more expensive than Hybrid (%s)", zkmlCost.TotalEstimate, hybridCost.TotalEstimate)
	require.True(t, zkmlCost.TotalEstimate.Amount.GT(teeCost.TotalEstimate.Amount),
		"zkML (%s) should be more expensive than TEE (%s)", zkmlCost.TotalEstimate, teeCost.TotalEstimate)

	// Verify the zkML/TEE ratio is in expected range (zkML has a 3x verification multiplier).
	teeAmt := teeCost.TotalEstimate.Amount.Int64()
	zkmlAmt := zkmlCost.TotalEstimate.Amount.Int64()
	ratio := float64(zkmlAmt) / float64(teeAmt)
	require.Greater(t, ratio, 1.3, "zkML/TEE ratio should be > 1.3")
	require.Less(t, ratio, 3.5, "zkML/TEE ratio should be < 3.5")
}

func TestEstimateJobCost_HybridMiddle(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x03)
	registerTestModel(t, k, ctx, modelHash, "medium-model", 200)

	estimator := keeper.NewCostEstimator(&k)

	teeCost, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)
	hybridCost, err := estimator.EstimateJobCost(ctx, modelHash, "hybrid", 0)
	require.NoError(t, err)
	zkmlCost, err := estimator.EstimateJobCost(ctx, modelHash, "zkml", 0)
	require.NoError(t, err)

	teeAmt := teeCost.TotalEstimate.Amount.Int64()
	hybridAmt := hybridCost.TotalEstimate.Amount.Int64()
	zkmlAmt := zkmlCost.TotalEstimate.Amount.Int64()

	require.Greater(t, hybridAmt, teeAmt, "hybrid should cost more than TEE")
	require.Less(t, hybridAmt, zkmlAmt, "hybrid should cost less than zkML")
}

func TestEstimateJobCost_UrgencyMultiplier(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x04)
	registerTestModel(t, k, ctx, modelHash, "urgency-test", 100)

	estimator := keeper.NewCostEstimator(&k)

	standard, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)
	priority, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 1)
	require.NoError(t, err)
	urgent, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 2)
	require.NoError(t, err)

	require.True(t, priority.TotalEstimate.Amount.GT(standard.TotalEstimate.Amount),
		"priority (%s) should cost more than standard (%s)", priority.TotalEstimate, standard.TotalEstimate)
	require.True(t, urgent.TotalEstimate.Amount.GT(priority.TotalEstimate.Amount),
		"urgent (%s) should cost more than priority (%s)", urgent.TotalEstimate, priority.TotalEstimate)

	require.InDelta(t, 1.0, standard.UrgencyMultiplier, 0.001)
	require.InDelta(t, 1.5, priority.UrgencyMultiplier, 0.001)
	require.InDelta(t, 2.0, urgent.UrgencyMultiplier, 0.001)
}

func TestEstimateJobCost_ModelSizeScaling(t *testing.T) {
	k, ctx := newTestKeeper(t)

	smallHash := costTestModelHash(0x10)
	mediumHash := costTestModelHash(0x11)
	largeHash := costTestModelHash(0x12)

	registerTestModel(t, k, ctx, smallHash, "small", 10)
	registerTestModel(t, k, ctx, mediumHash, "medium", 100)
	registerTestModel(t, k, ctx, largeHash, "large", 1000)

	estimator := keeper.NewCostEstimator(&k)

	smallCost, err := estimator.EstimateJobCost(ctx, smallHash, "tee", 0)
	require.NoError(t, err)
	medCost, err := estimator.EstimateJobCost(ctx, mediumHash, "tee", 0)
	require.NoError(t, err)
	largeCost, err := estimator.EstimateJobCost(ctx, largeHash, "tee", 0)
	require.NoError(t, err)

	require.True(t, medCost.TotalEstimate.Amount.GT(smallCost.TotalEstimate.Amount),
		"medium model (%s) should cost more than small (%s)", medCost.TotalEstimate, smallCost.TotalEstimate)
	require.True(t, largeCost.TotalEstimate.Amount.GT(medCost.TotalEstimate.Amount),
		"large model (%s) should cost more than medium (%s)", largeCost.TotalEstimate, medCost.TotalEstimate)

	t.Logf("Cost scaling: small=%s medium=%s large=%s",
		smallCost.TotalEstimate, medCost.TotalEstimate, largeCost.TotalEstimate)
}

func TestEstimateJobCost_UnknownModel(t *testing.T) {
	k, ctx := newTestKeeper(t)

	unknownHash := costTestModelHash(0xFF)
	estimator := keeper.NewCostEstimator(&k)

	estimate, err := estimator.EstimateJobCost(ctx, unknownHash, "tee", 0)
	require.NoError(t, err, "unknown model should not cause an error")

	require.Equal(t, "low", estimate.Confidence, "unknown model should have low confidence")
	require.True(t, estimate.TotalEstimate.Amount.GT(sdkmath.NewInt(0)),
		"total estimate should be positive even for unknown model")
}

func TestEstimateJobCost_NetworkUtilization(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x20)
	registerTestModel(t, k, ctx, modelHash, "network-test", 100)

	estimator := keeper.NewCostEstimator(&k)

	// With an empty queue, no surcharge.
	baseCost, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)
	require.InDelta(t, 1.0, baseCost.NetworkMultiplier, 0.001,
		"empty queue should have 1.0 network multiplier")

	// Fill the pending queue to exceed the 50% threshold.
	// MaxJobsPerBlock defaults to 10, so >5 pending jobs triggers surcharge.
	for i := 0; i < 8; i++ {
		mh := costTestModelHash(byte(0x30 + i))
		registerTestModel(t, k, ctx, mh, fmt.Sprintf("fill-%d", i), 10)
		job := types.ComputeJob{
			Id:          fmt.Sprintf("fill-job-%d", i),
			ModelHash:   mh,
			InputHash:   costTestModelHash(byte(0x50 + i)),
			RequestedBy: fmt.Sprintf("requester-%d", i),
			ProofType:   types.ProofTypeTEE,
			Purpose:     "test",
			Status:      types.JobStatusPending,
			BlockHeight: ctx.BlockHeight(),
		}
		// Store in pending jobs directly for queue fill simulation.
		require.NoError(t, k.PendingJobs.Set(ctx, job.Id, job))
	}

	loadedCost, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)

	// The loaded cost should be >= the base cost (queue fill adds surcharge).
	require.True(t, loadedCost.TotalEstimate.Amount.GTE(baseCost.TotalEstimate.Amount),
		"loaded cost (%s) should be >= base cost (%s)", loadedCost.TotalEstimate, baseCost.TotalEstimate)

	t.Logf("Network multiplier: empty=%.2f, loaded=%.2f",
		baseCost.NetworkMultiplier, loadedCost.NetworkMultiplier)
}

func TestEstimateJobCost_InvalidVerificationType(t *testing.T) {
	k, ctx := newTestKeeper(t)
	estimator := keeper.NewCostEstimator(&k)

	_, err := estimator.EstimateJobCost(ctx, costTestModelHash(0x01), "invalid", 0)
	require.Error(t, err, "invalid verification type should return error")
	require.Contains(t, err.Error(), "unsupported verification type")
}

func TestEstimateJobCost_BreakdownContents(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x05)
	registerTestModel(t, k, ctx, modelHash, "breakdown-test", 50)

	estimator := keeper.NewCostEstimator(&k)

	estimate, err := estimator.EstimateJobCost(ctx, modelHash, "hybrid", 1)
	require.NoError(t, err)

	requiredKeys := []string{
		"base_fee", "verification_fee", "verification_type",
		"verification_multiplier", "model_size_fee",
		"urgency_multiplier", "network_multiplier", "confidence",
	}
	for _, key := range requiredKeys {
		_, ok := estimate.Breakdown[key]
		require.True(t, ok, "missing breakdown key: %s", key)
	}

	require.Equal(t, "hybrid", estimate.Breakdown["verification_type"])
	require.Equal(t, "breakdown-test", estimate.Breakdown["model_name"])
}

func TestEstimateJobCost_NilModelHash(t *testing.T) {
	k, ctx := newTestKeeper(t)
	estimator := keeper.NewCostEstimator(&k)

	estimate, err := estimator.EstimateJobCost(ctx, nil, "tee", 0)
	require.NoError(t, err, "nil model hash should not cause error")
	require.Equal(t, "low", estimate.Confidence)
}

func TestEstimateJobCost_EmptyModelHash(t *testing.T) {
	k, ctx := newTestKeeper(t)
	estimator := keeper.NewCostEstimator(&k)

	estimate, err := estimator.EstimateJobCost(ctx, []byte{}, "tee", 0)
	require.NoError(t, err, "empty model hash should not cause error")
	require.Equal(t, "low", estimate.Confidence)
}

func TestEstimateJobCost_UnknownUrgencyDefaultsToStandard(t *testing.T) {
	k, ctx := newTestKeeper(t)
	modelHash := costTestModelHash(0x06)
	registerTestModel(t, k, ctx, modelHash, "urgency-default", 100)

	estimator := keeper.NewCostEstimator(&k)

	standard, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 0)
	require.NoError(t, err)

	highUrgency, err := estimator.EstimateJobCost(ctx, modelHash, "tee", 99)
	require.NoError(t, err)

	// Unknown urgency (99) should default to standard (1.0x).
	require.Equal(t, standard.TotalEstimate, highUrgency.TotalEstimate,
		"unknown urgency should default to standard pricing")
}

func FuzzEstimateJobCost(f *testing.F) {
	// Seed corpus with representative inputs.
	f.Add([]byte{0x01, 0x02, 0x03}, "tee", uint32(0))
	f.Add([]byte{}, "hybrid", uint32(1))
	f.Add(costTestModelHash(0xFF), "zkml", uint32(2))
	f.Add(costTestModelHash(0x00), "tee", uint32(99))

	f.Fuzz(func(t *testing.T, modelHashSeed []byte, verificationType string, urgency uint32) {
		k, ctx := newTestKeeper(t)
		estimator := keeper.NewCostEstimator(&k)

		validTypes := map[string]bool{"tee": true, "hybrid": true, "zkml": true}

		estimate, err := estimator.EstimateJobCost(ctx, modelHashSeed, verificationType, urgency)
		if !validTypes[verificationType] {
			require.Error(t, err, "invalid verification type %q should return error", verificationType)
			return
		}

		require.NoError(t, err)

		// Invariants that must hold for all valid inputs.
		require.True(t, estimate.TotalEstimate.Amount.GT(sdkmath.NewInt(0)),
			"total estimate must be positive")
		require.GreaterOrEqual(t, estimate.UrgencyMultiplier, 1.0,
			"urgency multiplier must be >= 1.0")
		require.GreaterOrEqual(t, estimate.NetworkMultiplier, 1.0,
			"network multiplier must be >= 1.0")
		require.Contains(t, []string{"high", "low"}, estimate.Confidence,
			"confidence must be high or low")
	})
}
