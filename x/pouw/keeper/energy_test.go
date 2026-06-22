package keeper

import (
	"bytes"
	"testing"

	sdkmath "cosmossdk.io/math"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/types"
)

func energyReceipt(jobID string, basis types.EnergyBasis) types.WorkReceipt {
	return types.WorkReceipt{
		JobID:              jobID,
		Validator:          "aethelredvaloper1abc",
		DeviceClass:        "nvidia-h100",
		DeviceMilliseconds: 3_600_000, // 1 hour
		AvgPowerMilliwatts: 1_000_000, // 1000 W -> 1 kWh device, 1.2 kWh facility
		Basis:              basis,
		UsefulWorkUnits:    500,
	}
}

func TestRecordWorkReceiptPersistsAndAggregates(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	r := energyReceipt("job-1", types.EnergyBasisMeasured)

	hash, err := k.RecordWorkReceipt(ctx, r)
	require.NoError(t, err)
	require.True(t, bytes.Equal(hash, r.Hash()), "returned hash must bind the receipt")

	got, found, err := k.GetWorkReceipt(ctx, "job-1")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, r, got)

	agg, err := k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(4_320_000_000_000), agg.UsefulFacilityMicrojoules)
	require.Equal(t, sdkmath.NewInt(96_000), agg.CostMicroUSD)
	require.Equal(t, sdkmath.NewInt(480_000), agg.CarbonMilligrams)
	require.Equal(t, sdkmath.OneInt(), agg.MeasuredJobCount)
	require.Equal(t, types.EnergyBasisMeasured, agg.Basis)
}

func TestRecordWorkReceiptIsIdempotentPerJob(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	r := energyReceipt("job-dup", types.EnergyBasisMeasured)
	_, err := k.RecordWorkReceipt(ctx, r)
	require.NoError(t, err)
	_, err = k.RecordWorkReceipt(ctx, r)
	require.Error(t, err, "a job's receipt must not be double-counted")

	agg, err := k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.Equal(t, sdkmath.OneInt(), agg.MeasuredJobCount)
}

func TestUsefulWorkRatioUsesMeasuredOverhead(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	_, err := k.RecordWorkReceipt(ctx, energyReceipt("job-1", types.EnergyBasisMeasured))
	require.NoError(t, err)
	// Useful facility energy is 4.32e12 uJ; add 1.08e12 uJ overhead -> 80% useful.
	require.NoError(t, k.RecordConsensusOverheadMicrojoules(ctx, sdkmath.NewInt(1_080_000_000_000)))

	agg, err := k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(800), agg.UsefulWorkRatioMilli()) // 0.80
}

func TestMixedBasisDegradesAggregate(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	_, err := k.RecordWorkReceipt(ctx, energyReceipt("job-m", types.EnergyBasisMeasured))
	require.NoError(t, err)
	agg, err := k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.Equal(t, types.EnergyBasisMeasured, agg.Basis)

	// A device-profile estimate downgrades the whole aggregate's basis.
	_, err = k.RecordWorkReceipt(ctx, energyReceipt("job-e", types.EnergyBasisDeviceProfile))
	require.NoError(t, err)
	agg, err = k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.Equal(t, types.EnergyBasisDeviceProfile, agg.Basis)
	require.Equal(t, sdkmath.NewInt(2), agg.MeasuredJobCount)
}

func TestRecordWorkReceiptRejectsInvalid(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	bad := energyReceipt("job-bad", types.EnergyBasisMeasured)
	bad.AvgPowerMilliwatts = 0
	_, err := k.RecordWorkReceipt(ctx, bad)
	require.Error(t, err)

	_, found, err := k.GetWorkReceipt(ctx, "job-bad")
	require.NoError(t, err)
	require.False(t, found, "an invalid receipt must not be persisted")
}

func TestEnergyParamsRoundTripAndValidation(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	// Default when unset.
	p, err := k.GetEnergyParams(ctx)
	require.NoError(t, err)
	require.Equal(t, types.DefaultEnergyParams(), p)

	// Set a custom (valid) model and read it back.
	custom := types.EnergyParams{PueMilli: 1100, GridCarbonGramsPerKWh: 250, ElectricityCostMicroUSDPerKWh: 60000, PoWBaselineWastedRatioMilli: 1000}
	require.NoError(t, k.SetEnergyParams(ctx, custom))
	got, err := k.GetEnergyParams(ctx)
	require.NoError(t, err)
	require.Equal(t, custom, got)

	// Invalid params are rejected.
	require.Error(t, k.SetEnergyParams(ctx, types.EnergyParams{PueMilli: 900, GridCarbonGramsPerKWh: 250, ElectricityCostMicroUSDPerKWh: 60000}))
}

func TestEnergyAggregatesEmptyIsZero(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	agg, err := k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.True(t, agg.UsefulFacilityMicrojoules.IsZero())
	require.True(t, agg.CostMicroUSD.IsZero())
	require.True(t, agg.MeasuredJobCount.IsZero())
	require.Equal(t, int64(0), agg.UsefulWorkRatioMilli()) // no fabricated ratio
}
