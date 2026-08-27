package keeper

import (
	"encoding/json"
	"fmt"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// Energy accounting keeper logic: persist each job's measured WorkReceipt and
// maintain running network totals for energy, cost, and carbon. Every figure is
// measured (or a labeled device-profile estimate); nothing is fabricated. All
// arithmetic is integer-only so consensus state is deterministic.

// Named running aggregates kept under EnergyAggregateKeyPrefix.
const (
	aggUsefulFacilityUJ = "useful_facility_uj"
	aggOverheadUJ       = "overhead_uj"
	aggCostMicroUSD     = "cost_micro_usd"
	aggCarbonMg         = "carbon_mg"
	aggPoWWasteUJ       = "pow_waste_uj"
	aggMeasuredJobs     = "measured_jobs"
	aggBasis            = "basis"
)

// EnergyAggregates is the network-wide measured energy picture.
type EnergyAggregates struct {
	UsefulFacilityMicrojoules     sdkmath.Int
	OverheadMicrojoules           sdkmath.Int
	CostMicroUSD                  sdkmath.Int
	CarbonMilligrams              sdkmath.Int
	PoWEquivalentWasteMicrojoules sdkmath.Int
	MeasuredJobCount              sdkmath.Int
	Basis                         types.EnergyBasis
}

// UsefulWorkRatioMilli is the measured share of energy spent on useful work,
// in per-mille (1000 = 100%). Returns 0 when no energy has been measured —
// never a configured target.
func (a EnergyAggregates) UsefulWorkRatioMilli() int64 {
	total := a.UsefulFacilityMicrojoules.Add(a.OverheadMicrojoules)
	if !total.IsPositive() {
		return 0
	}
	return a.UsefulFacilityMicrojoules.MulRaw(1000).Quo(total).Int64()
}

// GetEnergyParams returns the stored energy conversion factors, or the defaults
// if none have been set.
func (k Keeper) GetEnergyParams(ctx sdk.Context) (types.EnergyParams, error) {
	if k.storeService == nil {
		return types.EnergyParams{}, fmt.Errorf("store service not configured")
	}
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.EnergyParamsKey)
	if err != nil {
		return types.EnergyParams{}, err
	}
	if len(bz) == 0 {
		return types.DefaultEnergyParams(), nil
	}
	var params types.EnergyParams
	if err := json.Unmarshal(bz, &params); err != nil {
		return types.EnergyParams{}, fmt.Errorf("decode energy params: %w", err)
	}
	return params, nil
}

// SetEnergyParams validates and stores the energy conversion factors.
func (k Keeper) SetEnergyParams(ctx sdk.Context, params types.EnergyParams) error {
	if k.storeService == nil {
		return fmt.Errorf("store service not configured")
	}
	if err := params.Validate(); err != nil {
		return err
	}
	bz, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode energy params: %w", err)
	}
	store := k.storeService.OpenKVStore(ctx)
	return store.Set(types.EnergyParamsKey, bz)
}

// RecordWorkReceipt validates a job's measured receipt, persists it, and folds
// its energy, cost, and carbon into the running network aggregates. Returns the
// receipt's canonical hash so the caller can bind it into the Digital Seal.
func (k Keeper) RecordWorkReceipt(ctx sdk.Context, receipt types.WorkReceipt) ([]byte, error) {
	if k.storeService == nil {
		return nil, fmt.Errorf("store service not configured")
	}
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	store := k.storeService.OpenKVStore(ctx)

	// One receipt per job: refuse to double-count.
	key := types.WorkReceiptKey(receipt.JobID)
	existing, err := store.Get(key)
	if err != nil {
		return nil, err
	}
	if len(existing) != 0 {
		return nil, fmt.Errorf("work receipt already recorded for job %s", receipt.JobID)
	}

	params, err := k.GetEnergyParams(ctx)
	if err != nil {
		return nil, err
	}

	bz, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode work receipt: %w", err)
	}
	if err := store.Set(key, bz); err != nil {
		return nil, err
	}

	// Fold measured quantities into the running totals.
	if err := k.addEnergyAggregate(ctx, aggUsefulFacilityUJ, receipt.FacilityMicrojoules(params)); err != nil {
		return nil, err
	}
	if err := k.addEnergyAggregate(ctx, aggCostMicroUSD, receipt.CostMicroUSD(params)); err != nil {
		return nil, err
	}
	if err := k.addEnergyAggregate(ctx, aggCarbonMg, receipt.CarbonMilligrams(params)); err != nil {
		return nil, err
	}
	if err := k.addEnergyAggregate(ctx, aggPoWWasteUJ, receipt.PoWEquivalentWasteMicrojoules(params)); err != nil {
		return nil, err
	}
	if err := k.addEnergyAggregate(ctx, aggMeasuredJobs, sdkmath.OneInt()); err != nil {
		return nil, err
	}
	if err := k.combineBasis(ctx, receipt.Basis); err != nil {
		return nil, err
	}
	return receipt.Hash(), nil
}

// RecordConsensusOverheadMicrojoules adds measured consensus/overhead energy so
// the useful-work ratio reflects measured reality, not a configured target.
func (k Keeper) RecordConsensusOverheadMicrojoules(ctx sdk.Context, microjoules sdkmath.Int) error {
	if microjoules.IsNil() || !microjoules.IsPositive() {
		return nil
	}
	return k.addEnergyAggregate(ctx, aggOverheadUJ, microjoules)
}

// GetWorkReceipt returns the stored receipt for a job, if present.
func (k Keeper) GetWorkReceipt(ctx sdk.Context, jobID string) (types.WorkReceipt, bool, error) {
	if k.storeService == nil {
		return types.WorkReceipt{}, false, fmt.Errorf("store service not configured")
	}
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.WorkReceiptKey(jobID))
	if err != nil {
		return types.WorkReceipt{}, false, err
	}
	if len(bz) == 0 {
		return types.WorkReceipt{}, false, nil
	}
	var receipt types.WorkReceipt
	if err := json.Unmarshal(bz, &receipt); err != nil {
		return types.WorkReceipt{}, false, fmt.Errorf("decode work receipt: %w", err)
	}
	return receipt, true, nil
}

// GetEnergyAggregates returns the network-wide measured energy picture.
func (k Keeper) GetEnergyAggregates(ctx sdk.Context) (EnergyAggregates, error) {
	useful, err := k.getEnergyAggregate(ctx, aggUsefulFacilityUJ)
	if err != nil {
		return EnergyAggregates{}, err
	}
	overhead, err := k.getEnergyAggregate(ctx, aggOverheadUJ)
	if err != nil {
		return EnergyAggregates{}, err
	}
	cost, err := k.getEnergyAggregate(ctx, aggCostMicroUSD)
	if err != nil {
		return EnergyAggregates{}, err
	}
	carbon, err := k.getEnergyAggregate(ctx, aggCarbonMg)
	if err != nil {
		return EnergyAggregates{}, err
	}
	powWaste, err := k.getEnergyAggregate(ctx, aggPoWWasteUJ)
	if err != nil {
		return EnergyAggregates{}, err
	}
	jobs, err := k.getEnergyAggregate(ctx, aggMeasuredJobs)
	if err != nil {
		return EnergyAggregates{}, err
	}
	basis, err := k.getBasis(ctx)
	if err != nil {
		return EnergyAggregates{}, err
	}
	return EnergyAggregates{
		UsefulFacilityMicrojoules:     useful,
		OverheadMicrojoules:           overhead,
		CostMicroUSD:                  cost,
		CarbonMilligrams:              carbon,
		PoWEquivalentWasteMicrojoules: powWaste,
		MeasuredJobCount:              jobs,
		Basis:                         basis,
	}, nil
}

func (k Keeper) addEnergyAggregate(ctx sdk.Context, field string, delta sdkmath.Int) error {
	if delta.IsNil() || delta.IsZero() {
		return nil // adding zero (e.g. a sub-threshold cost) is a no-op
	}
	current, err := k.getEnergyAggregate(ctx, field)
	if err != nil {
		return err
	}
	store := k.storeService.OpenKVStore(ctx)
	return store.Set(types.EnergyAggregateKey(field), []byte(current.Add(delta).String()))
}

func (k Keeper) getEnergyAggregate(ctx sdk.Context, field string) (sdkmath.Int, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.EnergyAggregateKey(field))
	if err != nil {
		return sdkmath.ZeroInt(), err
	}
	if len(bz) == 0 {
		return sdkmath.ZeroInt(), nil
	}
	value, ok := sdkmath.NewIntFromString(string(bz))
	if !ok {
		return sdkmath.ZeroInt(), fmt.Errorf("invalid energy aggregate for %s", field)
	}
	return value, nil
}

func (k Keeper) combineBasis(ctx sdk.Context, basis types.EnergyBasis) error {
	current, err := k.getBasis(ctx)
	if err != nil {
		return err
	}
	store := k.storeService.OpenKVStore(ctx)
	return store.Set(types.EnergyAggregateKey(aggBasis), []byte(types.CombineEnergyBasis(current, basis)))
}

func (k Keeper) getBasis(ctx sdk.Context) (types.EnergyBasis, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.EnergyAggregateKey(aggBasis))
	if err != nil {
		return types.EnergyBasisMeasured, err
	}
	if len(bz) == 0 {
		// No measurement yet: seed with measured so the first real receipt sets
		// the true aggregate basis via combine.
		return types.EnergyBasisMeasured, nil
	}
	return types.EnergyBasis(bz), nil
}
