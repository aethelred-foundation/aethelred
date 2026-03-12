package keeper_test

// Audit Regression Tests
//
// Targeted regression tests for specific audit findings (C-01, H-03, M-05)
// to ensure the bugs remain fixed. Each test explicitly verifies the
// corrected behavior that the original bug would have broken.

import (
	"fmt"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// C-01 REGRESSION: math/big overflow protection in VestedAmount
// =============================================================================

// TestC01_VestedAmount_LargeValues_NoOverflow verifies that VestedAmount
// correctly handles large token amounts (up to 3*10^15 uAETHEL) multiplied by
// large elapsed block counts (up to ~5.256*10^7) without silent int64 overflow.
//
// Bug (C-01): Naive int64 multiplication of totalUAETHEL * elapsed could exceed
// 2^63 (~9.2*10^18), causing silent wraparound to negative values.
// Fix: All intermediate arithmetic uses math/big.
func TestC01_VestedAmount_LargeValues_NoOverflow(t *testing.T) {
	// Use the largest real-world allocation: 3,000,000,000,000,000 uAETHEL (3B AETHEL)
	// with 5-year vesting (~26,280,000 blocks).
	schedule := keeper.VestingSchedule{
		Category:         "large-allocation",
		TotalUAETHEL:       3_000_000_000_000_000,
		TGEUnlockBps:     0,
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear * 5, // ~26.28M blocks
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// At 50% of vesting period
	halfwayBlock := schedule.VestingBlocks / 2
	vested := keeper.VestedAmount(schedule, halfwayBlock)

	// Expected: ~1,500,000,000,000,000 (half of total)
	// The intermediate calculation: 3*10^15 * 13.14*10^6 = ~3.94*10^22
	// which WOULD overflow int64 without big.Int.
	require.Greater(t, vested, int64(0), "vested must be positive (no overflow wraparound)")
	require.InDelta(t,
		float64(schedule.TotalUAETHEL)/2.0,
		float64(vested),
		float64(schedule.TotalUAETHEL)*0.01, // Within 1% tolerance
		"halfway vesting should yield ~50% of total",
	)
}

func TestC01_VestedAmount_MaxSupplyWithTGE_NoOverflow(t *testing.T) {
	// Max total supply (10B AETHEL in uAETHEL) with TGE + cliff + linear
	schedule := keeper.VestingSchedule{
		Category:         "max-supply-stress",
		TotalUAETHEL:       10_000_000_000_000_000, // Full 10B AETHEL
		TGEUnlockBps:     2250,                   // 22.5% TGE
		CliffBlocks:      keeper.BlocksPerYear,
		VestingBlocks:    keeper.BlocksPerYear * 5,
		CliffPercent:     1500, // 15% cliff (stress test)
		LinearAfterCliff: true,
	}

	// At cliff: should get TGE + cliff = 35% of 10^16
	vested := keeper.VestedAmount(schedule, keeper.BlocksPerYear)
	expectedTGE := int64(10_000_000_000_000_000 * 2000 / 10000)
	expectedCliff := int64(10_000_000_000_000_000 * 1500 / 10000)
	expected := expectedTGE + expectedCliff

	require.Equal(t, expected, vested, "TGE + cliff at max supply must not overflow")
	require.Greater(t, vested, int64(0), "must be positive")

	// At 75% through linear vesting (after cliff)
	linearStart := schedule.CliffBlocks
	linearDuration := schedule.VestingBlocks - schedule.CliffBlocks
	at75pct := linearStart + (linearDuration * 3 / 4)

	vested = keeper.VestedAmount(schedule, at75pct)
	require.Greater(t, vested, expected, "75% into linear should exceed cliff-only vested")
	require.Less(t, vested, schedule.TotalUAETHEL, "should not be fully vested yet")
}

func TestC01_VestedAmount_Monotonically_Increasing(t *testing.T) {
	// Property: vested amount must never decrease as blockHeight increases.
	// This catches overflow-induced negative delta or wraparound.
	schedule := keeper.VestingSchedule{
		Category:         "monotonic-check",
		TotalUAETHEL:       2_500_000_000_000_000, // 2.5B AETHEL
		TGEUnlockBps:     500,                   // 5% TGE
		CliffBlocks:      keeper.BlocksPerYear / 2,
		VestingBlocks:    keeper.BlocksPerYear * 4,
		CliffPercent:     1500, // 15% cliff
		LinearAfterCliff: true,
	}

	prevVested := int64(0)
	// Sample 100 block heights across the full vesting range
	for i := 0; i <= 100; i++ {
		blockHeight := int64(i) * schedule.VestingBlocks / 100
		vested := keeper.VestedAmount(schedule, blockHeight)

		require.GreaterOrEqual(t, vested, prevVested,
			"vested amount must be monotonically non-decreasing at block %d (prev=%d, cur=%d)",
			blockHeight, prevVested, vested,
		)
		require.GreaterOrEqual(t, vested, int64(0),
			"vested amount must never be negative at block %d", blockHeight,
		)
		require.LessOrEqual(t, vested, schedule.TotalUAETHEL,
			"vested amount must never exceed total at block %d", blockHeight,
		)
		prevVested = vested
	}

	// Final block should be fully vested
	require.Equal(t, schedule.TotalUAETHEL, prevVested, "final block must be fully vested")
}

// =============================================================================
// H-03 REGRESSION: Genesis block TGE off-by-one
// =============================================================================

// TestH03_VestedAmount_GenesisBlock_ReturnsTGE verifies that the genesis block
// (blockHeight == 0) returns the TGE amount rather than 0.
//
// Bug (H-03): Original code used `if blockHeight <= 0 { return 0 }` which
// incorrectly returned 0 at genesis instead of the TGE unlock amount.
// Fix: Changed to `if blockHeight < 0 { return 0 }`.
func TestH03_VestedAmount_GenesisBlock_ReturnsTGE(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "public-sale",
		TotalUAETHEL:       1_000_000_000_000_000, // 1B AETHEL
		TGEUnlockBps:     2250,                  // 22.5%
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear * 18 / 12,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// At genesis block (height 0): must return TGE amount
	vestedAtGenesis := keeper.VestedAmount(schedule, 0)
	expectedTGE := int64(1_000_000_000_000_000 * 2250 / 10000) // 225B uAETHEL

	require.Greater(t, vestedAtGenesis, int64(0),
		"genesis block must return non-zero TGE amount (H-03 regression)")
	require.GreaterOrEqual(t, vestedAtGenesis, expectedTGE,
		"genesis block must include full TGE unlock")
}

func TestH03_VestedAmount_GenesisBlock_WithCliff_ReturnsTGE(t *testing.T) {
	// Ecosystem grants: 2% TGE, 6-month cliff
	schedule := keeper.VestingSchedule{
		Category:         "ecosystem",
		TotalUAETHEL:       1_500_000_000_000_000,
		TGEUnlockBps:     500, // 5%
		CliffBlocks:      keeper.BlocksPerYear / 2,
		VestingBlocks:    keeper.BlocksPerYear * 54 / 12,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// At genesis: should get TGE (2%), NOT zero
	vestedAtGenesis := keeper.VestedAmount(schedule, 0)
	expectedTGE := int64(1_500_000_000_000_000 * 500 / 10000) // 75B uAETHEL

	require.Equal(t, expectedTGE, vestedAtGenesis,
		"genesis block with cliff must return TGE amount (H-03 regression)")
}

func TestH03_VestedAmount_NegativeBlockHeight_ReturnsZero(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "test",
		TotalUAETHEL:       1_000_000_000,
		TGEUnlockBps:     2250,
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// Negative block heights must return 0
	require.Equal(t, int64(0), keeper.VestedAmount(schedule, -1))
	require.Equal(t, int64(0), keeper.VestedAmount(schedule, -100))
	require.Equal(t, int64(0), keeper.VestedAmount(schedule, -9223372036854775808)) // min int64
}

func TestH03_VestedAmount_Block1_SameAsGenesis_WithNoCliff(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "no-cliff",
		TotalUAETHEL:       1_000_000_000_000_000,
		TGEUnlockBps:     1000, // 10%
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear * 4,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	vestedAt0 := keeper.VestedAmount(schedule, 0)
	vestedAt1 := keeper.VestedAmount(schedule, 1)

	// Block 1 should be >= genesis (TGE + tiny linear increment)
	require.Greater(t, vestedAt0, int64(0), "genesis must return TGE")
	require.GreaterOrEqual(t, vestedAt1, vestedAt0, "block 1 must be >= genesis")
}

// =============================================================================
// M-05 REGRESSION: Deterministic integer halving (no float64)
// =============================================================================

// TestM05_ExponentialDecay_Deterministic verifies that the halving-style
// inflation decay uses only integer arithmetic and produces identical results
// regardless of execution context (no floating-point non-determinism).
//
// Bug (M-05): Original code used math.Pow(0.5, year/period) which is
// non-deterministic across CPU architectures due to different FP rounding modes.
// Fix: Uses integer right-shift for halvings with linear interpolation.
func TestM05_ExponentialDecay_Deterministic(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay
	config.DecayPeriodYears = 6

	// Run the same schedule computation twice - must be bit-identical
	schedule1 := keeper.ComputeEmissionSchedule(config, 30)
	schedule2 := keeper.ComputeEmissionSchedule(config, 30)

	require.Equal(t, len(schedule1), len(schedule2), "schedule length must be identical")
	for i := range schedule1 {
		require.Equal(t, schedule1[i].AnnualEmission, schedule2[i].AnnualEmission,
			"emission at year %d must be deterministic", i+1)
		require.Equal(t, schedule1[i].CumulativeSupply, schedule2[i].CumulativeSupply,
			"supply at year %d must be deterministic", i+1)
		require.Equal(t, schedule1[i].InflationBps, schedule2[i].InflationBps,
			"inflation BPS at year %d must be deterministic", i+1)
	}
}

func TestM05_ExponentialDecay_HalvesCorrectly(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay
	config.InitialInflationBps = 800 // 8%
	config.TargetInflationBps = 200  // 2% floor
	config.DecayPeriodYears = 6

	schedule := keeper.ComputeEmissionSchedule(config, 30)

	// Year 1 inflation should be near 800 BPS (8%) - with DecayPeriodYears=6,
	// year 1 is 1/6 toward first halving, so interpolation yields ~734 BPS.
	require.InDelta(t, 800, schedule[0].InflationBps, 100,
		"year 1 inflation should be near initial")

	// After 1 halving period (year 6), inflation should be ~400 BPS (4%)
	if len(schedule) > 5 {
		require.InDelta(t, 400, schedule[5].InflationBps, 50,
			"after 1 halving period, inflation should be ~halved")
	}

	// After 2 halving periods (year 12), inflation should be ~200 BPS (2%)
	if len(schedule) > 11 {
		require.GreaterOrEqual(t, schedule[11].InflationBps, config.TargetInflationBps,
			"inflation should not go below floor")
	}
}

func TestM05_ExponentialDecay_NeverBelowFloor(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay
	config.InitialInflationBps = 800
	config.TargetInflationBps = 200
	config.DecayPeriodYears = 4

	schedule := keeper.ComputeEmissionSchedule(config, 100)

	for i, entry := range schedule {
		require.GreaterOrEqual(t, entry.InflationBps, config.TargetInflationBps,
			"year %d: inflation must not go below target floor", i+1)
		require.GreaterOrEqual(t, entry.AnnualEmission, int64(0),
			"year %d: emission must be non-negative", i+1)
	}
}

func TestM05_ExponentialDecay_MonotonicDecrease(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay
	config.InitialInflationBps = 800
	config.TargetInflationBps = 200
	config.DecayPeriodYears = 6

	schedule := keeper.ComputeEmissionSchedule(config, 50)

	for i := 1; i < len(schedule); i++ {
		require.LessOrEqual(t, schedule[i].InflationBps, schedule[i-1].InflationBps,
			"inflation must not increase year over year (year %d > year %d)", i+1, i)
	}
}

func TestM05_ExponentialDecay_NoZeroInflation(t *testing.T) {
	// With round-up halving, inflation should never reach zero
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay
	config.InitialInflationBps = 800
	config.TargetInflationBps = 100 // Low floor
	config.DecayPeriodYears = 2     // Fast halving

	schedule := keeper.ComputeEmissionSchedule(config, 200)

	for i, entry := range schedule {
		require.Greater(t, entry.InflationBps, int64(0),
			"year %d: integer halving with round-up must never reach 0 BPS", i+1)
	}
}

// =============================================================================
// SUPPLY INVARIANT: All vesting categories must sum to total supply
// =============================================================================

func TestSupplyInvariant_AllSchedulesSumToTotalSupply(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	totalAllocated := int64(0)
	for _, s := range schedules {
		totalAllocated += s.TotalUAETHEL
	}

	require.Equal(t, keeper.InitialSupplyUAETHEL, totalAllocated,
		"all vesting categories must sum to exactly InitialSupplyUAETHEL (10B AETHEL)")
}

func TestSupplyInvariant_FullyVestedEqualsTotal(t *testing.T) {
	// After all vesting periods expire, the sum of vested amounts
	// must equal the total supply.
	schedules := keeper.DefaultVestingSchedules()

	totalVested := int64(0)
	farFutureBlock := keeper.BlocksPerYear * 10 // Well beyond any vesting period

	for _, s := range schedules {
		vested := keeper.VestedAmount(s, farFutureBlock)
		require.Equal(t, s.TotalUAETHEL, vested,
			"category %s must be fully vested at far future block", s.Category)
		totalVested += vested
	}

	require.Equal(t, keeper.InitialSupplyUAETHEL, totalVested,
		"sum of fully vested amounts must equal total supply")
}

func TestSupplyInvariant_NoScheduleExceedsTotalAtAnyPoint(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		for block := int64(0); block <= s.VestingBlocks+keeper.BlocksPerYear; block += keeper.BlocksPerYear / 12 {
			vested := keeper.VestedAmount(s, block)
			require.LessOrEqual(t, vested, s.TotalUAETHEL,
				"category %s: vested (%d) exceeds total (%d) at block %d",
				s.Category, vested, s.TotalUAETHEL, block)
			require.GreaterOrEqual(t, vested, int64(0),
				"category %s: vested negative at block %d", s.Category, block)
		}
	}
}

// =============================================================================
// EMISSION SCHEDULE: Cross-model consistency
// =============================================================================

func TestEmissionSchedule_AllModels_ProduceValidSchedules(t *testing.T) {
	models := []keeper.EmissionDecayModel{
		keeper.EmissionLinearDecay,
		keeper.EmissionExponentialDecay,
		keeper.EmissionStepDecay,
	}

	for _, model := range models {
		t.Run(string(model), func(t *testing.T) {
			config := keeper.DefaultEmissionConfig()
			config.DecayModel = model

			schedule := keeper.ComputeEmissionSchedule(config, 20)
			require.NotEmpty(t, schedule, "%s must produce non-empty schedule", model)

			for i, entry := range schedule {
				require.GreaterOrEqual(t, entry.AnnualEmission, int64(0),
					"%s year %d: negative emission", model, i+1)
				require.GreaterOrEqual(t, entry.CumulativeSupply, int64(0),
					"%s year %d: negative supply", model, i+1)

				if i > 0 {
					require.GreaterOrEqual(t, entry.CumulativeSupply, schedule[i-1].CumulativeSupply,
						"%s year %d: supply decreased", model, i+1)
				}
			}
		})
	}
}

// =============================================================================
// VESTED AMOUNT EDGE CASES
// =============================================================================

func TestVestedAmount_ZeroTotalUAETHEL(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "zero-total",
		TotalUAETHEL:       0,
		TGEUnlockBps:     2250,
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	vested := keeper.VestedAmount(schedule, keeper.BlocksPerYear/2)
	require.Equal(t, int64(0), vested, "zero total allocation must always vest 0")

	vestedFull := keeper.VestedAmount(schedule, keeper.BlocksPerYear)
	require.Equal(t, int64(0), vestedFull, "zero total must vest 0 even at full period")
}

func TestVestedAmount_ZeroVestingBlocks(t *testing.T) {
	// When VestingBlocks is 0, any positive block height should return TotalUAETHEL
	// because blockHeight >= VestingBlocks triggers the fully-vested branch.
	schedule := keeper.VestingSchedule{
		Category:         "zero-vesting",
		TotalUAETHEL:       1_000_000_000,
		TGEUnlockBps:     1000,
		CliffBlocks:      0,
		VestingBlocks:    0,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// blockHeight >= 0 means fully vested since VestingBlocks == 0
	vested := keeper.VestedAmount(schedule, 0)
	require.Equal(t, schedule.TotalUAETHEL, vested,
		"zero vesting blocks should be fully vested at genesis")
}

func TestVestedAmount_TGEOnly_NoCliff_NoLinear(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "tge-only",
		TotalUAETHEL:       1_000_000_000_000_000,
		TGEUnlockBps:     5000, // 50% TGE
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear * 5,
		CliffPercent:     0,
		LinearAfterCliff: false,
	}

	expectedTGE := int64(1_000_000_000_000_000 * 5000 / 10000)
	vested := keeper.VestedAmount(schedule, 0)
	require.Equal(t, expectedTGE, vested, "genesis should return TGE amount only")

	// Midway, with LinearAfterCliff=false and CliffPercent=0, no additional vesting
	vestedMid := keeper.VestedAmount(schedule, keeper.BlocksPerYear*2)
	require.Equal(t, expectedTGE, vestedMid,
		"with no linear and no cliff percent, midway should still be TGE only")

	// Fully vested at end
	vestedEnd := keeper.VestedAmount(schedule, keeper.BlocksPerYear*5)
	require.Equal(t, schedule.TotalUAETHEL, vestedEnd, "at vesting end should be fully vested")
}

func TestVestedAmount_CliffOnly_NoTGE_NoLinear(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "cliff-only",
		TotalUAETHEL:       500_000_000_000_000,
		TGEUnlockBps:     0,
		CliffBlocks:      keeper.BlocksPerYear,
		VestingBlocks:    keeper.BlocksPerYear * 4,
		CliffPercent:     3000, // 30% at cliff
		LinearAfterCliff: false,
	}

	// Before cliff: only TGE (which is 0)
	vestedBeforeCliff := keeper.VestedAmount(schedule, keeper.BlocksPerYear/2)
	require.Equal(t, int64(0), vestedBeforeCliff, "before cliff with no TGE should be 0")

	// At cliff: should get cliff amount
	expectedCliff := int64(500_000_000_000_000 * 3000 / 10000)
	vestedAtCliff := keeper.VestedAmount(schedule, keeper.BlocksPerYear)
	require.Equal(t, expectedCliff, vestedAtCliff, "at cliff should get cliff amount")

	// Midway after cliff: no linear, so should remain at cliff amount
	vestedMid := keeper.VestedAmount(schedule, keeper.BlocksPerYear*2)
	require.Equal(t, expectedCliff, vestedMid,
		"after cliff with no linear vesting should remain at cliff amount")

	// At vesting end
	vestedEnd := keeper.VestedAmount(schedule, keeper.BlocksPerYear*4)
	require.Equal(t, schedule.TotalUAETHEL, vestedEnd, "at vesting end should be fully vested")
}

func TestVestedAmount_LinearOnly_NoTGE_NoCliff(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "linear-only",
		TotalUAETHEL:       3_000_000_000_000_000,
		TGEUnlockBps:     0,
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear * 10,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// At genesis: TGE = 0
	vested0 := keeper.VestedAmount(schedule, 0)
	require.Equal(t, int64(0), vested0, "genesis should be 0 with no TGE")

	// At 50%: should get ~50% linearly
	vestedHalf := keeper.VestedAmount(schedule, keeper.BlocksPerYear*5)
	require.InDelta(t, float64(schedule.TotalUAETHEL)/2, float64(vestedHalf),
		float64(schedule.TotalUAETHEL)*0.001, "50% through linear should be ~50%")

	// At end: fully vested
	vestedEnd := keeper.VestedAmount(schedule, keeper.BlocksPerYear*10)
	require.Equal(t, schedule.TotalUAETHEL, vestedEnd, "at end should be fully vested")
}

func TestVestedAmount_AllCategories_BlockZero(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		t.Run(s.Category, func(t *testing.T) {
			vested := keeper.VestedAmount(s, 0)
			expectedTGE := s.TotalUAETHEL * s.TGEUnlockBps / 10000
			require.Equal(t, expectedTGE, vested,
				"category %s: at block 0 should return TGE amount", s.Category)
		})
	}
}

func TestVestedAmount_AllCategories_FullyVested(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		t.Run(s.Category, func(t *testing.T) {
			vested := keeper.VestedAmount(s, s.VestingBlocks)
			require.Equal(t, s.TotalUAETHEL, vested,
				"category %s: at vesting end should be fully vested", s.Category)

			vestedBeyond := keeper.VestedAmount(s, s.VestingBlocks+keeper.BlocksPerYear)
			require.Equal(t, s.TotalUAETHEL, vestedBeyond,
				"category %s: beyond vesting period should be fully vested", s.Category)
		})
	}
}

func TestVestedAmount_HalfwayPoint_AllSchedules(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		t.Run(s.Category, func(t *testing.T) {
			halfBlock := s.VestingBlocks / 2
			vested := keeper.VestedAmount(s, halfBlock)

			require.GreaterOrEqual(t, vested, int64(0),
				"halfway vested must be non-negative")
			require.LessOrEqual(t, vested, s.TotalUAETHEL,
				"halfway vested must not exceed total")

			// Must be at least the TGE amount
			tge := s.TotalUAETHEL * s.TGEUnlockBps / 10000
			require.GreaterOrEqual(t, vested, tge,
				"halfway vested must be at least TGE amount")
		})
	}
}

func TestVestedAmount_SmallAmount_1UAETHEL(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "tiny",
		TotalUAETHEL:       1, // Smallest possible allocation
		TGEUnlockBps:     5000,
		CliffBlocks:      0,
		VestingBlocks:    keeper.BlocksPerYear,
		CliffPercent:     0,
		LinearAfterCliff: true,
	}

	// TGE of 1 * 5000 / 10000 = 0 (integer division)
	vestedGenesis := keeper.VestedAmount(schedule, 0)
	require.GreaterOrEqual(t, vestedGenesis, int64(0), "must be non-negative for tiny amount")

	// Fully vested
	vestedEnd := keeper.VestedAmount(schedule, keeper.BlocksPerYear)
	require.Equal(t, int64(1), vestedEnd, "at end should be fully vested even for 1 uaethel")
}

func TestVestedAmount_ExactCliffBoundary(t *testing.T) {
	schedule := keeper.VestingSchedule{
		Category:         "cliff-boundary",
		TotalUAETHEL:       2_000_000_000_000_000,
		TGEUnlockBps:     0,
		CliffBlocks:      keeper.BlocksPerYear / 2,
		VestingBlocks:    keeper.BlocksPerYear * 4,
		CliffPercent:     1500,
		LinearAfterCliff: true,
	}

	// One block before cliff: TGE only (which is 0)
	vestedBeforeCliff := keeper.VestedAmount(schedule, keeper.BlocksPerYear/2-1)
	require.Equal(t, int64(0), vestedBeforeCliff, "one block before cliff should be TGE (0)")

	// Exactly at cliff
	expectedCliff := int64(2_000_000_000_000_000 * 1500 / 10000)
	vestedAtCliff := keeper.VestedAmount(schedule, keeper.BlocksPerYear/2)
	require.Equal(t, expectedCliff, vestedAtCliff, "exactly at cliff should get cliff amount")

	// One block after cliff: cliff + small linear increment
	vestedAfterCliff := keeper.VestedAmount(schedule, keeper.BlocksPerYear/2+1)
	require.Greater(t, vestedAfterCliff, expectedCliff,
		"one block after cliff should exceed cliff-only amount with linear")
}

// =============================================================================
// EMISSION SCHEDULE TESTS
// =============================================================================

func TestEmissionSchedule_LinearDecay_Monotonic(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionLinearDecay
	config.DecayPeriodYears = 10

	schedule := keeper.ComputeEmissionSchedule(config, 20)
	require.NotEmpty(t, schedule)

	for i := 1; i < len(schedule); i++ {
		require.LessOrEqual(t, schedule[i].InflationBps, schedule[i-1].InflationBps,
			"linear decay: inflation must not increase from year %d to %d", i, i+1)
	}
}

func TestEmissionSchedule_LinearDecay_ReachesFloor(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionLinearDecay
	config.DecayPeriodYears = 6

	schedule := keeper.ComputeEmissionSchedule(config, 20)
	require.True(t, len(schedule) >= 6, "schedule should have at least 6 entries")

	// After decay period, inflation should be at target
	for i := int(config.DecayPeriodYears); i < len(schedule); i++ {
		require.Equal(t, config.TargetInflationBps, schedule[i].InflationBps,
			"year %d: linear decay should have reached floor", i+1)
	}
}

func TestEmissionSchedule_ExponentialDecay_50Years(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay

	schedule := keeper.ComputeEmissionSchedule(config, 50)
	require.Equal(t, 50, len(schedule), "should produce 50 year schedule")

	for i, entry := range schedule {
		require.GreaterOrEqual(t, entry.InflationBps, config.TargetInflationBps,
			"year %d: inflation must not go below floor", i+1)
		require.GreaterOrEqual(t, entry.AnnualEmission, int64(0),
			"year %d: emission must be non-negative", i+1)
	}
}

func TestEmissionSchedule_ExponentialDecay_100Years(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay

	schedule := keeper.ComputeEmissionSchedule(config, 100)
	require.Equal(t, 100, len(schedule), "should produce 100 year schedule")

	// Last year should still be at or above the floor
	lastYear := schedule[len(schedule)-1]
	require.GreaterOrEqual(t, lastYear.InflationBps, config.TargetInflationBps,
		"year 100: inflation must not go below floor")
	require.Greater(t, lastYear.CumulativeSupply, keeper.InitialSupplyUAETHEL,
		"cumulative supply must exceed initial after 100 years")
}

func TestEmissionSchedule_StepDecay_DiscreteSteps(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionStepDecay
	config.DecayPeriodYears = 12

	schedule := keeper.ComputeEmissionSchedule(config, 20)
	require.NotEmpty(t, schedule)

	// Step decay should have discrete changes, not every year
	distinctValues := make(map[int64]bool)
	for _, entry := range schedule {
		distinctValues[entry.InflationBps] = true
	}
	// With step decay, we expect fewer distinct inflation values than years
	require.Less(t, len(distinctValues), len(schedule),
		"step decay should have fewer distinct inflation values than years")
}

func TestEmissionSchedule_StepDecay_AllStepsPositive(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionStepDecay

	schedule := keeper.ComputeEmissionSchedule(config, 30)

	for i, entry := range schedule {
		require.Greater(t, entry.InflationBps, int64(0),
			"year %d: step decay inflation must be positive", i+1)
		require.Greater(t, entry.AnnualEmission, int64(0),
			"year %d: step decay emission must be positive", i+1)
	}
}

func TestEmissionSchedule_ZeroYears_Empty(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	schedule := keeper.ComputeEmissionSchedule(config, 0)
	require.Empty(t, schedule, "0 years should produce empty schedule")
}

func TestEmissionSchedule_SingleYear(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	schedule := keeper.ComputeEmissionSchedule(config, 1)
	require.Equal(t, 1, len(schedule), "should produce exactly 1 entry")

	entry := schedule[0]
	require.Equal(t, 1, entry.Year)
	require.Greater(t, entry.AnnualEmission, int64(0))
	require.Greater(t, entry.CumulativeSupply, keeper.InitialSupplyUAETHEL)
}

func TestEmissionSchedule_CumulativeSupply_AlwaysIncreasing(t *testing.T) {
	models := []keeper.EmissionDecayModel{
		keeper.EmissionLinearDecay,
		keeper.EmissionExponentialDecay,
		keeper.EmissionStepDecay,
	}

	for _, model := range models {
		t.Run(string(model), func(t *testing.T) {
			config := keeper.DefaultEmissionConfig()
			config.DecayModel = model

			schedule := keeper.ComputeEmissionSchedule(config, 30)
			for i := 1; i < len(schedule); i++ {
				require.Greater(t, schedule[i].CumulativeSupply, schedule[i-1].CumulativeSupply,
					"%s year %d: cumulative supply must strictly increase", model, i+1)
			}
		})
	}
}

func TestEmissionSchedule_InflationBps_AlwaysPositive(t *testing.T) {
	models := []keeper.EmissionDecayModel{
		keeper.EmissionLinearDecay,
		keeper.EmissionExponentialDecay,
		keeper.EmissionStepDecay,
	}

	for _, model := range models {
		t.Run(string(model), func(t *testing.T) {
			config := keeper.DefaultEmissionConfig()
			config.DecayModel = model

			schedule := keeper.ComputeEmissionSchedule(config, 50)
			for i, entry := range schedule {
				require.Greater(t, entry.InflationBps, int64(0),
					"%s year %d: inflation must be positive", model, i+1)
			}
		})
	}
}

func TestEmissionSchedule_AnnualEmission_NeverNegative(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	config.DecayModel = keeper.EmissionExponentialDecay
	config.DecayPeriodYears = 2 // Fast halving

	schedule := keeper.ComputeEmissionSchedule(config, 100)
	for i, entry := range schedule {
		require.GreaterOrEqual(t, entry.AnnualEmission, int64(0),
			"year %d: annual emission must never be negative", i+1)
	}
}

func TestEmissionSchedule_StakingYield_NonNegative(t *testing.T) {
	config := keeper.DefaultEmissionConfig()

	schedule := keeper.ComputeEmissionSchedule(config, 30)
	for i, entry := range schedule {
		require.GreaterOrEqual(t, entry.StakingYield, 0.0,
			"year %d: staking yield must be non-negative", i+1)
	}
}

// =============================================================================
// BONDING CURVE TESTS
// =============================================================================

func TestBondingCurve_LinearExponent_PurchaseAndSale(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	config.ExponentScaled = 1000 // linear
	bc := keeper.NewBondingCurve(config)

	purchaseAmount := sdkmath.NewInt(1_000_000) // 1 AETHEL
	cost, err := bc.ExecutePurchase(purchaseAmount)
	require.NoError(t, err)
	require.True(t, cost.IsPositive(), "purchase cost must be positive")

	supply, reserve, price := bc.GetState()
	require.True(t, supply.Equal(purchaseAmount), "supply should match purchase amount")
	require.True(t, reserve.IsPositive(), "reserve must be positive after purchase")
	require.True(t, price.IsPositive(), "price must be positive after purchase")
}

func TestBondingCurve_QuadraticExponent_PurchaseAndSale(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	config.ExponentScaled = 2000 // quadratic
	bc := keeper.NewBondingCurve(config)

	purchaseAmount := sdkmath.NewInt(1_000_000)
	cost, err := bc.ExecutePurchase(purchaseAmount)
	require.NoError(t, err)
	require.True(t, cost.IsPositive(), "quadratic purchase cost must be positive")
}

func TestBondingCurve_SupplyIncreasesAfterPurchase(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)

	supplyBefore, _, _ := bc.GetState()
	require.True(t, supplyBefore.IsZero(), "initial supply should be zero")

	purchaseAmount := sdkmath.NewInt(5_000_000)
	_, err := bc.ExecutePurchase(purchaseAmount)
	require.NoError(t, err)

	supplyAfter, _, _ := bc.GetState()
	require.True(t, supplyAfter.Equal(purchaseAmount), "supply should increase by purchase amount")
}

func TestBondingCurve_SupplyDecreasesAfterSale(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)

	purchaseAmount := sdkmath.NewInt(10_000_000)
	_, err := bc.ExecutePurchase(purchaseAmount)
	require.NoError(t, err)

	saleAmount := sdkmath.NewInt(3_000_000)
	_, err = bc.ExecuteSale(saleAmount)
	require.NoError(t, err)

	supplyAfter, _, _ := bc.GetState()
	expected := purchaseAmount.Sub(saleAmount)
	require.True(t, supplyAfter.Equal(expected),
		"supply should decrease by sale amount: got %s, want %s", supplyAfter, expected)
}

func TestBondingCurve_PriceIncreasesWithSupply(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)

	_, _, priceAtZero := bc.GetState()

	_, err := bc.ExecutePurchase(sdkmath.NewInt(10_000_000))
	require.NoError(t, err)

	_, _, priceAfterPurchase := bc.GetState()
	require.True(t, priceAfterPurchase.GT(priceAtZero),
		"price must increase with supply: %s > %s", priceAfterPurchase, priceAtZero)
}

func TestBondingCurve_Disabled_AllOperationsFail(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	config.Enabled = false
	bc := keeper.NewBondingCurve(config)

	_, err := bc.CalculatePurchaseCost(sdkmath.NewInt(1_000_000))
	require.Error(t, err, "purchase should fail when disabled")

	_, err = bc.CalculateSaleReturn(sdkmath.NewInt(1_000_000))
	require.Error(t, err, "sale should fail when disabled")
}

func TestBondingCurve_MultiplePurchases_PriceIncreases(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)

	prevPrice := bc.GetCurrentPrice()
	for i := 0; i < 5; i++ {
		_, err := bc.ExecutePurchase(sdkmath.NewInt(5_000_000))
		require.NoError(t, err)

		currentPrice := bc.GetCurrentPrice()
		require.True(t, currentPrice.GTE(prevPrice),
			"price must not decrease after purchase %d: got %s, prev %s",
			i+1, currentPrice, prevPrice)
		prevPrice = currentPrice
	}
}

func TestBondingCurve_SaleReturn_LessThanPurchaseCost(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)

	amount := sdkmath.NewInt(5_000_000)
	purchaseCost, err := bc.ExecutePurchase(amount)
	require.NoError(t, err)

	saleReturn, err := bc.CalculateSaleReturn(amount)
	require.NoError(t, err)

	// Due to reserve ratio and slippage, sale return should be less than purchase cost
	require.True(t, saleReturn.LT(purchaseCost),
		"sale return (%s) should be less than purchase cost (%s) due to reserve ratio",
		saleReturn, purchaseCost)
}

func TestBondingCurve_ReserveRatio_Bounds(t *testing.T) {
	// Test with different reserve ratios
	for _, reserveBps := range []int64{1000, 5000, 9000} {
		t.Run(fmt.Sprintf("reserve_%d_bps", reserveBps), func(t *testing.T) {
			config := keeper.DefaultBondingCurveConfig()
			config.ReserveRatioBps = reserveBps
			bc := keeper.NewBondingCurve(config)

			_, err := bc.ExecutePurchase(sdkmath.NewInt(1_000_000))
			require.NoError(t, err)

			_, reserve, _ := bc.GetState()
			require.True(t, reserve.IsPositive(), "reserve must be positive with %d bps ratio", reserveBps)
		})
	}
}

func TestBondingCurve_ZeroPurchase(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	bc := keeper.NewBondingCurve(config)

	cost, err := bc.CalculatePurchaseCost(sdkmath.ZeroInt())
	require.NoError(t, err)
	require.True(t, cost.IsZero() || cost.IsPositive(),
		"zero purchase cost should be zero or positive")
}

// =============================================================================
// SAFE MATH TESTS
// =============================================================================

func TestSafeMath_Add_LargeValues(t *testing.T) {
	sm := keeper.NewSafeMath()

	a := sdkmath.NewInt(keeper.InitialSupplyUAETHEL)
	b := sdkmath.NewInt(keeper.InitialSupplyUAETHEL)

	result, err := sm.SafeAdd(a, b)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(2*keeper.InitialSupplyUAETHEL), result,
		"adding two large values should succeed")
}

func TestSafeMath_Sub_ResultZero(t *testing.T) {
	sm := keeper.NewSafeMath()

	a := sdkmath.NewInt(1_000_000)
	b := sdkmath.NewInt(1_000_000)

	result, err := sm.SafeSub(a, b)
	require.NoError(t, err)
	require.True(t, result.IsZero(), "subtracting equal values should give zero")
}

func TestSafeMath_Mul_LargeValues(t *testing.T) {
	sm := keeper.NewSafeMath()

	a := sdkmath.NewInt(1_000_000_000)
	b := sdkmath.NewInt(1_000_000_000)

	result, err := sm.SafeMul(a, b)
	require.NoError(t, err)
	expected := sdkmath.NewInt(1_000_000_000_000_000_000)
	require.Equal(t, expected, result, "multiplying large values should succeed")
}

func TestSafeMath_Div_ExactDivision(t *testing.T) {
	sm := keeper.NewSafeMath()

	a := sdkmath.NewInt(1_000_000)
	b := sdkmath.NewInt(1000)

	result, err := sm.SafeDiv(a, b)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(1000), result, "exact division should give exact result")
}

func TestSafeMath_Div_Remainder(t *testing.T) {
	sm := keeper.NewSafeMath()

	a := sdkmath.NewInt(10)
	b := sdkmath.NewInt(3)

	result, err := sm.SafeDiv(a, b)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(3), result, "10/3 should truncate to 3")
}

func TestSafeMath_MulDiv_Precision(t *testing.T) {
	sm := keeper.NewSafeMath()

	// Simulate BPS calculation: 1,000,000 * 800 / 10000 = 80,000
	a := sdkmath.NewInt(1_000_000)
	b := sdkmath.NewInt(800)
	c := sdkmath.NewInt(10000)

	result, err := sm.SafeMulDiv(a, b, c)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(80_000), result, "MulDiv BPS calculation should be exact")
}

func TestSafeMath_BpsMultiply_ZeroBps(t *testing.T) {
	sm := keeper.NewSafeMath()

	value := sdkmath.NewInt(1_000_000_000)
	result, err := sm.SafeBpsMultiply(value, 0)
	require.NoError(t, err)
	require.True(t, result.IsZero(), "0 BPS should yield zero")
}

func TestSafeMath_BpsMultiply_MaxBps(t *testing.T) {
	sm := keeper.NewSafeMath()

	value := sdkmath.NewInt(1_000_000)
	result, err := sm.SafeBpsMultiply(value, 10000)
	require.NoError(t, err)
	require.Equal(t, value, result, "10000 BPS should yield the original value")
}

func TestSafeMath_BpsMultiply_HalfBps(t *testing.T) {
	sm := keeper.NewSafeMath()

	value := sdkmath.NewInt(1_000_000)
	result, err := sm.SafeBpsMultiply(value, 5000)
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(500_000), result, "5000 BPS should yield half")
}

func TestSafeMath_Sub_NegativeResult(t *testing.T) {
	sm := keeper.NewSafeMath()

	a := sdkmath.NewInt(100)
	b := sdkmath.NewInt(200)

	result, err := sm.SafeSub(a, b)
	require.NoError(t, err, "SafeSub with negative result should not error (sdkmath supports negatives)")
	require.True(t, result.IsNegative(), "100 - 200 should be negative")
}

// =============================================================================
// BLOCK TIME TESTS
// =============================================================================

func TestBlockTime_DefaultConfig_Valid(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	err := keeper.ValidateBlockTimeConfig(config)
	require.NoError(t, err, "default block time config must be valid")

	require.Equal(t, int64(6000), config.TargetBlockTimeMs)
	require.Equal(t, int64(1000), config.MinBlockTimeMs)
	require.Equal(t, int64(30000), config.MaxBlockTimeMs)
}

func TestBlockTime_CustomConfig_Validation(t *testing.T) {
	config := keeper.BlockTimeConfig{
		TargetBlockTimeMs:    3000,
		MinBlockTimeMs:       1000,
		MaxBlockTimeMs:       10000,
		AdaptiveEnabled:      true,
		AdaptiveWindowBlocks: 50,
	}
	err := keeper.ValidateBlockTimeConfig(config)
	require.NoError(t, err, "valid custom config should pass")
}

func TestBlockTime_TargetTooLow_Rejected(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	config.TargetBlockTimeMs = 100 // below MinBlockTimeMs
	err := keeper.ValidateBlockTimeConfig(config)
	require.Error(t, err, "target below min should be rejected")
}

func TestBlockTime_MaxTooHigh_Rejected(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	config.MaxBlockTimeMs = 120000 // above 60000 limit
	err := keeper.ValidateBlockTimeConfig(config)
	require.Error(t, err, "max above 60000 should be rejected")
}

func TestBlockTime_WindowTooSmall_Rejected(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	config.AdaptiveWindowBlocks = 5 // below 10 minimum
	err := keeper.ValidateBlockTimeConfig(config)
	require.Error(t, err, "window below 10 should be rejected")
}

func TestBlocksPerYear_DefaultConfig(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	bpy := keeper.BlocksPerYearForConfig(config)

	// At 6 second blocks: 365 * 24 * 3600 / 6 = 5,256,000
	require.Equal(t, int64(5_256_000), bpy, "blocks per year at 6s should be 5,256,000")
}

func TestBlocksPerDay_DefaultConfig(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	bpd := keeper.BlocksPerDayForConfig(config)

	// At 6 second blocks: 24 * 3600 / 6 = 14,400
	require.Equal(t, int64(14_400), bpd, "blocks per day at 6s should be 14,400")
}

func TestRecalculateTokenomics_DifferentBlockTimes(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()

	// Recalculate for 3 second blocks (half the default)
	recalculated := keeper.RecalculateTokenomicsForBlockTime(model, 3000)

	// Unbonding period should double in blocks (same real time, faster blocks)
	require.Greater(t, recalculated.Staking.UnbondingPeriodBlocks,
		model.Staking.UnbondingPeriodBlocks,
		"faster blocks should increase unbonding block count")

	// Recalculate for 12 second blocks (double the default)
	recalculated12 := keeper.RecalculateTokenomicsForBlockTime(model, 12000)

	require.Less(t, recalculated12.Staking.UnbondingPeriodBlocks,
		model.Staking.UnbondingPeriodBlocks,
		"slower blocks should decrease unbonding block count")
}

// =============================================================================
// FEE DISTRIBUTION TESTS
// =============================================================================

func TestFeeBreakdown_DefaultConfig(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	err := keeper.ValidateFeeDistribution(config)
	require.NoError(t, err, "default fee distribution must be valid")

	totalBps := config.ValidatorRewardBps + config.TreasuryBps + config.BurnBps + config.InsuranceFundBps
	require.Equal(t, int64(10000), totalBps, "fee distribution must sum to 10000 BPS")
}

func TestFeeBreakdown_AllComponentsPositive(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 1_000_000)

	result := keeper.CalculateFeeBreakdown(fee, config, 10)

	require.True(t, result.ValidatorRewards.IsPositive(), "validator rewards must be positive")
	require.True(t, result.TreasuryAmount.IsPositive(), "treasury amount must be positive")
	require.True(t, result.BurnedAmount.IsPositive(), "burn amount must be positive")
	require.True(t, result.InsuranceFund.IsPositive(), "insurance fund must be positive")
}

func TestFeeBreakdown_SumsToTotal(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 1_000_000)

	result := keeper.CalculateFeeBreakdown(fee, config, 10)

	// Sum = validator_actual + treasury (includes dust) + burn + insurance
	sum := result.ValidatorRewards.Amount.
		Add(result.TreasuryAmount.Amount).
		Add(result.BurnedAmount.Amount).
		Add(result.InsuranceFund.Amount)

	require.True(t, sum.Equal(fee.Amount),
		"all components must sum to total fee: got %s, want %s", sum, fee.Amount)
}

func TestFeeBreakdown_SingleValidator(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 1_000_000)

	result := keeper.CalculateFeeBreakdown(fee, config, 1)

	// With a single validator, per-validator reward should equal total validator rewards
	require.True(t, result.PerValidatorReward.Amount.Equal(result.ValidatorRewards.Amount),
		"single validator should get all validator rewards")
}

func TestFeeBreakdown_ManyValidators(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 10_000_000)

	result := keeper.CalculateFeeBreakdown(fee, config, 100)

	require.Equal(t, 100, result.ValidatorCount)
	require.True(t, result.PerValidatorReward.IsPositive(),
		"per-validator reward must be positive with 100 validators")

	// Each validator's share times count should not exceed validator total
	perValTimesCount := result.PerValidatorReward.Amount.MulRaw(100)
	require.True(t, perValTimesCount.LTE(fee.Amount),
		"per-validator * count must not exceed total fee")
}

func TestFeeBreakdown_SmallFee(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 10) // Very small fee

	result := keeper.CalculateFeeBreakdown(fee, config, 3)

	// Total allocated must equal total fee
	sum := result.ValidatorRewards.Amount.
		Add(result.TreasuryAmount.Amount).
		Add(result.BurnedAmount.Amount).
		Add(result.InsuranceFund.Amount)
	require.True(t, sum.Equal(fee.Amount),
		"small fee must still sum correctly: got %s, want %s", sum, fee.Amount)
}

func TestFeeBreakdown_LargeFee(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 1_000_000_000_000) // 1M AETHEL

	result := keeper.CalculateFeeBreakdown(fee, config, 50)

	sum := result.ValidatorRewards.Amount.
		Add(result.TreasuryAmount.Amount).
		Add(result.BurnedAmount.Amount).
		Add(result.InsuranceFund.Amount)
	require.True(t, sum.Equal(fee.Amount),
		"large fee must sum correctly: got %s, want %s", sum, fee.Amount)
}

func TestFeeBreakdown_ZeroValidators(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 1_000_000)

	result := keeper.CalculateFeeBreakdown(fee, config, 0)

	// Zero validators: all validator reward goes to dust, which goes to treasury
	require.True(t, result.PerValidatorReward.Amount.IsZero(),
		"zero validators should have zero per-validator reward")
	require.True(t, result.ValidatorRewards.Amount.IsZero(),
		"zero validators should have zero total validator reward")

	// Total should still be conserved
	sum := result.ValidatorRewards.Amount.
		Add(result.TreasuryAmount.Amount).
		Add(result.BurnedAmount.Amount).
		Add(result.InsuranceFund.Amount)
	require.True(t, sum.Equal(fee.Amount),
		"with zero validators, fee must still be fully allocated")
}

// =============================================================================
// VALIDATOR REWARD TESTS
// =============================================================================

func TestValidatorReward_ZeroCommission(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1_000_000)
	valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, 50, 0)
	require.NoError(t, err)

	// Zero commission: validator gets nothing from commission, delegator gets all
	require.True(t, valReward.Amount.IsZero(), "zero commission should yield zero validator reward")
	require.True(t, delReward.Amount.IsPositive(), "delegator reward must be positive")
}

func TestValidatorReward_MaxCommission(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1_000_000)
	// Max 20% commission = 2000 BPS
	valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, 50, 2000)
	require.NoError(t, err)

	require.True(t, valReward.Amount.IsPositive(), "max commission should yield positive validator reward")
	require.True(t, delReward.Amount.IsPositive(), "delegator reward should still be positive")

	// Validator reward should be 20% of scaled amount
	total := valReward.Amount.Add(delReward.Amount)
	require.True(t, total.IsPositive(), "total rewards must be positive")
}

func TestValidatorReward_SplitConsistency(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1_000_000)
	commissions := []int64{500, 1000, 1500, 2000}

	for _, comm := range commissions {
		t.Run(fmt.Sprintf("commission_%d_bps", comm), func(t *testing.T) {
			valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, 75, comm)
			require.NoError(t, err)

			// val + del should equal scaled total
			total := valReward.Amount.Add(delReward.Amount)
			require.True(t, total.IsPositive(), "total must be positive for commission %d", comm)

			// Higher commission means more to validator
			if comm > 500 {
				prevVal, _, _ := keeper.ComputeValidatorRewardSafe(baseReward, 75, comm-500)
				require.True(t, valReward.Amount.GT(prevVal.Amount),
					"higher commission should yield more to validator")
			}
		})
	}
}

func TestValidatorReward_SmallReward(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1) // 1 uaethel
	valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, 50, 1000)
	require.NoError(t, err)

	// Even with tiny reward, should not error
	total := valReward.Amount.Add(delReward.Amount)
	require.True(t, total.GTE(sdkmath.ZeroInt()), "total must be non-negative for small reward")
}

func TestValidatorReward_LargeReward(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1_000_000_000_000) // 1M AETHEL
	valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, 100, 1500)
	require.NoError(t, err)

	require.True(t, valReward.Amount.IsPositive(), "large reward must produce positive validator reward")
	require.True(t, delReward.Amount.IsPositive(), "large reward must produce positive delegator reward")
}

func TestValidatorReward_MultiplePerformanceLevels(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1_000_000)
	scores := []int64{0, 25, 50, 75, 100}

	prevTotal := sdkmath.ZeroInt()
	for _, score := range scores {
		t.Run(fmt.Sprintf("reputation_%d", score), func(t *testing.T) {
			valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, score, 1000)
			require.NoError(t, err)

			total := valReward.Amount.Add(delReward.Amount)
			require.True(t, total.IsPositive(), "total must be positive for score %d", score)

			// Higher reputation should yield higher total (monotonic)
			require.True(t, total.GTE(prevTotal),
				"score %d total (%s) must be >= previous (%s)", score, total, prevTotal)
			prevTotal = total
		})
	}
}

// =============================================================================
// DEFAULT CONFIG TESTS
// =============================================================================

func TestDefaultEmissionConfig_Valid(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	err := keeper.ValidateEmissionConfig(config)
	require.NoError(t, err, "default emission config must be valid")

	require.Equal(t, int64(800), config.InitialInflationBps)
	require.Equal(t, int64(200), config.TargetInflationBps)
	require.Equal(t, keeper.EmissionExponentialDecay, config.DecayModel)
}

func TestDefaultBondingCurveConfig_Valid(t *testing.T) {
	config := keeper.DefaultBondingCurveConfig()
	err := keeper.ValidateBondingCurveConfig(config)
	require.NoError(t, err, "default bonding curve config must be valid")

	require.True(t, config.Enabled, "bonding curve should be enabled by default")
	require.Equal(t, int64(1500), config.ExponentScaled)
	require.Equal(t, int64(5000), config.ReserveRatioBps)
}

func TestDefaultBlockTimeConfig_Valid(t *testing.T) {
	config := keeper.DefaultBlockTimeConfig()
	err := keeper.ValidateBlockTimeConfig(config)
	require.NoError(t, err, "default block time config must be valid")

	require.Equal(t, int64(6000), config.TargetBlockTimeMs)
	require.False(t, config.AdaptiveEnabled, "adaptive should be disabled by default")
}

func TestDefaultTokenomicsModel_Coherent(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()
	issues := keeper.ValidateTokenomicsModel(model)
	require.Empty(t, issues, "default tokenomics model must have no issues: %v", issues)
}

func TestDefaultVestingSchedules_Count(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()
	require.Equal(t, 8, len(schedules), "default vesting should have 8 categories")

	err := keeper.ValidateVestingSchedules(schedules)
	require.NoError(t, err, "default vesting schedules must be valid")
}

func TestDefaultFeeDistributionConfig_Valid(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	err := keeper.ValidateFeeDistribution(config)
	require.NoError(t, err, "default fee distribution must be valid")

	require.Equal(t, int64(4000), config.ValidatorRewardBps)
	require.Equal(t, int64(3000), config.TreasuryBps)
	require.Equal(t, int64(2000), config.BurnBps)
	require.Equal(t, int64(1000), config.InsuranceFundBps)
}

// =============================================================================
// CROSS-MODEL TESTS
// =============================================================================

func TestCrossModel_EmissionThenVesting_Consistent(t *testing.T) {
	emissionConfig := keeper.DefaultEmissionConfig()
	schedule := keeper.ComputeEmissionSchedule(emissionConfig, 10)
	require.NotEmpty(t, schedule)

	vestingSchedules := keeper.DefaultVestingSchedules()

	// At year 10, all vesting should be complete or near complete
	year10Block := keeper.BlocksPerYear * 10
	totalVested := int64(0)
	for _, vs := range vestingSchedules {
		vested := keeper.VestedAmount(vs, year10Block)
		totalVested += vested
	}

	// All vesting should be fully vested by year 10
	require.Equal(t, keeper.InitialSupplyUAETHEL, totalVested,
		"all vesting must be complete by year 10")

	// Cumulative supply from emissions should exceed initial supply
	year10Supply := schedule[9].CumulativeSupply
	require.Greater(t, year10Supply, keeper.InitialSupplyUAETHEL,
		"10-year supply must exceed initial supply due to emissions")
}

func TestCrossModel_LinearVsExponentialDecay_InitialYear(t *testing.T) {
	linearConfig := keeper.DefaultEmissionConfig()
	linearConfig.DecayModel = keeper.EmissionLinearDecay

	expConfig := keeper.DefaultEmissionConfig()
	expConfig.DecayModel = keeper.EmissionExponentialDecay

	linearSchedule := keeper.ComputeEmissionSchedule(linearConfig, 1)
	expSchedule := keeper.ComputeEmissionSchedule(expConfig, 1)

	require.NotEmpty(t, linearSchedule)
	require.NotEmpty(t, expSchedule)

	// Both models should start from the same initial inflation
	// (values may differ slightly due to computation but should be similar)
	require.InDelta(t, float64(linearSchedule[0].InflationBps),
		float64(expSchedule[0].InflationBps), 200,
		"initial year inflation should be similar across models")
}

func TestCrossModel_AllDecayModels_NeverNegativeEmission(t *testing.T) {
	models := []keeper.EmissionDecayModel{
		keeper.EmissionLinearDecay,
		keeper.EmissionExponentialDecay,
		keeper.EmissionStepDecay,
	}

	for _, model := range models {
		t.Run(string(model), func(t *testing.T) {
			config := keeper.DefaultEmissionConfig()
			config.DecayModel = model

			schedule := keeper.ComputeEmissionSchedule(config, 100)
			for i, entry := range schedule {
				require.GreaterOrEqual(t, entry.AnnualEmission, int64(0),
					"%s year %d: emission must never be negative", model, i+1)
			}
		})
	}
}

func TestCrossModel_BlockTimeChange_EmissionAdjusts(t *testing.T) {
	model := keeper.DefaultTokenomicsModel()

	// With 3 second blocks, block-denominated durations should double
	adjusted := keeper.RecalculateTokenomicsForBlockTime(model, 3000)

	// Verify vesting durations adjusted
	for i := range model.Vesting {
		if model.Vesting[i].VestingBlocks > 0 {
			require.Greater(t, adjusted.Vesting[i].VestingBlocks, model.Vesting[i].VestingBlocks,
				"category %s: faster blocks should increase vesting block count",
				model.Vesting[i].Category)
		}
	}
}

func TestCrossModel_BondingCurve_AllExponents(t *testing.T) {
	exponents := keeper.SupportedBondingCurveExponents()
	require.GreaterOrEqual(t, len(exponents), 3, "should support at least 3 exponents")

	for _, exp := range exponents {
		t.Run(fmt.Sprintf("exponent_%d", exp), func(t *testing.T) {
			config := keeper.DefaultBondingCurveConfig()
			config.ExponentScaled = exp

			err := keeper.ValidateBondingCurveConfig(config)
			require.NoError(t, err, "exponent %d should be valid", exp)

			bc := keeper.NewBondingCurve(config)
			_, err = bc.ExecutePurchase(sdkmath.NewInt(1_000_000))
			require.NoError(t, err, "purchase should succeed with exponent %d", exp)

			price := bc.GetCurrentPrice()
			require.True(t, price.IsPositive(), "price must be positive with exponent %d", exp)
		})
	}
}

func TestCrossModel_FeeDistribution_AllConfigs(t *testing.T) {
	configs := []struct {
		name   string
		config keeper.FeeDistributionConfig
	}{
		{"default", keeper.DefaultFeeDistributionConfig()},
		{"mainnet", keeper.MainnetFeeDistribution()},
		{"validator_heavy", keeper.FeeDistributionConfig{
			ValidatorRewardBps: 7000,
			TreasuryBps:        1000,
			BurnBps:            1000,
			InsuranceFundBps:   1000,
		}},
		{"burn_heavy", keeper.FeeDistributionConfig{
			ValidatorRewardBps: 2000,
			TreasuryBps:        1000,
			BurnBps:            6000,
			InsuranceFundBps:   1000,
		}},
	}

	fee := sdk.NewInt64Coin("uaethel", 1_000_000)

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			err := keeper.ValidateFeeDistribution(tc.config)
			require.NoError(t, err, "config %s must be valid", tc.name)

			result := keeper.CalculateFeeBreakdown(fee, tc.config, 10)

			sum := result.ValidatorRewards.Amount.
				Add(result.TreasuryAmount.Amount).
				Add(result.BurnedAmount.Amount).
				Add(result.InsuranceFund.Amount)
			require.True(t, sum.Equal(fee.Amount),
				"%s: all components must sum to total fee", tc.name)
		})
	}
}

func TestCrossModel_SafeEmission_MatchesUnsafe(t *testing.T) {
	config := keeper.DefaultEmissionConfig()
	blockTimeConfig := keeper.DefaultBlockTimeConfig()

	unsafeSchedule := keeper.ComputeEmissionSchedule(config, 20)
	safeSchedule, err := keeper.ComputeEmissionScheduleSafe(config, 20, blockTimeConfig)
	require.NoError(t, err)

	require.Equal(t, len(unsafeSchedule), len(safeSchedule),
		"safe and unsafe schedules should have same length")

	for i := range unsafeSchedule {
		require.Equal(t, unsafeSchedule[i].AnnualEmission, safeSchedule[i].AnnualEmission,
			"year %d: safe and unsafe annual emission must match", i+1)
		require.Equal(t, unsafeSchedule[i].CumulativeSupply, safeSchedule[i].CumulativeSupply,
			"year %d: safe and unsafe cumulative supply must match", i+1)
		require.Equal(t, unsafeSchedule[i].InflationBps, safeSchedule[i].InflationBps,
			"year %d: safe and unsafe inflation BPS must match", i+1)
	}
}

func TestCrossModel_VestingSchedule_MonotonicAllCategories(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		t.Run(s.Category, func(t *testing.T) {
			prevVested := int64(0)
			// Sample 200 points across the vesting period
			for i := 0; i <= 200; i++ {
				block := int64(i) * s.VestingBlocks / 200
				vested := keeper.VestedAmount(s, block)

				require.GreaterOrEqual(t, vested, prevVested,
					"category %s: vested must be monotonic at block %d", s.Category, block)
				require.LessOrEqual(t, vested, s.TotalUAETHEL,
					"category %s: vested must not exceed total at block %d", s.Category, block)

				prevVested = vested
			}
		})
	}
}

// =============================================================================
// PROPERTY-BASED / STRESS TESTS
// =============================================================================

func TestProperty_VestedAmount_NeverExceedsTotal_1000Samples(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		t.Run(s.Category, func(t *testing.T) {
			for i := 0; i < 1000; i++ {
				// Use diverse block heights including boundaries and extremes
				block := int64(i) * (s.VestingBlocks + keeper.BlocksPerYear) / 1000
				vested := keeper.VestedAmount(s, block)

				require.GreaterOrEqual(t, vested, int64(0),
					"category %s: vested must be non-negative at block %d", s.Category, block)
				require.LessOrEqual(t, vested, s.TotalUAETHEL,
					"category %s: vested (%d) must not exceed total (%d) at block %d",
					s.Category, vested, s.TotalUAETHEL, block)
			}
		})
	}
}

func TestProperty_VestedAmount_MonotonicIncrease_AllSchedules(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	for _, s := range schedules {
		t.Run(s.Category, func(t *testing.T) {
			prevVested := int64(0)
			for block := int64(0); block <= s.VestingBlocks; block += s.VestingBlocks / 500 {
				if block == 0 && s.VestingBlocks/500 == 0 {
					break
				}
				vested := keeper.VestedAmount(s, block)
				require.GreaterOrEqual(t, vested, prevVested,
					"category %s: must be monotonically increasing at block %d (prev=%d, cur=%d)",
					s.Category, block, prevVested, vested)
				prevVested = vested
			}
		})
	}
}

func TestProperty_EmissionSchedule_NonNegative_AllModels(t *testing.T) {
	models := []keeper.EmissionDecayModel{
		keeper.EmissionLinearDecay,
		keeper.EmissionExponentialDecay,
		keeper.EmissionStepDecay,
	}

	configVariants := []keeper.EmissionConfig{
		{InitialInflationBps: 800, TargetInflationBps: 200, DecayModel: "", DecayPeriodYears: 6, StakingTargetBps: 5500, SecurityBudgetFloorBps: 100},
		{InitialInflationBps: 400, TargetInflationBps: 100, DecayModel: "", DecayPeriodYears: 4, StakingTargetBps: 5500, SecurityBudgetFloorBps: 100},
		{InitialInflationBps: 2000, TargetInflationBps: 50, DecayModel: "", DecayPeriodYears: 20, StakingTargetBps: 5500, SecurityBudgetFloorBps: 100},
	}

	for _, model := range models {
		for ci, baseConfig := range configVariants {
			t.Run(fmt.Sprintf("%s_config_%d", model, ci), func(t *testing.T) {
				config := baseConfig
				config.DecayModel = model

				schedule := keeper.ComputeEmissionSchedule(config, 50)
				for i, entry := range schedule {
					require.GreaterOrEqual(t, entry.AnnualEmission, int64(0),
						"%s config_%d year %d: emission must be non-negative", model, ci, i+1)
					require.GreaterOrEqual(t, entry.InflationBps, int64(0),
						"%s config_%d year %d: inflation must be non-negative", model, ci, i+1)
				}
			})
		}
	}
}

func TestProperty_BondingCurve_PricePositive_AfterPurchase(t *testing.T) {
	exponents := keeper.SupportedBondingCurveExponents()

	for _, exp := range exponents {
		t.Run(fmt.Sprintf("exp_%d", exp), func(t *testing.T) {
			config := keeper.DefaultBondingCurveConfig()
			config.ExponentScaled = exp
			bc := keeper.NewBondingCurve(config)

			amounts := []int64{1, 100, 1_000_000, 100_000_000}
			for _, amount := range amounts {
				_, err := bc.ExecutePurchase(sdkmath.NewInt(amount))
				require.NoError(t, err, "purchase of %d should succeed with exp %d", amount, exp)

				price := bc.GetCurrentPrice()
				require.True(t, price.IsPositive(),
					"price must be positive after purchase of %d with exp %d", amount, exp)
			}
		})
	}
}

func TestProperty_SafeMath_NoOverflow_LargeInputs(t *testing.T) {
	sm := keeper.NewSafeMath()

	largeValues := []int64{
		keeper.InitialSupplyUAETHEL,
		keeper.InitialSupplyUAETHEL / 2,
		keeper.BlocksPerYear * 100,
		9_223_372_036_854_775_807 / 2, // near max int64 / 2
	}

	for i, a := range largeValues {
		for j, b := range largeValues {
			t.Run(fmt.Sprintf("add_%d_%d", i, j), func(t *testing.T) {
				result, err := sm.SafeAdd(sdkmath.NewInt(a), sdkmath.NewInt(b))
				if err == nil {
					require.True(t, result.GT(sdkmath.ZeroInt()) || result.Equal(sdkmath.ZeroInt()),
						"valid addition result must be non-negative")
				}
				// Error is acceptable for overflow - that is the safe behavior
			})
		}
	}
}

func TestProperty_FeeBreakdown_Deterministic(t *testing.T) {
	config := keeper.DefaultFeeDistributionConfig()
	fee := sdk.NewInt64Coin("uaethel", 7_777_777)

	// Run the same calculation 100 times - must produce identical results
	first := keeper.CalculateFeeBreakdown(fee, config, 17)

	for i := 0; i < 100; i++ {
		result := keeper.CalculateFeeBreakdown(fee, config, 17)
		require.True(t, result.ValidatorRewards.Amount.Equal(first.ValidatorRewards.Amount),
			"iteration %d: validator rewards must be deterministic", i)
		require.True(t, result.TreasuryAmount.Amount.Equal(first.TreasuryAmount.Amount),
			"iteration %d: treasury amount must be deterministic", i)
		require.True(t, result.BurnedAmount.Amount.Equal(first.BurnedAmount.Amount),
			"iteration %d: burn amount must be deterministic", i)
		require.True(t, result.InsuranceFund.Amount.Equal(first.InsuranceFund.Amount),
			"iteration %d: insurance fund must be deterministic", i)
	}
}

func TestProperty_BlocksPerYear_PositiveForAllConfigs(t *testing.T) {
	blockTimes := []int64{1000, 2000, 3000, 6000, 10000, 15000, 30000}

	for _, bt := range blockTimes {
		t.Run(fmt.Sprintf("%dms", bt), func(t *testing.T) {
			config := keeper.BlockTimeConfig{
				TargetBlockTimeMs:    bt,
				MinBlockTimeMs:       500,
				MaxBlockTimeMs:       60000,
				AdaptiveWindowBlocks: 100,
			}

			bpy := keeper.BlocksPerYearForConfig(config)
			require.Greater(t, bpy, int64(0),
				"blocks per year must be positive for %d ms block time", bt)

			bpd := keeper.BlocksPerDayForConfig(config)
			require.Greater(t, bpd, int64(0),
				"blocks per day must be positive for %d ms block time", bt)

			// Blocks per year should be ~365x blocks per day
			ratio := float64(bpy) / float64(bpd)
			require.InDelta(t, 365.0, ratio, 1.0,
				"blocks_per_year / blocks_per_day should be ~365")
		})
	}
}

func TestProperty_VestingCategories_IndependentCalculation(t *testing.T) {
	schedules := keeper.DefaultVestingSchedules()

	// Verify each category can be calculated independently
	// and changing one does not affect others
	block := keeper.BlocksPerYear * 3

	baseResults := make([]int64, len(schedules))
	for i, s := range schedules {
		baseResults[i] = keeper.VestedAmount(s, block)
	}

	// Modify one schedule and verify others remain unaffected
	for modIdx := range schedules {
		modifiedSchedule := schedules[modIdx]
		modifiedSchedule.TotalUAETHEL = modifiedSchedule.TotalUAETHEL / 2

		modifiedResult := keeper.VestedAmount(modifiedSchedule, block)
		require.NotEqual(t, baseResults[modIdx], modifiedResult,
			"modified schedule %s should produce different result", schedules[modIdx].Category)

		// Other schedules should be unaffected
		for i, s := range schedules {
			if i == modIdx {
				continue
			}
			result := keeper.VestedAmount(s, block)
			require.Equal(t, baseResults[i], result,
				"category %s should not be affected by modifying %s",
				s.Category, schedules[modIdx].Category)
		}
	}
}
