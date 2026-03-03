package keeper

import (
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// Section 5: Treasury & Grants
// ---------------------------------------------------------------------------

// TreasuryConfig defines the treasury management parameters.
type TreasuryConfig struct {
	// AllocationFromEmissionBps is the % of new emission going to treasury.
	AllocationFromEmissionBps int64

	// GrantsAllocationBps is the % of treasury allocated to grants.
	GrantsAllocationBps int64

	// MaxGrantSizeUAETHEL is the maximum single grant amount.
	MaxGrantSizeUAETHEL int64

	// GrantVotingPeriodBlocks is the voting period for grant proposals.
	GrantVotingPeriodBlocks int64

	// GrantQuorumBps is the quorum for grant proposals.
	GrantQuorumBps int64

	// InsuranceReserveBps is the % of treasury earmarked for insurance.
	InsuranceReserveBps int64
}

// DefaultTreasuryConfig returns the default treasury configuration.
func DefaultTreasuryConfig() TreasuryConfig {
	return TreasuryConfig{
		AllocationFromEmissionBps: 1500,           // 15% of emissions
		GrantsAllocationBps:       4000,           // 40% of treasury for grants
		MaxGrantSizeUAETHEL:         10_000_000_000, // 10,000 AETHEL per grant
		GrantVotingPeriodBlocks:   BlocksPerWeek,  // 1 week
		GrantQuorumBps:            3300,           // 33%
		InsuranceReserveBps:       2000,           // 20% of treasury for insurance
	}
}

// ValidateTreasuryConfig checks treasury parameters.
func ValidateTreasuryConfig(config TreasuryConfig) error {
	if config.AllocationFromEmissionBps < 500 || config.AllocationFromEmissionBps > 5000 {
		return fmt.Errorf("emission allocation must be in [500, 5000] BPS, got %d",
			config.AllocationFromEmissionBps)
	}
	if config.GrantsAllocationBps < 0 || config.GrantsAllocationBps > 8000 {
		return fmt.Errorf("grants allocation must be in [0, 8000] BPS, got %d",
			config.GrantsAllocationBps)
	}
	if config.MaxGrantSizeUAETHEL <= 0 {
		return fmt.Errorf("max grant size must be positive, got %d", config.MaxGrantSizeUAETHEL)
	}
	if config.GrantQuorumBps < 2000 || config.GrantQuorumBps > 8000 {
		return fmt.Errorf("grant quorum must be in [2000, 8000] BPS, got %d", config.GrantQuorumBps)
	}
	sumBps := config.GrantsAllocationBps + config.InsuranceReserveBps
	if sumBps > 10000 {
		return fmt.Errorf("grants + insurance cannot exceed 10000 BPS, got %d", sumBps)
	}
	return nil
}

// TreasuryProjection projects treasury balance over time.
type TreasuryProjection struct {
	Year               int
	EmissionToTreasury int64
	GrantsSpent        int64
	InsuranceReserve   int64
	EndBalance         int64
}

// ProjectTreasuryGrowth simulates treasury accumulation over years.
//
// Audit fix [M-02]: Uses big.Int for all intermediate calculations to
// prevent silent int64 overflow in multi-year projections where
// AnnualEmission * BPS intermediate products exceed 2^63.
func ProjectTreasuryGrowth(emissionConfig EmissionConfig, treasuryConfig TreasuryConfig, years int) []TreasuryProjection {
	schedule := ComputeEmissionSchedule(emissionConfig, years)
	projections := make([]TreasuryProjection, 0, years)
	balance := new(big.Int)
	bpsBase := big.NewInt(BpsBase)

	for _, entry := range schedule {
		emission := big.NewInt(entry.AnnualEmission)
		allocBps := big.NewInt(treasuryConfig.AllocationFromEmissionBps)
		grantsBps := big.NewInt(treasuryConfig.GrantsAllocationBps)
		insuranceBps := big.NewInt(treasuryConfig.InsuranceReserveBps)

		// toTreasury = emission * allocBps / bpsBase
		toTreasury := new(big.Int).Mul(emission, allocBps)
		toTreasury.Div(toTreasury, bpsBase)

		// grantsSpent = toTreasury * grantsBps / bpsBase
		grantsSpent := new(big.Int).Mul(toTreasury, grantsBps)
		grantsSpent.Div(grantsSpent, bpsBase)

		// insuranceReserve = toTreasury * insuranceBps / bpsBase
		insuranceReserve := new(big.Int).Mul(toTreasury, insuranceBps)
		insuranceReserve.Div(insuranceReserve, bpsBase)

		balance.Add(balance, new(big.Int).Sub(toTreasury, grantsSpent))

		projections = append(projections, TreasuryProjection{
			Year:               entry.Year,
			EmissionToTreasury: toTreasury.Int64(),
			GrantsSpent:        grantsSpent.Int64(),
			InsuranceReserve:   insuranceReserve.Int64(),
			EndBalance:         balance.Int64(),
		})
	}

	return projections
}

// ---------------------------------------------------------------------------
// Section 6: Vesting & Distribution
// ---------------------------------------------------------------------------

// VestingSchedule defines a token vesting configuration.
type VestingSchedule struct {
	Category         string
	TotalUAETHEL       int64
	TGEUnlockBps     int64 // % released at TGE (genesis), before any cliff (BPS)
	CliffBlocks      int64 // Cliff period in blocks
	VestingBlocks    int64 // Total vesting period in blocks
	CliffPercent     int64 // % released at cliff (BPS), additional to TGE
	LinearAfterCliff bool  // Linear release after cliff
}

// DefaultVestingSchedules returns the standard vesting schedules.
// Revised Token Allocation (10B total supply):
//
//	Category                   %     Tokens    TGE     Cliff    Vest     Notes
//	Compute / PoUW Rewards    30%    3B        0%      0mo      120mo    H100 validator incentives (10-year program)
//	Core Contributors         20%    2B        0%      12mo     48mo     25% at cliff, then 36mo linear
//	Ecosystem & Grants        15%    1.5B      5%      6mo      60mo     Developer adoption, dApp incentives
//	Aethelred Labs Treasury   10%    1B        0%      12mo     60mo     Operational runway, working capital
//	Public Sale (Community)   10%    1B        22.5%   0mo      24mo     Echo + Exchange + Airdrop
//	Strategic Investors        5%    500M      0%      12mo     48mo     Seed + Strategic + Binance
//	Insurance / Stability      5%    500M      10%     0mo      30mo     Slashing appeals, bridge hack indemnification
//	Foundation Reserve         5%    500M      0%      12mo     60mo     Future initiatives, strategic partnerships
//
// TGE Unlock Total: 3.5% (350M tokens)
func DefaultVestingSchedules() []VestingSchedule {
	return []VestingSchedule{
		{
			Category:         "compute_pouw_rewards",
			TotalUAETHEL:       3_000_000_000_000_000, // 30% of supply — H100 validator incentives
			TGEUnlockBps:     0,                     // No TGE unlock
			CliffBlocks:      0,                     // No cliff — rewards from genesis
			VestingBlocks:    BlocksPerYear * 10,    // 10-year linear release (120 months)
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
		{
			Category:         "core_contributors",
			TotalUAETHEL:       2_000_000_000_000_000, // 20% of supply — Team alignment
			TGEUnlockBps:     0,                     // No TGE unlock
			CliffBlocks:      BlocksPerYear,         // 12-month cliff
			VestingBlocks:    BlocksPerYear * 4,     // 4-year total vest (48 months)
			CliffPercent:     2500,                   // 25% at cliff (500M), then 36mo linear
			LinearAfterCliff: true,
		},
		{
			Category:         "ecosystem_grants",
			TotalUAETHEL:       1_500_000_000_000_000, // 15% of supply — Developer adoption, dApp incentives
			TGEUnlockBps:     500,                   // 5% at TGE (75M tokens)
			CliffBlocks:      BlocksPerYear / 2,     // 6-month cliff
			VestingBlocks:    BlocksPerYear * 5,     // 5-year total vest (60 months)
			CliffPercent:     0,                     // No additional cliff unlock
			LinearAfterCliff: true,
		},
		{
			Category:         "aethelred_labs_treasury",
			TotalUAETHEL:       1_000_000_000_000_000, // 10% of supply — Operational runway
			TGEUnlockBps:     0,                     // No TGE unlock
			CliffBlocks:      BlocksPerYear,         // 12-month cliff
			VestingBlocks:    BlocksPerYear * 5,     // 5-year total vest (60 months)
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
		{
			Category:         "public_sale_community",
			TotalUAETHEL:       1_000_000_000_000_000, // 10% of supply — Echo + Exchange + Airdrop
			TGEUnlockBps:     2250,                  // 22.5% at TGE (225M tokens)
			CliffBlocks:      0,                     // No cliff
			VestingBlocks:    BlocksPerYear * 2,     // 2-year total vest (24 months)
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
		{
			Category:         "strategic_investors",
			TotalUAETHEL:       500_000_000_000_000, // 5% of supply — Seed + Strategic + Binance
			TGEUnlockBps:     0,                   // No TGE unlock
			CliffBlocks:      BlocksPerYear,       // 12-month cliff
			VestingBlocks:    BlocksPerYear * 4,   // 4-year total vest (48 months)
			CliffPercent:     0,                   // No cliff unlock, then 36mo linear post-cliff
			LinearAfterCliff: true,
		},
		{
			Category:         "insurance_stability",
			TotalUAETHEL:       500_000_000_000_000, // 5% of supply — Slashing appeals, bridge indemnification
			TGEUnlockBps:     1000,                // 10% at TGE (50M tokens)
			CliffBlocks:      0,                   // No cliff
			VestingBlocks:    BlocksPerYear * 5 / 2, // 2.5-year linear (30 months)
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
		{
			Category:         "foundation_reserve",
			TotalUAETHEL:       500_000_000_000_000, // 5% of supply — Future initiatives, strategic partnerships
			TGEUnlockBps:     0,                   // No TGE unlock
			CliffBlocks:      BlocksPerYear,       // 12-month cliff
			VestingBlocks:    BlocksPerYear * 5,   // 5-year total vest (60 months)
			CliffPercent:     0,
			LinearAfterCliff: true,
		},
	}
}

// ValidateVestingSchedules checks all vesting schedules.
func ValidateVestingSchedules(schedules []VestingSchedule) error {
	totalAllocated := int64(0)
	categories := make(map[string]bool)

	for _, s := range schedules {
		if s.Category == "" {
			return fmt.Errorf("vesting category must not be empty")
		}
		if categories[s.Category] {
			return fmt.Errorf("duplicate vesting category %q", s.Category)
		}
		categories[s.Category] = true

		if s.TotalUAETHEL <= 0 {
			return fmt.Errorf("category %q: total must be positive", s.Category)
		}
		if s.VestingBlocks <= 0 {
			return fmt.Errorf("category %q: vesting period must be positive", s.Category)
		}
		if s.CliffBlocks < 0 {
			return fmt.Errorf("category %q: cliff must be non-negative", s.Category)
		}
		if s.CliffBlocks >= s.VestingBlocks {
			return fmt.Errorf("category %q: cliff (%d) must be < vesting period (%d)",
				s.Category, s.CliffBlocks, s.VestingBlocks)
		}
		if s.TGEUnlockBps < 0 || s.TGEUnlockBps > 5000 {
			return fmt.Errorf("category %q: TGE unlock must be in [0, 5000] BPS, got %d",
				s.Category, s.TGEUnlockBps)
		}
		if s.CliffPercent < 0 || s.CliffPercent > 5000 {
			return fmt.Errorf("category %q: cliff percent must be in [0, 5000] BPS, got %d",
				s.Category, s.CliffPercent)
		}
		if s.TGEUnlockBps+s.CliffPercent > 8000 {
			return fmt.Errorf("category %q: TGE (%d) + cliff (%d) must not exceed 8000 BPS",
				s.Category, s.TGEUnlockBps, s.CliffPercent)
		}
		totalAllocated += s.TotalUAETHEL
	}

	if totalAllocated > InitialSupplyUAETHEL {
		return fmt.Errorf("total vesting allocation (%d) exceeds initial supply (%d)",
			totalAllocated, InitialSupplyUAETHEL)
	}

	return nil
}

// VestedAmount calculates how much has vested at a given block height.
//
// TGE unlock is available at genesis (block >= 0, i.e., the genesis block).
// Cliff unlock is additional, released when blockHeight >= CliffBlocks.
// Linear vesting covers the remainder after TGE + cliff.
//
// Audit fix [C-01]: All intermediate arithmetic uses math/big to prevent
// silent int64 overflow. With TotalUAETHEL up to 3*10^15 and elapsed up to
// 5.256*10^7 blocks, naive int64 multiplication overflows 2^63 (~9.2*10^18).
//
// Audit fix [H-03]: Genesis block (blockHeight == 0) now returns TGE amount
// instead of 0. In Cosmos SDK, the genesis block is height 0 (or 1 depending
// on InitChain config). The guard now uses blockHeight < 0 to reject only
// invalid negative heights.
func VestedAmount(schedule VestingSchedule, blockHeight int64) int64 {
	// Reject invalid negative block heights.
	if blockHeight < 0 {
		return 0
	}

	total := big.NewInt(schedule.TotalUAETHEL)
	bpsBase := big.NewInt(BpsBase)

	// TGE unlock is available from the genesis block (height 0).
	// tgeAmount = total * TGEUnlockBps / BpsBase
	tgeAmount := new(big.Int).Mul(total, big.NewInt(schedule.TGEUnlockBps))
	tgeAmount.Div(tgeAmount, bpsBase)

	// Before cliff — only TGE portion is available.
	if blockHeight < schedule.CliffBlocks {
		return tgeAmount.Int64()
	}

	// At/after cliff — add cliff amount.
	// cliffAmount = total * CliffPercent / BpsBase
	cliffAmount := new(big.Int).Mul(total, big.NewInt(schedule.CliffPercent))
	cliffAmount.Div(cliffAmount, bpsBase)

	if !schedule.LinearAfterCliff {
		if blockHeight >= schedule.VestingBlocks {
			return schedule.TotalUAETHEL
		}
		result := new(big.Int).Add(tgeAmount, cliffAmount)
		return result.Int64()
	}

	// Fully vested.
	if blockHeight >= schedule.VestingBlocks {
		return schedule.TotalUAETHEL
	}

	// Linear vesting after cliff for the remainder.
	// remainingToVest = total - tgeAmount - cliffAmount
	remainingToVest := new(big.Int).Sub(total, tgeAmount)
	remainingToVest.Sub(remainingToVest, cliffAmount)

	vestingAfterCliff := schedule.VestingBlocks - schedule.CliffBlocks
	if vestingAfterCliff <= 0 {
		return schedule.TotalUAETHEL
	}

	elapsed := blockHeight - schedule.CliffBlocks

	// linearVested = remainingToVest * elapsed / vestingAfterCliff
	// Uses big.Int to prevent overflow on remainingToVest * elapsed.
	linearVested := new(big.Int).Mul(remainingToVest, big.NewInt(elapsed))
	linearVested.Div(linearVested, big.NewInt(vestingAfterCliff))

	// result = tgeAmount + cliffAmount + linearVested
	result := new(big.Int).Add(tgeAmount, cliffAmount)
	result.Add(result, linearVested)

	// Clamp to total (safety invariant: never vest more than allocated).
	if result.Cmp(total) > 0 {
		return schedule.TotalUAETHEL
	}

	return result.Int64()
}
