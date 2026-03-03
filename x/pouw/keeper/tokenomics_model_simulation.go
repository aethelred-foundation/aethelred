package keeper

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Section 7: Anti-Abuse & MEV Policy
// ---------------------------------------------------------------------------

// AntiAbuseConfig defines anti-abuse and MEV prevention policies.
type AntiAbuseConfig struct {
	// MEVProtectionEnabled activates commit-reveal for job submission.
	MEVProtectionEnabled bool

	// ValidatorConcentrationCapBps is the max stake share per validator.
	ValidatorConcentrationCapBps int64

	// MaxDailyJobsPerSubmitter limits job submission rate.
	MaxDailyJobsPerSubmitter int64

	// ProgressivePenaltyEnabled increases penalty for repeat offenders.
	ProgressivePenaltyEnabled bool

	// ProgressivePenaltyMultiplierBps is the escalation factor per offense.
	ProgressivePenaltyMultiplierBps int64
}

// DefaultAntiAbuseConfig returns the default anti-abuse configuration.
func DefaultAntiAbuseConfig() AntiAbuseConfig {
	return AntiAbuseConfig{
		MEVProtectionEnabled:            true,
		ValidatorConcentrationCapBps:    3300, // 33% max stake per validator
		MaxDailyJobsPerSubmitter:        10000,
		ProgressivePenaltyEnabled:       true,
		ProgressivePenaltyMultiplierBps: 15000, // 1.5x per repeated offense
	}
}

// ValidateAntiAbuseConfig checks anti-abuse parameters.
func ValidateAntiAbuseConfig(config AntiAbuseConfig) error {
	if config.ValidatorConcentrationCapBps < 1000 || config.ValidatorConcentrationCapBps > 5000 {
		return fmt.Errorf("validator concentration cap must be in [1000, 5000] BPS, got %d",
			config.ValidatorConcentrationCapBps)
	}
	if config.MaxDailyJobsPerSubmitter < 10 {
		return fmt.Errorf("max daily jobs must be >= 10, got %d", config.MaxDailyJobsPerSubmitter)
	}
	if config.ProgressivePenaltyEnabled && config.ProgressivePenaltyMultiplierBps < 10000 {
		return fmt.Errorf("progressive penalty multiplier must be >= 10000 BPS, got %d",
			config.ProgressivePenaltyMultiplierBps)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Section 8: Comprehensive Tokenomics Model
// ---------------------------------------------------------------------------

// TokenomicsModel aggregates all tokenomics parameters.
type TokenomicsModel struct {
	Emission  EmissionConfig
	Staking   StakingConfig
	FeeMarket FeeMarketConfig
	Slashing  SlashingConfig
	Treasury  TreasuryConfig
	Vesting   []VestingSchedule
	AntiAbuse AntiAbuseConfig
	FeeDistro FeeDistributionConfig
}

// DefaultTokenomicsModel returns the complete default tokenomics model.
func DefaultTokenomicsModel() TokenomicsModel {
	return TokenomicsModel{
		Emission:  DefaultEmissionConfig(),
		Staking:   DefaultStakingConfig(),
		FeeMarket: DefaultFeeMarketConfig(),
		Slashing:  DefaultSlashingConfig(),
		Treasury:  DefaultTreasuryConfig(),
		Vesting:   DefaultVestingSchedules(),
		AntiAbuse: DefaultAntiAbuseConfig(),
		FeeDistro: DefaultFeeDistributionConfig(),
	}
}

// ValidateTokenomicsModel checks all tokenomics parameters.
func ValidateTokenomicsModel(model TokenomicsModel) []string {
	var issues []string

	if err := ValidateEmissionConfig(model.Emission); err != nil {
		issues = append(issues, "emission: "+err.Error())
	}
	if err := ValidateStakingConfig(model.Staking); err != nil {
		issues = append(issues, "staking: "+err.Error())
	}
	if err := ValidateFeeMarketConfig(model.FeeMarket); err != nil {
		issues = append(issues, "fee_market: "+err.Error())
	}
	if err := ValidateSlashingConfig(model.Slashing); err != nil {
		issues = append(issues, "slashing: "+err.Error())
	}
	if err := ValidateTreasuryConfig(model.Treasury); err != nil {
		issues = append(issues, "treasury: "+err.Error())
	}
	if err := ValidateVestingSchedules(model.Vesting); err != nil {
		issues = append(issues, "vesting: "+err.Error())
	}
	if err := ValidateAntiAbuseConfig(model.AntiAbuse); err != nil {
		issues = append(issues, "anti_abuse: "+err.Error())
	}
	if err := ValidateFeeDistribution(model.FeeDistro); err != nil {
		issues = append(issues, "fee_distribution: "+err.Error())
	}

	return issues
}

// ---------------------------------------------------------------------------
// Section 9: Tokenomics Simulation
// ---------------------------------------------------------------------------

// SimulationScenario defines a parameter sweep scenario.
type SimulationScenario struct {
	Name      string
	Emission  EmissionConfig
	Staking   StakingConfig
	FeeMarket FeeMarketConfig
	Slashing  SlashingConfig
	Treasury  TreasuryConfig
	FeeDistro FeeDistributionConfig
}

// SimulationResult captures the output of a tokenomics simulation.
type SimulationResult struct {
	Scenario           string
	EmissionSchedule   []EmissionScheduleEntry
	TreasuryProjection []TreasuryProjection
	Year10Supply       int64
	Year10Inflation    float64
	Year10Treasury     int64
	MaxDeterrenceRatio float64
	DynamicFeeAtPeak   int64
	Valid              bool
	Issues             []string
}

// RunTokenomicsSimulation executes a full simulation for a scenario.
func RunTokenomicsSimulation(scenario SimulationScenario) *SimulationResult {
	result := &SimulationResult{
		Scenario: scenario.Name,
		Valid:    true,
	}

	model := TokenomicsModel{
		Emission:  scenario.Emission,
		Staking:   scenario.Staking,
		FeeMarket: scenario.FeeMarket,
		Slashing:  scenario.Slashing,
		Treasury:  scenario.Treasury,
		FeeDistro: scenario.FeeDistro,
		Vesting:   DefaultVestingSchedules(),
		AntiAbuse: DefaultAntiAbuseConfig(),
	}
	result.Issues = ValidateTokenomicsModel(model)
	if len(result.Issues) > 0 {
		result.Valid = false
	}

	result.EmissionSchedule = ComputeEmissionSchedule(scenario.Emission, 10)
	if len(result.EmissionSchedule) >= 10 {
		yr10 := result.EmissionSchedule[9]
		result.Year10Supply = yr10.CumulativeSupply
		result.Year10Inflation = yr10.InflationPercent
	}

	result.TreasuryProjection = ProjectTreasuryGrowth(scenario.Emission, scenario.Treasury, 10)
	if len(result.TreasuryProjection) >= 10 {
		result.Year10Treasury = result.TreasuryProjection[9].EndBalance
	}

	for _, tier := range scenario.Slashing.Tiers {
		slashAmt := ComputeSlashAmount(tier, scenario.Staking.MinStakeUAETHEL)
		ratio := DeterrenceRatio(slashAmt, scenario.FeeMarket.BaseFeeUAETHEL*BlocksPerDay)
		if ratio > result.MaxDeterrenceRatio {
			result.MaxDeterrenceRatio = ratio
		}
	}

	result.DynamicFeeAtPeak = ComputeDynamicFee(scenario.FeeMarket, 250, 25)

	return result
}

// RunDefaultSimulation runs the default parameter simulation.
func RunDefaultSimulation() *SimulationResult {
	return RunTokenomicsSimulation(SimulationScenario{
		Name:      "default",
		Emission:  DefaultEmissionConfig(),
		Staking:   DefaultStakingConfig(),
		FeeMarket: DefaultFeeMarketConfig(),
		Slashing:  DefaultSlashingConfig(),
		Treasury:  DefaultTreasuryConfig(),
		FeeDistro: DefaultFeeDistributionConfig(),
	})
}

// ---------------------------------------------------------------------------
// Section 10: Tokenomics Report
// ---------------------------------------------------------------------------

// RenderTokenomicsReport produces a human-readable tokenomics summary.
func RenderTokenomicsReport(model TokenomicsModel) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          AETHEL TOKENOMICS MODEL                            ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString("─── TOKEN SUPPLY ──────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Genesis Supply:     %s AETHEL\n", formatAETHEL(InitialSupplyUAETHEL)))
	sb.WriteString(fmt.Sprintf("  Denomination:       %s\n", MainnetDenom))
	sb.WriteString(fmt.Sprintf("  1 AETHEL = 1,000,000 %s\n\n", MainnetDenom))

	sb.WriteString("─── EMISSION MODEL ────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Initial Inflation:  %.1f%%\n", float64(model.Emission.InitialInflationBps)/100))
	sb.WriteString(fmt.Sprintf("  Target Inflation:   %.1f%%\n", float64(model.Emission.TargetInflationBps)/100))
	sb.WriteString(fmt.Sprintf("  Decay Model:        %s\n", model.Emission.DecayModel))
	sb.WriteString(fmt.Sprintf("  Decay Period:       %d years\n", model.Emission.DecayPeriodYears))
	sb.WriteString(fmt.Sprintf("  Staking Target:     %.1f%%\n\n", float64(model.Emission.StakingTargetBps)/100))

	sb.WriteString("─── STAKING ECONOMICS ─────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Min Stake:          %s AETHEL\n", formatAETHEL(model.Staking.MinStakeUAETHEL)))
	sb.WriteString(fmt.Sprintf("  Commission Range:   %.1f%% – %.1f%%\n",
		float64(model.Staking.MinCommissionBps)/100, float64(model.Staking.MaxCommissionBps)/100))
	sb.WriteString(fmt.Sprintf("  Unbonding:          %d blocks (~%d days)\n",
		model.Staking.UnbondingPeriodBlocks, model.Staking.UnbondingPeriodBlocks/BlocksPerDay))
	sb.WriteString(fmt.Sprintf("  Max Validators:     %d\n\n", model.Staking.MaxValidators))

	sb.WriteString("─── FEE MARKET ────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Base Fee:           %d %s (%.4f AETHEL)\n",
		model.FeeMarket.BaseFeeUAETHEL, MainnetDenom, float64(model.FeeMarket.BaseFeeUAETHEL)/1e6))
	sb.WriteString(fmt.Sprintf("  Max Multiplier:     %.1fx\n", float64(model.FeeMarket.MaxMultiplierBps)/10000))
	sb.WriteString(fmt.Sprintf("  Congestion Trigger: %.0f%% utilization\n",
		float64(model.FeeMarket.CongestionThresholdBps)/100))
	sb.WriteString("  Priority Tiers:\n")
	for _, tier := range model.FeeMarket.PriorityFeeTiers {
		sb.WriteString(fmt.Sprintf("    %-12s %.1fx\n", tier.Name, float64(tier.MultiplierBps)/10000))
	}
	sb.WriteString("\n")

	sb.WriteString("─── FEE DISTRIBUTION ──────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Validators:    %d BPS (%.0f%%)\n",
		model.FeeDistro.ValidatorRewardBps, float64(model.FeeDistro.ValidatorRewardBps)/100))
	sb.WriteString(fmt.Sprintf("  Treasury:      %d BPS (%.0f%%)\n",
		model.FeeDistro.TreasuryBps, float64(model.FeeDistro.TreasuryBps)/100))
	sb.WriteString(fmt.Sprintf("  Burn:          %d BPS (%.0f%%)\n",
		model.FeeDistro.BurnBps, float64(model.FeeDistro.BurnBps)/100))
	sb.WriteString(fmt.Sprintf("  Insurance:     %d BPS (%.0f%%)\n\n",
		model.FeeDistro.InsuranceFundBps, float64(model.FeeDistro.InsuranceFundBps)/100))

	sb.WriteString("─── SLASHING TIERS ────────────────────────────────────────────\n")
	for _, tier := range model.Slashing.Tiers {
		permaban := ""
		if tier.IsPermaban {
			permaban = " [PERMABAN]"
		}
		sb.WriteString(fmt.Sprintf("  %-20s %.1f%% slash, %d blocks jail%s\n",
			tier.Name, float64(tier.SlashBps)/100, tier.JailBlocks, permaban))
	}
	sb.WriteString("\n")

	sb.WriteString("─── TREASURY & GRANTS ─────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Emission Allocation: %.1f%%\n",
		float64(model.Treasury.AllocationFromEmissionBps)/100))
	sb.WriteString(fmt.Sprintf("  Grants Budget:       %.1f%% of treasury\n",
		float64(model.Treasury.GrantsAllocationBps)/100))
	sb.WriteString(fmt.Sprintf("  Insurance Reserve:   %.1f%% of treasury\n",
		float64(model.Treasury.InsuranceReserveBps)/100))
	sb.WriteString(fmt.Sprintf("  Max Grant Size:      %s AETHEL\n\n", formatAETHEL(model.Treasury.MaxGrantSizeUAETHEL)))

	sb.WriteString("─── VESTING SCHEDULE ──────────────────────────────────────────\n")
	for _, v := range model.Vesting {
		cliffDays := v.CliffBlocks / BlocksPerDay
		vestDays := v.VestingBlocks / BlocksPerDay
		sb.WriteString(fmt.Sprintf("  %-24s %12s AETHEL  cliff=%dd  vest=%dd\n",
			v.Category, formatAETHEL(v.TotalUAETHEL), cliffDays, vestDays))
	}
	sb.WriteString("\n")

	sb.WriteString("─── ANTI-ABUSE POLICY ─────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  MEV Protection:       %v\n", model.AntiAbuse.MEVProtectionEnabled))
	sb.WriteString(fmt.Sprintf("  Validator Cap:        %.1f%%\n",
		float64(model.AntiAbuse.ValidatorConcentrationCapBps)/100))
	sb.WriteString(fmt.Sprintf("  Max Daily Jobs:       %d per submitter\n",
		model.AntiAbuse.MaxDailyJobsPerSubmitter))
	sb.WriteString(fmt.Sprintf("  Progressive Penalty:  %v (%.1fx escalation)\n",
		model.AntiAbuse.ProgressivePenaltyEnabled,
		float64(model.AntiAbuse.ProgressivePenaltyMultiplierBps)/10000))

	sb.WriteString("\n─── VALIDATION ────────────────────────────────────────────────\n")
	issues := ValidateTokenomicsModel(model)
	if len(issues) == 0 {
		sb.WriteString("  ✓ All tokenomics parameters VALID\n")
	} else {
		for _, issue := range issues {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", issue))
		}
	}

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// RenderSimulationReport produces a human-readable simulation report.
func RenderSimulationReport(result *SimulationResult) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║          TOKENOMICS SIMULATION REPORT                       ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Scenario: %s | Valid: %v\n\n", result.Scenario, result.Valid))

	sb.WriteString("─── 10-YEAR EMISSION SCHEDULE ─────────────────────────────────\n")
	sb.WriteString("  Year  Inflation   Annual Emission    Cumulative Supply   Yield\n")
	for _, e := range result.EmissionSchedule {
		sb.WriteString(fmt.Sprintf("  %4d  %6.2f%%  %18s  %18s  %5.1f%%\n",
			e.Year, e.InflationPercent,
			formatAETHEL(e.AnnualEmission),
			formatAETHEL(e.CumulativeSupply),
			e.StakingYield))
	}

	sb.WriteString("\n─── KEY METRICS ───────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Year-10 Supply:       %s AETHEL\n", formatAETHEL(result.Year10Supply)))
	sb.WriteString(fmt.Sprintf("  Year-10 Inflation:    %.2f%%\n", result.Year10Inflation))
	sb.WriteString(fmt.Sprintf("  Year-10 Treasury:     %s AETHEL\n", formatAETHEL(result.Year10Treasury)))
	sb.WriteString(fmt.Sprintf("  Max Deterrence Ratio: %.1fx\n", result.MaxDeterrenceRatio))
	sb.WriteString(fmt.Sprintf("  Peak Dynamic Fee:     %d %s\n", result.DynamicFeeAtPeak, MainnetDenom))

	if len(result.Issues) > 0 {
		sb.WriteString("\n─── ISSUES ────────────────────────────────────────────────────\n")
		for _, issue := range result.Issues {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", issue))
		}
	}

	sb.WriteString("\n══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// formatAETHEL formats uaethel as AETHEL with comma separators.
func formatAETHEL(uaethel int64) string {
	aethel := uaethel / 1_000_000
	if aethel == 0 && uaethel > 0 {
		return fmt.Sprintf("0.%06d", uaethel)
	}
	return formatWithCommas(aethel)
}

// formatWithCommas adds comma separators to a number.
func formatWithCommas(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
	}
	for i := remainder; i < len(s); i += 3 {
		if result.Len() > 0 {
			result.WriteByte(',')
		}
		result.WriteString(s[i : i+3])
	}
	return result.String()
}
