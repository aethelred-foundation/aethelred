package keeper

import (
	"fmt"
	"math"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// Cost Estimator -- dynamic proof cost estimation engine
// ---------------------------------------------------------------------------
//
// CostEstimator calculates expected job costs based on model characteristics,
// verification type, and network conditions. It provides transparent cost
// breakdowns so that submitters can make informed decisions about proof type
// and urgency trade-offs.
//
// Cost formula:
//   total = (baseFee + verificationFee + modelSizeFee) * urgencyMultiplier * networkMultiplier
//
// Verification type multipliers reflect real-world cost differentials:
//   TEE     = 1.0x  (hardware attestation, lowest marginal cost)
//   Hybrid  = 1.5x  (TEE + partial ZK, moderate overhead)
//   zkML    = 3.0x  (full ZK circuit proving, ~10x raw cost offset by batching)
//
// Model size scaling uses the model's BaseUwuValue as a proxy for computational
// complexity when explicit size metadata is unavailable.
// ---------------------------------------------------------------------------

// CostEstimator calculates expected job costs based on model characteristics,
// verification type, and network conditions.
type CostEstimator struct {
	keeper *Keeper
}

// CostEstimate represents the estimated cost breakdown for a compute job.
type CostEstimate struct {
	BaseFee           sdk.Coin          `json:"base_fee"`
	VerificationFee   sdk.Coin          `json:"verification_fee"`
	ModelSizeFee      sdk.Coin          `json:"model_size_fee"`
	UrgencyMultiplier float64           `json:"urgency_multiplier"`
	NetworkMultiplier float64           `json:"network_multiplier"`
	TotalEstimate     sdk.Coin          `json:"total_estimate"`
	VerificationType  string            `json:"verification_type"`
	Confidence        string            `json:"confidence"`
	Breakdown         map[string]string `json:"breakdown"`
}

// Verification type cost multipliers.
const (
	verificationMultiplierTEE    = 1.0
	verificationMultiplierHybrid = 1.5
	verificationMultiplierZKML   = 3.0
)

// Urgency level multipliers.
const (
	urgencyStandard = 1.0
	urgencyPriority = 1.5
	urgencyUrgent   = 2.0
)

// Model size fee scaling constants.
// The model size fee is computed as: baseUwuValue * modelSizeFeePerUWU.
// For models without UWU metadata, a default baseline fee applies.
const (
	modelSizeFeePerUWU      int64 = 10 // uaethel per UWU of model complexity
	defaultModelSizeFeeBasis int64 = 500 // baseline uaethel for unknown models
)

// Network utilization thresholds.
const (
	networkUtilizationThreshold = 0.5  // queue fill ratio above which surcharge applies
	networkSurchargePerDecile   = 0.10 // +10% per 10% queue fill above threshold
)

// NewCostEstimator creates a new CostEstimator bound to the given keeper.
func NewCostEstimator(keeper *Keeper) *CostEstimator {
	return &CostEstimator{keeper: keeper}
}

// EstimateJobCost calculates the expected cost for a compute job based on the
// model hash, verification type, urgency level, and current network conditions.
//
// Parameters:
//   - ctx: SDK context for state access
//   - modelHash: SHA-256 hash identifying the model (may be nil for estimates)
//   - verificationType: one of "tee", "hybrid", "zkml"
//   - urgency: 0 = standard, 1 = priority, 2 = urgent
//
// Returns a CostEstimate with full breakdown, or an error if parameters are invalid.
func (ce *CostEstimator) EstimateJobCost(
	ctx sdk.Context,
	modelHash []byte,
	verificationType string,
	urgency uint32,
) (*CostEstimate, error) {
	// Resolve verification multiplier.
	verifyMul, err := resolveVerificationMultiplier(verificationType)
	if err != nil {
		return nil, err
	}

	// Resolve urgency multiplier.
	urgencyMul := resolveUrgencyMultiplier(urgency)

	// Fetch base fee from module params.
	params, err := ce.keeper.GetParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read module params: %w", err)
	}

	baseFeeAmount := int64(1000) // fallback default in uaethel
	if params.BaseJobFee != "" {
		if parsed, parseErr := sdk.ParseCoinNormalized(params.BaseJobFee); parseErr == nil {
			baseFeeAmount = parsed.Amount.Int64()
		}
	}
	baseFee := sdk.NewCoin(types.DefaultDenom, sdkmath.NewInt(baseFeeAmount))

	// Compute verification fee component.
	verificationFeeAmount := int64(math.Round(float64(baseFeeAmount) * (verifyMul - 1.0)))
	if verificationFeeAmount < 0 {
		verificationFeeAmount = 0
	}
	verificationFee := sdk.NewCoin(types.DefaultDenom, sdkmath.NewInt(verificationFeeAmount))

	// Compute model size fee component.
	modelSizeFeeAmount := defaultModelSizeFeeBasis
	confidence := "low"

	var modelName string
	if len(modelHash) > 0 {
		model, modelErr := ce.keeper.GetRegisteredModel(ctx, modelHash)
		if modelErr == nil && model != nil {
			confidence = "high"
			modelName = model.Name
			if model.BaseUwuValue > 0 {
				modelSizeFeeAmount = int64(model.BaseUwuValue) * modelSizeFeePerUWU
			}
		}
	}
	modelSizeFee := sdk.NewCoin(types.DefaultDenom, sdkmath.NewInt(modelSizeFeeAmount))

	// Compute network utilization surcharge.
	networkMul := ce.computeNetworkMultiplier(ctx, params)

	// Compute total: (base + verification + modelSize) * urgency * network
	subtotal := baseFeeAmount + verificationFeeAmount + modelSizeFeeAmount
	totalFloat := float64(subtotal) * urgencyMul * networkMul
	totalAmount := int64(math.Ceil(totalFloat))
	totalEstimate := sdk.NewCoin(types.DefaultDenom, sdkmath.NewInt(totalAmount))

	// Build human-readable breakdown.
	breakdown := map[string]string{
		"base_fee":              baseFee.String(),
		"verification_fee":     verificationFee.String(),
		"verification_type":    verificationType,
		"verification_multiplier": fmt.Sprintf("%.1fx", verifyMul),
		"model_size_fee":       modelSizeFee.String(),
		"urgency_multiplier":   fmt.Sprintf("%.1fx", urgencyMul),
		"network_multiplier":   fmt.Sprintf("%.2fx", networkMul),
		"confidence":           confidence,
	}
	if modelName != "" {
		breakdown["model_name"] = modelName
	}

	return &CostEstimate{
		BaseFee:           baseFee,
		VerificationFee:   verificationFee,
		ModelSizeFee:      modelSizeFee,
		UrgencyMultiplier: urgencyMul,
		NetworkMultiplier: networkMul,
		TotalEstimate:     totalEstimate,
		VerificationType:  verificationType,
		Confidence:        confidence,
		Breakdown:         breakdown,
	}, nil
}

// resolveVerificationMultiplier returns the cost multiplier for the given
// verification type. Returns an error for unrecognized types.
func resolveVerificationMultiplier(verificationType string) (float64, error) {
	switch verificationType {
	case "tee":
		return verificationMultiplierTEE, nil
	case "hybrid":
		return verificationMultiplierHybrid, nil
	case "zkml":
		return verificationMultiplierZKML, nil
	default:
		return 0, fmt.Errorf("unsupported verification type: %q (expected tee, hybrid, or zkml)", verificationType)
	}
}

// resolveUrgencyMultiplier returns the cost multiplier for the given urgency level.
// Unrecognized levels default to standard urgency.
func resolveUrgencyMultiplier(urgency uint32) float64 {
	switch urgency {
	case 0:
		return urgencyStandard
	case 1:
		return urgencyPriority
	case 2:
		return urgencyUrgent
	default:
		return urgencyStandard
	}
}

// computeNetworkMultiplier calculates the network utilization surcharge based
// on pending job queue depth relative to max_jobs_per_block capacity.
func (ce *CostEstimator) computeNetworkMultiplier(ctx sdk.Context, params *types.Params) float64 {
	if params.MaxJobsPerBlock <= 0 {
		return 1.0
	}

	pendingJobs := ce.keeper.GetPendingJobs(ctx)
	queueDepth := len(pendingJobs)
	capacity := int(params.MaxJobsPerBlock)
	if capacity == 0 {
		return 1.0
	}

	utilizationRatio := float64(queueDepth) / float64(capacity)
	if utilizationRatio <= networkUtilizationThreshold {
		return 1.0
	}

	// Each 10% above the threshold adds a 10% surcharge.
	excessRatio := utilizationRatio - networkUtilizationThreshold
	surchargeDeciles := excessRatio / 0.10
	surcharge := surchargeDeciles * networkSurchargePerDecile

	return 1.0 + surcharge
}
