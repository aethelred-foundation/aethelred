package keeper

import (
	"context"
	"time"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ValidateVerificationWireForTest exposes validateVerificationWire for
// negative-case testing. This method is part of the production binary but
// only called from test code.
//
// NOTE: This follows the standard Go pattern of adding exported test helpers
// directly on the type rather than using export_test.go (which would require
// the _test package), because our tests are in keeper_test and need to call
// through the public API.
func (ch *ConsensusHandler) ValidateVerificationWireForTest(v *VerificationWire) error {
	return ch.validateVerificationWire(v)
}

// ValidateVerificationWireWithCtxForTest exposes deterministic validation that
// uses block context (e.g. block time) for freshness checks.
func (ch *ConsensusHandler) ValidateVerificationWireWithCtxForTest(ctx sdk.Context, v *VerificationWire) error {
	return ch.validateVerificationWireWithCtx(&ctx, v)
}

// ValidateTEEAttestationWireStrictForTest exposes the production-mode TEE
// attestation validation for testing. This checks AllowSimulated on the
// keeper's params and rejects simulated TEE when false.
func (ch *ConsensusHandler) ValidateTEEAttestationWireStrictForTest(ctx sdk.Context, v *VerificationWire) error {
	return ch.validateTEEAttestationWireStrict(ctx, v)
}

// ---------------------------------------------------------------------------
// Test wrappers for unexported functions
// ---------------------------------------------------------------------------

// SeverityOrdinalForTest wraps severityOrdinal for testing.
func SeverityOrdinalForTest(s AuditSeverity) int { return severityOrdinal(s) }

// StringSliceEqualForTest wraps stringSliceEqual for testing.
func StringSliceEqualForTest(a, b []string) bool { return stringSliceEqual(a, b) }

// ExtractValidatorAddressForTest wraps extractValidatorAddress for testing.
func ExtractValidatorAddressForTest(ext *VoteExtensionWire) string {
	return extractValidatorAddress(ext)
}

// GetMetaIntForTest wraps getMetaInt for testing.
func GetMetaIntForTest(meta map[string]string, key string, fallback int64) int64 {
	return getMetaInt(meta, key, fallback)
}

// GetMetaIntAsIntForTest wraps getMetaIntAsInt for testing.
func GetMetaIntAsIntForTest(meta map[string]string, key string, fallback int) int {
	return getMetaIntAsInt(meta, key, fallback)
}

// GetMetaStringSliceForTest wraps getMetaStringSlice for testing.
func GetMetaStringSliceForTest(meta map[string]string, key string) []string {
	return getMetaStringSlice(meta, key)
}

// GetMetaVRFAssignmentsForTest wraps getMetaVRFAssignments for testing.
func GetMetaVRFAssignmentsForTest(meta map[string]string, key string) []VRFAssignmentRecord {
	return getMetaVRFAssignments(meta, key)
}

// BytesLessForTest wraps bytesLess for testing.
func BytesLessForTest(a, b []byte) bool { return bytesLess(a, b) }

// RequiredThresholdCountForTest wraps requiredThresholdCount[int] for testing.
func RequiredThresholdCountForTest(total int, threshold int) int {
	return requiredThresholdCount(total, threshold)
}

// ExtractDrandPulsePayloadForTest wraps extractDrandPulsePayload for testing.
func ExtractDrandPulsePayloadForTest(ctx context.Context) (DrandPulsePayload, bool, error) {
	return extractDrandPulsePayload(ctx)
}

// ExtractDKGBeaconPayloadForTest wraps extractDKGBeaconPayload for testing.
func ExtractDKGBeaconPayloadForTest(ctx context.Context) (DKGBeaconPayload, bool, error) {
	return extractDKGBeaconPayload(ctx)
}

// IsLocalDrandEndpointForTest wraps isLocalDrandEndpoint for testing.
func IsLocalDrandEndpointForTest(endpoint string) bool { return isLocalDrandEndpoint(endpoint) }

// EqualBytesForTest wraps equalBytes for testing.
func EqualBytesForTest(a, b []byte) bool { return equalBytes(a, b) }

// ParsePositiveUintForTest wraps parsePositiveUint for testing.
func ParsePositiveUintForTest(raw string) (uint64, bool) { return parsePositiveUint(raw) }

// SaturatingMulForTest wraps saturatingMul for testing.
func SaturatingMulForTest(a, b uint64) uint64 { return saturatingMul(a, b) }

// GetConsensusThresholdForTest wraps getConsensusThreshold for testing.
func (ch *ConsensusHandler) GetConsensusThresholdForTest(ctx sdk.Context) int {
	return ch.getConsensusThreshold(ctx)
}

// PercentileIndexForTest wraps percentileIndex for testing.
func PercentileIndexForTest(n, p int) int { return percentileIndex(n, p) }

// StatusIconForTest wraps statusIcon for testing.
func StatusIconForTest(status MilestoneStatus) string { return statusIcon(status) }

// DetermineCurrentWeekForTest wraps determineCurrentWeek for testing.
func DetermineCurrentWeekForTest(blockTime time.Time) int { return determineCurrentWeek(blockTime) }

// AllowSimulatedInThisBuildForTest wraps allowSimulatedInThisBuild for testing.
func AllowSimulatedInThisBuildForTest() bool { return allowSimulatedInThisBuild() }

// NormalizeMeasurementHexForTest wraps normalizeMeasurementHex for testing.
func NormalizeMeasurementHexForTest(raw string) (string, error) {
	return normalizeMeasurementHex(raw)
}

// CanonicalizePlatformForTest wraps canonicalizePlatform for testing.
func CanonicalizePlatformForTest(platform string) (string, error) {
	return canonicalizePlatform(platform)
}

// ComputeInflationForYearForTest wraps computeInflationForYear for testing.
func ComputeInflationForYearForTest(config EmissionConfig, year int) int64 {
	return computeInflationForYear(config, year)
}

// RatioToPercentForTest wraps ratioToPercent for testing.
func RatioToPercentForTest(numerator, denominator sdkmath.Int) float64 {
	return ratioToPercent(numerator, denominator)
}

// FormatAETHELForTest wraps formatAETHEL for testing.
func FormatAETHELForTest(uaethel int64) string { return formatAETHEL(uaethel) }

// FormatWithCommasForTest wraps formatWithCommas for testing.
func FormatWithCommasForTest(n int64) string { return formatWithCommas(n) }

// LoadSchedulingMetadataForTest wraps loadSchedulingMetadata for testing.
// Returns all 11 values from loadSchedulingMetadata.
func (s *JobScheduler) LoadSchedulingMetadataForTest(job *types.ComputeJob) (
	retryCount int,
	lastAttempt int64,
	assigned []string,
	submittedBlock int64,
	vrfEntropy string,
	vrfAssignments []VRFAssignmentRecord,
	beaconSource string,
	beaconVersion string,
	beaconRound uint64,
	beaconRandomness string,
	beaconSigHash string,
) {
	return s.loadSchedulingMetadata(job)
}

// ---------------------------------------------------------------------------
// staking.go wrappers
// ---------------------------------------------------------------------------

// MeetsBasicCriteriaForTest wraps meetsBasicCriteria for testing.
func (vs *ValidatorSelector) MeetsBasicCriteriaForTest(cap *types.ValidatorCapability, criteria ValidatorSelectionCriteria) bool {
	return vs.meetsBasicCriteria(cap, criteria)
}

// IsExcludedForTest wraps isExcluded for testing.
func (vs *ValidatorSelector) IsExcludedForTest(addr string, exclusions []string) bool {
	return vs.isExcluded(addr, exclusions)
}

// CalculateSelectionScoreForTest wraps calculateSelectionScore for testing.
func (vs *ValidatorSelector) CalculateSelectionScoreForTest(cap *types.ValidatorCapability, stakingPower int64, criteria ValidatorSelectionCriteria) int64 {
	return vs.calculateSelectionScore(cap, stakingPower, criteria)
}

// SelectionTieBreakerForTest wraps selectionTieBreaker for testing.
func (vs *ValidatorSelector) SelectionTieBreakerForTest(seed []byte, addr string) [32]byte {
	return vs.selectionTieBreaker(seed, addr)
}

// SelectionEntropySeedForTest wraps selectionEntropySeed for testing.
func (vs *ValidatorSelector) SelectionEntropySeedForTest(sdkCtx sdk.Context, criteria ValidatorSelectionCriteria) []byte {
	return vs.selectionEntropySeed(sdkCtx, criteria)
}

// DeriveJobSelectionEntropyForTest wraps deriveJobSelectionEntropy for testing.
func (vs *ValidatorSelector) DeriveJobSelectionEntropyForTest(sdkCtx sdk.Context, job *types.ComputeJob) []byte {
	return vs.deriveJobSelectionEntropy(sdkCtx, job)
}

// GetValidatorStakingPowerForTest wraps getValidatorStakingPower for testing.
func (vs *ValidatorSelector) GetValidatorStakingPowerForTest(ctx context.Context, addr string) int64 {
	return vs.getValidatorStakingPower(ctx, addr)
}

// ---------------------------------------------------------------------------
// attestation_registry.go wrappers
// ---------------------------------------------------------------------------

// NormalizeCommitteeAddressForTest wraps normalizeCommitteeAddress for testing.
func NormalizeCommitteeAddressForTest(address string) string {
	return normalizeCommitteeAddress(address)
}

// HasNitroPlatformForTest wraps hasNitroPlatform for testing.
func HasNitroPlatformForTest(platforms []string) bool {
	return hasNitroPlatform(platforms)
}

// NormalizePCR0HexForTest wraps normalizePCR0Hex for testing.
func NormalizePCR0HexForTest(pcr0Hex string) (string, error) {
	return normalizePCR0Hex(pcr0Hex)
}

// ValidateTEEAttestationWireForTest wraps validateTEEAttestationWire for testing.
func (ch *ConsensusHandler) ValidateTEEAttestationWireForTest(v *VerificationWire) error {
	return ch.validateTEEAttestationWire(v)
}

// ---------------------------------------------------------------------------
// audit_closeout.go wrappers
// ---------------------------------------------------------------------------

// ClassifyImpactForTest wraps classifyImpact for testing.
func ClassifyImpactForTest(impact string) FindingSeverity {
	return classifyImpact(impact)
}

// ComputeSecurityScoreForTest wraps computeSecurityScore for testing.
func ComputeSecurityScoreForTest(report *AuditReport) int {
	return computeSecurityScore(report)
}

// ComputeTestCoverageForTest wraps computeTestCoverage for testing.
func ComputeTestCoverageForTest() int {
	return computeTestCoverage()
}

// ComputeRemediationRateForTest wraps computeRemediationRate for testing.
func ComputeRemediationRateForTest(tracker *RemediationTracker) int {
	return computeRemediationRate(tracker)
}

// ---------------------------------------------------------------------------
// scheduler.go wrappers
// ---------------------------------------------------------------------------

// NewValidatorPoolForTest wraps newValidatorPool for testing.
func NewValidatorPoolForTest(caps map[string]*types.ValidatorCapability) interface{} {
	return newValidatorPool(caps)
}

// ---------------------------------------------------------------------------
// consensus.go wrappers
// ---------------------------------------------------------------------------

// SimulatedVerificationEnabledForTest wraps simulatedVerificationEnabled for testing.
func (ch *ConsensusHandler) SimulatedVerificationEnabledForTest(ctx sdk.Context) bool {
	return ch.simulatedVerificationEnabled(ctx)
}

// ProductionVerificationModeForTest wraps productionVerificationMode for testing.
func (ch *ConsensusHandler) ProductionVerificationModeForTest(ctx sdk.Context) bool {
	return ch.productionVerificationMode(ctx)
}

// ---------------------------------------------------------------------------
// Additional export wrappers for coverage boost round 3
// ---------------------------------------------------------------------------

// StopForTest wraps scheduler Stop for testing.
func (s *JobScheduler) StopForTest() { s.Stop() }

// SeverityForReputationForTest wraps severityForReputation for testing.
func SeverityForReputationForTest(score int64) string { return severityForReputation(score) }

// ---------------------------------------------------------------------------
// Additional export wrappers for coverage boost round 5
// ---------------------------------------------------------------------------

// EmitEventIfEnabledForTest wraps emitEventIfEnabled for testing.
func EmitEventIfEnabledForTest(ctx sdk.Context, event sdk.Event) {
	emitEventIfEnabled(ctx, event)
}

// ExecuteVerificationForTest wraps executeVerification for testing.
func (ch *ConsensusHandler) ExecuteVerificationForTest(ctx sdk.Context, job *types.ComputeJob, validatorAddr string) types.VerificationResult {
	return ch.executeVerification(ctx, job, validatorAddr)
}

// AggregateBLSSignaturesForTest wraps aggregateBLSSignatures for testing.
func (ch *ConsensusHandler) AggregateBLSSignaturesForTest(ctx sdk.Context, jobID string, agg *AggregatedResult) {
	ch.aggregateBLSSignatures(ctx, jobID, agg)
}

// RecordSlashingEventForTest wraps recordSlashingEvent on SlashingIntegration for testing.
func (si *SlashingIntegration) RecordSlashingEventForTest(ctx sdk.Context, result *SlashResult) error {
	return si.recordSlashingEvent(ctx, result)
}

// GetValidatorStakeForTest wraps getValidatorStake on SlashingIntegration for testing.
func (si *SlashingIntegration) GetValidatorStakeForTest(ctx sdk.Context, addr string) (sdkmath.Int, error) {
	return si.getValidatorStake(ctx, addr)
}

// ActivateBondedValidatorCountForTest wraps activeBondedValidatorCount for testing.
func (fd *FeeDistributor) ActivateBondedValidatorCountForTest(ctx sdk.Context) int64 {
	return fd.activeBondedValidatorCount(ctx)
}

// JobPriorityQueueUpdateForTest wraps JobPriorityQueue.Update for testing.
func JobPriorityQueueUpdateForTest(pq *JobPriorityQueue, job *ScheduledJob, priority int64) {
	pq.Update(job, priority)
}

// ValidatePositiveCoinForTest wraps validatePositiveCoin for testing.
func ValidatePositiveCoinForTest(raw string, fieldName string) error {
	return validatePositiveCoin(raw, fieldName)
}

// UpdateParamsForTest exposes the UpdateParams handler via the unexported msgServer
// so that external test packages can exercise governance parameter updates.
func UpdateParamsForTest(k Keeper, goCtx context.Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	ms := msgServer{Keeper: k}
	return ms.UpdateParams(goCtx, msg)
}
