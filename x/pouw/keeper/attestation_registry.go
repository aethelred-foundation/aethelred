package keeper

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	nitroPlatformPrefix             = "aws-nitro"
	sgxPlatformPrefix               = "intel-sgx"
	nitroPlatformPCR0Prefix         = "aws-nitro:pcr0="
	sgxPlatformMRENCLAVEPrefix      = "intel-sgx:mrenclave="
	measurementHexLength            = 64 // 32-byte measurement hash encoded as hex
	fakeAttestationSlashRatio       = "1.00"
	minEmergencyRevocationApprovals = 2
)

// TrustedMeasurementRegistration represents a parsed platform-qualified
// TEE measurement declaration from validator capabilities.
type TrustedMeasurementRegistration struct {
	Platform       string
	MeasurementHex string
}

type trustedMeasurementRevocationStatus string

const (
	trustedMeasurementRevocationPending  trustedMeasurementRevocationStatus = "pending"
	trustedMeasurementRevocationExecuted trustedMeasurementRevocationStatus = "executed"
)

type trustedMeasurementRevocationState struct {
	RequestID         string                             `json:"request_id"`
	Platform          string                             `json:"platform"`
	MeasurementHex    string                             `json:"measurement_hex"`
	RequestedBy       string                             `json:"requested_by"`
	Approvals         []string                           `json:"approvals"`
	ApprovalThreshold int                                `json:"approval_threshold"`
	Status            trustedMeasurementRevocationStatus `json:"status"`
	CreatedAtHeight   int64                              `json:"created_at_height"`
	ExecutedAtHeight  int64                              `json:"executed_at_height,omitempty"`
}

func canonicalizePlatform(platform string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(platform)) {
	case nitroPlatformPrefix:
		return nitroPlatformPrefix, nil
	case sgxPlatformPrefix:
		return sgxPlatformPrefix, nil
	default:
		return "", fmt.Errorf("unsupported TEE platform: %s", platform)
	}
}

func normalizeMeasurementHex(raw string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(raw))
	if len(normalized) != measurementHexLength {
		return "", fmt.Errorf("invalid measurement hex length: got %d, need %d", len(normalized), measurementHexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("invalid measurement hex: %w", err)
	}
	return normalized, nil
}

func measurementRegistryKey(platform, measurementHex string) string {
	return platform + ":" + measurementHex
}

func validatorMeasurementKey(validatorAddr, platform string) string {
	return validatorAddr + "|" + platform
}

// RegisterValidatorMeasurement stores a validator's trusted platform measurement
// and marks it as globally registered.
func (k Keeper) RegisterValidatorMeasurement(
	ctx context.Context,
	validatorAddr string,
	platform string,
	measurementHex string,
) error {
	if validatorAddr == "" {
		return fmt.Errorf("validator address cannot be empty")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}

	normalizedMeasurement, err := normalizeMeasurementHex(measurementHex)
	if err != nil {
		return err
	}

	validatorPlatformKey := validatorMeasurementKey(validatorAddr, normalizedPlatform)
	if err := k.ValidatorMeasurements.Set(ctx, validatorPlatformKey, normalizedMeasurement); err != nil {
		return err
	}

	globalKey := measurementRegistryKey(normalizedPlatform, normalizedMeasurement)
	if err := k.RegisteredMeasurements.Set(ctx, globalKey); err != nil {
		return err
	}

	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				"validator_tee_measurement_registered",
				sdk.NewAttribute("validator", validatorAddr),
				sdk.NewAttribute("platform", normalizedPlatform),
				sdk.NewAttribute("measurement", normalizedMeasurement),
			),
		)
	}

	return nil
}

// RegisterValidatorPCR0 stores a validator's trusted Nitro PCR0 hash and marks
// it as globally registered.
func (k Keeper) RegisterValidatorPCR0(ctx context.Context, validatorAddr, pcr0Hex string) error {
	if err := k.RegisterValidatorMeasurement(ctx, validatorAddr, nitroPlatformPrefix, pcr0Hex); err != nil {
		return err
	}

	// Backward-compatible storage paths for existing query/CLI surfaces.
	normalized, err := normalizePCR0Hex(pcr0Hex)
	if err != nil {
		return err
	}
	if err := k.ValidatorPCR0Mappings.Set(ctx, validatorAddr, normalized); err != nil {
		return err
	}
	if err := k.RegisteredPCR0Set.Set(ctx, normalized); err != nil {
		return err
	}
	return nil
}

// ValidateTEEAttestationMeasurement ensures the attested measurement is both globally
// registered and bound to the submitting validator for the given platform.
func (k Keeper) ValidateTEEAttestationMeasurement(
	ctx context.Context,
	validatorAddr string,
	platform string,
	measurement []byte,
) error {
	if len(measurement) == 0 {
		return fmt.Errorf("missing TEE measurement for registry check")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}

	measurementHex := strings.ToLower(hex.EncodeToString(measurement))
	if len(measurementHex) != measurementHexLength {
		return fmt.Errorf("invalid %s measurement length: got %d hex chars, need %d", normalizedPlatform, len(measurementHex), measurementHexLength)
	}

	globalKey := measurementRegistryKey(normalizedPlatform, measurementHex)
	isRegistered, err := k.RegisteredMeasurements.Has(ctx, globalKey)
	if err != nil {
		return fmt.Errorf("failed to query %s measurement registry: %w", normalizedPlatform, err)
	}
	if !isRegistered {
		return fmt.Errorf("unregistered %s measurement: %s", normalizedPlatform, measurementHex)
	}

	expectedMeasurement, err := k.ValidatorMeasurements.Get(ctx, validatorMeasurementKey(validatorAddr, normalizedPlatform))
	if err != nil {
		return fmt.Errorf("validator %s has no registered %s measurement", validatorAddr, normalizedPlatform)
	}
	if expectedMeasurement != measurementHex {
		return fmt.Errorf("tampered %s measurement for validator %s", normalizedPlatform, validatorAddr)
	}

	return nil
}

// ValidateTEEAttestationPCR0 ensures the attested measurement is both globally
// registered and bound to the submitting validator.
func (k Keeper) ValidateTEEAttestationPCR0(ctx context.Context, validatorAddr string, measurement []byte) error {
	return k.ValidateTEEAttestationMeasurement(ctx, validatorAddr, nitroPlatformPrefix, measurement)
}

// IsRegisteredMeasurement checks platform-qualified global registry membership.
func (k Keeper) IsRegisteredMeasurement(
	ctx context.Context,
	platform string,
	measurement []byte,
) (bool, string, error) {
	if len(measurement) == 0 {
		return false, "", fmt.Errorf("missing TEE measurement for registry check")
	}
	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return false, "", err
	}

	measurementHex := strings.ToLower(hex.EncodeToString(measurement))
	if len(measurementHex) != measurementHexLength {
		return false, measurementHex, fmt.Errorf("invalid %s measurement length: got %d hex chars, need %d", normalizedPlatform, len(measurementHex), measurementHexLength)
	}

	registered, err := k.RegisteredMeasurements.Has(ctx, measurementRegistryKey(normalizedPlatform, measurementHex))
	if err != nil {
		return false, measurementHex, fmt.Errorf("failed to query %s measurement registry: %w", normalizedPlatform, err)
	}
	return registered, measurementHex, nil
}

// AppendTrustedMeasurementByAuthority appends a new trusted measurement.
// This is intended to be invoked by governance-controlled upgrade handlers.
func (k Keeper) AppendTrustedMeasurementByAuthority(
	ctx context.Context,
	authority string,
	platform string,
	measurementHex string,
) error {
	if strings.TrimSpace(authority) != k.GetAuthority() {
		return fmt.Errorf("unauthorized measurement update caller")
	}

	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}
	normalizedMeasurement, err := normalizeMeasurementHex(measurementHex)
	if err != nil {
		return err
	}

	key := measurementRegistryKey(normalizedPlatform, normalizedMeasurement)
	alreadyRegistered, err := k.RegisteredMeasurements.Has(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to query trusted measurement registry: %w", err)
	}

	registryResult := "already_registered"
	if !alreadyRegistered {
		if err := k.RegisteredMeasurements.Set(ctx, key); err != nil {
			return err
		}
		registryResult = "registered"
	}

	legacyPCR0Result := "not_applicable"
	if normalizedPlatform == nitroPlatformPrefix {
		legacyRegistered, err := k.RegisteredPCR0Set.Has(ctx, normalizedMeasurement)
		if err != nil {
			return fmt.Errorf("failed to query legacy nitro registry: %w", err)
		}
		legacyPCR0Result = "already_registered"
		if !legacyRegistered {
			if err := k.RegisteredPCR0Set.Set(ctx, normalizedMeasurement); err != nil {
				return err
			}
			legacyPCR0Result = "registered"
		}
	}

	k.recordTrustedMeasurementMutation(
		ctx,
		AuditCategoryGovernance,
		AuditSeverityWarning,
		"trusted_measurement_appended",
		"append",
		"authority",
		strings.TrimSpace(authority),
		normalizedPlatform,
		normalizedMeasurement,
		registryResult,
		legacyPCR0Result,
	)

	return nil
}

// RevokeTrustedMeasurementBySecurityCommittee removes a trusted measurement using
// emergency committee authority (top 10 validators by bonded stake).
func (k Keeper) RevokeTrustedMeasurementBySecurityCommittee(
	ctx context.Context,
	requester string,
	platform string,
	measurementHex string,
) error {
	requester = normalizeCommitteeAddress(requester)
	committeeMembers, err := k.securityCommitteeMembers(ctx)
	if err != nil {
		return err
	}
	if !committeeContainsRequester(requester, committeeMembers) {
		return fmt.Errorf("requester is not in security committee")
	}
	sdkCtx, ok := unwrapSDKContext(ctx)
	if !ok {
		return fmt.Errorf("sdk context unavailable for trusted measurement revocation")
	}
	approvalThreshold, err := trustedMeasurementRevocationApprovalThreshold(len(committeeMembers))
	if err != nil {
		return err
	}
	normalizedPlatform, err := canonicalizePlatform(platform)
	if err != nil {
		return err
	}
	normalizedMeasurement, err := normalizeMeasurementHex(measurementHex)
	if err != nil {
		return err
	}

	key := measurementRegistryKey(normalizedPlatform, normalizedMeasurement)
	registered, err := k.RegisteredMeasurements.Has(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to query trusted measurement registry: %w", err)
	}

	legacyPCR0Result := "not_applicable"
	legacyRegistered := false
	if normalizedPlatform == nitroPlatformPrefix {
		legacyRegistered, err = k.RegisteredPCR0Set.Has(ctx, normalizedMeasurement)
		if err != nil {
			return fmt.Errorf("failed to query legacy nitro registry: %w", err)
		}
		legacyPCR0Result = "revoked"
	}

	if !registered && !legacyRegistered {
		return fmt.Errorf("trusted %s measurement not registered: %s", normalizedPlatform, normalizedMeasurement)
	}

	requestKey := key
	state, found, err := k.getTrustedMeasurementRevocationState(ctx, requestKey)
	if err != nil {
		return err
	}
	isNewRequest := !found || state.Status == trustedMeasurementRevocationExecuted
	if isNewRequest {
		state = &trustedMeasurementRevocationState{
			RequestID:         trustedMeasurementRevocationRequestID(normalizedPlatform, normalizedMeasurement, sdkCtx.BlockHeight()),
			Platform:          normalizedPlatform,
			MeasurementHex:    normalizedMeasurement,
			RequestedBy:       requester,
			Approvals:         []string{requester},
			ApprovalThreshold: approvalThreshold,
			Status:            trustedMeasurementRevocationPending,
			CreatedAtHeight:   sdkCtx.BlockHeight(),
		}
	} else {
		if revocationStateHasApprover(state, requester) {
			return fmt.Errorf("security committee member %s already approved revocation for %s", requester, requestKey)
		}
		state.Approvals = append(state.Approvals, requester)
		state.ApprovalThreshold = approvalThreshold
	}

	if len(state.Approvals) < state.ApprovalThreshold {
		if err := k.setTrustedMeasurementRevocationState(ctx, requestKey, state); err != nil {
			return err
		}
		k.recordTrustedMeasurementRevocationApproval(
			ctx,
			requester,
			state,
			revocationApprovalOperation(isNewRequest, false),
		)
		return nil
	}

	k.recordTrustedMeasurementRevocationApproval(
		ctx,
		requester,
		state,
		revocationApprovalOperation(isNewRequest, true),
	)

	registryResult := "already_absent"
	if registered {
		if err := k.RegisteredMeasurements.Remove(ctx, key); err != nil {
			return err
		}
		registryResult = "revoked"
	}

	if normalizedPlatform == nitroPlatformPrefix {
		legacyPCR0Result = "already_absent"
		if legacyRegistered {
			if err := k.RegisteredPCR0Set.Remove(ctx, normalizedMeasurement); err != nil {
				return err
			}
			legacyPCR0Result = "revoked"
		}
	}

	k.recordTrustedMeasurementMutation(
		ctx,
		AuditCategorySecurity,
		AuditSeverityCritical,
		"trusted_measurement_revoked",
		"revoke",
		"security_committee",
		normalizeCommitteeAddress(requester),
		normalizedPlatform,
		normalizedMeasurement,
		registryResult,
		legacyPCR0Result,
	)

	state.Status = trustedMeasurementRevocationExecuted
	state.ExecutedAtHeight = sdkCtx.BlockHeight()
	if err := k.setTrustedMeasurementRevocationState(ctx, requestKey, state); err != nil {
		return err
	}

	return nil
}

func (k Keeper) recordTrustedMeasurementMutation(
	ctx context.Context,
	category AuditCategory,
	severity AuditSeverity,
	action string,
	operation string,
	actorRole string,
	actor string,
	platform string,
	measurement string,
	registryResult string,
	legacyPCR0Result string,
) {
	sdkCtx, ok := unwrapSDKContext(ctx)
	if !ok {
		return
	}

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"trusted_tee_measurement_registry_updated",
			sdk.NewAttribute("actor", actor),
			sdk.NewAttribute("actor_role", actorRole),
			sdk.NewAttribute("operation", operation),
			sdk.NewAttribute("platform", platform),
			sdk.NewAttribute("measurement", measurement),
			sdk.NewAttribute("registry_result", registryResult),
			sdk.NewAttribute("legacy_pcr0_result", legacyPCR0Result),
		),
	)

	if k.auditLogger != nil {
		k.auditLogger.Record(sdkCtx, category, severity, action, actor, map[string]string{
			"actor_role":         actorRole,
			"platform":           platform,
			"measurement":        measurement,
			"registry_result":    registryResult,
			"legacy_pcr0_result": legacyPCR0Result,
		})
	}
}

// IsRegisteredPCR0 checks global registry membership for a measurement hash.
func (k Keeper) IsRegisteredPCR0(ctx context.Context, measurement []byte) (bool, string, error) {
	return k.IsRegisteredMeasurement(ctx, nitroPlatformPrefix, measurement)
}

func normalizeCommitteeAddress(address string) string {
	return strings.TrimSpace(address)
}

func trustedMeasurementRevocationApprovalThreshold(committeeSize int) (int, error) {
	if committeeSize < minEmergencyRevocationApprovals {
		return 0, fmt.Errorf("security committee quorum unavailable: need at least %d bonded validators", minEmergencyRevocationApprovals)
	}
	return minEmergencyRevocationApprovals, nil
}

func revocationApprovalOperation(isNewRequest bool, thresholdReached bool) string {
	if thresholdReached {
		return "approval_threshold_reached"
	}
	if isNewRequest {
		return "request_created"
	}
	return "approval_recorded"
}

func trustedMeasurementRevocationRequestID(platform, measurementHex string, blockHeight int64) string {
	return fmt.Sprintf("%s:%s:%d", platform, measurementHex, blockHeight)
}

func isRequesterMatchValidator(requester string, validator stakingtypes.Validator) bool {
	req := normalizeCommitteeAddress(requester)
	if req == "" {
		return false
	}
	if validator.GetOperator() == req {
		return true
	}
	if valAddr, err := sdk.ValAddressFromBech32(validator.GetOperator()); err == nil {
		if sdk.AccAddress(valAddr).String() == req {
			return true
		}
	}
	return false
}

func (k Keeper) isSecurityCommitteeMember(ctx context.Context, requester string) bool {
	validators, err := k.securityCommitteeMembers(ctx)
	if err != nil {
		return false
	}
	return committeeContainsRequester(requester, validators)
}

func (k Keeper) securityCommitteeMembers(ctx context.Context) ([]stakingtypes.Validator, error) {
	if k.stakingKeeper == nil {
		return nil, fmt.Errorf("staking keeper unavailable for security committee lookup")
	}

	validators, err := k.stakingKeeper.GetAllValidators(ctx)
	if err != nil || len(validators) == 0 {
		if err != nil {
			return nil, fmt.Errorf("failed to load security committee validators: %w", err)
		}
		return nil, fmt.Errorf("security committee is empty")
	}

	bondedValidators := make([]stakingtypes.Validator, 0, len(validators))
	for _, validator := range validators {
		if validator.Status == stakingtypes.Bonded {
			bondedValidators = append(bondedValidators, validator)
		}
	}
	if len(bondedValidators) == 0 {
		return nil, fmt.Errorf("security committee is empty")
	}

	sort.Slice(bondedValidators, func(i, j int) bool {
		left := bondedValidators[i].GetBondedTokens()
		right := bondedValidators[j].GetBondedTokens()
		if !left.Equal(right) {
			return left.GT(right)
		}
		return bondedValidators[i].GetOperator() < bondedValidators[j].GetOperator()
	})

	committeeSize := 10
	if len(bondedValidators) < committeeSize {
		committeeSize = len(bondedValidators)
	}

	return append([]stakingtypes.Validator(nil), bondedValidators[:committeeSize]...), nil
}

func committeeContainsRequester(requester string, validators []stakingtypes.Validator) bool {
	for _, validator := range validators {
		if isRequesterMatchValidator(requester, validator) {
			return true
		}
	}
	return false
}

func (k Keeper) getTrustedMeasurementRevocationState(ctx context.Context, requestKey string) (*trustedMeasurementRevocationState, bool, error) {
	found, err := k.TrustedMeasurementRevocations.Has(ctx, requestKey)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query trusted measurement revocation state: %w", err)
	}
	if !found {
		return nil, false, nil
	}

	raw, err := k.TrustedMeasurementRevocations.Get(ctx, requestKey)
	if err != nil {
		return nil, false, fmt.Errorf("failed to load trusted measurement revocation state: %w", err)
	}

	var state trustedMeasurementRevocationState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, false, fmt.Errorf("failed to decode trusted measurement revocation state: %w", err)
	}
	return &state, true, nil
}

func (k Keeper) setTrustedMeasurementRevocationState(ctx context.Context, requestKey string, state *trustedMeasurementRevocationState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to encode trusted measurement revocation state: %w", err)
	}
	return k.TrustedMeasurementRevocations.Set(ctx, requestKey, string(encoded))
}

func revocationStateHasApprover(state *trustedMeasurementRevocationState, approver string) bool {
	for _, existing := range state.Approvals {
		if existing == approver {
			return true
		}
	}
	return false
}

func (k Keeper) recordTrustedMeasurementRevocationApproval(
	ctx context.Context,
	actor string,
	state *trustedMeasurementRevocationState,
	operation string,
) {
	sdkCtx, ok := unwrapSDKContext(ctx)
	if !ok {
		return
	}

	approvalCount := fmt.Sprintf("%d", len(state.Approvals))
	approvalThreshold := fmt.Sprintf("%d", state.ApprovalThreshold)
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"trusted_tee_measurement_revocation_approval_recorded",
			sdk.NewAttribute("actor", actor),
			sdk.NewAttribute("actor_role", "security_committee"),
			sdk.NewAttribute("operation", operation),
			sdk.NewAttribute("request_id", state.RequestID),
			sdk.NewAttribute("platform", state.Platform),
			sdk.NewAttribute("measurement", state.MeasurementHex),
			sdk.NewAttribute("approval_count", approvalCount),
			sdk.NewAttribute("approval_threshold", approvalThreshold),
			sdk.NewAttribute("status", string(state.Status)),
		),
	)

	if k.auditLogger != nil {
		k.auditLogger.Record(sdkCtx, AuditCategorySecurity, AuditSeverityWarning, "trusted_measurement_revocation_approval_recorded", actor, map[string]string{
			"actor_role":         "security_committee",
			"operation":          operation,
			"request_id":         state.RequestID,
			"platform":           state.Platform,
			"measurement":        state.MeasurementHex,
			"approval_count":     approvalCount,
			"approval_threshold": approvalThreshold,
			"status":             string(state.Status),
		})
	}
}

// ExtractTEETrustedMeasurementsFromPlatforms parses platform strings and returns
// recognized platform-qualified trusted measurements.
func ExtractTEETrustedMeasurementsFromPlatforms(platforms []string) []TrustedMeasurementRegistration {
	seen := make(map[string]struct{})
	var registrations []TrustedMeasurementRegistration

	for _, platform := range platforms {
		normalized := strings.TrimSpace(strings.ToLower(platform))
		if strings.HasPrefix(normalized, nitroPlatformPCR0Prefix) {
			raw := strings.TrimPrefix(normalized, nitroPlatformPCR0Prefix)
			measurement, err := normalizeMeasurementHex(raw)
			if err != nil {
				continue
			}
			key := measurementRegistryKey(nitroPlatformPrefix, measurement)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			registrations = append(registrations, TrustedMeasurementRegistration{
				Platform:       nitroPlatformPrefix,
				MeasurementHex: measurement,
			})
			continue
		}

		if strings.HasPrefix(normalized, sgxPlatformMRENCLAVEPrefix) {
			raw := strings.TrimPrefix(normalized, sgxPlatformMRENCLAVEPrefix)
			measurement, err := normalizeMeasurementHex(raw)
			if err != nil {
				continue
			}
			key := measurementRegistryKey(sgxPlatformPrefix, measurement)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			registrations = append(registrations, TrustedMeasurementRegistration{
				Platform:       sgxPlatformPrefix,
				MeasurementHex: measurement,
			})
		}
	}

	return registrations
}

// ExtractNitroPCR0FromPlatforms parses a validator's tee_platforms list and
// returns a configured Nitro PCR0 hash when present.
func ExtractNitroPCR0FromPlatforms(platforms []string) (string, bool) {
	for _, registration := range ExtractTEETrustedMeasurementsFromPlatforms(platforms) {
		if registration.Platform == nitroPlatformPrefix {
			return registration.MeasurementHex, true
		}
	}
	return "", false
}

// hasNitroPlatform returns true when a capability advertises AWS Nitro.
func hasNitroPlatform(platforms []string) bool {
	for _, platform := range platforms {
		normalized := strings.TrimSpace(strings.ToLower(platform))
		if strings.HasPrefix(normalized, nitroPlatformPrefix) {
			return true
		}
	}
	return false
}

func normalizePCR0Hex(pcr0Hex string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(pcr0Hex))
	if len(normalized) != measurementHexLength {
		return "", fmt.Errorf("invalid PCR0 hex length: got %d, need %d", len(normalized), measurementHexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("invalid PCR0 hex: %w", err)
	}
	return normalized, nil
}

// slashUntrustedAttestationValidator applies punitive slashing when a validator
// submits an unregistered or tampered TEE measurement.
func (k Keeper) slashUntrustedAttestationValidator(ctx context.Context, validatorAddr, jobID, reason string) {
	slashFactor := sdkmath.LegacyMustNewDecFromStr(fakeAttestationSlashRatio)
	slashedAmount, applied, slashErr := k.slashValidatorBondedStake(ctx, validatorAddr, slashFactor)
	if slashErr != nil {
		if sdkCtx, ok := unwrapSDKContext(ctx); ok {
			sdkCtx.Logger().Warn("Failed bonded-stake slashing for untrusted TEE attestation",
				"validator", validatorAddr,
				"error", slashErr,
			)
		}
	}

	stats, err := k.GetValidatorStats(ctx, validatorAddr)
	if err != nil || stats == nil {
		stats = types.NewValidatorStats(validatorAddr)
	}
	stats.RecordFailure()
	stats.RecordSlashing()
	_ = k.SetValidatorStats(ctx, stats)

	if sdkCtx, ok := unwrapSDKContext(ctx); ok {
		slashedValue := "0"
		if applied {
			slashedValue = slashedAmount.String()
		}

		sdkCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				"validator_slashed_untrusted_tee",
				sdk.NewAttribute("validator", validatorAddr),
				sdk.NewAttribute("job_id", jobID),
				sdk.NewAttribute("reason", reason),
				sdk.NewAttribute("slash_factor", fakeAttestationSlashRatio),
				sdk.NewAttribute("slashed_amount", slashedValue),
				sdk.NewAttribute("slashed_from_bonded_stake", fmt.Sprintf("%t", applied)),
			),
		)
	}
}
