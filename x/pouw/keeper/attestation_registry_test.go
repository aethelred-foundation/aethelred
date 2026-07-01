package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	storemetrics "cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/types"
	sealkeeper "github.com/aethelred/aethelred/x/seal/keeper"
	verifykeeper "github.com/aethelred/aethelred/x/verify/keeper"
)

type registryBankKeeper struct{}

func (registryBankKeeper) SendCoinsFromModuleToAccount(context.Context, string, sdk.AccAddress, sdk.Coins) error {
	return nil
}
func (registryBankKeeper) SendCoinsFromAccountToModule(context.Context, sdk.AccAddress, string, sdk.Coins) error {
	return nil
}
func (registryBankKeeper) SendCoinsFromModuleToModule(context.Context, string, string, sdk.Coins) error {
	return nil
}
func (registryBankKeeper) BurnCoins(context.Context, string, sdk.Coins) error { return nil }
func (registryBankKeeper) MintCoins(context.Context, string, sdk.Coins) error { return nil }
func (registryBankKeeper) SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}

type registryStakingKeeper struct {
	validators []stakingtypes.Validator
	// byConsAddr maps a bech32 consensus address to its validator, used by
	// GetValidatorByConsAddr in seal-quorum resolution tests.
	byConsAddr map[string]stakingtypes.Validator
}

func (m registryStakingKeeper) GetAllValidators(context.Context) ([]stakingtypes.Validator, error) {
	return m.validators, nil
}

func (registryStakingKeeper) GetValidator(context.Context, sdk.ValAddress) (stakingtypes.Validator, error) {
	return stakingtypes.Validator{}, nil
}

func (m registryStakingKeeper) GetValidatorByConsAddr(_ context.Context, consAddr sdk.ConsAddress) (stakingtypes.Validator, error) {
	if v, ok := m.byConsAddr[consAddr.String()]; ok {
		return v, nil
	}
	return stakingtypes.Validator{}, fmt.Errorf("validator not found for consensus address %s", consAddr)
}

func newRegistryTestKeeper(t *testing.T) (Keeper, sdk.Context) {
	return newRegistryTestKeeperWithValidators(t, nil)
}

func newRegistryTestKeeperWithValidators(t *testing.T, validators []stakingtypes.Validator) (Keeper, sdk.Context) {
	return newRegistryTestKeeperWithStaking(t, registryStakingKeeper{validators: validators})
}

func newRegistryTestKeeperWithStaking(t *testing.T, sk registryStakingKeeper) (Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.ModuleName)
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger(), storemetrics.NoOpMetrics{})
	cms.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, cms.LoadLatestVersion())

	ctx := sdk.NewContext(cms, tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Date(2026, 2, 21, 0, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())

	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)

	k := NewKeeper(
		cdc,
		runtime.NewKVStoreService(storeKey),
		sk,
		registryBankKeeper{},
		sealkeeper.Keeper{},
		verifykeeper.Keeper{},
		"authority",
	)
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	require.NoError(t, k.JobCount.Set(ctx, 0))

	return k, ctx
}

func findEvent(t *testing.T, ctx sdk.Context, eventType string) sdk.Event {
	t.Helper()
	var matched sdk.Event
	found := false
	for _, event := range ctx.EventManager().Events() {
		if event.Type == eventType {
			matched = event
			found = true
		}
	}
	if !found {
		t.Fatalf("event %q not found", eventType)
	}
	return matched
}

func eventAttr(t *testing.T, event sdk.Event, key string) string {
	t.Helper()
	for _, attr := range event.Attributes {
		if string(attr.Key) == key {
			return string(attr.Value)
		}
	}
	t.Fatalf("attribute %q not found on event %q", key, event.Type)
	return ""
}

func loadTrustedMeasurementRevocationState(t *testing.T, k Keeper, ctx sdk.Context, requestKey string) trustedMeasurementRevocationState {
	t.Helper()

	raw, err := k.TrustedMeasurementRevocations.Get(ctx, requestKey)
	require.NoError(t, err)

	var state trustedMeasurementRevocationState
	require.NoError(t, json.Unmarshal([]byte(raw), &state))
	return state
}

func makeCommitteeValidator(seed string, tokens int64) stakingtypes.Validator {
	raw := make([]byte, 20)
	copy(raw, []byte(seed))
	return stakingtypes.Validator{
		OperatorAddress: sdk.ValAddress(raw).String(),
		Status:          stakingtypes.Bonded,
		Tokens:          sdkmath.NewInt(tokens),
	}
}

func TestAttestationRegistry_RegisterAndValidatePCR0(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	registered := sha256.Sum256([]byte("trusted-pcr0"))
	registeredHex := hex.EncodeToString(registered[:])

	require.NoError(t, k.RegisterValidatorPCR0(ctx, "validator-1", registeredHex))
	require.NoError(t, k.ValidateTEEAttestationPCR0(ctx, "validator-1", registered[:]))

	unregistered := sha256.Sum256([]byte("untrusted-pcr0"))
	err := k.ValidateTEEAttestationPCR0(ctx, "validator-1", unregistered[:])
	require.ErrorContains(t, err, "unregistered aws-nitro measurement")
}

func TestAttestationRegistry_RegisterAndValidateSGXMRENCLAVE(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	measurement := sha256.Sum256([]byte("trusted-mrenclave"))
	measurementHex := hex.EncodeToString(measurement[:])

	require.NoError(t, k.RegisterValidatorMeasurement(ctx, "validator-1", "intel-sgx", measurementHex))
	require.NoError(t, k.ValidateTEEAttestationMeasurement(ctx, "validator-1", "intel-sgx", measurement[:]))

	tampered := sha256.Sum256([]byte("tampered-mrenclave"))
	err := k.ValidateTEEAttestationMeasurement(ctx, "validator-1", "intel-sgx", tampered[:])
	require.ErrorContains(t, err, "unregistered intel-sgx measurement")
}

func TestExtractTEETrustedMeasurementsFromPlatforms(t *testing.T) {
	nitro := sha256.Sum256([]byte("nitro"))
	sgx := sha256.Sum256([]byte("sgx"))

	registrations := ExtractTEETrustedMeasurementsFromPlatforms([]string{
		"aws-nitro",
		"aws-nitro:pcr0=" + hex.EncodeToString(nitro[:]),
		"intel-sgx:mrenclave=" + hex.EncodeToString(sgx[:]),
		"intel-sgx",
	})
	require.Len(t, registrations, 2)
	require.Equal(t, "aws-nitro", registrations[0].Platform)
	require.Equal(t, hex.EncodeToString(nitro[:]), registrations[0].MeasurementHex)
	require.Equal(t, "intel-sgx", registrations[1].Platform)
	require.Equal(t, hex.EncodeToString(sgx[:]), registrations[1].MeasurementHex)
}

func TestConsensusHandler_StrictTEEValidationUsesPCR0Registry(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	ch := NewConsensusHandler(log.NewNopLogger(), &k, nil)

	outputHash := sha256.Sum256([]byte("output"))
	measurement := sha256.Sum256([]byte("nitro-measurement"))
	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	attestation := TEEAttestationWire{
		Platform:    "aws-nitro",
		Measurement: measurement[:],
		Quote:       make([]byte, 128),
		UserData:    outputHash[:],
		Nonce:       make([]byte, 32),
		Timestamp:   ctx.BlockTime(),
	}
	payload, err := json.Marshal(attestation)
	require.NoError(t, err)

	verification := &VerificationWire{
		JobID:           "job-pcr0",
		ModelHash:       modelHash[:],
		InputHash:       inputHash[:],
		OutputHash:      outputHash[:],
		AttestationType: "tee",
		TEEAttestation:  payload,
		ExecutionTimeMs: 10,
		Success:         true,
		Nonce:           make([]byte, 32),
	}

	err = ch.validateTEEAttestationWireStrict(ctx, verification)
	require.ErrorContains(t, err, "unregistered aws-nitro measurement")

	require.NoError(t, k.RegisterValidatorPCR0(ctx, "validator-anchor", hex.EncodeToString(measurement[:])))
	require.NoError(t, ch.validateTEEAttestationWireStrict(ctx, verification))
}

func TestAttestationRegistry_UntrustedSlashUpdatesValidatorStats(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	k.slashUntrustedAttestationValidator(ctx, "validator-2", "job-2", "tampered PCR0")

	stats, err := k.GetValidatorStats(ctx, "validator-2")
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.SlashingEvents)
	require.Less(t, stats.ReputationScore, int64(50))
}

func TestAttestationRegistry_AppendTrustedMeasurement_AuditsAndReconcilesLegacyNitroIndex(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)

	measurement := sha256.Sum256([]byte("trusted-nitro-authority"))
	measurementHex := hex.EncodeToString(measurement[:])
	key := measurementRegistryKey(nitroPlatformPrefix, measurementHex)

	require.NoError(t, k.RegisteredMeasurements.Set(ctx, key))
	require.NoError(t, k.AppendTrustedMeasurementByAuthority(ctx, "authority", "aws-nitro", measurementHex))

	registered, err := k.RegisteredPCR0Set.Has(ctx, measurementHex)
	require.NoError(t, err)
	require.True(t, registered)

	event := findEvent(t, ctx, "trusted_tee_measurement_registry_updated")
	require.Equal(t, "authority", eventAttr(t, event, "actor"))
	require.Equal(t, "authority", eventAttr(t, event, "actor_role"))
	require.Equal(t, "append", eventAttr(t, event, "operation"))
	require.Equal(t, "aws-nitro", eventAttr(t, event, "platform"))
	require.Equal(t, measurementHex, eventAttr(t, event, "measurement"))
	require.Equal(t, "already_registered", eventAttr(t, event, "registry_result"))
	require.Equal(t, "registered", eventAttr(t, event, "legacy_pcr0_result"))

	records := k.AuditLogger().GetRecords()
	require.NotEmpty(t, records)
	last := records[len(records)-1]
	require.Equal(t, "trusted_measurement_appended", last.Action)
	require.Equal(t, "authority", last.Actor)
	require.Equal(t, "authority", last.Details["actor_role"])
	require.Equal(t, "already_registered", last.Details["registry_result"])
	require.Equal(t, "registered", last.Details["legacy_pcr0_result"])
}

func TestAttestationRegistry_RevokeTrustedMeasurementBySecurityCommittee_RequiresMultiApprovalAndAuditsLifecycle(t *testing.T) {
	committeeOne := makeCommitteeValidator("committee-member-1", 2_000_000)
	committeeTwo := makeCommitteeValidator("committee-member-2", 1_000_000)
	k, ctx := newRegistryTestKeeperWithValidators(t, []stakingtypes.Validator{committeeOne, committeeTwo})

	measurement := sha256.Sum256([]byte("revoked-nitro-measurement"))
	measurementHex := hex.EncodeToString(measurement[:])
	requestKey := measurementRegistryKey(nitroPlatformPrefix, measurementHex)

	require.NoError(t, k.AppendTrustedMeasurementByAuthority(ctx, "authority", "aws-nitro", measurementHex))
	require.NoError(t, k.RevokeTrustedMeasurementBySecurityCommittee(ctx, committeeOne.OperatorAddress, "aws-nitro", measurementHex))

	registered, err := k.RegisteredMeasurements.Has(ctx, measurementRegistryKey(nitroPlatformPrefix, measurementHex))
	require.NoError(t, err)
	require.True(t, registered)

	legacyRegistered, err := k.RegisteredPCR0Set.Has(ctx, measurementHex)
	require.NoError(t, err)
	require.True(t, legacyRegistered)

	state := loadTrustedMeasurementRevocationState(t, k, ctx, requestKey)
	require.Equal(t, trustedMeasurementRevocationPending, state.Status)
	require.Equal(t, committeeOne.OperatorAddress, state.RequestedBy)
	require.Equal(t, []string{committeeOne.OperatorAddress}, state.Approvals)
	require.Equal(t, 2, state.ApprovalThreshold)
	require.EqualValues(t, ctx.BlockHeight(), state.CreatedAtHeight)
	require.Zero(t, state.ExecutedAtHeight)

	approvalEvent := findEvent(t, ctx, "trusted_tee_measurement_revocation_approval_recorded")
	require.Equal(t, committeeOne.OperatorAddress, eventAttr(t, approvalEvent, "actor"))
	require.Equal(t, "request_created", eventAttr(t, approvalEvent, "operation"))
	require.Equal(t, "1", eventAttr(t, approvalEvent, "approval_count"))
	require.Equal(t, "2", eventAttr(t, approvalEvent, "approval_threshold"))
	require.Equal(t, string(trustedMeasurementRevocationPending), eventAttr(t, approvalEvent, "status"))

	records := k.AuditLogger().GetRecords()
	require.Len(t, records, 2)
	require.Equal(t, "trusted_measurement_revocation_approval_recorded", records[len(records)-1].Action)
	require.Equal(t, committeeOne.OperatorAddress, records[len(records)-1].Actor)

	err = k.RevokeTrustedMeasurementBySecurityCommittee(ctx, committeeOne.OperatorAddress, "aws-nitro", measurementHex)
	require.ErrorContains(t, err, "already approved")

	require.NoError(t, k.RevokeTrustedMeasurementBySecurityCommittee(ctx, committeeTwo.OperatorAddress, "aws-nitro", measurementHex))

	registered, err = k.RegisteredMeasurements.Has(ctx, measurementRegistryKey(nitroPlatformPrefix, measurementHex))
	require.NoError(t, err)
	require.False(t, registered)

	legacyRegistered, err = k.RegisteredPCR0Set.Has(ctx, measurementHex)
	require.NoError(t, err)
	require.False(t, legacyRegistered)

	state = loadTrustedMeasurementRevocationState(t, k, ctx, requestKey)
	require.Equal(t, trustedMeasurementRevocationExecuted, state.Status)
	require.Equal(t, []string{committeeOne.OperatorAddress, committeeTwo.OperatorAddress}, state.Approvals)
	require.EqualValues(t, ctx.BlockHeight(), state.ExecutedAtHeight)

	approvalEvent = findEvent(t, ctx, "trusted_tee_measurement_revocation_approval_recorded")
	require.Equal(t, committeeTwo.OperatorAddress, eventAttr(t, approvalEvent, "actor"))
	require.Equal(t, "approval_threshold_reached", eventAttr(t, approvalEvent, "operation"))
	require.Equal(t, "2", eventAttr(t, approvalEvent, "approval_count"))
	require.Equal(t, "2", eventAttr(t, approvalEvent, "approval_threshold"))

	event := findEvent(t, ctx, "trusted_tee_measurement_registry_updated")
	require.Equal(t, committeeTwo.OperatorAddress, eventAttr(t, event, "actor"))
	require.Equal(t, "security_committee", eventAttr(t, event, "actor_role"))
	require.Equal(t, "revoke", eventAttr(t, event, "operation"))
	require.Equal(t, "revoked", eventAttr(t, event, "registry_result"))
	require.Equal(t, "revoked", eventAttr(t, event, "legacy_pcr0_result"))

	records = k.AuditLogger().GetRecords()
	require.Len(t, records, 4)
	require.Equal(t, "trusted_measurement_revocation_approval_recorded", records[len(records)-2].Action)
	last := records[len(records)-1]
	require.Equal(t, "trusted_measurement_revoked", last.Action)
	require.Equal(t, string(AuditSeverityCritical), string(last.Severity))
	require.Equal(t, committeeTwo.OperatorAddress, last.Actor)
	require.Equal(t, "revoked", last.Details["registry_result"])
	require.Equal(t, "revoked", last.Details["legacy_pcr0_result"])
}

func TestAttestationRegistry_RevokeTrustedMeasurementBySecurityCommittee_RejectsUnknownMeasurement(t *testing.T) {
	committeeOne := makeCommitteeValidator("committee-member-1", 2_000_000)
	committeeTwo := makeCommitteeValidator("committee-member-2", 1_000_000)
	k, ctx := newRegistryTestKeeperWithValidators(t, []stakingtypes.Validator{committeeOne, committeeTwo})

	measurement := sha256.Sum256([]byte("unknown-nitro-measurement"))
	err := k.RevokeTrustedMeasurementBySecurityCommittee(ctx, committeeOne.OperatorAddress, "aws-nitro", hex.EncodeToString(measurement[:]))
	require.ErrorContains(t, err, "not registered")
}

func TestAttestationRegistry_RevokeTrustedMeasurementBySecurityCommittee_RequiresMultiMemberCommittee(t *testing.T) {
	committee := makeCommitteeValidator("committee-member-solo", 1_000_000)
	k, ctx := newRegistryTestKeeperWithValidators(t, []stakingtypes.Validator{committee})

	measurement := sha256.Sum256([]byte("solo-committee-measurement"))
	measurementHex := hex.EncodeToString(measurement[:])

	require.NoError(t, k.AppendTrustedMeasurementByAuthority(ctx, "authority", "aws-nitro", measurementHex))

	err := k.RevokeTrustedMeasurementBySecurityCommittee(ctx, committee.OperatorAddress, "aws-nitro", measurementHex)
	require.ErrorContains(t, err, "need at least 2 bonded validators")

	registered, hasErr := k.RegisteredMeasurements.Has(ctx, measurementRegistryKey(nitroPlatformPrefix, measurementHex))
	require.NoError(t, hasErr)
	require.True(t, registered)
}
