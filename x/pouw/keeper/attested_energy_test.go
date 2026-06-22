package keeper

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/internal/attestation"
	"github.com/aethelred/aethelred/x/pouw/types"
)

func TestRecordAttestedWorkBindsEnergyToAttestedDevice(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	reg := attestation.NewRegistry()

	// The attestation's report_data binds the work identity.
	workBinding := []byte("job-xyz-seal-digest")
	tv := attestation.GenerateSEVSNPTestVector(bytes.Repeat([]byte{0xA}, 48), workBinding)
	policy := &attestation.Policy{Roots: tv.Roots, ExpectedReportData: workBinding}

	hash, claims, err := k.RecordAttestedWork(
		ctx, reg, tv.Evidence, policy, "job-xyz", "val",
		3_600_000, 1_000_000, 500, types.EnergyBasisMeasured,
	)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	require.Equal(t, "amd-epyc-sev-snp", claims.DeviceClass)

	// The receipt is recorded attributed to the *attested* device.
	rcpt, found, err := k.GetWorkReceipt(ctx, "job-xyz")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "amd-epyc-sev-snp", rcpt.DeviceClass)

	// Energy/cost was aggregated for the attested device.
	agg, err := k.GetEnergyAggregates(ctx)
	require.NoError(t, err)
	require.True(t, agg.UsefulFacilityMicrojoules.IsPositive())

	// The verified attestation is queryable.
	sum, found, err := k.GetAttestationSummary(ctx, "job-xyz")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "amd-sev-snp", sum.Platform)
	require.Equal(t, "test_root", sum.TrustBasis)
}

func TestRecordAttestedWorkAcceptsAnyPlatform(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	reg := attestation.NewRegistry()

	// Nitro device: attested, energy attributed to the AWS enclave.
	tv := attestation.GenerateNitroTestVector(bytes.Repeat([]byte{0x7}, 48), []byte("job-n"))
	policy := &attestation.Policy{Roots: tv.Roots, ExpectedReportData: []byte("job-n")}
	_, claims, err := k.RecordAttestedWork(ctx, reg, tv.Evidence, policy, "job-n", "val",
		1_000_000, 700_000, 10, types.EnergyBasisDeviceProfile)
	require.NoError(t, err)
	require.Equal(t, "aws-nitro-enclave", claims.DeviceClass)
}

func TestRecordAttestedWorkRejectsUnboundOrUnverified(t *testing.T) {
	k, ctx := newRegistryTestKeeper(t)
	reg := attestation.NewRegistry()
	tv := attestation.GenerateSEVSNPTestVector(bytes.Repeat([]byte{0xA}, 48), []byte("work-A"))

	// Wrong report_data binding -> rejected, no receipt recorded.
	policy := &attestation.Policy{Roots: tv.Roots, ExpectedReportData: []byte("work-B")}
	_, _, err := k.RecordAttestedWork(ctx, reg, tv.Evidence, policy, "job-bad", "val",
		1000, 1000, 1, types.EnergyBasisMeasured)
	require.Error(t, err)
	_, found, err := k.GetWorkReceipt(ctx, "job-bad")
	require.NoError(t, err)
	require.False(t, found)
}
