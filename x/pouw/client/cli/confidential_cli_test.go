package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfidentialityPolicyFromFlags_NilWhenUnset(t *testing.T) {
	cmd := CmdSubmitJob()
	pol, err := confidentialityPolicyFromFlags(cmd)
	require.NoError(t, err)
	require.Nil(t, pol, "no --conf-* flag set must yield a nil policy")
}

func TestConfidentialityPolicyFromFlags_FullPolicy(t *testing.T) {
	cmd := CmdSubmitJob()
	require.NoError(t, cmd.Flags().Set(flagConfBackends, "tee,fhe"))
	require.NoError(t, cmd.Flags().Set(flagConfMinVerification, "zkml"))
	require.NoError(t, cmd.Flags().Set(flagConfPlatforms, "amd-sev-snp,intel-tdx"))
	require.NoError(t, cmd.Flags().Set(flagConfRequireVendor, "true"))
	require.NoError(t, cmd.Flags().Set(flagConfResidency, "EU,UK"))

	pol, err := confidentialityPolicyFromFlags(cmd)
	require.NoError(t, err)
	require.NotNil(t, pol)
	require.Equal(t, []string{"tee", "fhe"}, pol.AllowedBackends)
	require.Equal(t, "zkml", pol.MinVerification)
	require.Equal(t, []string{"amd-sev-snp", "intel-tdx"}, pol.AllowedPlatforms)
	require.True(t, pol.RequireVendorRoot)
	require.Equal(t, []string{"EU", "UK"}, pol.DataResidency)
}

func TestConfidentialityPolicyFromFlags_SingleTrigger(t *testing.T) {
	// Any single confidentiality flag is enough to attach a policy.
	cmd := CmdSubmitJob()
	require.NoError(t, cmd.Flags().Set(flagConfRequireVendor, "true"))
	pol, err := confidentialityPolicyFromFlags(cmd)
	require.NoError(t, err)
	require.NotNil(t, pol)
	require.True(t, pol.RequireVendorRoot)
	require.Empty(t, pol.AllowedBackends)
}
