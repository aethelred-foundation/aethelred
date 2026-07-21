package types

import (
	"encoding/json"
	"testing"

	sdkmath "cosmossdk.io/math"
	"github.com/stretchr/testify/require"
)

func mustSDKInt(t *testing.T, value string) sdkmath.Int {
	t.Helper()
	result, ok := sdkmath.NewIntFromString(value)
	require.True(t, ok)
	return result
}

func TestMonetaryTypesJSONRoundTripBeyondUint64(t *testing.T) {
	beyondUint64 := mustSDKInt(t, "184467440737095516160")
	record := StakerRecord{
		Address:      "aethel1wide",
		Shares:       beyondUint64,
		StakedAmount: beyondUint64.AddRaw(1),
	}

	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"shares":"184467440737095516160"`)
	require.Contains(t, string(encoded), `"staked_amount":"184467440737095516161"`)

	var decoded StakerRecord
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.True(t, decoded.Shares.Equal(record.Shares))
	require.True(t, decoded.StakedAmount.Equal(record.StakedAmount))
}

func TestVaultParamsValidateSDKIntegerMinimum(t *testing.T) {
	params := DefaultParams()
	require.NoError(t, params.Validate())

	params.MinStake = sdkmath.Int{}
	require.ErrorContains(t, params.Validate(), "min_stake must be > 0")

	params.MinStake = sdkmath.ZeroInt()
	require.ErrorContains(t, params.Validate(), "min_stake must be > 0")

	params.MinStake = sdkmath.NewInt(-1)
	require.ErrorContains(t, params.Validate(), "min_stake must be > 0")
}
