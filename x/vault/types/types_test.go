package types

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVaultParamsValidateDurationBounds(t *testing.T) {
	maxSeconds := uint64(math.MaxInt64 / int64(time.Second))

	params := DefaultParams()
	params.UnbondingPeriod = maxSeconds + 1
	require.ErrorContains(t, params.Validate(), "unbonding_period exceeds time.Duration range")

	params = DefaultParams()
	params.TelemetryMaxAgeSec = maxSeconds + 1
	require.ErrorContains(t, params.Validate(), "telemetry_max_age_sec exceeds time.Duration range")
}
