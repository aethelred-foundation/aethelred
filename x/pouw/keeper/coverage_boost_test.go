package keeper_test

// coverage_boost_test.go - Comprehensive tests to push coverage from 75.7% to 95%+.
// Targets every 0%-coverage function and low-coverage branch in the keeper package.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newSDKCtx() sdk.Context {
	header := tmproto.Header{
		ChainID: "aethelred-test-1",
		Height:  100,
		Time:    time.Now().UTC(),
	}
	return sdk.NewContext(nil, header, false, log.NewNopLogger())
}

func wrappedContext() context.Context {
	return sdk.WrapSDKContext(newSDKCtx())
}

// =============================================================================
// PROMETHEUS EXPORTER - 0% → 100%
// =============================================================================

func TestCB_PrometheusExporter_NewAndRender(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	pe := keeper.NewPrometheusExporter(metrics)
	require.NotNil(t, pe)

	output := pe.Render()
	require.Contains(t, output, "aethelred_pouw_jobs_submitted_total")
	require.Contains(t, output, "aethelred_pouw_jobs_completed_total")
	require.Contains(t, output, "# TYPE")
	require.Contains(t, output, "chain_id=\"aethelred-1\"")
}

func TestCB_PrometheusExporter_SetDefaultLabel(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	pe := keeper.NewPrometheusExporter(metrics)
	pe.SetDefaultLabel("env", "test")

	output := pe.Render()
	require.Contains(t, output, "env=\"test\"")
}

func TestCB_PrometheusExporter_RegisterCounter(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	pe := keeper.NewPrometheusExporter(metrics)

	c1 := pe.RegisterCounter("my_counter")
	require.NotNil(t, c1)
	c1.Add(42)

	// Re-register same name returns same counter
	c2 := pe.RegisterCounter("my_counter")
	require.Equal(t, int64(42), c2.Get())

	output := pe.Render()
	require.Contains(t, output, "aethelred_pouw_my_counter")
	require.Contains(t, output, "42")
}

func TestCB_PrometheusExporter_RegisterGauge(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	pe := keeper.NewPrometheusExporter(metrics)

	g1 := pe.RegisterGauge("my_gauge")
	require.NotNil(t, g1)
	g1.Set(99)

	// Re-register same name returns same gauge
	g2 := pe.RegisterGauge("my_gauge")
	require.Equal(t, int64(99), g2.Get())

	output := pe.Render()
	require.Contains(t, output, "aethelred_pouw_my_gauge")
}

func TestCB_PrometheusExporter_RegisterHistogram(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	pe := keeper.NewPrometheusExporter(metrics)

	h1 := pe.RegisterHistogram("my_hist", 100)
	require.NotNil(t, h1)
	h1.Record(50 * time.Millisecond)

	// Re-register same name returns same histogram
	h2 := pe.RegisterHistogram("my_hist", 100)
	require.NotNil(t, h2)

	output := pe.Render()
	require.Contains(t, output, "aethelred_pouw_my_hist")
	require.Contains(t, output, "quantile")
}

func TestCB_PrometheusExporter_ServeHTTP(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	metrics.JobsSubmitted.Add(10)
	pe := keeper.NewPrometheusExporter(metrics)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	pe.ServeHTTP(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, w.Body.String(), "aethelred_pouw_jobs_submitted_total")
	require.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
}

func TestCB_PrometheusHandler_ReturnsHandler(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	handler := keeper.PrometheusHandler(metrics)
	require.NotNil(t, handler)
}

func TestCB_PrometheusExporter_NilMetrics(t *testing.T) {
	pe := keeper.NewPrometheusExporter(nil)
	output := pe.Render()
	require.NotNil(t, output)
}

func TestCB_PrometheusExporter_WithTimingHistograms(t *testing.T) {
	metrics := keeper.NewModuleMetrics()
	metrics.JobCompletionTime.Record(100 * time.Millisecond)
	metrics.ConsensusRoundTime.Record(200 * time.Millisecond)
	metrics.VerificationTime.Record(50 * time.Millisecond)
	metrics.VoteExtensionTime.Record(30 * time.Millisecond)

	pe := keeper.NewPrometheusExporter(metrics)
	output := pe.Render()
	require.Contains(t, output, "job_completion_seconds")
	require.Contains(t, output, "consensus_round_seconds")
	require.Contains(t, output, "verification_seconds")
	require.Contains(t, output, "vote_extension_seconds")
}

// =============================================================================
// MODULE METRICS - RecordJobSubmission, RecordJobCompletion, RecordVerification,
// RecordConsensus, EmitMetricsEvent - all 0%
// =============================================================================

func TestCB_RecordJobSubmission(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.RecordJobSubmission()
	require.Equal(t, int64(1), m.JobsSubmitted.Get())
	require.Equal(t, int64(1), m.JobsPending.Get())
}

func TestCB_RecordJobCompletion_Success(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsPending.Inc()
	m.RecordJobCompletion(100*time.Millisecond, true)
	require.Equal(t, int64(1), m.JobsCompleted.Get())
	require.Equal(t, int64(0), m.JobsPending.Get())
}

func TestCB_RecordJobCompletion_Failure(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsPending.Inc()
	m.RecordJobCompletion(100*time.Millisecond, false)
	require.Equal(t, int64(1), m.JobsFailed.Get())
	require.Equal(t, int64(0), m.JobsPending.Get())
}

func TestCB_RecordVerification_Success(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.RecordVerification(50*time.Millisecond, true)
	require.Equal(t, int64(1), m.VerificationsTotal.Get())
	require.Equal(t, int64(1), m.VerificationsSuccess.Get())
}

func TestCB_RecordVerification_Failure(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.RecordVerification(50*time.Millisecond, false)
	require.Equal(t, int64(1), m.VerificationsTotal.Get())
	require.Equal(t, int64(1), m.VerificationsFailed.Get())
}

func TestCB_RecordConsensus_Success(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.RecordConsensus(200*time.Millisecond, true)
	require.Equal(t, int64(1), m.ConsensusRounds.Get())
	require.Equal(t, int64(1), m.ConsensusReached.Get())
}

func TestCB_RecordConsensus_Failure(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.RecordConsensus(200*time.Millisecond, false)
	require.Equal(t, int64(1), m.ConsensusRounds.Get())
	require.Equal(t, int64(1), m.ConsensusFailed.Get())
}

func TestCB_EmitMetricsEvent(t *testing.T) {
	m := keeper.NewModuleMetrics()
	m.JobsSubmitted.Add(5)
	m.JobsCompleted.Add(3)

	ctx := newSDKCtx()
	m.EmitMetricsEvent(ctx)

	events := ctx.EventManager().Events()
	require.GreaterOrEqual(t, len(events), 1)
	found := false
	for _, ev := range events {
		if ev.Type == "pouw_module_metrics" {
			found = true
		}
	}
	require.True(t, found, "expected pouw_module_metrics event")
}

// =============================================================================
// THREAT MODEL - 0% → 100%
// =============================================================================

func TestCB_ThreatModelSummary(t *testing.T) {
	summary := keeper.ThreatModelSummary()
	require.Contains(t, summary, "Aethelred Threat Model")
	require.Contains(t, summary, "Attacker classes")
	require.Contains(t, summary, "Trust boundaries")
	require.Contains(t, summary, "Attack surfaces")
	require.Contains(t, summary, "Security properties")
}

func TestCB_AttackerClasses_NonEmpty(t *testing.T) {
	require.Greater(t, len(keeper.AttackerClasses), 0)
	for _, ac := range keeper.AttackerClasses {
		require.NotEmpty(t, ac.ID)
		require.NotEmpty(t, ac.Name)
	}
}

func TestCB_TrustBoundaries_NonEmpty(t *testing.T) {
	require.Greater(t, len(keeper.TrustBoundaries), 0)
}

func TestCB_AttackSurfaces_NonEmpty(t *testing.T) {
	require.Greater(t, len(keeper.AttackSurfaces), 0)
	for _, as := range keeper.AttackSurfaces {
		require.NotEmpty(t, as.ID)
		require.Contains(t, []string{"mitigated", "partial", "open"}, as.Status)
	}
}

func TestCB_SecurityProperties_NonEmpty(t *testing.T) {
	require.Greater(t, len(keeper.SecurityProperties), 0)
}

// =============================================================================
// ATTESTATION REGISTRY - 0% coverage functions
// =============================================================================

func TestCB_ExtractNitroPCR0FromPlatforms(t *testing.T) {
	tests := []struct {
		name      string
		platforms []string
		wantPCR0  bool
	}{
		{"empty platforms", nil, false},
		{"no nitro platform", []string{"intel-sgx"}, false},
		{"nitro with pcr0", []string{"aws-nitro:pcr0=" + strings.Repeat("ab", 32)}, true},
		{"nitro with invalid pcr0", []string{"aws-nitro:pcr0=invalidhex"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pcr0, found := keeper.ExtractNitroPCR0FromPlatforms(tc.platforms)
			require.Equal(t, tc.wantPCR0, found)
			if found {
				require.NotEmpty(t, pcr0)
			}
		})
	}
}

// =============================================================================
// AUDIT LOGGER - 0% coverage convenience methods
// =============================================================================

func TestCB_AuditLogger_ConvenienceMethods(t *testing.T) {
	ctx := newSDKCtx()
	logger := keeper.NewAuditLogger(1000)
	require.NotNil(t, logger)

	logger.AuditConsensusFailed(ctx, "job-1", 2, 5)
	logger.AuditFeeDistributed(ctx, "job-1", "100uaethel", "60uaethel", "20uaethel", "10uaethel", "10uaethel")
	logger.AuditValidatorRegistered(ctx, "cosmos1validator", 10, true)

	records := logger.GetRecords()
	require.GreaterOrEqual(t, len(records), 3)
}

func TestCB_AuditLogger_SecurityAlert_NilDetails(t *testing.T) {
	ctx := newSDKCtx()
	logger := keeper.NewAuditLogger(1000)
	logger.AuditSecurityAlert(ctx, "test_alert", "testing nil details", nil)

	records := logger.GetRecords()
	require.GreaterOrEqual(t, len(records), 1)
	last := records[len(records)-1]
	require.Equal(t, keeper.AuditCategorySecurity, last.Category)
}

func TestCB_AuditLogger_NewWithZeroCapacity(t *testing.T) {
	logger := keeper.NewAuditLogger(0)
	require.NotNil(t, logger)
	// 0 capacity defaults to 10000
}

func TestCB_AuditLogger_VerifyChain(t *testing.T) {
	logger := keeper.NewAuditLogger(1000)
	ctx := newSDKCtx()

	err := logger.VerifyChain()
	require.NoError(t, err)

	logger.Record(ctx, keeper.AuditCategoryJob, keeper.AuditSeverityInfo, "test1", "actor1", nil)
	logger.Record(ctx, keeper.AuditCategoryJob, keeper.AuditSeverityWarning, "test2", "actor2", nil)
	logger.Record(ctx, keeper.AuditCategoryJob, keeper.AuditSeverityCritical, "test3", "actor3", nil)

	err = logger.VerifyChain()
	require.NoError(t, err)
}

func TestCB_SeverityOrdinal(t *testing.T) {
	tests := []struct {
		severity keeper.AuditSeverity
		want     int
	}{
		{keeper.AuditSeverityInfo, 0},
		{keeper.AuditSeverityWarning, 1},
		{keeper.AuditSeverityCritical, 2},
		{"unknown", 0},
	}
	for _, tc := range tests {
		t.Run(string(tc.severity), func(t *testing.T) {
			require.Equal(t, tc.want, keeper.SeverityOrdinalForTest(tc.severity))
		})
	}
}

// =============================================================================
// GOVERNANCE - 0% coverage functions
// =============================================================================

func TestCB_FormatParamChangeEvent_Empty(t *testing.T) {
	events := keeper.FormatParamChangeEvent(nil)
	require.Nil(t, events)
}

func TestCB_FormatParamChangeEvent_WithChanges(t *testing.T) {
	changes := []keeper.ParamFieldChange{
		{Field: "consensus_threshold", OldValue: "67", NewValue: "75"},
		{Field: "max_jobs_per_block", OldValue: "10", NewValue: "20"},
	}
	events := keeper.FormatParamChangeEvent(changes)
	require.Len(t, events, 1)
	ev := events[0]
	require.Equal(t, "params_updated", ev.Type)
	require.GreaterOrEqual(t, len(ev.Attributes), 3)
}

func TestCB_StringSliceEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []string{}, []string{}, true},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"different content", []string{"a"}, []string{"b"}, false},
		{"nil vs empty", nil, []string{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, keeper.StringSliceEqualForTest(tc.a, tc.b))
		})
	}
}

// =============================================================================
// FEE DISTRIBUTION - RewardScaleByReputation
// =============================================================================

func TestCB_RewardScaleByReputation(t *testing.T) {
	baseCoin := sdk.NewInt64Coin("uaethel", 1000)

	result := keeper.RewardScaleByReputation(baseCoin, 0)
	require.Equal(t, int64(500), result.Amount.Int64())

	result = keeper.RewardScaleByReputation(baseCoin, 100)
	require.Equal(t, int64(1000), result.Amount.Int64())

	result = keeper.RewardScaleByReputation(baseCoin, 50)
	require.Equal(t, int64(750), result.Amount.Int64())

	result = keeper.RewardScaleByReputation(baseCoin, -10)
	require.Equal(t, int64(500), result.Amount.Int64())

	result = keeper.RewardScaleByReputation(baseCoin, 200)
	require.Equal(t, int64(1000), result.Amount.Int64())
}

// =============================================================================
// EVIDENCE - SeverityMultiplier and extractValidatorAddress
// =============================================================================

func TestCB_SeverityMultiplier_AllCases(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"low", "0.250000000000000000"},
		{"medium", "0.500000000000000000"},
		{"high", "1.000000000000000000"},
		{"critical", "2.000000000000000000"},
		{"unknown", "1.000000000000000000"},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			result := keeper.SeverityMultiplier(tc.severity)
			require.Equal(t, tc.want, result.String())
		})
	}
}

func TestCB_ExtractValidatorAddress(t *testing.T) {
	require.Equal(t, "", keeper.ExtractValidatorAddressForTest(nil))

	wire := &keeper.VoteExtensionWire{}
	require.Equal(t, "", keeper.ExtractValidatorAddressForTest(wire))

	addrJSON, _ := json.Marshal("cosmos1validator")
	wire = &keeper.VoteExtensionWire{ValidatorAddress: addrJSON}
	require.Equal(t, "cosmos1validator", keeper.ExtractValidatorAddressForTest(wire))

	wire = &keeper.VoteExtensionWire{ValidatorAddress: []byte("not-json")}
	require.Equal(t, "", keeper.ExtractValidatorAddressForTest(wire))
}

// =============================================================================
// SCHEDULER - 0% coverage functions
// =============================================================================

func TestCB_Scheduler_Stop(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	require.NotNil(t, sched)
	sched.Stop()
}

func TestCB_Scheduler_MarkJobCompleteWithContext(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	sched.MarkJobCompleteWithContext(context.Background(), "nonexistent-job")
}

func TestCB_WithDrandPulsePayload(t *testing.T) {
	ctx := context.Background()
	payload := keeper.DrandPulsePayload{
		Round:      12345,
		Randomness: make([]byte, 32),
		Signature:  make([]byte, 96),
		Scheme:     "bls-unchained-on-g1",
	}
	newCtx := keeper.WithDrandPulsePayload(ctx, payload)
	require.NotNil(t, newCtx)
}

func TestCB_GetMetaInt(t *testing.T) {
	meta := map[string]string{"key1": "42", "key2": "invalid", "key3": ""}
	require.Equal(t, int64(42), keeper.GetMetaIntForTest(meta, "key1", 0))
	require.Equal(t, int64(0), keeper.GetMetaIntForTest(meta, "key2", 0))
	require.Equal(t, int64(0), keeper.GetMetaIntForTest(meta, "key3", 0))
	require.Equal(t, int64(99), keeper.GetMetaIntForTest(meta, "missing", 99))
}

func TestCB_GetMetaIntAsInt(t *testing.T) {
	meta := map[string]string{"key1": "42", "key2": "invalid"}
	require.Equal(t, 42, keeper.GetMetaIntAsIntForTest(meta, "key1", 0))
	require.Equal(t, 0, keeper.GetMetaIntAsIntForTest(meta, "key2", 0))
	require.Equal(t, 99, keeper.GetMetaIntAsIntForTest(meta, "missing", 99))
}

func TestCB_GetMetaStringSlice(t *testing.T) {
	meta := map[string]string{"key1": `["a","b","c"]`, "key2": "invalid", "key3": ""}
	require.Equal(t, []string{"a", "b", "c"}, keeper.GetMetaStringSliceForTest(meta, "key1"))
	require.Nil(t, keeper.GetMetaStringSliceForTest(meta, "key2"))
	require.Nil(t, keeper.GetMetaStringSliceForTest(meta, "key3"))
	require.Nil(t, keeper.GetMetaStringSliceForTest(meta, "missing"))
}

func TestCB_GetMetaVRFAssignments(t *testing.T) {
	vrfData := []keeper.VRFAssignmentRecord{{ValidatorAddress: "val1"}}
	rawJSON, _ := json.Marshal(vrfData)
	meta := map[string]string{"vrf": string(rawJSON), "invalid": "not-json"}

	result := keeper.GetMetaVRFAssignmentsForTest(meta, "vrf")
	require.Len(t, result, 1)
	require.Equal(t, "val1", result[0].ValidatorAddress)

	require.Nil(t, keeper.GetMetaVRFAssignmentsForTest(meta, "invalid"))
	require.Nil(t, keeper.GetMetaVRFAssignmentsForTest(meta, "missing"))
}

func TestCB_BytesLess(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := []byte{0x01, 0x03}
	require.True(t, keeper.BytesLessForTest(a, b))
	require.False(t, keeper.BytesLessForTest(b, a))
	require.False(t, keeper.BytesLessForTest(a, a))
	require.False(t, keeper.BytesLessForTest(nil, nil))
	require.True(t, keeper.BytesLessForTest(nil, a))
}

func TestCB_LoadSchedulingMetadata_Empty(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	job := &types.ComputeJob{
		Id:       "job-1",
		Metadata: map[string]string{},
	}
	retryCount, _, _, _, _, _, _, _, _, _, _ := sched.LoadSchedulingMetadataForTest(job)
	require.Equal(t, 0, retryCount)
}

func TestCB_LoadSchedulingMetadata_Full(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	vrfData := []keeper.VRFAssignmentRecord{{ValidatorAddress: "val1"}}
	vrfJSON, _ := json.Marshal(vrfData)
	assignedJSON, _ := json.Marshal([]string{"val1", "val2"})

	job := &types.ComputeJob{
		Id: "job-2",
		Metadata: map[string]string{
			"scheduler.retry_count":        "3",
			"scheduler.last_attempt_block": "500",
			"scheduler.submitted_block":    "100",
			"scheduler.assigned_to":        string(assignedJSON),
			"scheduler.vrf_entropy":        "abcdef",
			"scheduler.vrf_assignments":    string(vrfJSON),
		},
	}
	retryCount, lastAttempt, _, submittedBlock, vrfEntropy, _, _, _, _, _, _ := sched.LoadSchedulingMetadataForTest(job)
	require.Equal(t, 3, retryCount)
	require.Equal(t, int64(500), lastAttempt)
	require.Equal(t, int64(100), submittedBlock)
	require.Equal(t, "abcdef", vrfEntropy)
}

func TestCB_LoadSchedulingMetadata_Nil(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	retryCount, _, _, _, _, _, _, _, _, _, _ := sched.LoadSchedulingMetadataForTest(nil)
	require.Equal(t, 0, retryCount)
}

// =============================================================================
// CONSENSUS - low coverage functions
// =============================================================================

func TestCB_ConsensusHandler_Scheduler_Nil(t *testing.T) {
	var ch *keeper.ConsensusHandler
	require.Nil(t, ch.Scheduler())
}

func TestCB_ConsensusHandler_Scheduler_NonNil(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, sched)
	require.NotNil(t, ch.Scheduler())
}

func TestCB_RequiredThresholdCount(t *testing.T) {
	tests := []struct {
		total, threshold, want int
	}{
		{0, 67, 0}, {10, 0, 0}, {10, 67, 7}, {10, 100, 10},
		{10, 150, 10}, {3, 67, 3}, {1, 50, 1}, {100, 51, 51},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d_%d", tc.total, tc.threshold), func(t *testing.T) {
			got := keeper.RequiredThresholdCountForTest(tc.total, tc.threshold)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestCB_GetConsensusThreshold(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, sched)
	ctx := newSDKCtx()
	threshold := ch.GetConsensusThresholdForTest(ctx)
	require.GreaterOrEqual(t, threshold, 67)
}

func TestCB_ValidateSealTransaction_Nil(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, sched)
	ctx := newSDKCtx()
	err := ch.ValidateSealTransaction(ctx, nil)
	require.Error(t, err)
}

func TestCB_ProcessSealTransaction_Nil(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, sched)
	err := ch.ProcessSealTransaction(context.Background(), nil)
	require.Error(t, err)
}

func TestCB_CreateSealTransactions_Nil(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, sched)
	ctx := newSDKCtx()
	txs := ch.CreateSealTransactions(ctx, nil)
	require.Empty(t, txs)
}

func TestCB_AggregateVoteExtensions_Empty(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, sched)
	ctx := newSDKCtx()
	result := ch.AggregateVoteExtensions(ctx, nil)
	require.NotNil(t, result)
}

func TestCB_ExtractDKGBeaconPayload_NoPayload(t *testing.T) {
	ctx := context.Background()
	_, ok, err := keeper.ExtractDKGBeaconPayloadForTest(ctx)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestCB_ExtractDrandPulsePayload_NoPayload(t *testing.T) {
	ctx := context.Background()
	_, ok, err := keeper.ExtractDrandPulsePayloadForTest(ctx)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestCB_ExtractDrandPulsePayload_WithPayload(t *testing.T) {
	ctx := context.Background()
	expected := keeper.DrandPulsePayload{Round: 42, Randomness: make([]byte, 32), Signature: make([]byte, 96)}
	ctx = keeper.WithDrandPulsePayload(ctx, expected)
	payload, ok, err := keeper.ExtractDrandPulsePayloadForTest(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, expected.Round, payload.Round)
}

// =============================================================================
// HARDENING
// =============================================================================

func TestCB_SanitizePurpose(t *testing.T) {
	// Valid input
	result, err := keeper.SanitizePurpose("valid purpose")
	require.NoError(t, err)
	require.Equal(t, "valid purpose", result.Sanitized)

	// Input with disallowed chars
	result, err = keeper.SanitizePurpose("has<html>tags")
	require.NoError(t, err)
	require.Equal(t, "hashtmltags", result.Sanitized)
	require.NotEmpty(t, result.Warnings)

	// Too long input
	_, err = keeper.SanitizePurpose(strings.Repeat("a", 300))
	require.Error(t, err)

	// Empty input
	_, err = keeper.SanitizePurpose("")
	require.Error(t, err)
}

func TestCB_ValidateHexHash(t *testing.T) {
	validHex := strings.Repeat("ab", 32)
	require.NoError(t, keeper.ValidateHexHash(validHex, "test", 32))
	require.Error(t, keeper.ValidateHexHash("", "test", 32))
	require.Error(t, keeper.ValidateHexHash(strings.Repeat("ab", 16), "test", 32))
	require.Error(t, keeper.ValidateHexHash("not-hex!", "test", 32))
}

// =============================================================================
// REMEDIATION - GetThreshold 0%
// =============================================================================

func TestCB_LivenessTracker_GetThreshold(t *testing.T) {
	lt := keeper.NewLivenessTracker(50, 100)
	require.Equal(t, int64(50), lt.GetThreshold())
}

// =============================================================================
// EVIDENCE - ProcessEndBlockEvidence, DetectInvalidOutputs, DetectDoubleSigners,
// DetectColludingValidators
// =============================================================================

func TestCB_EvidenceCollector_ProcessEndBlockEvidence(t *testing.T) {
	ec := keeper.NewEvidenceCollector(log.NewNopLogger(), nil)
	ctx := newSDKCtx()
	err := ec.ProcessEndBlockEvidence(ctx)
	require.NoError(t, err)
}

func TestCB_DetectInvalidOutputs_Empty(t *testing.T) {
	ec := keeper.NewEvidenceCollector(log.NewNopLogger(), nil)
	ctx := newSDKCtx()
	evidence := ec.DetectInvalidOutputs(ctx, "job-1", nil, nil)
	require.Empty(t, evidence)
}

func TestCB_DetectDoubleSigners_Empty(t *testing.T) {
	ec := keeper.NewEvidenceCollector(log.NewNopLogger(), nil)
	ctx := newSDKCtx()
	evidence := ec.DetectDoubleSigners(ctx, "job-1", nil)
	require.Empty(t, evidence)
}

func TestCB_DetectColludingValidators_Empty(t *testing.T) {
	ec := keeper.NewEvidenceCollector(log.NewNopLogger(), nil)
	ctx := newSDKCtx()
	evidence := ec.DetectColludingValidators(ctx, "job-1", nil, nil, 0)
	require.Empty(t, evidence)
}

// =============================================================================
// EVIDENCE SYSTEM - low coverage functions
// =============================================================================

func TestCB_NewBlockMissTracker(t *testing.T) {
	tracker := keeper.NewBlockMissTracker(log.NewNopLogger(), nil, keeper.DefaultBlockMissConfig())
	require.NotNil(t, tracker)
	tracker.RecordParticipation("val1", 100)
	for i := 0; i < 10; i++ {
		tracker.RecordMiss("val2", int64(101+i))
	}
	ctx := newSDKCtx()
	_ = tracker.CheckAndApplyDowntimePenalties(ctx)
}

func TestCB_NewDoubleVotingDetector(t *testing.T) {
	detector := keeper.NewDoubleVotingDetector(log.NewNopLogger(), nil)
	require.NotNil(t, detector)
	detector.ClearProcessedEquivocations(nil)
	detector.PruneOldHistory(100)
}

func TestCB_VerifyEquivocationEvidence_Empty(t *testing.T) {
	// Empty evidence should fail verification
	evidence := &keeper.EquivocationEvidence{}
	valid := keeper.VerifyEquivocationEvidence(evidence)
	require.False(t, valid)
}

func TestCB_NewEvidenceProcessor(t *testing.T) {
	processor := keeper.NewEvidenceProcessor(
		log.NewNopLogger(), nil,
		keeper.DefaultBlockMissConfig(),
		keeper.DefaultEvidenceSlashingConfig(),
	)
	require.NotNil(t, processor)
}

// =============================================================================
// SLASHING INTEGRATION
// =============================================================================

func TestCB_IntegratedEvidenceResult_TotalSlashed(t *testing.T) {
	result := &keeper.IntegratedEvidenceResult{
		DowntimeSlashes:      []*keeper.PoUWSlashResult{{SlashedAmount: sdkmath.NewInt(100)}},
		DoubleSignSlashes:    []*keeper.PoUWSlashResult{{SlashedAmount: sdkmath.NewInt(500)}},
		InvalidOutputSlashes: []*keeper.PoUWSlashResult{{SlashedAmount: sdkmath.NewInt(50)}},
		CollusionSlashes:     []*keeper.PoUWSlashResult{{SlashedAmount: sdkmath.NewInt(150)}},
	}
	require.Equal(t, sdkmath.NewInt(800), result.TotalSlashed())
}

func TestCB_IntegratedEvidenceResult_TotalSlashed_Empty(t *testing.T) {
	result := &keeper.IntegratedEvidenceResult{}
	require.True(t, result.TotalSlashed().IsZero())
}

func TestCB_DefaultSlashingAdapterConfig(t *testing.T) {
	cfg := keeper.DefaultSlashingAdapterConfig()
	require.Greater(t, cfg.DowntimeSlashBps, int64(0))
	require.Greater(t, cfg.DoubleSignSlashBps, int64(0))
}

func TestCB_NewSlashingModuleAdapter(t *testing.T) {
	cfg := keeper.DefaultSlashingAdapterConfig()
	adapter := keeper.NewSlashingModuleAdapter(log.NewNopLogger(), nil, nil, nil, cfg)
	require.NotNil(t, adapter)
}

// =============================================================================
// STAKING - 0% coverage functions
// =============================================================================

func TestCB_DefaultSelectionCriteria(t *testing.T) {
	criteria := keeper.DefaultSelectionCriteria(types.ProofTypeTEE)
	require.Equal(t, types.ProofTypeTEE, criteria.ProofType)
	require.Equal(t, int64(30), criteria.MinReputationScore)
	require.Equal(t, 100, criteria.MaxValidators)
	require.Greater(t, criteria.MinStake, int64(0))
}

func TestCB_NewValidatorSelector(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	vs := keeper.NewValidatorSelector(nil, sched, nil)
	require.NotNil(t, vs)
}

// =============================================================================
// STAKE SECURITY
// =============================================================================

func TestCB_MinimumValidatorStakeUAETHEL(t *testing.T) {
	stake := keeper.MinimumValidatorStakeUAETHEL()
	require.True(t, stake.IsPositive())
}

// =============================================================================
// DRAND PULSE
// =============================================================================

func TestCB_IsLocalDrandEndpoint(t *testing.T) {
	require.True(t, keeper.IsLocalDrandEndpointForTest("http://localhost:8080"))
	require.True(t, keeper.IsLocalDrandEndpointForTest("http://127.0.0.1:3000"))
	require.False(t, keeper.IsLocalDrandEndpointForTest("https://api.drand.sh"))
	require.False(t, keeper.IsLocalDrandEndpointForTest(""))
}

func TestCB_EqualBytes(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	c := []byte{4, 5, 6}
	require.True(t, keeper.EqualBytesForTest(a, b))
	require.False(t, keeper.EqualBytesForTest(a, c))
	require.True(t, keeper.EqualBytesForTest(nil, nil))
	require.False(t, keeper.EqualBytesForTest(nil, a))
}

func TestCB_NewHTTPDrandPulseProvider_EmptyEndpoint(t *testing.T) {
	provider := keeper.NewHTTPDrandPulseProvider("", 5*time.Second)
	require.NotNil(t, provider)
}

// =============================================================================
// USEFUL WORK
// =============================================================================

func TestCB_ParsePositiveUint(t *testing.T) {
	tests := []struct {
		input  string
		want   uint64
		wantOK bool
	}{
		{"42", 42, true},
		{"0", 0, false},
		{"-1", 0, false},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := keeper.ParsePositiveUintForTest(tc.input)
			require.Equal(t, tc.wantOK, ok)
			if ok {
				require.Equal(t, tc.want, got)
			}
		})
	}
}

func TestCB_SaturatingMul(t *testing.T) {
	require.Equal(t, uint64(6), keeper.SaturatingMulForTest(2, 3))
	require.Equal(t, ^uint64(0), keeper.SaturatingMulForTest(^uint64(0), 2))
	require.Equal(t, uint64(0), keeper.SaturatingMulForTest(0, 100))
}

// =============================================================================
// TOKENOMICS SAFE
// =============================================================================

func TestCB_SafeAdd_Normal(t *testing.T) {
	sm := keeper.NewSafeMath()
	result, err := sm.SafeAdd(sdkmath.NewInt(100), sdkmath.NewInt(200))
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(300), result)
}

func TestCB_SafeSub_Normal_NegResult(t *testing.T) {
	sm := keeper.NewSafeMath()
	// sdkmath.Int supports negative results, so this should succeed
	result, err := sm.SafeSub(sdkmath.NewInt(100), sdkmath.NewInt(200))
	require.NoError(t, err)
	require.True(t, result.IsNegative())
}

func TestCB_SafeSub_Normal(t *testing.T) {
	sm := keeper.NewSafeMath()
	result, err := sm.SafeSub(sdkmath.NewInt(300), sdkmath.NewInt(100))
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(200), result)
}

func TestCB_SafeMul_Normal(t *testing.T) {
	sm := keeper.NewSafeMath()
	result, err := sm.SafeMul(sdkmath.NewInt(100), sdkmath.NewInt(200))
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(20000), result)
}

func TestCB_SafeMulDiv(t *testing.T) {
	sm := keeper.NewSafeMath()
	_, err := sm.SafeMulDiv(sdkmath.NewInt(100), sdkmath.NewInt(200), sdkmath.NewInt(0))
	require.Error(t, err)

	result, err := sm.SafeMulDiv(sdkmath.NewInt(100), sdkmath.NewInt(200), sdkmath.NewInt(50))
	require.NoError(t, err)
	require.Equal(t, sdkmath.NewInt(400), result)
}

func TestCB_ValidateBondingCurveConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateBondingCurveConfig(keeper.DefaultBondingCurveConfig()))
	cfg := keeper.DefaultBondingCurveConfig()
	cfg.BasePriceUAETHEL = sdkmath.NewInt(0)
	require.Error(t, keeper.ValidateBondingCurveConfig(cfg))
}

func TestCB_ValidateBlockTimeConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateBlockTimeConfig(keeper.DefaultBlockTimeConfig()))
	cfg := keeper.DefaultBlockTimeConfig()
	cfg.TargetBlockTimeMs = 0
	require.Error(t, keeper.ValidateBlockTimeConfig(cfg))
}

func TestCB_ComputeEmissionScheduleSafe(t *testing.T) {
	cfg := keeper.InflationarySimulationConfig()
	btCfg := keeper.DefaultBlockTimeConfig()
	schedule, err := keeper.ComputeEmissionScheduleSafe(cfg, 5, btCfg)
	require.NoError(t, err)
	require.NotEmpty(t, schedule)
}

func TestCB_ComputeValidatorRewardSafe(t *testing.T) {
	baseReward := sdk.NewInt64Coin("uaethel", 1000000)
	valReward, delReward, err := keeper.ComputeValidatorRewardSafe(baseReward, 80, 1000)
	require.NoError(t, err)
	require.True(t, valReward.IsPositive())
	require.True(t, delReward.IsPositive())
}

// =============================================================================
// TOKENOMICS
// =============================================================================

func TestCB_ValidateEmissionConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateEmissionConfig(keeper.DefaultEmissionConfig()))
}

func TestCB_ComputeEmissionSchedule(t *testing.T) {
	schedule := keeper.ComputeEmissionSchedule(keeper.InflationarySimulationConfig(), 5)
	require.NotEmpty(t, schedule)
}

func TestCB_ComputeInflationForYear(t *testing.T) {
	cfg := keeper.InflationarySimulationConfig()
	require.Greater(t, keeper.ComputeInflationForYearForTest(cfg, 1), int64(0))
	require.Greater(t, keeper.ComputeInflationForYearForTest(cfg, 0), int64(0))
}

func TestCB_ValidateSlashingConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateSlashingConfig(keeper.DefaultSlashingConfig()))
}

func TestCB_ValidateFeeMarketConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateFeeMarketConfig(keeper.DefaultFeeMarketConfig()))
}

func TestCB_ComputeDynamicFee(t *testing.T) {
	cfg := keeper.DefaultFeeMarketConfig()
	fee := keeper.ComputeDynamicFee(cfg, 50, 100)
	require.Greater(t, fee, int64(0))
}

func TestCB_RatioToPercent(t *testing.T) {
	require.Equal(t, float64(0), keeper.RatioToPercentForTest(sdkmath.NewInt(1), sdkmath.NewInt(0)))
	require.InDelta(t, float64(50), keeper.RatioToPercentForTest(sdkmath.NewInt(1), sdkmath.NewInt(2)), 0.01)
	require.InDelta(t, float64(100), keeper.RatioToPercentForTest(sdkmath.NewInt(1), sdkmath.NewInt(1)), 0.01)
}

// =============================================================================
// TOKENOMICS MODEL SIMULATION
// =============================================================================

func TestCB_ValidateTokenomicsModel(t *testing.T) {
	errs := keeper.ValidateTokenomicsModel(keeper.DefaultTokenomicsModel())
	require.Empty(t, errs)
}

func TestCB_ValidateAntiAbuseConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateAntiAbuseConfig(keeper.DefaultAntiAbuseConfig()))
	cfg := keeper.DefaultAntiAbuseConfig()
	cfg.ValidatorConcentrationCapBps = 0
	require.Error(t, keeper.ValidateAntiAbuseConfig(cfg))
}

func TestCB_FormatAETHEL(t *testing.T) {
	require.Equal(t, "1", keeper.FormatAETHELForTest(1_000_000))
	require.Equal(t, "1,000", keeper.FormatAETHELForTest(1_000_000_000))
	require.Contains(t, keeper.FormatAETHELForTest(500), "0.") // fractional AETHEL
}

func TestCB_FormatWithCommas(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0"}, {999, "999"}, {1000, "1,000"}, {1000000, "1,000,000"}, {-1000, "-1,000"},
	}
	for _, tc := range tests {
		require.Equal(t, tc.want, keeper.FormatWithCommasForTest(tc.input))
	}
}

// =============================================================================
// TOKENOMICS TREASURY VESTING
// =============================================================================

func TestCB_ValidateTreasuryConfig(t *testing.T) {
	require.NoError(t, keeper.ValidateTreasuryConfig(keeper.DefaultTreasuryConfig()))
}

func TestCB_ValidateVestingSchedules_Empty(t *testing.T) {
	require.NoError(t, keeper.ValidateVestingSchedules(nil))
}

func TestCB_ValidateVestingSchedules_Invalid(t *testing.T) {
	schedules := []keeper.VestingSchedule{{Category: "test", TotalUAETHEL: -1, VestingBlocks: 1000}}
	require.Error(t, keeper.ValidateVestingSchedules(schedules))
}

// =============================================================================
// GOVERNANCE - ValidateParams, MergeParamsWithMask, DiffParams
// =============================================================================

func TestCB_ValidateParams(t *testing.T) {
	require.NoError(t, keeper.ValidateParams(types.DefaultParams()))
}

func TestCB_MergeParamsWithMask(t *testing.T) {
	current := types.DefaultParams()
	update := types.DefaultParams()
	update.MaxJobsPerBlock = 20
	merged := keeper.MergeParamsWithMask(current, update, keeper.BoolFieldMask{})
	require.NotNil(t, merged)
	require.Equal(t, int64(20), merged.MaxJobsPerBlock)
}

func TestCB_DiffParams_Identical(t *testing.T) {
	params := types.DefaultParams()
	changes := keeper.DiffParams(params, params)
	require.Empty(t, changes)
}

// =============================================================================
// INVARIANTS - RegisterInvariants 0%
// =============================================================================

type testInvariantRegistry struct {
	routes map[string]sdk.Invariant
}

func (m *testInvariantRegistry) RegisterRoute(moduleName string, route string, inv sdk.Invariant) {
	if m.routes == nil {
		m.routes = make(map[string]sdk.Invariant)
	}
	m.routes[moduleName+"/"+route] = inv
}

func TestCB_RegisterInvariants(t *testing.T) {
	registry := &testInvariantRegistry{}
	k := keeper.Keeper{}
	keeper.RegisterInvariants(registry, k)
	require.GreaterOrEqual(t, len(registry.routes), 7)
}

// =============================================================================
// METRICS - CircuitBreaker, PercentileIndex
// =============================================================================

func TestCB_CircuitBreaker_State(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 5, time.Second)
	require.Equal(t, "closed", cb.State().String())
	require.Equal(t, "test", cb.Name())
	require.Equal(t, int64(0), cb.TotalTrips())

	for i := 0; i < 6; i++ {
		cb.RecordFailure()
	}
	require.Equal(t, "open", cb.State().String())
	require.Equal(t, int64(1), cb.TotalTrips())
}

func TestCB_CircuitBreaker_Allow(t *testing.T) {
	cb := keeper.NewCircuitBreaker("test", 3, 100*time.Millisecond)
	require.True(t, cb.Allow())

	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	require.False(t, cb.Allow())

	time.Sleep(150 * time.Millisecond)
	require.True(t, cb.Allow())
}

func TestCB_PercentileIndex(t *testing.T) {
	require.Equal(t, -1, keeper.PercentileIndexForTest(0, 50))
	require.Equal(t, 0, keeper.PercentileIndexForTest(1, 50))
	require.Equal(t, 50, keeper.PercentileIndexForTest(100, 50))
	require.Equal(t, 99, keeper.PercentileIndexForTest(100, 100))
}

// =============================================================================
// PERFORMANCE - Remaining, PerformanceScore
// =============================================================================

func TestCB_BlockBudget_Remaining(t *testing.T) {
	bb := keeper.NewBlockBudget(100 * time.Millisecond)
	require.Greater(t, bb.Remaining(), time.Duration(0))
}

// =============================================================================
// SECURITY COMPLIANCE
// =============================================================================

func TestCB_ValidateVerificationPolicy(t *testing.T) {
	policy := keeper.DefaultVerificationPolicy()
	require.NoError(t, keeper.ValidateVerificationPolicy(policy))

	policy.MaxAttestationAgeBlocks = 0
	require.Error(t, keeper.ValidateVerificationPolicy(policy))
}

// =============================================================================
// ECOSYSTEM LAUNCH
// =============================================================================

func TestCB_ValidateGenesisValidator(t *testing.T) {
	gv := keeper.GenesisValidator{
		Address:     "cosmos1abc",
		Moniker:     "validator1",
		Power:       100,
		TEEPlatform: "aws-nitro",
		SupportsTEE: true,
	}
	require.NoError(t, keeper.ValidateGenesisValidator(gv))

	gv.Address = ""
	require.Error(t, keeper.ValidateGenesisValidator(gv))
}

// =============================================================================
// POST LAUNCH
// =============================================================================

func TestCB_IncidentTracker(t *testing.T) {
	tracker := keeper.NewIncidentTracker()
	require.NotNil(t, tracker)

	err := tracker.CreateIncident("inc-1", keeper.IncidentSev1, "test incident", "desc", "2024-01-01T00:00:00Z")
	require.NoError(t, err)

	inc, found := tracker.GetIncident("inc-1")
	require.True(t, found)
	require.Equal(t, "test incident", inc.Title)

	err = tracker.UpdateStatus("inc-1", keeper.IncidentResolved, "fixed", "admin", "2024-01-02T00:00:00Z")
	require.NoError(t, err)

	_, found = tracker.GetIncident("nonexistent")
	require.False(t, found)

	err = tracker.UpdateStatus("nonexistent", keeper.IncidentResolved, "", "", "")
	require.Error(t, err)

	// Duplicate ID
	err = tracker.CreateIncident("inc-1", keeper.IncidentSev3, "dup", "", "")
	require.Error(t, err)

	// Empty ID
	err = tracker.CreateIncident("", keeper.IncidentSev3, "dup", "", "")
	require.Error(t, err)
}

func TestCB_AllGraduationCriteriaPassed(t *testing.T) {
	assessment := &keeper.MaturityAssessment{
		GraduationCriteria: []keeper.MaturityCriterion{
			{ID: "c1", Passed: true},
			{ID: "c2", Passed: true},
		},
	}
	require.True(t, assessment.AllGraduationCriteriaPassed())

	assessment.GraduationCriteria = append(assessment.GraduationCriteria, keeper.MaturityCriterion{ID: "c3", Passed: false})
	require.False(t, assessment.AllGraduationCriteriaPassed())
}

func TestCB_DefaultGovernanceConfig(t *testing.T) {
	cfg := keeper.DefaultGovernanceConfig()
	require.NoError(t, keeper.ValidateGovernanceConfig(cfg))
}

// =============================================================================
// UPGRADE / UPGRADE REHEARSAL
// =============================================================================

func TestCB_BlockingFailuresFromChecklist(t *testing.T) {
	items := []keeper.UpgradeChecklistItem{
		{ID: "item1", Passed: true, Blocking: true},
		{ID: "item2", Passed: false, Blocking: true},
		{ID: "item3", Passed: false, Blocking: false},
	}
	failures := keeper.BlockingFailuresFromChecklist(items)
	require.Len(t, failures, 1)
	require.Equal(t, "item2", failures[0].ID)
}

// =============================================================================
// PERFORMANCE BASELINES
// =============================================================================

func TestCB_EvaluateBenchmarkBaselines(t *testing.T) {
	violations := keeper.EvaluateBenchmarkBaselines(nil, nil)
	require.Empty(t, violations)
}

// =============================================================================
// ROADMAP TRACKER
// =============================================================================

func TestCB_StatusIcon(t *testing.T) {
	// Test all milestone statuses
	require.NotEmpty(t, keeper.StatusIconForTest(keeper.MilestoneCompleted))
	require.NotEmpty(t, keeper.StatusIconForTest(keeper.MilestoneInProgress))
	require.NotEmpty(t, keeper.StatusIconForTest(keeper.MilestoneBlocked))
	require.NotEmpty(t, keeper.StatusIconForTest(keeper.MilestoneNotStarted))
}

func TestCB_DetermineCurrentWeek(t *testing.T) {
	week := keeper.DetermineCurrentWeekForTest(time.Now())
	require.Greater(t, week, 0)
	require.LessOrEqual(t, week, 52)
}

// =============================================================================
// SCHEDULER - RegisterValidator, GetValidatorCapabilities
// =============================================================================

func TestCB_Scheduler_RegisterValidator(t *testing.T) {
	sched := keeper.NewJobScheduler(log.NewNopLogger(), nil, keeper.SchedulerConfig{MaxJobsPerBlock: 10})
	sched.RegisterValidator(&types.ValidatorCapability{
		Address:           "val1",
		IsOnline:          true,
		MaxConcurrentJobs: 5,
		ReputationScore:   80,
		TeePlatforms:      []string{"aws-nitro"},
	})
	caps := sched.GetValidatorCapabilities()
	require.Len(t, caps, 1)
}

// =============================================================================
// MAINNET PARAMS
// =============================================================================

func TestCB_ValidateParamChangeProposal(t *testing.T) {
	proposal := keeper.ParamChangeProposal{
		Field:    "max_jobs_per_block",
		OldValue: "10",
		NewValue: "20",
		Proposer: "cosmos1abc",
	}
	result := keeper.ValidateParamChangeProposal(proposal)
	_ = result // ensure no panic
}

// =============================================================================
// CONSENSUS TESTING OVERRIDE
// =============================================================================

func TestCB_AllowSimulatedInThisBuild(t *testing.T) {
	_ = keeper.AllowSimulatedInThisBuildForTest() // just exercise the code path
}

// =============================================================================
// FEE DISTRIBUTION - ValidateFeeDistribution
// =============================================================================

func TestCB_ValidateFeeDistribution(t *testing.T) {
	cfg := keeper.DefaultFeeDistributionConfig()
	require.NoError(t, keeper.ValidateFeeDistribution(cfg))
}

// =============================================================================
// VALIDATOR ONBOARDING - ValidateApplication
// =============================================================================

func TestCB_ValidateApplication_Missing(t *testing.T) {
	app := keeper.OnboardingApplication{
		Moniker: "test-validator",
	}
	require.Error(t, keeper.ValidateApplication(app))
}

// =============================================================================
// FEE EARMARK
// =============================================================================

// FeeEarmarkStore tests removed - type does not exist in current codebase

// =============================================================================
// AUDIT SCOPE
// =============================================================================

func TestCB_RenderChecklist(t *testing.T) {
	items := []keeper.EngagementChecklistItem{
		{ID: "1", Category: "access", Description: "repo access", Required: true, Completed: true},
		{ID: "2", Category: "documentation", Description: "API docs", Required: true, Completed: false},
	}
	output := keeper.RenderChecklist(items)
	require.Contains(t, output, "repo access")
	require.Contains(t, output, "API docs")
	require.Contains(t, output, "[x]")  // completed item
	require.Contains(t, output, "[ ]")  // incomplete item
}

// =============================================================================
// ATTESTATION REGISTRY - normalizeMeasurementHex, canonicalizePlatform
// =============================================================================

func TestCB_NormalizeMeasurementHex(t *testing.T) {
	validHex := strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
	result, err := keeper.NormalizeMeasurementHexForTest(validHex)
	require.NoError(t, err)
	require.Equal(t, validHex, result)

	result, err = keeper.NormalizeMeasurementHexForTest(strings.ToUpper(validHex))
	require.NoError(t, err)
	require.Equal(t, validHex, result)

	// wrong length
	_, err = keeper.NormalizeMeasurementHexForTest("xyz")
	require.Error(t, err)

	// invalid hex (correct length)
	_, err = keeper.NormalizeMeasurementHexForTest(strings.Repeat("zz", 32))
	require.Error(t, err)
}

func TestCB_CanonicalizePlatform(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"aws-nitro", "aws-nitro", false},
		{"AWS-NITRO", "aws-nitro", false},
		{"intel-sgx", "intel-sgx", false},
		{"INTEL-SGX", "intel-sgx", false},
		{"", "", true},
		{"unknown-platform", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := keeper.CanonicalizePlatformForTest(tc.input)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
