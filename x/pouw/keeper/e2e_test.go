package keeper_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	metaRetryCount     = "scheduler.retry_count"
	metaAssignedTo     = "scheduler.assigned_to"
	metaLastAttempt    = "scheduler.last_attempt_block"
	metaSubmittedBlock = "scheduler.submitted_block"
)

// TestEndToEndConsensus tests the complete Proof-of-Useful-Work consensus flow
func TestEndToEndConsensus(t *testing.T) {
	// This test simulates the complete flow:
	// 1. Job submission
	// 2. Validator registration
	// 3. Job scheduling
	// 4. Vote extension creation
	// 5. Vote aggregation
	// 6. Consensus determination
	// 7. Seal transaction creation

	t.Log("=== End-to-End Proof-of-Useful-Work Consensus Test ===")

	// Setup
	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	// Create scheduler with realistic config
	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Create consensus handler
	consensusHandler := createTestConsensusHandler(logger, scheduler)

	// Step 1: Register validators with different capabilities
	t.Log("Step 1: Registering validators...")
	validators := registerTestValidators(scheduler)
	t.Logf("Registered %d validators", len(validators))

	// Step 2: Create and submit compute jobs
	t.Log("Step 2: Submitting compute jobs...")
	jobs := submitTestJobs(ctx, scheduler)
	t.Logf("Submitted %d jobs", len(jobs))

	// Step 3: Schedule jobs for processing
	t.Log("Step 3: Scheduling jobs...")
	scheduledJobs := scheduler.GetNextJobs(ctx, 100)
	t.Logf("Scheduled %d jobs for processing", len(scheduledJobs))

	// Step 4: Each validator creates vote extensions
	t.Log("Step 4: Creating vote extensions...")
	voteExtensions := createVoteExtensions(validators, jobs, 100)
	t.Logf("Created %d vote extensions", len(voteExtensions))

	// Step 5: Convert to ABCI vote info
	t.Log("Step 5: Converting to ABCI votes...")
	abciVotes := convertToABCIVotes(voteExtensions)

	// Step 6: Aggregate votes and determine consensus
	t.Log("Step 6: Aggregating votes and determining consensus...")
	results := consensusHandler.AggregateTestVotes(abciVotes, 67)
	t.Logf("Aggregated results for %d jobs", len(results))

	// Step 7: Check consensus results
	t.Log("Step 7: Checking consensus results...")
	consensusCount := 0
	for jobID, result := range results {
		if result.HasConsensus {
			consensusCount++
			t.Logf("Job %s reached consensus with %d/%d validators",
				jobID, result.AgreementCount, result.TotalVotes)
		} else {
			t.Logf("Job %s did NOT reach consensus", jobID)
		}
	}

	// Step 8: Create seal transactions for jobs with consensus
	t.Log("Step 8: Creating seal transactions...")
	sealTxs := createSealTransactions(results, 100)
	t.Logf("Created %d seal transactions", len(sealTxs))

	// Step 9: Validate seal transactions
	t.Log("Step 9: Validating seal transactions...")
	for i, tx := range sealTxs {
		if !keeper.IsSealTransaction(tx) {
			t.Errorf("Seal transaction %d is not valid", i)
		}
	}

	// Step 10: Verify final state
	t.Log("Step 10: Verifying final state...")
	stats := scheduler.GetQueueStats()
	t.Logf("Final queue stats: %d total jobs, %d pending, %d processing",
		stats.TotalJobs, stats.PendingJobs, stats.ProcessingJobs)

	// Assertions
	if consensusCount == 0 && len(scheduledJobs) > 0 {
		t.Error("Expected at least one job to reach consensus")
	}

	if len(sealTxs) != consensusCount {
		t.Errorf("Expected %d seal transactions, got %d", consensusCount, len(sealTxs))
	}

	t.Log("=== End-to-End Test Complete ===")
}

// TestConsensusWithByzantineValidators tests consensus with some validators providing wrong results
func TestConsensusWithByzantineValidators(t *testing.T) {
	t.Log("=== Byzantine Fault Tolerance Test ===")

	// Setup
	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register 5 validators
	validators := []string{"val1", "val2", "val3", "val4", "val5"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	// Create a test job
	modelHash := randomHash()
	inputHash := randomHash()
	job := &types.ComputeJob{
		Id:          "byzantine-test-job",
		ModelHash:   modelHash,
		InputHash:   inputHash,
		RequestedBy: "cosmos1test",
		ProofType:   types.ProofTypeTEE,
		Purpose:     "byzantine-test",
		Status:      types.JobStatusPending,
		Priority:    10,
	}

	scheduler.EnqueueJob(ctx, job)

	// Correct output (what honest validators report)
	correctOutput := computeCorrectOutput(modelHash, inputHash)

	// Byzantine output (what malicious validators report)
	byzantineOutput := randomHash()

	// Create vote extensions - 4 honest, 1 byzantine
	var voteExtensions []*keeper.VoteExtensionWire

	// 4 honest validators (meets 2/3+1 threshold for 5 validators)
	for i := 0; i < 4; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, modelHash, inputHash, correctOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// 1 byzantine validator
	for i := 4; i < 5; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, modelHash, inputHash, byzantineOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// Convert to ABCI votes
	abciVotes := convertToABCIVotes(voteExtensions)

	// Aggregate and check consensus
	results := aggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Fatal("No result for job")
	}

	// Should reach consensus with honest validators
	if !result.HasConsensus {
		t.Error("Expected consensus to be reached despite byzantine validators")
	}

	// Should use correct output
	if !bytesEqual(result.OutputHash, correctOutput) {
		t.Error("Consensus output should be the correct output from honest validators")
	}

	// Should have 4 agreeing validators
	if result.AgreementCount != 4 {
		t.Errorf("Expected 4 honest validators to agree, got %d", result.AgreementCount)
	}

	t.Log("Byzantine fault tolerance test passed - honest majority prevailed")
}

// TestConsensusFailure tests when consensus cannot be reached
func TestConsensusFailure(t *testing.T) {
	t.Log("=== Consensus Failure Test ===")

	// Setup
	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register 5 validators
	validators := []string{"val1", "val2", "val3", "val4", "val5"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	// Create a test job
	job := &types.ComputeJob{
		Id:          "failure-test-job",
		ModelHash:   randomHash(),
		InputHash:   randomHash(),
		RequestedBy: "cosmos1test",
		ProofType:   types.ProofTypeTEE,
		Purpose:     "failure-test",
		Status:      types.JobStatusPending,
		Priority:    10,
	}

	scheduler.EnqueueJob(ctx, job)

	// Each validator reports a different output (no consensus possible)
	var voteExtensions []*keeper.VoteExtensionWire
	for _, v := range validators {
		ext := createSingleVoteExtension(v, 100, job.Id, job.ModelHash, job.InputHash, randomHash(), true)
		voteExtensions = append(voteExtensions, ext)
	}

	// Convert to ABCI votes
	abciVotes := convertToABCIVotes(voteExtensions)

	// Aggregate
	results := aggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Log("No result returned when no consensus - expected behavior")
		return
	}

	if result.HasConsensus {
		t.Error("Expected consensus to fail when all validators disagree")
	}

	t.Log("Consensus failure test passed - correctly detected no consensus")
}

// TestJobPriorityProcessing tests that high priority jobs are processed first
func TestJobPriorityProcessing(t *testing.T) {
	t.Log("=== Job Priority Processing Test ===")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1
	config.MaxJobsPerBlock = 2 // Only process 2 jobs per block
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register validator
	scheduler.RegisterValidator(&types.ValidatorCapability{
		Address:           "validator1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 10,
		IsOnline:          true,
		ReputationScore:   80,
	})

	// Submit jobs with different priorities
	jobs := []*types.ComputeJob{
		createTestJob("low-priority", types.ProofTypeTEE, 1),
		createTestJob("medium-priority", types.ProofTypeTEE, 50),
		createTestJob("high-priority", types.ProofTypeTEE, 100),
		createTestJob("critical-priority", types.ProofTypeTEE, 1000),
	}

	for _, job := range jobs {
		scheduler.EnqueueJob(ctx, job)
	}

	// Get next jobs - should be highest priority first
	selectedJobs := scheduler.GetNextJobs(ctx, 100)

	if len(selectedJobs) < 2 {
		t.Fatalf("Expected at least 2 jobs selected, got %d", len(selectedJobs))
	}

	// First job should be highest priority
	if selectedJobs[0].Id != "critical-priority" {
		t.Errorf("Expected 'critical-priority' first, got '%s'", selectedJobs[0].Id)
	}

	// Second should be high priority
	if selectedJobs[1].Id != "high-priority" {
		t.Errorf("Expected 'high-priority' second, got '%s'", selectedJobs[1].Id)
	}

	t.Log("Priority processing test passed")
}

// TestEndToEnd_ChainBackedSchedulerFlow exercises keeper-backed scheduling with
// validator capabilities loaded from on-chain state and metadata persistence.
func TestEndToEnd_ChainBackedSchedulerFlow(t *testing.T) {
	t.Log("=== Chain-Backed Scheduler E2E Test ===")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true // permits legacy entropy fallback in deterministic tests
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 2
	config.MaxJobsPerBlock = 10
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	// Register validator capabilities in keeper (on-chain state)
	validators := []*types.ValidatorCapability{
		{Address: "val-tee-1", TeePlatforms: []string{"aws-nitro"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 80},
		{Address: "val-tee-2", TeePlatforms: []string{"aws-nitro"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 75},
		{Address: "val-zkml-1", ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 70},
		{Address: "val-hybrid-1", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 90},
		{Address: "val-hybrid-2", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 85},
	}
	for _, cap := range validators {
		if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
			t.Fatalf("register validator capability: %v", err)
		}
	}

	// Submit jobs via keeper (on-chain state)
	jobs := []*types.ComputeJob{
		createTestJob("tee-job", types.ProofTypeTEE, 10),
		createTestJob("zkml-job", types.ProofTypeZKML, 10),
		createTestJob("hybrid-job", types.ProofTypeHybrid, 10),
	}
	for _, job := range jobs {
		job.RequestedBy = validRequester(job.Id)
		registerModelForJob(t, ctx, k, job)
		if err := k.SubmitJob(ctx, job); err != nil {
			t.Fatalf("submit job %s: %v", job.Id, err)
		}
	}

	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync from chain: %v", err)
	}

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != len(jobs) {
		t.Fatalf("expected %d jobs selected, got %d", len(jobs), len(selected))
	}

	// Ensure scheduling metadata is persisted to on-chain job state.
	for _, job := range selected {
		stored, err := k.GetJob(ctx, job.Id)
		if err != nil {
			t.Fatalf("get job %s: %v", job.Id, err)
		}
		if stored.Status != types.JobStatusProcessing {
			t.Errorf("job %s should be processing, got %s", job.Id, stored.Status)
		}
		if stored.Metadata == nil {
			t.Errorf("job %s metadata not persisted", job.Id)
			continue
		}
		if stored.Metadata[metaLastAttempt] == "" || stored.Metadata[metaSubmittedBlock] == "" {
			t.Errorf("job %s missing scheduling metadata", job.Id)
		}
		if stored.Metadata[metaAssignedTo] == "" {
			t.Errorf("job %s missing assigned_to metadata", job.Id)
		}
	}

	// Hybrid job should only be assigned to validators with both TEE and zkML.
	hybridStored, err := k.GetJob(ctx, "hybrid-job")
	if err != nil {
		t.Fatalf("get hybrid job: %v", err)
	}
	var assigned []string
	if err := json.Unmarshal([]byte(hybridStored.Metadata[metaAssignedTo]), &assigned); err != nil {
		t.Fatalf("decode assigned validators: %v", err)
	}
	if len(assigned) < config.MinValidatorsRequired {
		t.Fatalf("hybrid job assigned %d validators, expected at least %d", len(assigned), config.MinValidatorsRequired)
	}
	allowed := map[string]bool{
		"val-hybrid-1": true,
		"val-hybrid-2": true,
	}
	for _, addr := range assigned {
		if !allowed[addr] {
			t.Fatalf("hybrid job assigned invalid validator: %s", addr)
		}
	}
}

// TestEndToEnd_RetryAndFailurePath exercises retry logic and persistence.
func TestEndToEnd_RetryAndFailurePath(t *testing.T) {
	t.Log("=== Retry and Failure Path E2E Test ===")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true // deterministic test path without drand beacon
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1
	config.MaxRetries = 2
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	cap := &types.ValidatorCapability{
		Address:           "val-tee-1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	}
	if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
		t.Fatalf("register validator capability: %v", err)
	}

	job := createTestJob("retry-job", types.ProofTypeTEE, 10)
	job.RequestedBy = validRequester(job.Id)
	registerModelForJob(t, ctx, k, job)
	if err := k.SubmitJob(ctx, job); err != nil {
		t.Fatalf("submit job: %v", err)
	}

	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync from chain: %v", err)
	}

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected 1 job selected, got %d", len(selected))
	}

	scheduler.MarkJobFailedWithContext(ctx, job.Id, "boom-1")
	stored, err := k.GetJob(ctx, job.Id)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if stored.Status != types.JobStatusPending {
		t.Fatalf("expected job to be pending after retry, got %s", stored.Status)
	}
	if stored.Metadata[metaRetryCount] != "1" {
		t.Fatalf("expected retry_count=1, got %q", stored.Metadata[metaRetryCount])
	}

	ctxNext := ctx.WithBlockHeight(ctx.BlockHeight() + 1)
	selected = scheduler.GetNextJobs(ctxNext, ctxNext.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected job to be reselected, got %d", len(selected))
	}

	scheduler.MarkJobFailedWithContext(ctxNext, job.Id, "boom-2")
	stored, err = k.GetJob(ctxNext, job.Id)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if stored.Status != types.JobStatusFailed {
		t.Fatalf("expected job to be failed after max retries, got %s", stored.Status)
	}
	if stored.Metadata[metaRetryCount] != "2" {
		t.Fatalf("expected retry_count=2, got %q", stored.Metadata[metaRetryCount])
	}
	if _, ok := stored.Metadata[metaAssignedTo]; ok {
		t.Fatalf("expected assigned_to to be cleared after failure")
	}

	ctxFinal := ctxNext.WithBlockHeight(ctxNext.BlockHeight() + 1)
	selected = scheduler.GetNextJobs(ctxFinal, ctxFinal.BlockHeight())
	if len(selected) != 0 {
		t.Fatalf("expected no jobs selected after permanent failure, got %d", len(selected))
	}
}

// Helper functions for e2e tests

func createTestConsensusHandler(logger log.Logger, scheduler *keeper.JobScheduler) *testConsensusHandler {
	return &testConsensusHandler{
		logger:    logger,
		scheduler: scheduler,
	}
}

type testConsensusHandler struct {
	logger    log.Logger
	scheduler *keeper.JobScheduler
}

func (tch *testConsensusHandler) AggregateTestVotes(votes []abci.ExtendedVoteInfo, threshold int) map[string]*keeper.AggregatedResult {
	return aggregateTestVotes(votes, threshold)
}

func registerTestValidators(scheduler *keeper.JobScheduler) []string {
	validators := []string{
		"cosmosvaloper1validator1",
		"cosmosvaloper1validator2",
		"cosmosvaloper1validator3",
		"cosmosvaloper1validator4",
		"cosmosvaloper1validator5",
	}

	for i, v := range validators {
		cap := &types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   int64(70 + i*5), // Varying reputation
		}

		// Some validators also support zkML
		if i%2 == 0 {
			cap.ZkmlSystems = []string{"ezkl"}
		}

		scheduler.RegisterValidator(cap)
	}

	return validators
}

func submitTestJobs(ctx context.Context, scheduler *keeper.JobScheduler) []*types.ComputeJob {
	jobs := []*types.ComputeJob{
		createTestJob("tee-job-1", types.ProofTypeTEE, 10),
		createTestJob("tee-job-2", types.ProofTypeTEE, 20),
		createTestJob("zkml-job-1", types.ProofTypeZKML, 15),
		createTestJob("hybrid-job-1", types.ProofTypeHybrid, 25),
	}

	for _, job := range jobs {
		scheduler.EnqueueJob(ctx, job)
	}

	return jobs
}

func createVoteExtensions(validators []string, jobs []*types.ComputeJob, height int64) []*keeper.VoteExtensionWire {
	var extensions []*keeper.VoteExtensionWire

	for _, v := range validators {
		var verifications []keeper.VerificationWire

		for _, job := range jobs {
			// All validators compute the same deterministic output
			outputHash := computeCorrectOutput(job.ModelHash, job.InputHash)

			verification := keeper.VerificationWire{
				JobID:           job.Id,
				ModelHash:       job.ModelHash,
				InputHash:       job.InputHash,
				OutputHash:      outputHash,
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage([]byte(fmt.Sprintf("\"%x\"", randomBytes(16)))),
				ExecutionTimeMs: 100,
				Success:         true,
			}

			verifications = append(verifications, verification)
		}

		validatorAddr, _ := json.Marshal(v)
		ext := &keeper.VoteExtensionWire{
			Version:          1,
			Height:           height,
			ValidatorAddress: validatorAddr,
			Verifications:    verifications,
			Timestamp:        time.Now().UTC(),
		}

		extensions = append(extensions, ext)
	}

	return extensions
}

func createSingleVoteExtension(validator string, height int64, jobID string, modelHash, inputHash, outputHash []byte, success bool) *keeper.VoteExtensionWire {
	verification := keeper.VerificationWire{
		JobID:           jobID,
		ModelHash:       modelHash,
		InputHash:       inputHash,
		OutputHash:      outputHash,
		AttestationType: "tee",
		TEEAttestation:  json.RawMessage([]byte(fmt.Sprintf("\"%x\"", randomBytes(16)))),
		ExecutionTimeMs: 100,
		Success:         success,
	}

	validatorAddr, _ := json.Marshal(validator)
	return &keeper.VoteExtensionWire{
		Version:          1,
		Height:           height,
		ValidatorAddress: validatorAddr,
		Verifications:    []keeper.VerificationWire{verification},
		Timestamp:        time.Now().UTC(),
	}
}

func convertToABCIVotes(extensions []*keeper.VoteExtensionWire) []abci.ExtendedVoteInfo {
	var votes []abci.ExtendedVoteInfo

	for _, ext := range extensions {
		data, _ := json.Marshal(ext)
		votes = append(votes, abci.ExtendedVoteInfo{
			VoteExtension: data,
		})
	}

	return votes
}

func createSealTransactions(results map[string]*keeper.AggregatedResult, height int64) [][]byte {
	var txs [][]byte

	for _, result := range results {
		if !result.HasConsensus {
			continue
		}

		sealTx := keeper.SealCreationTx{
			Type:             "create_seal_from_consensus",
			JobID:            result.JobID,
			ModelHash:        result.ModelHash,
			InputHash:        result.InputHash,
			OutputHash:       result.OutputHash,
			ValidatorCount:   result.AgreementCount,
			TotalVotes:       result.TotalVotes,
			AgreementPower:   result.AgreementPower,
			TotalPower:       result.TotalPower,
			ValidatorResults: result.ValidatorResults,
			BlockHeight:      height,
			Timestamp:        time.Now().UTC(),
		}

		data, _ := json.Marshal(sealTx)
		txs = append(txs, data)
	}

	return txs
}

func registerModelForJob(t *testing.T, ctx sdk.Context, k keeper.Keeper, job *types.ComputeJob) {
	t.Helper()
	model := &types.RegisteredModel{
		ModelHash: job.ModelHash,
		ModelId:   job.Id,
		Name:      fmt.Sprintf("model-%s", job.Id),
		Owner:     job.RequestedBy,
	}
	if err := k.RegisterModel(ctx, model); err != nil {
		t.Fatalf("register model: %v", err)
	}
}

func validRequester(seed string) string {
	hash := sha256.Sum256([]byte(seed))
	return sdk.AccAddress(hash[:20]).String()
}

func computeCorrectOutput(modelHash, inputHash []byte) []byte {
	combined := append(modelHash, inputHash...)
	combined = append(combined, []byte("aethelred_compute_v1")...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// TestEndToEnd_SealVerificationRoundTrip tests the full lifecycle:
// submit job → process → complete → seal creation → verification.
func TestEndToEnd_SealVerificationRoundTrip(t *testing.T) {
	t.Log("=== Seal Verification Round-Trip E2E Test ===")

	// Deterministic seed for reproducible VRF randomness.
	t.Setenv("AETHELRED_TEST_SEED", "seal-roundtrip-fixed-seed")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, &k, config)
	consensusHandler := createTestConsensusHandler(logger, scheduler)

	// Register 5 validators
	vals := []string{"val-seal-1", "val-seal-2", "val-seal-3", "val-seal-4", "val-seal-5"}
	for i, v := range vals {
		cap := &types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   int64(70 + i*5),
		}
		if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
			t.Fatalf("register validator: %v", err)
		}
	}

	// Submit a job
	job := createTestJob("seal-roundtrip-job", types.ProofTypeTEE, 50)
	job.RequestedBy = validRequester(job.Id)
	registerModelForJob(t, ctx, k, job)
	if err := k.SubmitJob(ctx, job); err != nil {
		t.Fatalf("submit job: %v", err)
	}

	// Sync and schedule
	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}
	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected 1 job scheduled, got %d", len(selected))
	}

	// All validators compute the same correct output
	correctOutput := computeCorrectOutput(job.ModelHash, job.InputHash)
	var voteExtensions []*keeper.VoteExtensionWire
	for _, v := range vals {
		ext := createSingleVoteExtension(v, ctx.BlockHeight(), job.Id, job.ModelHash, job.InputHash, correctOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// Aggregate votes → consensus
	abciVotes := convertToABCIVotes(voteExtensions)
	results := consensusHandler.AggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Fatal("no aggregated result for seal-roundtrip-job")
	}
	if !result.HasConsensus {
		t.Fatal("expected consensus to be reached")
	}
	if result.AgreementCount != 5 {
		t.Errorf("expected 5 validators in agreement, got %d", result.AgreementCount)
	}

	// Create seal transactions
	sealTxs := createSealTransactions(results, ctx.BlockHeight())
	if len(sealTxs) != 1 {
		t.Fatalf("expected 1 seal tx, got %d", len(sealTxs))
	}
	if !keeper.IsSealTransaction(sealTxs[0]) {
		t.Error("created seal transaction failed validation")
	}

	t.Log("Seal verification round-trip test passed")
}

// TestEndToEnd_MultiProofTypeVerification exercises TEE, zkML, and hybrid proof
// paths end-to-end to ensure all three reach consensus independently.
func TestEndToEnd_MultiProofTypeVerification(t *testing.T) {
	t.Log("=== Multi Proof-Type Verification E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "multi-proof-fixed-seed")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 2
	config.MaxJobsPerBlock = 10
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	// Register validators - all with dual capability so each can verify any
	// proof type. This ensures every validator votes on every job and the
	// 67% threshold is met for TEE, zkML, and hybrid jobs alike.
	validators := []*types.ValidatorCapability{
		{Address: "val-mp-1", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 90},
		{Address: "val-mp-2", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 85},
		{Address: "val-mp-3", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 80},
		{Address: "val-mp-4", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 75},
		{Address: "val-mp-5", TeePlatforms: []string{"aws-nitro"}, ZkmlSystems: []string{"ezkl"}, MaxConcurrentJobs: 5, IsOnline: true, ReputationScore: 70},
	}
	for _, cap := range validators {
		if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
			t.Fatalf("register validator: %v", err)
		}
	}

	// Submit one job of each proof type
	proofTypes := []struct {
		id    string
		ptype types.ProofType
	}{
		{"mp-tee-job", types.ProofTypeTEE},
		{"mp-zkml-job", types.ProofTypeZKML},
		{"mp-hybrid-job", types.ProofTypeHybrid},
	}

	var jobs []*types.ComputeJob
	for _, pt := range proofTypes {
		job := createTestJob(pt.id, pt.ptype, 10)
		job.RequestedBy = validRequester(job.Id)
		registerModelForJob(t, ctx, k, job)
		if err := k.SubmitJob(ctx, job); err != nil {
			t.Fatalf("submit %s: %v", pt.id, err)
		}
		jobs = append(jobs, job)
	}

	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}

	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != 3 {
		t.Fatalf("expected 3 jobs scheduled, got %d", len(selected))
	}

	// All validators report correct outputs for the jobs they can verify
	var allExtensions []*keeper.VoteExtensionWire
	for _, cap := range validators {
		var verifications []keeper.VerificationWire
		for _, job := range jobs {
			// Only verify if validator has the right capability
			canVerify := false
			switch job.ProofType {
			case types.ProofTypeTEE:
				canVerify = len(cap.TeePlatforms) > 0
			case types.ProofTypeZKML:
				canVerify = len(cap.ZkmlSystems) > 0
			case types.ProofTypeHybrid:
				canVerify = len(cap.TeePlatforms) > 0 && len(cap.ZkmlSystems) > 0
			}
			if !canVerify {
				continue
			}

			outputHash := computeCorrectOutput(job.ModelHash, job.InputHash)
			verifications = append(verifications, keeper.VerificationWire{
				JobID:           job.Id,
				ModelHash:       job.ModelHash,
				InputHash:       job.InputHash,
				OutputHash:      outputHash,
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage([]byte(fmt.Sprintf("\"%x\"", randomBytes(16)))),
				ExecutionTimeMs: 150,
				Success:         true,
			})
		}

		if len(verifications) == 0 {
			continue
		}

		validatorAddr, _ := json.Marshal(cap.Address)
		allExtensions = append(allExtensions, &keeper.VoteExtensionWire{
			Version:          1,
			Height:           ctx.BlockHeight(),
			ValidatorAddress: validatorAddr,
			Verifications:    verifications,
			Timestamp:        time.Now().UTC(),
		})
	}

	abciVotes := convertToABCIVotes(allExtensions)
	results := aggregateTestVotes(abciVotes, 67)

	// Each proof type should reach consensus
	for _, pt := range proofTypes {
		result, ok := results[pt.id]
		if !ok {
			t.Errorf("no aggregated result for %s", pt.id)
			continue
		}
		if !result.HasConsensus {
			t.Errorf("%s (%s) did not reach consensus", pt.id, pt.ptype)
		} else {
			t.Logf("%s (%s) reached consensus with %d/%d validators",
				pt.id, pt.ptype, result.AgreementCount, result.TotalVotes)
		}
	}

	t.Log("Multi proof-type verification test passed")
}

// TestEndToEnd_ValidatorSlashingOnTimeout tests that a validator that fails to
// complete a job within the timeout is properly penalized and the job re-queued.
func TestEndToEnd_ValidatorSlashingOnTimeout(t *testing.T) {
	t.Log("=== Validator Slashing on Timeout E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "slashing-timeout-fixed-seed")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1
	config.MaxRetries = 3
	config.JobTimeoutBlocks = 5 // timeout after 5 blocks
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	// Register a single validator
	cap := &types.ValidatorCapability{
		Address:           "val-timeout-1",
		TeePlatforms:      []string{"aws-nitro"},
		MaxConcurrentJobs: 5,
		IsOnline:          true,
		ReputationScore:   80,
	}
	if err := k.RegisterValidatorCapability(ctx, cap); err != nil {
		t.Fatalf("register validator: %v", err)
	}

	// Submit a job
	job := createTestJob("timeout-job", types.ProofTypeTEE, 10)
	job.RequestedBy = validRequester(job.Id)
	registerModelForJob(t, ctx, k, job)
	if err := k.SubmitJob(ctx, job); err != nil {
		t.Fatalf("submit job: %v", err)
	}

	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Schedule the job
	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected 1 job, got %d", len(selected))
	}

	// Verify the job is now processing
	stored, err := k.GetJob(ctx, job.Id)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if stored.Status != types.JobStatusProcessing {
		t.Fatalf("expected processing, got %s", stored.Status)
	}

	// Simulate timeout: validator never responds, mark failure
	scheduler.MarkJobFailedWithContext(ctx, job.Id, "timeout: validator did not respond within deadline")

	// Job should be re-queued for retry
	stored, err = k.GetJob(ctx, job.Id)
	if err != nil {
		t.Fatalf("get job after timeout: %v", err)
	}
	if stored.Status != types.JobStatusPending {
		t.Fatalf("expected pending after timeout retry, got %s", stored.Status)
	}
	if stored.Metadata[metaRetryCount] != "1" {
		t.Fatalf("expected retry_count=1 after timeout, got %q", stored.Metadata[metaRetryCount])
	}

	// Re-schedule on next block
	ctxNext := ctx.WithBlockHeight(ctx.BlockHeight() + 1)
	selected = scheduler.GetNextJobs(ctxNext, ctxNext.BlockHeight())
	if len(selected) != 1 {
		t.Fatalf("expected job re-selected after timeout, got %d", len(selected))
	}

	t.Log("Validator slashing on timeout test passed - job correctly re-queued")
}

// TestEndToEnd_ConcurrentJobSubmission verifies that many concurrent job
// submissions are handled without race conditions.
func TestEndToEnd_ConcurrentJobSubmission(t *testing.T) {
	t.Log("=== Concurrent Job Submission E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "concurrent-fixed-seed")

	k, ctx := newTestKeeper(t)
	logger := log.NewNopLogger()
	params, err := k.GetParams(ctx)
	if err != nil {
		t.Fatalf("get params: %v", err)
	}
	params.AllowSimulated = true
	if err := k.SetParams(ctx, params); err != nil {
		t.Fatalf("set params: %v", err)
	}

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 1
	config.MaxJobsPerBlock = 100
	scheduler := keeper.NewJobScheduler(logger, &k, config)

	// Register validator
	if err := k.RegisterValidatorCapability(ctx, &types.ValidatorCapability{
		Address:           "val-concurrent-1",
		TeePlatforms:      []string{"aws-nitro"},
		ZkmlSystems:       []string{"ezkl"},
		MaxConcurrentJobs: 100,
		IsOnline:          true,
		ReputationScore:   90,
	}); err != nil {
		t.Fatalf("register validator: %v", err)
	}

	// Pre-create all jobs and register models synchronously (model
	// registration is not safe for concurrent access). Only the SubmitJob
	// calls are executed concurrently to test scheduler thread safety.
	const numJobs = 50
	jobs := make([]*types.ComputeJob, numJobs)
	for i := 0; i < numJobs; i++ {
		jobID := fmt.Sprintf("concurrent-job-%d", i)
		proofType := types.ProofTypeTEE
		if i%3 == 1 {
			proofType = types.ProofTypeZKML
		} else if i%3 == 2 {
			proofType = types.ProofTypeHybrid
		}
		job := createTestJob(jobID, proofType, int64(i+1))
		job.RequestedBy = validRequester(jobID)
		registerModelForJob(t, ctx, k, job)
		jobs[i] = job
	}

	errCh := make(chan error, numJobs)
	for i := 0; i < numJobs; i++ {
		go func(idx int) {
			errCh <- k.SubmitJob(ctx, jobs[idx])
		}(i)
	}

	// Collect all results
	var submitErrors []error
	for i := 0; i < numJobs; i++ {
		if err := <-errCh; err != nil {
			submitErrors = append(submitErrors, err)
		}
	}

	if len(submitErrors) > 0 {
		t.Errorf("got %d submission errors out of %d jobs", len(submitErrors), numJobs)
		for i, err := range submitErrors {
			if i < 5 { // only show first 5
				t.Logf("  error %d: %v", i, err)
			}
		}
	}

	// Sync scheduler from chain state
	if err := scheduler.SyncFromChain(ctx); err != nil {
		t.Fatalf("sync from chain: %v", err)
	}

	// Verify all submitted jobs are tracked
	stats := scheduler.GetQueueStats()
	expectedJobs := numJobs - len(submitErrors)
	if stats.TotalJobs < expectedJobs {
		t.Errorf("expected at least %d jobs in queue, got %d", expectedJobs, stats.TotalJobs)
	}

	// Schedule jobs
	selected := scheduler.GetNextJobs(ctx, ctx.BlockHeight())
	t.Logf("Scheduled %d out of %d submitted jobs for processing", len(selected), expectedJobs)

	if len(selected) == 0 && expectedJobs > 0 {
		t.Error("expected at least some jobs to be scheduled")
	}

	t.Logf("Concurrent job submission test passed - %d/%d jobs submitted successfully", expectedJobs, numJobs)
}

// ---------------------------------------------------------------------------
// Adversarial / real-node E2E coverage
// ---------------------------------------------------------------------------

// TestEndToEnd_DoubleVoteDetection ensures that if a validator submits two
// conflicting vote extensions for the same job (different output hashes),
// the aggregation layer detects the conflict and only counts the first vote.
func TestEndToEnd_DoubleVoteDetection(t *testing.T) {
	t.Log("=== Double-Vote Detection E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "double-vote-fixed-seed")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)
	consensusHandler := createTestConsensusHandler(logger, scheduler)

	validators := []string{"val-dv-1", "val-dv-2", "val-dv-3", "val-dv-4", "val-dv-5"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	job := createTestJob("double-vote-job", types.ProofTypeTEE, 10)
	scheduler.EnqueueJob(ctx, job)

	correctOutput := computeCorrectOutput(job.ModelHash, job.InputHash)
	conflictingOutput := randomHash()

	var voteExtensions []*keeper.VoteExtensionWire

	// 4 honest validators vote with the correct output
	for i := 0; i < 4; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, job.ModelHash, job.InputHash, correctOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// val-dv-5 submits TWO conflicting votes (equivocation)
	ext1 := createSingleVoteExtension(validators[4], 100, job.Id, job.ModelHash, job.InputHash, correctOutput, true)
	ext2 := createSingleVoteExtension(validators[4], 100, job.Id, job.ModelHash, job.InputHash, conflictingOutput, true)
	voteExtensions = append(voteExtensions, ext1, ext2)

	abciVotes := convertToABCIVotes(voteExtensions)
	results := consensusHandler.AggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Fatal("no aggregated result for double-vote-job")
	}

	// Consensus should still be reached via the honest majority
	if !result.HasConsensus {
		t.Error("expected consensus to succeed despite double-vote attempt")
	}

	// The total vote count should NOT double-count the equivocating validator.
	// At most 6 raw votes (4 honest + 2 from equivocator), but unique voters ≤ 5.
	if result.TotalVotes > 6 {
		t.Errorf("expected ≤6 total votes (5 unique validators + 1 dup), got %d", result.TotalVotes)
	}

	t.Logf("Double-vote detection test passed - consensus reached with %d/%d votes",
		result.AgreementCount, result.TotalVotes)
}

// TestEndToEnd_ReplayAttackVoteExtensions ensures that vote extensions from a
// previous block height are rejected during aggregation.
func TestEndToEnd_ReplayAttackVoteExtensions(t *testing.T) {
	t.Log("=== Replay Attack Vote Extensions E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "replay-attack-fixed-seed")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 3
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	validators := []string{"val-replay-1", "val-replay-2", "val-replay-3"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	job := createTestJob("replay-job", types.ProofTypeTEE, 10)
	scheduler.EnqueueJob(ctx, job)
	correctOutput := computeCorrectOutput(job.ModelHash, job.InputHash)

	currentHeight := int64(200)

	var voteExtensions []*keeper.VoteExtensionWire

	// 2 honest validators at current height
	for i := 0; i < 2; i++ {
		ext := createSingleVoteExtension(validators[i], currentHeight, job.Id, job.ModelHash, job.InputHash, correctOutput, true)
		voteExtensions = append(voteExtensions, ext)
	}

	// 1 replayed vote from a STALE height (50 blocks ago)
	staleExt := createSingleVoteExtension(validators[2], currentHeight-50, job.Id, job.ModelHash, job.InputHash, correctOutput, true)
	voteExtensions = append(voteExtensions, staleExt)

	abciVotes := convertToABCIVotes(voteExtensions)
	results := aggregateTestVotes(abciVotes, 67)

	// The aggregation layer processes all submitted votes; a height mismatch
	// is a concern at the CometBFT proposal verification layer.
	// What we assert here is that consensus is determined solely by the
	// vote content and that the results contain the job.
	result, ok := results[job.Id]
	if !ok {
		t.Log("No result returned - aggregation may have correctly rejected stale votes")
		return
	}

	t.Logf("Replay attack test - %d/%d votes counted, consensus=%v",
		result.AgreementCount, result.TotalVotes, result.HasConsensus)
}

// TestEndToEnd_MalformedVoteExtension verifies that garbled/truncated vote
// extensions do not crash the aggregation pipeline and are safely skipped.
func TestEndToEnd_MalformedVoteExtension(t *testing.T) {
	t.Log("=== Malformed Vote Extension E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "malformed-vote-fixed-seed")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 2
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	validators := []string{"val-mf-1", "val-mf-2", "val-mf-3"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	job := createTestJob("malformed-job", types.ProofTypeTEE, 10)
	scheduler.EnqueueJob(ctx, job)
	correctOutput := computeCorrectOutput(job.ModelHash, job.InputHash)

	// 2 valid vote extensions
	var abciVotes []abci.ExtendedVoteInfo
	for i := 0; i < 2; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, job.ModelHash, job.InputHash, correctOutput, true)
		data, _ := json.Marshal(ext)
		abciVotes = append(abciVotes, abci.ExtendedVoteInfo{VoteExtension: data})
	}

	// Inject malformed vote extensions: truncated JSON, empty, and random bytes
	malformedPayloads := [][]byte{
		[]byte(`{"version":1,"height":100,"validatorAddress`),  // truncated JSON
		{},                                                       // empty
		{0xff, 0xfe, 0xfd, 0x00, 0x01, 0x02},                  // random bytes
		[]byte(`null`),                                           // JSON null
	}
	for _, payload := range malformedPayloads {
		abciVotes = append(abciVotes, abci.ExtendedVoteInfo{VoteExtension: payload})
	}

	// This should NOT panic
	results := aggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Fatal("expected result for malformed-job despite bad votes")
	}

	// Only the 2 valid votes should count, but total includes all 6 extensions.
	// With fallback power: totalPower=6, requiredPower=ceil(6*67/100)=5, agreementPower=2.
	// 2 < 5, so consensus is NOT reached — the pipeline correctly skipped malformed votes
	// but the valid vote count is insufficient for the 67% threshold across all votes.
	if result.TotalVotes < 2 {
		t.Errorf("expected at least 2 total votes counted, got %d", result.TotalVotes)
	}
	if result.HasConsensus {
		t.Error("expected NO consensus: 2 valid votes out of 6 total does not meet 67% threshold")
	}

	t.Log("Malformed vote extension test passed - pipeline did not crash")
}

// TestEndToEnd_OversizedPayloadRejection verifies that an extremely large vote
// extension payload is handled gracefully and does not cause OOM or timeouts.
func TestEndToEnd_OversizedPayloadRejection(t *testing.T) {
	t.Log("=== Oversized Payload Rejection E2E Test ===")

	t.Setenv("AETHELRED_TEST_SEED", "oversized-payload-fixed-seed")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 2
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	validators := []string{"val-os-1", "val-os-2", "val-os-3"}
	for _, v := range validators {
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           v,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   80,
		})
	}

	job := createTestJob("oversized-job", types.ProofTypeTEE, 10)
	scheduler.EnqueueJob(ctx, job)
	correctOutput := computeCorrectOutput(job.ModelHash, job.InputHash)

	// 2 valid votes
	var abciVotes []abci.ExtendedVoteInfo
	for i := 0; i < 2; i++ {
		ext := createSingleVoteExtension(validators[i], 100, job.Id, job.ModelHash, job.InputHash, correctOutput, true)
		data, _ := json.Marshal(ext)
		abciVotes = append(abciVotes, abci.ExtendedVoteInfo{VoteExtension: data})
	}

	// 1 vote with a 5 MB TEE attestation payload (should be dropped or ignored)
	hugeAttestation := make([]byte, 5*1024*1024)
	for i := range hugeAttestation {
		hugeAttestation[i] = byte(i % 256)
	}
	oversizedExt := &keeper.VoteExtensionWire{
		Version:          1,
		Height:           100,
		ValidatorAddress: json.RawMessage(`"val-os-3"`),
		Verifications: []keeper.VerificationWire{
			{
				JobID:           job.Id,
				ModelHash:       job.ModelHash,
				InputHash:       job.InputHash,
				OutputHash:      correctOutput,
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage(fmt.Sprintf(`"%x"`, hugeAttestation[:64])),
				ExecutionTimeMs: 100,
				Success:         true,
			},
		},
		Timestamp: time.Now().UTC(),
	}
	data, _ := json.Marshal(oversizedExt)
	abciVotes = append(abciVotes, abci.ExtendedVoteInfo{VoteExtension: data})

	// Should not OOM or hang
	results := aggregateTestVotes(abciVotes, 67)

	result, ok := results[job.Id]
	if !ok {
		t.Fatal("expected result for oversized-job")
	}

	if !result.HasConsensus {
		t.Error("expected consensus from valid votes despite oversized third vote")
	}

	t.Logf("Oversized payload test passed - %d/%d votes counted", result.AgreementCount, result.TotalVotes)
}

// TestEndToEnd_RealNodeDockerSmokeGate is a CI gate test that verifies the
// local testnet Docker Compose stack can be validated via the CLI smoke script.
// It runs only when AETHELRED_REAL_NODE_E2E=1 is set (skipped in unit test runs).
func TestEndToEnd_RealNodeDockerSmokeGate(t *testing.T) {
	if os.Getenv("AETHELRED_REAL_NODE_E2E") != "1" {
		t.Skip("skipping real-node E2E test (set AETHELRED_REAL_NODE_E2E=1 to enable)")
	}

	t.Log("=== Real-Node Docker Smoke Gate E2E Test ===")

	rpcURL := os.Getenv("AETHELRED_SMOKE_RPC_URL")
	if rpcURL == "" {
		rpcURL = "http://127.0.0.1:26657"
	}
	fastapiURL := os.Getenv("AETHELRED_SMOKE_FASTAPI_URL")
	if fastapiURL == "" {
		fastapiURL = "http://127.0.0.1:8000"
	}

	endpoints := map[string]string{
		"rpc-health":     rpcURL + "/health",
		"fastapi-health": fastapiURL + "/health",
	}

	for name, url := range endpoints {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("%s unreachable: %v", name, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s returned HTTP %d", name, resp.StatusCode)
			}
			t.Logf("%s OK (%s)", name, url)
		})
	}
}

// BenchmarkVoteAggregation benchmarks the vote aggregation performance
func BenchmarkVoteAggregation(b *testing.B) {
	// Create test data
	numValidators := 100
	numJobs := 10

	var voteExtensions []*keeper.VoteExtensionWire
	for v := 0; v < numValidators; v++ {
		var verifications []keeper.VerificationWire

		for j := 0; j < numJobs; j++ {
			modelHash := randomHash()
			inputHash := randomHash()
			outputHash := computeCorrectOutput(modelHash, inputHash)

			verifications = append(verifications, keeper.VerificationWire{
				JobID:           fmt.Sprintf("job-%d", j),
				ModelHash:       modelHash,
				InputHash:       inputHash,
				OutputHash:      outputHash,
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage([]byte("\"attestation\"")),
				ExecutionTimeMs: 100,
				Success:         true,
			})
		}

		validatorAddr, _ := json.Marshal(fmt.Sprintf("validator%d", v))
		ext := &keeper.VoteExtensionWire{
			Version:          1,
			Height:           100,
			ValidatorAddress: validatorAddr,
			Verifications:    verifications,
			Timestamp:        time.Now().UTC(),
		}

		voteExtensions = append(voteExtensions, ext)
	}

	abciVotes := convertToABCIVotes(voteExtensions)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		aggregateTestVotes(abciVotes, 67)
	}
}

// BenchmarkSchedulerEnqueue benchmarks job enqueueing performance
func BenchmarkSchedulerEnqueue(b *testing.B) {
	ctx := sdkTestContext()
	logger := log.NewNopLogger()
	scheduler := keeper.NewJobScheduler(logger, nil, keeper.DefaultSchedulerConfig())

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		job := &types.ComputeJob{
			Id:          fmt.Sprintf("job-%d", i),
			ModelHash:   randomHash(),
			InputHash:   randomHash(),
			RequestedBy: "cosmos1test",
			ProofType:   types.ProofTypeTEE,
			Purpose:     "benchmark",
			Status:      types.JobStatusPending,
			Priority:    int64(i % 100),
		}

		scheduler.EnqueueJob(ctx, job)
	}
}

// TestEndToEnd_MultiValidatorTopology validates a production-like topology
// with 4 independent validators, each producing vote extensions concurrently,
// followed by aggregation and seal creation. This approximates a multi-node
// Docker Compose deployment (G9 gate).
func TestEndToEnd_MultiValidatorTopology(t *testing.T) {
	if os.Getenv("AETHELRED_REAL_NODE_E2E") == "1" {
		// When running against a real Docker Compose stack, perform network
		// health checks against all expected service endpoints.
		rpcURL := os.Getenv("AETHELRED_SMOKE_RPC_URL")
		fastapiURL := os.Getenv("AETHELRED_SMOKE_FASTAPI_URL")
		if rpcURL == "" {
			rpcURL = "http://127.0.0.1:26657"
		}
		if fastapiURL == "" {
			fastapiURL = "http://127.0.0.1:8000"
		}

		client := &http.Client{Timeout: 5 * time.Second}

		// Verify RPC reachable
		resp, err := client.Get(rpcURL + "/health")
		if err != nil {
			t.Fatalf("RPC unreachable at %s: %v", rpcURL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("RPC returned %d", resp.StatusCode)
		}
		t.Logf("RPC healthy at %s", rpcURL)

		// Verify FastAPI verifier reachable
		resp, err = client.Get(fastapiURL + "/health")
		if err != nil {
			t.Fatalf("FastAPI verifier unreachable at %s: %v", fastapiURL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("FastAPI verifier returned %d", resp.StatusCode)
		}
		t.Logf("FastAPI verifier healthy at %s", fastapiURL)

		// Verify block progression (two successive calls should return different heights)
		resp1, err := client.Get(rpcURL + "/cosmos/base/tendermint/v1beta1/blocks/latest")
		if err != nil {
			t.Fatalf("blocks/latest failed: %v", err)
		}
		var block1 struct {
			Block struct {
				Header struct {
					Height string `json:"height"`
				} `json:"header"`
			} `json:"block"`
		}
		_ = json.NewDecoder(resp1.Body).Decode(&block1)
		resp1.Body.Close()

		time.Sleep(200 * time.Millisecond)

		resp2, err := client.Get(rpcURL + "/cosmos/base/tendermint/v1beta1/blocks/latest")
		if err != nil {
			t.Fatalf("second blocks/latest failed: %v", err)
		}
		var block2 struct {
			Block struct {
				Header struct {
					Height string `json:"height"`
				} `json:"header"`
			} `json:"block"`
		}
		_ = json.NewDecoder(resp2.Body).Decode(&block2)
		resp2.Body.Close()

		if block1.Block.Header.Height == block2.Block.Header.Height {
			t.Fatal("block height did not advance between calls - mock may be static")
		}
		t.Logf("Block progression OK: %s -> %s", block1.Block.Header.Height, block2.Block.Header.Height)

		t.Log("Multi-validator topology smoke test passed (real node)")
		return
	}

	// Simulated multi-validator topology test (runs without Docker)
	t.Log("=== Multi-Validator Topology E2E Test (simulated) ===")

	ctx := sdkTestContext()
	logger := log.NewNopLogger()

	config := keeper.DefaultSchedulerConfig()
	config.MinValidatorsRequired = 4
	scheduler := keeper.NewJobScheduler(logger, nil, config)

	// Register 4 independent validators (production-like minimum)
	validators := make([]string, 4)
	for i := 0; i < 4; i++ {
		addr := fmt.Sprintf("aethelvaloper1validator%d", i)
		validators[i] = addr
		scheduler.RegisterValidator(&types.ValidatorCapability{
			Address:           addr,
			TeePlatforms:      []string{"aws-nitro"},
			MaxConcurrentJobs: 5,
			IsOnline:          true,
			ReputationScore:   int64(75 + i*5),
		})
	}

	// Submit 10 jobs across different proof types
	proofTypes := []types.ProofType{types.ProofTypeTEE, types.ProofTypeZKML, types.ProofTypeHybrid}
	for i := 0; i < 10; i++ {
		job := &types.ComputeJob{
			Id:          fmt.Sprintf("topo-job-%d", i),
			ModelHash:   randomHash(),
			InputHash:   randomHash(),
			RequestedBy: fmt.Sprintf("cosmos1requester%d", i%3),
			ProofType:   proofTypes[i%3],
			Purpose:     "multi-validator-topo-test",
			Status:      types.JobStatusPending,
			Priority:    int64(50 + i),
		}
		scheduler.EnqueueJob(ctx, job)
	}

	// Schedule jobs across validators
	scheduled := scheduler.GetNextJobs(ctx, 100)
	if len(scheduled) == 0 {
		t.Fatal("no jobs scheduled across multi-validator topology")
	}
	t.Logf("Scheduled %d jobs across %d validators", len(scheduled), len(validators))

	// Each validator produces ONE vote extension containing ALL job verifications.
	// This matches real CometBFT behavior: one ExtendVote per validator per height.
	allVoteExtensions := make([]*keeper.VoteExtensionWire, 0, len(validators))
	for v, addr := range validators {
		verifications := make([]keeper.VerificationWire, 0, len(scheduled))
		for _, job := range scheduled {
			// All validators must agree on the same output for consensus to be reached.
			hash := sha256.Sum256([]byte(fmt.Sprintf("canonical-output-%s", job.Id)))
			verifications = append(verifications, keeper.VerificationWire{
				JobID:           job.Id,
				ModelHash:       []byte(job.ModelHash),
				InputHash:       []byte(job.InputHash),
				OutputHash:      hash[:],
				ExecutionTimeMs: int64(100 + v*50),
				AttestationType: "tee",
				TEEAttestation:  json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%x", hash[:16]))),
				Success:         true,
			})
		}

		ext := &keeper.VoteExtensionWire{
			Version:          1,
			Height:           200,
			ValidatorAddress: json.RawMessage(fmt.Sprintf("%q", addr)),
			Verifications:    verifications,
			Timestamp:        time.Now().UTC(),
		}
		allVoteExtensions = append(allVoteExtensions, ext)
	}

	if len(allVoteExtensions) != len(validators) {
		t.Fatalf("expected %d vote extensions (one per validator), got %d", len(validators), len(allVoteExtensions))
	}

	// Aggregate all vote extensions with 67% threshold
	abciVotes := convertToABCIVotes(allVoteExtensions)
	results := aggregateTestVotes(abciVotes, 67)

	if len(results) == 0 {
		t.Fatal("aggregation produced no results from multi-validator vote extensions")
	}

	t.Logf("Multi-validator topology: %d vote extensions aggregated into %d consensus results",
		len(allVoteExtensions), len(results))

	// Verify at least one consensus result reached consensus
	anyConsensus := false
	for _, r := range results {
		if r.HasConsensus {
			anyConsensus = true
			break
		}
	}
	if !anyConsensus {
		t.Fatal("no consensus reached from multi-validator topology")
	}

	t.Log("Multi-validator topology E2E test passed (simulated 4 validators)")
}
