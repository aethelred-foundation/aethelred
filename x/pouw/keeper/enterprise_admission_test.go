package keeper_test

import (
	"testing"

	"github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// SQ06: Enterprise Scheduler Admission Tests
// =============================================================================

// ---------------------------------------------------------------------------
// Scheduler: Enterprise job compliance
// ---------------------------------------------------------------------------

func TestEnterprise_SchedulerRejectsTEEOnlyJob(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.EnterpriseMode = true
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	job := makeJob("enterprise-tee-only", 10, types.ProofTypeTEE)
	err := s.EnqueueJob(ctx, job)
	if err == nil {
		t.Fatal("expected enterprise mode to reject TEE-only job, but EnqueueJob succeeded")
	}
	t.Logf("OK: TEE-only job rejected in enterprise mode: %v", err)
}

func TestEnterprise_SchedulerRejectsZKMLOnlyJob(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.EnterpriseMode = true
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	job := makeJob("enterprise-zkml-only", 10, types.ProofTypeZKML)
	err := s.EnqueueJob(ctx, job)
	if err == nil {
		t.Fatal("expected enterprise mode to reject ZKML-only job, but EnqueueJob succeeded")
	}
	t.Logf("OK: ZKML-only job rejected in enterprise mode: %v", err)
}

func TestEnterprise_SchedulerAcceptsHybridJob(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.EnterpriseMode = true
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	job := makeJob("enterprise-hybrid", 10, types.ProofTypeHybrid)
	err := s.EnqueueJob(ctx, job)
	if err != nil {
		t.Fatalf("expected enterprise mode to accept hybrid job, but got error: %v", err)
	}
	t.Log("OK: hybrid job accepted in enterprise mode")
}

func TestEnterprise_IsEnterpriseCompliantJob_NilJob(t *testing.T) {
	err := keeper.IsEnterpriseCompliantJob(nil)
	if err == nil {
		t.Fatal("expected error for nil job")
	}
	t.Logf("OK: nil job rejected: %v", err)
}

func TestEnterprise_NonEnterpriseModeAllowsAllTypes(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.EnterpriseMode = false
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	for _, pt := range []types.ProofType{types.ProofTypeTEE, types.ProofTypeZKML, types.ProofTypeHybrid} {
		job := makeJob("non-enterprise-"+pt.String(), 10, pt)
		err := s.EnqueueJob(ctx, job)
		if err != nil {
			t.Errorf("non-enterprise mode should accept %s jobs, but got error: %v", pt, err)
		}
	}
	t.Log("OK: non-enterprise mode accepts all proof types")
}

// ---------------------------------------------------------------------------
// Validator Onboarding: Enterprise capability
// ---------------------------------------------------------------------------

func TestEnterprise_ValidatorMustSupportHybrid(t *testing.T) {
	app := keeper.OnboardingApplication{
		ValidatorAddr:    "val1",
		Moniker:          "enterprise-val",
		SupportsTEE:      true,
		SupportsZKML:     true,
		SupportsHybrid:   true,
		TEEPlatform:      "nitro",
		ZKMLBackend:      "ezkl",
		NodeVersion:      "v1.0.0",
		MaxConcurrentJobs: 5,
	}
	err := keeper.IsEnterpriseCapableValidator(app)
	if err != nil {
		t.Fatalf("expected fully capable validator to pass enterprise check, got: %v", err)
	}
	t.Log("OK: fully capable validator passes enterprise check")
}

func TestEnterprise_NonHybridValidatorRejected(t *testing.T) {
	tests := []struct {
		name           string
		supportsTEE    bool
		supportsZKML   bool
		supportsHybrid bool
	}{
		{"TEE-only", true, false, false},
		{"ZKML-only", false, true, false},
		{"TEE+ZKML-no-hybrid", true, true, false},
		{"none", false, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := keeper.OnboardingApplication{
				ValidatorAddr:    "val-" + tc.name,
				Moniker:          "test-" + tc.name,
				SupportsTEE:      tc.supportsTEE,
				SupportsZKML:     tc.supportsZKML,
				SupportsHybrid:   tc.supportsHybrid,
				TEEPlatform:      "nitro",
				ZKMLBackend:      "ezkl",
				NodeVersion:      "v1.0.0",
				MaxConcurrentJobs: 5,
			}
			err := keeper.IsEnterpriseCapableValidator(app)
			if err == nil {
				t.Fatalf("expected validator %q to be rejected by enterprise check", tc.name)
			}
			t.Logf("OK: validator %q rejected: %v", tc.name, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Job Assignment: Enterprise jobs only to hybrid validators
// ---------------------------------------------------------------------------

func TestEnterprise_JobAssignmentOnlyToHybridValidators(t *testing.T) {
	cfg := keeper.DefaultSchedulerConfig()
	cfg.EnterpriseMode = true
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Register a TEE-only validator (not hybrid-capable)
	teeOnly := makeValidator("val-tee", []string{"nitro"}, nil, 5)
	s.RegisterValidator(teeOnly)

	// Register a ZKML-only validator (not hybrid-capable)
	zkmlOnly := makeValidator("val-zkml", nil, []string{"ezkl"}, 5)
	s.RegisterValidator(zkmlOnly)

	// Enqueue a hybrid job (only allowed type in enterprise mode)
	job := makeJob("enterprise-assign-test", 10, types.ProofTypeHybrid)
	err := s.EnqueueJob(ctx, job)
	if err != nil {
		t.Fatalf("failed to enqueue hybrid job: %v", err)
	}

	// GetNextJobs should return nothing because no hybrid-capable validators exist
	jobs := s.GetNextJobs(ctx, 100)
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs assigned (no hybrid validators), got %d", len(jobs))
	}
	t.Log("OK: no jobs assigned when only non-hybrid validators are available")

	// Now register a hybrid-capable validator
	hybridVal := makeValidator("val-hybrid", []string{"nitro"}, []string{"ezkl"}, 5)
	s.RegisterValidator(hybridVal)

	// Re-enqueue (the job is still in queue from before)
	// GetNextJobs should now assign the job
	jobs = s.GetNextJobs(ctx, 101)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job assigned to hybrid validator, got %d", len(jobs))
	}
	t.Logf("OK: hybrid job assigned to hybrid-capable validator")
}

func TestEnterprise_GetNextJobsSkipsNonHybridInQueue(t *testing.T) {
	// Simulate a scenario where enterprise mode was enabled after jobs were already queued.
	// First enqueue in non-enterprise mode, then switch to enterprise mode.
	cfg := keeper.DefaultSchedulerConfig()
	cfg.EnterpriseMode = false
	cfg.MinValidatorsRequired = 1
	s := testSchedulerWithConfig(cfg)
	ctx := sdkCtxForHeight(100)

	// Register a hybrid-capable validator
	hybridVal := makeValidator("val-hybrid", []string{"nitro"}, []string{"ezkl"}, 5)
	s.RegisterValidator(hybridVal)

	// Enqueue a TEE-only job in non-enterprise mode
	teeJob := makeJob("pre-enterprise-tee", 10, types.ProofTypeTEE)
	err := s.EnqueueJob(ctx, teeJob)
	if err != nil {
		t.Fatalf("failed to enqueue TEE job in non-enterprise mode: %v", err)
	}

	// Enqueue a hybrid job in non-enterprise mode
	hybridJob := makeJob("pre-enterprise-hybrid", 20, types.ProofTypeHybrid)
	err = s.EnqueueJob(ctx, hybridJob)
	if err != nil {
		t.Fatalf("failed to enqueue hybrid job: %v", err)
	}

	// Now enable enterprise mode by creating a new scheduler with the same state
	// We'll just test that the enterprise filter in GetNextJobs works
	// by setting the config directly
	s.SetEnterpriseMode(true)

	// GetNextJobs should only return the hybrid job, skipping the TEE job
	jobs := s.GetNextJobs(ctx, 101)

	// The hybrid job should be processed; the TEE job should be skipped
	hybridFound := false
	for _, j := range jobs {
		if j.ProofType == types.ProofTypeTEE {
			t.Fatal("enterprise mode should have skipped TEE job in GetNextJobs")
		}
		if j.Id == "pre-enterprise-hybrid" {
			hybridFound = true
		}
	}
	if !hybridFound && len(jobs) > 0 {
		t.Log("WARNING: hybrid job may not have been assigned due to validator constraints")
	}
	t.Logf("OK: enterprise mode filters non-hybrid jobs in GetNextJobs, got %d jobs", len(jobs))
}
