package app

import (
	"testing"

	"cosmossdk.io/log"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestResolveSchedulerPerformanceProfile_DefaultsToMainnet(t *testing.T) {
	t.Setenv("AETHELRED_PERFORMANCE_PROFILE", "")
	t.Setenv("AETHELRED_BENCHMARK_PROFILE", "")

	profile := resolveSchedulerPerformanceProfile(log.NewNopLogger())
	if profile.Name != "mainnet" {
		t.Fatalf("expected mainnet profile, got %q", profile.Name)
	}
}

func TestResolveSchedulerPerformanceProfile_UsesReferenceBenchmark(t *testing.T) {
	t.Setenv("AETHELRED_PERFORMANCE_PROFILE", pouwkeeper.ReferenceBenchmarkProfileName)

	profile := resolveSchedulerPerformanceProfile(log.NewNopLogger())
	if profile.Name != pouwkeeper.ReferenceBenchmarkProfileName {
		t.Fatalf("expected %q profile, got %q", pouwkeeper.ReferenceBenchmarkProfileName, profile.Name)
	}
	if profile.MaxJobsPerBlock != 2000 {
		t.Fatalf("expected 2000 jobs/block, got %d", profile.MaxJobsPerBlock)
	}
}

func TestResolveSchedulerPerformanceProfile_FallsBackOnUnknownProfile(t *testing.T) {
	t.Setenv("AETHELRED_PERFORMANCE_PROFILE", "unknown-profile")

	profile := resolveSchedulerPerformanceProfile(log.NewNopLogger())
	if profile.Name != "mainnet" {
		t.Fatalf("expected fallback mainnet profile, got %q", profile.Name)
	}
}
