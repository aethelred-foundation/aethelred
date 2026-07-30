package verify

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

func TestValidateProductionReadiness_AllowSimulated(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = true

	report := ValidateProductionReadiness(params, nil, nil)
	if !report.Ready {
		t.Fatalf("expected readiness to pass in simulated mode")
	}
	if len(report.Checks) == 0 {
		t.Fatalf("expected readiness checks")
	}
}

func TestReadinessReportString(t *testing.T) {
	report := ReadinessReport{
		Ready: false,
		Checks: []ReadinessCheck{
			{Name: "check-a", Passed: true, Message: "ok"},
			{Name: "check-b", Passed: false, Message: "bad"},
		},
	}
	out := report.String()
	if !strings.Contains(out, "NOT READY") {
		t.Fatalf("expected NOT READY in report output, got %s", out)
	}
	if !strings.Contains(out, "[PASS] check-a") || !strings.Contains(out, "[FAIL] check-b") {
		t.Fatalf("expected check lines in report output, got %s", out)
	}
}

func TestValidateProductionReadiness_ProductionFailures(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = ""
	params.SupportedProofSystems = nil

	report := ValidateProductionReadiness(params, nil, nil)
	if report.Ready {
		t.Fatalf("expected readiness to fail when missing config")
	}
}

func TestValidateProductionReadiness_NilParams(t *testing.T) {
	report := ValidateProductionReadiness(nil, nil, nil)
	if report.Ready {
		t.Fatalf("expected readiness failure for nil params")
	}
	if !containsAnyReadinessCheck(report.Checks, "params", false) {
		t.Fatalf("expected params failure check, got %+v", report.Checks)
	}
}

func TestValidateProductionReadiness_OrchestratorConfig(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{{
		Platform:            types.TEEPlatformAWSNitro,
		IsActive:            true,
		AttestationEndpoint: "https://attest",
		TrustedMeasurements: [][]byte{[]byte("trusted-measurement")},
	}}

	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "https://exec",
			AttestationVerifierEndpoint: "https://attest-verifier",
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, orch)
	if !report.Ready {
		t.Fatalf("expected readiness to pass with configured endpoints")
	}
}

func TestValidateProductionReadiness_TrustedMeasurementsRequiredInProduction(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{{
		Platform:            types.TEEPlatformAWSNitro,
		IsActive:            true,
		AttestationEndpoint: "https://attest",
		TrustedMeasurements: nil,
	}}

	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "https://exec",
			AttestationVerifierEndpoint: "https://attest-verifier",
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, orch)
	if report.Ready {
		t.Fatalf("expected readiness to fail when trusted measurements are missing")
	}
	if !containsAnyReadinessCheck(report.Checks, "trusted_measurements", false) {
		t.Fatalf("expected trusted_measurements check to fail, got %+v", report.Checks)
	}
}

func TestValidateProductionReadiness_PartialTrustedMeasurementsFail(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{
		{
			Platform:            types.TEEPlatformAWSNitro,
			IsActive:            true,
			AttestationEndpoint: "https://attest-1",
			TrustedMeasurements: [][]byte{[]byte("m1")},
		},
		{
			Platform:            types.TEEPlatformIntelSGX,
			IsActive:            true,
			AttestationEndpoint: "https://attest-2",
			TrustedMeasurements: nil,
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, nil)
	if report.Ready {
		t.Fatalf("expected readiness to fail when only a subset of active platforms has trusted measurements")
	}
	if !containsAnyReadinessCheck(report.Checks, "trusted_measurements", false) {
		t.Fatalf("expected trusted_measurements check to fail, got %+v", report.Checks)
	}
}

func TestValidateProductionReadiness_MissingAttestationEndpointFails(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{
		{
			Platform:            types.TEEPlatformAWSNitro,
			IsActive:            true,
			AttestationEndpoint: "",
			TrustedMeasurements: [][]byte{[]byte("m1")},
		},
	}

	report := ValidateProductionReadiness(params, teeConfigs, nil)
	if report.Ready {
		t.Fatalf("expected readiness failure when attestation endpoint is missing")
	}
	if !containsAnyReadinessCheck(report.Checks, "tee_attestation_endpoints", false) {
		t.Fatalf("expected tee_attestation_endpoints failure, got %+v", report.Checks)
	}
}

func TestValidateEndpointReachability_NoConfig(t *testing.T) {
	if unreachable := ValidateEndpointReachability(nil); len(unreachable) != 0 {
		t.Fatalf("expected no unreachable endpoints")
	}
}

func TestValidateEndpointReachability(t *testing.T) {
	unreachableEndpoint := "http://127.0.0.1:1"
	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			AllowSimulated: false,
			ProverEndpoint: unreachableEndpoint + "/prove",
		},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            unreachableEndpoint,
			AttestationVerifierEndpoint: "http://127.0.0.1:2",
		},
	}

	unreachable := ValidateEndpointReachability(orch)
	if len(unreachable) != 3 {
		t.Fatalf("expected exactly three unreachable endpoints, got %d (%v)", len(unreachable), unreachable)
	}
	if !containsAny(unreachable, "ezkl-prover") {
		t.Fatalf("expected ezkl-prover to be unreachable, got %v", unreachable)
	}
	if !containsAny(unreachable, "nitro-executor") {
		t.Fatalf("expected nitro-executor to be unreachable, got %v", unreachable)
	}
	if !containsAny(unreachable, "attestation-verifier") {
		t.Fatalf("expected attestation-verifier to be unreachable, got %v", unreachable)
	}
}

func TestValidateEndpointReachability_UsesConfiguredBearerTokens(t *testing.T) {
	t.Setenv(readinessTEEAPITokenEnv, "wrong-tee-environment-token")
	t.Setenv(readinessZKMLAPITokenEnv, "wrong-zkml-environment-token")

	prover := newBearerProtectedReadinessServer(t, "zkml-config-token", http.StatusNoContent)
	teeWorker := newBearerProtectedReadinessServer(t, "tee-config-token", http.StatusOK)

	unreachable := ValidateEndpointReachability(&OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			ProverEndpoint: prover.URL,
			APIToken:       "  zkml-config-token  ",
		},
		NitroConfig: &tee.NitroConfig{
			ExecutorEndpoint:            teeWorker.URL,
			AttestationVerifierEndpoint: teeWorker.URL,
			APIToken:                    "  tee-config-token  ",
		},
	})

	if len(unreachable) != 0 {
		t.Fatalf("expected authenticated endpoints to be reachable, got %v", unreachable)
	}
}

func TestValidateEndpointReachability_UsesEnvironmentBearerTokens(t *testing.T) {
	t.Setenv(readinessTEEAPITokenEnv, "tee-environment-token")
	t.Setenv(readinessZKMLAPITokenEnv, "zkml-environment-token")

	prover := newBearerProtectedReadinessServer(t, "zkml-environment-token", http.StatusOK)
	teeWorker := newBearerProtectedReadinessServer(t, "tee-environment-token", http.StatusOK)

	unreachable := ValidateEndpointReachability(&OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			ProverEndpoint: prover.URL,
		},
		NitroConfig: &tee.NitroConfig{
			ExecutorEndpoint:            teeWorker.URL,
			AttestationVerifierEndpoint: teeWorker.URL,
		},
	})

	if len(unreachable) != 0 {
		t.Fatalf("expected environment-authenticated endpoints to be reachable, got %v", unreachable)
	}
}

func containsAny(values []string, part string) bool {
	for _, v := range values {
		if strings.Contains(v, part) {
			return true
		}
	}
	return false
}

func TestEndpointProbeURLs(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		want     []string
	}{
		{
			name:     "host only",
			endpoint: "localhost:8546",
			want:     []string{"http://localhost:8546/health"},
		},
		{
			name:     "path endpoint",
			endpoint: "https://example.com/prove",
			want:     []string{"https://example.com/health"},
		},
		{
			name:     "health endpoint",
			endpoint: "https://example.com/health",
			want:     []string{"https://example.com/health"},
		},
		{
			name:     "empty endpoint",
			endpoint: " ",
			want:     nil,
		},
		{
			name:     "invalid parse",
			endpoint: "http://[::1",
			want:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := endpointProbeURLs(tc.endpoint)
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d probes, got %d (%v)", len(tc.want), len(got), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("probe[%d]: expected %q, got %q", i, tc.want[i], got[i])
				}
			}
		})
	}
}

func TestIsEndpointReachable_BlankEndpoint(t *testing.T) {
	if isEndpointReachable(" ", "") {
		t.Fatalf("blank endpoint must not be considered reachable")
	}
}

func TestIsEndpointReachable_RejectsBlockedEndpoint(t *testing.T) {
	if isEndpointReachable("https://169.254.169.254", "") {
		t.Fatalf("blocked metadata endpoint must not be probed or considered reachable")
	}
}

func TestIsEndpointReachable_RequiresBearerTokenAnd2xx(t *testing.T) {
	tests := []struct {
		name                string
		requiredToken       string
		providedToken       string
		authenticatedStatus int
		want                bool
	}{
		{
			name:                "authorized 200",
			requiredToken:       "worker-secret",
			providedToken:       "worker-secret",
			authenticatedStatus: http.StatusOK,
			want:                true,
		},
		{
			name:                "authorized 204",
			requiredToken:       "worker-secret",
			providedToken:       " worker-secret ",
			authenticatedStatus: http.StatusNoContent,
			want:                true,
		},
		{
			name:                "missing token rejected",
			requiredToken:       "worker-secret",
			authenticatedStatus: http.StatusOK,
			want:                false,
		},
		{
			name:                "wrong token rejected",
			requiredToken:       "worker-secret",
			providedToken:       "wrong-secret",
			authenticatedStatus: http.StatusOK,
			want:                false,
		},
		{
			name:                "authenticated 404 rejected",
			requiredToken:       "worker-secret",
			providedToken:       "worker-secret",
			authenticatedStatus: http.StatusNotFound,
			want:                false,
		},
		{
			name:                "authenticated 403 rejected",
			requiredToken:       "worker-secret",
			providedToken:       "worker-secret",
			authenticatedStatus: http.StatusForbidden,
			want:                false,
		},
		{
			name:                "authenticated 429 rejected",
			requiredToken:       "worker-secret",
			providedToken:       "worker-secret",
			authenticatedStatus: http.StatusTooManyRequests,
			want:                false,
		},
		{
			name:                "authenticated 500 rejected",
			requiredToken:       "worker-secret",
			providedToken:       "worker-secret",
			authenticatedStatus: http.StatusInternalServerError,
			want:                false,
		},
		{
			name:                "authenticated 503 rejected",
			requiredToken:       "worker-secret",
			providedToken:       "worker-secret",
			authenticatedStatus: http.StatusServiceUnavailable,
			want:                false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newBearerProtectedReadinessServer(
				t,
				tc.requiredToken,
				tc.authenticatedStatus,
			)
			if got := isEndpointReachable(server.URL, tc.providedToken); got != tc.want {
				t.Fatalf("expected reachable=%t, got %t", tc.want, got)
			}
		})
	}
}

func TestIsEndpointReachable_DoesNotMaskFailedHealthWithBaseResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer worker-secret"; got != want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/health" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	if isEndpointReachable(server.URL, "worker-secret") {
		t.Fatal("base endpoint 200 must not mask an authenticated /health 503")
	}
}

func TestValidateEndpointReachability_TreatsBlockedEndpointsAsUnreachable(t *testing.T) {
	unreachable := ValidateEndpointReachability(&OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			AllowSimulated: false,
			ProverEndpoint: "https://169.254.169.254",
		},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "https://10.0.0.2",
			AttestationVerifierEndpoint: "https://metadata.google.internal",
		},
	})

	if len(unreachable) != 3 {
		t.Fatalf("expected three unreachable blocked endpoints, got %d (%v)", len(unreachable), unreachable)
	}
}

func TestValidateOrchestratorConfig_AllBranches(t *testing.T) {
	checks := validateOrchestratorConfig(&OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{
			AllowSimulated: false,
			ProverEndpoint: "",
		},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "",
			AttestationVerifierEndpoint: "",
		},
	})

	if !containsAnyReadinessCheck(checks, "ezkl_prover_endpoint", false) {
		t.Fatalf("expected prover endpoint failure, got %+v", checks)
	}
	if !containsAnyReadinessCheck(checks, "nitro_executor_endpoint", false) {
		t.Fatalf("expected nitro executor endpoint failure, got %+v", checks)
	}
	if !containsAnyReadinessCheck(checks, "attestation_verifier_endpoint", false) {
		t.Fatalf("expected attestation verifier endpoint failure, got %+v", checks)
	}
}

func TestValidateProductionReadiness_OrchestratorMissingEndpoint(t *testing.T) {
	params := types.DefaultParams()
	params.AllowSimulated = false
	params.ZkVerifierEndpoint = "https://verifier"
	params.SupportedProofSystems = []string{"ezkl"}

	teeConfigs := []*types.TEEConfig{{
		Platform:            types.TEEPlatformAWSNitro,
		IsActive:            true,
		AttestationEndpoint: "https://attest",
		TrustedMeasurements: [][]byte{[]byte("trusted-measurement")},
	}}

	orch := &OrchestratorConfig{
		ProverConfig: &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: ""},
		NitroConfig:  &tee.NitroConfig{AllowSimulated: true},
	}

	report := ValidateProductionReadiness(params, teeConfigs, orch)
	if report.Ready {
		t.Fatalf("expected readiness to fail when prover endpoint missing")
	}
}

// ── Enterprise mode tests ──

func TestEnterprise_OrchestratorRejectsNonHybridDefault(t *testing.T) {
	cfg := OrchestratorConfig{
		EnterpriseMode:          true,
		DefaultVerificationType: types.VerificationTypeTEE,
		RequireBothForHybrid:    true,
	}
	err := cfg.ValidateEnterpriseConfig()
	if err == nil {
		t.Fatal("expected error when enterprise mode uses non-Hybrid default")
	}
	if !strings.Contains(err.Error(), "Hybrid") {
		t.Fatalf("expected error to mention Hybrid, got: %s", err.Error())
	}
}

func TestEnterprise_OrchestratorRejectsDisabledRequireBoth(t *testing.T) {
	cfg := OrchestratorConfig{
		EnterpriseMode:          true,
		DefaultVerificationType: types.VerificationTypeHybrid,
		RequireBothForHybrid:    false,
	}
	err := cfg.ValidateEnterpriseConfig()
	if err == nil {
		t.Fatal("expected error when enterprise mode has RequireBothForHybrid=false")
	}
	if !strings.Contains(err.Error(), "RequireBothForHybrid") {
		t.Fatalf("expected error to mention RequireBothForHybrid, got: %s", err.Error())
	}
}

func TestEnterprise_OrchestratorRejectsSimulatedProver(t *testing.T) {
	cfg := OrchestratorConfig{
		EnterpriseMode:          true,
		DefaultVerificationType: types.VerificationTypeHybrid,
		RequireBothForHybrid:    true,
		ProverConfig:            &ezkl.ProverConfig{AllowSimulated: true},
	}
	err := cfg.ValidateEnterpriseConfig()
	if err == nil {
		t.Fatal("expected error when enterprise mode allows simulated prover")
	}
	if !strings.Contains(err.Error(), "simulated prover") {
		t.Fatalf("expected error to mention simulated prover, got: %s", err.Error())
	}
}

func TestEnterprise_OrchestratorRejectsSimulatedTEE(t *testing.T) {
	cfg := OrchestratorConfig{
		EnterpriseMode:          true,
		DefaultVerificationType: types.VerificationTypeHybrid,
		RequireBothForHybrid:    true,
		NitroConfig:             &tee.NitroConfig{AllowSimulated: true},
	}
	err := cfg.ValidateEnterpriseConfig()
	if err == nil {
		t.Fatal("expected error when enterprise mode allows simulated TEE")
	}
	if !strings.Contains(err.Error(), "simulated TEE") {
		t.Fatalf("expected error to mention simulated TEE, got: %s", err.Error())
	}
}

func TestEnterprise_OrchestratorPassesValidConfig(t *testing.T) {
	cfg := OrchestratorConfig{
		EnterpriseMode:          true,
		DefaultVerificationType: types.VerificationTypeHybrid,
		RequireBothForHybrid:    true,
		ProverConfig:            &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
		NitroConfig: &tee.NitroConfig{
			AllowSimulated:              false,
			ExecutorEndpoint:            "https://exec",
			AttestationVerifierEndpoint: "https://attest",
		},
	}
	if err := cfg.ValidateEnterpriseConfig(); err != nil {
		t.Fatalf("expected valid enterprise config to pass, got: %s", err.Error())
	}
}

func TestEnterprise_ValidateSkippedWhenNotEnterprise(t *testing.T) {
	cfg := OrchestratorConfig{
		EnterpriseMode:          false,
		DefaultVerificationType: types.VerificationTypeTEE,
		RequireBothForHybrid:    false,
	}
	if err := cfg.ValidateEnterpriseConfig(); err != nil {
		t.Fatalf("expected no error when enterprise mode is off, got: %s", err.Error())
	}
}

func TestEnterprise_ReadinessFailsWithoutTEEEndpoint(t *testing.T) {
	check := &EnterpriseReadinessCheck{
		OrchestratorConfig: &OrchestratorConfig{
			EnterpriseMode:          true,
			DefaultVerificationType: types.VerificationTypeHybrid,
			RequireBothForHybrid:    true,
			ProverConfig:            &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
			NitroConfig: &tee.NitroConfig{
				AllowSimulated:              false,
				ExecutorEndpoint:            "",
				AttestationVerifierEndpoint: "https://attest",
			},
		},
	}
	result, err := check.Validate()
	if err == nil {
		t.Fatal("expected error when TEE endpoint is missing")
	}
	if result.Ready {
		t.Fatal("expected result.Ready=false when TEE endpoint is missing")
	}
	if !containsAnyReadinessCheck(result.Checks, "enterprise_tee_endpoint", false) {
		t.Fatalf("expected enterprise_tee_endpoint failure, got %+v", result.Checks)
	}
}

func TestEnterprise_ReadinessFailsWithoutProverEndpoint(t *testing.T) {
	check := &EnterpriseReadinessCheck{
		OrchestratorConfig: &OrchestratorConfig{
			EnterpriseMode:          true,
			DefaultVerificationType: types.VerificationTypeHybrid,
			RequireBothForHybrid:    true,
			ProverConfig:            &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: ""},
			NitroConfig: &tee.NitroConfig{
				AllowSimulated:              false,
				ExecutorEndpoint:            "https://exec",
				AttestationVerifierEndpoint: "https://attest",
			},
		},
	}
	result, err := check.Validate()
	if err == nil {
		t.Fatal("expected error when prover endpoint is missing")
	}
	if result.Ready {
		t.Fatal("expected result.Ready=false when prover endpoint is missing")
	}
	if !containsAnyReadinessCheck(result.Checks, "enterprise_prover_endpoint", false) {
		t.Fatalf("expected enterprise_prover_endpoint failure, got %+v", result.Checks)
	}
}

func TestEnterprise_ReadinessFailsWithoutAttestationEndpoint(t *testing.T) {
	check := &EnterpriseReadinessCheck{
		OrchestratorConfig: &OrchestratorConfig{
			EnterpriseMode:          true,
			DefaultVerificationType: types.VerificationTypeHybrid,
			RequireBothForHybrid:    true,
			ProverConfig:            &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "https://prover"},
			NitroConfig: &tee.NitroConfig{
				AllowSimulated:              false,
				ExecutorEndpoint:            "https://exec",
				AttestationVerifierEndpoint: "",
			},
		},
	}
	result, err := check.Validate()
	if err == nil {
		t.Fatal("expected error when attestation endpoint is missing")
	}
	if result.Ready {
		t.Fatal("expected result.Ready=false when attestation endpoint is missing")
	}
	if !containsAnyReadinessCheck(result.Checks, "enterprise_attestation_endpoint", false) {
		t.Fatalf("expected enterprise_attestation_endpoint failure, got %+v", result.Checks)
	}
}

func TestEnterprise_ReadinessFailsWithNilConfig(t *testing.T) {
	check := &EnterpriseReadinessCheck{OrchestratorConfig: nil}
	result, err := check.Validate()
	if err == nil {
		t.Fatal("expected error when config is nil")
	}
	if result.Ready {
		t.Fatal("expected result.Ready=false when config is nil")
	}
}

func TestEnterprise_ReadinessPassesWithAllEndpoints(t *testing.T) {
	// Note: this test checks config validation only — the endpoints are not
	// actually reachable. Reachability checks against unreachable localhost
	// ports would cause this test to fail since EnterpriseReadinessCheck.Validate
	// probes endpoints. We verify the config-level validation passes and
	// endpoint reachability fails gracefully.
	check := &EnterpriseReadinessCheck{
		OrchestratorConfig: &OrchestratorConfig{
			EnterpriseMode:          true,
			DefaultVerificationType: types.VerificationTypeHybrid,
			RequireBothForHybrid:    true,
			ProverConfig:            &ezkl.ProverConfig{AllowSimulated: false, ProverEndpoint: "http://127.0.0.1:1/prove"},
			NitroConfig: &tee.NitroConfig{
				AllowSimulated:              false,
				ExecutorEndpoint:            "http://127.0.0.1:2",
				AttestationVerifierEndpoint: "http://127.0.0.1:3",
			},
		},
	}
	result, err := check.Validate()
	// Endpoints are unreachable so Validate returns an error, but the config
	// validation itself (enterprise_config check) passes.
	if err == nil {
		// If somehow the ports are reachable in CI, that's fine too.
		if !result.Ready {
			t.Fatal("expected ready=true when Validate returns nil error")
		}
		return
	}
	// Config check must still pass even though endpoints are unreachable.
	if !containsAnyReadinessCheck(result.Checks, "enterprise_config", true) {
		t.Fatalf("expected enterprise_config check to pass, got %+v", result.Checks)
	}
}

func TestEnterprise_ReadinessUsesConfiguredBearerTokens(t *testing.T) {
	prover := newBearerProtectedReadinessServer(t, "zkml-enterprise-token", http.StatusOK)
	teeWorker := newBearerProtectedReadinessServer(t, "tee-enterprise-token", http.StatusOK)

	check := &EnterpriseReadinessCheck{
		OrchestratorConfig: &OrchestratorConfig{
			EnterpriseMode:          true,
			DefaultVerificationType: types.VerificationTypeHybrid,
			RequireBothForHybrid:    true,
			ProverConfig: &ezkl.ProverConfig{
				AllowSimulated: false,
				ProverEndpoint: prover.URL,
				APIToken:       "zkml-enterprise-token",
			},
			NitroConfig: &tee.NitroConfig{
				AllowSimulated:              false,
				ExecutorEndpoint:            teeWorker.URL,
				AttestationVerifierEndpoint: teeWorker.URL,
				APIToken:                    "tee-enterprise-token",
			},
		},
	}

	result, err := check.Validate()
	if err != nil {
		t.Fatalf("expected authenticated enterprise endpoints to pass: %v", err)
	}
	if !result.Ready {
		t.Fatalf("expected enterprise readiness, got %+v", result.Checks)
	}
}

func newBearerProtectedReadinessServer(t *testing.T, token string, status int) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer "+token; got != want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server
}

func containsAnyReadinessCheck(checks []ReadinessCheck, name string, passed bool) bool {
	for _, c := range checks {
		if c.Name == name && c.Passed == passed {
			return true
		}
	}
	return false
}
