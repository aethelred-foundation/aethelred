package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
)

func TestNitroEnclaveClient_SimulatedPlatformIdentity(t *testing.T) {
	t.Parallel()

	client, err := NewNitroEnclaveClient(log.NewNopLogger(), "simulated://nitro")
	if err != nil {
		t.Fatalf("expected simulated nitro client, got %v", err)
	}

	caps := client.GetCapabilities()
	if caps.Platform != "nitro-simulated" {
		t.Fatalf("expected nitro-simulated platform, got %q", caps.Platform)
	}
}

func TestNitroEnclaveClient_SimulatedExecutionProducesValidArtifacts(t *testing.T) {
	t.Parallel()

	client, err := NewNitroEnclaveClient(log.NewNopLogger(), "simulated://nitro")
	if err != nil {
		t.Fatalf("expected simulated nitro client, got %v", err)
	}

	req := &TEEExecutionRequest{
		JobID:          "job-tee-client-sim",
		ModelHash:      make([]byte, 32),
		InputHash:      bytes32(0x42),
		RequireZKProof: true,
		Timeout:        time.Second,
	}

	result, err := client.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("expected execute success, got %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success result, got %#v", result)
	}
	if result.Attestation == nil {
		t.Fatalf("expected attestation")
	}
	if result.Attestation.Platform != "nitro-simulated" {
		t.Fatalf("expected nitro-simulated attestation, got %q", result.Attestation.Platform)
	}
	if err := result.Attestation.Validate(); err != nil {
		t.Fatalf("expected valid simulated attestation, got %v", err)
	}
	if err := validateTEEQuoteSchema(result.Attestation); err != nil {
		t.Fatalf("expected schema-valid simulated nitro quote, got %v", err)
	}
	if result.ZKProof == nil {
		t.Fatalf("expected zk proof")
	}
	if err := result.ZKProof.Validate(); err != nil {
		t.Fatalf("expected valid simulated zk proof, got %v", err)
	}
}

func TestBuildFullOrchestratorConfig_UsesSimulatedNitroConfig(t *testing.T) {
	t.Parallel()

	client, err := NewNitroEnclaveClient(log.NewNopLogger(), "simulated://nitro")
	if err != nil {
		t.Fatalf("expected simulated nitro client, got %v", err)
	}

	app := &AethelredApp{teeClient: client}
	cfg := app.buildFullOrchestratorConfig()
	if cfg.NitroConfig == nil {
		t.Fatalf("expected nitro config")
	}
	if !cfg.NitroConfig.AllowSimulated {
		t.Fatalf("expected simulated nitro config to allow simulated mode")
	}
}

func TestRemoteTEEClient_RejectsInvalidEndpointAtConstruction(t *testing.T) {
	t.Parallel()

	_, err := NewRemoteTEEClient(log.NewNopLogger(), "https://169.254.169.254")
	if err == nil {
		t.Fatal("expected invalid remote endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid remote TEE endpoint") {
		t.Fatalf("expected invalid endpoint error, got %v", err)
	}
}

func TestRemoteTEEClient_IsHealthyRejectsBlockedEndpoint(t *testing.T) {
	t.Parallel()

	client := &RemoteTEEClient{
		logger:   log.NewNopLogger(),
		endpoint: "https://169.254.169.254",
	}

	if client.IsHealthy(context.Background()) {
		t.Fatal("expected blocked endpoint health probe to fail closed")
	}
}

func TestRemoteTEEClient_IsHealthyUsesBearerTokenWhenConfigured(t *testing.T) {
	t.Setenv("AETHELRED_TEE_API_TOKEN", "worker-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer worker-secret" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewRemoteTEEClient(log.NewNopLogger(), server.URL)
	if err != nil {
		t.Fatalf("expected local test server endpoint to be accepted, got %v", err)
	}

	if !client.IsHealthy(context.Background()) {
		t.Fatal("expected health probe to succeed with configured bearer token")
	}
}

func bytes32(fill byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = fill
	}
	return out
}
