package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
)

func TestHealthHandler_NilApp(t *testing.T) {
	handler := &AethelredHealthHandler{app: nil}
	req := httptest.NewRequest(http.MethodGet, "/health/aethelred", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload["status"] != "unhealthy" {
		t.Fatalf("expected unhealthy status, got %v", payload["status"])
	}
}

func TestBoolStatus(t *testing.T) {
	if got := boolStatus(true); got != "healthy" {
		t.Fatalf("expected healthy, got %s", got)
	}
	if got := boolStatus(false); got != "unhealthy" {
		t.Fatalf("expected unhealthy, got %s", got)
	}
}

func TestOverallStatus(t *testing.T) {
	status := overallStatus([]componentStatus{{Status: "healthy"}, {Status: "healthy"}})
	if status != "healthy" {
		t.Fatalf("expected healthy, got %s", status)
	}

	status = overallStatus([]componentStatus{{Status: "healthy"}, {Status: "simulated"}})
	if status != "simulated" {
		t.Fatalf("expected simulated, got %s", status)
	}

	status = overallStatus([]componentStatus{{Status: "healthy"}, {Status: "degraded"}})
	if status != "degraded" {
		t.Fatalf("expected degraded, got %s", status)
	}

	status = overallStatus([]componentStatus{{Status: "simulated"}, {Status: "unhealthy"}})
	if status != "unhealthy" {
		t.Fatalf("expected unhealthy, got %s", status)
	}
}

func TestOverallHTTPStatus(t *testing.T) {
	if got := overallHTTPStatus("healthy"); got != http.StatusOK {
		t.Fatalf("expected 200 for healthy, got %d", got)
	}
	if got := overallHTTPStatus("simulated"); got != http.StatusOK {
		t.Fatalf("expected 200 for simulated, got %d", got)
	}
	if got := overallHTTPStatus("degraded"); got != http.StatusOK {
		t.Fatalf("expected 200 for degraded, got %d", got)
	}
	if got := overallHTTPStatus("unhealthy"); got != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unhealthy, got %d", got)
	}
}

func TestIsSimulatedTEEPlatform(t *testing.T) {
	for _, platform := range []string{"simulated", "nitro-simulated", "mock-tee"} {
		if !isSimulatedTEEPlatform(platform) {
			t.Fatalf("expected platform %q to be treated as simulated", platform)
		}
	}
	if isSimulatedTEEPlatform("aws-nitro") {
		t.Fatalf("real platform must not be treated as simulated")
	}
}

func TestSummarizeBreakers(t *testing.T) {
	closed := circuitbreaker.Snapshot{Name: "closed", State: circuitbreaker.Closed}
	half := circuitbreaker.Snapshot{Name: "half", State: circuitbreaker.HalfOpen}
	open := circuitbreaker.Snapshot{Name: "open", State: circuitbreaker.Open}

	_, healthy := summarizeBreakers([]circuitbreaker.Snapshot{closed})
	if !healthy {
		t.Fatalf("expected healthy with closed breaker")
	}

	_, healthy = summarizeBreakers([]circuitbreaker.Snapshot{half})
	if healthy {
		t.Fatalf("expected unhealthy with half-open breaker")
	}

	_, healthy = summarizeBreakers([]circuitbreaker.Snapshot{open})
	if healthy {
		t.Fatalf("expected unhealthy with open breaker")
	}
}
