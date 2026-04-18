package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).MetricsHandler()
	req := httptest.NewRequest(http.MethodPost, "/metrics/aethelred", nil)
	req.RemoteAddr = "127.0.0.1:26657"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestMetricsHandler_RejectsNonLoopbackWithoutToken(t *testing.T) {
	t.Setenv(metricsAuthTokenEnv, "")

	handler := (&AethelredApp{}).MetricsHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics/aethelred", nil)
	req.RemoteAddr = "203.0.113.10:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMetricsHandler_AllowsBearerTokenOffLoopback(t *testing.T) {
	t.Setenv(metricsAuthTokenEnv, "metrics-token")

	handler := (&AethelredApp{}).MetricsHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics/aethelred", nil)
	req.RemoteAddr = "203.0.113.10:8443"
	req.Header.Set("Authorization", "Bearer metrics-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "aethelred_build_info") {
		t.Fatalf("expected Prometheus build metric, got body=%s", rec.Body.String())
	}
}

func TestMetricsHandler_RejectsForwardedLoopbackWithoutToken(t *testing.T) {
	t.Setenv(metricsAuthTokenEnv, "")

	handler := (&AethelredApp{}).MetricsHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics/aethelred", nil)
	req.RemoteAddr = "127.0.0.1:26657"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMetricsHandler_AllowsBearerTokenOnForwardedLoopback(t *testing.T) {
	t.Setenv(metricsAuthTokenEnv, "metrics-token")

	handler := (&AethelredApp{}).MetricsHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics/aethelred", nil)
	req.RemoteAddr = "127.0.0.1:26657"
	req.Header.Set("Forwarded", "for=203.0.113.10;proto=https")
	req.Header.Set("Authorization", "Bearer metrics-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMetricsHandler_RejectsInvalidBearerToken(t *testing.T) {
	t.Setenv(metricsAuthTokenEnv, "expected-token")

	handler := (&AethelredApp{}).MetricsHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics/aethelred", nil)
	req.RemoteAddr = "203.0.113.10:8443"
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMetricsHandler_NilApp(t *testing.T) {
	handler := (&AethelredMetricsExporter{app: nil})
	req := httptest.NewRequest(http.MethodGet, "/metrics/aethelred", nil)
	req.RemoteAddr = "127.0.0.1:26657"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "aethelred_metrics_error 1") {
		t.Fatalf("expected error metric in body, got %s", rec.Body.String())
	}
}
