package dcap

import (
	"context"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
)

func newSecurityTestVerifier(t *testing.T) *DCAPVerifier {
	t.Helper()

	verifier, err := NewDCAPVerifier(DCAPConfig{
		PCCSEndpoint:     "https://localhost:8081/sgx/certification/v4",
		RequestTimeout:   time.Second,
		MaxRetries:       1,
		CacheEnabled:     false,
		AllowOutOfDate:   false,
		AllowSWHardening: true,
		MinISVSVN:        1,
	}, log.NewNopLogger())
	if err != nil {
		t.Fatalf("NewDCAPVerifier() error = %v", err)
	}

	return verifier
}

func TestHTTPGetRejectsBlockedCollateralEndpoint(t *testing.T) {
	verifier := newSecurityTestVerifier(t)

	_, err := verifier.httpGet(context.Background(), "https://169.254.169.254/sgx/certification/v4/tcb")
	if err == nil {
		t.Fatal("expected blocked collateral endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid collateral endpoint") {
		t.Fatalf("expected invalid collateral endpoint error, got %v", err)
	}
	if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "internal IP") {
		t.Fatalf("expected blocked-host detail in error, got %v", err)
	}
}

func TestFetchCRLFromIntelRejectsBlockedDistributionPoint(t *testing.T) {
	verifier := newSecurityTestVerifier(t)

	_, err := verifier.fetchCRLFromIntel("https://169.254.169.254/rootca.crl")
	if err == nil {
		t.Fatal("expected blocked CRL endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid CRL endpoint") {
		t.Fatalf("expected invalid CRL endpoint error, got %v", err)
	}
	if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "internal IP") {
		t.Fatalf("expected blocked-host detail in error, got %v", err)
	}
}
