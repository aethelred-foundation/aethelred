package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	audithttp "github.com/aethelred/aethelred/pkg/audit"
	auditexport "github.com/aethelred/aethelred/pkg/audit/export"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestDeriveAPIBaseURLFromNodeURI(t *testing.T) {
	tests := []struct {
		name    string
		nodeURI string
		want    string
	}{
		{name: "tcp default rpc port", nodeURI: "tcp://127.0.0.1:26657", want: "http://127.0.0.1:1317"},
		{name: "http keeps host", nodeURI: "http://example.com:26657", want: "http://example.com:1317"},
		{name: "https keeps scheme", nodeURI: "https://example.com:443", want: "https://example.com:443"},
		{name: "wss becomes https", nodeURI: "wss://example.com:26657", want: "https://example.com:1317"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveAPIBaseURLFromNodeURI(tc.nodeURI); got != tc.want {
				t.Fatalf("deriveAPIBaseURLFromNodeURI(%q) = %q, want %q", tc.nodeURI, got, tc.want)
			}
		})
	}
}

func TestFetchPouwModuleStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/module-status" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		payload := pouwkeeper.QueryModuleStatusResponse{
			JobCount:                          3,
			PendingJobCount:                   1,
			CurrentEpoch:                      7,
			TotalUWU:                          99,
			EnterpriseTrustRegistryConfigured: true,
			EnterpriseTrustRegistryVersion:    "2026.04.14",
			EnterpriseTrustRegistrySource:     "pouw_governance",
			EnterpriseTrustPolicySignerCount:  2,
			EnterpriseTrustActiveSignerCount:  1,
			BlockHeight:                       42,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	status, err := fetchPouwModuleStatus(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("fetchPouwModuleStatus returned error: %v", err)
	}
	if status.CurrentEpoch != 7 || status.TotalUWU != 99 {
		t.Fatalf("unexpected module status: %+v", status)
	}
	if !status.EnterpriseTrustRegistryConfigured || status.EnterpriseTrustRegistrySource != "pouw_governance" {
		t.Fatalf("unexpected trust status: %+v", status)
	}
}

func TestFetchPouwModuleStatus_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"pouw module status is unavailable"}`))
	}))
	defer server.Close()

	_, err := fetchPouwModuleStatus(context.Background(), server.Client(), server.URL)
	if err == nil {
		t.Fatal("expected error from fetchPouwModuleStatus")
	}
	if got := err.Error(); got != "query pouw module status: pouw module status is unavailable" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestFetchPouwTrustRegistry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/trust-registry" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		payload := pouwTrustRegistryResponse{
			Configured: true,
			Status: &pouwkeeper.EnterpriseAuditTrustRegistryStatus{
				Configured:              true,
				Version:                 "2026.04.14",
				Source:                  "pouw_governance",
				PolicySignerCount:       2,
				ActivePolicySignerCount: 1,
				AllowedSponsorCount:     1,
				ActiveSponsorCount:      1,
			},
			Registry: &pouwkeeper.EnterpriseAuditTrustRegistry{
				Version:              "2026.04.14",
				Source:               "pouw_governance",
				RequiredAction:       "audit.control_ledger.write",
				RequiredJurisdiction: "UAE",
				PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
					DID:          "did:aethelred:policy-gateway-1",
					PublicKeyHex: "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	resp, err := fetchPouwTrustRegistry(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("fetchPouwTrustRegistry returned error: %v", err)
	}
	if !resp.Configured || resp.Status == nil || resp.Registry == nil {
		t.Fatalf("unexpected trust registry response: %+v", resp)
	}
	if resp.Status.Source != "pouw_governance" || len(resp.Registry.PolicySigners) != 1 {
		t.Fatalf("unexpected trust registry payload: %+v", resp)
	}
}

func TestFetchPouwTrustRegistry_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"pouw trust registry is unavailable"}`))
	}))
	defer server.Close()

	_, err := fetchPouwTrustRegistry(context.Background(), server.Client(), server.URL)
	if err == nil {
		t.Fatal("expected error from fetchPouwTrustRegistry")
	}
	if got := err.Error(); got != "query pouw trust registry: pouw trust registry is unavailable" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestFetchPouwTrustRegistryHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/trust-registry/history" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("actor"); got != "gov-authority" {
			t.Fatalf("expected actor filter, got %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Fatalf("expected limit filter, got %q", got)
		}
		payload := pouwTrustRegistryHistoryResponse{
			Records: []pouwkeeper.AuditRecord{
				{Sequence: 1, Action: "enterprise_audit_trust_registry_updated", Actor: "gov-authority"},
				{Sequence: 2, Action: "enterprise_audit_trust_registry_cleared", Actor: "gov-authority"},
			},
			Total: 2,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	params := url.Values{
		"actor": []string{"gov-authority"},
		"limit": []string{"5"},
	}
	resp, err := fetchPouwTrustRegistryHistory(context.Background(), server.Client(), server.URL, params)
	if err != nil {
		t.Fatalf("fetchPouwTrustRegistryHistory returned error: %v", err)
	}
	if resp.Total != 2 || len(resp.Records) != 2 {
		t.Fatalf("unexpected trust registry history response: %+v", resp)
	}
}

func TestFetchPouwTrustRegistryHistory_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"pouw trust registry history is unavailable"}`))
	}))
	defer server.Close()

	_, err := fetchPouwTrustRegistryHistory(context.Background(), server.Client(), server.URL, nil)
	if err == nil {
		t.Fatal("expected error from fetchPouwTrustRegistryHistory")
	}
	if got := err.Error(); got != "query pouw trust registry history: pouw trust registry history is unavailable" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestFetchPouwTrustComplianceExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/trust-registry/compliance-export" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("format"); got != "csv" {
			t.Fatalf("expected csv format query, got %q", got)
		}
		if got := r.URL.Query().Get("actor"); got != "gov-authority" {
			t.Fatalf("expected actor filter, got %q", got)
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("row_type,generated_at\nsummary,2026-04-14T14:00:00Z\n"))
	}))
	defer server.Close()

	params := url.Values{
		"format": []string{"csv"},
		"actor":  []string{"gov-authority"},
	}
	payload, err := fetchPouwTrustComplianceExport(context.Background(), server.Client(), server.URL, params)
	if err != nil {
		t.Fatalf("fetchPouwTrustComplianceExport returned error: %v", err)
	}
	if got := string(payload); got != "row_type,generated_at\nsummary,2026-04-14T14:00:00Z\n" {
		t.Fatalf("unexpected compliance export payload %q", got)
	}
}

func TestNormalizePouwExportFormat(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "default json", value: "", want: "json"},
		{name: "csv", value: "csv", want: "csv"},
		{name: "oscal", value: "oscal", want: "oscal"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := CmdQueryPoUWTrustComplianceExport()
			if err := cmd.Flags().Set(flagFormat, tc.value); err != nil {
				t.Fatalf("set format flag: %v", err)
			}
			got, err := normalizePouwExportFormat(cmd)
			if err != nil {
				t.Fatalf("normalizePouwExportFormat returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("normalizePouwExportFormat(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestBuildPouwTrustComplianceQueryParams(t *testing.T) {
	cmd := CmdQueryPoUWTrustComplianceExport()
	if err := cmd.Flags().Set(flagFormat, "oscal"); err != nil {
		t.Fatalf("set format flag: %v", err)
	}
	if err := cmd.Flags().Set(flagActor, "gov-authority"); err != nil {
		t.Fatalf("set actor flag: %v", err)
	}
	if err := cmd.Flags().Set(flagPackage, "true"); err != nil {
		t.Fatalf("set package flag: %v", err)
	}

	params, err := buildPouwTrustComplianceQueryParams(cmd)
	if err != nil {
		t.Fatalf("buildPouwTrustComplianceQueryParams returned error: %v", err)
	}
	if got := params.Get("format"); got != "oscal" {
		t.Fatalf("expected oscal format, got %q", got)
	}
	if got := params.Get("actor"); got != "gov-authority" {
		t.Fatalf("expected actor filter, got %q", got)
	}
	if got := params.Get("package"); got != "true" {
		t.Fatalf("expected package query flag, got %q", got)
	}
}

func TestBuildPouwTrustComplianceAnchorQueryParams(t *testing.T) {
	cmd := CmdQueryPoUWTrustComplianceExportAnchors()
	if err := cmd.Flags().Set(flagFormat, "oscal"); err != nil {
		t.Fatalf("set format flag: %v", err)
	}
	if err := cmd.Flags().Set(flagSigner, "validator:abc123"); err != nil {
		t.Fatalf("set signer flag: %v", err)
	}
	if err := cmd.Flags().Set(flagSigned, "true"); err != nil {
		t.Fatalf("set signed flag: %v", err)
	}
	if err := cmd.Flags().Set(flagPackageHash, "pkg-anchor-1"); err != nil {
		t.Fatalf("set package hash flag: %v", err)
	}

	params, err := buildPouwTrustComplianceAnchorQueryParams(cmd)
	if err != nil {
		t.Fatalf("buildPouwTrustComplianceAnchorQueryParams returned error: %v", err)
	}
	if got := params.Get("format"); got != "oscal" {
		t.Fatalf("expected oscal format, got %q", got)
	}
	if got := params.Get("signer"); got != "validator:abc123" {
		t.Fatalf("expected signer filter, got %q", got)
	}
	if got := params.Get("signed"); got != "true" {
		t.Fatalf("expected signed filter, got %q", got)
	}
	if got := params.Get("package_hash"); got != "pkg-anchor-1" {
		t.Fatalf("expected package hash filter, got %q", got)
	}
}

func TestFetchPouwTrustComplianceExportAnchors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/trust-registry/compliance-export/anchors" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("package_hash"); got != "pkg-anchor-1" {
			t.Fatalf("expected package_hash filter, got %q", got)
		}
		payload := auditexport.PouwTrustComplianceExportAnchorsResponse{
			Anchors: []auditexport.PouwTrustComplianceExportAnchorRecord{{
				Record:  pouwkeeper.AuditRecord{Sequence: 1, Action: "trust_compliance_export_anchored"},
				Summary: &auditexport.PouwTrustComplianceExportAnchorSummary{PackageHash: "pkg-anchor-1", Format: "oscal", Signed: true},
			}},
			Total: 1,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	resp, err := fetchPouwTrustComplianceExportAnchors(context.Background(), server.Client(), server.URL, url.Values{
		"package_hash": []string{"pkg-anchor-1"},
	})
	if err != nil {
		t.Fatalf("fetchPouwTrustComplianceExportAnchors returned error: %v", err)
	}
	if resp.Total != 1 || len(resp.Anchors) != 1 {
		t.Fatalf("unexpected anchored export response: %+v", resp)
	}
	if resp.Anchors[0].Summary == nil || resp.Anchors[0].Summary.PackageHash != "pkg-anchor-1" {
		t.Fatalf("unexpected anchor summary %+v", resp.Anchors[0])
	}
}

func TestBuildPouwControlLedgerPackageAnchorQueryParams(t *testing.T) {
	cmd := CmdQueryPoUWControlLedgerPackageAnchors()
	if err := cmd.Flags().Set(flagLedgerID, "runtime-ledger-1"); err != nil {
		t.Fatalf("set ledger flag: %v", err)
	}
	if err := cmd.Flags().Set(flagSigner, "validator:abc123"); err != nil {
		t.Fatalf("set signer flag: %v", err)
	}
	if err := cmd.Flags().Set(flagSigned, "true"); err != nil {
		t.Fatalf("set signed flag: %v", err)
	}
	if err := cmd.Flags().Set(flagPackageHash, "ledger-pkg-1"); err != nil {
		t.Fatalf("set package hash flag: %v", err)
	}

	params, err := buildPouwControlLedgerPackageAnchorQueryParams(cmd)
	if err != nil {
		t.Fatalf("buildPouwControlLedgerPackageAnchorQueryParams returned error: %v", err)
	}
	if got := params.Get("ledger_id"); got != "runtime-ledger-1" {
		t.Fatalf("expected ledger_id filter, got %q", got)
	}
	if got := params.Get("signer"); got != "validator:abc123" {
		t.Fatalf("expected signer filter, got %q", got)
	}
	if got := params.Get("signed"); got != "true" {
		t.Fatalf("expected signed filter, got %q", got)
	}
	if got := params.Get("package_hash"); got != "ledger-pkg-1" {
		t.Fatalf("expected package hash filter, got %q", got)
	}
}

func TestFetchPouwControlLedgerPackageAnchors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/control-ledger-packages/anchors" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("ledger_id"); got != "runtime-ledger-1" {
			t.Fatalf("expected ledger_id filter, got %q", got)
		}
		payload := audithttp.GetControlLedgerPackageAnchorsResponse{
			Anchors: []audithttp.PortableControlLedgerPackageAnchorRecord{{
				Record:  pouwkeeper.AuditRecord{Sequence: 1, Action: "control_ledger_package_anchored"},
				Summary: &audithttp.PortableControlLedgerPackageAnchorSummary{PackageHash: "ledger-pkg-1", LedgerID: "runtime-ledger-1", Signed: true},
			}},
			Total: 1,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	resp, err := fetchPouwControlLedgerPackageAnchors(context.Background(), server.Client(), server.URL, url.Values{
		"ledger_id": []string{"runtime-ledger-1"},
	})
	if err != nil {
		t.Fatalf("fetchPouwControlLedgerPackageAnchors returned error: %v", err)
	}
	if resp.Total != 1 || len(resp.Anchors) != 1 {
		t.Fatalf("unexpected anchored package response: %+v", resp)
	}
	if resp.Anchors[0].Summary == nil || resp.Anchors[0].Summary.LedgerID != "runtime-ledger-1" {
		t.Fatalf("unexpected anchor summary %+v", resp.Anchors[0])
	}
}

func TestVerifyPortableControlLedgerPackageRemote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/control-ledger-packages/verify" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		payload := audithttp.VerifyPortableControlLedgerPackageResponse{
			Valid:            true,
			LedgerID:         "runtime-ledger-1",
			PackageHash:      "ledger-pkg-1",
			AnchorMatchCount: 1,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	resp, err := verifyPortableControlLedgerPackageRemote(context.Background(), server.Client(), server.URL, []byte(`{"package_hash":"ledger-pkg-1"}`))
	if err != nil {
		t.Fatalf("verifyPortableControlLedgerPackageRemote returned error: %v", err)
	}
	if !resp.Valid || resp.PackageHash != "ledger-pkg-1" || resp.AnchorMatchCount != 1 {
		t.Fatalf("unexpected verification response %+v", resp)
	}
}

func TestVerifyPouwTrustCompliancePackageRemote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pouw/trust-registry/compliance-export/verify" {
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		payload := auditexport.PouwTrustCompliancePackageVerificationResponse{
			Verification: &auditexport.PouwTrustCompliancePackageVerification{
				Valid: true,
				Summary: &auditexport.PouwTrustCompliancePackageSummary{
					PackageHash: "pkg-anchor-1",
					Format:      "json",
				},
			},
			AnchorMatchCount: 1,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode payload: %v", err)
		}
	}))
	defer server.Close()

	resp, err := verifyPouwTrustCompliancePackageRemote(context.Background(), server.Client(), server.URL, []byte(`{"manifest":{"package_hash":"pkg-anchor-1"}}`))
	if err != nil {
		t.Fatalf("verifyPouwTrustCompliancePackageRemote returned error: %v", err)
	}
	if resp.Verification == nil || !resp.Verification.Valid || resp.AnchorMatchCount != 1 {
		t.Fatalf("unexpected verification response %+v", resp)
	}
}

func TestReadPouwTrustCompliancePackageInput_File(t *testing.T) {
	path := t.TempDir() + "/package.json"
	if err := os.WriteFile(path, []byte(`{"manifest":{"package_hash":"pkg-anchor-1"}}`), 0o600); err != nil {
		t.Fatalf("write package file: %v", err)
	}

	payload, err := readPouwTrustCompliancePackageInput(path)
	if err != nil {
		t.Fatalf("readPouwTrustCompliancePackageInput returned error: %v", err)
	}
	if string(payload) != `{"manifest":{"package_hash":"pkg-anchor-1"}}` {
		t.Fatalf("unexpected package payload %q", string(payload))
	}
}

func TestFetchPouwTrustComplianceExport_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported export format"}`))
	}))
	defer server.Close()

	_, err := fetchPouwTrustComplianceExport(context.Background(), server.Client(), server.URL, url.Values{"format": []string{"bad"}})
	if err == nil {
		t.Fatal("expected error from fetchPouwTrustComplianceExport")
	}
	if got := err.Error(); got != "query pouw trust compliance export: unsupported export format" {
		t.Fatalf("unexpected error %q", got)
	}
}
