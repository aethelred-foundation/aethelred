package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/testutil/sims"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	financeintegration "github.com/aethelred/aethelred/pkg/integrations/finance"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

func TestFinanceTreasuryReleaseInitiateHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).FinanceTreasuryReleaseInitiateHandler()
	req := httptest.NewRequest(http.MethodGet, financeTreasuryReleaseCollectionRoute, nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestNewApp_InitializesFinanceWorkflow(t *testing.T) {
	homeDir := t.TempDir()
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	})

	if app.financeTreasuryReleaseWorkflow == nil {
		t.Fatal("expected finance treasury release workflow to be initialized")
	}

	wantDir := filepath.Join(homeDir, "data", "finance", "control-ledgers")
	if app.financeControlLedgerDir != wantDir {
		t.Fatalf("expected finance control ledger dir %q, got %q", wantDir, app.financeControlLedgerDir)
	}
}

func TestNewApp_InitializesFinanceWriteAuth_DisabledByDefault(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	initReq := mustMarshalFinanceInitiateRequest(t, identity, financeintegration.TreasuryOperation{
		Type:         financeintegration.OpPayment,
		Amount:       1000,
		Currency:     "USD",
		Initiator:    "treasury.bot",
		Description:  "Default finance auth posture",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "UAE",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	}
}

func TestFinanceTreasuryReleaseInitiateHandler_RejectsMissingBearerToken(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                "simulated",
		"aethelred.finance.api.write_token": "finance-secret",
		flags.FlagHome:                      t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	initReq := mustMarshalFinanceInitiateRequest(t, identity, financeintegration.TreasuryOperation{
		Type:         financeintegration.OpPayment,
		Amount:       1000,
		Currency:     "USD",
		Initiator:    "treasury.bot",
		Description:  "Bearer token required",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "UAE",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestFinanceTreasuryReleaseHandlers_PendingApproveGetFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                "simulated",
		"aethelred.finance.api.write_token": "finance-secret",
		flags.FlagHome:                      t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	identity := mustFinanceAgentIdentity(t)
	initReq := mustMarshalFinanceInitiateRequest(t, identity, financeintegration.TreasuryOperation{
		Type:         financeintegration.OpTransfer,
		Amount:       75000,
		Currency:     "USD",
		Initiator:    "controller@bank.example",
		Description:  "Vendor treasury release",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "UAE",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	req.Header.Set("Authorization", "Bearer finance-secret")
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusAccepted, rec.Code, rec.Body.String())
	}

	var initResp financeTreasuryReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &initResp); err != nil {
		t.Fatalf("unmarshal initiate response: %v", err)
	}
	if initResp.Result == nil || initResp.Result.WorkflowID == "" {
		t.Fatal("expected initiated workflow result with ID")
	}
	if initResp.Result.Status != financeintegration.ReleaseStatusPendingApproval {
		t.Fatalf("expected pending approval result, got %s", initResp.Result.Status)
	}

	getReq := httptest.NewRequest(http.MethodGet, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID, nil)
	getRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseGetHandler().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, getRec.Code)
	}

	approveReqBody, err := json.Marshal(financeTreasuryReleaseApproveRequest{
		Approver: "treasurer@bank.example",
		Comment:  "treasury review complete",
	})
	if err != nil {
		t.Fatalf("marshal first approval request: %v", err)
	}
	approveReq := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/approve", bytes.NewReader(approveReqBody))
	approveReq.Header.Set("Authorization", "Bearer finance-secret")
	approveRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseApproveHandler().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, approveRec.Code)
	}

	var approveResp financeTreasuryReleaseResponse
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approveResp); err != nil {
		t.Fatalf("unmarshal first approval response: %v", err)
	}
	if approveResp.Result == nil || approveResp.Result.Status != financeintegration.ReleaseStatusPendingApproval {
		t.Fatalf("expected still-pending workflow after first approval, got %+v", approveResp.Result)
	}

	finalApproveReqBody, err := json.Marshal(financeTreasuryReleaseApproveRequest{
		Approver: "cfo@bank.example",
		Comment:  "final approval",
	})
	if err != nil {
		t.Fatalf("marshal second approval request: %v", err)
	}
	finalApproveReq := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/approve", bytes.NewReader(finalApproveReqBody))
	finalApproveReq.Header.Set("Authorization", "Bearer finance-secret")
	finalApproveRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseApproveHandler().ServeHTTP(finalApproveRec, finalApproveReq)
	if finalApproveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, finalApproveRec.Code, finalApproveRec.Body.String())
	}

	var finalResp financeTreasuryReleaseResponse
	if err := json.Unmarshal(finalApproveRec.Body.Bytes(), &finalResp); err != nil {
		t.Fatalf("unmarshal final approval response: %v", err)
	}
	if finalResp.Result == nil || finalResp.Result.Status != financeintegration.ReleaseStatusCompleted {
		t.Fatalf("expected completed result, got %+v", finalResp.Result)
	}
	if finalResp.Result.Settlement == nil || finalResp.Result.SettlementReceipt == nil {
		t.Fatal("expected settlement artifacts after final approval")
	}
	if finalResp.Result.PortablePackage == nil || finalResp.Result.PortablePackage.Signature == nil {
		t.Fatal("expected signed portable package after final approval")
	}
	if finalResp.Result.PortablePackage.AuditAnchor == nil {
		t.Fatal("expected anchored portable package after final approval")
	}

	settlementReq := httptest.NewRequest(http.MethodGet, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/settlement", nil)
	settlementRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseGetHandler().ServeHTTP(settlementRec, settlementReq)
	if settlementRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, settlementRec.Code, settlementRec.Body.String())
	}

	var settlementResp financeTreasuryReleaseSettlementResponse
	if err := json.Unmarshal(settlementRec.Body.Bytes(), &settlementResp); err != nil {
		t.Fatalf("unmarshal settlement response: %v", err)
	}
	if !settlementResp.Ready || settlementResp.Settlement == nil || settlementResp.SettlementReceipt == nil {
		t.Fatalf("expected ready settlement projection, got %+v", settlementResp)
	}
	if settlementResp.PortablePackageHash == "" || settlementResp.ExecutionSealID == "" {
		t.Fatalf("expected package hash and execution seal ID, got %+v", settlementResp)
	}

	artifactReq := httptest.NewRequest(http.MethodGet, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/settlement/artifacts", nil)
	artifactRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseGetHandler().ServeHTTP(artifactRec, artifactReq)
	if artifactRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, artifactRec.Code, artifactRec.Body.String())
	}

	var artifactResp financeTreasuryReleaseSettlementArtifactsResponse
	if err := json.Unmarshal(artifactRec.Body.Bytes(), &artifactResp); err != nil {
		t.Fatalf("unmarshal settlement artifacts response: %v", err)
	}
	if artifactResp.ControlLedgerID == "" || artifactResp.ControlLedgerContentHash == "" {
		t.Fatalf("expected control-ledger identifiers, got %+v", artifactResp)
	}
	if !artifactResp.PortablePackageSigned || !artifactResp.PortablePackageAnchored {
		t.Fatalf("expected signed and anchored settlement artifacts, got %+v", artifactResp)
	}
}

func TestFinanceTreasurySettlementQuoteHandler_ReturnsEligibleQuote(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                 "simulated",
		"aethelred.finance.api.write_token":                  "finance-secret",
		"aethelred.finance.settlement.provider_id":           "partner-bank-1",
		"aethelred.finance.settlement.corridor_id":           "uae-usd-vendors",
		"aethelred.finance.settlement.allowed_jurisdictions": "UAE",
		"aethelred.finance.settlement.allowed_currencies":    "USD",
		"aethelred.finance.settlement.required_reason_codes": "vendor_payment",
		flags.FlagHome: t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	body, err := json.Marshal(financeTreasuryReleaseInitiateRequest{
		Identity:     mustJSONRawMessage(t, identity),
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		ReasonCode:   "vendor_payment",
		Operation: &financeintegration.TreasuryOperation{
			Type:         financeintegration.OpPayment,
			Amount:       4200,
			Currency:     "USD",
			Initiator:    "treasury.bot",
			Description:  "Settlement quote",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: financeintegration.ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err != nil {
		t.Fatalf("marshal quote request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, financeTreasurySettlementQuoteRoute, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer finance-secret")
	rec := httptest.NewRecorder()
	app.FinanceTreasurySettlementQuoteHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp financeTreasurySettlementQuoteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal quote response: %v", err)
	}
	if resp.Quote == nil || !resp.Quote.Eligible {
		t.Fatalf("expected eligible quote, got %+v", resp.Quote)
	}
	if resp.Quote.ProviderID != "partner-bank-1" || resp.Quote.CorridorID != "uae-usd-vendors" {
		t.Fatalf("expected configured provider/corridor, got %+v", resp.Quote)
	}
}

func TestFinanceTreasurySettlementQuoteHandler_ReturnsIneligibleQuote(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                 "simulated",
		"aethelred.finance.api.write_token":                  "finance-secret",
		"aethelred.finance.settlement.provider_status":       "disabled",
		"aethelred.finance.settlement.allowed_jurisdictions": "UAE",
		"aethelred.finance.settlement.allowed_currencies":    "USD",
		"aethelred.finance.settlement.required_reason_codes": "vendor_payment",
		"aethelred.finance.settlement.max_amount":            "1000",
		flags.FlagHome: t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	body, err := json.Marshal(financeTreasuryReleaseInitiateRequest{
		Identity:     mustJSONRawMessage(t, identity),
		Resource:     "acct:treasury-main",
		Jurisdiction: "UK",
		ReasonCode:   "unexpected_reason",
		Operation: &financeintegration.TreasuryOperation{
			Type:         financeintegration.OpPayment,
			Amount:       4200,
			Currency:     "EUR",
			Initiator:    "treasury.bot",
			Description:  "Ineligible settlement quote",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: financeintegration.ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UK",
		},
	})
	if err != nil {
		t.Fatalf("marshal quote request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, financeTreasurySettlementQuoteRoute, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer finance-secret")
	rec := httptest.NewRecorder()
	app.FinanceTreasurySettlementQuoteHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp financeTreasurySettlementQuoteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal quote response: %v", err)
	}
	if resp.Quote == nil || resp.Quote.Eligible {
		t.Fatalf("expected ineligible quote, got %+v", resp.Quote)
	}
	if len(resp.Quote.Violations) < 3 {
		t.Fatalf("expected multiple violations, got %+v", resp.Quote)
	}
}

func TestFinanceTreasuryReleaseApproveHandler_RejectsMissingBearerToken(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                "simulated",
		"aethelred.finance.api.write_token": "finance-secret",
		flags.FlagHome:                      t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	initReq := mustMarshalFinanceInitiateRequest(t, identity, financeintegration.TreasuryOperation{
		Type:         financeintegration.OpTransfer,
		Amount:       75000,
		Currency:     "USD",
		Initiator:    "controller@bank.example",
		Description:  "Approval auth guard",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "UAE",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	req.Header.Set("Authorization", "Bearer finance-secret")
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusAccepted, rec.Code, rec.Body.String())
	}

	var initResp financeTreasuryReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &initResp); err != nil {
		t.Fatalf("unmarshal initiate response: %v", err)
	}

	approveReqBody, err := json.Marshal(financeTreasuryReleaseApproveRequest{
		Approver: "treasurer@bank.example",
		Comment:  "token intentionally missing",
	})
	if err != nil {
		t.Fatalf("marshal approval request: %v", err)
	}
	approveReq := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/approve", bytes.NewReader(approveReqBody))
	approveRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseApproveHandler().ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusUnauthorized, approveRec.Code, approveRec.Body.String())
	}
}

func TestFinanceTreasuryReleaseHandlers_SanctionsReject(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                "simulated",
		"aethelred.finance.api.write_token": "finance-secret",
		flags.FlagHome:                      t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	initReq := mustMarshalFinanceInitiateRequest(t, identity, financeintegration.TreasuryOperation{
		Type:         financeintegration.OpPayment,
		Amount:       6000,
		Currency:     "USD",
		Initiator:    "treasury.bot",
		Description:  "Blocked supplier payment",
		Counterparty: "Blocked Entity",
	}, financeintegration.ScreeningEntity{
		Name:       "Blocked Entity",
		EntityType: "organization",
		Country:    "UAE",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	req.Header.Set("Authorization", "Bearer finance-secret")
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusForbidden, rec.Code, rec.Body.String())
	}

	var resp financeTreasuryReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal rejection response: %v", err)
	}
	if resp.Result == nil || resp.Result.Status != financeintegration.ReleaseStatusRejected {
		t.Fatalf("expected rejected workflow result, got %+v", resp.Result)
	}
	if resp.Result.PortablePackage != nil {
		t.Fatal("did not expect final portable package for rejected release")
	}
}

func TestFinanceTreasuryReleaseHandlers_AcceptsEnterprisePolicyReceipt(t *testing.T) {
	signerKey := mustFinancePolicySignerKey(t)
	signerDID := "did:aethelred:finance-policy-gateway-1"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                     "simulated",
		"aethelred.finance.api.enterprise_policy_signers":        signerDID + "=" + mustFinanceCompressedPublicKeyHex(t, &signerKey.PublicKey),
		"aethelred.finance.api.enterprise_allowed_sponsors":      "did:aethelred:bank-parent",
		"aethelred.finance.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	resource := financeTreasuryReleaseAuthDefaultResource
	initReq := mustMarshalFinanceEnterpriseInitiateRequest(t, identity, mustFinanceSignedPolicyReceipt(t, signerKey, signerDID, identity, financeTreasuryReleaseAuthRequestAction, resource, "UAE"), financeintegration.TreasuryOperation{
		Type:         financeintegration.OpPayment,
		Amount:       5000,
		Currency:     "USD",
		Initiator:    "treasury.bot",
		Description:  "Enterprise authorized release",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "UAE",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, rec.Code, rec.Body.String())
	}
}

func TestFinanceTreasuryReleaseHandlers_RejectsWrongEnterpriseJurisdiction(t *testing.T) {
	signerKey := mustFinancePolicySignerKey(t)
	signerDID := "did:aethelred:finance-policy-gateway-1"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                     "simulated",
		"aethelred.finance.api.enterprise_policy_signers":        signerDID + "=" + mustFinanceCompressedPublicKeyHex(t, &signerKey.PublicKey),
		"aethelred.finance.api.enterprise_allowed_sponsors":      "did:aethelred:bank-parent",
		"aethelred.finance.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})

	identity := mustFinanceAgentIdentity(t)
	resource := financeTreasuryReleaseAuthDefaultResource
	initReq := mustMarshalFinanceEnterpriseInitiateRequest(t, identity, mustFinanceSignedPolicyReceipt(t, signerKey, signerDID, identity, financeTreasuryReleaseAuthRequestAction, resource, "US"), financeintegration.TreasuryOperation{
		Type:         financeintegration.OpPayment,
		Amount:       5000,
		Currency:     "USD",
		Initiator:    "treasury.bot",
		Description:  "Wrong jurisdiction",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "US",
	})

	req := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	rec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestFinanceTreasuryReleaseHandlers_EnterpriseApprovalEvidencePersists(t *testing.T) {
	signerKey := mustFinancePolicySignerKey(t)
	signerDID := "did:aethelred:finance-policy-gateway-1"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                     "simulated",
		"aethelred.finance.api.enterprise_policy_signers":        signerDID + "=" + mustFinanceCompressedPublicKeyHex(t, &signerKey.PublicKey),
		"aethelred.finance.api.enterprise_allowed_sponsors":      "did:aethelred:bank-parent",
		"aethelred.finance.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})

	initiatorIdentity := mustFinanceAgentIdentity(t)
	initReq := mustMarshalFinanceEnterpriseInitiateRequest(t, initiatorIdentity, mustFinanceSignedPolicyReceipt(t, signerKey, signerDID, initiatorIdentity, financeTreasuryReleaseAuthRequestAction, financeTreasuryReleaseAuthDefaultResource, "UAE"), financeintegration.TreasuryOperation{
		Type:         financeintegration.OpTransfer,
		Amount:       75000,
		Currency:     "USD",
		Initiator:    "controller@bank.example",
		Description:  "Enterprise approval evidence",
		Counterparty: "Trusted Vendor",
	}, financeintegration.ScreeningEntity{
		Name:       "Trusted Vendor",
		EntityType: "organization",
		Country:    "UAE",
	})

	initReqHTTP := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseCollectionRoute, bytes.NewReader(initReq))
	initRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseInitiateHandler().ServeHTTP(initRec, initReqHTTP)
	if initRec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusAccepted, initRec.Code, initRec.Body.String())
	}

	var initResp financeTreasuryReleaseResponse
	if err := json.Unmarshal(initRec.Body.Bytes(), &initResp); err != nil {
		t.Fatalf("unmarshal initiate response: %v", err)
	}
	if initResp.Result == nil || initResp.Result.WorkflowID == "" {
		t.Fatal("expected initiated workflow result")
	}

	approverOne := mustFinanceAgentIdentity(t)
	approveReqOne := mustMarshalFinanceEnterpriseApproveRequest(t, approverOne, mustFinanceSignedPolicyReceipt(t, signerKey, signerDID, approverOne, financeTreasuryReleaseAuthApproveAction, "treasury-release:"+initResp.Result.WorkflowID, "UAE"), "")
	approveReqHTTP := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/approve", bytes.NewReader(approveReqOne))
	approveRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseApproveHandler().ServeHTTP(approveRec, approveReqHTTP)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, approveRec.Code, approveRec.Body.String())
	}

	approverTwo := mustFinanceAgentIdentity(t)
	approveReqTwo := mustMarshalFinanceEnterpriseApproveRequest(t, approverTwo, mustFinanceSignedPolicyReceipt(t, signerKey, signerDID, approverTwo, financeTreasuryReleaseAuthApproveAction, "treasury-release:"+initResp.Result.WorkflowID, "UAE"), "final enterprise approval")
	finalApproveReqHTTP := httptest.NewRequest(http.MethodPost, financeTreasuryReleaseItemPrefix+initResp.Result.WorkflowID+"/approve", bytes.NewReader(approveReqTwo))
	finalApproveRec := httptest.NewRecorder()
	app.FinanceTreasuryReleaseApproveHandler().ServeHTTP(finalApproveRec, finalApproveReqHTTP)
	if finalApproveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, finalApproveRec.Code, finalApproveRec.Body.String())
	}

	var finalResp financeTreasuryReleaseResponse
	if err := json.Unmarshal(finalApproveRec.Body.Bytes(), &finalResp); err != nil {
		t.Fatalf("unmarshal final approval response: %v", err)
	}
	if finalResp.Result == nil || finalResp.Result.Status != financeintegration.ReleaseStatusCompleted {
		t.Fatalf("expected completed workflow result, got %+v", finalResp.Result)
	}
	if len(finalResp.Result.ApprovalEvidence) != 2 {
		t.Fatalf("expected 2 approval evidence items, got %d", len(finalResp.Result.ApprovalEvidence))
	}
	if finalResp.Result.ControlLedger == nil {
		t.Fatal("expected control ledger")
	}
	if finalResp.Result.ControlLedger.Summary.TotalPassports != 3 {
		t.Fatalf("expected 3 passports, got %d", finalResp.Result.ControlLedger.Summary.TotalPassports)
	}
	if finalResp.Result.ControlLedger.Summary.TotalApproverAttestations != 2 {
		t.Fatalf("expected 2 approver attestations, got %d", finalResp.Result.ControlLedger.Summary.TotalApproverAttestations)
	}
	if finalResp.Result.ControlLedger.Summary.TotalValueSettlements != 1 {
		t.Fatalf("expected 1 value settlement, got %d", finalResp.Result.ControlLedger.Summary.TotalValueSettlements)
	}
	if finalResp.Result.ControlLedger.Summary.TotalPolicyReceipts != 5 {
		t.Fatalf("expected 5 policy receipts, got %d", finalResp.Result.ControlLedger.Summary.TotalPolicyReceipts)
	}
	if finalResp.Result.ControlLedger.Summary.TotalTraceLinks != 3 {
		t.Fatalf("expected 3 trace links, got %d", finalResp.Result.ControlLedger.Summary.TotalTraceLinks)
	}
}

func mustFinanceAgentIdentity(t *testing.T) *agent.AgentIdentity {
	t.Helper()

	identity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{
			{Name: "payments.release", Version: "1.0"},
			{Name: "sanctions.screen", Version: "1.0"},
		},
		agent.EnterpriseIdentityOptions{
			Issuer: "did:aethelred:issuer-bank-1",
			SponsorChain: []agent.SponsorRecord{{
				SponsorDID:        "did:aethelred:bank-parent",
				SponsorName:       "Bank Parent",
				Jurisdiction:      "UAE",
				Role:              "sponsor_of_record",
				LiabilityAccepted: true,
				SignedAt:          time.Date(2026, 4, 15, 9, 0, 0, 0, time.UTC),
			}},
			Liability: &agent.LiabilityProfile{
				HumanOwner:      "alice.chen",
				BusinessUnit:    "treasury",
				SponsorOfRecord: "did:aethelred:bank-parent",
				IncidentContact: "soc@bank.example",
				LiabilityModel:  "enterprise-sponsored",
			},
			JurisdictionTags: []string{"UAE", "UK"},
			AllowedTools:     []string{"payments.release", "sanctions.screen"},
			Metadata: map[string]string{
				"sector": "finance",
			},
		},
	)
	if err != nil {
		t.Fatalf("creating finance agent identity: %v", err)
	}
	return identity
}

func mustFinancePolicySignerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate finance policy signer key: %v", err)
	}
	return key
}

func mustFinanceCompressedPublicKeyHex(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()
	if publicKey == nil {
		t.Fatal("public key is required")
	}
	return hex.EncodeToString(elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y))
}

func mustFinanceSignedPolicyReceipt(
	t *testing.T,
	signerKey *ecdsa.PrivateKey,
	signerDID string,
	identity *agent.AgentIdentity,
	action string,
	resource string,
	jurisdiction string,
) *policy.SignedPolicyReceipt {
	t.Helper()

	if identity == nil {
		t.Fatal("identity is required")
	}
	evalReq := &policy.EvaluationRequest{
		Actor:    identity.AgentID(),
		Action:   action,
		Resource: resource,
		Context: map[string]string{
			"sector":       "finance",
			"jurisdiction": jurisdiction,
		},
		Metadata: map[string]string{
			"workflow": "treasury_release",
		},
	}
	evalResult := &policy.EvaluationResult{
		RequestID:    fmt.Sprintf("receipt-%d", time.Now().UnixNano()),
		Decision:     policy.Allow,
		MatchedRules: []string{"finance.enterprise.allow"},
		AuditTrail:   "finance-enterprise-audit-trail",
		EvaluatedAt:  time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC),
	}
	receipt, err := policy.CreateSignedPolicyReceipt(context.Background(), signerKey, signerDID, evalReq, evalResult, "")
	if err != nil {
		t.Fatalf("create signed finance policy receipt: %v", err)
	}
	return receipt
}

func mustMarshalFinanceInitiateRequest(
	t *testing.T,
	identity *agent.AgentIdentity,
	operation financeintegration.TreasuryOperation,
	beneficiary financeintegration.ScreeningEntity,
) []byte {
	t.Helper()

	body, err := json.Marshal(financeTreasuryReleaseInitiateRequest{
		Identity:     mustJSONRawMessage(t, identity),
		Operation:    &operation,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		Beneficiary:  beneficiary,
	})
	if err != nil {
		t.Fatalf("marshal finance initiate request: %v", err)
	}
	return body
}

func mustMarshalFinanceEnterpriseInitiateRequest(
	t *testing.T,
	identity *agent.AgentIdentity,
	receipt *policy.SignedPolicyReceipt,
	operation financeintegration.TreasuryOperation,
	beneficiary financeintegration.ScreeningEntity,
) []byte {
	t.Helper()

	body, err := json.Marshal(financeTreasuryReleaseInitiateRequest{
		Identity:      mustJSONRawMessage(t, identity),
		PolicyReceipt: receipt,
		Operation:     &operation,
		Resource:      financeTreasuryReleaseAuthDefaultResource,
		Jurisdiction:  beneficiary.Country,
		Beneficiary:   beneficiary,
	})
	if err != nil {
		t.Fatalf("marshal finance enterprise initiate request: %v", err)
	}
	return body
}

func mustMarshalFinanceEnterpriseApproveRequest(
	t *testing.T,
	identity *agent.AgentIdentity,
	receipt *policy.SignedPolicyReceipt,
	comment string,
) []byte {
	t.Helper()

	body, err := json.Marshal(financeTreasuryReleaseApproveRequest{
		Comment:       comment,
		ActorIdentity: mustJSONRawMessage(t, identity),
		PolicyReceipt: receipt,
	})
	if err != nil {
		t.Fatalf("marshal finance enterprise approve request: %v", err)
	}
	return body
}

func mustJSONRawMessage(t *testing.T, value any) json.RawMessage {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal raw JSON message: %v", err)
	}
	return json.RawMessage(data)
}
