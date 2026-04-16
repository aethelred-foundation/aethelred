package finance

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/pkg/seal/sdk"
)

type mockTreasuryReleaseSealer struct {
	count int
}

func (m *mockTreasuryReleaseSealer) CreateSeal(_ context.Context, req sdk.SealRequest) (*sdk.SealResponse, error) {
	m.count++
	return &sdk.SealResponse{
		SealID:       fmt.Sprintf("seal-treasury-%d", m.count),
		Timestamp:    time.Now().UTC(),
		BlockHeight:  int64(100 + m.count),
		Purpose:      req.Purpose,
		ValidatorSet: []string{"validator-a", "validator-b", "validator-c"},
	}, nil
}

func TestTreasuryReleaseWorkflow_AutoApprovedHappyPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflow, store, _, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold: 10000,
		DualThreshold:   50000,
	})

	result, err := workflow.InitiateRelease(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		Operation: &TreasuryOperation{
			Type:         OpPayment,
			Amount:       5000,
			Currency:     "USD",
			Initiator:    "treasury.bot",
			Description:  "Payroll release",
			Counterparty: "Acme Supplier",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Acme Supplier",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err != nil {
		t.Fatalf("InitiateRelease failed: %v", err)
	}

	if result.Status != ReleaseStatusCompleted {
		t.Fatalf("expected completed status, got %s", result.Status)
	}
	if result.RequestReceipt == nil || result.ExecuteReceipt == nil {
		t.Fatal("expected both request and execution receipts")
	}
	if result.SettlementReceipt == nil || result.Settlement == nil {
		t.Fatal("expected settlement receipt and settlement evidence")
	}
	if result.RequestReceipt.Decision != "Allow" || result.ExecuteReceipt.Decision != "Allow" {
		t.Fatalf("expected allow/allow receipts, got %q and %q", result.RequestReceipt.Decision, result.ExecuteReceipt.Decision)
	}
	if result.SettlementReceipt.Decision != "Allow" {
		t.Fatalf("expected settlement receipt allow, got %q", result.SettlementReceipt.Decision)
	}
	if result.ExecuteReceipt.PreviousReceiptHash != result.RequestReceipt.ContentHash {
		t.Fatal("expected execution receipt to chain from request receipt")
	}
	if result.SettlementReceipt.PreviousReceiptHash != result.ExecuteReceipt.ContentHash {
		t.Fatal("expected settlement receipt to chain from execution receipt")
	}
	if result.ReceiptChain == nil || len(result.ReceiptChain.Receipts) != 3 {
		t.Fatal("expected a three-step receipt chain")
	}
	if result.ExecutionSeal == nil || result.ExecutionSeal.SealID == "" {
		t.Fatal("expected an execution seal")
	}
	if result.ControlLedger == nil {
		t.Fatal("expected a control ledger")
	}
	if result.ControlLedger.Summary.TotalPolicyReceipts != 3 {
		t.Fatalf("expected 3 policy receipts, got %d", result.ControlLedger.Summary.TotalPolicyReceipts)
	}
	if result.ControlLedger.Summary.TotalValueSettlements != 1 {
		t.Fatalf("expected 1 value settlement, got %d", result.ControlLedger.Summary.TotalValueSettlements)
	}
	if !result.ControlLedger.Summary.TraceIntact {
		t.Fatal("expected trace-intact ledger summary")
	}
	if !controlLedgerHasControl(result.ControlLedger, "TREASURY-SET-01") {
		t.Fatalf("expected settlement control in ledger, got %+v", result.ControlLedger.Controls)
	}
	if result.PortablePackage == nil || result.PortablePackage.PackageHash == "" {
		t.Fatal("expected a portable control-ledger package")
	}
	if result.PortablePackage.Signature == nil {
		t.Fatal("expected the portable package to be signed")
	}
	if err := evidence.VerifyPortableControlLedgerPackage(result.PortablePackage); err != nil {
		t.Fatalf("VerifyPortableControlLedgerPackage failed: %v", err)
	}

	stored, err := store.Get(ctx, result.ControlLedger.Bundle.ID)
	if err != nil {
		t.Fatalf("control ledger was not persisted: %v", err)
	}
	if stored.Bundle.ContentHash != result.ControlLedger.Bundle.ContentHash {
		t.Fatal("stored control ledger content hash mismatch")
	}

	loaded, err := workflow.GetRelease(ctx, result.WorkflowID)
	if err != nil {
		t.Fatalf("GetRelease failed: %v", err)
	}
	if loaded.Status != ReleaseStatusCompleted {
		t.Fatalf("expected loaded workflow to be completed, got %s", loaded.Status)
	}
}

func TestTreasuryReleaseWorkflow_DualApprovalFinalizes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflow, _, auditTrail, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold:       10000,
		DualThreshold:         50000,
		CommitteeThreshold:    500000,
		RequiredCommitteeSize: 3,
	})
	approverOne := mustTreasuryApprovalIdentity(t, "did:aethelred:approver-treasurer", "treasurer")
	approverTwo := mustTreasuryApprovalIdentity(t, "did:aethelred:approver-cfo", "finance")

	result, err := workflow.InitiateRelease(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		Operation: &TreasuryOperation{
			Type:         OpTransfer,
			Amount:       75000,
			Currency:     "USD",
			Initiator:    "controller@bank.example",
			Description:  "Vendor treasury release",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err != nil {
		t.Fatalf("InitiateRelease failed: %v", err)
	}

	if result.Status != ReleaseStatusPendingApproval {
		t.Fatalf("expected pending approval, got %s", result.Status)
	}
	if result.ExecuteReceipt != nil || result.PortablePackage != nil {
		t.Fatal("did not expect final artifacts before approval")
	}

	result, err = workflow.ApproveReleaseWithAuthorization(ctx, result.WorkflowID, TreasuryReleaseApprovalRequest{
		ActorIdentity: approverOne,
		PolicyReceipt: mustTreasuryApprovalReceipt(t, approverOne, financeTreasuryApprovalAction, "treasury-release:"+result.WorkflowID, "UAE"),
		Comment:       "treasury review complete",
	})
	if err != nil {
		t.Fatalf("first approval failed: %v", err)
	}
	if result.Status != ReleaseStatusPendingApproval {
		t.Fatalf("expected still pending after first approval, got %s", result.Status)
	}
	if result.ApprovalStatus == nil || result.ApprovalStatus.CurrentApprovals != 1 {
		t.Fatal("expected one recorded approval after first approver")
	}
	if len(result.ApprovalEvidence) != 1 || result.ApprovalEvidence[0].ActorIdentity == nil || result.ApprovalEvidence[0].PolicyReceipt == nil {
		t.Fatalf("expected first approval evidence to carry actor identity and policy receipt, got %+v", result.ApprovalEvidence)
	}

	result, err = workflow.ApproveReleaseWithAuthorization(ctx, result.WorkflowID, TreasuryReleaseApprovalRequest{
		ActorIdentity: approverTwo,
		PolicyReceipt: mustTreasuryApprovalReceipt(t, approverTwo, financeTreasuryApprovalAction, "treasury-release:"+result.WorkflowID, "UAE"),
		Comment:       "final release approval",
	})
	if err != nil {
		t.Fatalf("second approval failed: %v", err)
	}
	if result.Status != ReleaseStatusCompleted {
		t.Fatalf("expected completed after second approval, got %s", result.Status)
	}
	if result.ApprovalStatus == nil || !result.ApprovalStatus.FullyApproved {
		t.Fatal("expected fully approved status after second approval")
	}
	if result.PortablePackage == nil {
		t.Fatal("expected portable package after final approval")
	}
	if err := evidence.VerifyPortableControlLedgerPackage(result.PortablePackage); err != nil {
		t.Fatalf("portable package verification failed: %v", err)
	}
	if len(result.ApprovalEvidence) != 2 {
		t.Fatalf("expected two approval evidence records, got %d", len(result.ApprovalEvidence))
	}
	if result.ControlLedger == nil {
		t.Fatal("expected control ledger after final approval")
	}
	if result.Settlement == nil || result.SettlementReceipt == nil {
		t.Fatal("expected settlement artifacts after final approval")
	}
	if result.ControlLedger.Summary.TotalPassports != 3 {
		t.Fatalf("expected 3 passports (originator + 2 approvers), got %d", result.ControlLedger.Summary.TotalPassports)
	}
	if result.ControlLedger.Summary.TotalApproverAttestations != 2 {
		t.Fatalf("expected 2 approver attestations, got %d", result.ControlLedger.Summary.TotalApproverAttestations)
	}
	if result.ControlLedger.Summary.TotalValueSettlements != 1 {
		t.Fatalf("expected 1 value settlement, got %d", result.ControlLedger.Summary.TotalValueSettlements)
	}
	if result.ControlLedger.Summary.TotalPolicyReceipts != 5 {
		t.Fatalf("expected 5 policy receipts (request + execute + settlement + 2 approval), got %d", result.ControlLedger.Summary.TotalPolicyReceipts)
	}
	if result.ControlLedger.Summary.TotalTraceLinks != 3 {
		t.Fatalf("expected 3 trace links (execute + 2 approval), got %d", result.ControlLedger.Summary.TotalTraceLinks)
	}
	if !controlLedgerHasControl(result.ControlLedger, "TREASURY-APP-01") {
		t.Fatalf("expected authenticated approval control in ledger, got %+v", result.ControlLedger.Controls)
	}
	if !controlLedgerHasControl(result.ControlLedger, "TREASURY-SET-01") {
		t.Fatalf("expected settlement control in ledger, got %+v", result.ControlLedger.Controls)
	}

	events := auditTrail.GetEvents()
	if len(events) < 4 {
		t.Fatalf("expected multiple financial audit events, got %d", len(events))
	}
	if !auditTrail.VerifyChainIntegrity() {
		t.Fatal("expected intact audit trail chain")
	}
}

func TestTreasuryReleaseWorkflow_SettlementAllowlistRejects(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	identity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{
			{Name: treasuryReleaseTool, Version: "1.0"},
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
				SignedAt:          time.Now().UTC(),
			}},
			Liability: &agent.LiabilityProfile{
				HumanOwner:      "alice.chen",
				BusinessUnit:    "treasury",
				SponsorOfRecord: "did:aethelred:bank-parent",
				IncidentContact: "soc@bank.example",
				LiabilityModel:  "enterprise-sponsored",
			},
			JurisdictionTags: []string{"UAE"},
			AllowedTools:     []string{treasuryReleaseTool, "sanctions.screen"},
		},
	)
	if err != nil {
		t.Fatalf("creating enterprise identity: %v", err)
	}
	policySignerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating policy signer key: %v", err)
	}
	workflow, err := NewTreasuryReleaseWorkflow(TreasuryReleaseWorkflowConfig{
		Controller:      NewTreasuryController(ApprovalPolicy{SingleThreshold: 10000, DualThreshold: 50000}),
		Sanctions:       NewSanctionsService(SanctionsConfig{BlockOnMatch: true}),
		AuditTrail:      NewFinancialAuditTrail(),
		PolicySignerKey: policySignerKey,
		PolicySigner:    "did:aethelred:policy-gateway-finance",
		Sealer:          &mockTreasuryReleaseSealer{},
		LedgerStore:     evidence.NewInMemoryControlLedgerStore(),
		SettlementRail: NewPolicyBoundSettlementRail(PolicyBoundSettlementConfig{
			AllowedCounterparties: []string{"Only Allowed Counterparty"},
		}),
	})
	if err != nil {
		t.Fatalf("creating treasury release workflow: %v", err)
	}

	result, err := workflow.InitiateRelease(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		Operation: &TreasuryOperation{
			Type:         OpPayment,
			Amount:       5000,
			Currency:     "USD",
			Initiator:    "treasury.bot",
			Description:  "Blocked settlement counterparty",
			Counterparty: "Unlisted Vendor",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Unlisted Vendor",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err == nil {
		t.Fatal("expected settlement allowlist rejection")
	}
	if !errors.Is(err, ErrSettlementDenied) {
		t.Fatalf("expected ErrSettlementDenied, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result on settlement rejection, got %+v", result)
	}
}

func TestTreasuryReleaseWorkflow_SanctionsRejects(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflow, _, _, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold: 10000,
		DualThreshold:   50000,
	})

	result, err := workflow.InitiateRelease(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		Operation: &TreasuryOperation{
			Type:         OpPayment,
			Amount:       6000,
			Currency:     "USD",
			Initiator:    "treasury.bot",
			Description:  "Blocked supplier payment",
			Counterparty: "Blocked Entity",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Blocked Entity",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err == nil {
		t.Fatal("expected sanctions rejection error")
	}
	if !errors.Is(err, ErrSanctionsMatch) {
		t.Fatalf("expected ErrSanctionsMatch, got %v", err)
	}
	if result == nil {
		t.Fatal("expected a rejected workflow result")
	}
	if result.Status != ReleaseStatusRejected {
		t.Fatalf("expected rejected status, got %s", result.Status)
	}
	if result.RequestReceipt == nil {
		t.Fatal("expected a denied request-stage policy receipt")
	}
	if result.ExecuteReceipt != nil || result.ControlLedger != nil || result.PortablePackage != nil {
		t.Fatal("did not expect final artifacts for rejected sanctions flow")
	}

	loaded, loadErr := workflow.GetRelease(ctx, result.WorkflowID)
	if loadErr != nil {
		t.Fatalf("GetRelease failed: %v", loadErr)
	}
	if loaded.Status != ReleaseStatusRejected {
		t.Fatalf("expected loaded workflow to be rejected, got %s", loaded.Status)
	}
}

func TestTreasuryReleaseWorkflow_PreviewSettlementQuoteEligible(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflow, _, _, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold: 10000,
		DualThreshold:   50000,
	})

	quote, err := workflow.PreviewSettlement(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		ReasonCode:   "vendor_payment",
		Operation: &TreasuryOperation{
			Type:         OpPayment,
			Amount:       3200,
			Currency:     "USD",
			Initiator:    "treasury.bot",
			Description:  "Settlement preview",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err != nil {
		t.Fatalf("PreviewSettlement failed: %v", err)
	}
	if quote == nil || !quote.Eligible {
		t.Fatalf("expected eligible settlement quote, got %+v", quote)
	}
	if quote.ProviderID == "" || quote.CorridorID == "" {
		t.Fatalf("expected provider and corridor in quote, got %+v", quote)
	}
	if quote.ReasonCode != "vendor_payment" {
		t.Fatalf("expected reason code to round-trip, got %q", quote.ReasonCode)
	}
}

func TestTreasuryReleaseWorkflow_PreviewSettlementQuoteShowsCorridorViolations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflow, _, _, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold: 10000,
		DualThreshold:   50000,
	})
	workflow.config.SettlementRail = NewPolicyBoundSettlementRail(PolicyBoundSettlementConfig{
		ProviderID:           "provider.finance.1",
		ProviderStatus:       "active",
		CorridorID:           "uae-usd-vendors",
		AllowedJurisdictions: []string{"UAE"},
		AllowedCurrencies:    []string{"USD"},
		RequiredReasonCodes:  []string{"vendor_payment"},
		MaxFiatAmount:        10000,
	})

	quote, err := workflow.PreviewSettlement(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UK",
		ReasonCode:   "unknown_reason",
		Operation: &TreasuryOperation{
			Type:         OpPayment,
			Amount:       15000,
			Currency:     "EUR",
			Initiator:    "treasury.bot",
			Description:  "Invalid settlement preview",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UK",
		},
	})
	if err != nil {
		t.Fatalf("PreviewSettlement failed: %v", err)
	}
	if quote == nil || quote.Eligible {
		t.Fatalf("expected ineligible settlement quote, got %+v", quote)
	}
	if len(quote.Violations) < 3 {
		t.Fatalf("expected multiple corridor violations, got %+v", quote)
	}
}

func TestTreasuryReleaseWorkflow_ApprovalEvidenceRejectsMismatchedApproverIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	workflow, _, _, identity := newTestTreasuryReleaseWorkflow(t, ApprovalPolicy{
		SingleThreshold: 10000,
		DualThreshold:   50000,
	})

	result, err := workflow.InitiateRelease(ctx, TreasuryReleaseRequest{
		Identity:     identity,
		Resource:     "acct:treasury-main",
		Jurisdiction: "UAE",
		Operation: &TreasuryOperation{
			Type:         OpTransfer,
			Amount:       75000,
			Currency:     "USD",
			Initiator:    "controller@bank.example",
			Description:  "Mismatch approval evidence",
			Counterparty: "Trusted Vendor",
		},
		Beneficiary: ScreeningEntity{
			Name:       "Trusted Vendor",
			EntityType: "organization",
			Country:    "UAE",
		},
	})
	if err != nil {
		t.Fatalf("InitiateRelease failed: %v", err)
	}

	approver := mustTreasuryApprovalIdentity(t, "did:aethelred:approver-ops", "operations")
	_, err = workflow.ApproveReleaseWithAuthorization(ctx, result.WorkflowID, TreasuryReleaseApprovalRequest{
		Approver:      "treasurer@bank.example",
		ActorIdentity: approver,
		PolicyReceipt: mustTreasuryApprovalReceipt(t, approver, financeTreasuryApprovalAction, "treasury-release:"+result.WorkflowID, "UAE"),
	})
	if err == nil {
		t.Fatal("expected mismatched approver/identity error")
	}
}

func newTestTreasuryReleaseWorkflow(t *testing.T, approvalPolicy ApprovalPolicy) (*TreasuryReleaseWorkflow, evidence.ControlLedgerStore, *FinancialAuditTrail, *agent.AgentIdentity) {
	t.Helper()

	identity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{
			{Name: treasuryReleaseTool, Version: "1.0"},
			{Name: "sanctions.screen", Version: "1.0"},
		},
		agent.EnterpriseIdentityOptions{
			Issuer: "did:aethelred:issuer-bank-1",
			SponsorChain: []agent.SponsorRecord{
				{
					SponsorDID:        "did:aethelred:bank-parent",
					SponsorName:       "Bank Parent",
					Jurisdiction:      "UAE",
					Role:              "sponsor_of_record",
					LiabilityAccepted: true,
					SignedAt:          time.Now().UTC(),
				},
			},
			Liability: &agent.LiabilityProfile{
				HumanOwner:      "alice.chen",
				BusinessUnit:    "treasury",
				SponsorOfRecord: "did:aethelred:bank-parent",
				IncidentContact: "soc@bank.example",
				LiabilityModel:  "enterprise-sponsored",
			},
			JurisdictionTags: []string{"UAE", "UK"},
			AllowedTools:     []string{treasuryReleaseTool, "sanctions.screen"},
			Metadata: map[string]string{
				"sector": "finance",
			},
		},
	)
	if err != nil {
		t.Fatalf("creating enterprise identity: %v", err)
	}

	policySignerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating policy signer key: %v", err)
	}

	signSeed := make([]byte, ed25519.SeedSize)
	for i := range signSeed {
		signSeed[i] = byte(i + 1)
	}
	packageSigningKey := ed25519.NewKeyFromSeed(signSeed)

	store := evidence.NewInMemoryControlLedgerStore()
	auditTrail := NewFinancialAuditTrail()
	workflow, err := NewTreasuryReleaseWorkflow(TreasuryReleaseWorkflowConfig{
		Controller:        NewTreasuryController(approvalPolicy),
		Sanctions:         NewSanctionsService(SanctionsConfig{BlockOnMatch: true}),
		AuditTrail:        auditTrail,
		PolicySignerKey:   policySignerKey,
		PolicySigner:      "did:aethelred:policy-gateway-finance",
		Sealer:            &mockTreasuryReleaseSealer{},
		LedgerStore:       store,
		Framework:         "SOX Treasury Release",
		PackageSigningKey: packageSigningKey,
		PackageSigner:     "validator:finance-workflow-test",
	})
	if err != nil {
		t.Fatalf("creating treasury release workflow: %v", err)
	}

	return workflow, store, auditTrail, identity
}

const financeTreasuryApprovalAction = "payments.release.approve"

func mustTreasuryApprovalIdentity(t *testing.T, did string, businessUnit string) *agent.AgentIdentity {
	t.Helper()

	identity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{
			{Name: "payments.release", Version: "1.0"},
			{Name: financeTreasuryApprovalAction, Version: "1.0"},
		},
		agent.EnterpriseIdentityOptions{
			Issuer: "did:aethelred:issuer-bank-1",
			SponsorChain: []agent.SponsorRecord{{
				SponsorDID:        "did:aethelred:bank-parent",
				SponsorName:       "Bank Parent",
				Jurisdiction:      "UAE",
				Role:              "approver",
				LiabilityAccepted: true,
				SignedAt:          time.Now().UTC(),
			}},
			Liability: &agent.LiabilityProfile{
				HumanOwner:      did,
				BusinessUnit:    businessUnit,
				SponsorOfRecord: "did:aethelred:bank-parent",
				IncidentContact: "soc@bank.example",
				LiabilityModel:  "enterprise-sponsored",
			},
			JurisdictionTags: []string{"UAE"},
			AllowedTools:     []string{"payments.release", financeTreasuryApprovalAction},
			Metadata: map[string]string{
				"sector": "finance",
				"role":   "approver",
			},
		},
	)
	if err != nil {
		t.Fatalf("creating approval identity: %v", err)
	}
	return identity
}

func mustTreasuryApprovalReceipt(t *testing.T, identity *agent.AgentIdentity, action string, resource string, jurisdiction string) *policy.SignedPolicyReceipt {
	t.Helper()

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating approval signer key: %v", err)
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
		RequestID:    fmt.Sprintf("approval-%d", time.Now().UnixNano()),
		Decision:     policy.Allow,
		MatchedRules: []string{"finance.approval.allow"},
		AuditTrail:   "finance-approval-audit-trail",
		EvaluatedAt:  time.Now().UTC(),
	}
	receipt, err := policy.CreateSignedPolicyReceipt(context.Background(), signerKey, "did:aethelred:approval-policy-gateway", evalReq, evalResult, "")
	if err != nil {
		t.Fatalf("creating approval receipt: %v", err)
	}
	return receipt
}

func controlLedgerHasControl(ledger *evidence.ControlLedger, controlID string) bool {
	if ledger == nil {
		return false
	}
	for _, control := range ledger.Controls {
		if control.ControlID == controlID {
			return true
		}
	}
	return false
}

func TestTreasuryReleaseResult_ApprovalEvidenceRoundTripJSON(t *testing.T) {
	t.Parallel()

	approver := mustTreasuryApprovalIdentity(t, "did:aethelred:approver-json", "json")
	result := TreasuryReleaseResult{
		WorkflowID: "trl-json",
		Status:     ReleaseStatusPendingApproval,
		ApprovalEvidence: []TreasuryReleaseApprovalEvidence{{
			Approver:      approver.AgentID(),
			ActorIdentity: approver,
			PolicyReceipt: mustTreasuryApprovalReceipt(t, approver, financeTreasuryApprovalAction, "treasury-release:trl-json", "UAE"),
			AuthorizedAt:  time.Now().UTC(),
		}},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded TreasuryReleaseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(decoded.ApprovalEvidence) != 1 || decoded.ApprovalEvidence[0].ActorIdentity == nil || decoded.ApprovalEvidence[0].PolicyReceipt == nil {
		t.Fatalf("expected approval evidence round-trip, got %+v", decoded.ApprovalEvidence)
	}
}
