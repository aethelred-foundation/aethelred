//go:build integration

// Package pkg_test provides end-to-end integration tests that wire real
// package instances together and exercise cross-package workflows. These
// tests validate that the Aethelred platform components compose correctly
// for enterprise compliance, seal, agent, healthcare, supply-chain,
// incident response, finance, defense, and sovereign deployment scenarios.
package pkg_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/assurance"
	"github.com/aethelred/aethelred/pkg/compliance/assessor"
	"github.com/aethelred/aethelred/pkg/compliance/frameworks"
	"github.com/aethelred/aethelred/pkg/compliance/mappings"
	"github.com/aethelred/aethelred/pkg/deploy/sovereign"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/integrations/defense"
	"github.com/aethelred/aethelred/pkg/integrations/epcis"
	"github.com/aethelred/aethelred/pkg/integrations/fhir"
	"github.com/aethelred/aethelred/pkg/integrations/finance"
	"github.com/aethelred/aethelred/pkg/operations/incident"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/pkg/seal/sdk"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// ---------------------------------------------------------------------------
// Mock seal keeper for integration tests
// ---------------------------------------------------------------------------

type mockSealKeeper struct {
	seals map[string]*sealtypes.DigitalSeal
}

func newMockSealKeeper() *mockSealKeeper {
	return &mockSealKeeper{seals: make(map[string]*sealtypes.DigitalSeal)}
}

func (m *mockSealKeeper) CreateSeal(_ context.Context, seal *sealtypes.DigitalSeal) error {
	if seal.Id == "" {
		h := sha256.Sum256(seal.ModelCommitment)
		seal.Id = "seal_" + hex.EncodeToString(h[:8])
	}
	if seal.Status == sealtypes.SealStatus_SEAL_STATUS_UNSPECIFIED {
		seal.Status = sealtypes.SealStatus_SEAL_STATUS_ACTIVE
	}
	m.seals[seal.Id] = seal
	return nil
}

func (m *mockSealKeeper) GetSeal(_ context.Context, id string) (*sealtypes.DigitalSeal, error) {
	seal, ok := m.seals[id]
	if !ok {
		return nil, fmt.Errorf("seal %s not found", id)
	}
	return seal, nil
}

func (m *mockSealKeeper) SetSeal(_ context.Context, seal *sealtypes.DigitalSeal) error {
	m.seals[seal.Id] = seal
	return nil
}

func (m *mockSealKeeper) RevokeSeal(_ context.Context, id string, _ string) error {
	seal, ok := m.seals[id]
	if !ok {
		return fmt.Errorf("seal %s not found", id)
	}
	seal.Status = sealtypes.SealStatus_SEAL_STATUS_REVOKED
	return nil
}

func (m *mockSealKeeper) VerifySeal(_ context.Context, id string) (bool, error) {
	seal, ok := m.seals[id]
	if !ok {
		return false, fmt.Errorf("seal %s not found", id)
	}
	return seal.Status == sealtypes.SealStatus_SEAL_STATUS_ACTIVE, nil
}

func (m *mockSealKeeper) ListSeals(_ context.Context, limit int, offset int) ([]*sealtypes.DigitalSeal, error) {
	var result []*sealtypes.DigitalSeal
	for _, s := range m.seals {
		result = append(result, s)
	}
	if offset > len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

func (m *mockSealKeeper) ListSealsByModel(_ context.Context, modelHash []byte) ([]*sealtypes.DigitalSeal, error) {
	var result []*sealtypes.DigitalSeal
	for _, s := range m.seals {
		if sliceEqual(s.ModelCommitment, modelHash) {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockSealKeeper) ListSealsByRequester(_ context.Context, requester string) ([]*sealtypes.DigitalSeal, error) {
	var result []*sealtypes.DigitalSeal
	for _, s := range m.seals {
		if s.RequestedBy == requester {
			result = append(result, s)
		}
	}
	return result, nil
}

func sliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Mock assurance providers
// ---------------------------------------------------------------------------

type mockAuditProvider struct {
	records    int
	chainValid bool
}

func (m *mockAuditProvider) GetAuditEvidence(_ context.Context, _ string) (*assurance.AuditEvidence, error) {
	return &assurance.AuditEvidence{
		RecordCount: m.records,
		ChainIntact: m.chainValid,
		FirstRecord: time.Now().Add(-1 * time.Hour),
		LastRecord:  time.Now(),
	}, nil
}

type mockSealProvider struct {
	sealCount int
}

func (m *mockSealProvider) GetSealEvidence(_ context.Context, jobID string) ([]assurance.SealEvidence, error) {
	var seals []assurance.SealEvidence
	for i := 0; i < m.sealCount; i++ {
		seals = append(seals, assurance.SealEvidence{
			SealID:         fmt.Sprintf("seal-%s-%d", jobID, i),
			JobID:          jobID,
			OutputHash:     "abc123",
			ValidatorCount: 3,
			BlockHeight:    int64(100 + i),
			Timestamp:      time.Now(),
			Status:         "active",
		})
	}
	return seals, nil
}

type mockVerificationProvider struct {
	hasTEE bool
	hasZK  bool
}

func (m *mockVerificationProvider) GetVerificationEvidence(_ context.Context, _ string) (*assurance.VerificationEvidence, error) {
	return &assurance.VerificationEvidence{
		HasTEEAttestation: m.hasTEE,
		HasZKProof:        m.hasZK,
		AttestationType:   "sgx",
		ProofSystem:       "groth16",
		VerifiedAt:        time.Now(),
	}, nil
}

type mockComplianceProvider struct {
	met   int
	total int
}

func (m *mockComplianceProvider) GetComplianceEvidence(_ context.Context, _ string) (*assurance.ComplianceEvidence, error) {
	score := 0.0
	if m.total > 0 {
		score = float64(m.met) / float64(m.total) * 100
	}
	return &assurance.ComplianceEvidence{
		Frameworks:    []string{"NIST AI RMF", "SOC 2"},
		ControlsMet:   m.met,
		ControlsTotal: m.total,
		CoverageScore: score,
	}, nil
}

func newTestSealSDK(t *testing.T) *sdk.SealSDK {
	t.Helper()
	keeper := newMockSealKeeper()
	s, err := sdk.NewSealSDK(sdk.Config{
		ChainID:      "aethelred-test-1",
		SignerAddress: "aethelred1testaddr",
		Timeout:      5 * time.Second,
	}, keeper)
	if err != nil {
		t.Fatalf("creating test seal SDK: %v", err)
	}
	return s
}

// =========================================================================
// Test 1: Compliance Assessment with Audit Trail
// =========================================================================

func TestComplianceAssessmentWithAuditTrail(t *testing.T) {
	t.Parallel()

	// Step 1: Load a compliance framework and validate it.
	fw := frameworks.NISTAIIRMF()
	if err := fw.Validate(); err != nil {
		t.Fatalf("framework validation failed: %v", err)
	}

	// Step 2: Create mapper (pre-loaded with all frameworks and mappings).
	mapper := mappings.NewMapper()

	// Step 3: Run compliance assessment.
	assess := assessor.NewAssessor(mapper)
	report, err := assess.Assess(fw.ID)
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	// Step 4: Verify assessment report has controls.
	if report.TotalControls == 0 {
		t.Fatal("expected controls in assessment report")
	}
	if report.OverallScore < 0 || report.OverallScore > 100 {
		t.Fatalf("overall score %d out of valid range", report.OverallScore)
	}

	// Step 5: Build evidence bundle from assessment.
	bundle := evidence.NewEvidenceBundle("NIST AI RMF")
	bundle.AddRecord(evidence.Record{
		ID:        "compliance-assessment-1",
		Type:      "audit",
		Action:    "compliance_assessment",
		Actor:     "system",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"framework":      fw.ID,
			"overall_score":  fmt.Sprintf("%d", report.OverallScore),
			"total_controls": fmt.Sprintf("%d", report.TotalControls),
		},
	})

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("bundle finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}

	// Step 6: Verify the chain from framework -> assessment -> evidence.
	if bundle.Framework != "NIST AI RMF" {
		t.Fatalf("expected framework 'NIST AI RMF', got %q", bundle.Framework)
	}
	if len(bundle.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(bundle.Records))
	}
	if bundle.ContentHash == "" {
		t.Fatal("expected content hash to be set after finalization")
	}
}

// =========================================================================
// Test 2: Seal with Policy Approval
// =========================================================================

func TestSealWithPolicyApproval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Create agent identities.
	requesterCaps := []agent.Capability{{Name: "seal.request", Version: "1.0"}}
	requesterIdentity, requesterKey, err := agent.NewAgentIdentity(requesterCaps)
	if err != nil {
		t.Fatalf("creating requester identity: %v", err)
	}

	approverCaps := []agent.Capability{{Name: "seal.approve", Version: "1.0"}}
	approverIdentity, _, err := agent.NewAgentIdentity(approverCaps)
	if err != nil {
		t.Fatalf("creating approver identity: %v", err)
	}

	// Step 2: Register agents.
	registry := agent.NewAgentRegistry()
	if _, err := registry.RegisterAgent(ctx, requesterIdentity); err != nil {
		t.Fatalf("registering requester: %v", err)
	}
	if _, err := registry.RegisterAgent(ctx, approverIdentity); err != nil {
		t.Fatalf("registering approver: %v", err)
	}

	// Step 3: Set up authorization policy.
	authorizer := agent.NewAuthorizer([]*agent.AuthorizationPolicy{
		{AllowedActions: []string{"seal.request", "seal.approve"}},
	}, nil)

	// Step 4: Authorize the seal request.
	authResult, err := authorizer.Authorize(ctx, &agent.AuthorizationContext{
		Actor:  requesterIdentity,
		Action: "seal.request",
	})
	if err != nil {
		t.Fatalf("authorization failed: %v", err)
	}
	if !authResult.Authorized {
		t.Fatalf("expected authorization, got denied: %s", authResult.Reason)
	}

	// Step 5: Create the seal.
	sealSDK := newTestSealSDK(t)
	sealResp, err := sealSDK.CreateSeal(ctx, sdk.SealRequest{
		ModelHash:  sha256Bytes("test-model"),
		InputHash:  sha256Bytes("test-input"),
		OutputHash: sha256Bytes("test-output"),
		Purpose:    "integration_test",
	})
	if err != nil {
		t.Fatalf("creating seal: %v", err)
	}
	if sealResp.SealID == "" {
		t.Fatal("expected non-empty seal ID")
	}

	// Step 6: Create action receipt for audit trail.
	receipt, err := agent.CreateReceipt(ctx, requesterKey,
		requesterIdentity.AgentID(), "seal.create", sealResp.SealID, "success",
		"", map[string]string{"purpose": "integration_test"})
	if err != nil {
		t.Fatalf("creating receipt: %v", err)
	}
	if receipt.ContentHash == "" {
		t.Fatal("expected non-empty receipt content hash")
	}

	// Step 7: Verify the receipt signature.
	if err := agent.VerifyReceipt(receipt, requesterIdentity.PublicKey); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}
}

// =========================================================================
// Test 3: Agent Delegation with Authorization
// =========================================================================

func TestAgentDelegationWithAuthorization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Create principal and delegate identities.
	principalID, principalKey, err := agent.NewAgentIdentity([]agent.Capability{
		{Name: "compute.execute", Version: "1.0"},
		{Name: "model.deploy", Version: "1.0"},
	})
	if err != nil {
		t.Fatalf("creating principal: %v", err)
	}

	delegateID, _, err := agent.NewAgentIdentity([]agent.Capability{
		{Name: "compute.execute", Version: "1.0"},
	})
	if err != nil {
		t.Fatalf("creating delegate: %v", err)
	}

	// Step 2: Register agents.
	registry := agent.NewAgentRegistry()
	if _, err := registry.RegisterAgent(ctx, principalID); err != nil {
		t.Fatalf("registering principal: %v", err)
	}
	if _, err := registry.RegisterAgent(ctx, delegateID); err != nil {
		t.Fatalf("registering delegate: %v", err)
	}

	// Step 3: Create delegation.
	dm := agent.NewDelegationManager()
	delegation, err := dm.Delegate(ctx, principalID.AgentID(), delegateID.AgentID(), &agent.DelegationScope{
		Actions:   []string{"compute.execute"},
		MaxDepth:  2,
		TimeLimit: 1 * time.Hour,
	}, nil)
	if err != nil {
		t.Fatalf("creating delegation: %v", err)
	}

	// Step 4: Authorize action via delegation.
	authorizer := agent.NewAuthorizer([]*agent.AuthorizationPolicy{
		{
			AllowedActions: []string{"compute.execute"},
			DelegationRules: &agent.DelegationAuthRules{
				AllowDelegation:          true,
				MaxDepth:                 3,
				RequireChainVerification: true,
			},
		},
	}, dm)

	authResult, err := authorizer.Authorize(ctx, &agent.AuthorizationContext{
		Actor:      delegateID,
		Action:     "compute.execute",
		Delegation: delegation,
	})
	if err != nil {
		t.Fatalf("authorization failed: %v", err)
	}
	if !authResult.Authorized {
		t.Fatalf("expected authorized, got: %s", authResult.Reason)
	}

	// Step 5: Create receipt for the delegated action.
	receipt, err := agent.CreateReceipt(ctx, principalKey,
		principalID.AgentID(), "compute.execute", "job-123", "success",
		delegation.ID, map[string]string{"delegated_to": delegateID.AgentID()})
	if err != nil {
		t.Fatalf("creating receipt: %v", err)
	}

	// Step 6: Build and verify receipt chain.
	chain, err := agent.BuildReceiptChain(ctx, []*agent.ActionReceipt{receipt})
	if err != nil {
		t.Fatalf("building receipt chain: %v", err)
	}
	if err := agent.VerifyReceiptChain(chain); err != nil {
		t.Fatalf("receipt chain verification failed: %v", err)
	}
}

// =========================================================================
// Test 4: FHIR Bridge with Consent
// =========================================================================

func TestFHIRBridgeWithConsent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Set up seal SDK and FHIR bridge.
	sealSDK := newTestSealSDK(t)
	bridge, err := fhir.NewFHIRBridge(fhir.BridgeConfig{
		DefaultJurisdiction:  "US",
		ConsentRequired:      true,
		DefaultRetentionDays: 2555,
	}, sealSDK)
	if err != nil {
		t.Fatalf("creating FHIR bridge: %v", err)
	}

	// Step 2: Create patient.
	patient := &fhir.Patient{
		ResourceType: "Patient",
		ID:           "patient-001",
		Active:       true,
		Name:         []fhir.HumanName{{Family: "Smith", Given: []string{"John"}}},
		Gender:       "male",
		BirthDate:    "1980-01-15",
	}

	// Step 3: Create consent.
	consentMgr := fhir.NewConsentManager(bridge, fhir.ConsentPolicy{
		RequireExplicit: true,
		AllowedPurposes: []string{"treatment", "research"},
	})

	now := time.Now().UTC()
	futureEnd := now.Add(365 * 24 * time.Hour)
	sealedConsent, err := consentMgr.CreateConsent(ctx, fhir.Consent{
		ResourceType: "Consent",
		ID:           "consent-001",
		Status:       fhir.ConsentStatusActive,
		Scope:        fhir.CodeableConcept{Text: "patient-privacy"},
		Patient:      &fhir.Reference{Reference: "Patient/patient-001"},
		DateTime:     &now,
		Provision: &fhir.ConsentProvision{
			Type:    "permit",
			Period:  &fhir.Period{Start: &now, End: &futureEnd},
			Purpose: []fhir.Coding{{Code: "treatment"}},
		},
	})
	if err != nil {
		t.Fatalf("creating consent: %v", err)
	}
	if sealedConsent.SealID == "" {
		t.Fatal("expected sealed consent to have seal ID")
	}

	// Step 4: Validate consent.
	hasConsent, err := consentMgr.ValidateConsent(ctx, "Patient/patient-001", "treatment")
	if err != nil {
		t.Fatalf("validating consent: %v", err)
	}
	if !hasConsent {
		t.Fatal("expected consent to be valid for treatment purpose")
	}

	// Step 5: Seal patient resource.
	sealed, err := bridge.SealResource(ctx, patient)
	if err != nil {
		t.Fatalf("sealing patient resource: %v", err)
	}
	if sealed.SealID == "" {
		t.Fatal("expected seal ID for patient resource")
	}

	// Step 6: Verify sealed resource.
	verifyResult, err := bridge.VerifyResource(ctx, patient, sealed.SealID)
	if err != nil {
		t.Fatalf("verifying resource: %v", err)
	}
	if !verifyResult.SealValid {
		t.Fatal("expected seal to be valid")
	}
	if !verifyResult.DataIntact {
		t.Fatal("expected data to be intact")
	}
}

// =========================================================================
// Test 5: EPCIS Capture with Provenance
// =========================================================================

func TestEPCISCaptureWithProvenance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	sealSDK := newTestSealSDK(t)
	captureSvc := epcis.NewCaptureService(epcis.CaptureConfig{
		SealOnCapture:       true,
		DefaultJurisdiction: "US",
	}, sealSDK)

	// Step 1: Capture a commissioning event.
	commissionEvent := &epcis.ObjectEvent{}
	commissionEvent.Type = epcis.EventTypeObject
	commissionEvent.EPCList = []string{"urn:epc:id:sgtin:0614141.107346.2017"}
	commissionEvent.Action = epcis.ActionADD
	commissionEvent.BizStep = epcis.BizStepCommissioning
	commissionEvent.EventTime = time.Now().UTC()

	result1, err := captureSvc.CaptureEvent(ctx, commissionEvent)
	if err != nil {
		t.Fatalf("capturing commission event: %v", err)
	}
	if result1.EventID == "" {
		t.Fatal("expected event ID")
	}

	// Step 2: Capture a shipping event.
	shipEvent := &epcis.ObjectEvent{}
	shipEvent.Type = epcis.EventTypeObject
	shipEvent.EPCList = []string{"urn:epc:id:sgtin:0614141.107346.2017"}
	shipEvent.Action = epcis.ActionOBSERVE
	shipEvent.BizStep = epcis.BizStepShipping
	shipEvent.Disposition = epcis.DispositionInTransit
	shipEvent.EventTime = time.Now().UTC()

	result2, err := captureSvc.CaptureEvent(ctx, shipEvent)
	if err != nil {
		t.Fatalf("capturing shipping event: %v", err)
	}

	// Step 3: Build evidence bundle from captured events.
	bundle := evidence.NewEvidenceBundle("GS1 EPCIS 2.0")
	for _, evtID := range []string{result1.EventID, result2.EventID} {
		bundle.AddRecord(evidence.Record{
			ID:        evtID,
			Type:      "computation",
			Action:    "epcis_capture",
			Actor:     "supply-chain-system",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Data:      map[string]string{"epc": "urn:epc:id:sgtin:0614141.107346.2017"},
		})
	}

	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("bundle finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}
	if len(bundle.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(bundle.Records))
	}
}

// =========================================================================
// Test 6: Incident with Kill Switch and Disclosure
// =========================================================================

func TestIncidentWithKillSwitchAndDisclosure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Create incident controller and kill switch.
	controller := incident.NewIncidentController()
	killSwitch := incident.NewKillSwitch()

	// Step 2: Report an incident.
	inc, err := controller.CreateIncident(ctx, &incident.Incident{
		Type:            incident.IncidentSecurityBreach,
		Severity:        incident.SeverityP0,
		Title:           "Security Breach Detected",
		Description:     "Unauthorized access to model weights",
		AffectedSystems: []string{"model-inference", "data-pipeline"},
	})
	if err != nil {
		t.Fatalf("creating incident: %v", err)
	}
	if inc.ID == "" {
		t.Fatal("expected incident ID")
	}
	if inc.Status != incident.StatusDetected {
		t.Fatalf("expected status 'detected', got %q", inc.Status)
	}

	// Step 3: Activate kill switch.
	ksRecord, err := killSwitch.ActivateKillSwitch(ctx, incident.ActionIsolate, "security breach", incident.KillSwitchScope{
		Systems: []string{"model-inference", "data-pipeline"},
	})
	if err != nil {
		t.Fatalf("activating kill switch: %v", err)
	}
	if !ksRecord.Active {
		t.Fatal("expected kill switch to be active")
	}

	// Step 4: Execute runbook for security breach.
	runbookExec := incident.NewRunbookExecutor()
	runbooks := runbookExec.FindRunbooksForIncident(inc)
	if len(runbooks) == 0 {
		t.Fatal("expected at least one matching runbook for security breach")
	}
	rbExec, err := runbookExec.ExecuteRunbook(ctx, runbooks[0].ID, inc)
	if err != nil {
		t.Fatalf("executing runbook: %v", err)
	}
	if rbExec == nil {
		t.Fatal("expected runbook execution result")
	}

	// Step 5: Generate disclosure documents.
	disclosureSvc := incident.NewDisclosureService()
	requirements, err := disclosureSvc.GetDisclosureRequirements(ctx, inc)
	if err != nil {
		t.Fatalf("getting disclosure requirements: %v", err)
	}
	if len(requirements) == 0 {
		t.Fatal("expected at least one disclosure requirement for security breach")
	}

	// Step 6: Verify timeline has events.
	if len(inc.Timeline) == 0 {
		t.Fatal("expected timeline entries for incident")
	}
}

// =========================================================================
// Test 7: Full Assurance Fabric Workflow
// =========================================================================

func TestFullAssuranceFabricWorkflow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Set up providers.
	fabric, err := assurance.NewAssuranceFabric(assurance.FabricConfig{
		AuditProvider:        &mockAuditProvider{records: 10, chainValid: true},
		SealProvider:         &mockSealProvider{sealCount: 2},
		VerificationProvider: &mockVerificationProvider{hasTEE: true, hasZK: true},
		ComplianceProvider:   &mockComplianceProvider{met: 8, total: 10},
	})
	if err != nil {
		t.Fatalf("creating assurance fabric: %v", err)
	}

	// Step 2: Collect evidence.
	jobID := "test-job-001"
	ev, err := fabric.CollectEvidence(ctx, jobID)
	if err != nil {
		t.Fatalf("collecting evidence: %v", err)
	}
	if ev.JobID != jobID {
		t.Fatalf("expected job ID %q, got %q", jobID, ev.JobID)
	}

	// Step 3: Verify Critical assurance level (all evidence present).
	if ev.AssuranceLevel != assurance.AssuranceLevelCritical {
		t.Fatalf("expected Critical assurance level, got %s", ev.AssuranceLevel)
	}

	// Step 4: Build execution receipt.
	receipt, buildErr := assurance.NewReceiptBuilder(jobID).
		WithAuditTrail(&assurance.ReceiptAuditTrail{
			RecordCount: ev.Audit.RecordCount,
			ChainIntact: ev.Audit.ChainIntact,
		}).
		WithSeal(&assurance.ReceiptSeal{
			SealID:         ev.Seals[0].SealID,
			OutputHash:     ev.Seals[0].OutputHash,
			ValidatorCount: ev.Seals[0].ValidatorCount,
			BlockHeight:    ev.Seals[0].BlockHeight,
		}).
		WithCompliance(&assurance.ReceiptComplianceMetadata{
			Frameworks:    ev.Compliance.Frameworks,
			ControlsMet:   ev.Compliance.ControlsMet,
			ControlsTotal: ev.Compliance.ControlsTotal,
		}).
		WithAssuranceLevel(ev.AssuranceLevel).
		Build()
	if buildErr != nil {
		t.Fatalf("building receipt: %v", buildErr)
	}

	if err := receipt.Validate(); err != nil {
		t.Fatalf("receipt validation failed: %v", err)
	}
	if receipt.ContentHash == "" {
		t.Fatal("expected content hash on receipt")
	}

	// Step 5: Verify cache.
	cached, ok := fabric.GetCachedEvidence(jobID)
	if !ok {
		t.Fatal("expected cached evidence")
	}
	if cached.ContentHash != ev.ContentHash {
		t.Fatal("cached evidence hash mismatch")
	}
}

// =========================================================================
// Test 8: Finance Treasury with Dual Approval
// =========================================================================

func TestFinanceTreasuryWithDualApproval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Create treasury controller with dual approval policy.
	controller := finance.NewTreasuryController(finance.ApprovalPolicy{
		SingleThreshold:       10000,
		DualThreshold:         50000,
		CommitteeThreshold:    500000,
		RequiredCommitteeSize: 3,
		Approvers: map[string]int{
			"cfo@company.com":        3,
			"treasurer@company.com":  2,
			"controller@company.com": 1,
		},
	})

	// Step 2: Create a treasury operation requiring dual approval.
	op := &finance.TreasuryOperation{
		Type:         finance.OpTransfer,
		Amount:       75000,
		Currency:     "USD",
		Initiator:    "controller@company.com",
		Description:  "Vendor payment Q1",
		Counterparty: "vendor-corp",
	}

	if err := controller.InitiateOperation(ctx, op); err != nil {
		t.Fatalf("initiating operation: %v", err)
	}
	if op.Status != finance.StatusAwaitingApproval {
		t.Fatalf("expected awaiting_approval, got %s", op.Status)
	}

	// Step 3: First approval.
	if err := controller.ApproveOperation(ctx, op.ID, "treasurer@company.com"); err != nil {
		t.Fatalf("first approval failed: %v", err)
	}

	// Step 4: Second approval.
	if err := controller.ApproveOperation(ctx, op.ID, "cfo@company.com"); err != nil {
		t.Fatalf("second approval failed: %v", err)
	}

	// Step 5: Check approval status.
	status, err := controller.GetApprovalStatus(ctx, op.ID)
	if err != nil {
		t.Fatalf("getting approval status: %v", err)
	}
	if !status.FullyApproved {
		t.Fatal("expected fully approved after dual approval")
	}

	// Step 6: Build SOX evidence bundle.
	bundle := evidence.NewEvidenceBundle("SOX")
	bundle.AddRecord(evidence.Record{
		ID:        op.ID,
		Type:      "governance",
		Action:    "treasury_operation",
		Actor:     op.Initiator,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"amount":    fmt.Sprintf("%.2f", op.Amount),
			"currency":  op.Currency,
			"approvals": fmt.Sprintf("%d", status.CurrentApprovals),
			"status":    string(op.Status),
		},
	})
	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("bundle finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}
}

// =========================================================================
// Test 9: Defense Air Gap with CMMC
// =========================================================================

func TestDefenseAirGapWithCMMC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Validate air-gap configuration.
	agConfig := sovereign.AirGapConfig{
		DisableExternalDNS:   true,
		DisableExternalHTTPS: true,
		LocalCertAuthority:   "dod-internal-ca",
		OfflineCRL:           true,
		SnapshotFrequency:    6 * time.Hour,
		TransferMedium:       sovereign.TransferSecureCourier,
		MaxBundleAge:         24 * time.Hour,
	}
	if err := agConfig.Validate(); err != nil {
		t.Fatalf("air-gap config validation failed: %v", err)
	}

	// Step 2: Create air-gap manager and prepare bundle.
	mgr, err := sovereign.NewAirGapManager(agConfig)
	if err != nil {
		t.Fatalf("creating air-gap manager: %v", err)
	}
	agBundle, err := mgr.PrepareAirGapBundle(ctx, "1.0.0")
	if err != nil {
		t.Fatalf("preparing air-gap bundle: %v", err)
	}
	if agBundle.Version != "1.0.0" {
		t.Fatalf("expected bundle version 1.0.0, got %s", agBundle.Version)
	}

	// Step 3: Validate bundle.
	if err := sovereign.ValidateBundle(agBundle); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}

	// Step 4: Run CMMC assessment.
	cmmcAssessor := defense.NewCMMCAssessor()
	assessment, err := cmmcAssessor.AssessCMMC(ctx, defense.CMMCLevel2)
	if err != nil {
		t.Fatalf("CMMC assessment failed: %v", err)
	}
	if assessment.TargetLevel != defense.CMMCLevel2 {
		t.Fatalf("expected level 2, got %v", assessment.TargetLevel)
	}

	// Step 5: Build evidence bundle.
	bundle := evidence.NewEvidenceBundle("CMMC 2.0")
	bundle.AddRecord(evidence.Record{
		ID:        "cmmc-assessment-1",
		Type:      "audit",
		Action:    "cmmc_assessment",
		Actor:     "defense-assessor",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"level":           fmt.Sprintf("%d", int(assessment.TargetLevel)),
			"practices_met":   fmt.Sprintf("%d", assessment.SatisfiedPractices),
			"practices_total": fmt.Sprintf("%d", assessment.TotalPractices),
		},
	})
	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("bundle finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}
}

// =========================================================================
// Test 10: Sovereign Deployment with Compliance
// =========================================================================

func TestSovereignDeploymentWithCompliance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Step 1: Create sovereign controller.
	controller, err := sovereign.NewSovereignController(sovereign.ControllerConfig{
		DefaultMode:            sovereign.OnPrem,
		AllowedRegions:         []string{"eu-west-1", "eu-central-1", "us-east-1"},
		ComplianceRequirements: []string{"GDPR", "SOC 2"},
	})
	if err != nil {
		t.Fatalf("creating sovereign controller: %v", err)
	}

	// Step 2: Deploy to an allowed region.
	deployment, err := controller.Deploy(ctx, sovereign.DeploymentSpec{
		Name:   "prod-eu-west",
		Mode:   sovereign.OnPrem,
		Region: "eu-west-1",
	})
	if err != nil {
		t.Fatalf("creating deployment: %v", err)
	}
	if deployment.ID == "" {
		t.Fatal("expected deployment ID")
	}

	// Step 3: Verify disallowed region is rejected.
	_, err = controller.Deploy(ctx, sovereign.DeploymentSpec{
		Name:   "prod-cn",
		Mode:   sovereign.Cloud,
		Region: "cn-north-1",
	})
	if err == nil {
		t.Fatal("expected error for disallowed region")
	}

	// Step 4: Run compliance framework validation.
	fw := frameworks.SOC2()
	if err := fw.Validate(); err != nil {
		t.Fatalf("SOC 2 framework validation failed: %v", err)
	}

	// Step 5: Build evidence of compliant deployment.
	bundle := evidence.NewEvidenceBundle("SOC 2 Type II")
	bundle.AddRecord(evidence.Record{
		ID:        deployment.ID,
		Type:      "audit",
		Action:    "sovereign_deployment",
		Actor:     "deployment-controller",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: map[string]string{
			"region":     "eu-west-1",
			"mode":       sovereign.OnPrem.String(),
			"compliance": "GDPR,SOC 2",
		},
	})
	if err := bundle.Finalize(""); err != nil {
		t.Fatalf("bundle finalize failed: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sha256Bytes(data string) []byte {
	h := sha256.Sum256([]byte(data))
	return h[:]
}
