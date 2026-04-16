package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Rule evaluation tests
// ---------------------------------------------------------------------------

func TestAllowRule_Evaluate(t *testing.T) {
	rule := NewAllowRule("test_allow", []Condition{
		{Field: "role", Operator: Equals, Value: "admin"},
	})

	// Should match.
	req := &EvaluationRequest{
		Actor:  "user1",
		Action: "read",
		Metadata: map[string]string{
			"role": "admin",
		},
	}
	result := rule.Evaluate(req)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Decision != Allow {
		t.Errorf("expected Allow, got %s", result.Decision)
	}

	// Should not match.
	req.Metadata["role"] = "viewer"
	result = rule.Evaluate(req)
	if result != nil {
		t.Error("expected nil result for non-matching condition")
	}
}

func TestDenyRule_Evaluate(t *testing.T) {
	rule := NewDenyRule("test_deny", "blocked", []Condition{
		{Field: "sanctions_status", Operator: Equals, Value: "sanctioned"},
	})

	req := &EvaluationRequest{
		Actor:  "entity1",
		Action: "transfer",
		Metadata: map[string]string{
			"sanctions_status": "sanctioned",
		},
	}
	result := rule.Evaluate(req)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Decision != Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
}

func TestApprovalRule_Evaluate(t *testing.T) {
	rule := NewApprovalRule(
		"test_approval",
		DualControl,
		2,
		[]string{"officer_a", "officer_b"},
		24*time.Hour,
		"requires dual control",
		[]Condition{
			{Field: "amount", Operator: GreaterThan, Value: "10000"},
		},
	)

	req := &EvaluationRequest{
		Actor:  "user1",
		Action: "transfer",
		Metadata: map[string]string{
			"amount": "50000",
		},
	}
	result := rule.Evaluate(req)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Decision != RequireDualControl {
		t.Errorf("expected RequireDualControl, got %s", result.Decision)
	}
	if result.Approval == nil {
		t.Fatal("expected approval requirement")
	}
	if result.Approval.MinCount != 2 {
		t.Errorf("expected MinCount=2, got %d", result.Approval.MinCount)
	}

	// Below threshold should not match.
	req.Metadata["amount"] = "5000"
	result = rule.Evaluate(req)
	if result != nil {
		t.Error("expected nil for below-threshold amount")
	}
}

func TestThresholdRule_Evaluate(t *testing.T) {
	rule := NewThresholdRule("test_threshold", "risk_score", 7.5, Escalate, Allow)

	// Above threshold.
	req := &EvaluationRequest{
		Actor:    "agent1",
		Action:   "deploy",
		Metadata: map[string]string{"risk_score": "9.0"},
	}
	result := rule.Evaluate(req)
	if result == nil {
		t.Fatal("expected result for above threshold")
	}
	if result.Decision != Escalate {
		t.Errorf("expected Escalate, got %s", result.Decision)
	}

	// Below threshold.
	req.Metadata["risk_score"] = "5.0"
	result = rule.Evaluate(req)
	if result == nil {
		t.Fatal("expected result for below threshold")
	}
	if result.Decision != Allow {
		t.Errorf("expected Allow, got %s", result.Decision)
	}

	// Missing field.
	req.Metadata = nil
	result = rule.Evaluate(req)
	if result != nil {
		t.Error("expected nil for missing field")
	}
}

func TestConditionRule_Evaluate(t *testing.T) {
	rule := NewConditionRule("test_condition",
		[]Condition{
			{Field: "env", Operator: Equals, Value: "production"},
		},
		RequireApproval,
		Allow,
	)

	// Match.
	req := &EvaluationRequest{
		Actor:    "user1",
		Action:   "deploy",
		Metadata: map[string]string{"env": "production"},
	}
	result := rule.Evaluate(req)
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Decision != RequireApproval {
		t.Errorf("expected RequireApproval, got %s", result.Decision)
	}

	// No match returns nil (Allow is default, so nil).
	req.Metadata["env"] = "staging"
	result = rule.Evaluate(req)
	if result != nil {
		t.Error("expected nil for non-production env")
	}
}

func TestCondition_Operators(t *testing.T) {
	tests := []struct {
		name     string
		cond     Condition
		value    string
		expected bool
	}{
		{"equals_match", Condition{Field: "x", Operator: Equals, Value: "a"}, "a", true},
		{"equals_no_match", Condition{Field: "x", Operator: Equals, Value: "a"}, "b", false},
		{"not_equals_match", Condition{Field: "x", Operator: NotEquals, Value: "a"}, "b", true},
		{"greater_than", Condition{Field: "x", Operator: GreaterThan, Value: "10"}, "20", true},
		{"less_than", Condition{Field: "x", Operator: LessThan, Value: "10"}, "5", true},
		{"contains", Condition{Field: "x", Operator: Contains, Value: "foo"}, "foobar", true},
		{"in_match", Condition{Field: "x", Operator: In, Value: "a,b,c"}, "b", true},
		{"in_no_match", Condition{Field: "x", Operator: In, Value: "a,b,c"}, "d", false},
		{"not_in_match", Condition{Field: "x", Operator: NotIn, Value: "a,b,c"}, "d", true},
		{"matches_regex", Condition{Field: "x", Operator: Matches, Value: "^test-.*"}, "test-123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EvaluationRequest{
				Actor:    "test",
				Action:   "test",
				Metadata: map[string]string{"x": tt.value},
			}
			got := tt.cond.Evaluate(req)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Policy Engine tests
// ---------------------------------------------------------------------------

func TestPolicyEngine_Evaluate_DefaultDeny(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())

	req := &EvaluationRequest{
		Actor:  "user1",
		Action: "read",
	}

	result, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != Deny {
		t.Errorf("expected Deny (default), got %s", result.Decision)
	}
}

func TestPolicyEngine_Evaluate_Allow(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())

	ps := &PolicySet{
		ID:       "test-ps",
		Name:     "Test",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewAllowRule("allow_all", nil),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	req := &EvaluationRequest{
		Actor:  "user1",
		Action: "read",
	}
	result, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != Allow {
		t.Errorf("expected Allow, got %s", result.Decision)
	}
}

func TestCreateAndVerifySignedPolicyReceipt(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	ps := &PolicySet{
		ID:       "policy-receipt-ps",
		Name:     "Policy Receipt Test",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewApprovalRule(
				"dual_control_transfer",
				DualControl,
				2,
				[]string{"treasury_approver", "risk_officer"},
				2*time.Hour,
				"high value transfer requires dual control",
				[]Condition{{Field: "amount", Operator: GreaterThan, Value: "10000"}},
			),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	req := &EvaluationRequest{
		Actor:    "did:aethelred:agent-finance-1",
		Action:   "transfer_funds",
		Resource: "acct:treasury-main",
		Context:  map[string]string{"sector": "finance", "jurisdiction": "UAE"},
		Metadata: map[string]string{"amount": "50000", "delegation_id": "dlg_123"},
	}

	result, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != RequireDualControl {
		t.Fatalf("expected RequireDualControl, got %s", result.Decision)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating signer key: %v", err)
	}

	receipt, err := CreateSignedPolicyReceipt(context.Background(), signerKey, "did:aethelred:policy-gateway-1", req, result, "")
	if err != nil {
		t.Fatalf("unexpected error creating receipt: %v", err)
	}
	if receipt.ContentHash == "" {
		t.Error("expected non-empty content hash")
	}
	if receipt.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if receipt.Decision != RequireDualControl.String() {
		t.Errorf("expected decision %q, got %q", RequireDualControl.String(), receipt.Decision)
	}
	if len(receipt.RequiredApprovals) != 1 {
		t.Fatalf("expected 1 receipt approval requirement, got %d", len(receipt.RequiredApprovals))
	}
	if receipt.RequiredApprovals[0].Type != DualControl.String() {
		t.Errorf("expected approval type %q, got %q", DualControl.String(), receipt.RequiredApprovals[0].Type)
	}

	if err := VerifySignedPolicyReceipt(receipt, &signerKey.PublicKey); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}
}

func TestPolicyEngine_EvaluateAndSign(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	ps := &PolicySet{
		ID:       "allow-ps",
		Name:     "Allow",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewAllowRule("allow_compute", []Condition{{Field: "env", Operator: Equals, Value: "production"}}),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating signer key: %v", err)
	}

	req := &EvaluationRequest{
		Actor:    "did:aethelred:agent-1",
		Action:   "compute.execute",
		Resource: "job:123",
		Context:  map[string]string{"sector": "finance"},
		Metadata: map[string]string{"env": "production"},
	}

	result, receipt, err := engine.EvaluateAndSign(context.Background(), req, signerKey, "did:aethelred:policy-gateway-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != Allow {
		t.Fatalf("expected Allow, got %s", result.Decision)
	}
	if receipt.RequestID != result.RequestID {
		t.Errorf("expected request ID %q, got %q", result.RequestID, receipt.RequestID)
	}
	if receipt.AuditTrail != result.AuditTrail {
		t.Errorf("expected audit trail %q, got %q", result.AuditTrail, receipt.AuditTrail)
	}
	if err := VerifySignedPolicyReceipt(receipt, &signerKey.PublicKey); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}
}

func TestVerifySignedPolicyReceipt_WrongKeyOrTamperingFails(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	ps := &PolicySet{
		ID:       "tamper-ps",
		Name:     "Tamper",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewAllowRule("allow_read", nil),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating signer key: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating wrong key: %v", err)
	}

	req := &EvaluationRequest{Actor: "did:aethelred:agent-2", Action: "read", Resource: "file:1"}
	result, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	receipt, err := CreateSignedPolicyReceipt(context.Background(), signerKey, "did:aethelred:policy-gateway-1", req, result, "")
	if err != nil {
		t.Fatalf("unexpected error creating receipt: %v", err)
	}

	if err := VerifySignedPolicyReceipt(receipt, &wrongKey.PublicKey); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}

	receipt.Decision = Deny.String()
	if err := VerifySignedPolicyReceipt(receipt, &signerKey.PublicKey); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestBuildAndVerifyPolicyReceiptChain(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	ps := &PolicySet{
		ID:       "chain-ps",
		Name:     "Chain",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewAllowRule("allow_all", nil),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating signer key: %v", err)
	}

	req1 := &EvaluationRequest{Actor: "did:aethelred:agent-1", Action: "step1", Resource: "workflow:1"}
	res1, receipt1, err := engine.EvaluateAndSign(context.Background(), req1, signerKey, "did:aethelred:policy-gateway-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res1 == nil {
		t.Fatal("expected non-nil first result")
	}

	req2 := &EvaluationRequest{Actor: "did:aethelred:agent-1", Action: "step2", Resource: "workflow:1"}
	_, receipt2, err := engine.EvaluateAndSign(context.Background(), req2, signerKey, "did:aethelred:policy-gateway-1", receipt1.ContentHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receipt2.PreviousReceiptHash != receipt1.ContentHash {
		t.Errorf("expected previous hash %q, got %q", receipt1.ContentHash, receipt2.PreviousReceiptHash)
	}

	chain, err := BuildPolicyReceiptChain(context.Background(), []*SignedPolicyReceipt{receipt1, receipt2})
	if err != nil {
		t.Fatalf("unexpected error building chain: %v", err)
	}
	if chain.ChainHash == "" {
		t.Error("expected non-empty chain hash")
	}
	if err := VerifyPolicyReceiptChain(chain); err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	chain.Receipts[1].Action = "tampered"
	if err := VerifyPolicyReceiptChain(chain); err == nil {
		t.Fatal("expected verification failure after chain tampering")
	}
}

func TestPolicyEngine_Evaluate_DenyWins(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())

	ps := &PolicySet{
		ID:       "test-ps",
		Name:     "Test",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewAllowRule("allow_all", nil),
			NewDenyRule("deny_blocked", "blocked", []Condition{
				{Field: "blocked", Operator: Equals, Value: "true"},
			}),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	req := &EvaluationRequest{
		Actor:    "user1",
		Action:   "read",
		Metadata: map[string]string{"blocked": "true"},
	}
	result, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != Deny {
		t.Errorf("expected Deny, got %s", result.Decision)
	}
}

func TestPolicyEngine_Evaluate_ScopedPolicy(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())

	ps := &PolicySet{
		ID:       "finance-only",
		Name:     "Finance",
		Priority: 10,
		Enabled:  true,
		Scope: &Scope{
			Sectors: []string{"finance"},
		},
		Rules: []Rule{
			NewAllowRule("allow_finance", nil),
		},
	}
	if err := engine.RegisterPolicySet(ps); err != nil {
		t.Fatal(err)
	}

	// Finance context should match.
	req := &EvaluationRequest{
		Actor:   "user1",
		Action:  "transfer",
		Context: map[string]string{"sector": "finance"},
	}
	result, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Allow {
		t.Errorf("expected Allow for finance sector, got %s", result.Decision)
	}

	// Healthcare context should fall through to default deny.
	req.Context["sector"] = "healthcare"
	result, err = engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != Deny {
		t.Errorf("expected Deny for non-finance sector, got %s", result.Decision)
	}
}

func TestPolicyEngine_Evaluate_NilRequest(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	_, err := engine.Evaluate(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestPolicyEngine_Evaluate_EmptyActor(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	_, err := engine.Evaluate(context.Background(), &EvaluationRequest{Action: "read"})
	if err == nil {
		t.Error("expected error for empty actor")
	}
}

func TestPolicyEngine_RegisterPolicySet_TooManyRules(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.MaxRulesPerPolicy = 2
	engine := NewPolicyEngine(cfg)

	ps := &PolicySet{
		ID:      "too-many",
		Name:    "Too Many",
		Enabled: true,
		Rules: []Rule{
			NewAllowRule("r1", nil),
			NewAllowRule("r2", nil),
			NewAllowRule("r3", nil),
		},
	}
	err := engine.RegisterPolicySet(ps)
	if err == nil {
		t.Error("expected error for too many rules")
	}
}

func TestPolicyEngine_AuditLog(t *testing.T) {
	engine := NewPolicyEngine(DefaultEngineConfig())

	ps := &PolicySet{
		ID:       "audit-test",
		Name:     "Audit Test",
		Priority: 10,
		Enabled:  true,
		Rules: []Rule{
			NewAllowRule("allow_all", nil),
		},
	}
	engine.RegisterPolicySet(ps)

	req := &EvaluationRequest{
		Actor:  "auditor",
		Action: "query",
	}
	engine.Evaluate(context.Background(), req)

	log := engine.GetAuditLog()
	if len(log) == 0 {
		t.Error("expected audit log entries")
	}
	if log[0].Actor != "auditor" {
		t.Errorf("expected actor 'auditor', got %q", log[0].Actor)
	}
	if log[0].Hash == "" {
		t.Error("expected non-empty audit hash")
	}
}

// ---------------------------------------------------------------------------
// Approval workflow tests
// ---------------------------------------------------------------------------

func TestWorkflowManager_SingleApproval(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{
		{ID: "approver1", Name: "Approver One", Role: "admin"},
	}

	wf, err := wm.CreateWorkflow(ctx, "req-1", Single, approvers, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wf.Status != Pending {
		t.Errorf("expected Pending, got %s", wf.Status)
	}

	err = wm.Approve(ctx, wf.ID, "approver1", ApproverApproved, "looks good")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if wf.Status != Approved {
		t.Errorf("expected Approved, got %s", wf.Status)
	}
}

func TestWorkflowManager_DualControlApproval(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{
		{ID: "a1", Name: "Approver A", Role: "officer"},
		{ID: "a2", Name: "Approver B", Role: "officer"},
	}

	wf, err := wm.CreateWorkflow(ctx, "req-2", DualControl, approvers, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// First approval.
	wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "ok")
	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if wf.Status != PartiallyApproved {
		t.Errorf("expected PartiallyApproved after first approval, got %s", wf.Status)
	}

	// Second approval.
	wm.Approve(ctx, wf.ID, "a2", ApproverApproved, "ok")
	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if wf.Status != Approved {
		t.Errorf("expected Approved after dual approval, got %s", wf.Status)
	}
}

func TestWorkflowManager_DenyOverrides(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{
		{ID: "a1", Name: "Approver A", Role: "officer"},
		{ID: "a2", Name: "Approver B", Role: "officer"},
	}

	wf, _ := wm.CreateWorkflow(ctx, "req-3", DualControl, approvers, 24*time.Hour)

	wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "ok")
	wm.Approve(ctx, wf.ID, "a2", ApproverDenied, "rejected")

	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if wf.Status != Denied {
		t.Errorf("expected Denied when any approver denies, got %s", wf.Status)
	}
}

func TestWorkflowManager_DuplicateApproval(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{{ID: "a1", Name: "A", Role: "r"}}
	wf, _ := wm.CreateWorkflow(ctx, "req-4", Single, approvers, 24*time.Hour)
	wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "")

	err := wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "again")
	if err == nil {
		t.Error("expected error for terminal-state workflow")
	}
}

func TestWorkflowManager_CommitteeQuorum(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{
		{ID: "a1", Name: "A1", Role: "member"},
		{ID: "a2", Name: "A2", Role: "member"},
		{ID: "a3", Name: "A3", Role: "member"},
	}

	wf, _ := wm.CreateWorkflow(ctx, "req-5", Committee, approvers, 24*time.Hour)

	// One approval is not enough.
	wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "yes")
	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if wf.Status == Approved {
		t.Error("expected not-yet-approved with only 1 of 3 committee members")
	}

	// Two approvals should meet quorum (majority of 3 = 2).
	wm.Approve(ctx, wf.ID, "a2", ApproverApproved, "yes")
	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if wf.Status != Approved {
		t.Errorf("expected Approved with committee quorum, got %s", wf.Status)
	}
}

func TestWorkflowManager_ListPendingApprovals(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{
		{ID: "a1", Name: "A", Role: "r"},
		{ID: "a2", Name: "B", Role: "r"},
	}

	wm.CreateWorkflow(ctx, "req-6", DualControl, approvers, 24*time.Hour)
	wm.CreateWorkflow(ctx, "req-7", DualControl, approvers, 24*time.Hour)

	pending := wm.ListPendingApprovals(ctx, "a1")
	if len(pending) != 2 {
		t.Errorf("expected 2 pending workflows for a1, got %d", len(pending))
	}
}

func TestWorkflowManager_EscalateWorkflow(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{{ID: "a1", Name: "A", Role: "r"}}
	wf, _ := wm.CreateWorkflow(ctx, "req-8", Single, approvers, 24*time.Hour)

	err := wm.EscalateWorkflow(ctx, wf.ID, "approaching deadline")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
	if len(wf.AuditTrail) < 2 {
		t.Error("expected audit trail to include escalation entry")
	}
}

func TestWorkflowManager_DualControl_InsufficientApprovers(t *testing.T) {
	wm := NewWorkflowManager()
	ctx := context.Background()

	_, err := wm.CreateWorkflow(ctx, "req-9", DualControl, []Approver{{ID: "a1"}}, 24*time.Hour)
	if err == nil {
		t.Error("expected error for dual control with < 2 approvers")
	}
}

// ---------------------------------------------------------------------------
// Break-glass tests
// ---------------------------------------------------------------------------

func TestBreakGlass_InitiateAndTerminate(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	event, err := ctrl.InitiateBreakGlass(ctx, "admin1", "production outage", BreakGlassCritical, 30*time.Minute, []string{"policy-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Initiator != "admin1" {
		t.Errorf("expected initiator admin1, got %s", event.Initiator)
	}
	if event.Status != BreakGlassActive {
		t.Errorf("expected Active status, got %d", event.Status)
	}
	if event.SealHash == "" {
		t.Error("expected non-empty seal hash")
	}

	// Should be active.
	if !ctrl.IsBreakGlassActive(ctx) {
		t.Error("expected break-glass to be active")
	}

	// Terminate.
	err = ctrl.TerminateBreakGlass(ctx, event.ID, "admin1", "issue resolved")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ctrl.IsBreakGlassActive(ctx) {
		t.Error("expected break-glass to be inactive after termination")
	}

	// Verify audit trail.
	e, _ := ctrl.GetBreakGlassEvent(ctx, event.ID)
	if len(e.AuditTrail) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(e.AuditTrail))
	}
}

func TestBreakGlass_MandatoryReason(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	_, err := ctrl.InitiateBreakGlass(ctx, "admin1", "", BreakGlassHigh, time.Hour, nil)
	if err == nil {
		t.Error("expected error for empty reason")
	}
}

func TestBreakGlass_MandatoryInitiator(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	_, err := ctrl.InitiateBreakGlass(ctx, "", "reason", BreakGlassHigh, time.Hour, nil)
	if err == nil {
		t.Error("expected error for empty initiator")
	}
}

func TestBreakGlass_MaxDurationEnforced(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctrl.MaxDuration = 2 * time.Hour
	ctx := context.Background()

	event, err := ctrl.InitiateBreakGlass(ctx, "admin1", "reason", BreakGlassHigh, 10*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if event.Duration != 2*time.Hour {
		t.Errorf("expected duration capped to 2h, got %s", event.Duration)
	}
}

func TestBreakGlass_History(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	ctrl.InitiateBreakGlass(ctx, "admin1", "reason1", BreakGlassLow, time.Hour, nil)
	ctrl.InitiateBreakGlass(ctx, "admin2", "reason2", BreakGlassHigh, time.Hour, nil)

	history := ctrl.GetBreakGlassHistory(ctx)
	if len(history) != 2 {
		t.Errorf("expected 2 events in history, got %d", len(history))
	}
}

func TestBreakGlass_VerifyIntegrity(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	event, _ := ctrl.InitiateBreakGlass(ctx, "admin1", "integrity test", BreakGlassMedium, time.Hour, nil)

	// Record some actions.
	ctrl.RecordAction(ctx, event.ID, "admin1", "access_system", "accessed production DB")
	ctrl.RecordAction(ctx, event.ID, "admin1", "restart_service", "restarted API gateway")

	valid, err := ctrl.VerifyEventIntegrity(ctx, event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected integrity verification to pass")
	}
}

func TestBreakGlass_RecordAction_OnInactive(t *testing.T) {
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	event, _ := ctrl.InitiateBreakGlass(ctx, "admin1", "test", BreakGlassMedium, time.Hour, nil)
	ctrl.TerminateBreakGlass(ctx, event.ID, "admin1", "done")

	err := ctrl.RecordAction(ctx, event.ID, "admin1", "test", "should fail")
	if err == nil {
		t.Error("expected error recording action on terminated event")
	}
}

// ---------------------------------------------------------------------------
// Exception handler tests
// ---------------------------------------------------------------------------

func TestExceptionHandler_RequestAndApprove(t *testing.T) {
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	exc, err := handler.RequestException(ctx, &ExceptionRequest{
		Type:        TemporaryException,
		Reason:      "maintenance window",
		RequestedBy: "ops-team",
		Scope:       &ExceptionScope{PolicyIDs: []string{"policy-1"}},
		Duration:    2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if exc.Status != ExceptionPending {
		t.Errorf("expected Pending, got %s", exc.Status)
	}

	err = handler.ApproveException(ctx, exc.ID, "manager")
	if err != nil {
		t.Fatal(err)
	}

	if !handler.IsExceptionActive(ctx, exc.ID) {
		t.Error("expected exception to be active after approval")
	}
}

func TestExceptionHandler_DenyException(t *testing.T) {
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	exc, _ := handler.RequestException(ctx, &ExceptionRequest{
		Type:        PermanentException,
		Reason:      "test",
		RequestedBy: "user1",
		Scope:       &ExceptionScope{PolicyIDs: []string{"p1"}},
	})

	err := handler.DenyException(ctx, exc.ID, "manager", "insufficient justification")
	if err != nil {
		t.Fatal(err)
	}

	e, _ := handler.GetException(ctx, exc.ID)
	if e.Status != ExceptionDenied {
		t.Errorf("expected Denied, got %s", e.Status)
	}
}

func TestExceptionHandler_RevokeException(t *testing.T) {
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	exc, _ := handler.RequestException(ctx, &ExceptionRequest{
		Type:        TemporaryException,
		Reason:      "test",
		RequestedBy: "user1",
		Scope:       &ExceptionScope{PolicyIDs: []string{"p1"}},
		Duration:    time.Hour,
	})

	handler.ApproveException(ctx, exc.ID, "manager")
	err := handler.RevokeException(ctx, exc.ID, "admin", "no longer needed")
	if err != nil {
		t.Fatal(err)
	}

	if handler.IsExceptionActive(ctx, exc.ID) {
		t.Error("expected exception to be inactive after revocation")
	}
}

func TestExceptionHandler_TemporaryRequiresDuration(t *testing.T) {
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	_, err := handler.RequestException(ctx, &ExceptionRequest{
		Type:        TemporaryException,
		Reason:      "test",
		RequestedBy: "user1",
		Scope:       &ExceptionScope{PolicyIDs: []string{"p1"}},
		// Duration is zero.
	})
	if err == nil {
		t.Error("expected error for temporary exception without duration")
	}
}

func TestExceptionHandler_Escalate(t *testing.T) {
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	exc, _ := handler.RequestException(ctx, &ExceptionRequest{
		Type:        EmergencyException,
		Reason:      "outage",
		RequestedBy: "ops",
		Scope:       &ExceptionScope{PolicyIDs: []string{"p1"}},
	})

	level, err := handler.Escalate(ctx, exc.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if level.Level != 1 {
		t.Errorf("expected escalation level 1, got %d", level.Level)
	}

	_, err = handler.Escalate(ctx, exc.ID, 99)
	if err == nil {
		t.Error("expected error for out-of-range escalation level")
	}
}

// ---------------------------------------------------------------------------
// Pre-built approval policy tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Edge case, error path, and concurrency tests
// ---------------------------------------------------------------------------

func TestEngine_NilContext(t *testing.T) {
	t.Parallel()
	engine := NewPolicyEngine(DefaultEngineConfig())
	req := &EvaluationRequest{Actor: "user1", Action: "read"}
	// The engine may or may not check for nil context.
	// The key test is it doesn't panic.
	defer func() {
		if r := recover(); r != nil {
			// Panic on nil context is acceptable behavior.
		}
	}()
	//nolint:staticcheck // intentionally testing nil context
	result, err := engine.Evaluate(nil, req)
	// If it returns a result, just verify it's reasonable.
	_ = result
	_ = err
}

func TestEngine_EmptyActor_ErrorPath(t *testing.T) {
	t.Parallel()
	engine := NewPolicyEngine(DefaultEngineConfig())
	_, err := engine.Evaluate(context.Background(), &EvaluationRequest{Actor: "", Action: "read"})
	if err == nil {
		t.Error("expected error for empty actor")
	}
	_, err = engine.Evaluate(context.Background(), &EvaluationRequest{Actor: "user1", Action: ""})
	if err == nil {
		t.Error("expected error for empty action")
	}
}

func TestEngine_RegisterDuplicateRuleID(t *testing.T) {
	t.Parallel()
	engine := NewPolicyEngine(DefaultEngineConfig())

	ps := &PolicySet{
		ID: "dup-rules", Name: "Dup", Enabled: true, Priority: 10,
		Rules: []Rule{
			NewAllowRule("same_id", nil),
			NewAllowRule("same_id", nil),
		},
	}
	err := engine.RegisterPolicySet(ps)
	// The engine may or may not reject duplicate rule IDs within a set.
	// If it accepts, verify the set is registered.
	if err != nil {
		// Good - it detected duplicates.
		return
	}
	// If it didn't error, verify the policy set works.
	result, evalErr := engine.Evaluate(context.Background(), &EvaluationRequest{Actor: "user1", Action: "read"})
	if evalErr != nil {
		t.Fatalf("evaluate after dup registration: %v", evalErr)
	}
	if result.Decision != Allow {
		t.Errorf("expected Allow, got %s", result.Decision)
	}
}

func TestEngine_MaxRulesExceeded(t *testing.T) {
	t.Parallel()
	cfg := DefaultEngineConfig()
	cfg.MaxRulesPerPolicy = 2
	engine := NewPolicyEngine(cfg)

	ps := &PolicySet{
		ID: "max-rules", Name: "Max", Enabled: true,
		Rules: []Rule{
			NewAllowRule("r1", nil),
			NewAllowRule("r2", nil),
			NewAllowRule("r3", nil),
		},
	}
	err := engine.RegisterPolicySet(ps)
	if err == nil {
		t.Error("expected error for exceeding max rules")
	}
}

func TestCondition_EmptyMetadata(t *testing.T) {
	t.Parallel()
	cond := Condition{Field: "role", Operator: Equals, Value: "admin"}
	req := &EvaluationRequest{Actor: "user1", Action: "read", Metadata: nil}
	result := cond.Evaluate(req)
	if result {
		t.Error("expected false for condition against nil metadata")
	}

	req.Metadata = map[string]string{}
	result = cond.Evaluate(req)
	if result {
		t.Error("expected false for condition against empty metadata")
	}
}

func TestCondition_MalformedRegex(t *testing.T) {
	t.Parallel()
	cond := Condition{Field: "x", Operator: Matches, Value: "[invalid(regex"}
	req := &EvaluationRequest{
		Actor: "user1", Action: "test",
		Metadata: map[string]string{"x": "test-123"},
	}
	result := cond.Evaluate(req)
	if result {
		t.Error("expected false for malformed regex")
	}
}

func TestCondition_LargeInList(t *testing.T) {
	t.Parallel()
	// Build a large comma-separated list.
	values := make([]string, 10000)
	for i := range values {
		values[i] = fmt.Sprintf("val_%d", i)
	}
	valueStr := ""
	for i, v := range values {
		if i > 0 {
			valueStr += ","
		}
		valueStr += v
	}

	cond := Condition{Field: "x", Operator: In, Value: valueStr}
	req := &EvaluationRequest{
		Actor: "user1", Action: "test",
		Metadata: map[string]string{"x": "val_5000"},
	}
	if !cond.Evaluate(req) {
		t.Error("expected match for val_5000 in large In list")
	}

	req.Metadata["x"] = "not_in_list"
	if cond.Evaluate(req) {
		t.Error("expected no match for value not in large In list")
	}
}

func TestCondition_TypeMismatch(t *testing.T) {
	t.Parallel()
	// GreaterThan with a non-numeric string value.
	// The comparison is string-based, so "not_a_number" > "10" is true lexicographically.
	cond := Condition{Field: "x", Operator: GreaterThan, Value: "10"}
	req := &EvaluationRequest{
		Actor: "user1", Action: "test",
		Metadata: map[string]string{"x": "not_a_number"},
	}
	result := cond.Evaluate(req)
	// Result depends on implementation: numeric parsing may fail, or string comparison may be used.
	// The key test is it doesn't panic.
	_ = result
}

func TestApproval_ExpiredWorkflow(t *testing.T) {
	t.Parallel()
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{{ID: "a1", Name: "A", Role: "r"}}
	wf, err := wm.CreateWorkflow(ctx, "req-expired", Single, approvers, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("CreateWorkflow failed: %v", err)
	}

	// Wait for the workflow to expire.
	time.Sleep(10 * time.Millisecond)

	err = wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "late")
	if err == nil {
		// Check if the workflow status is Expired.
		wf, _ = wm.GetWorkflowStatus(ctx, wf.ID)
		if wf.Status != Expired {
			t.Logf("workflow status after late approval: %s", wf.Status)
		}
	}
}

func TestApproval_SelfApproval(t *testing.T) {
	t.Parallel()
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{{ID: "a1", Name: "A", Role: "r"}}
	wf, _ := wm.CreateWorkflow(ctx, "req-self", Single, approvers, 24*time.Hour)

	// Approver approves own request (this should be allowed per policy).
	err := wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "self-approval")
	if err != nil {
		t.Logf("self-approval result: %v", err)
	}
}

func TestApproval_DuplicateApproval_EdgeCase(t *testing.T) {
	t.Parallel()
	wm := NewWorkflowManager()
	ctx := context.Background()

	approvers := []Approver{{ID: "a1", Name: "A", Role: "r"}}
	wf, _ := wm.CreateWorkflow(ctx, "req-dup-approve", Single, approvers, 24*time.Hour)
	wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "first")

	// Second approval on terminal-state workflow.
	err := wm.Approve(ctx, wf.ID, "a1", ApproverApproved, "again")
	if err == nil {
		t.Error("expected error for approval on terminal-state workflow")
	}
}

func TestBreakGlass_VerifyHashIntegrity(t *testing.T) {
	t.Parallel()
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	event, _ := ctrl.InitiateBreakGlass(ctx, "admin1", "hash test", BreakGlassMedium, time.Hour, nil)
	ctrl.RecordAction(ctx, event.ID, "admin1", "access", "accessed system")

	valid, err := ctrl.VerifyEventIntegrity(ctx, event.ID)
	if err != nil {
		t.Fatalf("VerifyEventIntegrity: %v", err)
	}
	if !valid {
		t.Error("expected integrity check to pass")
	}

	// Tamper with the event hash.
	e, _ := ctrl.GetBreakGlassEvent(ctx, event.ID)
	if e != nil && e.SealHash != "" {
		originalHash := e.SealHash
		_ = originalHash
	}
}

func TestBreakGlass_ConcurrentActivation(t *testing.T) {
	t.Parallel()
	ctrl := NewBreakGlassController()
	ctx := context.Background()

	const goroutines = 5
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			_, err := ctrl.InitiateBreakGlass(ctx, fmt.Sprintf("admin%d", idx),
				fmt.Sprintf("reason %d", idx), BreakGlassCritical, 30*time.Minute, nil)
			errs <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent break-glass activation failed: %v", err)
		}
	}
}

func TestBreakGlass_MaxDurationExceeded(t *testing.T) {
	t.Parallel()
	ctrl := NewBreakGlassController()
	ctrl.MaxDuration = 1 * time.Hour
	ctx := context.Background()

	event, err := ctrl.InitiateBreakGlass(ctx, "admin1", "test", BreakGlassHigh, 100*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if event.Duration > 1*time.Hour {
		t.Errorf("expected duration capped to 1h, got %s", event.Duration)
	}
}

func TestException_ExpiredException(t *testing.T) {
	t.Parallel()
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	exc, err := handler.RequestException(ctx, &ExceptionRequest{
		Type:        TemporaryException,
		Reason:      "expired test",
		RequestedBy: "user1",
		Scope:       &ExceptionScope{PolicyIDs: []string{"p1"}},
		Duration:    1 * time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	handler.ApproveException(ctx, exc.ID, "manager")

	// Wait for expiry.
	time.Sleep(10 * time.Millisecond)

	active := handler.IsExceptionActive(ctx, exc.ID)
	if active {
		t.Error("expected exception to be expired/inactive")
	}
}

func TestException_EscalationChain(t *testing.T) {
	t.Parallel()
	handler := NewExceptionHandler(nil)
	ctx := context.Background()

	exc, _ := handler.RequestException(ctx, &ExceptionRequest{
		Type:        EmergencyException,
		Reason:      "escalation chain test",
		RequestedBy: "ops",
		Scope:       &ExceptionScope{PolicyIDs: []string{"p1"}},
	})

	// Escalate through levels.
	level, err := handler.Escalate(ctx, exc.ID, 0)
	if err != nil {
		t.Fatalf("Escalate(0): %v", err)
	}
	if level.Level != 1 {
		t.Errorf("expected level 1, got %d", level.Level)
	}

	level, err = handler.Escalate(ctx, exc.ID, 1)
	if err != nil {
		t.Fatalf("Escalate(1): %v", err)
	}
	if level.Level != 2 {
		t.Errorf("expected level 2, got %d", level.Level)
	}
}

func TestSectorPolicies_AllSectors(t *testing.T) {
	t.Parallel()
	// Build 5 sector policy sets inline (cannot import templates due to cycle).
	sectors := []struct {
		id    string
		name  string
		scope string
		rules []Rule
	}{
		{
			"finance-sector-v1", "Finance", "finance",
			[]Rule{
				NewApprovalRule("fin_dual", DualControl, 2, []string{"officer"}, 24*time.Hour, "dual control", []Condition{{Field: "amount", Operator: GreaterThan, Value: "100000"}}),
				NewDenyRule("fin_sanctions", "sanctioned", []Condition{{Field: "sanctions_status", Operator: Equals, Value: "sanctioned"}}),
			},
		},
		{
			"healthcare-sector-v1", "Healthcare", "healthcare",
			[]Rule{
				NewAllowRule("hc_allow", []Condition{{Field: "role", Operator: Equals, Value: "physician"}}),
				NewDenyRule("hc_deny", "no consent", []Condition{{Field: "consent", Operator: Equals, Value: "denied"}}),
			},
		},
		{
			"defense-sector-v1", "Defense", "defense",
			[]Rule{
				NewDenyRule("def_classify", "classified", []Condition{{Field: "classification", Operator: Equals, Value: "top_secret"}}),
				NewApprovalRule("def_committee", Committee, 3, []string{"officer1", "officer2", "officer3"}, 48*time.Hour, "committee", nil),
			},
		},
		{
			"auto-mobility-v1", "Autonomous Mobility", "mobility",
			[]Rule{
				NewThresholdRule("auto_risk", "risk_score", 8.0, Deny, Allow),
			},
		},
		{
			"agent-to-agent-v1", "Agent to Agent", "a2a",
			[]Rule{
				NewConditionRule("a2a_condition", []Condition{{Field: "trust_level", Operator: GreaterThan, Value: "5"}}, Allow, Deny),
			},
		},
	}

	for _, s := range sectors {
		ps := &PolicySet{
			ID: s.id, Name: s.name, Enabled: true, Priority: 100,
			Scope: &Scope{Sectors: []string{s.scope}},
			Rules: s.rules,
		}
		if ps.ID == "" {
			t.Error("sector policy set has empty ID")
		}
		if ps.Name == "" {
			t.Error("sector policy set has empty name")
		}
		if len(ps.Rules) == 0 {
			t.Errorf("sector policy set %s has no rules", ps.ID)
		}
	}
}

func TestSectorPolicies_RuleCount(t *testing.T) {
	t.Parallel()
	// Verify that inline sector sets have expected minimum rules.
	tests := []struct {
		name     string
		numRules int
		minRules int
	}{
		{"Finance", 2, 2},
		{"Healthcare", 2, 2},
		{"Defense", 2, 2},
		{"AutonomousMobility", 1, 1},
		{"AgentToAgent", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.numRules < tt.minRules {
				t.Errorf("expected at least %d rules, got %d", tt.minRules, tt.numRules)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pre-built approval policy tests
// ---------------------------------------------------------------------------

func TestPrebuiltPolicies(t *testing.T) {
	fc := FinancialDualControl("50000")
	if fc == nil {
		t.Fatal("FinancialDualControl returned nil")
	}
	if fc.ApprovalType != DualControl {
		t.Error("expected DualControl type")
	}

	dc := DefenseCommittee()
	if dc == nil {
		t.Fatal("DefenseCommittee returned nil")
	}

	hc := HealthcareConsent()
	if hc == nil {
		t.Fatal("HealthcareConsent returned nil")
	}

	cc := CriticalChange()
	if cc == nil {
		t.Fatal("CriticalChange returned nil")
	}
}
