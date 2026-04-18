package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkRuleEvaluation_Allow(b *testing.B) {
	rule := NewAllowRule("bench-allow", []Condition{
		{Field: "action", Operator: Equals, Value: "deploy_model"},
	})
	req := &EvaluationRequest{
		Actor:    "agent-001",
		Action:   "deploy_model",
		Resource: "model-123",
		Metadata: map[string]string{"action": "deploy_model"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Evaluate(req)
	}
}

func BenchmarkRuleEvaluation_Condition(b *testing.B) {
	cond := &Condition{
		Field:    "risk_score",
		Operator: GreaterThan,
		Value:    "50",
	}
	req := &EvaluationRequest{
		Actor:    "agent-001",
		Action:   "transfer_funds",
		Resource: "account-456",
		Metadata: map[string]string{"risk_score": "75"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cond.Evaluate(req)
	}
}

func BenchmarkPolicyEngineEvaluate(b *testing.B) {
	engine := NewPolicyEngine(DefaultEngineConfig())
	// Register 10 policy sets with varying rules.
	for j := 0; j < 10; j++ {
		ps := &PolicySet{
			ID:       fmt.Sprintf("ps-%d", j),
			Name:     fmt.Sprintf("PolicySet %d", j),
			Priority: j,
			Enabled:  true,
			Rules: []Rule{
				NewAllowRule(fmt.Sprintf("allow-%d", j), []Condition{
					{Field: "sector", Operator: Equals, Value: fmt.Sprintf("sector-%d", j)},
				}),
			},
		}
		_ = engine.RegisterPolicySet(ps)
	}

	req := &EvaluationRequest{
		Actor:    "agent-bench",
		Action:   "deploy_model",
		Resource: "model-bench",
		Context:  map[string]string{"sector": "sector-5"},
		Metadata: map[string]string{"sector": "sector-5"},
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Evaluate(ctx, req)
	}
}

func BenchmarkApprovalWorkflow(b *testing.B) {
	wm := NewWorkflowManager()
	ctx := context.Background()
	approvers := []Approver{
		{ID: "approver-1", Name: "Alice", Role: "admin", Authority: 10},
		{ID: "approver-2", Name: "Bob", Role: "admin", Authority: 10},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wf, err := wm.CreateWorkflow(ctx, fmt.Sprintf("req-%d", i), DualControl, approvers, 24*time.Hour)
		if err != nil {
			b.Fatalf("CreateWorkflow failed: %v", err)
		}
		_ = wm.Approve(ctx, wf.ID, "approver-1", ApproverApproved, "approved")
		_ = wm.Approve(ctx, wf.ID, "approver-2", ApproverApproved, "approved")
	}
}
