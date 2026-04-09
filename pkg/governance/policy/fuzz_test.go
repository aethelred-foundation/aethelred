package policy

import (
	"testing"
)

func FuzzConditionEvaluate(f *testing.F) {
	f.Add("risk_score", "50", "75")
	f.Add("sector", "finance", "finance")
	f.Add("action", "deploy", "transfer")
	f.Add("", "", "")
	f.Add("field", "value", "other")

	f.Fuzz(func(t *testing.T, field, condValue, metadataValue string) {
		operators := []Operator{
			Equals, NotEquals, GreaterThan, LessThan,
			GreaterThanOrEqual, LessThanOrEqual, Contains, In, NotIn, Matches,
		}

		for _, op := range operators {
			cond := &Condition{
				Field:    field,
				Operator: op,
				Value:    condValue,
			}
			req := &EvaluationRequest{
				Actor:    "fuzz-agent",
				Action:   "fuzz-action",
				Resource: "fuzz-resource",
				Metadata: map[string]string{field: metadataValue},
			}
			// Must not panic.
			_ = cond.Evaluate(req)
		}
	})
}

func FuzzRuleEvaluation(f *testing.F) {
	f.Add("deploy_model", "finance", "agent-001")
	f.Add("", "", "")
	f.Add("transfer_funds", "healthcare", "did:aethelred:abc123")
	f.Add("delete_data", "defense", "system")

	f.Fuzz(func(t *testing.T, action, sector, actor string) {
		rule := NewAllowRule("fuzz-rule", []Condition{
			{Field: "action", Operator: Equals, Value: action},
			{Field: "sector", Operator: Equals, Value: sector},
		})

		req := &EvaluationRequest{
			Actor:    actor,
			Action:   action,
			Resource: "fuzz-resource",
			Context:  map[string]string{"sector": sector},
			Metadata: map[string]string{"action": action, "sector": sector},
		}
		// Must not panic.
		_ = rule.Evaluate(req)
	})
}
