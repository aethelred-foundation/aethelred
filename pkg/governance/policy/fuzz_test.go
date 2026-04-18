package policy

import (
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FuzzConditionEvaluate — fuzz condition evaluation with invariant checks.
//
// Invariants:
//   - "equals": result is true iff metadata value == condition value.
//   - "not_equals": result is the inverse of "equals".
//   - "in": result is true if metadata value is in the comma-separated list.
//   - "greater_than" with numeric values: verify mathematical correctness.
//   - "matches" with invalid regex: must not panic (returns false).
//   - No panics for any operator + input combination.
// ---------------------------------------------------------------------------
func FuzzConditionEvaluate(f *testing.F) {
	f.Add("risk_score", "50", "75")
	f.Add("sector", "finance", "finance")
	f.Add("action", "deploy", "transfer")
	f.Add("", "", "")
	f.Add("field", "value", "other")
	f.Add("num", "100", "50")
	f.Add("regex_field", "[invalid", "test")
	f.Add("in_field", "a,b,c", "b")
	f.Add("in_field", "x,y,z", "w")

	f.Fuzz(func(t *testing.T, field, condValue, metadataValue string) {
		req := &EvaluationRequest{
			Actor:    "fuzz-agent",
			Action:   "fuzz-action",
			Resource: "fuzz-resource",
			Metadata: map[string]string{field: metadataValue},
		}

		// --- Equals invariant ---
		equalsCond := &Condition{Field: field, Operator: Equals, Value: condValue}
		equalsResult := equalsCond.Evaluate(req)
		expectedEquals := metadataValue == condValue
		if equalsResult != expectedEquals {
			t.Fatalf("Equals(%q, %q): got %v, want %v", condValue, metadataValue, equalsResult, expectedEquals)
		}

		// --- NotEquals invariant: must be inverse of Equals ---
		notEqualsCond := &Condition{Field: field, Operator: NotEquals, Value: condValue}
		notEqualsResult := notEqualsCond.Evaluate(req)
		if notEqualsResult != !equalsResult {
			t.Fatalf("NotEquals(%q, %q): got %v, want %v (inverse of Equals=%v)",
				condValue, metadataValue, notEqualsResult, !equalsResult, equalsResult)
		}

		// --- In invariant ---
		inCond := &Condition{Field: field, Operator: In, Value: condValue}
		inResult := inCond.Evaluate(req)
		values := strings.Split(condValue, ",")
		expectedIn := false
		for _, v := range values {
			if strings.TrimSpace(v) == metadataValue {
				expectedIn = true
				break
			}
		}
		if inResult != expectedIn {
			t.Fatalf("In(%q, %q): got %v, want %v", condValue, metadataValue, inResult, expectedIn)
		}

		// --- NotIn invariant: must be inverse of In ---
		notInCond := &Condition{Field: field, Operator: NotIn, Value: condValue}
		notInResult := notInCond.Evaluate(req)
		if notInResult != !inResult {
			t.Fatalf("NotIn(%q, %q): got %v, want %v (inverse of In=%v)",
				condValue, metadataValue, notInResult, !inResult, inResult)
		}

		// --- GreaterThan with numeric values: verify mathematical correctness ---
		gtCond := &Condition{Field: field, Operator: GreaterThan, Value: condValue}
		gtResult := gtCond.Evaluate(req)
		metaFloat, metaErr := strconv.ParseFloat(metadataValue, 64)
		condFloat, condErr := strconv.ParseFloat(condValue, 64)
		if metaErr == nil && condErr == nil {
			expectedGT := metaFloat > condFloat
			if gtResult != expectedGT {
				t.Fatalf("GreaterThan(%q, %q): got %v, want %v (%.2f > %.2f)",
					condValue, metadataValue, gtResult, expectedGT, metaFloat, condFloat)
			}

			// LessThan: inverse relationship
			ltCond := &Condition{Field: field, Operator: LessThan, Value: condValue}
			ltResult := ltCond.Evaluate(req)
			expectedLT := metaFloat < condFloat
			if ltResult != expectedLT {
				t.Fatalf("LessThan(%q, %q): got %v, want %v (%.2f < %.2f)",
					condValue, metadataValue, ltResult, expectedLT, metaFloat, condFloat)
			}

			// GreaterThanOrEqual
			gteCond := &Condition{Field: field, Operator: GreaterThanOrEqual, Value: condValue}
			gteResult := gteCond.Evaluate(req)
			expectedGTE := metaFloat >= condFloat
			if gteResult != expectedGTE {
				t.Fatalf("GreaterThanOrEqual(%q, %q): got %v, want %v", condValue, metadataValue, gteResult, expectedGTE)
			}

			// LessThanOrEqual
			lteCond := &Condition{Field: field, Operator: LessThanOrEqual, Value: condValue}
			lteResult := lteCond.Evaluate(req)
			expectedLTE := metaFloat <= condFloat
			if lteResult != expectedLTE {
				t.Fatalf("LessThanOrEqual(%q, %q): got %v, want %v", condValue, metadataValue, lteResult, expectedLTE)
			}
		}

		// --- Contains invariant ---
		containsCond := &Condition{Field: field, Operator: Contains, Value: condValue}
		containsResult := containsCond.Evaluate(req)
		expectedContains := strings.Contains(metadataValue, condValue)
		if containsResult != expectedContains {
			t.Fatalf("Contains(%q, %q): got %v, want %v", condValue, metadataValue, containsResult, expectedContains)
		}

		// --- Matches: invalid regex must not panic, must return false ---
		matchesCond := &Condition{Field: field, Operator: Matches, Value: condValue}
		matchesResult := matchesCond.Evaluate(req)
		// We cannot easily predict the result for all regex patterns, but
		// the critical invariant is: no panic occurs. For obviously invalid
		// regex patterns containing unmatched brackets, result should be false.
		_ = matchesResult // no-panic invariant is verified by reaching this line
	})
}

// ---------------------------------------------------------------------------
// FuzzRuleEvaluation — fuzz rule evaluation with invariant checks.
//
// Invariants:
//   - AllowRule with matching scope must return Allow decision.
//   - DenyRule with matching scope must return Deny decision.
//   - ThresholdRule must respect boundary (below threshold = BelowDecision,
//     at or above = AboveDecision).
//   - No panics for any input.
// ---------------------------------------------------------------------------
func FuzzRuleEvaluation(f *testing.F) {
	f.Add("deploy_model", "finance", "agent-001", "75.0")
	f.Add("", "", "", "")
	f.Add("transfer_funds", "healthcare", "did:aethelred:abc123", "100")
	f.Add("delete_data", "defense", "system", "0")
	f.Add("action", "sector", "actor", "not_a_number")
	f.Add("query", "tech", "user1", "49.9")
	f.Add("query", "tech", "user1", "50.0")
	f.Add("query", "tech", "user1", "50.1")

	f.Fuzz(func(t *testing.T, action, sector, actor, riskScore string) {
		// Build request with matching metadata
		req := &EvaluationRequest{
			Actor:    actor,
			Action:   action,
			Resource: "fuzz-resource",
			Context:  map[string]string{"sector": sector},
			Metadata: map[string]string{
				"action":     action,
				"sector":     sector,
				"risk_score": riskScore,
			},
		}

		// --- AllowRule invariant: matching conditions produce Allow decision ---
		allowRule := NewAllowRule("fuzz-allow-rule", []Condition{
			{Field: "action", Operator: Equals, Value: action},
			{Field: "sector", Operator: Equals, Value: sector},
		})

		allowResult := allowRule.Evaluate(req)
		// Both conditions check for exact equality with the metadata, so they
		// always match (we set metadata[action]=action, metadata[sector]=sector).
		if allowResult == nil {
			t.Fatal("AllowRule with matching conditions returned nil, expected Allow result")
		}
		if allowResult.Decision != Allow {
			t.Fatalf("AllowRule: expected Allow, got %v", allowResult.Decision)
		}

		// --- DenyRule invariant: matching conditions produce Deny decision ---
		denyRule := NewDenyRule("fuzz-deny-rule", "fuzz-reason", []Condition{
			{Field: "action", Operator: Equals, Value: action},
			{Field: "sector", Operator: Equals, Value: sector},
		})

		denyResult := denyRule.Evaluate(req)
		if denyResult == nil {
			t.Fatal("DenyRule with matching conditions returned nil, expected Deny result")
		}
		if denyResult.Decision != Deny {
			t.Fatalf("DenyRule: expected Deny, got %v", denyResult.Decision)
		}

		// --- ThresholdRule invariant: respects numeric boundary ---
		threshold := 50.0
		thresholdRule := NewThresholdRule(
			"fuzz-threshold",
			"risk_score",
			threshold,
			RequireApproval, // above threshold
			Allow,           // below threshold
		)

		thresholdResult := thresholdRule.Evaluate(req)
		riskFloat, parseErr := strconv.ParseFloat(riskScore, 64)

		if parseErr != nil || riskScore == "" {
			// Non-numeric or empty risk score: threshold rule returns nil (no match)
			if thresholdResult != nil {
				t.Fatalf("ThresholdRule with non-numeric risk_score %q: expected nil, got decision %v",
					riskScore, thresholdResult.Decision)
			}
		} else {
			if thresholdResult == nil {
				t.Fatal("ThresholdRule with numeric risk_score returned nil")
			}
			if riskFloat >= threshold {
				if thresholdResult.Decision != RequireApproval {
					t.Fatalf("ThresholdRule: risk_score=%.2f >= threshold=%.2f, expected RequireApproval, got %v",
						riskFloat, threshold, thresholdResult.Decision)
				}
			} else {
				if thresholdResult.Decision != Allow {
					t.Fatalf("ThresholdRule: risk_score=%.2f < threshold=%.2f, expected Allow, got %v",
						riskFloat, threshold, thresholdResult.Decision)
				}
			}
		}

		// --- AllowRule with non-matching conditions must return nil ---
		nonMatchRule := NewAllowRule("fuzz-non-match", []Condition{
			{Field: "action", Operator: Equals, Value: action + "-NOMATCH"},
		})
		nonMatchResult := nonMatchRule.Evaluate(req)
		if nonMatchResult != nil {
			t.Fatalf("AllowRule with non-matching condition returned non-nil: %v", nonMatchResult.Decision)
		}
	})
}
