package incident

import (
	"testing"
)

// ---------------------------------------------------------------------------
// FuzzIncidentStatusTransition
// ---------------------------------------------------------------------------

// FuzzIncidentStatusTransition fuzzes status sequences to verify that only
// valid transitions are accepted according to the incident lifecycle:
//
//	Detected -> Triaging -> Mitigating -> Resolved -> PostMortem
//
// Invariants:
//   - Valid transitions succeed.
//   - Invalid transitions (e.g., Resolved -> Detected) fail.
//   - Unknown statuses are rejected.
//   - No panics regardless of input.
func FuzzIncidentStatusTransition(f *testing.F) {
	// Valid transitions
	f.Add("detected", "triaging")
	f.Add("detected", "mitigating")
	f.Add("detected", "resolved")
	f.Add("triaging", "mitigating")
	f.Add("triaging", "resolved")
	f.Add("mitigating", "resolved")
	f.Add("resolved", "post_mortem")
	// Invalid transitions
	f.Add("resolved", "detected")
	f.Add("post_mortem", "detected")
	f.Add("post_mortem", "mitigating")
	f.Add("mitigating", "detected")
	f.Add("triaging", "detected")
	// Unknown statuses
	f.Add("", "")
	f.Add("unknown", "resolved")
	f.Add("detected", "invalid_status")
	f.Add("\x00\xff", "\t\n")
	f.Add("DETECTED", "TRIAGING")

	validStatuses := map[IncidentStatus]bool{
		StatusDetected:  true,
		StatusTriaging:  true,
		StatusMitigating: true,
		StatusResolved:  true,
		StatusPostMortem: true,
	}

	// Valid transition map (from -> allowed destinations)
	validTransitionMap := map[IncidentStatus]map[IncidentStatus]bool{
		StatusDetected:  {StatusTriaging: true, StatusMitigating: true, StatusResolved: true},
		StatusTriaging:  {StatusMitigating: true, StatusResolved: true},
		StatusMitigating: {StatusResolved: true},
		StatusResolved:  {StatusPostMortem: true},
		StatusPostMortem: {},
	}

	f.Fuzz(func(t *testing.T, from, to string) {
		fromStatus := IncidentStatus(from)
		toStatus := IncidentStatus(to)

		err := ValidateTransition(fromStatus, toStatus)

		isFromValid := validStatuses[fromStatus]
		isToValid := validStatuses[toStatus]

		// Invariant 1: unknown 'from' status always produces error
		if !isFromValid {
			if err == nil {
				t.Errorf("transition from unknown status %q should fail", from)
			}
			return
		}

		// Invariant 2: valid transitions succeed
		allowedDests := validTransitionMap[fromStatus]
		if isToValid && allowedDests[toStatus] {
			if err != nil {
				t.Errorf("valid transition %q -> %q should succeed: %v", from, to, err)
			}
		}

		// Invariant 3: invalid transitions fail
		if isFromValid && isToValid && !allowedDests[toStatus] {
			if err == nil {
				t.Errorf("invalid transition %q -> %q should fail", from, to)
			}
		}

		// Invariant 4: backward transitions always fail
		// (resolved -> detected, post_mortem -> anything)
		if fromStatus == StatusPostMortem {
			if err == nil {
				t.Errorf("transition from post_mortem to %q should fail", to)
			}
		}
		if fromStatus == StatusResolved && toStatus != StatusPostMortem {
			if err == nil && isToValid {
				t.Errorf("transition from resolved to %q should fail (only post_mortem allowed)", to)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzKillSwitchScopeValidation
// ---------------------------------------------------------------------------

// FuzzKillSwitchScopeValidation fuzzes kill switch scope to verify that
// empty scopes are rejected and non-empty scopes are accepted.
//
// Invariants:
//   - Completely empty scope (no systems, regions, or services) is rejected.
//   - Scope with at least one system/region/service is accepted.
//   - No panics regardless of input.
func FuzzKillSwitchScopeValidation(f *testing.F) {
	f.Add("consensus", "", "")
	f.Add("", "eu-west-1", "")
	f.Add("", "", "seal-service")
	f.Add("", "", "")
	f.Add("system-a", "us-east-1", "svc-1")
	f.Add("\x00\xff", "\t", "\n")

	f.Fuzz(func(t *testing.T, system, region, service string) {
		scope := KillSwitchScope{}
		if system != "" {
			scope.Systems = []string{system}
		}
		if region != "" {
			scope.Regions = []string{region}
		}
		if service != "" {
			scope.Services = []string{service}
		}

		err := scope.Validate()

		hasContent := system != "" || region != "" || service != ""

		// Invariant 1: completely empty scope is rejected
		if !hasContent {
			if err == nil {
				t.Error("empty scope (no systems, regions, or services) must be rejected")
			}
		}

		// Invariant 2: scope with content is accepted
		if hasContent {
			if err != nil {
				t.Errorf("scope with content should be accepted: %v", err)
			}
		}

		// Additional validation: scope fields are preserved
		if system != "" && len(scope.Systems) != 1 {
			t.Error("system should be in scope")
		}
		if region != "" && len(scope.Regions) != 1 {
			t.Error("region should be in scope")
		}
		if service != "" && len(scope.Services) != 1 {
			t.Error("service should be in scope")
		}
	})
}
