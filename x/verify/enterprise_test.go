package verify_test

import (
	"testing"

	"github.com/aethelred/aethelred/x/verify"
	"github.com/aethelred/aethelred/x/verify/types"
)

// =============================================================================
// SQ01: Enterprise Policy Tests - Verification Defaults
// =============================================================================

func TestEnterprise_DefaultVerificationIsHybrid(t *testing.T) {
	config := verify.DefaultOrchestratorConfig()

	if config.DefaultVerificationType != types.VerificationTypeHybrid {
		t.Fatalf(
			"ENTERPRISE POLICY VIOLATION: DefaultVerificationType must be Hybrid, got %s",
			config.DefaultVerificationType.String(),
		)
	}

	t.Logf("OK: DefaultVerificationType = %s (enterprise compliant)", config.DefaultVerificationType.String())
}

func TestEnterprise_RequireBothForHybridIsDefault(t *testing.T) {
	config := verify.DefaultOrchestratorConfig()

	if !config.RequireBothForHybrid {
		t.Fatal("ENTERPRISE POLICY VIOLATION: RequireBothForHybrid must be true by default")
	}

	t.Log("OK: RequireBothForHybrid = true (enterprise compliant)")
}
