package keeper_test

import (
	"testing"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// SQ01: Enterprise Parameter Profile Tests
// =============================================================================

func TestEnterprise_EnterpriseParamsOnlyAllowHybrid(t *testing.T) {
	params := keeper.EnterpriseParams()

	if len(params.AllowedProofTypes) != 1 {
		t.Fatalf("enterprise params must have exactly 1 allowed proof type, got %d", len(params.AllowedProofTypes))
	}
	if params.AllowedProofTypes[0] != "hybrid" {
		t.Fatalf("enterprise params must only allow 'hybrid', got %q", params.AllowedProofTypes[0])
	}

	t.Log("OK: EnterpriseParams only allows hybrid")
}

func TestEnterprise_EnterpriseParamsFallbackDisabled(t *testing.T) {
	params := keeper.EnterpriseParams()

	if params.AllowZkmlFallback {
		t.Fatal("enterprise params must have AllowZkmlFallback=false")
	}
	if params.AllowSimulated {
		t.Fatal("enterprise params must have AllowSimulated=false")
	}
	if !params.RequireTeeAttestation {
		t.Fatal("enterprise params must have RequireTeeAttestation=true")
	}

	t.Log("OK: enterprise params security constraints satisfied")
}

func TestEnterprise_ValidateEnterpriseParams_AcceptsValid(t *testing.T) {
	params := keeper.EnterpriseParams()
	err := keeper.ValidateEnterpriseParams(params)
	if err != nil {
		t.Fatalf("valid enterprise params should pass validation: %v", err)
	}
}

func TestEnterprise_ValidateEnterpriseParams_RejectsFallback(t *testing.T) {
	params := keeper.EnterpriseParams()
	params.AllowZkmlFallback = true

	err := keeper.ValidateEnterpriseParams(params)
	if err == nil {
		t.Fatal("enterprise validation must reject AllowZkmlFallback=true")
	}
	t.Logf("OK: correctly rejected: %s", err.Error())
}

func TestEnterprise_ValidateEnterpriseParams_RejectsTEEOnly(t *testing.T) {
	params := keeper.EnterpriseParams()
	params.AllowedProofTypes = []string{"tee"}

	err := keeper.ValidateEnterpriseParams(params)
	if err == nil {
		t.Fatal("enterprise validation must reject TEE-only proof types")
	}
	t.Logf("OK: TEE-only correctly rejected: %s", err.Error())
}

func TestEnterprise_ValidateEnterpriseParams_RejectsZKMLOnly(t *testing.T) {
	params := keeper.EnterpriseParams()
	params.AllowedProofTypes = []string{"zkml"}

	err := keeper.ValidateEnterpriseParams(params)
	if err == nil {
		t.Fatal("enterprise validation must reject ZKML-only proof types")
	}
	t.Logf("OK: ZKML-only correctly rejected: %s", err.Error())
}

func TestEnterprise_ValidateEnterpriseParams_RejectsSimulated(t *testing.T) {
	params := keeper.EnterpriseParams()
	params.AllowSimulated = true

	err := keeper.ValidateEnterpriseParams(params)
	if err == nil {
		t.Fatal("enterprise validation must reject AllowSimulated=true")
	}
	t.Logf("OK: correctly rejected: %s", err.Error())
}
