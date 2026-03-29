package types_test

import (
	"testing"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// =============================================================================
// SQ01: Enterprise Policy Tests - Genesis and Params
// =============================================================================

func TestEnterprise_GenesisRejectsFallback(t *testing.T) {
	// Enterprise mode must reject AllowZkmlFallback=true
	gs := types.EnterpriseGenesis()
	gs.Params.AllowZkmlFallback = true

	err := types.ValidateEnterprise(gs)
	if err == nil {
		t.Fatal("enterprise validation must reject AllowZkmlFallback=true")
	}
	t.Logf("OK: correctly rejected: %s", err.Error())
}

func TestEnterprise_GenesisRejectsNonHybridProofTypes(t *testing.T) {
	// Enterprise mode must reject non-hybrid proof types
	gs := types.EnterpriseGenesis()
	gs.Params.AllowedProofTypes = []string{"tee", "zkml", "hybrid"}

	err := types.ValidateEnterprise(gs)
	if err == nil {
		t.Fatal("enterprise validation must reject AllowedProofTypes with non-hybrid entries")
	}
	t.Logf("OK: correctly rejected: %s", err.Error())
}

func TestEnterprise_GenesisRejectsSimulated(t *testing.T) {
	gs := types.EnterpriseGenesis()
	gs.Params.AllowSimulated = true

	err := types.ValidateEnterprise(gs)
	if err == nil {
		t.Fatal("enterprise validation must reject AllowSimulated=true")
	}
	t.Logf("OK: correctly rejected: %s", err.Error())
}

func TestEnterprise_ValidGenesisPassesValidation(t *testing.T) {
	gs := types.EnterpriseGenesis()

	// Must pass both standard and enterprise validation
	err := gs.Validate()
	if err != nil {
		t.Fatalf("enterprise genesis should pass standard validation: %v", err)
	}

	err = types.ValidateEnterprise(gs)
	if err != nil {
		t.Fatalf("enterprise genesis should pass enterprise validation: %v", err)
	}

	t.Log("OK: enterprise genesis passes both standard and enterprise validation")
}

func TestEnterprise_ParamsOnlyAllowHybrid(t *testing.T) {
	params := types.EnterpriseParams()

	if len(params.AllowedProofTypes) != 1 {
		t.Fatalf("enterprise params must have exactly 1 allowed proof type, got %d", len(params.AllowedProofTypes))
	}
	if params.AllowedProofTypes[0] != "hybrid" {
		t.Fatalf("enterprise params must only allow 'hybrid', got %q", params.AllowedProofTypes[0])
	}
	if params.AllowZkmlFallback {
		t.Fatal("enterprise params must have AllowZkmlFallback=false")
	}

	t.Logf("OK: enterprise params: AllowedProofTypes=%v, AllowZkmlFallback=%v",
		params.AllowedProofTypes, params.AllowZkmlFallback)
}

func TestEnterprise_IsEnterpriseProofType(t *testing.T) {
	if !types.IsEnterpriseProofType("hybrid") {
		t.Fatal("'hybrid' must be an enterprise proof type")
	}
	if types.IsEnterpriseProofType("tee") {
		t.Fatal("'tee' must NOT be an enterprise proof type")
	}
	if types.IsEnterpriseProofType("zkml") {
		t.Fatal("'zkml' must NOT be an enterprise proof type")
	}
}

// ---------------------------------------------------------------------------
// Rejection tests: TEE-only and ZKML-only must fail in enterprise mode
// ---------------------------------------------------------------------------

func TestEnterprise_TEEOnlyJobRejectedInEnterpriseMode(t *testing.T) {
	gs := types.EnterpriseGenesis()
	gs.Params.AllowedProofTypes = []string{"tee"}

	err := types.ValidateEnterprise(gs)
	if err == nil {
		t.Fatal("enterprise mode must reject TEE-only AllowedProofTypes")
	}
	t.Logf("OK: TEE-only correctly rejected: %s", err.Error())
}

func TestEnterprise_ZKMLOnlyJobRejectedInEnterpriseMode(t *testing.T) {
	gs := types.EnterpriseGenesis()
	gs.Params.AllowedProofTypes = []string{"zkml"}

	err := types.ValidateEnterprise(gs)
	if err == nil {
		t.Fatal("enterprise mode must reject ZKML-only AllowedProofTypes")
	}
	t.Logf("OK: ZKML-only correctly rejected: %s", err.Error())
}
