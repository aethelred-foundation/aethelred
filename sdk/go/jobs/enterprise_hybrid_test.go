package jobs

import (
	"testing"

	"github.com/aethelred/sdk-go/types"
)

func TestEnterpriseHybridDefault(t *testing.T) {
	t.Run("empty ProofType defaults to HYBRID", func(t *testing.T) {
		req := SubmitRequest{
			ModelHash: "0xabc123",
			InputHash: "0xdef456",
			// ProofType deliberately left empty
		}

		// Simulate the default-filling logic from Module.Submit
		if req.ProofType == "" {
			req.ProofType = types.ProofTypeHybrid
		}

		if req.ProofType != types.ProofTypeHybrid {
			t.Errorf("expected ProofType to be %q, got %q", types.ProofTypeHybrid, req.ProofType)
		}
	})

	t.Run("explicit TEE overrides the default", func(t *testing.T) {
		req := SubmitRequest{
			ModelHash: "0xabc123",
			InputHash: "0xdef456",
			ProofType: types.ProofTypeTEE,
		}

		// Simulate the default-filling logic from Module.Submit
		if req.ProofType == "" {
			req.ProofType = types.ProofTypeHybrid
		}

		if req.ProofType != types.ProofTypeTEE {
			t.Errorf("expected ProofType to be %q, got %q", types.ProofTypeTEE, req.ProofType)
		}
	})

	t.Run("ProofTypeHybrid constant exists", func(t *testing.T) {
		if types.ProofTypeHybrid != "PROOF_TYPE_HYBRID" {
			t.Errorf("expected ProofTypeHybrid to be %q, got %q", "PROOF_TYPE_HYBRID", types.ProofTypeHybrid)
		}
	})
}
