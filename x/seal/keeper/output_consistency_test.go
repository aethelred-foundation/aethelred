package keeper

import (
	"bytes"
	"testing"

	"github.com/aethelred/aethelred/x/seal/types"
)

func TestTEEOutputsConsistent(t *testing.T) {
	out := bytes.Repeat([]byte{0xAB}, 32)
	other := bytes.Repeat([]byte{0xCD}, 32)

	consistent := []types.TEEVerification{
		{ValidatorAddress: "v1", OutputHash: out},
		{ValidatorAddress: "v2", OutputHash: out},
	}
	if !teeOutputsConsistent(consistent, out) {
		t.Fatal("expected consistent outputs to pass")
	}

	mixed := []types.TEEVerification{
		{ValidatorAddress: "v1", OutputHash: out},
		{ValidatorAddress: "v2", OutputHash: other}, // dissenter
	}
	if teeOutputsConsistent(mixed, out) {
		t.Fatal("expected a dissenting output to fail consistency")
	}

	// Empty set is trivially consistent (no TEE claims to contradict).
	if !teeOutputsConsistent(nil, out) {
		t.Fatal("empty TEE set should be consistent")
	}
}

func TestOutputsAgree(t *testing.T) {
	out := bytes.Repeat([]byte{0x11}, 32)

	// TEE-only, all agree => match.
	b := &types.VerificationBundle{
		AggregatedOutputHash: out,
		TEEVerifications: []types.TEEVerification{
			{OutputHash: out}, {OutputHash: out},
		},
	}
	if !outputsAgree(b) {
		t.Fatal("TEE-only agreeing bundle should match")
	}

	// TEE + verified zkML => match and cross-validated.
	b.ZKMLVerification = &types.ZKMLVerification{Verified: true}
	if !outputsAgree(b) {
		t.Fatal("TEE + verified zkML should match")
	}

	// zkML present but NOT verified => no longer agrees (the old code assumed true).
	b.ZKMLVerification = &types.ZKMLVerification{Verified: false}
	if outputsAgree(b) {
		t.Fatal("unverified zkML must not count as agreement")
	}

	// A disagreeing TEE output breaks agreement even with verified zkML.
	b.ZKMLVerification = &types.ZKMLVerification{Verified: true}
	b.TEEVerifications[1].OutputHash = bytes.Repeat([]byte{0x22}, 32)
	if outputsAgree(b) {
		t.Fatal("disagreeing TEE output must break agreement")
	}
}
