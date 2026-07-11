package evidence

import (
	"path/filepath"
	"testing"
)

const vectorPath = "../../config/pilots/m42/crossstack/seal-vector.json"

// The production Go stack must independently verify the artifact the Python
// demonstration layer generated (regenerate with: make m42-crossstack).
func TestGoVerifiesPythonGeneratedArtifact(t *testing.T) {
	v, err := LoadVector(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("load vector (run `make m42-crossstack` to regenerate): %v", err)
	}
	res, err := Verify(v)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.SignatureValid {
		t.Error("Go crypto/ed25519 did not verify the demo's batch signature")
	}
	if !res.DigestValid {
		t.Error("Go SHA-256 did not reproduce the record seal_id digest")
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	v, err := LoadVector(filepath.Clean(vectorPath))
	if err != nil {
		t.Skipf("no vector: %v", err)
	}
	// Flip the last byte of the signature.
	b := []byte(v.BatchEd25519SignatureHex)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	v.BatchEd25519SignatureHex = string(b)
	res, err := Verify(v)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.SignatureValid {
		t.Error("a tampered signature was accepted")
	}
}

func TestTamperedBodyBreaksDigest(t *testing.T) {
	v, err := LoadVector(filepath.Clean(vectorPath))
	if err != nil {
		t.Skipf("no vector: %v", err)
	}
	// Corrupt one hex nibble of the canonical body.
	b := []byte(v.SealBodyCanonicalHex)
	b[10] = map[byte]byte{'a': 'b', 'b': 'a'}[b[10]]
	if b[10] == 0 {
		b[10] = 'f'
	}
	v.SealBodyCanonicalHex = string(b)
	res, err := Verify(v)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.DigestValid {
		t.Error("a tampered body still matched the seal_id digest")
	}
}
