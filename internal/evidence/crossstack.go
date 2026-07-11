// Package evidence verifies evidence artifacts produced by the Python
// demonstration layer using only the Go standard library — the cross-stack
// bridge that pins ONE canonical evidence format across both stacks.
//
// The demonstration layer (scripts/m42-crossstack-vector.py) emits a vector; the
// production stack here re-verifies the demo's Ed25519 batch signature (RFC 8032,
// interoperable with crypto/ed25519) and re-derives the record identity digest
// (SHA-256). If both pass, the production verifier accepts an artifact the
// demonstration layer generated — closing the "which one is the product?" gap.
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Vector is a Python-generated evidence artifact for independent Go verification.
type Vector struct {
	Format                    string `json:"format"`
	Description               string `json:"description"`
	ValidatorEd25519PubkeyHex string `json:"validator_ed25519_pubkey_hex"`
	BatchCommitmentHex        string `json:"batch_commitment_hex"`
	BatchEd25519SignatureHex  string `json:"batch_ed25519_signature_hex"`
	SealIDHex                 string `json:"seal_id_hex"`
	SealBodyCanonicalHex      string `json:"seal_body_canonical_hex"`
}

// Result reports what the production verifier independently confirmed.
type Result struct {
	SignatureValid bool
	DigestValid    bool
}

// Verify checks a demo-generated vector with only the Go standard library:
//   - the Ed25519 batch signature verifies against the committed message;
//   - SHA-256 of the canonical record body equals the recorded seal_id.
func Verify(v *Vector) (Result, error) {
	pub, err := hex.DecodeString(v.ValidatorEd25519PubkeyHex)
	if err != nil {
		return Result{}, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return Result{}, fmt.Errorf("pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	msg, err := hex.DecodeString(v.BatchCommitmentHex)
	if err != nil {
		return Result{}, fmt.Errorf("decode commitment: %w", err)
	}
	sig, err := hex.DecodeString(v.BatchEd25519SignatureHex)
	if err != nil {
		return Result{}, fmt.Errorf("decode signature: %w", err)
	}
	body, err := hex.DecodeString(v.SealBodyCanonicalHex)
	if err != nil {
		return Result{}, fmt.Errorf("decode body: %w", err)
	}

	sigOK := len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
	digest := sha256.Sum256(body)
	digestOK := hex.EncodeToString(digest[:]) == v.SealIDHex

	return Result{SignatureValid: sigOK, DigestValid: digestOK}, nil
}

// LoadVector reads a vector JSON file.
func LoadVector(path string) (*Vector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vector
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
