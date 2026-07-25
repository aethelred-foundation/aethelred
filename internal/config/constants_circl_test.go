//go:build pqc_circl

package config

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestDefaultCryptoParamsMatchCirclFIPS204Encodings(t *testing.T) {
	t.Parallel()

	params := DefaultCryptoParams()
	if got, want := params.Dilithium3PubKeySize, mldsa65.PublicKeySize; got != want {
		t.Fatalf("ML-DSA-65 public key size mismatch: config=%d CIRCL=%d", got, want)
	}
	if got, want := params.Dilithium3SigSize, mldsa65.SignatureSize; got != want {
		t.Fatalf("ML-DSA-65 signature size mismatch: config=%d CIRCL=%d", got, want)
	}
	if got, want := params.Dilithium5PubKeySize, mldsa87.PublicKeySize; got != want {
		t.Fatalf("ML-DSA-87 public key size mismatch: config=%d CIRCL=%d", got, want)
	}
	if got, want := params.Dilithium5SigSize, mldsa87.SignatureSize; got != want {
		t.Fatalf("ML-DSA-87 signature size mismatch: config=%d CIRCL=%d", got, want)
	}
}
