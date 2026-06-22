package attestation

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNitroVerifiesRealCOSESign1(t *testing.T) {
	tv := GenerateNitroTestVector(bytes.Repeat([]byte{0x7}, 48), []byte("seal-binding"))
	claims, err := NewRegistry().Verify(tv.Evidence, &Policy{
		Roots:               tv.Roots,
		AllowedMeasurements: map[string]bool{hex.EncodeToString(tv.Measurement): true},
		ExpectedReportData:  []byte("seal-binding"),
	})
	if err != nil {
		t.Fatalf("valid Nitro doc rejected: %v", err)
	}
	if claims.Platform != PlatformAWSNitro || !claims.SignatureValid || !claims.ChainValid {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if string(claims.ReportData) != "seal-binding" {
		t.Fatalf("user_data not extracted: %q", claims.ReportData)
	}
}

func TestNitroRejectsTamperedPayload(t *testing.T) {
	tv := GenerateNitroTestVector(bytes.Repeat([]byte{0x7}, 48), []byte("x"))
	// Flip a byte in the COSE document; ES384 over the Sig_structure must fail.
	tv.Evidence.Raw[len(tv.Evidence.Raw)-1] ^= 0xFF
	if _, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: tv.Roots}); err == nil {
		t.Fatal("tampered COSE accepted")
	}
}

func TestNitroRejectsUntrustedRoot(t *testing.T) {
	tv := GenerateNitroTestVector(bytes.Repeat([]byte{0x7}, 48), []byte("x"))
	other := GenerateNitroTestVector(bytes.Repeat([]byte{0x9}, 48), []byte("y"))
	if _, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: other.Roots}); err == nil {
		t.Fatal("Nitro doc accepted under untrusted root")
	}
}
