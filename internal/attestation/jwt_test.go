package attestation

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestJWTPlatformsVerify(t *testing.T) {
	for _, plat := range []Platform{PlatformAzureMAA, PlatformGCPConfSpace, PlatformNVIDIAGPU} {
		measurement := bytes.Repeat([]byte{0x5A}, 32)
		tv := GenerateJWTTestVector(plat, measurement, []byte("seal-nonce"))
		claims, err := NewRegistry().Verify(tv.Evidence, &Policy{
			JWKS:                tv.JWKS,
			AllowedMeasurements: map[string]bool{hex.EncodeToString(measurement): true},
			ExpectedReportData:  []byte("seal-nonce"),
		})
		if err != nil {
			t.Fatalf("%s token rejected: %v", plat, err)
		}
		if claims.Platform != plat || !claims.SignatureValid {
			t.Fatalf("%s: unexpected claims %+v", plat, claims)
		}
	}
}

func TestJWTRejectsWrongKey(t *testing.T) {
	tv := GenerateJWTTestVector(PlatformAzureMAA, bytes.Repeat([]byte{1}, 32), []byte("n"))
	other := GenerateJWTTestVector(PlatformAzureMAA, bytes.Repeat([]byte{2}, 32), []byte("n"))
	// Verify tv's token against the other key under the same kid.
	jwks := map[string]any{"azure-maa-test-kid": other.JWKS["azure-maa-test-kid"]}
	if _, err := NewRegistry().Verify(tv.Evidence, &Policy{JWKS: jwks}); err == nil {
		t.Fatal("token verified under the wrong key")
	}
}

func TestJWTRejectsTamperedClaims(t *testing.T) {
	tv := GenerateJWTTestVector(PlatformGCPConfSpace, bytes.Repeat([]byte{1}, 32), []byte("n"))
	tv.Evidence.Raw[len(tv.Evidence.Raw)-3] ^= 0x7 // corrupt the signature segment
	if _, err := NewRegistry().Verify(tv.Evidence, &Policy{JWKS: tv.JWKS}); err == nil {
		t.Fatal("tampered token accepted")
	}
}
