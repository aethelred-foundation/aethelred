package attestation

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTDXVerifiesRealQuote(t *testing.T) {
	tv := GenerateTDXTestVector(bytes.Repeat([]byte{0x3C}, 48), []byte("tdx-binding"))
	claims, err := NewRegistry().Verify(tv.Evidence, &Policy{
		Roots:               tv.Roots,
		AllowedMeasurements: map[string]bool{hex.EncodeToString(tv.Measurement): true},
		ExpectedReportData:  []byte("tdx-binding"),
	})
	if err != nil {
		t.Fatalf("valid TDX quote rejected: %v", err)
	}
	if claims.Platform != PlatformIntelTDX || !claims.SignatureValid {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestTDXRejectsTamperedMRTD(t *testing.T) {
	tv := GenerateTDXTestVector(bytes.Repeat([]byte{1}, 48), make([]byte, 64))
	tv.Evidence.Raw[tdxOffMRTD] ^= 0xFF
	if _, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: tv.Roots}); err == nil {
		t.Fatal("tampered MRTD accepted")
	}
}

// The registry is the hardware-agnostic entry point: one call site accepts a
// verifiable workload from any attested platform.
func TestRegistryIsHardwareAgnostic(t *testing.T) {
	reg := NewRegistry()
	if len(reg.Platforms()) < 6 {
		t.Fatalf("expected >=6 platforms, got %v", reg.Platforms())
	}

	cases := []struct {
		name     string
		evidence *Evidence
		policy   *Policy
		want     Platform
	}{}

	snp := GenerateSEVSNPTestVector(bytes.Repeat([]byte{1}, 48), []byte("b"))
	cases = append(cases, struct {
		name     string
		evidence *Evidence
		policy   *Policy
		want     Platform
	}{"amd-sev-snp", snp.Evidence, &Policy{Roots: snp.Roots}, PlatformAMDSEVSNP})

	nitro := GenerateNitroTestVector(bytes.Repeat([]byte{2}, 48), []byte("b"))
	cases = append(cases, struct {
		name     string
		evidence *Evidence
		policy   *Policy
		want     Platform
	}{"aws-nitro", nitro.Evidence, &Policy{Roots: nitro.Roots}, PlatformAWSNitro})

	tdx := GenerateTDXTestVector(bytes.Repeat([]byte{3}, 48), []byte("b"))
	cases = append(cases, struct {
		name     string
		evidence *Evidence
		policy   *Policy
		want     Platform
	}{"intel-tdx", tdx.Evidence, &Policy{Roots: tdx.Roots}, PlatformIntelTDX})

	for _, plat := range []Platform{PlatformAzureMAA, PlatformGCPConfSpace, PlatformNVIDIAGPU} {
		jt := GenerateJWTTestVector(plat, bytes.Repeat([]byte{4}, 32), []byte("b"))
		cases = append(cases, struct {
			name     string
			evidence *Evidence
			policy   *Policy
			want     Platform
		}{string(plat), jt.Evidence, &Policy{JWKS: jt.JWKS}, plat})
	}

	for _, c := range cases {
		claims, err := reg.Verify(c.evidence, c.policy)
		if err != nil {
			t.Fatalf("%s: verify failed: %v", c.name, err)
		}
		if claims.Platform != c.want {
			t.Fatalf("%s: platform %s != %s", c.name, claims.Platform, c.want)
		}
		if claims.DeviceClass == "" {
			t.Fatalf("%s: device class missing (needed for energy attribution)", c.name)
		}
	}
}

func TestRegistryRejectsUnknownPlatform(t *testing.T) {
	_, err := NewRegistry().Verify(&Evidence{Platform: "quantum-toaster", Raw: []byte("x")}, &Policy{})
	if err == nil {
		t.Fatal("unknown platform accepted")
	}
}
