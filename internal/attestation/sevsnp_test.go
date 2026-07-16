package attestation

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSEVSNPVerifiesRealSignedReport(t *testing.T) {
	measurement := bytes.Repeat([]byte{0xAB}, 48)
	reportData := append([]byte("seal-digest-binding"), make([]byte, 45)...)
	tv := GenerateSEVSNPTestVector(measurement, reportData)

	reg := NewRegistry()
	policy := &Policy{
		Roots:               tv.Roots,
		AllowedMeasurements: map[string]bool{hex.EncodeToString(tv.Measurement): true},
		ExpectedReportData:  []byte("seal-digest-binding"),
	}
	claims, err := reg.Verify(tv.Evidence, policy)
	if err != nil {
		t.Fatalf("valid SEV-SNP report rejected: %v", err)
	}
	if claims.Platform != PlatformAMDSEVSNP || !claims.SignatureValid || !claims.ChainValid {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !bytes.Equal(claims.Measurement, tv.Measurement) {
		t.Fatal("measurement not extracted")
	}
	if claims.TrustBasis != TrustTestRoot {
		t.Fatalf("expected test-root basis, got %s", claims.TrustBasis)
	}
}

func TestSEVSNPRejectsTamperedMeasurement(t *testing.T) {
	tv := GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x01}, 48), make([]byte, 64))
	// Flip a measurement byte after signing — the ECDSA signature must fail.
	tv.Evidence.Raw[snpOffMeasure] ^= 0xFF
	_, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: tv.Roots})
	if err == nil {
		t.Fatal("tampered report accepted")
	}
}

func TestSEVSNPRejectsUntrustedRoot(t *testing.T) {
	tv := GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x01}, 48), make([]byte, 64))
	other := GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x02}, 48), make([]byte, 64))
	// Verify tv's report against a different chain's root.
	_, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: other.Roots})
	if err == nil {
		t.Fatal("report accepted under an untrusted root")
	}
}

func TestSEVSNPReportDataBindingEnforced(t *testing.T) {
	tv := GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x01}, 48), []byte("workload-A"))
	_, err := NewRegistry().Verify(tv.Evidence, &Policy{
		Roots:              tv.Roots,
		ExpectedReportData: []byte("workload-B"), // wrong binding
	})
	if err != ErrReportData {
		t.Fatalf("expected report-data mismatch, got %v", err)
	}
}

func TestSEVSNPVendorRootPolicy(t *testing.T) {
	tv := GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x01}, 48), make([]byte, 64))
	// Pilot test root cannot satisfy a vendor-root requirement.
	_, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: tv.Roots, RequireVendorRoot: true})
	if err != ErrVendorRoot {
		t.Fatalf("expected vendor-root rejection, got %v", err)
	}
	// Marking the pool as the vendor root makes it pass and reports vendor basis.
	claims, err := NewRegistry().Verify(tv.Evidence, &Policy{Roots: tv.Roots, VendorRoot: true, RequireVendorRoot: true})
	if err != nil || claims.TrustBasis != TrustVendorRoot {
		t.Fatalf("vendor-root path failed: %v %+v", err, claims)
	}
}
