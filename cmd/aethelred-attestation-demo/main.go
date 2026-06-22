// Command aethelred-attestation-demo verifies a real attestation from every
// supported confidential-compute platform end to end, and demonstrates the
// honest vendor-vs-test-root trust boundary. It is the one-command artifact a
// reviewer runs to confirm the hardware-agnostic verifier is real.
//
// The evidence here is generated from real cryptographic test vectors (real
// ECDSA/cert chains, real binary/COSE/JWT formats) rooted in a disclosed TEST
// root. Swapping the root pool for the silicon vendor's production root and
// feeding a real quote flips the trust basis to vendor_root with no change to
// the parsing or cryptography.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/aethelred/aethelred/internal/attestation"
)

type demoCase struct {
	platform attestation.Platform
	evidence *attestation.Evidence
	policy   *attestation.Policy
}

func buildCases() []demoCase {
	bind := []byte("m42-seal-digest-binding")
	snp := attestation.GenerateSEVSNPTestVector(bytes.Repeat([]byte{0xAB}, 48), bind)
	nitro := attestation.GenerateNitroTestVector(bytes.Repeat([]byte{0xC7}, 48), bind)
	tdx := attestation.GenerateTDXTestVector(bytes.Repeat([]byte{0x3C}, 48), bind)

	cases := []demoCase{
		{attestation.PlatformAMDSEVSNP, snp.Evidence, &attestation.Policy{Roots: snp.Roots, ExpectedReportData: bind}},
		{attestation.PlatformAWSNitro, nitro.Evidence, &attestation.Policy{Roots: nitro.Roots, ExpectedReportData: bind}},
		{attestation.PlatformIntelTDX, tdx.Evidence, &attestation.Policy{Roots: tdx.Roots, ExpectedReportData: bind}},
	}
	for _, plat := range []attestation.Platform{
		attestation.PlatformAzureMAA, attestation.PlatformGCPConfSpace, attestation.PlatformNVIDIAGPU,
	} {
		jt := attestation.GenerateJWTTestVector(plat, bytes.Repeat([]byte{0x5A}, 32), bind)
		cases = append(cases, demoCase{plat, jt.Evidence, &attestation.Policy{JWKS: jt.JWKS, ExpectedReportData: bind}})
	}
	return cases
}

func main() {
	reg := attestation.NewRegistry()
	cases := buildCases()

	fmt.Println("======================================================================")
	fmt.Println("Aethelred hardware-agnostic attestation — every platform verified end to end")
	fmt.Println("======================================================================")
	fmt.Printf("%-24s %-24s %-4s %-5s %-12s %s\n", "PLATFORM", "DEVICE CLASS", "SIG", "CHN", "MEASURE", "TRUST BASIS")

	verified := 0
	for _, c := range cases {
		claims, err := reg.Verify(c.evidence, c.policy)
		if err != nil {
			fmt.Printf("%-24s  FAILED: %v\n", c.platform, err)
			continue
		}
		verified++
		fmt.Printf("%-24s %-24s %-4s %-5s %-12s %s\n",
			claims.Platform, claims.DeviceClass,
			okmark(claims.SignatureValid), okmark(claims.ChainValid),
			short(claims.Measurement), claims.TrustBasis)
	}
	fmt.Printf("\n%d/%d platform attestations verified.\n", verified, len(cases))

	// Prove the verification is real, not a pass-through: tamper one byte.
	tv := attestation.GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x01}, 48), []byte("x"))
	tampered := *tv.Evidence
	tampered.Raw = append([]byte(nil), tv.Evidence.Raw...)
	tampered.Raw[0x90] ^= 0xFF // flip a measurement byte
	if _, err := reg.Verify(&tampered, &attestation.Policy{Roots: tv.Roots}); err != nil {
		fmt.Printf("Tamper check: a single flipped measurement byte is REJECTED (%v).\n", err)
	} else {
		fmt.Println("Tamper check: FAILED — tampered report accepted!")
		os.Exit(1)
	}

	// The honest vendor-vs-test-root boundary.
	fmt.Println("\nVendor-vs-test-root boundary (the honest disclosure):")
	vb := attestation.GenerateSEVSNPTestVector(bytes.Repeat([]byte{0x02}, 48), []byte("x"))
	if _, err := reg.Verify(vb.Evidence, &attestation.Policy{Roots: vb.Roots, RequireVendorRoot: true}); err != nil {
		fmt.Printf("  RequireVendorRoot=true against a pilot TEST root : REJECTED (%v)\n", err)
	} else {
		fmt.Println("  RequireVendorRoot=true against a pilot TEST root : ACCEPTED — boundary broken!")
		os.Exit(1)
	}
	claims, err := reg.Verify(vb.Evidence, &attestation.Policy{Roots: vb.Roots, VendorRoot: true, RequireVendorRoot: true})
	if err != nil {
		fmt.Printf("  Root pool marked as silicon VENDOR root         : unexpected error %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Root pool marked as silicon VENDOR root         : ACCEPTED, trust_basis=%s\n", claims.TrustBasis)

	fmt.Println("\nBoundary: the pilot verifies against a disclosed TEST root. Pinning the")
	fmt.Println("silicon vendor's production root and supplying a real quote flips trust_basis")
	fmt.Println("to vendor_root with zero change to the parsing or cryptography above.")

	if verified != len(cases) {
		os.Exit(1)
	}
}

func okmark(b bool) string {
	if b {
		return "ok"
	}
	return "x"
}

func short(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) > 10 {
		return h[:10]
	}
	return h
}
