package attestation

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// AMD SEV-SNP ATTESTATION_REPORT binary layout (AMD SEV-SNP ABI). The report is
// 1184 bytes; the signature covers the first 0x2A0 bytes, and the ECDSA P-384
// (r,s) are stored as 72-byte little-endian fields starting at 0x2A0.
const (
	snpReportSize    = 0x4A0
	snpSignedLen     = 0x2A0
	snpOffReportData = 0x50
	snpOffMeasure    = 0x90
	snpOffReportTCB  = 0x180
	snpOffSignature  = 0x2A0
	snpEcdsaFieldLen = 0x48 // 72 bytes; P-384 uses the low 48
	snpMeasureLen    = 48
	snpReportDataLen = 64
)

// SEVSNPVerifier verifies AMD SEV-SNP attestation reports: real binary parse,
// real ECDSA-P384/SHA-384 signature check against the VCEK, and a real VCEK ->
// ASK -> ARK X.509 chain.
type SEVSNPVerifier struct{}

func (SEVSNPVerifier) Platform() Platform { return PlatformAMDSEVSNP }

func (SEVSNPVerifier) Verify(ev *Evidence, policy *Policy) (*VerifiedClaims, error) {
	if ev == nil || len(ev.Raw) != snpReportSize {
		return nil, fmt.Errorf("%w: sev-snp report must be %d bytes, got %d", ErrMalformed, snpReportSize, len(ev.Raw))
	}
	if len(ev.Certificates) < 1 {
		return nil, fmt.Errorf("%w: sev-snp needs at least a VCEK leaf certificate", ErrMalformed)
	}
	report := ev.Raw

	// Verify the VCEK -> ASK -> ARK chain. Leaf is VCEK; the rest are
	// intermediates; the ARK root lives in policy.Roots.
	if policy == nil || policy.Roots == nil {
		return nil, fmt.Errorf("%w: no trusted roots configured", ErrChain)
	}
	vcek, rootSubject, err := verifyChain(ev.Certificates[0], ev.Certificates[1:], policy.Roots)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChain, err)
	}
	pub, ok := vcek.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: VCEK is not an ECDSA key", ErrSignature)
	}

	// The report signature is ECDSA-P384 over SHA-384 of the signed region.
	digest := sha512.Sum384(report[:snpSignedLen])
	r := leBytesToInt(report[snpOffSignature : snpOffSignature+snpEcdsaFieldLen])
	s := leBytesToInt(report[snpOffSignature+snpEcdsaFieldLen : snpOffSignature+2*snpEcdsaFieldLen])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrSignature
	}

	measurement := append([]byte(nil), report[snpOffMeasure:snpOffMeasure+snpMeasureLen]...)
	reportData := append([]byte(nil), report[snpOffReportData:snpOffReportData+snpReportDataLen]...)
	tcb := fmt.Sprintf("reported_tcb=0x%x", report[snpOffReportTCB:snpOffReportTCB+8])

	return &VerifiedClaims{
		Platform:       PlatformAMDSEVSNP,
		Measurement:    measurement,
		ReportData:     reportData,
		DeviceClass:    "amd-epyc-sev-snp",
		TCB:            tcb,
		RootSubject:    rootSubject,
		TrustBasis:     policy.basis(),
		SignatureValid: true,
		ChainValid:     true,
	}, nil
}

// leBytesToInt interprets a little-endian byte field (AMD's signature encoding)
// as a big integer.
func leBytesToInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

// intToLEField encodes a big integer into a little-endian field of fieldLen
// bytes (AMD's signature encoding).
func intToLEField(v *big.Int, fieldLen int) []byte {
	be := v.Bytes()
	out := make([]byte, fieldLen)
	for i := 0; i < len(be); i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}
