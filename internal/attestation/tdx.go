package attestation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Intel TDX quote (v4) layout: a 48-byte header, a 584-byte TD quote body, and
// an ECDSA-P256 signature. This verifier reads the MRTD measurement and
// REPORTDATA at their real offsets, verifies the signature over header||body
// with the PCK leaf, and chains PCK -> Intel SGX Root.
//
// This is the quote-signature + PCK-chain core. Full DCAP additionally binds the
// attestation key through a QE report and parses an in-quote cert-data section;
// that fuller path lives in x/verify/tee/dcap. Here the PCK chain is supplied
// alongside the quote (as SEV-SNP supplies VCEK), keeping the unified interface.
const (
	tdxHeaderLen  = 48
	tdxBodyLen    = 584
	tdxSignedLen  = tdxHeaderLen + tdxBodyLen // 632
	tdxQuoteLen   = tdxSignedLen + 64         // + r||s
	tdxOffMRTD    = 184                       // header(48) + body offset 136
	tdxMRTDLen    = 48
	tdxOffReport  = 568 // header(48) + body offset 520
	tdxReportLen  = 64
	tdxTeeTypeTDX = 0x00000081
)

type TDXVerifier struct{}

func (TDXVerifier) Platform() Platform { return PlatformIntelTDX }

func (TDXVerifier) Verify(ev *Evidence, policy *Policy) (*VerifiedClaims, error) {
	if ev == nil || len(ev.Raw) != tdxQuoteLen {
		return nil, fmt.Errorf("%w: tdx quote must be %d bytes, got %d", ErrMalformed, tdxQuoteLen, len(ev.Raw))
	}
	if len(ev.Certificates) < 1 {
		return nil, fmt.Errorf("%w: tdx needs a PCK leaf certificate", ErrMalformed)
	}
	if policy == nil || policy.Roots == nil {
		return nil, fmt.Errorf("%w: no trusted roots configured", ErrChain)
	}
	quote := ev.Raw
	// tee_type at header offset 4 (LE u32) must be TDX.
	teeType := uint32(quote[4]) | uint32(quote[5])<<8 | uint32(quote[6])<<16 | uint32(quote[7])<<24
	if teeType != tdxTeeTypeTDX {
		return nil, fmt.Errorf("%w: not a TDX tee_type (0x%x)", ErrMalformed, teeType)
	}

	pck, rootSubject, err := verifyChain(ev.Certificates[0], ev.Certificates[1:], policy.Roots)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChain, err)
	}
	pub, ok := pck.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: PCK is not an ECDSA key", ErrSignature)
	}

	digest := sha256.Sum256(quote[:tdxSignedLen])
	r := new(big.Int).SetBytes(quote[tdxSignedLen : tdxSignedLen+32])
	s := new(big.Int).SetBytes(quote[tdxSignedLen+32 : tdxSignedLen+64])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrSignature
	}

	return &VerifiedClaims{
		Platform:       PlatformIntelTDX,
		Measurement:    append([]byte(nil), quote[tdxOffMRTD:tdxOffMRTD+tdxMRTDLen]...),
		ReportData:     append([]byte(nil), quote[tdxOffReport:tdxOffReport+tdxReportLen]...),
		DeviceClass:    "intel-tdx",
		TCB:            "tdx-quote-v4",
		RootSubject:    rootSubject,
		TrustBasis:     policy.basis(),
		SignatureValid: true,
		ChainValid:     true,
	}, nil
}
