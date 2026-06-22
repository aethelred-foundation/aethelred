package attestation

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// JWTVerifier handles the attestation-token platforms — Azure Microsoft
// Attestation (MAA), Google Confidential Space, and NVIDIA NRAS — which return a
// signed JWT/EAT. The token's issuer signs over the platform's underlying
// hardware evidence (SEV-SNP/TDX/GPU); we verify the token signature against the
// issuer's published JWKS and extract the measurement and nonce claims.
//
// The claim *paths* differ per platform (Azure nests the launch measurement
// under x-ms-isolation-tee; GCP under submods.confidential_space; NVIDIA under
// measurement), so a deployment supplies a ClaimMap. The defaults read a
// top-level "measurement" (hex) and "nonce" claim.
type JWTVerifier struct {
	platform    Platform
	deviceClass string
	// MeasurementClaim and NonceClaim are top-level claim names; empty uses
	// "measurement"/"nonce".
	MeasurementClaim string
	NonceClaim       string
}

func (v JWTVerifier) Platform() Platform { return v.platform }

var jwtAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256, jose.PS256}

func (v JWTVerifier) Verify(ev *Evidence, policy *Policy) (*VerifiedClaims, error) {
	if ev == nil || len(ev.Raw) == 0 {
		return nil, fmt.Errorf("%w: empty token", ErrMalformed)
	}
	if policy == nil || len(policy.JWKS) == 0 {
		return nil, fmt.Errorf("%w: no JWKS configured for %s", ErrChain, v.platform)
	}
	sig, err := jose.ParseSigned(string(ev.Raw), jwtAlgs)
	if err != nil {
		return nil, fmt.Errorf("%w: parse token: %v", ErrMalformed, err)
	}
	if len(sig.Signatures) == 0 {
		return nil, fmt.Errorf("%w: token has no signature", ErrMalformed)
	}
	kid := sig.Signatures[0].Header.KeyID
	key, ok := policy.JWKS[kid]
	if !ok {
		return nil, fmt.Errorf("%w: no JWKS key for kid %q", ErrChain, kid)
	}
	payload, err := sig.Verify(key) // real signature verification
	if err != nil {
		return nil, ErrSignature
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims decode: %v", ErrMalformed, err)
	}

	mClaim := v.MeasurementClaim
	if mClaim == "" {
		mClaim = "measurement"
	}
	nClaim := v.NonceClaim
	if nClaim == "" {
		nClaim = "nonce"
	}
	var measurement, reportData []byte
	if s, ok := claims[mClaim].(string); ok {
		if b, err := hex.DecodeString(s); err == nil {
			measurement = b
		}
	}
	if s, ok := claims[nClaim].(string); ok {
		reportData = []byte(s)
	}

	tcb := "jwt-attested"
	if iss, ok := claims["iss"].(string); ok {
		tcb = "iss=" + iss
	}
	return &VerifiedClaims{
		Platform:       v.platform,
		Measurement:    measurement,
		ReportData:     reportData,
		DeviceClass:    v.deviceClass,
		TCB:            tcb,
		RootSubject:    fmt.Sprintf("jwks:%s", kid),
		TrustBasis:     policy.basis(),
		SignatureValid: true,
		ChainValid:     true,
	}, nil
}
