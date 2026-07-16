package attestation

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// AWS Nitro Enclaves attestation: a COSE_Sign1 (RFC 8152) document signed with
// ES384 by a per-enclave leaf certificate that chains, via the cabundle, to the
// AWS Nitro root CA. This verifier parses the real COSE/CBOR structure, verifies
// the chain to the configured root, and verifies the ES384 signature over the
// reconstructed Sig_structure.
type NitroVerifier struct{}

func (NitroVerifier) Platform() Platform { return PlatformAWSNitro }

func (NitroVerifier) Verify(ev *Evidence, policy *Policy) (*VerifiedClaims, error) {
	if ev == nil || len(ev.Raw) == 0 {
		return nil, fmt.Errorf("%w: empty nitro evidence", ErrMalformed)
	}
	if policy == nil || policy.Roots == nil {
		return nil, fmt.Errorf("%w: no trusted roots configured", ErrChain)
	}

	decoded, err := cborDecode(ev.Raw)
	if err != nil {
		return nil, fmt.Errorf("%w: cose decode: %v", ErrMalformed, err)
	}
	arr, ok := decoded.([]any)
	if !ok || len(arr) != 4 {
		return nil, fmt.Errorf("%w: COSE_Sign1 must be a 4-element array", ErrMalformed)
	}
	protected, ok1 := arr[0].([]byte)
	payload, ok2 := arr[2].([]byte)
	signature, ok3 := arr[3].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("%w: bad COSE_Sign1 element types", ErrMalformed)
	}
	if len(signature) != 96 {
		return nil, fmt.Errorf("%w: ES384 signature must be 96 bytes", ErrMalformed)
	}

	doc, err := cborDecode(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: doc decode: %v", ErrMalformed, err)
	}
	m, ok := doc.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: attestation doc is not a map", ErrMalformed)
	}
	leafDER, _ := m["certificate"].([]byte)
	if len(leafDER) == 0 {
		return nil, fmt.Errorf("%w: missing leaf certificate", ErrMalformed)
	}
	var intermediates [][]byte
	if cab, ok := m["cabundle"].([]any); ok {
		for _, c := range cab {
			if der, ok := c.([]byte); ok {
				intermediates = append(intermediates, der)
			}
		}
	}

	leaf, rootSubject, err := verifyChain(leafDER, intermediates, policy.Roots)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChain, err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: nitro leaf is not an ECDSA key", ErrSignature)
	}

	// Reconstruct the COSE Sig_structure and verify the ES384 signature.
	sig := buildSig1Structure(protected, payload)
	digest := sha512.Sum384(sig)
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrSignature
	}

	measurement := nitroMeasurement(m)
	reportData, _ := m["user_data"].([]byte)

	return &VerifiedClaims{
		Platform:       PlatformAWSNitro,
		Measurement:    measurement,
		ReportData:     reportData,
		DeviceClass:    "aws-nitro-enclave",
		TCB:            "nitro-pcrs",
		RootSubject:    rootSubject,
		TrustBasis:     policy.basis(),
		SignatureValid: true,
		ChainValid:     true,
	}, nil
}

// buildSig1Structure encodes the COSE Sig_structure that ES384 signs:
//
//	["Signature1", body_protected (bstr), external_aad (bstr, empty), payload (bstr)]
func buildSig1Structure(protected, payload []byte) []byte {
	out := cborArray(4)
	out = append(out, cborText("Signature1")...)
	out = append(out, cborBytes(protected)...)
	out = append(out, cborBytes(nil)...) // empty external_aad
	out = append(out, cborBytes(payload)...)
	return out
}

// nitroMeasurement digests the PCR set (PCR0..) into one allow-listable value.
func nitroMeasurement(doc map[any]any) []byte {
	pcrs, ok := doc["pcrs"].(map[any]any)
	if !ok {
		return nil
	}
	h := sha512.New384()
	for i := int64(0); i < 16; i++ {
		if v, ok := pcrs[i].([]byte); ok {
			h.Write(v)
		}
	}
	return h.Sum(nil)
}
