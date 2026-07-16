package attestation

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
)

func hexLower(b []byte) string { return hex.EncodeToString(b) }

// constantTimeEqualPrefix reports whether want is a prefix of got and equal over
// its length, in constant time. The binding field (report_data) is typically a
// fixed 64 bytes with the workload digest in the leading bytes.
func constantTimeEqualPrefix(got, want []byte) bool {
	if len(got) < len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(got[:len(want)], want) == 1
}

// verifyChain parses a DER leaf+intermediates chain and verifies it to roots,
// returning the verified leaf and the terminal root subject. Signature-only
// usage (no key usage / EKU constraints) keeps it format-agnostic; callers add
// the report signature check on top.
func verifyChain(leafDER []byte, intermediateDER [][]byte, roots *x509.CertPool) (*x509.Certificate, string, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, "", err
	}
	inter := x509.NewCertPool()
	for _, der := range intermediateDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "", err
		}
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, "", err
	}
	chain := chains[0]
	root := chain[len(chain)-1]
	return leaf, root.Subject.String(), nil
}
