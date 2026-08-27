package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// This file generates real, self-consistent attestation evidence rooted in a
// *test* vendor root, for self-test and integration. It is honest test support:
// the cryptography (ECDSA/RSA, X.509 chains, the binary/COSE/JWT formats) is
// identical to production — only the root is a generated test key rather than
// the silicon vendor's published root. Swapping the root pool and supplying a
// real quote is the whole difference.

func newP384CA(commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	return newCA(commonName, elliptic.P384(), parent, parentKey)
}

func newCA(commonName string, curve elliptic.Curve, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, issuerKey := tmpl, key
	if parent != nil {
		issuer, issuerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert, key
}

// SEVSNPTestVector is a generated SEV-SNP chain + a signed report.
type SEVSNPTestVector struct {
	Evidence    *Evidence
	Roots       *x509.CertPool // contains the test ARK
	Measurement []byte
	ReportData  []byte
}

// GenerateSEVSNPTestVector builds a real ARK->ASK->VCEK P-384 chain and a real
// 1184-byte report with the given measurement (48B) and report_data (64B),
// signed by the VCEK exactly as silicon would.
func GenerateSEVSNPTestVector(measurement, reportData []byte) *SEVSNPTestVector {
	ark, arkKey := newP384CA("test ARK (AMD Root Key, TEST)", nil, nil)
	ask, askKey := newP384CA("test ASK (AMD SEV Key, TEST)", ark, arkKey)
	vcek, vcekKey := newP384CA("test VCEK (TEST)", ask, askKey)

	report := make([]byte, snpReportSize)
	report[0] = 2 // VERSION
	copy(report[snpOffReportData:snpOffReportData+snpReportDataLen], pad(reportData, snpReportDataLen))
	copy(report[snpOffMeasure:snpOffMeasure+snpMeasureLen], pad(measurement, snpMeasureLen))

	digest := sha512.Sum384(report[:snpSignedLen])
	r, s, err := ecdsa.Sign(rand.Reader, vcekKey, digest[:])
	if err != nil {
		panic(err)
	}
	copy(report[snpOffSignature:snpOffSignature+snpEcdsaFieldLen], intToLEField(r, snpEcdsaFieldLen))
	copy(report[snpOffSignature+snpEcdsaFieldLen:snpOffSignature+2*snpEcdsaFieldLen], intToLEField(s, snpEcdsaFieldLen))

	roots := x509.NewCertPool()
	roots.AddCert(ark)
	return &SEVSNPTestVector{
		Evidence: &Evidence{
			Platform:     PlatformAMDSEVSNP,
			Raw:          report,
			Certificates: [][]byte{vcek.Raw, ask.Raw},
		},
		Roots:       roots,
		Measurement: pad(measurement, snpMeasureLen),
		ReportData:  pad(reportData, snpReportDataLen),
	}
}

func pad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// beFixed left-pads a big-int's big-endian bytes to a fixed width (COSE r||s).
func beFixed(v *big.Int, width int) []byte {
	b := v.Bytes()
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

// NitroTestVector is a generated AWS Nitro COSE_Sign1 document + root pool.
type NitroTestVector struct {
	Evidence    *Evidence
	Roots       *x509.CertPool
	Measurement []byte
	ReportData  []byte
}

// GenerateNitroTestVector builds a real root->intermediate->leaf P-384 chain and
// a real ES384-signed COSE_Sign1 attestation document with the given PCR0 and
// user_data, exactly as a Nitro enclave would.
func GenerateNitroTestVector(pcr0, userData []byte) *NitroTestVector {
	root, rootKey := newP384CA("test AWS Nitro Root CA (TEST)", nil, nil)
	inter, interKey := newP384CA("test Nitro Intermediate (TEST)", root, rootKey)
	leaf, leafKey := newP384CA("test enclave instance (TEST)", inter, interKey)

	// Attestation document (CBOR map).
	doc := append([]byte(nil), cborMap(5)...)
	doc = append(doc, cborText("module_id")...)
	doc = append(doc, cborText("i-test-enclave")...)
	doc = append(doc, cborText("pcrs")...)
	doc = append(doc, cborMap(3)...)
	for i, v := range [][]byte{pad(pcr0, 48), pad([]byte{0x01}, 48), pad([]byte{0x02}, 48)} {
		doc = append(doc, cborUint(uint64(i))...)
		doc = append(doc, cborBytes(v)...)
	}
	doc = append(doc, cborText("certificate")...)
	doc = append(doc, cborBytes(leaf.Raw)...)
	doc = append(doc, cborText("cabundle")...)
	doc = append(doc, cborArray(1)...)
	doc = append(doc, cborBytes(inter.Raw)...)
	doc = append(doc, cborText("user_data")...)
	doc = append(doc, cborBytes(userData)...)

	// Protected header {1: ES384(-35)}.
	protected := append([]byte(nil), cborMap(1)...)
	protected = append(protected, cborUint(1)...)
	protected = append(protected, cborNegInt(-35)...)

	digest := sha512.Sum384(buildSig1Structure(protected, doc))
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest[:])
	if err != nil {
		panic(err)
	}
	sig := append(beFixed(r, 48), beFixed(s, 48)...)

	cose := append([]byte(nil), cborArray(4)...)
	cose = append(cose, cborBytes(protected)...)
	cose = append(cose, cborMap(0)...) // empty unprotected
	cose = append(cose, cborBytes(doc)...)
	cose = append(cose, cborBytes(sig)...)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	docMap, _ := cborDecode(doc)
	measurement := nitroMeasurement(docMap.(map[any]any))
	return &NitroTestVector{
		Evidence:    &Evidence{Platform: PlatformAWSNitro, Raw: cose},
		Roots:       roots,
		Measurement: measurement,
		ReportData:  userData,
	}
}

// JWTTestVector is a generated attestation token + the JWKS to verify it.
type JWTTestVector struct {
	Evidence    *Evidence
	JWKS        map[string]any
	Measurement []byte
	ReportData  []byte
}

// GenerateJWTTestVector builds a real ES256-signed attestation token (as Azure
// MAA / GCP Confidential Space / NVIDIA NRAS issue) with a hex measurement and
// nonce, and the public JWKS entry to verify it.
func GenerateJWTTestVector(platform Platform, measurement, nonce []byte) *JWTTestVector {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	kid := string(platform) + "-test-kid"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		panic(err)
	}
	claims, _ := json.Marshal(map[string]any{
		"iss":         string(platform) + ".attestation.test",
		"measurement": hex.EncodeToString(measurement),
		"nonce":       string(nonce),
		"exp":         time.Now().Add(time.Hour).Unix(),
	})
	obj, err := signer.Sign(claims)
	if err != nil {
		panic(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return &JWTTestVector{
		Evidence:    &Evidence{Platform: platform, Raw: []byte(token)},
		JWKS:        map[string]any{kid: &key.PublicKey},
		Measurement: measurement,
		ReportData:  nonce,
	}
}

// TDXTestVector is a generated Intel TDX quote + root pool.
type TDXTestVector struct {
	Evidence    *Evidence
	Roots       *x509.CertPool
	Measurement []byte
	ReportData  []byte
}

// GenerateTDXTestVector builds a real Intel-Root -> PCK P-256 chain and a TDX v4
// quote with the given MRTD (48B) and report_data (64B), signed by the PCK over
// SHA-256 of header||body exactly as the quote signature is formed.
func GenerateTDXTestVector(mrtd, reportData []byte) *TDXTestVector {
	root, rootKey := newCA("test Intel SGX Root CA (TEST)", elliptic.P256(), nil, nil)
	pck, pckKey := newCA("test PCK (TEST)", elliptic.P256(), root, rootKey)

	quote := make([]byte, tdxQuoteLen)
	quote[0] = 4 // version
	// tee_type = TDX (0x81) at offset 4, little-endian.
	quote[4] = 0x81
	copy(quote[tdxOffMRTD:tdxOffMRTD+tdxMRTDLen], pad(mrtd, tdxMRTDLen))
	copy(quote[tdxOffReport:tdxOffReport+tdxReportLen], pad(reportData, tdxReportLen))

	digest := sha256Sum(quote[:tdxSignedLen])
	r, s, err := ecdsa.Sign(rand.Reader, pckKey, digest)
	if err != nil {
		panic(err)
	}
	copy(quote[tdxSignedLen:tdxSignedLen+32], beFixed(r, 32))
	copy(quote[tdxSignedLen+32:tdxSignedLen+64], beFixed(s, 32))

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &TDXTestVector{
		Evidence:    &Evidence{Platform: PlatformIntelTDX, Raw: quote, Certificates: [][]byte{pck.Raw}},
		Roots:       roots,
		Measurement: pad(mrtd, tdxMRTDLen),
		ReportData:  pad(reportData, tdxReportLen),
	}
}
