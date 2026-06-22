// Package attestation is a hardware-agnostic remote-attestation verifier. It
// parses and cryptographically verifies real attestation formats from multiple
// confidential-compute platforms — AMD SEV-SNP, AWS Nitro, Intel TDX, Azure
// (MAA), Google Confidential Space, and NVIDIA GPUs — behind one interface, so
// the chain can accept a verifiable workload from any attested device.
//
// The verification logic is real: real binary/COSE/JWT parsing, real ECDSA/RSA
// signature checks, and real X.509 chain validation to a configured root. The
// only honest boundary is *which* root anchors trust: a pilot may verify against
// a disclosed test root (TrustTestRoot) until the deployment pins the silicon
// vendor's production root (TrustVendorRoot). Swapping the root pool and feeding
// a real quote is the whole difference — the parsing and crypto do not change.
package attestation

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// Platform identifies a confidential-compute attestation format.
type Platform string

const (
	PlatformAMDSEVSNP    Platform = "amd-sev-snp"
	PlatformAWSNitro     Platform = "aws-nitro"
	PlatformIntelTDX     Platform = "intel-tdx"
	PlatformAzureMAA     Platform = "azure-maa"
	PlatformGCPConfSpace Platform = "gcp-confidential-space"
	PlatformNVIDIAGPU    Platform = "nvidia-gpu"
)

// TrustBasis records whether the chain terminated at the real silicon-vendor
// root or at a disclosed pilot test root — the energy analogue of the
// measured/estimate label.
type TrustBasis string

const (
	TrustVendorRoot TrustBasis = "vendor_root"
	TrustTestRoot   TrustBasis = "test_root"
)

// Evidence is a platform-tagged raw attestation plus its certificate material.
type Evidence struct {
	Platform Platform
	// Raw is the attestation itself: an SEV-SNP/TDX binary report, an AWS Nitro
	// COSE_Sign1 document, or a JWT (Azure/GCP/NVIDIA NRAS).
	Raw []byte
	// Certificates is the DER chain when carried out-of-band (SEV-SNP VCEK/ASK,
	// NVIDIA device cert). COSE/JWT carry their own chains inline.
	Certificates [][]byte
}

// VerifiedClaims is the trustworthy result of a successful verification.
type VerifiedClaims struct {
	Platform Platform `json:"platform"`
	// Measurement is the launch/firmware measurement (SEV-SNP MEASUREMENT,
	// TDX MRTD, Nitro PCR digest) the policy allow-lists.
	Measurement []byte `json:"measurement"`
	// ReportData is the platform binding field (64 bytes on SEV-SNP/TDX, user
	// data on Nitro, a nonce claim on JWT platforms) — bound to the workload so
	// the attestation cannot be replayed for a different computation.
	ReportData []byte `json:"report_data"`
	// DeviceClass feeds energy/cost attribution: every measured watt is now tied
	// to an attested device.
	DeviceClass    string     `json:"device_class"`
	TCB            string     `json:"tcb"`
	RootSubject    string     `json:"root_subject"`
	TrustBasis     TrustBasis `json:"trust_basis"`
	SignatureValid bool       `json:"signature_valid"`
	ChainValid     bool       `json:"chain_valid"`
}

// Policy constrains what a verifier will accept.
type Policy struct {
	// Roots is the trusted anchor pool (real vendor roots in production, a test
	// root in the pilot).
	Roots *x509.CertPool
	// VendorRoot marks the Roots pool as the real silicon vendor's root, so the
	// result is reported as TrustVendorRoot rather than TrustTestRoot.
	VendorRoot bool
	// AllowedMeasurements, when non-empty, is a hex allow-list the report
	// measurement must be a member of.
	AllowedMeasurements map[string]bool
	// ExpectedReportData, when set, must equal the attestation's binding field.
	ExpectedReportData []byte
	// JWKS keys for the JWT platforms (Azure MAA, GCP, NVIDIA NRAS), keyed by kid.
	JWKS map[string]any
	// RequireVendorRoot rejects any result that only chains to a test root.
	RequireVendorRoot bool
}

func (p *Policy) basis() TrustBasis {
	if p != nil && p.VendorRoot {
		return TrustVendorRoot
	}
	return TrustTestRoot
}

// Verifier verifies one platform's attestation format.
type Verifier interface {
	Platform() Platform
	Verify(ev *Evidence, policy *Policy) (*VerifiedClaims, error)
}

var (
	ErrUnknownPlatform = errors.New("attestation: no verifier registered for platform")
	ErrSignature       = errors.New("attestation: signature verification failed")
	ErrChain           = errors.New("attestation: certificate chain verification failed")
	ErrMeasurement     = errors.New("attestation: measurement not in allow-list")
	ErrReportData      = errors.New("attestation: report_data binding mismatch")
	ErrVendorRoot      = errors.New("attestation: policy requires a vendor root, evidence chains only to a test root")
	ErrMalformed       = errors.New("attestation: malformed evidence")
)

// Registry dispatches verification by platform — the hardware-agnostic entry point.
type Registry struct {
	verifiers map[Platform]Verifier
}

// NewRegistry builds a registry with every built-in platform verifier.
func NewRegistry() *Registry {
	r := &Registry{verifiers: map[Platform]Verifier{}}
	for _, v := range []Verifier{
		&SEVSNPVerifier{},
		&NitroVerifier{},
		&TDXVerifier{},
		&JWTVerifier{platform: PlatformAzureMAA, deviceClass: "azure-confidential-vm"},
		&JWTVerifier{platform: PlatformGCPConfSpace, deviceClass: "gcp-confidential-space"},
		&JWTVerifier{platform: PlatformNVIDIAGPU, deviceClass: "nvidia-gpu"},
	} {
		r.verifiers[v.Platform()] = v
	}
	return r
}

// Register adds or overrides a verifier (e.g. a custom platform).
func (r *Registry) Register(v Verifier) { r.verifiers[v.Platform()] = v }

// Platforms lists the registered platforms.
func (r *Registry) Platforms() []Platform {
	out := make([]Platform, 0, len(r.verifiers))
	for p := range r.verifiers {
		out = append(out, p)
	}
	return out
}

// Verify dispatches to the platform verifier and enforces the policy's
// measurement/report-data/vendor-root requirements uniformly across platforms.
func (r *Registry) Verify(ev *Evidence, policy *Policy) (*VerifiedClaims, error) {
	if ev == nil {
		return nil, ErrMalformed
	}
	v, ok := r.verifiers[ev.Platform]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPlatform, ev.Platform)
	}
	claims, err := v.Verify(ev, policy)
	if err != nil {
		return nil, err
	}
	if err := enforce(claims, policy); err != nil {
		return nil, err
	}
	return claims, nil
}

func enforce(claims *VerifiedClaims, policy *Policy) error {
	if policy == nil {
		return nil
	}
	if policy.RequireVendorRoot && claims.TrustBasis != TrustVendorRoot {
		return ErrVendorRoot
	}
	if len(policy.AllowedMeasurements) > 0 {
		if !policy.AllowedMeasurements[hexLower(claims.Measurement)] {
			return ErrMeasurement
		}
	}
	if len(policy.ExpectedReportData) > 0 {
		if !constantTimeEqualPrefix(claims.ReportData, policy.ExpectedReportData) {
			return ErrReportData
		}
	}
	return nil
}
