// Package confidential implements the Confidential Execution & Attestation
// Protocol (CEAP, see docs/architecture/ADR-0003). It separates two orthogonal,
// independently-attested dimensions of a verifiable-AI computation:
//
//   - the confidentiality Backend — how the data was protected while computed on
//     (TEE / FHE / MPC / GPU-CC / Hybrid), and
//   - the Verification method — how correctness was proven
//     (zkML / Freivalds / optimistic / re-execution / TEE-attested).
//
// A client attaches a ConfidentialityPolicy to a job; the network must satisfy
// it (never silently downgrade) and binds the resulting ConfidentialityAttestation
// into the post-quantum Digital Seal, so a regulator reads exactly how the
// computation was protected and proven. Backends are pluggable (see backend.go),
// so FHE/MPC/GPU-CC drop in without a protocol change.
package confidential

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/aethelred/aethelred/internal/attestation"
)

// Backend is how the data was protected during computation.
type Backend string

const (
	BackendNone   Backend = "none"   // no data confidentiality (public inputs)
	BackendTEE    Backend = "tee"    // trusted execution environment (CPU enclave)
	BackendGPUCC  Backend = "gpu-cc" // confidential-compute-mode GPU (large models)
	BackendMPC    Backend = "mpc"    // secure multiparty computation (threshold)
	BackendFHE    Backend = "fhe"    // fully homomorphic encryption
	BackendHybrid Backend = "hybrid" // e.g. FHE-encrypted input executed in a TEE
)

// confidentialityStrength orders backends by confidentiality assurance. Used only
// to deterministically pick the strongest backend a policy permits; it is NOT a
// claim that a stronger backend is always preferable (FHE is far slower). Higher
// is stronger. GPU-CC is TEE-class confidentiality for larger models.
func (b Backend) confidentialityStrength() int {
	switch b {
	case BackendNone:
		return 0
	case BackendTEE, BackendGPUCC:
		return 1
	case BackendMPC:
		return 2
	case BackendFHE:
		return 3
	case BackendHybrid:
		return 4
	default:
		return -1
	}
}

// Verification is how correctness of the computation was proven.
type Verification string

const (
	VerificationNone        Verification = "none"
	VerificationTEEAttested Verification = "tee-attested" // attested enclave execution
	VerificationFreivalds   Verification = "freivalds"    // probabilistic matrix check
	VerificationOptimistic  Verification = "optimistic"   // fraud-proof challenge window
	VerificationReexec      Verification = "reexec"       // deterministic re-execution
	VerificationZKML        Verification = "zkml"         // succinct zero-knowledge proof
)

// verificationStrength orders verification methods by cryptographic assurance,
// used to enforce a policy's minimum. Higher is stronger.
func (v Verification) strength() int {
	switch v {
	case VerificationNone:
		return 0
	case VerificationTEEAttested:
		return 1
	case VerificationFreivalds:
		return 2
	case VerificationOptimistic:
		return 3
	case VerificationReexec:
		return 4
	case VerificationZKML:
		return 5
	default:
		return -1
	}
}

// Jurisdiction is an ISO-3166-style region code for data-residency policy.
type Jurisdiction string

// ConfidentialityPolicy is the client-declared requirement enforced by the
// network. An empty/zero policy means "no confidentiality required" (public).
type ConfidentialityPolicy struct {
	// AllowedBackends restricts which confidentiality backends may run the job.
	// Empty means any backend is acceptable (including none).
	AllowedBackends []Backend `json:"allowed_backends,omitempty"`
	// MinVerification is the weakest acceptable verification method.
	MinVerification Verification `json:"min_verification,omitempty"`
	// AllowedPlatforms restricts the attesting platform (e.g. only SEV-SNP/TDX).
	// Empty means any platform.
	AllowedPlatforms []attestation.Platform `json:"allowed_platforms,omitempty"`
	// RequireVendorRoot forbids test roots — production silicon attestation only.
	RequireVendorRoot bool `json:"require_vendor_root,omitempty"`
	// DataResidency lists jurisdictions the data may be processed in. Empty = any.
	DataResidency []Jurisdiction `json:"data_residency,omitempty"`
}

func (p ConfidentialityPolicy) backendAllowed(b Backend) bool {
	if len(p.AllowedBackends) == 0 {
		return true
	}
	for _, a := range p.AllowedBackends {
		if a == b {
			return true
		}
	}
	return false
}

func (p ConfidentialityPolicy) platformAllowed(pl attestation.Platform) bool {
	if len(p.AllowedPlatforms) == 0 {
		return true
	}
	for _, a := range p.AllowedPlatforms {
		if a == pl {
			return true
		}
	}
	return false
}

func (p ConfidentialityPolicy) residencyAllowed(j Jurisdiction) bool {
	if len(p.DataResidency) == 0 {
		return true
	}
	for _, a := range p.DataResidency {
		if a == j {
			return true
		}
	}
	return false
}

// CanonicalHash is a deterministic hash of the policy, bound into the Digital
// Seal so the seal testifies to the exact policy the computation satisfied.
// Field order and value ordering are normalized so the hash is stable.
func (p ConfidentialityPolicy) CanonicalHash() []byte {
	var b strings.Builder
	writeSorted := func(label string, xs []string) {
		sort.Strings(xs)
		b.WriteString(label)
		b.WriteByte('=')
		b.WriteString(strings.Join(xs, ","))
		b.WriteByte(';')
	}
	backends := make([]string, len(p.AllowedBackends))
	for i, x := range p.AllowedBackends {
		backends[i] = string(x)
	}
	platforms := make([]string, len(p.AllowedPlatforms))
	for i, x := range p.AllowedPlatforms {
		platforms[i] = string(x)
	}
	residency := make([]string, len(p.DataResidency))
	for i, x := range p.DataResidency {
		residency[i] = string(x)
	}
	b.WriteString("ceap/v1;")
	writeSorted("backends", backends)
	b.WriteString("min_verification=")
	b.WriteString(string(p.MinVerification))
	b.WriteByte(';')
	writeSorted("platforms", platforms)
	b.WriteString(fmt.Sprintf("vendor_root=%t;", p.RequireVendorRoot))
	writeSorted("residency", residency)
	sum := sha256.Sum256([]byte(b.String()))
	return sum[:]
}

// ConfidentialityAttestation is produced by the executing worker, verified by
// validators, and bound into the Digital Seal.
type ConfidentialityAttestation struct {
	Backend      Backend                `json:"backend"`
	Verification Verification           `json:"verification"`
	Platform     attestation.Platform   `json:"platform"`
	Measurement  []byte                 `json:"measurement"`
	TrustBasis   attestation.TrustBasis `json:"trust_basis"`
	Jurisdiction Jurisdiction           `json:"jurisdiction,omitempty"`
	// DataSealed asserts the input was encrypted to the backend and the operator
	// never held plaintext — the confidentiality claim itself.
	DataSealed bool   `json:"data_sealed"`
	PolicyHash []byte `json:"policy_hash"`
	Worker     string `json:"worker"`
}

// Satisfies reports whether this attestation meets the policy. This is the
// consensus-critical check: validators run it against the worker's attestation
// rather than re-selecting a backend, keeping consensus deterministic while the
// heavy computation stays off-chain in the backend.
func (a ConfidentialityAttestation) Satisfies(p ConfidentialityPolicy) error {
	if !p.backendAllowed(a.Backend) {
		return fmt.Errorf("backend %q not permitted by policy", a.Backend)
	}
	if a.Verification.strength() < p.MinVerification.strength() {
		return fmt.Errorf("verification %q weaker than required %q", a.Verification, p.MinVerification)
	}
	if !p.platformAllowed(a.Platform) {
		return fmt.Errorf("platform %q not permitted by policy", a.Platform)
	}
	if p.RequireVendorRoot && a.TrustBasis != attestation.TrustVendorRoot {
		return fmt.Errorf("policy requires vendor root, attestation trust basis is %q", a.TrustBasis)
	}
	if !p.residencyAllowed(a.Jurisdiction) {
		return fmt.Errorf("jurisdiction %q outside permitted data residency", a.Jurisdiction)
	}
	// Any backend other than "none" must actually have sealed the data.
	if a.Backend != BackendNone && !a.DataSealed {
		return fmt.Errorf("backend %q claims no data sealing", a.Backend)
	}
	return nil
}
