package confidential

import (
	"context"
	"errors"

	"github.com/aethelred/aethelred/internal/attestation"
)

// Executor runs a model on encrypted input inside a confidentiality boundary and
// returns the committed output plus the raw platform attestation. It is injected
// by the composition root (the verification orchestrator holds the real enclave /
// FHE / MPC executor); the confidential layer stays free of heavy dependencies.
type Executor func(ctx context.Context, in EncryptedInput, m ModelRef) (Output, RawAttestation, error)

// RawAttestation is the platform-level evidence an executor returns, which the
// backend lifts into a ConfidentialityAttestation.
type RawAttestation struct {
	Platform     attestation.Platform
	Measurement  []byte
	TrustBasis   attestation.TrustBasis
	Jurisdiction Jurisdiction
	Worker       string
}

var errNoExecutor = errors.New("confidential: executor not configured (wire it in the verification orchestrator)")

// ── TEE backend (operational: this is the production path today) ──────────────

type teeBackend struct {
	exec Executor
	ver  Verification // verification method the enclave provides (e.g. TEE-attested)
}

// NewTEEBackend builds the TEE confidentiality backend. exec may be nil in
// contexts that only need capability/policy logic (Execute then reports honestly).
func NewTEEBackend(exec Executor) ConfidentialBackend {
	return &teeBackend{exec: exec, ver: VerificationTEEAttested}
}

func (t *teeBackend) Kind() Backend    { return BackendTEE }
func (t *teeBackend) Available() error { return nil }

func (t *teeBackend) SatisfiesPlatform(p Platform) bool {
	switch attestation.Platform(p) {
	case attestation.PlatformAMDSEVSNP, attestation.PlatformIntelTDX,
		attestation.PlatformAWSNitro, attestation.PlatformAzureMAA,
		attestation.PlatformGCPConfSpace:
		return true
	default:
		return false
	}
}

func (t *teeBackend) Prepare(_ context.Context, _ ConfidentialityPolicy) (Session, error) {
	return noopSession{}, nil
}

func (t *teeBackend) Execute(ctx context.Context, _ Session, in EncryptedInput, m ModelRef) (Output, ConfidentialityAttestation, error) {
	if t.exec == nil {
		return Output{}, ConfidentialityAttestation{}, errNoExecutor
	}
	out, raw, err := t.exec(ctx, in, m)
	if err != nil {
		return Output{}, ConfidentialityAttestation{}, err
	}
	att := ConfidentialityAttestation{
		Backend:      BackendTEE,
		Verification: t.ver,
		Platform:     raw.Platform,
		Measurement:  raw.Measurement,
		TrustBasis:   raw.TrustBasis,
		Jurisdiction: raw.Jurisdiction,
		DataSealed:   true, // data is sealed to the enclave; operator holds no plaintext
		Worker:       raw.Worker,
	}
	return out, att, nil
}

// ── GPU-CC / MPC / FHE backends (declared, not yet operational) ───────────────
//
// These are first-class in the protocol but not wired to a real executor yet.
// Available() returns a non-nil error so the policy engine never selects them and
// they can never be presented as production. Wiring one is a drop-in: give it a
// real Executor and flip Available().

type unavailableBackend struct {
	kind      Backend
	platforms []attestation.Platform
	reason    string
}

func (u *unavailableBackend) Kind() Backend { return u.kind }
func (u *unavailableBackend) Available() error {
	return errors.New("confidential: " + string(u.kind) + " backend not yet operational: " + u.reason)
}
func (u *unavailableBackend) SatisfiesPlatform(p Platform) bool {
	for _, pl := range u.platforms {
		if attestation.Platform(p) == pl {
			return true
		}
	}
	return false
}
func (u *unavailableBackend) Prepare(context.Context, ConfidentialityPolicy) (Session, error) {
	return nil, u.Available()
}
func (u *unavailableBackend) Execute(context.Context, Session, EncryptedInput, ModelRef) (Output, ConfidentialityAttestation, error) {
	return Output{}, ConfidentialityAttestation{}, u.Available()
}

// NewGPUCCBackend — confidential-compute-mode GPU for large-model inference.
func NewGPUCCBackend() ConfidentialBackend {
	return &unavailableBackend{kind: BackendGPUCC, platforms: []attestation.Platform{attestation.PlatformNVIDIAGPU}, reason: "confidential-GPU executor pending"}
}

// NewMPCBackend — threshold secure-multiparty computation.
func NewMPCBackend() ConfidentialBackend {
	return &unavailableBackend{kind: BackendMPC, reason: "MPC session layer pending"}
}

// NewFHEBackend — fully homomorphic encryption (research tier; slow, small models).
func NewFHEBackend() ConfidentialBackend {
	return &unavailableBackend{kind: BackendFHE, reason: "FHE runtime pending (research tier)"}
}

type noopSession struct{}

func (noopSession) Close() error { return nil }
