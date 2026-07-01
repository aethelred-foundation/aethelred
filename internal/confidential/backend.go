package confidential

import (
	"context"
	"fmt"
	"sort"
)

// EncryptedInput is opaque, backend-specific ciphertext (a TEE-sealed blob, an
// FHE ciphertext, MPC shares, …). The confidential layer never handles plaintext.
type EncryptedInput []byte

// ModelRef identifies the model to run (its on-chain commitment / registry id).
type ModelRef struct {
	ModelHash []byte
	ModelID   string
}

// Output is the (committed) result of a confidential computation. Only the
// commitment is public; any plaintext output stays inside the backend boundary.
type Output struct {
	OutputCommitment []byte
	// Plaintext is present only when the policy permits disclosure to the caller;
	// for confidential workloads it is nil and the result is fetched out of band.
	Plaintext []byte
}

// Session is an opaque, backend-held handle for a prepared computation
// (enclave instance, FHE key context, MPC session).
type Session interface{ Close() error }

// ConfidentialBackend is a pluggable confidentiality provider. Adding FHE / MPC /
// GPU-CC later is a new implementation of this interface, not a protocol change.
type ConfidentialBackend interface {
	// Kind reports which confidentiality backend this is.
	Kind() Backend
	// Available returns nil if the backend is operational in this deployment, or a
	// descriptive error otherwise. Backends MUST report honestly — a not-yet-wired
	// backend returns a non-nil error and is never selected.
	Available() error
	// SatisfiesPlatform reports whether the backend can attest as the given platform.
	SatisfiesPlatform(p Platform) bool
	// Prepare provisions a session honouring the policy (enclave launch, FHE keys,
	// MPC session). Callers Close() the returned session.
	Prepare(ctx context.Context, policy ConfidentialityPolicy) (Session, error)
	// Execute runs the model on the encrypted input inside the confidentiality
	// boundary and returns the committed output plus a signed attestation of how
	// the data was protected.
	Execute(ctx context.Context, s Session, in EncryptedInput, m ModelRef) (Output, ConfidentialityAttestation, error)
}

// Platform re-exports the attestation platform type at the confidential layer for
// the SatisfiesPlatform signature; it is the same underlying type.
type Platform = string

// Registry holds the confidentiality backends wired into a deployment and selects
// among them under a policy.
type Registry struct {
	backends map[Backend]ConfidentialBackend
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry { return &Registry{backends: make(map[Backend]ConfidentialBackend)} }

// Register adds a backend (last registration for a Kind wins).
func (r *Registry) Register(b ConfidentialBackend) { r.backends[b.Kind()] = b }

// Get returns a registered backend.
func (r *Registry) Get(k Backend) (ConfidentialBackend, bool) { b, ok := r.backends[k]; return b, ok }

// AvailableBackends returns the kinds that are registered AND operational, sorted
// for determinism.
func (r *Registry) AvailableBackends() []Backend {
	var ks []Backend
	for k, b := range r.backends {
		if b.Available() == nil {
			ks = append(ks, k)
		}
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

// Select deterministically chooses the strongest-confidentiality backend that is
// registered, operational, and permitted by the policy. It is a worker/scheduler
// helper — consensus does NOT re-select; validators verify the returned
// attestation via ConfidentialityAttestation.Satisfies. Returns an error if no
// backend satisfies the policy (the job is rejected, never downgraded).
func (r *Registry) Select(policy ConfidentialityPolicy) (ConfidentialBackend, error) {
	var best ConfidentialBackend
	bestStrength := -1
	// Iterate in a stable order so ties resolve deterministically.
	kinds := make([]Backend, 0, len(r.backends))
	for k := range r.backends {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	for _, k := range kinds {
		b := r.backends[k]
		if b.Available() != nil {
			continue
		}
		if !policy.backendAllowed(k) {
			continue
		}
		s := k.confidentialityStrength()
		if s > bestStrength {
			best, bestStrength = b, s
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no available confidentiality backend satisfies policy (allowed=%v)", policy.AllowedBackends)
	}
	return best, nil
}
