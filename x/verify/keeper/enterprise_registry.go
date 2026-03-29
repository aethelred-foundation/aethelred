package keeper

import (
	"fmt"
	"sync"
	"time"
)

// RegistryStatus represents the lifecycle state of a registry entry.
type RegistryStatus int

const (
	// RegistryStatusActive indicates the entry is active and valid for verification.
	RegistryStatusActive RegistryStatus = iota
	// RegistryStatusRevoked indicates the entry has been revoked and must not be used.
	RegistryStatusRevoked
	// RegistryStatusDeprecated indicates the entry is deprecated but still valid.
	RegistryStatusDeprecated
)

// String returns the human-readable status name.
func (s RegistryStatus) String() string {
	switch s {
	case RegistryStatusActive:
		return "active"
	case RegistryStatusRevoked:
		return "revoked"
	case RegistryStatusDeprecated:
		return "deprecated"
	default:
		return "unknown"
	}
}

// SignedRegistryEntry represents a governed measurement or circuit hash in the
// enterprise registry. Each entry tracks its lifecycle from activation through
// potential revocation, with cryptographic signatures for auditability.
type SignedRegistryEntry struct {
	// Hash is the SHA-256 hash identifying the measurement or circuit.
	Hash string

	// Version is the registry version at which this entry was activated.
	Version uint64

	// Status is the current lifecycle state.
	Status RegistryStatus

	// ActivatedAt records when the entry was activated.
	ActivatedAt time.Time

	// RevokedAt records when the entry was revoked (zero if not revoked).
	RevokedAt time.Time

	// RevokeReason explains why the entry was revoked (empty if not revoked).
	RevokeReason string

	// Signature is the governance authority signature over the entry.
	Signature []byte
}

// JobRegistryUsage records which registry versions a job used at verification
// time, providing a complete audit trail for compliance.
type JobRegistryUsage struct {
	JobID              string
	MeasurementVersion uint64
	CircuitVersion     uint64
	RecordedAt         time.Time
}

// EnterpriseRegistry provides governed lifecycle management for measurement
// and circuit hashes. It supports activation, revocation, versioning, and
// per-job audit trails of which registry versions were used.
//
// SECURITY: All mutations increment the version counter to ensure that
// downstream consumers can detect registry changes. Revoked entries are
// never deleted — they remain in the registry with status Revoked for
// auditability.
type EnterpriseRegistry struct {
	mu      sync.RWMutex
	entries map[string]*SignedRegistryEntry
	version uint64

	jobUsages map[string]*JobRegistryUsage
}

// NewEnterpriseRegistry creates a new empty enterprise registry.
func NewEnterpriseRegistry() *EnterpriseRegistry {
	return &EnterpriseRegistry{
		entries:   make(map[string]*SignedRegistryEntry),
		jobUsages: make(map[string]*JobRegistryUsage),
	}
}

// ActivateEntry adds a hash to the active registry with the given governance
// signature. If the hash is already active, an error is returned. If the hash
// was previously revoked, it cannot be re-activated — a new hash must be used.
func (r *EnterpriseRegistry) ActivateEntry(hash string, signature []byte) error {
	if hash == "" {
		return fmt.Errorf("enterprise registry: hash cannot be empty")
	}
	if len(signature) == 0 {
		return fmt.Errorf("enterprise registry: signature cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.entries[hash]; ok {
		if existing.Status == RegistryStatusActive {
			return fmt.Errorf("enterprise registry: entry %s is already active", hash)
		}
		if existing.Status == RegistryStatusRevoked {
			return fmt.Errorf("enterprise registry: entry %s was revoked and cannot be re-activated", hash)
		}
	}

	r.version++
	r.entries[hash] = &SignedRegistryEntry{
		Hash:        hash,
		Version:     r.version,
		Status:      RegistryStatusActive,
		ActivatedAt: time.Now().UTC(),
		Signature:   signature,
	}
	return nil
}

// RevokeEntry marks an active entry as revoked with the given reason.
// Revoked entries remain in the registry for audit purposes but will
// fail all subsequent IsActive checks.
func (r *EnterpriseRegistry) RevokeEntry(hash string, reason string) error {
	if hash == "" {
		return fmt.Errorf("enterprise registry: hash cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[hash]
	if !ok {
		return fmt.Errorf("enterprise registry: entry %s not found", hash)
	}
	if entry.Status == RegistryStatusRevoked {
		return fmt.Errorf("enterprise registry: entry %s is already revoked", hash)
	}

	r.version++
	entry.Status = RegistryStatusRevoked
	entry.RevokedAt = time.Now().UTC()
	entry.RevokeReason = reason
	return nil
}

// IsActive returns true if the hash is in the registry and has status Active.
func (r *EnterpriseRegistry) IsActive(hash string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.entries[hash]
	if !ok {
		return false
	}
	return entry.Status == RegistryStatusActive
}

// GetEntry returns the registry entry for the given hash, or nil if not found.
func (r *EnterpriseRegistry) GetEntry(hash string) *SignedRegistryEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.entries[hash]
	if !ok {
		return nil
	}
	// Return a copy to prevent external mutation.
	cp := *entry
	return &cp
}

// GetRegistryVersion returns the current registry version counter.
// The version increments on every activation or revocation.
func (r *EnterpriseRegistry) GetRegistryVersion() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// RecordJobRegistryUsage records which measurement and circuit registry
// versions were used when verifying a specific job. This creates an
// immutable audit trail for compliance and forensic analysis.
func (r *EnterpriseRegistry) RecordJobRegistryUsage(jobID string, measurementVersion, circuitVersion uint64) error {
	if jobID == "" {
		return fmt.Errorf("enterprise registry: jobID cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.jobUsages[jobID] = &JobRegistryUsage{
		JobID:              jobID,
		MeasurementVersion: measurementVersion,
		CircuitVersion:     circuitVersion,
		RecordedAt:         time.Now().UTC(),
	}
	return nil
}

// GetJobRegistryUsage retrieves the registry usage record for a job.
func (r *EnterpriseRegistry) GetJobRegistryUsage(jobID string) *JobRegistryUsage {
	r.mu.RLock()
	defer r.mu.RUnlock()

	usage, ok := r.jobUsages[jobID]
	if !ok {
		return nil
	}
	cp := *usage
	return &cp
}
