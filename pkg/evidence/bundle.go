// Package evidence provides portable, self-contained evidence bundles that
// can be verified offline without network access. Evidence bundles package
// audit records, verification seals, TEE attestations, and chain-of-custody
// metadata into cryptographically-bound artifacts.
//
// This package is distinct from pkg/audit's bundle implementation in that it
// focuses on portability and standalone verification, while pkg/audit focuses
// on internal audit trail management.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Evidence bundle schema version
// ---------------------------------------------------------------------------

const SchemaVersion = "1.0.0"

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// Record represents an individual evidence record within a bundle.
type Record struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "audit", "computation", "verification", "governance"
	Action      string            `json:"action"`
	Actor       string            `json:"actor"`
	Timestamp   string            `json:"timestamp"`
	BlockHeight int64             `json:"block_height,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
	Hash        string            `json:"hash"`
}

// ComputeHash computes the SHA-256 hash of a record's content.
func (r *Record) ComputeHash() string {
	h := sha256.New()
	h.Write([]byte(r.ID))
	h.Write([]byte(r.Type))
	h.Write([]byte(r.Action))
	h.Write([]byte(r.Actor))
	h.Write([]byte(r.Timestamp))
	data, _ := json.Marshal(r.Data)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Seal represents a cryptographic verification seal.
type Seal struct {
	SealID         string `json:"seal_id"`
	JobID          string `json:"job_id"`
	OutputHash     string `json:"output_hash"`
	ValidatorCount int    `json:"validator_count"`
	BlockHeight    int64  `json:"block_height"`
	Timestamp      string `json:"timestamp"`
}

// Attestation represents a TEE or validator attestation.
type Attestation struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "tee", "validator", "zkml"
	Platform    string            `json:"platform,omitempty"`
	EnclaveID   string            `json:"enclave_id,omitempty"`
	Measurement string            `json:"measurement,omitempty"`
	Timestamp   string            `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CustodyEntry records a single custody transfer event.
type CustodyEntry struct {
	Custodian    string `json:"custodian"`
	Action       string `json:"action"` // "created", "transfer", "export", "verify"
	Timestamp    string `json:"timestamp"`
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature,omitempty"`
}

// ComputeHash computes the SHA-256 hash of a custody entry.
func (ce *CustodyEntry) ComputeHash() string {
	h := sha256.New()
	h.Write([]byte(ce.Custodian))
	h.Write([]byte(ce.Action))
	h.Write([]byte(ce.Timestamp))
	h.Write([]byte(ce.PreviousHash))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Evidence Bundle
// ---------------------------------------------------------------------------

// EvidenceBundle is a self-contained, cryptographically-bound package of
// trust evidence for one or more computation jobs.
type EvidenceBundle struct {
	// Identity
	ID            string `json:"bundle_id"`
	Version       string `json:"schema_version"`
	CreatedAt     string `json:"created_at"`

	// Framework context
	Framework string `json:"framework,omitempty"`

	// Evidence components
	Records      []Record      `json:"records"`
	Seals        []Seal        `json:"seals,omitempty"`
	Attestations []Attestation `json:"attestations,omitempty"`

	// Chain of custody
	ChainOfCustody []CustodyEntry `json:"chain_of_custody,omitempty"`

	// Integrity
	ContentHash string `json:"content_hash"`
	Signature   string `json:"signature,omitempty"`

	// Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewEvidenceBundle creates a new empty evidence bundle for the given framework.
func NewEvidenceBundle(framework string) *EvidenceBundle {
	return &EvidenceBundle{
		ID:             uuid.New().String(),
		Version:        SchemaVersion,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		Framework:      framework,
		Records:        make([]Record, 0),
		Seals:          make([]Seal, 0),
		Attestations:   make([]Attestation, 0),
		ChainOfCustody: make([]CustodyEntry, 0),
		Metadata:       make(map[string]string),
	}
}

// AddRecord appends an evidence record to the bundle.
func (eb *EvidenceBundle) AddRecord(record Record) {
	if record.Hash == "" {
		record.Hash = record.ComputeHash()
	}
	eb.Records = append(eb.Records, record)
}

// AddSeal appends a verification seal to the bundle.
func (eb *EvidenceBundle) AddSeal(seal Seal) {
	eb.Seals = append(eb.Seals, seal)
}

// AddAttestation appends an attestation to the bundle.
func (eb *EvidenceBundle) AddAttestation(attestation Attestation) {
	eb.Attestations = append(eb.Attestations, attestation)
}

// Finalize computes the content hash and optionally signs the bundle.
// The signer parameter is a hex-encoded signing key; pass empty string
// to skip signing.
func (eb *EvidenceBundle) Finalize(signer string) error {
	if len(eb.Records) == 0 {
		return fmt.Errorf("EvidenceBundle.Finalize: %w: at least one record is required", ErrInvalidBundle)
	}

	// Check for nil/empty content before computing hash.
	for i, r := range eb.Records {
		if r.ID == "" {
			return fmt.Errorf("EvidenceBundle.Finalize: %w: record %d has empty ID", ErrInvalidBundle, i)
		}
	}

	// Add a custody entry for finalization BEFORE computing the hash,
	// so the hash covers the complete state including the seal entry.
	eb.addCustodyEntry("system", "seal")

	hash, err := eb.computeContentHash()
	if err != nil {
		return fmt.Errorf("EvidenceBundle.Finalize: %w", err)
	}
	eb.ContentHash = hash

	if signer != "" {
		sig, err := computeSignature(hash, signer)
		if err != nil {
			return fmt.Errorf("EvidenceBundle.Finalize: %w: %v", ErrSignatureInvalid, err)
		}
		eb.Signature = sig
	}

	return nil
}

// Validate checks the bundle's structural integrity and content hash.
func (eb *EvidenceBundle) Validate() error {
	if eb.ID == "" {
		return fmt.Errorf("EvidenceBundle.Validate: %w: ID is empty", ErrInvalidBundle)
	}
	if eb.Version == "" {
		return fmt.Errorf("EvidenceBundle.Validate: %w: schema version is empty", ErrInvalidBundle)
	}
	if len(eb.Records) == 0 {
		return fmt.Errorf("EvidenceBundle.Validate: %w: at least one record is required", ErrInvalidBundle)
	}
	if eb.ContentHash == "" {
		return fmt.Errorf("EvidenceBundle.Validate: %w: call Finalize first", ErrBundleNotFinalized)
	}

	// Verify content hash.
	computed, err := eb.computeContentHash()
	if err != nil {
		return fmt.Errorf("EvidenceBundle.Validate: %w: %v", ErrVerificationFailed, err)
	}
	if computed != eb.ContentHash {
		return fmt.Errorf("EvidenceBundle.Validate: %w: expected %s, computed %s",
			ErrChainBroken, eb.ContentHash, computed)
	}

	// Verify individual record hashes.
	for i, r := range eb.Records {
		expected := r.ComputeHash()
		if r.Hash != expected {
			return fmt.Errorf("EvidenceBundle.Validate: %w: record %d hash mismatch", ErrChainBroken, i)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// computeContentHash computes SHA-256 over the canonical bundle content,
// excluding content hash and signature.
func (eb *EvidenceBundle) computeContentHash() (string, error) {
	type hashable struct {
		ID             string            `json:"bundle_id"`
		Version        string            `json:"schema_version"`
		CreatedAt      string            `json:"created_at"`
		Framework      string            `json:"framework"`
		Records        []Record          `json:"records"`
		Seals          []Seal            `json:"seals"`
		Attestations   []Attestation     `json:"attestations"`
		ChainOfCustody []CustodyEntry    `json:"chain_of_custody"`
		Metadata       map[string]string `json:"metadata"`
	}

	h := hashable{
		ID:             eb.ID,
		Version:        eb.Version,
		CreatedAt:      eb.CreatedAt,
		Framework:      eb.Framework,
		Records:        eb.Records,
		Seals:          eb.Seals,
		Attestations:   eb.Attestations,
		ChainOfCustody: eb.ChainOfCustody,
		Metadata:       eb.Metadata,
	}

	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("evidence/bundle: marshal failed: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// computeSignature creates an HMAC-SHA256 signature of the content hash.
func computeSignature(contentHash, signerKey string) (string, error) {
	if contentHash == "" {
		return "", fmt.Errorf("computeSignature: %w: content hash is empty", ErrSignatureInvalid)
	}
	keyBytes, err := hex.DecodeString(signerKey)
	if err != nil {
		return "", fmt.Errorf("computeSignature: %w: invalid signer key encoding: %v", ErrSignatureInvalid, err)
	}
	// Validate signer key length: must be at least 16 bytes (128 bits).
	if len(keyBytes) < 16 {
		return "", fmt.Errorf("computeSignature: %w: signer key too short (%d bytes, minimum 16)", ErrSignatureInvalid, len(keyBytes))
	}

	h := sha256.New()
	h.Write([]byte("aethelred_evidence_sig_v1:"))
	h.Write(keyBytes)
	h.Write([]byte(contentHash))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// addCustodyEntry appends a new custody entry to the chain.
func (eb *EvidenceBundle) addCustodyEntry(custodian, action string) {
	prevHash := ""
	if len(eb.ChainOfCustody) > 0 {
		prevHash = eb.ChainOfCustody[len(eb.ChainOfCustody)-1].Hash
	}

	entry := CustodyEntry{
		Custodian:    custodian,
		Action:       action,
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: prevHash,
	}
	entry.Hash = entry.ComputeHash()
	eb.ChainOfCustody = append(eb.ChainOfCustody, entry)
}
