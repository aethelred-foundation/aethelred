package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Cryptographic Chain of Custody
// ---------------------------------------------------------------------------
//
// Chain of custody tracks who has held or accessed an evidence bundle over
// time. Each custody transfer is cryptographically linked to the previous
// one, forming an append-only chain that proves the bundle's provenance.
//
// This is essential for:
//   - Legal admissibility of evidence
//   - Regulatory audits requiring proof of evidence handling
//   - Internal compliance tracking
//   - Detecting unauthorized access or modification
// ---------------------------------------------------------------------------

// CustodyAction describes the type of custody event.
type CustodyAction string

const (
	CustodyCreated    CustodyAction = "created"
	CustodyTransfer   CustodyAction = "transfer"
	CustodyAccess     CustodyAction = "access"
	CustodyExport     CustodyAction = "export"
	CustodyArchive    CustodyAction = "archive"
	CustodyDelete     CustodyAction = "delete"
	CustodySeal       CustodyAction = "seal"     // Bundle was sealed/finalized.
	CustodyVerify     CustodyAction = "verify"    // Bundle integrity was verified.
)

// CustodyRecord is a single entry in the chain of custody.
type CustodyRecord struct {
	// BundleID identifies the evidence bundle.
	BundleID string `json:"bundle_id"`

	// Custodian is the current holder of the bundle.
	Custodian string `json:"custodian"`

	// Action describes what happened.
	Action CustodyAction `json:"action"`

	// PreviousCustodian is the prior holder (for transfers).
	PreviousCustodian string `json:"previous_custodian,omitempty"`

	// Timestamp records when the event occurred.
	Timestamp string `json:"timestamp"`

	// Signature is the custodian's cryptographic signature of this record.
	Signature string `json:"signature"`

	// RecordHash is the SHA-256 hash of this record's content.
	RecordHash string `json:"record_hash"`

	// PreviousHash links this record to the prior chain entry.
	PreviousHash string `json:"previous_hash"`

	// Notes contains optional human-readable context.
	Notes string `json:"notes,omitempty"`
}

// CustodyChain is the complete chain of custody for an evidence bundle.
type CustodyChain struct {
	BundleID string           `json:"bundle_id"`
	Records  []CustodyRecord  `json:"records"`
}

// CustodyStore manages chains of custody for multiple evidence bundles.
type CustodyStore struct {
	mu     sync.RWMutex
	chains map[string]*CustodyChain // bundleID -> chain
}

// NewCustodyStore creates a new custody store.
func NewCustodyStore() *CustodyStore {
	return &CustodyStore{
		chains: make(map[string]*CustodyChain),
	}
}

// ---------------------------------------------------------------------------
// Custody operations
// ---------------------------------------------------------------------------

// InitCustody creates a new chain of custody for a bundle, recording the
// initial custodian.
func (cs *CustodyStore) InitCustody(bundleID, custodian, signature string) (*CustodyRecord, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, exists := cs.chains[bundleID]; exists {
		return nil, fmt.Errorf("audit/custody: chain already exists for bundle %s", bundleID)
	}

	record := CustodyRecord{
		BundleID:     bundleID,
		Custodian:    custodian,
		Action:       CustodyCreated,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Signature:    signature,
		PreviousHash: "genesis",
	}
	record.RecordHash = computeCustodyHash(record)

	chain := &CustodyChain{
		BundleID: bundleID,
		Records:  []CustodyRecord{record},
	}
	cs.chains[bundleID] = chain

	return &record, nil
}

// Transfer records a custody transfer from one party to another.
func (cs *CustodyStore) Transfer(bundleID, from, to, signature string) (*CustodyRecord, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	chain, ok := cs.chains[bundleID]
	if !ok {
		return nil, fmt.Errorf("audit/custody: no chain found for bundle %s", bundleID)
	}

	if len(chain.Records) == 0 {
		return nil, fmt.Errorf("audit/custody: empty chain for bundle %s", bundleID)
	}

	// Verify the transfer is from the current custodian.
	lastRecord := chain.Records[len(chain.Records)-1]
	if lastRecord.Custodian != from {
		return nil, fmt.Errorf("audit/custody: transfer must be from current custodian %s, got %s",
			lastRecord.Custodian, from)
	}

	record := CustodyRecord{
		BundleID:          bundleID,
		Custodian:         to,
		Action:            CustodyTransfer,
		PreviousCustodian: from,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Signature:         signature,
		PreviousHash:      lastRecord.RecordHash,
	}
	record.RecordHash = computeCustodyHash(record)

	chain.Records = append(chain.Records, record)
	return &record, nil
}

// RecordAction records a non-transfer custody event (access, export,
// verify, etc.).
func (cs *CustodyStore) RecordAction(bundleID, custodian string, action CustodyAction, signature, notes string) (*CustodyRecord, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	chain, ok := cs.chains[bundleID]
	if !ok {
		return nil, fmt.Errorf("audit/custody: no chain found for bundle %s", bundleID)
	}

	if len(chain.Records) == 0 {
		return nil, fmt.Errorf("audit/custody: empty chain for bundle %s", bundleID)
	}

	lastRecord := chain.Records[len(chain.Records)-1]

	record := CustodyRecord{
		BundleID:     bundleID,
		Custodian:    custodian,
		Action:       action,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Signature:    signature,
		PreviousHash: lastRecord.RecordHash,
		Notes:        notes,
	}
	record.RecordHash = computeCustodyHash(record)

	chain.Records = append(chain.Records, record)
	return &record, nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// VerifyCustody verifies the integrity of a chain of custody by checking
// hash linkage and hash correctness for every record.
func VerifyCustody(chain *CustodyChain) error {
	if chain == nil {
		return fmt.Errorf("audit/custody: nil chain")
	}
	if len(chain.Records) == 0 {
		return fmt.Errorf("audit/custody: empty chain")
	}

	for i, r := range chain.Records {
		// Verify the record hash.
		expected := computeCustodyHash(r)
		if expected != r.RecordHash {
			return fmt.Errorf("audit/custody: hash mismatch at record %d: expected %s, got %s",
				i, expected, r.RecordHash)
		}

		// Verify chain linkage.
		if i == 0 {
			if r.PreviousHash != "genesis" {
				return fmt.Errorf("audit/custody: first record must have previous_hash 'genesis', got %s",
					r.PreviousHash)
			}
			if r.Action != CustodyCreated {
				return fmt.Errorf("audit/custody: first record must have action 'created', got %s",
					r.Action)
			}
		} else {
			prev := chain.Records[i-1]
			if r.PreviousHash != prev.RecordHash {
				return fmt.Errorf("audit/custody: chain break at record %d: previous_hash %s != prior record_hash %s",
					i, r.PreviousHash, prev.RecordHash)
			}
		}

		// Verify bundle ID consistency.
		if r.BundleID != chain.BundleID {
			return fmt.Errorf("audit/custody: bundle ID mismatch at record %d: chain=%s, record=%s",
				i, chain.BundleID, r.BundleID)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

// GetCustodyHistory returns the full chain of custody for a bundle.
func (cs *CustodyStore) GetCustodyHistory(bundleID string) (*CustodyChain, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	chain, ok := cs.chains[bundleID]
	if !ok {
		return nil, fmt.Errorf("audit/custody: no chain found for bundle %s", bundleID)
	}

	// Return a copy.
	result := &CustodyChain{
		BundleID: chain.BundleID,
		Records:  make([]CustodyRecord, len(chain.Records)),
	}
	copy(result.Records, chain.Records)
	return result, nil
}

// GetCurrentCustodian returns the current custodian of a bundle.
func (cs *CustodyStore) GetCurrentCustodian(bundleID string) (string, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	chain, ok := cs.chains[bundleID]
	if !ok {
		return "", fmt.Errorf("audit/custody: no chain found for bundle %s", bundleID)
	}

	if len(chain.Records) == 0 {
		return "", fmt.Errorf("audit/custody: empty chain for bundle %s", bundleID)
	}

	return chain.Records[len(chain.Records)-1].Custodian, nil
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

// computeCustodyHash produces a deterministic SHA-256 hash of a custody
// record. The hash covers all fields except RecordHash itself.
func computeCustodyHash(r CustodyRecord) string {
	canonical := fmt.Sprintf(
		"bundle=%s|custodian=%s|action=%s|prev_custodian=%s|ts=%s|sig=%s|prev_hash=%s|notes=%s",
		r.BundleID, r.Custodian, r.Action, r.PreviousCustodian,
		r.Timestamp, r.Signature, r.PreviousHash, r.Notes,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
