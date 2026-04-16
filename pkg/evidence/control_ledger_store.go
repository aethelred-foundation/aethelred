package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	// ErrControlLedgerNotFound indicates that the requested ledger does not
	// exist in the configured source of truth.
	ErrControlLedgerNotFound = errors.New("evidence/control_ledger_store: control ledger not found")

	// ErrInvalidControlLedgerID indicates that a caller supplied an unsafe or
	// malformed ledger identifier.
	ErrInvalidControlLedgerID = errors.New("evidence/control_ledger_store: invalid ledger ID")
)

var controlLedgerIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ControlLedgerStore defines the persistence contract for control ledgers.
type ControlLedgerStore interface {
	Save(ctx context.Context, ledger *ControlLedger) error
	Get(ctx context.Context, ledgerID string) (*ControlLedger, error)
	List(ctx context.Context) ([]*ControlLedger, error)
}

// InMemoryControlLedgerStore is a lightweight store for tests and local
// development.
type InMemoryControlLedgerStore struct {
	mu      sync.RWMutex
	ledgers map[string]*ControlLedger
}

// NewInMemoryControlLedgerStore creates a new in-memory control-ledger store.
func NewInMemoryControlLedgerStore() *InMemoryControlLedgerStore {
	return &InMemoryControlLedgerStore{
		ledgers: make(map[string]*ControlLedger),
	}
}

// Save persists a ledger in memory using a defensive clone.
func (s *InMemoryControlLedgerStore) Save(_ context.Context, ledger *ControlLedger) error {
	cloned, ledgerID, err := prepareControlLedgerForStorage(ledger)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ledgers[ledgerID] = cloned
	return nil
}

// Get retrieves a ledger by ID from memory.
func (s *InMemoryControlLedgerStore) Get(_ context.Context, ledgerID string) (*ControlLedger, error) {
	normalizedLedgerID, err := validateControlLedgerID(ledgerID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ledger, ok := s.ledgers[normalizedLedgerID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrControlLedgerNotFound, normalizedLedgerID)
	}

	return cloneControlLedger(ledger)
}

// List returns all ledgers in memory.
func (s *InMemoryControlLedgerStore) List(_ context.Context) ([]*ControlLedger, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ledgerIDs := make([]string, 0, len(s.ledgers))
	for ledgerID := range s.ledgers {
		ledgerIDs = append(ledgerIDs, ledgerID)
	}
	sort.Strings(ledgerIDs)

	out := make([]*ControlLedger, 0, len(ledgerIDs))
	for _, ledgerID := range ledgerIDs {
		ledger := s.ledgers[ledgerID]
		cloned, err := cloneControlLedger(ledger)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}
	return out, nil
}

// FileControlLedgerStore persists control ledgers as JSON snapshots on disk.
type FileControlLedgerStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileControlLedgerStore creates a file-backed control-ledger store rooted
// at the provided directory.
func NewFileControlLedgerStore(dir string) (*FileControlLedgerStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("evidence/control_ledger_store: directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("evidence/control_ledger_store: create directory: %w", err)
	}
	return &FileControlLedgerStore{dir: dir}, nil
}

// Save persists a ledger to disk as a JSON snapshot.
func (s *FileControlLedgerStore) Save(_ context.Context, ledger *ControlLedger) error {
	cloned, ledgerID, err := prepareControlLedgerForStorage(ledger)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cloned, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence/control_ledger_store: marshal ledger: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ledgerPath, err := s.ledgerPath(ledgerID)
	if err != nil {
		return err
	}

	tmpPath := ledgerPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("evidence/control_ledger_store: write temp ledger: %w", err)
	}
	if err := os.Rename(tmpPath, ledgerPath); err != nil {
		return fmt.Errorf("evidence/control_ledger_store: commit ledger file: %w", err)
	}

	return nil
}

// Get retrieves and decodes a ledger from disk.
func (s *FileControlLedgerStore) Get(_ context.Context, ledgerID string) (*ControlLedger, error) {
	ledgerPath, err := s.ledgerPath(ledgerID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrControlLedgerNotFound, strings.TrimSpace(ledgerID))
		}
		return nil, fmt.Errorf("evidence/control_ledger_store: read ledger: %w", err)
	}

	var ledger ControlLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		return nil, fmt.Errorf("evidence/control_ledger_store: decode ledger: %w", err)
	}

	return cloneControlLedger(&ledger)
}

// List returns all ledgers persisted under the store directory.
func (s *FileControlLedgerStore) List(_ context.Context) ([]*ControlLedger, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("evidence/control_ledger_store: read directory: %w", err)
	}

	out := make([]*ControlLedger, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("evidence/control_ledger_store: read ledger file: %w", err)
		}
		var ledger ControlLedger
		if err := json.Unmarshal(data, &ledger); err != nil {
			return nil, fmt.Errorf("evidence/control_ledger_store: decode ledger file: %w", err)
		}
		cloned, err := cloneControlLedger(&ledger)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}

	return out, nil
}

func (s *FileControlLedgerStore) ledgerPath(ledgerID string) (string, error) {
	normalizedLedgerID, err := validateControlLedgerID(ledgerID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, normalizedLedgerID+".json"), nil
}

func validateControlLedgerID(ledgerID string) (string, error) {
	normalizedLedgerID := strings.TrimSpace(ledgerID)
	if normalizedLedgerID == "" {
		return "", fmt.Errorf("%w: ledger ID is required", ErrInvalidControlLedgerID)
	}
	if strings.Contains(normalizedLedgerID, "..") || !controlLedgerIDPattern.MatchString(normalizedLedgerID) {
		return "", fmt.Errorf("%w: %s", ErrInvalidControlLedgerID, normalizedLedgerID)
	}
	return normalizedLedgerID, nil
}

func prepareControlLedgerForStorage(ledger *ControlLedger) (*ControlLedger, string, error) {
	if ledger == nil || ledger.Bundle == nil {
		return nil, "", fmt.Errorf("evidence/control_ledger_store: nil control ledger")
	}

	ledgerID, err := validateControlLedgerID(ledger.Bundle.ID)
	if err != nil {
		return nil, "", err
	}

	cloned, err := cloneControlLedger(ledger)
	if err != nil {
		return nil, "", err
	}

	if cloned.Bundle.ContentHash == "" {
		if err := cloned.Finalize(""); err != nil {
			return nil, "", fmt.Errorf("evidence/control_ledger_store: finalize ledger: %w", err)
		}
	}
	if err := cloned.Validate(); err != nil {
		return nil, "", fmt.Errorf("evidence/control_ledger_store: validate ledger: %w", err)
	}

	return cloned, ledgerID, nil
}

func cloneControlLedger(ledger *ControlLedger) (*ControlLedger, error) {
	if ledger == nil {
		return nil, fmt.Errorf("evidence/control_ledger_store: nil control ledger")
	}

	clonedBundle, err := cloneEvidenceBundle(ledger.Bundle)
	if err != nil {
		return nil, err
	}

	cloned := &ControlLedger{
		Bundle:   clonedBundle,
		Controls: cloneLedgerControls(ledger.Controls),
		Summary:  ledger.Summary,
		Metadata: cloneStringMapPreserve(ledger.Metadata),
	}

	return cloned, nil
}

func cloneLedgerControls(in []LedgerControl) []LedgerControl {
	if in == nil {
		return nil
	}
	out := make([]LedgerControl, len(in))
	for i, control := range in {
		out[i] = control
		out[i].EvidenceRefs = cloneControlEvidenceRefs(control.EvidenceRefs)
		out[i].Findings = cloneStringSlicePreserve(control.Findings)
		out[i].Metadata = cloneStringMapPreserve(control.Metadata)
	}
	return out
}
