package securecells

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SecureCellRecord is the durable snapshot for one secure-cell runtime.
type SecureCellRecord struct {
	CellID   string            `json:"cell_id"`
	Request  SecureCellRequest `json:"request"`
	Result   *SecureCellResult `json:"result"`
	StoredAt time.Time         `json:"stored_at"`
}

// SecureCellStore persists secure-cell workflow state.
type SecureCellStore interface {
	Save(ctx context.Context, record *SecureCellRecord) error
	Get(ctx context.Context, cellID string) (*SecureCellRecord, error)
	List(ctx context.Context) ([]*SecureCellRecord, error)
}

// InMemorySecureCellStore keeps secure-cell state in memory.
type InMemorySecureCellStore struct {
	mu      sync.RWMutex
	records map[string]*SecureCellRecord
}

// NewInMemorySecureCellStore creates an in-memory secure-cell store.
func NewInMemorySecureCellStore() *InMemorySecureCellStore {
	return &InMemorySecureCellStore{records: make(map[string]*SecureCellRecord)}
}

// Save stores a cloned secure-cell record in memory.
func (s *InMemorySecureCellStore) Save(_ context.Context, record *SecureCellRecord) error {
	cloned, cellID, err := prepareSecureCellRecordForStorage(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[cellID] = cloned
	return nil
}

// Get returns one cloned secure-cell record from memory.
func (s *InMemorySecureCellStore) Get(_ context.Context, cellID string) (*SecureCellRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[strings.TrimSpace(cellID)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return cloneSecureCellRecord(record)
}

// List returns cloned secure-cell records sorted by most-recent update.
func (s *InMemorySecureCellStore) List(_ context.Context) ([]*SecureCellRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*SecureCellRecord, 0, len(s.records))
	for _, record := range s.records {
		cloned, err := cloneSecureCellRecord(record)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return secureCellRecordSortTime(out[i]).After(secureCellRecordSortTime(out[j]))
	})
	return out, nil
}

// FileSecureCellStore persists secure-cell state as JSON snapshots on disk.
type FileSecureCellStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileSecureCellStore creates a file-backed secure-cell store rooted at the
// provided directory.
func NewFileSecureCellStore(dir string) (*FileSecureCellStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("securecells/store: directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("securecells/store: create directory: %w", err)
	}
	return &FileSecureCellStore{dir: dir}, nil
}

// Save persists one secure-cell record to disk.
func (s *FileSecureCellStore) Save(_ context.Context, record *SecureCellRecord) error {
	cloned, cellID, err := prepareSecureCellRecordForStorage(record)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cloned, "", "  ")
	if err != nil {
		return fmt.Errorf("securecells/store: marshal record: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	recordPath, err := s.recordPath(cellID)
	if err != nil {
		return err
	}
	tmpPath := recordPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("securecells/store: write temp record: %w", err)
	}
	if err := os.Rename(tmpPath, recordPath); err != nil {
		return fmt.Errorf("securecells/store: commit record file: %w", err)
	}
	return nil
}

// Get reads one secure-cell record from disk.
func (s *FileSecureCellStore) Get(_ context.Context, cellID string) (*SecureCellRecord, error) {
	recordPath, err := s.recordPath(cellID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(recordPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrCellNotFound, strings.TrimSpace(cellID))
		}
		return nil, fmt.Errorf("securecells/store: read record: %w", err)
	}

	var record SecureCellRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("securecells/store: decode record: %w", err)
	}
	cloned, _, err := prepareSecureCellRecordForStorage(&record)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

// List reads all secure-cell records from disk.
func (s *FileSecureCellStore) List(_ context.Context) ([]*SecureCellRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("securecells/store: read directory: %w", err)
	}

	out := make([]*SecureCellRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("securecells/store: read record %q: %w", entry.Name(), err)
		}
		var record SecureCellRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("securecells/store: decode record %q: %w", entry.Name(), err)
		}
		cloned, _, err := prepareSecureCellRecordForStorage(&record)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return secureCellRecordSortTime(out[i]).After(secureCellRecordSortTime(out[j]))
	})
	return out, nil
}

func (s *FileSecureCellStore) recordPath(cellID string) (string, error) {
	normalized := strings.TrimSpace(cellID)
	if normalized == "" {
		return "", fmt.Errorf("securecells/store: cell ID is required")
	}
	if normalized != filepath.Base(normalized) || strings.Contains(normalized, "..") {
		return "", fmt.Errorf("%w: %s", ErrCellNotFound, normalized)
	}
	return filepath.Join(s.dir, normalized+".json"), nil
}

func prepareSecureCellRecordForStorage(record *SecureCellRecord) (*SecureCellRecord, string, error) {
	if record == nil {
		return nil, "", fmt.Errorf("securecells/store: record is required")
	}
	cloned, err := cloneSecureCellRecord(record)
	if err != nil {
		return nil, "", err
	}
	if cloned.Result == nil {
		return nil, "", fmt.Errorf("securecells/store: result is required")
	}
	cellID := strings.TrimSpace(firstNonEmpty(cloned.CellID, cloned.Result.CellID, cellID(cloned.Request)))
	if cellID == "" {
		return nil, "", fmt.Errorf("securecells/store: cell ID is required")
	}
	cloned.CellID = cellID
	cloned.Result.CellID = cellID
	if cloned.StoredAt.IsZero() {
		cloned.StoredAt = time.Now().UTC()
	}
	return cloned, cellID, nil
}

func cloneSecureCellRecord(in *SecureCellRecord) (*SecureCellRecord, error) {
	if in == nil {
		return nil, nil
	}
	request, err := cloneSecureCellRequest(in.Request)
	if err != nil {
		return nil, err
	}
	result, err := cloneResult(in.Result)
	if err != nil {
		return nil, err
	}
	return &SecureCellRecord{
		CellID:   strings.TrimSpace(in.CellID),
		Request:  request,
		Result:   result,
		StoredAt: in.StoredAt.UTC(),
	}, nil
}

func cloneSecureCellRequest(in SecureCellRequest) (SecureCellRequest, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return SecureCellRequest{}, err
	}
	var out SecureCellRequest
	if err := json.Unmarshal(data, &out); err != nil {
		return SecureCellRequest{}, err
	}
	return out, nil
}

func secureCellRecordSortTime(record *SecureCellRecord) time.Time {
	if record == nil || record.Result == nil {
		return time.Time{}
	}
	if !record.Result.UpdatedAt.IsZero() {
		return record.Result.UpdatedAt
	}
	if !record.Result.CreatedAt.IsZero() {
		return record.Result.CreatedAt
	}
	return record.StoredAt
}
