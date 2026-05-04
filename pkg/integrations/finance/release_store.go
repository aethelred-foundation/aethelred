package finance

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

	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

// TreasuryReleaseRecord is the durable snapshot for one treasury release
// workflow, including the normalized request needed to resume the workflow
// after process restart.
type TreasuryReleaseRecord struct {
	WorkflowID string                 `json:"workflow_id"`
	Request    TreasuryReleaseRequest `json:"request"`
	Result     *TreasuryReleaseResult `json:"result"`
	StoredAt   time.Time              `json:"stored_at"`
}

// TreasuryReleaseStore persists treasury release workflow state.
type TreasuryReleaseStore interface {
	Save(ctx context.Context, record *TreasuryReleaseRecord) error
	Get(ctx context.Context, workflowID string) (*TreasuryReleaseRecord, error)
	List(ctx context.Context) ([]*TreasuryReleaseRecord, error)
}

// InMemoryTreasuryReleaseStore keeps workflow state in memory.
type InMemoryTreasuryReleaseStore struct {
	mu      sync.RWMutex
	records map[string]*TreasuryReleaseRecord
}

// NewInMemoryTreasuryReleaseStore creates an in-memory workflow store.
func NewInMemoryTreasuryReleaseStore() *InMemoryTreasuryReleaseStore {
	return &InMemoryTreasuryReleaseStore{records: make(map[string]*TreasuryReleaseRecord)}
}

// Save stores a cloned workflow record in memory.
func (s *InMemoryTreasuryReleaseStore) Save(_ context.Context, record *TreasuryReleaseRecord) error {
	cloned, workflowID, err := prepareTreasuryReleaseRecordForStorage(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[workflowID] = cloned
	return nil
}

// Get returns one cloned workflow record from memory.
func (s *InMemoryTreasuryReleaseStore) Get(_ context.Context, workflowID string) (*TreasuryReleaseRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[strings.TrimSpace(workflowID)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrReleaseNotFound, strings.TrimSpace(workflowID))
	}
	return cloneTreasuryReleaseRecord(record)
}

// List returns cloned workflow records sorted by most-recent update.
func (s *InMemoryTreasuryReleaseStore) List(_ context.Context) ([]*TreasuryReleaseRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*TreasuryReleaseRecord, 0, len(s.records))
	for _, record := range s.records {
		cloned, err := cloneTreasuryReleaseRecord(record)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return treasuryReleaseRecordSortTime(out[i]).After(treasuryReleaseRecordSortTime(out[j]))
	})
	return out, nil
}

// FileTreasuryReleaseStore persists workflow state as JSON snapshots on disk.
type FileTreasuryReleaseStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileTreasuryReleaseStore creates a file-backed workflow store rooted at
// the provided directory.
func NewFileTreasuryReleaseStore(dir string) (*FileTreasuryReleaseStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("finance/release_store: directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("finance/release_store: create directory: %w", err)
	}
	return &FileTreasuryReleaseStore{dir: dir}, nil
}

// Save persists one workflow record to disk.
func (s *FileTreasuryReleaseStore) Save(_ context.Context, record *TreasuryReleaseRecord) error {
	cloned, workflowID, err := prepareTreasuryReleaseRecordForStorage(record)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cloned, "", "  ")
	if err != nil {
		return fmt.Errorf("finance/release_store: marshal record: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	recordPath, err := s.recordPath(workflowID)
	if err != nil {
		return err
	}
	tmpPath := recordPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("finance/release_store: write temp record: %w", err)
	}
	if err := os.Rename(tmpPath, recordPath); err != nil {
		return fmt.Errorf("finance/release_store: commit record file: %w", err)
	}
	return nil
}

// Get reads one workflow record from disk.
func (s *FileTreasuryReleaseStore) Get(_ context.Context, workflowID string) (*TreasuryReleaseRecord, error) {
	recordPath, err := s.recordPath(workflowID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(recordPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrReleaseNotFound, strings.TrimSpace(workflowID))
		}
		return nil, fmt.Errorf("finance/release_store: read record: %w", err)
	}

	var record TreasuryReleaseRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("finance/release_store: decode record: %w", err)
	}
	cloned, _, err := prepareTreasuryReleaseRecordForStorage(&record)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

// List reads all workflow records from disk.
func (s *FileTreasuryReleaseStore) List(_ context.Context) ([]*TreasuryReleaseRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("finance/release_store: read directory: %w", err)
	}

	out := make([]*TreasuryReleaseRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("finance/release_store: read record %q: %w", entry.Name(), err)
		}
		var record TreasuryReleaseRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("finance/release_store: decode record %q: %w", entry.Name(), err)
		}
		cloned, _, err := prepareTreasuryReleaseRecordForStorage(&record)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return treasuryReleaseRecordSortTime(out[i]).After(treasuryReleaseRecordSortTime(out[j]))
	})
	return out, nil
}

func (s *FileTreasuryReleaseStore) recordPath(workflowID string) (string, error) {
	normalized := strings.TrimSpace(workflowID)
	if normalized == "" {
		return "", fmt.Errorf("finance/release_store: workflow ID is required")
	}
	if normalized != filepath.Base(normalized) || strings.Contains(normalized, "..") {
		return "", fmt.Errorf("%w: %s", ErrReleaseNotFound, normalized)
	}
	return filepath.Join(s.dir, normalized+".json"), nil
}

func prepareTreasuryReleaseRecordForStorage(record *TreasuryReleaseRecord) (*TreasuryReleaseRecord, string, error) {
	if record == nil {
		return nil, "", fmt.Errorf("finance/release_store: record is required")
	}
	cloned, err := cloneTreasuryReleaseRecord(record)
	if err != nil {
		return nil, "", err
	}
	if cloned.Result == nil {
		return nil, "", fmt.Errorf("finance/release_store: result is required")
	}

	workflowID := strings.TrimSpace(firstNonEmpty(cloned.WorkflowID, cloned.Result.WorkflowID))
	if workflowID == "" {
		return nil, "", fmt.Errorf("finance/release_store: workflow ID is required")
	}
	cloned.WorkflowID = workflowID
	cloned.Result.WorkflowID = workflowID
	if cloned.Request.Operation == nil {
		return nil, "", fmt.Errorf("finance/release_store: request operation is required")
	}
	if strings.TrimSpace(cloned.Request.Operation.ID) == "" {
		cloned.Request.Operation.ID = workflowID
	}
	if cloned.Request.Operation.ID != workflowID {
		return nil, "", fmt.Errorf("finance/release_store: request operation ID %q does not match workflow ID %q", cloned.Request.Operation.ID, workflowID)
	}
	if cloned.Result.Operation != nil {
		if strings.TrimSpace(cloned.Result.Operation.ID) == "" {
			cloned.Result.Operation.ID = workflowID
		}
		if cloned.Result.Operation.ID != workflowID {
			return nil, "", fmt.Errorf("finance/release_store: result operation ID %q does not match workflow ID %q", cloned.Result.Operation.ID, workflowID)
		}
	}
	if cloned.StoredAt.IsZero() {
		cloned.StoredAt = time.Now().UTC()
	}
	return cloned, workflowID, nil
}

func cloneTreasuryReleaseRecord(in *TreasuryReleaseRecord) (*TreasuryReleaseRecord, error) {
	if in == nil {
		return nil, nil
	}
	out := &TreasuryReleaseRecord{
		WorkflowID: strings.TrimSpace(in.WorkflowID),
		Request:    cloneTreasuryReleaseRequest(in.Request),
		StoredAt:   in.StoredAt,
	}
	result, err := cloneTreasuryReleaseResult(in.Result)
	if err != nil {
		return nil, err
	}
	out.Result = result
	return out, nil
}

func cloneTreasuryReleaseRequest(in TreasuryReleaseRequest) TreasuryReleaseRequest {
	out := TreasuryReleaseRequest{
		Resource:     strings.TrimSpace(in.Resource),
		Jurisdiction: strings.TrimSpace(in.Jurisdiction),
		ReasonCode:   strings.TrimSpace(in.ReasonCode),
		Tool:         strings.TrimSpace(in.Tool),
		Operation:    cloneTreasuryOperation(in.Operation),
		Metadata:     cloneStringMap(in.Metadata),
		Originator:   in.Originator,
		Beneficiary:  in.Beneficiary,
	}
	if in.Identity != nil {
		out.Identity = cloneTreasuryReleaseAgentIdentity(in.Identity)
	}
	return out
}

func cloneTreasuryReleaseAgentIdentity(in *agent.AgentIdentity) *agent.AgentIdentity {
	if in == nil {
		return nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return in
	}
	var out agent.AgentIdentity
	if err := json.Unmarshal(data, &out); err != nil {
		return in
	}
	return &out
}

func treasuryReleaseRecordSortTime(record *TreasuryReleaseRecord) time.Time {
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
