package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Audit Studio -- Core Service
// ---------------------------------------------------------------------------
//
// The Audit Studio provides a queryable, verifiable interface to the
// structured audit log maintained by the pouw module. It is the primary
// entry point for compliance tooling, forensic analysis, and operational
// dashboards.
//
// Responsibilities:
//   - Query and filter audit records
//   - Verify hash chain integrity over arbitrary ranges
//   - Compute aggregate statistics for compliance reporting
//   - Serve as the backing service for the REST/gRPC API
//
// The Studio is safe for concurrent use.
// ---------------------------------------------------------------------------

// LogSource abstracts access to the underlying audit log. In production this
// is backed by the pouw keeper's AuditLogger; in tests it can be a simple
// in-memory store.
type LogSource interface {
	// GetRecords returns all buffered audit records.
	GetRecords() []keeper.AuditRecord

	// GetRecordsSince returns records at or after the given block height.
	GetRecordsSince(height int64) []keeper.AuditRecord

	// GetRecordsByCategory returns records matching the given category.
	GetRecordsByCategory(cat keeper.AuditCategory) []keeper.AuditRecord

	// Sequence returns the current sequence counter.
	Sequence() uint64

	// LastHash returns the hash of the most recently appended record.
	LastHash() string

	// TotalEmitted returns the total number of records ever emitted.
	TotalEmitted() uint64
}

// IndexConfig controls how the studio indexes records for fast lookups.
type IndexConfig struct {
	// EnableActorIndex builds a secondary index on Actor fields.
	EnableActorIndex bool `json:"enable_actor_index"`

	// EnableActionIndex builds a secondary index on Action fields.
	EnableActionIndex bool `json:"enable_action_index"`

	// EnableDetailIndex builds a full-text index on detail values.
	EnableDetailIndex bool `json:"enable_detail_index"`
}

// Config configures a new Studio instance.
type Config struct {
	// LogSource provides access to the audit log.
	LogSource LogSource

	// RetentionPolicy defines how long records are retained.
	RetentionPolicy *RetentionPolicy

	// ExportFormats lists the formats available for export (informational).
	ExportFormats []string

	// IndexConfig controls secondary indexes.
	IndexConfig IndexConfig

	// Logger provides structured logging. Defaults to no-op.
	Logger Logger

	// Metrics provides metrics collection hooks. Defaults to no-op.
	Metrics MetricsCollector
}

// Studio is the central audit query and verification service.
type Studio struct {
	mu     sync.RWMutex
	source LogSource
	config Config

	// In-memory indexes (rebuilt on demand).
	actorIndex  map[string][]uint64 // actor -> list of sequence numbers
	actionIndex map[string][]uint64 // action -> list of sequence numbers

	logger  Logger
	metrics MetricsCollector
}

// NewStudio creates a new audit studio with the given configuration.
func NewStudio(cfg Config) (*Studio, error) {
	if cfg.LogSource == nil {
		return nil, fmt.Errorf("NewStudio: %w: LogSource is required", ErrInvalidInput)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = NoopLogger{}
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = NoopMetrics{}
	}

	s := &Studio{
		source:  cfg.LogSource,
		config:  cfg,
		logger:  logger,
		metrics: metrics,
	}
	if cfg.IndexConfig.EnableActorIndex {
		s.actorIndex = make(map[string][]uint64)
	}
	if cfg.IndexConfig.EnableActionIndex {
		s.actionIndex = make(map[string][]uint64)
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Query operations
// ---------------------------------------------------------------------------

// Query returns audit records matching the given filter.
func (s *Studio) Query(_ context.Context, f *Filter) ([]keeper.AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if f == nil {
		f = NewFilter()
	}

	records := s.source.GetRecords()
	return f.Apply(records), nil
}

// GetRecord returns a single audit record by its sequence number. Returns
// an error if the record is not found in the buffer.
func (s *Studio) GetRecord(_ context.Context, sequence uint64) (*keeper.AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := s.source.GetRecords()
	for i := range records {
		if records[i].Sequence == sequence {
			r := records[i]
			return &r, nil
		}
	}
	return nil, fmt.Errorf("Studio.GetRecord: %w: sequence %d", ErrRecordNotFound, sequence)
}

// GetChain returns a contiguous range of records [from, to] with integrity
// verification. The returned records are guaranteed to have a valid hash
// chain.
func (s *Studio) GetChain(_ context.Context, from, to uint64) ([]keeper.AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if from > to {
		return nil, fmt.Errorf("Studio.GetChain: %w: from (%d) > to (%d)", ErrInvalidInput, from, to)
	}

	records := s.source.GetRecords()

	// Extract the requested range.
	var chain []keeper.AuditRecord
	for _, r := range records {
		if r.Sequence >= from && r.Sequence <= to {
			chain = append(chain, r)
		}
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("Studio.GetChain: %w: no records in range [%d, %d]", ErrRecordNotFound, from, to)
	}

	// Verify the chain integrity within the extracted range.
	if err := VerifyChain(chain); err != nil {
		return chain, fmt.Errorf("Studio.GetChain: %w: range [%d, %d]: %v", ErrChainIntegrityFailed, from, to, err)
	}

	return chain, nil
}

// VerifyChain verifies the hash chain integrity of a slice of ordered audit
// records. Each record's hash is recomputed and compared to the stored hash,
// and the chain linkage (PreviousHash -> prior RecordHash) is checked for
// adjacent records.
func VerifyChain(records []keeper.AuditRecord) error {
	for i, r := range records {
		// Recompute the hash for this record.
		expected := ComputeRecordHash(r)
		if expected != r.RecordHash {
			return fmt.Errorf("hash mismatch at sequence %d: computed %s, stored %s",
				r.Sequence, expected, r.RecordHash)
		}

		// Verify chain linkage for consecutive records.
		if i > 0 {
			prev := records[i-1]
			if r.PreviousHash != prev.RecordHash {
				return fmt.Errorf("chain break at sequence %d: previous_hash %s != prior record_hash %s",
					r.Sequence, r.PreviousHash, prev.RecordHash)
			}
		}
	}
	return nil
}

// ComputeRecordHash mirrors the deterministic hashing logic in the keeper's
// AuditRecord.computeHash() method. This must stay in sync with the keeper
// implementation.
func ComputeRecordHash(r keeper.AuditRecord) string {
	canonical := fmt.Sprintf(
		"seq=%d|prev=%s|cat=%s|sev=%s|act=%s|height=%d|ts=%s|actor=%s",
		r.Sequence, r.PreviousHash, r.Category, r.Severity, r.Action,
		r.BlockHeight, r.Timestamp, r.Actor,
	)
	if len(r.Details) > 0 {
		keys := sortedMapKeys(r.Details)
		for _, k := range keys {
			canonical += fmt.Sprintf("|%s=%s", k, r.Details[k])
		}
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

// AuditStats contains aggregate statistics over a set of audit records.
type AuditStats struct {
	TotalRecords  int                          `json:"total_records"`
	ByCategory    map[keeper.AuditCategory]int `json:"by_category"`
	BySeverity    map[keeper.AuditSeverity]int `json:"by_severity"`
	ByActor       map[string]int               `json:"by_actor"`
	FirstTimestamp string                       `json:"first_timestamp"`
	LastTimestamp  string                       `json:"last_timestamp"`
	FirstBlock    int64                         `json:"first_block"`
	LastBlock     int64                         `json:"last_block"`
	FirstSequence uint64                        `json:"first_sequence"`
	LastSequence  uint64                        `json:"last_sequence"`
	TotalEmitted  uint64                        `json:"total_emitted"`
	ChainIntact   bool                          `json:"chain_intact"`
}

// GetStats computes aggregate statistics over records matching the given
// filter.
func (s *Studio) GetStats(_ context.Context, f *Filter) (*AuditStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if f == nil {
		f = NewFilter()
	}

	records := f.Apply(s.source.GetRecords())
	stats := &AuditStats{
		TotalRecords: len(records),
		ByCategory:   make(map[keeper.AuditCategory]int),
		BySeverity:   make(map[keeper.AuditSeverity]int),
		ByActor:      make(map[string]int),
		TotalEmitted: s.source.TotalEmitted(),
	}

	for i, r := range records {
		stats.ByCategory[r.Category]++
		stats.BySeverity[r.Severity]++
		stats.ByActor[r.Actor]++

		if i == 0 {
			stats.FirstTimestamp = r.Timestamp
			stats.FirstBlock = r.BlockHeight
			stats.FirstSequence = r.Sequence
		}
		stats.LastTimestamp = r.Timestamp
		stats.LastBlock = r.BlockHeight
		stats.LastSequence = r.Sequence
	}

	// Check chain integrity.
	stats.ChainIntact = VerifyChain(records) == nil

	return stats, nil
}

// ---------------------------------------------------------------------------
// Index management
// ---------------------------------------------------------------------------

// RebuildIndexes rebuilds all enabled secondary indexes from the current
// record set. This is called automatically when needed but can be invoked
// explicitly after bulk operations.
func (s *Studio) RebuildIndexes() {
	s.mu.Lock()
	defer s.mu.Unlock()

	records := s.source.GetRecords()

	if s.actorIndex != nil {
		s.actorIndex = make(map[string][]uint64, len(records)/4+1)
		for _, r := range records {
			s.actorIndex[r.Actor] = append(s.actorIndex[r.Actor], r.Sequence)
		}
	}

	if s.actionIndex != nil {
		s.actionIndex = make(map[string][]uint64, len(records)/4+1)
		for _, r := range records {
			s.actionIndex[r.Action] = append(s.actionIndex[r.Action], r.Sequence)
		}
	}
}

// Source returns the underlying log source for direct access.
func (s *Studio) Source() LogSource {
	return s.source
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sortedMapKeys returns the keys of a string map in sorted order. Uses the
// same insertion-sort approach as the keeper for determinism.
func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		k := keys[i]
		j := i - 1
		for j >= 0 && keys[j] > k {
			keys[j+1] = keys[j]
			j--
		}
		keys[j+1] = k
	}
	return keys
}

// parseTimestamp parses an RFC3339 timestamp string.
func parseTimestamp(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
