package audit

import (
	"strings"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Audit record filtering
// ---------------------------------------------------------------------------
//
// Filter provides structured, composable filtering of audit records. It
// supports builder-pattern construction with chainable methods, and a
// Match predicate for evaluating individual records.
//
// Usage:
//
//	f := NewFilter().
//	    WithCategories(keeper.AuditCategoryJob, keeper.AuditCategorySecurity).
//	    WithSeverities(keeper.AuditSeverityCritical).
//	    WithActor("aethel1abc...").
//	    WithTimeRange(start, end).
//	    WithLimit(100)
//
//	for _, r := range records {
//	    if f.Match(r) { ... }
//	}
// ---------------------------------------------------------------------------

// Filter defines criteria for selecting audit records. Zero-value fields
// are treated as "match any".
type Filter struct {
	// Classification filters.
	Categories []keeper.AuditCategory `json:"categories,omitempty"`
	Severities []keeper.AuditSeverity `json:"severities,omitempty"`
	Actions    []string               `json:"actions,omitempty"`
	Actors     []string               `json:"actors,omitempty"`

	// Time range (inclusive).
	FromTime *time.Time `json:"from_time,omitempty"`
	ToTime   *time.Time `json:"to_time,omitempty"`

	// Block range (inclusive).
	FromBlock *int64 `json:"from_block,omitempty"`
	ToBlock   *int64 `json:"to_block,omitempty"`

	// Sequence range (inclusive).
	FromSequence *uint64 `json:"from_sequence,omitempty"`
	ToSequence   *uint64 `json:"to_sequence,omitempty"`

	// Free-text keyword search across action and detail values.
	Keywords []string `json:"keywords,omitempty"`

	// Pagination.
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// NewFilter returns an empty filter (matches all records).
func NewFilter() *Filter {
	return &Filter{}
}

// ---------------------------------------------------------------------------
// Builder methods (chainable)
// ---------------------------------------------------------------------------

// WithCategories restricts matches to the given categories.
func (f *Filter) WithCategories(cats ...keeper.AuditCategory) *Filter {
	f.Categories = append(f.Categories, cats...)
	return f
}

// WithSeverities restricts matches to the given severities.
func (f *Filter) WithSeverities(sevs ...keeper.AuditSeverity) *Filter {
	f.Severities = append(f.Severities, sevs...)
	return f
}

// WithActions restricts matches to the given action strings.
func (f *Filter) WithActions(actions ...string) *Filter {
	f.Actions = append(f.Actions, actions...)
	return f
}

// WithActors restricts matches to the given actor addresses.
func (f *Filter) WithActors(actors ...string) *Filter {
	f.Actors = append(f.Actors, actors...)
	return f
}

// WithTimeRange restricts matches to records within [from, to].
func (f *Filter) WithTimeRange(from, to time.Time) *Filter {
	f.FromTime = &from
	f.ToTime = &to
	return f
}

// WithFromTime restricts matches to records at or after the given time.
func (f *Filter) WithFromTime(t time.Time) *Filter {
	f.FromTime = &t
	return f
}

// WithToTime restricts matches to records at or before the given time.
func (f *Filter) WithToTime(t time.Time) *Filter {
	f.ToTime = &t
	return f
}

// WithBlockRange restricts matches to records within [from, to] block heights.
func (f *Filter) WithBlockRange(from, to int64) *Filter {
	f.FromBlock = &from
	f.ToBlock = &to
	return f
}

// WithSequenceRange restricts matches to records within [from, to] sequence
// numbers.
func (f *Filter) WithSequenceRange(from, to uint64) *Filter {
	f.FromSequence = &from
	f.ToSequence = &to
	return f
}

// WithKeywords adds free-text search terms. A record matches if any keyword
// appears in its action string or detail values.
func (f *Filter) WithKeywords(kw ...string) *Filter {
	f.Keywords = append(f.Keywords, kw...)
	return f
}

// WithLimit sets the maximum number of records to return.
func (f *Filter) WithLimit(n int) *Filter {
	f.Limit = n
	return f
}

// WithOffset sets the number of matching records to skip (pagination).
func (f *Filter) WithOffset(n int) *Filter {
	f.Offset = n
	return f
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

// Match returns true if the given audit record satisfies all non-empty
// filter criteria. An empty filter matches every record.
func (f *Filter) Match(r keeper.AuditRecord) bool {
	if !f.matchCategories(r) {
		return false
	}
	if !f.matchSeverities(r) {
		return false
	}
	if !f.matchActions(r) {
		return false
	}
	if !f.matchActors(r) {
		return false
	}
	if !f.matchTime(r) {
		return false
	}
	if !f.matchBlock(r) {
		return false
	}
	if !f.matchSequence(r) {
		return false
	}
	if !f.matchKeywords(r) {
		return false
	}
	return true
}

func (f *Filter) matchCategories(r keeper.AuditRecord) bool {
	if len(f.Categories) == 0 {
		return true
	}
	for _, c := range f.Categories {
		if r.Category == c {
			return true
		}
	}
	return false
}

func (f *Filter) matchSeverities(r keeper.AuditRecord) bool {
	if len(f.Severities) == 0 {
		return true
	}
	for _, s := range f.Severities {
		if r.Severity == s {
			return true
		}
	}
	return false
}

func (f *Filter) matchActions(r keeper.AuditRecord) bool {
	if len(f.Actions) == 0 {
		return true
	}
	for _, a := range f.Actions {
		if r.Action == a {
			return true
		}
	}
	return false
}

func (f *Filter) matchActors(r keeper.AuditRecord) bool {
	if len(f.Actors) == 0 {
		return true
	}
	for _, a := range f.Actors {
		if r.Actor == a {
			return true
		}
	}
	return false
}

func (f *Filter) matchTime(r keeper.AuditRecord) bool {
	if f.FromTime == nil && f.ToTime == nil {
		return true
	}
	t, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		return false
	}
	if f.FromTime != nil && t.Before(*f.FromTime) {
		return false
	}
	if f.ToTime != nil && t.After(*f.ToTime) {
		return false
	}
	return true
}

func (f *Filter) matchBlock(r keeper.AuditRecord) bool {
	if f.FromBlock != nil && r.BlockHeight < *f.FromBlock {
		return false
	}
	if f.ToBlock != nil && r.BlockHeight > *f.ToBlock {
		return false
	}
	return true
}

func (f *Filter) matchSequence(r keeper.AuditRecord) bool {
	if f.FromSequence != nil && r.Sequence < *f.FromSequence {
		return false
	}
	if f.ToSequence != nil && r.Sequence > *f.ToSequence {
		return false
	}
	return true
}

func (f *Filter) matchKeywords(r keeper.AuditRecord) bool {
	if len(f.Keywords) == 0 {
		return true
	}
	// Build a search corpus from action + all detail values.
	corpus := strings.ToLower(r.Action)
	for _, v := range r.Details {
		corpus += " " + strings.ToLower(v)
	}
	for _, kw := range f.Keywords {
		if strings.Contains(corpus, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

// Apply filters a slice of audit records, returning those that match the
// filter. Limit and Offset are applied after matching.
func (f *Filter) Apply(records []keeper.AuditRecord) []keeper.AuditRecord {
	var matched []keeper.AuditRecord
	for _, r := range records {
		if f.Match(r) {
			matched = append(matched, r)
		}
	}

	// Apply offset.
	if f.Offset > 0 {
		if f.Offset >= len(matched) {
			return nil
		}
		matched = matched[f.Offset:]
	}

	// Apply limit.
	if f.Limit > 0 && len(matched) > f.Limit {
		matched = matched[:f.Limit]
	}

	return matched
}
