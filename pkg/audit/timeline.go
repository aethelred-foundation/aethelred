package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Chronological Event Timeline
// ---------------------------------------------------------------------------
//
// Timelines provide a human-readable, chronologically ordered view of audit
// events. They are used for:
//
//   - Incident investigation (what happened, in what order)
//   - Compliance evidence (demonstrating control execution over time)
//   - Operational dashboards (real-time event streams)
//   - Forensic reconstruction (replaying a sequence of events)
//
// A timeline can be scoped to a job, an actor, an incident, or any
// arbitrary filter. Multiple timelines can be merged for cross-cutting views.
// ---------------------------------------------------------------------------

// TimelineEvent represents a single event in a chronological timeline.
type TimelineEvent struct {
	// Timestamp is the event time (RFC3339).
	Timestamp time.Time `json:"timestamp"`

	// Category classifies the event domain.
	Category keeper.AuditCategory `json:"category"`

	// Severity indicates importance.
	Severity keeper.AuditSeverity `json:"severity"`

	// Action is the specific action that occurred.
	Action string `json:"action"`

	// Actor is the address or identifier of who triggered the event.
	Actor string `json:"actor"`

	// Details contains the event payload.
	Details map[string]string `json:"details,omitempty"`

	// Sequence is the audit record sequence number.
	Sequence uint64 `json:"sequence"`

	// RecordHash is the SHA-256 hash of the underlying audit record.
	RecordHash string `json:"record_hash"`

	// BlockHeight is the chain height at which the event was recorded.
	BlockHeight int64 `json:"block_height"`

	// LinkedEvents holds sequence numbers of causally related events.
	LinkedEvents []uint64 `json:"linked_events,omitempty"`
}

// Timeline is an ordered collection of audit events with metadata.
type Timeline struct {
	// Events in chronological order.
	Events []TimelineEvent `json:"events"`

	// StartTime is the timestamp of the earliest event.
	StartTime *time.Time `json:"start_time,omitempty"`

	// EndTime is the timestamp of the latest event.
	EndTime *time.Time `json:"end_time,omitempty"`

	// Actor is set when the timeline is scoped to a single actor.
	Actor string `json:"actor,omitempty"`

	// Context describes the scope of this timeline.
	Context string `json:"context,omitempty"`

	// TotalEvents is the count before any pagination.
	TotalEvents int `json:"total_events"`
}

// ---------------------------------------------------------------------------
// Timeline construction
// ---------------------------------------------------------------------------

// BuildTimeline constructs a timeline from audit records matching the given
// filter.
func BuildTimeline(_ context.Context, source LogSource, f *Filter) (*Timeline, error) {
	if source == nil {
		return nil, fmt.Errorf("audit: LogSource is required")
	}
	if f == nil {
		f = NewFilter()
	}

	records := f.Apply(source.GetRecords())
	return buildTimelineFromRecords(records, "filtered")
}

// BuildJobTimeline constructs a timeline for a specific compute job.
func BuildJobTimeline(_ context.Context, source LogSource, jobID string) (*Timeline, error) {
	if source == nil {
		return nil, fmt.Errorf("audit: LogSource is required")
	}
	if jobID == "" {
		return nil, fmt.Errorf("audit: jobID is required")
	}

	// Filter for records that reference this job in their details.
	records := source.GetRecords()
	var jobRecords []keeper.AuditRecord
	for _, r := range records {
		if r.Details["job_id"] == jobID {
			jobRecords = append(jobRecords, r)
		}
	}

	tl, err := buildTimelineFromRecords(jobRecords, fmt.Sprintf("job:%s", jobID))
	if err != nil {
		return nil, err
	}

	// Link related events within the job timeline.
	linkJobEvents(tl)
	return tl, nil
}

// BuildActorTimeline constructs a timeline for a specific actor's actions.
func BuildActorTimeline(_ context.Context, source LogSource, actor string) (*Timeline, error) {
	if source == nil {
		return nil, fmt.Errorf("audit: LogSource is required")
	}
	if actor == "" {
		return nil, fmt.Errorf("audit: actor is required")
	}

	f := NewFilter().WithActors(actor)
	records := f.Apply(source.GetRecords())

	tl, err := buildTimelineFromRecords(records, fmt.Sprintf("actor:%s", actor))
	if err != nil {
		return nil, err
	}
	tl.Actor = actor
	return tl, nil
}

// BuildIncidentTimeline constructs a timeline focused on an incident. An
// incident is identified by an evidence detection event, and the timeline
// includes all causally related events.
func BuildIncidentTimeline(_ context.Context, source LogSource, incidentID string) (*Timeline, error) {
	if source == nil {
		return nil, fmt.Errorf("audit: LogSource is required")
	}
	if incidentID == "" {
		return nil, fmt.Errorf("audit: incidentID is required")
	}

	records := source.GetRecords()
	var incidentRecords []keeper.AuditRecord

	// Collect all records that reference the incident by job_id, seal_id,
	// or any detail value matching the incident ID.
	for _, r := range records {
		if matchesIncident(r, incidentID) {
			incidentRecords = append(incidentRecords, r)
		}
	}

	// Also include security events around the same time window.
	if len(incidentRecords) > 0 {
		first := incidentRecords[0]
		last := incidentRecords[len(incidentRecords)-1]
		firstTime, _ := parseTimestamp(first.Timestamp)
		lastTime, _ := parseTimestamp(last.Timestamp)

		// Expand the window by 5 minutes on each side.
		windowStart := firstTime.Add(-5 * time.Minute)
		windowEnd := lastTime.Add(5 * time.Minute)

		for _, r := range records {
			if r.Category == keeper.AuditCategorySecurity {
				rt, err := parseTimestamp(r.Timestamp)
				if err == nil && !rt.Before(windowStart) && !rt.After(windowEnd) {
					if !containsSequence(incidentRecords, r.Sequence) {
						incidentRecords = append(incidentRecords, r)
					}
				}
			}
		}
	}

	// Sort by sequence to ensure chronological order.
	sortRecordsBySequence(incidentRecords)

	return buildTimelineFromRecords(incidentRecords, fmt.Sprintf("incident:%s", incidentID))
}

// MergeTimelines combines multiple timelines into a single chronological
// view. Events are sorted by timestamp, then by sequence number.
func MergeTimelines(timelines []*Timeline) *Timeline {
	merged := &Timeline{
		Context: "merged",
	}

	for _, tl := range timelines {
		if tl == nil {
			continue
		}
		merged.Events = append(merged.Events, tl.Events...)
	}

	// Sort by timestamp, breaking ties by sequence.
	sortTimelineEvents(merged.Events)

	merged.TotalEvents = len(merged.Events)
	if len(merged.Events) > 0 {
		first := merged.Events[0].Timestamp
		last := merged.Events[len(merged.Events)-1].Timestamp
		merged.StartTime = &first
		merged.EndTime = &last
	}

	return merged
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func buildTimelineFromRecords(records []keeper.AuditRecord, ctx string) (*Timeline, error) {
	tl := &Timeline{
		Events:      make([]TimelineEvent, 0, len(records)),
		Context:     ctx,
		TotalEvents: len(records),
	}

	for _, r := range records {
		ts, err := parseTimestamp(r.Timestamp)
		if err != nil {
			// Use zero time if timestamp is unparseable.
			ts = time.Time{}
		}

		event := TimelineEvent{
			Timestamp:   ts,
			Category:    r.Category,
			Severity:    r.Severity,
			Action:      r.Action,
			Actor:       r.Actor,
			Details:     r.Details,
			Sequence:    r.Sequence,
			RecordHash:  r.RecordHash,
			BlockHeight: r.BlockHeight,
		}

		tl.Events = append(tl.Events, event)
	}

	if len(tl.Events) > 0 {
		first := tl.Events[0].Timestamp
		last := tl.Events[len(tl.Events)-1].Timestamp
		tl.StartTime = &first
		tl.EndTime = &last
	}

	return tl, nil
}

// linkJobEvents adds causal links between events within a job timeline.
// For example, job_submitted -> job_completed, or evidence_detected ->
// slashing_applied.
func linkJobEvents(tl *Timeline) {
	seqByAction := make(map[string][]int) // action -> indices in Events
	for i, e := range tl.Events {
		seqByAction[e.Action] = append(seqByAction[e.Action], i)
	}

	// Link submissions to completions.
	linkActions(tl, seqByAction, "job_submitted", "job_completed")
	linkActions(tl, seqByAction, "job_submitted", "job_failed")
	linkActions(tl, seqByAction, "evidence_detected", "slashing_applied")
	linkActions(tl, seqByAction, "consensus_reached", "job_completed")
}

func linkActions(tl *Timeline, seqByAction map[string][]int, from, to string) {
	fromIndices := seqByAction[from]
	toIndices := seqByAction[to]
	for _, fi := range fromIndices {
		for _, ti := range toIndices {
			tl.Events[fi].LinkedEvents = append(tl.Events[fi].LinkedEvents, tl.Events[ti].Sequence)
			tl.Events[ti].LinkedEvents = append(tl.Events[ti].LinkedEvents, tl.Events[fi].Sequence)
		}
	}
}

func matchesIncident(r keeper.AuditRecord, incidentID string) bool {
	if r.Details["job_id"] == incidentID {
		return true
	}
	if r.Details["seal_id"] == incidentID {
		return true
	}
	if r.Details["incident_id"] == incidentID {
		return true
	}
	// Check if any detail value matches.
	for _, v := range r.Details {
		if v == incidentID {
			return true
		}
	}
	return false
}

func containsSequence(records []keeper.AuditRecord, seq uint64) bool {
	for _, r := range records {
		if r.Sequence == seq {
			return true
		}
	}
	return false
}

// sortRecordsBySequence sorts audit records by sequence number (ascending)
// using insertion sort for determinism.
func sortRecordsBySequence(records []keeper.AuditRecord) {
	for i := 1; i < len(records); i++ {
		r := records[i]
		j := i - 1
		for j >= 0 && records[j].Sequence > r.Sequence {
			records[j+1] = records[j]
			j--
		}
		records[j+1] = r
	}
}

// sortTimelineEvents sorts events by timestamp, then by sequence.
func sortTimelineEvents(events []TimelineEvent) {
	for i := 1; i < len(events); i++ {
		e := events[i]
		j := i - 1
		for j >= 0 && (events[j].Timestamp.After(e.Timestamp) ||
			(events[j].Timestamp.Equal(e.Timestamp) && events[j].Sequence > e.Sequence)) {
			events[j+1] = events[j]
			j--
		}
		events[j+1] = e
	}
}
