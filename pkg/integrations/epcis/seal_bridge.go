package epcis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Provenance Bridge
// ---------------------------------------------------------------------------
//
// ProvenanceBridge constructs and verifies provenance chains that link
// EPCIS events with Aethelred Digital Seals. This enables end-to-end
// supply chain traceability with cryptographic integrity guarantees.
// ---------------------------------------------------------------------------

// ProvenanceChain contains a complete, verifiable provenance history for
// an item identified by its EPC.
type ProvenanceChain struct {
	// EPC is the Electronic Product Code being traced.
	EPC string `json:"epc"`

	// Events are the EPCIS events in chronological order.
	Events []EPCISEvent `json:"-"`

	// EventSummaries are serializable event summaries for export.
	EventSummaries []EventSummary `json:"events"`

	// SealIDs maps event IDs to their Digital Seal IDs.
	SealIDs map[string]string `json:"seal_ids"`

	// ChainValid indicates whether all seals in the chain verified.
	ChainValid bool `json:"chain_valid"`

	// StartTime is the time of the earliest event.
	StartTime time.Time `json:"start_time"`

	// EndTime is the time of the most recent event.
	EndTime time.Time `json:"end_time"`

	// TotalEvents is the number of events in the chain.
	TotalEvents int `json:"total_events"`

	// SealedEvents is the number of events with valid seals.
	SealedEvents int `json:"sealed_events"`
}

// EventSummary is a serializable summary of an EPCIS event.
type EventSummary struct {
	EventID     string    `json:"event_id"`
	EventType   EventType `json:"event_type"`
	EventTime   time.Time `json:"event_time"`
	BizStep     string    `json:"biz_step,omitempty"`
	Disposition string    `json:"disposition,omitempty"`
	Location    string    `json:"location,omitempty"`
	SealID      string    `json:"seal_id,omitempty"`
	Sealed      bool      `json:"sealed"`
}

// ProvenanceBridge constructs provenance chains from EPCIS events and
// Digital Seals.
type ProvenanceBridge struct {
	capture *CaptureService
	query   *QueryService
}

// NewProvenanceBridge creates a new provenance bridge.
func NewProvenanceBridge(capture *CaptureService, query *QueryService) *ProvenanceBridge {
	return &ProvenanceBridge{
		capture: capture,
		query:   query,
	}
}

// BuildProvenanceChain constructs a complete provenance chain for an item
// identified by its EPC. It gathers all related EPCIS events and links
// them with their Digital Seals.
func (pb *ProvenanceBridge) BuildProvenanceChain(ctx context.Context, epc string) (*ProvenanceChain, error) {
	if epc == "" {
		return nil, fmt.Errorf("ProvenanceBridge.BuildProvenanceChain: %w: EPC is empty", ErrInvalidEPC)
	}

	// Query all events for this EPC.
	events, err := pb.query.QueryByEPC(ctx, epc)
	if err != nil {
		return nil, fmt.Errorf("ProvenanceBridge.BuildProvenanceChain: %w: %v", ErrProvenanceFailed, err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("ProvenanceBridge.BuildProvenanceChain: %w: no events found for EPC %s", ErrProvenanceFailed, epc)
	}

	chain := &ProvenanceChain{
		EPC:        epc,
		Events:     events,
		SealIDs:    make(map[string]string),
		ChainValid: true,
		TotalEvents: len(events),
	}

	// Build event summaries and collect seal IDs.
	for _, event := range events {
		summary := EventSummary{
			EventID:     event.GetEventID(),
			EventType:   event.GetEventType(),
			EventTime:   event.GetEventTime(),
			BizStep:     event.GetBizStep(),
			Disposition: getEventDisposition(event),
			Location:    getEventBizLocation(event),
		}

		// Check for associated seal.
		if sealID, ok := pb.capture.GetSealID(event.GetEventID()); ok {
			summary.SealID = sealID
			summary.Sealed = true
			chain.SealIDs[event.GetEventID()] = sealID
			chain.SealedEvents++
		}

		chain.EventSummaries = append(chain.EventSummaries, summary)
	}

	// Set time range.
	chain.StartTime = events[0].GetEventTime()
	chain.EndTime = events[len(events)-1].GetEventTime()

	// Chain is valid if all events have seals.
	chain.ChainValid = chain.SealedEvents == chain.TotalEvents

	return chain, nil
}

// VerifyProvenance verifies the integrity of a provenance chain. It checks
// that all seals are present and that the event sequence is chronologically
// consistent.
func (pb *ProvenanceBridge) VerifyProvenance(_ context.Context, chain *ProvenanceChain) (*ProvenanceVerification, error) {
	if chain == nil {
		return nil, fmt.Errorf("ProvenanceBridge.VerifyProvenance: %w: chain is nil", ErrProvenanceFailed)
	}

	result := &ProvenanceVerification{
		EPC:          chain.EPC,
		Valid:        true,
		TotalEvents:  chain.TotalEvents,
		SealedEvents: chain.SealedEvents,
		VerifiedAt:   time.Now().UTC(),
	}

	// Check that all events have seals.
	if chain.SealedEvents < chain.TotalEvents {
		result.Valid = false
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%d of %d events are unsealed",
				chain.TotalEvents-chain.SealedEvents, chain.TotalEvents))
	}

	// Check chronological ordering.
	for i := 1; i < len(chain.EventSummaries); i++ {
		prev := chain.EventSummaries[i-1]
		curr := chain.EventSummaries[i]
		if curr.EventTime.Before(prev.EventTime) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("event %s is before preceding event %s",
					curr.EventID, prev.EventID))
		}
	}

	// Check for gaps (events with no seal).
	for _, summary := range chain.EventSummaries {
		if !summary.Sealed {
			result.UnsealedEvents = append(result.UnsealedEvents, summary.EventID)
		}
	}

	return result, nil
}

// ProvenanceVerification contains the result of verifying a provenance chain.
type ProvenanceVerification struct {
	EPC            string    `json:"epc"`
	Valid          bool      `json:"valid"`
	TotalEvents    int       `json:"total_events"`
	SealedEvents   int       `json:"sealed_events"`
	UnsealedEvents []string  `json:"unsealed_events,omitempty"`
	Warnings       []string  `json:"warnings,omitempty"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// ExportFormat defines the export format for provenance data.
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
)

// ExportProvenance exports a provenance chain in the specified format.
func (pb *ProvenanceBridge) ExportProvenance(ctx context.Context, epc string, format ExportFormat) ([]byte, error) {
	chain, err := pb.BuildProvenanceChain(ctx, epc)
	if err != nil {
		return nil, err
	}

	switch format {
	case ExportFormatJSON:
		return json.MarshalIndent(chain, "", "  ")
	case ExportFormatCSV:
		return exportProvenanceCSV(chain), nil
	default:
		return nil, fmt.Errorf("ProvenanceBridge.ExportProvenance: unsupported export format: %s", format)
	}
}

// exportProvenanceCSV generates a CSV representation of a provenance chain.
func exportProvenanceCSV(chain *ProvenanceChain) []byte {
	header := "event_id,event_type,event_time,biz_step,disposition,location,seal_id,sealed\n"
	var rows string
	for _, s := range chain.EventSummaries {
		rows += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%v\n",
			s.EventID, s.EventType, s.EventTime.Format(time.RFC3339),
			s.BizStep, s.Disposition, s.Location, s.SealID, s.Sealed)
	}
	return []byte(header + rows)
}
