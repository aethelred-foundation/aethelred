package epcis

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// EPCIS Query Service
// ---------------------------------------------------------------------------
//
// QueryService provides EPCIS 2.0-standard query operations over captured
// events. It supports the standard query parameters defined in the EPCIS 2.0
// specification and provides item traceability.
// ---------------------------------------------------------------------------

// QueryParams contains EPCIS-standard query parameters for event discovery.
// Parameter names follow the EPCIS 2.0 query parameter naming convention.
type QueryParams struct {
	// EventType filters by event type (ObjectEvent, AggregationEvent, etc.).
	EventType EventType

	// GE_eventTime filters events at or after this time (greater than or equal).
	GE_eventTime *time.Time

	// LT_eventTime filters events before this time (less than).
	LT_eventTime *time.Time

	// EQ_bizStep filters by exact business step match.
	EQ_bizStep string

	// EQ_disposition filters by exact disposition match.
	EQ_disposition string

	// EQ_readPoint filters by exact read point match.
	EQ_readPoint string

	// EQ_bizLocation filters by exact business location match.
	EQ_bizLocation string

	// MATCH_epc filters events containing this EPC.
	MATCH_epc string

	// EQ_action filters by action (ADD, OBSERVE, DELETE).
	EQ_action Action

	// MaxEventCount limits the number of returned events.
	MaxEventCount int

	// OrderByEventTime sorts results by event time when true.
	OrderByEventTime bool

	// OrderDirection is "ASC" or "DESC" for ordering.
	OrderDirection string
}

// QueryService provides query operations over captured EPCIS events.
type QueryService struct {
	capture *CaptureService
}

// NewQueryService creates a new query service backed by a capture service.
func NewQueryService(capture *CaptureService) *QueryService {
	return &QueryService{capture: capture}
}

// QueryEvents returns events matching the given EPCIS-standard parameters.
func (qs *QueryService) QueryEvents(_ context.Context, params QueryParams) ([]EPCISEvent, error) {
	allEvents := qs.capture.AllEvents()
	var results []EPCISEvent

	for _, event := range allEvents {
		if matchesQueryParams(event, params) {
			results = append(results, event)
		}
	}

	// Apply ordering.
	if params.OrderByEventTime {
		sortEventsByTime(results, params.OrderDirection == "DESC")
	}

	// Apply limit.
	if params.MaxEventCount > 0 && len(results) > params.MaxEventCount {
		results = results[:params.MaxEventCount]
	}

	return results, nil
}

// QueryByEPC traces an item by its EPC, returning all events that reference
// the given EPC identifier.
func (qs *QueryService) QueryByEPC(_ context.Context, epc string) ([]EPCISEvent, error) {
	if epc == "" {
		return nil, fmt.Errorf("QueryService.QueryByEPC: %w: EPC is empty", ErrInvalidEPC)
	}

	allEvents := qs.capture.AllEvents()
	var results []EPCISEvent

	for _, event := range allEvents {
		if containsEPC(event, epc) {
			results = append(results, event)
		}
	}

	// Sort chronologically.
	sortEventsByTime(results, false)

	return results, nil
}

// QueryByBizStep returns events matching a specific business step within
// an optional time range.
func (qs *QueryService) QueryByBizStep(_ context.Context, bizStep string, from, to *time.Time) ([]EPCISEvent, error) {
	if bizStep == "" {
		return nil, fmt.Errorf("QueryService.QueryByBizStep: %w: business step is empty", ErrQueryFailed)
	}

	allEvents := qs.capture.AllEvents()
	var results []EPCISEvent

	for _, event := range allEvents {
		if event.GetBizStep() != bizStep {
			continue
		}
		if from != nil && event.GetEventTime().Before(*from) {
			continue
		}
		if to != nil && event.GetEventTime().After(*to) {
			continue
		}
		results = append(results, event)
	}

	sortEventsByTime(results, false)
	return results, nil
}

// QueryByLocation returns events at a specific business location within
// an optional time range.
func (qs *QueryService) QueryByLocation(_ context.Context, location string, from, to *time.Time) ([]EPCISEvent, error) {
	if location == "" {
		return nil, fmt.Errorf("QueryService.QueryByLocation: %w: location is empty", ErrQueryFailed)
	}

	allEvents := qs.capture.AllEvents()
	var results []EPCISEvent

	for _, event := range allEvents {
		if getEventBizLocation(event) != location {
			continue
		}
		if from != nil && event.GetEventTime().Before(*from) {
			continue
		}
		if to != nil && event.GetEventTime().After(*to) {
			continue
		}
		results = append(results, event)
	}

	sortEventsByTime(results, false)
	return results, nil
}

// TraceItem returns a complete, chronologically ordered traceability chain
// for an item identified by its EPC. This includes all events that reference
// the item across its lifecycle.
func (qs *QueryService) TraceItem(ctx context.Context, epc string) (*TraceResult, error) {
	if epc == "" {
		return nil, fmt.Errorf("QueryService.TraceItem: %w: EPC is empty", ErrInvalidEPC)
	}

	events, err := qs.QueryByEPC(ctx, epc)
	if err != nil {
		return nil, err
	}

	result := &TraceResult{
		EPC:    epc,
		Events: events,
		Total:  len(events),
	}

	if len(events) > 0 {
		result.FirstSeen = events[0].GetEventTime()
		result.LastSeen = events[len(events)-1].GetEventTime()

		// Determine current disposition from the most recent event.
		result.CurrentDisposition = getEventDisposition(events[len(events)-1])

		// Collect all locations visited.
		locSet := make(map[string]bool)
		for _, e := range events {
			loc := getEventBizLocation(e)
			if loc != "" {
				locSet[loc] = true
			}
		}
		for loc := range locSet {
			result.Locations = append(result.Locations, loc)
		}
	}

	return result, nil
}

// TraceResult contains the full traceability chain for an item.
type TraceResult struct {
	EPC                string      `json:"epc"`
	Events             []EPCISEvent `json:"-"`
	Total              int         `json:"total"`
	FirstSeen          time.Time   `json:"first_seen"`
	LastSeen           time.Time   `json:"last_seen"`
	CurrentDisposition string      `json:"current_disposition,omitempty"`
	Locations          []string    `json:"locations,omitempty"`
}

// ---------------------------------------------------------------------------
// Matching and utility helpers
// ---------------------------------------------------------------------------

// matchesQueryParams checks if an event matches the given query parameters.
func matchesQueryParams(event EPCISEvent, params QueryParams) bool {
	// Filter by event type.
	if params.EventType != "" && event.GetEventType() != params.EventType {
		return false
	}

	// Filter by time range.
	if params.GE_eventTime != nil && event.GetEventTime().Before(*params.GE_eventTime) {
		return false
	}
	if params.LT_eventTime != nil && !event.GetEventTime().Before(*params.LT_eventTime) {
		return false
	}

	// Filter by business step.
	if params.EQ_bizStep != "" && event.GetBizStep() != params.EQ_bizStep {
		return false
	}

	// Filter by disposition.
	if params.EQ_disposition != "" && getEventDisposition(event) != params.EQ_disposition {
		return false
	}

	// Filter by read point.
	if params.EQ_readPoint != "" && getEventReadPoint(event) != params.EQ_readPoint {
		return false
	}

	// Filter by business location.
	if params.EQ_bizLocation != "" && getEventBizLocation(event) != params.EQ_bizLocation {
		return false
	}

	// Filter by EPC.
	if params.MATCH_epc != "" && !containsEPC(event, params.MATCH_epc) {
		return false
	}

	// Filter by action.
	if params.EQ_action != "" && getEventAction(event) != params.EQ_action {
		return false
	}

	return true
}

// containsEPC checks if an event references the given EPC.
func containsEPC(event EPCISEvent, epc string) bool {
	for _, e := range event.GetEPCList() {
		if e == epc {
			return true
		}
	}

	// Also check parent ID for aggregation events.
	if ae, ok := event.(*AggregationEvent); ok {
		if ae.ParentID == epc {
			return true
		}
	}
	if te, ok := event.(*TransactionEvent); ok {
		if te.ParentID == epc {
			return true
		}
	}

	return false
}

// getEventDisposition extracts the disposition from a concrete event type.
func getEventDisposition(event EPCISEvent) string {
	switch e := event.(type) {
	case *ObjectEvent:
		return e.Disposition
	case *AggregationEvent:
		return e.Disposition
	case *TransactionEvent:
		return e.Disposition
	case *TransformationEvent:
		return e.Disposition
	}
	return ""
}

// getEventReadPoint extracts the read point from a concrete event type.
func getEventReadPoint(event EPCISEvent) string {
	switch e := event.(type) {
	case *ObjectEvent:
		if e.ReadPoint != nil {
			return e.ReadPoint.ID
		}
	case *AggregationEvent:
		if e.ReadPoint != nil {
			return e.ReadPoint.ID
		}
	case *TransactionEvent:
		if e.ReadPoint != nil {
			return e.ReadPoint.ID
		}
	case *TransformationEvent:
		if e.ReadPoint != nil {
			return e.ReadPoint.ID
		}
	}
	return ""
}

// getEventBizLocation extracts the business location from a concrete event.
func getEventBizLocation(event EPCISEvent) string {
	switch e := event.(type) {
	case *ObjectEvent:
		if e.BizLocation != nil {
			return e.BizLocation.ID
		}
	case *AggregationEvent:
		if e.BizLocation != nil {
			return e.BizLocation.ID
		}
	case *TransactionEvent:
		if e.BizLocation != nil {
			return e.BizLocation.ID
		}
	case *TransformationEvent:
		if e.BizLocation != nil {
			return e.BizLocation.ID
		}
	}
	return ""
}

// getEventAction extracts the action from a concrete event type.
func getEventAction(event EPCISEvent) Action {
	switch e := event.(type) {
	case *ObjectEvent:
		return e.Action
	case *AggregationEvent:
		return e.Action
	case *TransactionEvent:
		return e.Action
	}
	return ""
}

// sortEventsByTime sorts events by event time using insertion sort for
// determinism and simplicity.
func sortEventsByTime(events []EPCISEvent, descending bool) {
	for i := 1; i < len(events); i++ {
		key := events[i]
		j := i - 1
		for j >= 0 && shouldSwap(events[j], key, descending) {
			events[j+1] = events[j]
			j--
		}
		events[j+1] = key
	}
}

func shouldSwap(a, b EPCISEvent, descending bool) bool {
	if descending {
		return a.GetEventTime().Before(b.GetEventTime())
	}
	return a.GetEventTime().After(b.GetEventTime())
}
