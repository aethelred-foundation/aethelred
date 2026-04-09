package epcis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/aethelred/aethelred/pkg/seal/sdk"
)

const maxSealRetries = 3

// epcURNPattern validates EPC URN format (e.g., urn:epc:id:sgtin:...).
var epcURNPattern = regexp.MustCompile(`^urn:epc:id:[a-z]+:.+$`)

// ---------------------------------------------------------------------------
// EPCIS Capture Service
// ---------------------------------------------------------------------------
//
// CaptureService handles the capture (recording) of EPCIS events and
// optionally seals them with Aethelred Digital Seals for tamper-proof
// supply chain traceability.
// ---------------------------------------------------------------------------

// CaptureConfig holds configuration for the EPCIS capture service.
type CaptureConfig struct {
	// DefaultBizLocation is the business location used when an event does
	// not specify one.
	DefaultBizLocation string

	// SealOnCapture indicates whether events should be automatically sealed
	// upon capture.
	SealOnCapture bool

	// JurisdictionRules maps business locations to compliance jurisdictions.
	JurisdictionRules map[string]string

	// DefaultJurisdiction is used when no rule matches.
	DefaultJurisdiction string
}

// CaptureResult contains the outcome of capturing an EPCIS event.
type CaptureResult struct {
	EventID   string    `json:"event_id"`
	SealID    string    `json:"seal_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Sealed    bool      `json:"sealed"`
}

// CaptureService captures EPCIS events and optionally binds them to
// Aethelred Digital Seals.
type CaptureService struct {
	mu      sync.Mutex
	sealMu  sync.RWMutex
	sealSDK *sdk.SealSDK
	config  CaptureConfig
	logger  Logger
	metrics MetricsCollector

	// events stores captured events keyed by event ID.
	events map[string]EPCISEvent

	// sealMap maps event IDs to their seal IDs.
	sealMap map[string]string

	// eventOrder preserves insertion order for querying.
	eventOrder []string

	// sequence generates unique event IDs.
	sequence uint64
}

// NewCaptureService creates a new capture service with the given configuration.
func NewCaptureService(config CaptureConfig, sealSDK *sdk.SealSDK) *CaptureService {
	if config.DefaultJurisdiction == "" {
		config.DefaultJurisdiction = "US"
	}
	if config.JurisdictionRules == nil {
		config.JurisdictionRules = make(map[string]string)
	}

	return &CaptureService{
		sealSDK:    sealSDK,
		config:     config,
		logger:     nopLogger{},
		metrics:    nopMetrics{},
		events:     make(map[string]EPCISEvent),
		sealMap:    make(map[string]string),
		eventOrder: make([]string, 0),
	}
}

// SetLogger configures the logger for the capture service.
func (cs *CaptureService) SetLogger(l Logger) {
	if l != nil {
		cs.logger = l
	}
}

// SetMetrics configures the metrics collector for the capture service.
func (cs *CaptureService) SetMetrics(m MetricsCollector) {
	if m != nil {
		cs.metrics = m
	}
}

// ValidateEPC checks that an EPC URN matches the expected format.
func ValidateEPC(epc string) error {
	if epc == "" {
		return fmt.Errorf("ValidateEPC: %w: empty EPC", ErrInvalidEPC)
	}
	if !epcURNPattern.MatchString(epc) {
		return fmt.Errorf("ValidateEPC: %w: invalid format: %s", ErrInvalidEPC, epc)
	}
	return nil
}

// CaptureEvent captures a single EPCIS event and optionally seals it.
// If the event does not have an ID, one is generated.
func (cs *CaptureService) CaptureEvent(ctx context.Context, event EPCISEvent) (*CaptureResult, error) {
	if event == nil {
		return nil, fmt.Errorf("CaptureService.CaptureEvent: %w: event is nil", ErrInvalidEvent)
	}

	cs.mu.Lock()

	// Assign event ID if missing.
	eventID := event.GetEventID()
	if eventID == "" {
		cs.sequence++
		eventID = fmt.Sprintf("evt-%d-%d", time.Now().UnixNano(), cs.sequence)
		// Set the event ID on the concrete type.
		setEventID(event, eventID)
	}

	// Store the event.
	cs.events[eventID] = event
	cs.eventOrder = append(cs.eventOrder, eventID)
	cs.mu.Unlock()

	result := &CaptureResult{
		EventID:   eventID,
		Timestamp: time.Now().UTC(),
	}

	// Seal if configured.
	if cs.config.SealOnCapture && cs.sealSDK != nil {
		sealResult, err := cs.SealEvent(ctx, event)
		if err != nil {
			return nil, fmt.Errorf("CaptureService.CaptureEvent: %w", err)
		}
		result.SealID = sealResult.SealID
		result.Sealed = true
	}

	return result, nil
}

// CaptureDocument captures all events in an EPCIS document.
func (cs *CaptureService) CaptureDocument(ctx context.Context, document *EPCISDocument) ([]*CaptureResult, error) {
	if document == nil {
		return nil, fmt.Errorf("CaptureService.CaptureDocument: %w: document is nil", ErrInvalidEvent)
	}

	var results []*CaptureResult
	for _, event := range document.EPCISBody.EventList {
		result, err := cs.CaptureEvent(ctx, event)
		if err != nil {
			return results, fmt.Errorf("CaptureService.CaptureDocument: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}

// SealEvent creates a Digital Seal for an EPCIS event. The event is hashed
// and submitted to the Aethelred seal infrastructure with supply-chain
// regulatory metadata.
func (cs *CaptureService) SealEvent(ctx context.Context, event EPCISEvent) (*CaptureResult, error) {
	if event == nil {
		return nil, fmt.Errorf("CaptureService.SealEvent: %w: event is nil", ErrInvalidEvent)
	}
	if cs.sealSDK == nil {
		return nil, fmt.Errorf("CaptureService.SealEvent: %w: seal SDK is required", ErrSealFailed)
	}

	// Serialize the event.
	eventData, err := event.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("CaptureService.SealEvent: %w: serialize: %v", ErrSealFailed, err)
	}

	// Compute event hash.
	eventHash := sha256.Sum256(eventData)

	// Determine jurisdiction.
	jurisdiction := cs.resolveJurisdiction(event)

	// Build seal request with supply chain metadata.
	sealReq := sdk.SealRequest{
		ModelHash:  eventHash[:],
		InputHash:  eventHash[:],
		OutputHash: eventHash[:],
		Purpose:    fmt.Sprintf("epcis_%s_seal", event.GetEventType()),
		RegulatoryInfo: &sdk.RegulatoryConfig{
			DataClassification:       "supply_chain",
			ComplianceFrameworks:     []string{"GS1-EPCIS", "FDA-FSMA", "EU-FMD"},
			JurisdictionRestrictions: []string{jurisdiction},
			RetentionPeriodDays:      3650, // 10 years
			AuditRequired:            true,
		},
		Metadata: map[string]string{
			"event_type":  string(event.GetEventType()),
			"event_id":    event.GetEventID(),
			"event_time":  event.GetEventTime().Format(time.RFC3339),
			"biz_step":    event.GetBizStep(),
			"standard":    "EPCIS-2.0",
			"sealed_at":   time.Now().UTC().Format(time.RFC3339),
			"event_hash":  hex.EncodeToString(eventHash[:]),
		},
	}

	// Submit to the seal SDK with retry and exponential backoff.
	var resp *sdk.SealResponse
	var lastErr error
	for attempt := 0; attempt < maxSealRetries; attempt++ {
		resp, lastErr = cs.sealSDK.CreateSeal(ctx, sealReq)
		if lastErr == nil {
			break
		}
		cs.logger.Warn("CaptureService.SealEvent: seal attempt failed, retrying",
			"attempt", attempt+1, "err", lastErr)
		cs.metrics.IncCounter("epcis_seal_retry", "event_type", string(event.GetEventType()))
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("CaptureService.SealEvent: %w: context cancelled during retry", ctx.Err())
		case <-time.After(time.Duration(100<<uint(attempt)) * time.Millisecond):
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("CaptureService.SealEvent: %w: %v", ErrSealFailed, lastErr)
	}

	// Record the mapping with dedicated RWMutex.
	cs.sealMu.Lock()
	cs.sealMap[event.GetEventID()] = resp.SealID
	cs.sealMu.Unlock()

	cs.metrics.IncCounter("epcis_event_sealed", "event_type", string(event.GetEventType()))

	return &CaptureResult{
		EventID:   event.GetEventID(),
		SealID:    resp.SealID,
		Timestamp: resp.Timestamp,
		Sealed:    true,
	}, nil
}

// GetEvent retrieves a captured event by its ID.
func (cs *CaptureService) GetEvent(eventID string) (EPCISEvent, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	e, ok := cs.events[eventID]
	return e, ok
}

// GetSealID returns the seal ID for a captured event.
func (cs *CaptureService) GetSealID(eventID string) (string, bool) {
	cs.sealMu.RLock()
	defer cs.sealMu.RUnlock()
	sid, ok := cs.sealMap[eventID]
	return sid, ok
}

// EventCount returns the number of captured events.
func (cs *CaptureService) EventCount() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.events)
}

// AllEvents returns all captured events in insertion order.
func (cs *CaptureService) AllEvents() []EPCISEvent {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	result := make([]EPCISEvent, 0, len(cs.eventOrder))
	for _, id := range cs.eventOrder {
		if e, ok := cs.events[id]; ok {
			result = append(result, e)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolveJurisdiction determines the jurisdiction for an event based on its
// business location and the configured rules.
func (cs *CaptureService) resolveJurisdiction(event EPCISEvent) string {
	// Attempt to extract business location from the concrete event type.
	var bizLoc string
	switch e := event.(type) {
	case *ObjectEvent:
		if e.BizLocation != nil {
			bizLoc = e.BizLocation.ID
		}
	case *AggregationEvent:
		if e.BizLocation != nil {
			bizLoc = e.BizLocation.ID
		}
	case *TransactionEvent:
		if e.BizLocation != nil {
			bizLoc = e.BizLocation.ID
		}
	case *TransformationEvent:
		if e.BizLocation != nil {
			bizLoc = e.BizLocation.ID
		}
	}

	if bizLoc != "" {
		if j, ok := cs.config.JurisdictionRules[bizLoc]; ok {
			return j
		}
	}

	return cs.config.DefaultJurisdiction
}

// setEventID sets the event ID on a concrete EPCIS event type.
func setEventID(event EPCISEvent, id string) {
	switch e := event.(type) {
	case *ObjectEvent:
		e.EventID = id
	case *AggregationEvent:
		e.EventID = id
	case *TransactionEvent:
		e.EventID = id
	case *TransformationEvent:
		e.EventID = id
	}
}
