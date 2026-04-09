package epcis

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Recall Workflow
// ---------------------------------------------------------------------------
//
// RecallService manages product recall workflows by leveraging EPCIS event
// data and Aethelred Digital Seals. It supports initiating recalls, tracking
// affected items, and generating evidence packages for regulatory agencies.
// ---------------------------------------------------------------------------

// RecallSeverity classifies the urgency of a recall.
type RecallSeverity string

const (
	RecallSeverityClassI   RecallSeverity = "class_i"   // Serious health hazard
	RecallSeverityClassII  RecallSeverity = "class_ii"  // Temporary or reversible
	RecallSeverityClassIII RecallSeverity = "class_iii" // Unlikely adverse health
)

// RecallStatus tracks the current state of a recall.
type RecallStatus string

const (
	RecallStatusInitiated  RecallStatus = "initiated"
	RecallStatusInProgress RecallStatus = "in_progress"
	RecallStatusCompleted  RecallStatus = "completed"
	RecallStatusCancelled  RecallStatus = "cancelled"
)

// RecallRequest contains the parameters for initiating a product recall.
type RecallRequest struct {
	// EPC is the Electronic Product Code of the item being recalled.
	EPC string `json:"epc"`

	// Reason describes why the recall is being initiated.
	Reason string `json:"reason"`

	// Severity classifies the recall urgency.
	Severity RecallSeverity `json:"severity"`

	// AffectedBatch identifies the production batch (if broader than one EPC).
	AffectedBatch string `json:"affected_batch,omitempty"`

	// Initiator is the entity initiating the recall.
	Initiator string `json:"initiator"`
}

// RecallResponse contains the outcome of a recall initiation.
type RecallResponse struct {
	// RecallID is the unique identifier for this recall.
	RecallID string `json:"recall_id"`

	// Status is the current recall status.
	Status RecallStatus `json:"status"`

	// AffectedItems lists all EPCs affected by this recall.
	AffectedItems []string `json:"affected_items"`

	// ProvenanceChain is the full provenance chain of the recalled item.
	ProvenanceChain *ProvenanceChain `json:"provenance_chain,omitempty"`

	// InitiatedAt is when the recall was initiated.
	InitiatedAt time.Time `json:"initiated_at"`

	// Severity is the recall severity.
	Severity RecallSeverity `json:"severity"`

	// Reason is the recall reason.
	Reason string `json:"reason"`
}

// RecallEvidence is a package of evidence for regulatory review.
type RecallEvidence struct {
	// RecallID is the associated recall.
	RecallID string `json:"recall_id"`

	// ProvenanceChain is the complete provenance chain.
	ProvenanceChain *ProvenanceChain `json:"provenance_chain"`

	// EventTimeline lists all events in chronological order.
	EventTimeline []EventSummary `json:"event_timeline"`

	// SealVerifications maps seal IDs to their verification status.
	SealVerifications map[string]bool `json:"seal_verifications"`

	// GeneratedAt is when this evidence package was created.
	GeneratedAt time.Time `json:"generated_at"`

	// AffectedLocations lists all locations where the recalled item was present.
	AffectedLocations []string `json:"affected_locations"`
}

// recallRecord is the internal storage representation of a recall.
type recallRecord struct {
	Request  RecallRequest    `json:"request"`
	Response RecallResponse   `json:"response"`
	Status   RecallStatus     `json:"status"`
	Evidence *RecallEvidence  `json:"evidence,omitempty"`
}

// RecallService manages product recall workflows.
type RecallService struct {
	mu       sync.Mutex
	bridge   *ProvenanceBridge
	capture  *CaptureService
	query    *QueryService

	// recalls maps recall IDs to their records.
	recalls map[string]*recallRecord

	// sequence generates unique recall IDs.
	sequence uint64
}

// NewRecallService creates a new recall service.
func NewRecallService(capture *CaptureService, query *QueryService, bridge *ProvenanceBridge) *RecallService {
	return &RecallService{
		bridge:  bridge,
		capture: capture,
		query:   query,
		recalls: make(map[string]*recallRecord),
	}
}

// InitiateRecall starts a product recall workflow. It traces the affected
// item, identifies all related events and locations, and creates a recall
// record with full provenance.
func (rs *RecallService) InitiateRecall(ctx context.Context, req RecallRequest) (*RecallResponse, error) {
	if req.EPC == "" {
		return nil, fmt.Errorf("RecallService.InitiateRecall: %w: EPC is empty", ErrRecallFailed)
	}
	if req.Reason == "" {
		return nil, fmt.Errorf("RecallService.InitiateRecall: %w: reason is empty", ErrRecallFailed)
	}
	if req.Initiator == "" {
		return nil, fmt.Errorf("RecallService.InitiateRecall: %w: initiator is empty", ErrRecallFailed)
	}
	if req.Severity == "" {
		req.Severity = RecallSeverityClassII
	}

	rs.mu.Lock()
	rs.sequence++
	recallID := fmt.Sprintf("recall-%d-%d", time.Now().Unix(), rs.sequence)
	rs.mu.Unlock()

	// Build the provenance chain for the affected item.
	var chain *ProvenanceChain
	if rs.bridge != nil {
		var err error
		chain, err = rs.bridge.BuildProvenanceChain(ctx, req.EPC)
		if err != nil {
			// Recall can proceed even without full provenance.
			chain = nil
		}
	}

	// Collect affected items (the EPC itself plus batch items if specified).
	affectedItems := []string{req.EPC}
	if req.AffectedBatch != "" {
		batchItems := rs.findBatchItems(ctx, req.AffectedBatch)
		affectedItems = append(affectedItems, batchItems...)
	}

	response := &RecallResponse{
		RecallID:        recallID,
		Status:          RecallStatusInitiated,
		AffectedItems:   affectedItems,
		ProvenanceChain: chain,
		InitiatedAt:     time.Now().UTC(),
		Severity:        req.Severity,
		Reason:          req.Reason,
	}

	// Store the recall record.
	rs.mu.Lock()
	rs.recalls[recallID] = &recallRecord{
		Request:  req,
		Response: *response,
		Status:   RecallStatusInitiated,
	}
	rs.mu.Unlock()

	return response, nil
}

// GetRecallStatus returns the current status of a recall.
func (rs *RecallService) GetRecallStatus(_ context.Context, recallID string) (*RecallResponse, error) {
	if recallID == "" {
		return nil, fmt.Errorf("RecallService: %w: recall ID is empty", ErrRecallFailed)
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	record, ok := rs.recalls[recallID]
	if !ok {
		return nil, fmt.Errorf("RecallService: %w: recall %s not found", ErrRecallFailed, recallID)
	}

	return &record.Response, nil
}

// GenerateRecallEvidence generates a comprehensive evidence package for
// regulatory agencies. It includes the full provenance chain, event
// timeline, seal verifications, and affected locations.
func (rs *RecallService) GenerateRecallEvidence(ctx context.Context, recallID string) (*RecallEvidence, error) {
	if recallID == "" {
		return nil, fmt.Errorf("RecallService: %w: recall ID is empty", ErrRecallFailed)
	}

	rs.mu.Lock()
	record, ok := rs.recalls[recallID]
	rs.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("RecallService: %w: recall %s not found", ErrRecallFailed, recallID)
	}

	// Build or use existing provenance chain.
	chain := record.Response.ProvenanceChain
	if chain == nil && rs.bridge != nil {
		var err error
		chain, err = rs.bridge.BuildProvenanceChain(ctx, record.Request.EPC)
		if err != nil {
			return nil, fmt.Errorf("RecallService.GenerateRecallEvidence: %w: %v", ErrProvenanceFailed, err)
		}
	}

	evidence := &RecallEvidence{
		RecallID:          recallID,
		ProvenanceChain:   chain,
		SealVerifications: make(map[string]bool),
		GeneratedAt:       time.Now().UTC(),
	}

	// Build event timeline and collect locations.
	locationSet := make(map[string]bool)
	if chain != nil {
		evidence.EventTimeline = chain.EventSummaries

		for _, summary := range chain.EventSummaries {
			if summary.Location != "" {
				locationSet[summary.Location] = true
			}

			// Record seal verification status.
			if summary.Sealed {
				evidence.SealVerifications[summary.SealID] = true
			}
		}
	}

	for loc := range locationSet {
		evidence.AffectedLocations = append(evidence.AffectedLocations, loc)
	}

	// Store the evidence in the recall record.
	rs.mu.Lock()
	rs.recalls[recallID].Evidence = evidence
	rs.mu.Unlock()

	return evidence, nil
}

// CompleteRecall marks a recall as completed.
func (rs *RecallService) CompleteRecall(_ context.Context, recallID string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	record, ok := rs.recalls[recallID]
	if !ok {
		return fmt.Errorf("RecallService: %w: recall %s not found", ErrRecallFailed, recallID)
	}

	record.Status = RecallStatusCompleted
	record.Response.Status = RecallStatusCompleted
	return nil
}

// CancelRecall cancels a recall.
func (rs *RecallService) CancelRecall(_ context.Context, recallID string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	record, ok := rs.recalls[recallID]
	if !ok {
		return fmt.Errorf("RecallService: %w: recall %s not found", ErrRecallFailed, recallID)
	}

	record.Status = RecallStatusCancelled
	record.Response.Status = RecallStatusCancelled
	return nil
}

// RecallCount returns the number of recalls in the system.
func (rs *RecallService) RecallCount() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.recalls)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// findBatchItems searches for EPCs associated with a batch identifier.
func (rs *RecallService) findBatchItems(ctx context.Context, batch string) []string {
	allEvents := rs.capture.AllEvents()
	epcSet := make(map[string]bool)

	for _, event := range allEvents {
		// Check for batch in extensions.
		if oe, ok := event.(*ObjectEvent); ok {
			if oe.Extensions != nil && oe.Extensions["batch_number"] == batch {
				for _, epc := range oe.EPCList {
					epcSet[epc] = true
				}
			}
		}
	}

	// Suppress unused variable warning for ctx — the parameter is retained
	// for interface consistency with async implementations.
	_ = ctx

	var items []string
	for epc := range epcSet {
		items = append(items, epc)
	}
	return items
}
