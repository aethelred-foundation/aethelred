package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Audit Service API
// ---------------------------------------------------------------------------
//
// This file defines the service interface and HTTP API for the Audit Studio.
// It provides:
//   - A clean Go interface (AuditService) for programmatic use
//   - An HTTP server implementation (AuditServer) for REST API access
//   - Request/response types for each operation
//
// The HTTP API uses JSON for request and response bodies and follows
// REST conventions for resource addressing.
// ---------------------------------------------------------------------------

// AuditService defines the operations available through the Audit Studio.
type AuditService interface {
	// Query returns audit records matching the given filter.
	QueryRecords(ctx context.Context, req *QueryRequest) (*QueryResponse, error)

	// GetRecord returns a single audit record by sequence number.
	GetRecord(ctx context.Context, req *GetRecordRequest) (*GetRecordResponse, error)

	// GetChain returns a range of chained records with integrity verification.
	GetChain(ctx context.Context, req *GetChainRequest) (*GetChainResponse, error)

	// VerifyChain verifies hash chain integrity.
	VerifyChainIntegrity(ctx context.Context, req *VerifyChainRequest) (*VerifyChainResponse, error)

	// GetStats returns aggregate statistics.
	GetStats(ctx context.Context, req *GetStatsRequest) (*GetStatsResponse, error)

	// BuildTimeline constructs a chronological event timeline.
	BuildTimeline(ctx context.Context, req *BuildTimelineRequest) (*BuildTimelineResponse, error)

	// GetBundle returns an evidence bundle.
	GetBundle(ctx context.Context, req *GetBundleRequest) (*GetBundleResponse, error)

	// VerifyBundle verifies bundle integrity.
	VerifyBundleIntegrity(ctx context.Context, req *VerifyBundleRequest) (*VerifyBundleResponse, error)

	// GetRetentionStatus returns retention status for records.
	GetRetentionStatus(ctx context.Context, req *GetRetentionRequest) (*GetRetentionResponse, error)

	// GetCustodyHistory returns chain of custody for a bundle.
	GetCustodyHistory(ctx context.Context, req *GetCustodyRequest) (*GetCustodyResponse, error)
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// QueryRequest is the input for record queries.
type QueryRequest struct {
	Filter *Filter `json:"filter"`
}

// QueryResponse is the output for record queries.
type QueryResponse struct {
	Records []keeper.AuditRecord `json:"records"`
	Total   int                  `json:"total"`
}

// GetRecordRequest identifies a single record.
type GetRecordRequest struct {
	Sequence uint64 `json:"sequence"`
}

// GetRecordResponse contains a single audit record.
type GetRecordResponse struct {
	Record *keeper.AuditRecord `json:"record"`
}

// GetChainRequest specifies a range of records to retrieve.
type GetChainRequest struct {
	FromSequence uint64 `json:"from_sequence"`
	ToSequence   uint64 `json:"to_sequence"`
}

// GetChainResponse contains the retrieved chain and its integrity status.
type GetChainResponse struct {
	Records []keeper.AuditRecord `json:"records"`
	Intact  bool                 `json:"intact"`
	Error   string               `json:"error,omitempty"`
}

// VerifyChainRequest requests chain verification over a range.
type VerifyChainRequest struct {
	FromSequence uint64 `json:"from_sequence,omitempty"`
	ToSequence   uint64 `json:"to_sequence,omitempty"`
}

// VerifyChainResponse reports the verification outcome.
type VerifyChainResponse struct {
	Intact       bool   `json:"intact"`
	RecordCount  int    `json:"record_count"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence uint64 `json:"last_sequence"`
	Error        string `json:"error,omitempty"`
}

// GetStatsRequest specifies the filter for statistics computation.
type GetStatsRequest struct {
	Filter *Filter `json:"filter,omitempty"`
}

// GetStatsResponse contains the computed statistics.
type GetStatsResponse struct {
	Stats *AuditStats `json:"stats"`
}

// BuildTimelineRequest specifies how to build a timeline.
type BuildTimelineRequest struct {
	// Type is one of: "filter", "job", "actor", "incident".
	Type string `json:"type"`

	// Filter is used when Type is "filter".
	Filter *Filter `json:"filter,omitempty"`

	// JobID is used when Type is "job".
	JobID string `json:"job_id,omitempty"`

	// Actor is used when Type is "actor".
	Actor string `json:"actor,omitempty"`

	// IncidentID is used when Type is "incident".
	IncidentID string `json:"incident_id,omitempty"`
}

// BuildTimelineResponse contains the constructed timeline.
type BuildTimelineResponse struct {
	Timeline *Timeline `json:"timeline"`
}

// GetBundleRequest identifies a bundle.
type GetBundleRequest struct {
	BundleID string `json:"bundle_id"`
}

// GetBundleResponse contains a bundle.
type GetBundleResponse struct {
	Bundle *Bundle `json:"bundle"`
}

// VerifyBundleRequest requests bundle verification.
type VerifyBundleRequest struct {
	BundleID string `json:"bundle_id,omitempty"`
	Bundle   *Bundle `json:"bundle,omitempty"`
}

// VerifyBundleResponse reports the bundle verification outcome.
type VerifyBundleResponse struct {
	Valid       bool   `json:"valid"`
	ContentHash string `json:"content_hash"`
	ChainIntact bool   `json:"chain_intact"`
	Error       string `json:"error,omitempty"`
}

// GetRetentionRequest specifies the retention query.
type GetRetentionRequest struct {
	Policy *RetentionPolicy `json:"policy,omitempty"`
}

// GetRetentionResponse contains retention status.
type GetRetentionResponse struct {
	Summary *RetentionSummary `json:"summary"`
}

// GetCustodyRequest identifies a custody chain.
type GetCustodyRequest struct {
	BundleID string `json:"bundle_id"`
}

// GetCustodyResponse contains a custody chain.
type GetCustodyResponse struct {
	Chain *CustodyChain `json:"chain"`
}

// ---------------------------------------------------------------------------
// AuditServer -- HTTP API implementation
// ---------------------------------------------------------------------------

// AuditServer implements AuditService and provides HTTP handlers.
type AuditServer struct {
	studio       *Studio
	custodyStore *CustodyStore
	bundles      map[string]*Bundle // In-memory bundle store for demonstration.
}

// NewAuditServer creates a new HTTP API server backed by the given studio.
func NewAuditServer(studio *Studio, custodyStore *CustodyStore) *AuditServer {
	return &AuditServer{
		studio:       studio,
		custodyStore: custodyStore,
		bundles:      make(map[string]*Bundle),
	}
}

// RegisterRoutes registers the audit API HTTP routes on the given mux.
func (s *AuditServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/audit/records", s.handleQueryRecords)
	mux.HandleFunc("/api/v1/audit/records/", s.handleGetRecord)
	mux.HandleFunc("/api/v1/audit/chain", s.handleGetChain)
	mux.HandleFunc("/api/v1/audit/verify", s.handleVerifyChain)
	mux.HandleFunc("/api/v1/audit/stats", s.handleGetStats)
	mux.HandleFunc("/api/v1/audit/timeline", s.handleBuildTimeline)
	mux.HandleFunc("/api/v1/audit/bundles/", s.handleGetBundle)
	mux.HandleFunc("/api/v1/audit/bundles/verify", s.handleVerifyBundle)
	mux.HandleFunc("/api/v1/audit/retention", s.handleGetRetention)
	mux.HandleFunc("/api/v1/audit/custody/", s.handleGetCustody)
}

// ---------------------------------------------------------------------------
// AuditService interface implementation
// ---------------------------------------------------------------------------

func (s *AuditServer) QueryRecords(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	records, err := s.studio.Query(ctx, req.Filter)
	if err != nil {
		return nil, err
	}
	return &QueryResponse{
		Records: records,
		Total:   len(records),
	}, nil
}

func (s *AuditServer) GetRecord(ctx context.Context, req *GetRecordRequest) (*GetRecordResponse, error) {
	record, err := s.studio.GetRecord(ctx, req.Sequence)
	if err != nil {
		return nil, err
	}
	return &GetRecordResponse{Record: record}, nil
}

func (s *AuditServer) GetChain(ctx context.Context, req *GetChainRequest) (*GetChainResponse, error) {
	records, err := s.studio.GetChain(ctx, req.FromSequence, req.ToSequence)
	resp := &GetChainResponse{
		Records: records,
		Intact:  err == nil,
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *AuditServer) VerifyChainIntegrity(ctx context.Context, req *VerifyChainRequest) (*VerifyChainResponse, error) {
	f := NewFilter()
	if req.FromSequence > 0 || req.ToSequence > 0 {
		f.WithSequenceRange(req.FromSequence, req.ToSequence)
	}

	records, err := s.studio.Query(ctx, f)
	if err != nil {
		return nil, err
	}

	chainErr := VerifyChain(records)
	resp := &VerifyChainResponse{
		Intact:      chainErr == nil,
		RecordCount: len(records),
	}
	if len(records) > 0 {
		resp.FirstSequence = records[0].Sequence
		resp.LastSequence = records[len(records)-1].Sequence
	}
	if chainErr != nil {
		resp.Error = chainErr.Error()
	}
	return resp, nil
}

func (s *AuditServer) GetStats(ctx context.Context, req *GetStatsRequest) (*GetStatsResponse, error) {
	stats, err := s.studio.GetStats(ctx, req.Filter)
	if err != nil {
		return nil, err
	}
	return &GetStatsResponse{Stats: stats}, nil
}

func (s *AuditServer) BuildTimeline(ctx context.Context, req *BuildTimelineRequest) (*BuildTimelineResponse, error) {
	var tl *Timeline
	var err error

	switch req.Type {
	case "filter", "":
		tl, err = BuildTimeline(ctx, s.studio.Source(), req.Filter)
	case "job":
		tl, err = BuildJobTimeline(ctx, s.studio.Source(), req.JobID)
	case "actor":
		tl, err = BuildActorTimeline(ctx, s.studio.Source(), req.Actor)
	case "incident":
		tl, err = BuildIncidentTimeline(ctx, s.studio.Source(), req.IncidentID)
	default:
		return nil, fmt.Errorf("audit/api: unknown timeline type %q", req.Type)
	}

	if err != nil {
		return nil, err
	}
	return &BuildTimelineResponse{Timeline: tl}, nil
}

func (s *AuditServer) GetBundle(_ context.Context, req *GetBundleRequest) (*GetBundleResponse, error) {
	bundle, ok := s.bundles[req.BundleID]
	if !ok {
		return nil, fmt.Errorf("audit/api: bundle %s not found", req.BundleID)
	}
	return &GetBundleResponse{Bundle: bundle}, nil
}

func (s *AuditServer) VerifyBundleIntegrity(_ context.Context, req *VerifyBundleRequest) (*VerifyBundleResponse, error) {
	bundle := req.Bundle
	if bundle == nil && req.BundleID != "" {
		b, ok := s.bundles[req.BundleID]
		if !ok {
			return nil, fmt.Errorf("audit/api: bundle %s not found", req.BundleID)
		}
		bundle = b
	}
	if bundle == nil {
		return nil, fmt.Errorf("audit/api: no bundle provided")
	}

	err := VerifyBundle(bundle)
	resp := &VerifyBundleResponse{
		Valid:       err == nil,
		ContentHash: bundle.ContentHash,
		ChainIntact: VerifyChain(bundle.Records) == nil,
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *AuditServer) GetRetentionStatus(_ context.Context, req *GetRetentionRequest) (*GetRetentionResponse, error) {
	policy := req.Policy
	if policy == nil {
		p := PolicyGDPR()
		policy = &p
	}
	summary, err := SummarizeRetention(s.studio.Source(), *policy)
	if err != nil {
		return nil, err
	}
	return &GetRetentionResponse{Summary: summary}, nil
}

func (s *AuditServer) GetCustodyHistory(_ context.Context, req *GetCustodyRequest) (*GetCustodyResponse, error) {
	if s.custodyStore == nil {
		return nil, fmt.Errorf("audit/api: custody store not configured")
	}
	chain, err := s.custodyStore.GetCustodyHistory(req.BundleID)
	if err != nil {
		return nil, err
	}
	return &GetCustodyResponse{Chain: chain}, nil
}

// StoreBundle adds a bundle to the in-memory store (for testing and
// demonstration).
func (s *AuditServer) StoreBundle(bundle *Bundle) {
	if bundle != nil {
		s.bundles[bundle.ID] = bundle
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func (s *AuditServer) handleQueryRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req QueryRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	} else {
		req.Filter = parseFilterFromQuery(r)
	}

	resp, err := s.QueryRecords(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleGetRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	seqStr := r.URL.Path[len("/api/v1/audit/records/"):]
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid sequence number")
		return
	}

	resp, err := s.GetRecord(r.Context(), &GetRecordRequest{Sequence: seq})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleGetChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	from, _ := strconv.ParseUint(fromStr, 10, 64)
	to, _ := strconv.ParseUint(toStr, 10, 64)

	resp, err := s.GetChain(r.Context(), &GetChainRequest{FromSequence: from, ToSequence: to})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.VerifyChainIntegrity(r.Context(), &VerifyChainRequest{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.GetStats(r.Context(), &GetStatsRequest{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleBuildTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req BuildTimelineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.BuildTimeline(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bundleID := r.URL.Path[len("/api/v1/audit/bundles/"):]
	resp, err := s.GetBundle(r.Context(), &GetBundleRequest{BundleID: bundleID})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleVerifyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req VerifyBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.VerifyBundleIntegrity(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleGetRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.GetRetentionStatus(r.Context(), &GetRetentionRequest{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleGetCustody(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bundleID := r.URL.Path[len("/api/v1/audit/custody/"):]
	resp, err := s.GetCustodyHistory(r.Context(), &GetCustodyRequest{BundleID: bundleID})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

type apiError struct {
	Error     string `json:"error"`
	Timestamp string `json:"timestamp"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiError{ //nolint:errcheck
		Error:     msg,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func parseFilterFromQuery(r *http.Request) *Filter {
	f := NewFilter()

	if cat := r.URL.Query().Get("category"); cat != "" {
		f.WithCategories(keeper.AuditCategory(cat))
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		f.WithSeverities(keeper.AuditSeverity(sev))
	}
	if actor := r.URL.Query().Get("actor"); actor != "" {
		f.WithActors(actor)
	}
	if action := r.URL.Query().Get("action"); action != "" {
		f.WithActions(action)
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			f.WithLimit(limit)
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			f.WithOffset(offset)
		}
	}

	return f
}
