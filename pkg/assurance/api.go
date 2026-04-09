package assurance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ---------------------------------------------------------------------------
// Assurance Service API
// ---------------------------------------------------------------------------
//
// This file defines the service interface and HTTP API for the Enterprise
// Assurance Fabric. It provides:
//
//   - A clean Go interface (AssuranceService) for programmatic use
//   - An HTTP server implementation (AssuranceServer) for REST API access
//   - Request/response types for each operation
// ---------------------------------------------------------------------------

// AssuranceService defines the operations available through the Assurance Fabric.
type AssuranceService interface {
	// CollectEvidence gathers all trust evidence for a job.
	CollectEvidence(ctx context.Context, req *CollectEvidenceRequest) (*CollectEvidenceResponse, error)

	// GetAssuranceLevel returns the assurance level for a job.
	GetAssuranceLevel(ctx context.Context, req *AssuranceLevelRequest) (*AssuranceLevelResponse, error)

	// CreateReceipt creates an execution receipt for a job.
	CreateReceipt(ctx context.Context, req *CreateReceiptRequest) (*CreateReceiptResponse, error)

	// VerifyReceipt verifies an execution receipt.
	VerifyReceiptIntegrity(ctx context.Context, req *VerifyReceiptRequest) (*VerifyReceiptResponse, error)

	// ExportRegulatorPackage creates a regulator-ready package.
	ExportRegulator(ctx context.Context, req *ExportRegulatorRequest) (*ExportRegulatorResponse, error)

	// GetPosture returns current compliance posture.
	GetPosture(ctx context.Context, req *GetPostureRequest) (*GetPostureResponse, error)
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// CollectEvidenceRequest requests evidence collection for a job.
type CollectEvidenceRequest struct {
	JobID string `json:"job_id"`
}

// CollectEvidenceResponse returns collected trust evidence.
type CollectEvidenceResponse struct {
	Evidence *TrustEvidence `json:"evidence"`
}

// AssuranceLevelRequest requests the assurance level for a job.
type AssuranceLevelRequest struct {
	JobID string `json:"job_id"`
}

// AssuranceLevelResponse returns the assurance level.
type AssuranceLevelResponse struct {
	JobID          string `json:"job_id"`
	AssuranceLevel string `json:"assurance_level"`
	Score          int    `json:"score"`
}

// CreateReceiptRequest requests receipt creation for a job.
type CreateReceiptRequest struct {
	JobID string `json:"job_id"`
}

// CreateReceiptResponse returns the created receipt.
type CreateReceiptResponse struct {
	Receipt *ExecutionReceipt `json:"receipt"`
}

// VerifyReceiptRequest requests verification of a receipt.
type VerifyReceiptRequest struct {
	Receipt *ExecutionReceipt `json:"receipt"`
}

// VerifyReceiptResponse returns the verification result.
type VerifyReceiptResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// ExportRegulatorRequest requests export of a regulator package.
type ExportRegulatorRequest struct {
	Receipts  []ExecutionReceipt `json:"receipts"`
	Framework string             `json:"framework"`
	Format    ExportFormat       `json:"format"`
}

// ExportRegulatorResponse returns the exported package.
type ExportRegulatorResponse struct {
	Package *RegulatorPackage `json:"package"`
	Data    []byte            `json:"data,omitempty"` // rendered in requested format
}

// GetPostureRequest requests current compliance posture.
type GetPostureRequest struct{}

// GetPostureResponse returns the compliance posture.
type GetPostureResponse struct {
	Posture *CompliancePosture `json:"posture"`
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

// AssuranceServer serves the Assurance Fabric over HTTP.
type AssuranceServer struct {
	fabric  *AssuranceFabric
	monitor *ContinuousMonitor
	mux     *http.ServeMux
}

// NewAssuranceServer creates a new HTTP server for the assurance fabric.
func NewAssuranceServer(fabric *AssuranceFabric, monitor *ContinuousMonitor) *AssuranceServer {
	s := &AssuranceServer{
		fabric:  fabric,
		monitor: monitor,
		mux:     http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// Handler returns the HTTP handler for the server.
func (s *AssuranceServer) Handler() http.Handler {
	return s.mux
}

func (s *AssuranceServer) registerRoutes() {
	s.mux.HandleFunc("/api/v1/assurance/evidence", s.handleCollectEvidence)
	s.mux.HandleFunc("/api/v1/assurance/level", s.handleGetAssuranceLevel)
	s.mux.HandleFunc("/api/v1/assurance/receipt", s.handleCreateReceipt)
	s.mux.HandleFunc("/api/v1/assurance/receipt/verify", s.handleVerifyReceipt)
	s.mux.HandleFunc("/api/v1/assurance/export/regulator", s.handleExportRegulator)
	s.mux.HandleFunc("/api/v1/assurance/posture", s.handleGetPosture)
}

func (s *AssuranceServer) handleCollectEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CollectEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	evidence, err := s.fabric.CollectEvidence(r.Context(), req.JobID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, &CollectEvidenceResponse{Evidence: evidence})
}

func (s *AssuranceServer) handleGetAssuranceLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	jobID := r.URL.Query().Get("job_id")
	if jobID == "" {
		writeJSONError(w, http.StatusBadRequest, "job_id query parameter is required")
		return
	}

	level, err := s.fabric.GetAssuranceLevel(r.Context(), jobID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, &AssuranceLevelResponse{
		JobID:          jobID,
		AssuranceLevel: level.String(),
		Score:          level.Score(),
	})
}

func (s *AssuranceServer) handleCreateReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CreateReceiptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	receipt, err := s.fabric.CreateReceipt(r.Context(), req.JobID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, &CreateReceiptResponse{Receipt: receipt})
}

func (s *AssuranceServer) handleVerifyReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req VerifyReceiptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	err := VerifyReceipt(req.Receipt)
	resp := &VerifyReceiptResponse{Valid: err == nil}
	if err != nil {
		resp.Message = err.Error()
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *AssuranceServer) handleExportRegulator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ExportRegulatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	pkg, err := ExportRegulatorPackage(r.Context(), req.Receipts, req.Framework)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, &ExportRegulatorResponse{Package: pkg})
}

func (s *AssuranceServer) handleGetPosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.monitor == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "continuous monitoring not configured")
		return
	}

	posture, err := s.monitor.GetPosture(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, &GetPostureResponse{Posture: posture})
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
