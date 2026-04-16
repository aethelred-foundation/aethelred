package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	evidenceexport "github.com/aethelred/aethelred/pkg/evidence/export"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
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

	// GetControlLedger returns a typed control ledger.
	GetControlLedger(ctx context.Context, req *GetControlLedgerRequest) (*GetControlLedgerResponse, error)

	// ListControlLedgers returns all persisted control ledgers.
	ListControlLedgers(ctx context.Context, req *ListControlLedgersRequest) (*ListControlLedgersResponse, error)

	// PutControlLedger validates and persists a control ledger.
	PutControlLedger(ctx context.Context, req *PutControlLedgerRequest) (*PutControlLedgerResponse, error)

	// ExportControlLedger exports a control ledger in an auditor-ready format.
	ExportControlLedger(ctx context.Context, req *ExportControlLedgerRequest) (*ExportControlLedgerResponse, error)

	// GetPortableControlLedgerPackage returns a portable auditor package for a
	// persisted control ledger.
	GetPortableControlLedgerPackage(ctx context.Context, req *GetPortableControlLedgerPackageRequest) (*GetPortableControlLedgerPackageResponse, error)

	// VerifyPortableControlLedgerPackage verifies a posted portable control-ledger package.
	VerifyPortableControlLedgerPackage(ctx context.Context, req *VerifyPortableControlLedgerPackageRequest) (*VerifyPortableControlLedgerPackageResponse, error)

	// GetControlLedgerTrustCompliancePackages returns the canonical
	// trust-compliance artifacts embedded in a control ledger.
	GetControlLedgerTrustCompliancePackages(ctx context.Context, req *GetControlLedgerTrustCompliancePackagesRequest) (*GetControlLedgerTrustCompliancePackagesResponse, error)

	// GetControlLedgerApproverAttestations returns the canonical approver
	// attestation artifacts embedded in a control ledger.
	GetControlLedgerApproverAttestations(ctx context.Context, req *GetControlLedgerApproverAttestationsRequest) (*GetControlLedgerApproverAttestationsResponse, error)

	// GetControlLedgerValueSettlements returns the canonical value-settlement
	// artifacts embedded in a control ledger.
	GetControlLedgerValueSettlements(ctx context.Context, req *GetControlLedgerValueSettlementsRequest) (*GetControlLedgerValueSettlementsResponse, error)

	// GetControlLedgerPackageAnchors returns governance audit records for
	// portable control-ledger package anchors.
	GetControlLedgerPackageAnchors(ctx context.Context, req *GetControlLedgerPackageAnchorsRequest) (*GetControlLedgerPackageAnchorsResponse, error)

	// GetEnterpriseTrustRegistry returns the active enterprise trust registry.
	GetEnterpriseTrustRegistry(ctx context.Context, req *GetEnterpriseTrustRegistryRequest) (*GetEnterpriseTrustRegistryResponse, error)

	// GetEnterpriseTrustRegistryStatus returns status for the active trust registry.
	GetEnterpriseTrustRegistryStatus(ctx context.Context, req *GetEnterpriseTrustRegistryStatusRequest) (*GetEnterpriseTrustRegistryStatusResponse, error)

	// GetEnterpriseTrustRegistryHistory returns governance audit records for trust-registry mutations.
	GetEnterpriseTrustRegistryHistory(ctx context.Context, req *GetEnterpriseTrustRegistryHistoryRequest) (*GetEnterpriseTrustRegistryHistoryResponse, error)

	// GetTrustComplianceExportAnchors returns governance audit records for anchored trust-compliance exports.
	GetTrustComplianceExportAnchors(ctx context.Context, req *GetTrustComplianceExportAnchorsRequest) (*GetTrustComplianceExportAnchorsResponse, error)

	// PutEnterpriseTrustRegistry validates and persists a new trust registry.
	PutEnterpriseTrustRegistry(ctx context.Context, req *PutEnterpriseTrustRegistryRequest) (*PutEnterpriseTrustRegistryResponse, error)

	// DeleteEnterpriseTrustRegistry clears the active trust registry.
	DeleteEnterpriseTrustRegistry(ctx context.Context, req *DeleteEnterpriseTrustRegistryRequest) (*DeleteEnterpriseTrustRegistryResponse, error)

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
	Intact        bool   `json:"intact"`
	RecordCount   int    `json:"record_count"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
	Error         string `json:"error,omitempty"`
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
	BundleID string  `json:"bundle_id,omitempty"`
	Bundle   *Bundle `json:"bundle,omitempty"`
}

// VerifyBundleResponse reports the bundle verification outcome.
type VerifyBundleResponse struct {
	Valid       bool   `json:"valid"`
	ContentHash string `json:"content_hash"`
	ChainIntact bool   `json:"chain_intact"`
	Error       string `json:"error,omitempty"`
}

// GetControlLedgerRequest identifies a control ledger.
type GetControlLedgerRequest struct {
	LedgerID string `json:"ledger_id"`
}

// GetControlLedgerResponse contains a control ledger.
type GetControlLedgerResponse struct {
	Ledger *evidence.ControlLedger `json:"ledger"`
}

// ListControlLedgersRequest requests all persisted control ledgers.
type ListControlLedgersRequest struct{}

// ListControlLedgersResponse contains all persisted control ledgers.
type ListControlLedgersResponse struct {
	Ledgers []*evidence.ControlLedger `json:"ledgers"`
	Total   int                       `json:"total"`
}

// PutControlLedgerRequest validates and persists a control ledger.
type PutControlLedgerRequest struct {
	Ledger         *evidence.ControlLedger            `json:"ledger"`
	EnterpriseAuth *EnterpriseControlLedgerWriteAuthz `json:"enterprise_auth,omitempty"`
}

// PutControlLedgerResponse returns the persisted control ledger snapshot.
type PutControlLedgerResponse struct {
	Ledger *evidence.ControlLedger `json:"ledger"`
}

// EnterpriseControlLedgerWriteAuthz carries the enterprise identity and
// signed policy decision that authorize a mutating control-ledger request.
type EnterpriseControlLedgerWriteAuthz struct {
	ActorIdentity *agent.AgentIdentity        `json:"actor_identity"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt"`
}

// ExportControlLedgerRequest requests an auditor-ready control-ledger export.
type ExportControlLedgerRequest struct {
	LedgerID string `json:"ledger_id"`
	Format   string `json:"format,omitempty"`
}

// ExportControlLedgerResponse contains the raw export payload and response
// metadata for a control ledger export.
type ExportControlLedgerResponse struct {
	LedgerID    string `json:"ledger_id"`
	Format      string `json:"format"`
	ContentType string `json:"content_type"`
	Payload     []byte `json:"-"`
}

// GetPortableControlLedgerPackageRequest requests a portable auditor package
// for a persisted control ledger.
type GetPortableControlLedgerPackageRequest struct {
	LedgerID                string `json:"ledger_id"`
	IncludeVerificationKeys bool   `json:"include_verification_keys,omitempty"`
	Sign                    bool   `json:"sign,omitempty"`
	Anchor                  bool   `json:"anchor,omitempty"`
}

// GetPortableControlLedgerPackageResponse returns a portable control-ledger
// package.
type GetPortableControlLedgerPackageResponse struct {
	LedgerID string                                 `json:"ledger_id"`
	Package  *evidence.PortableControlLedgerPackage `json:"package"`
}

// VerifyPortableControlLedgerPackageRequest requests verification for a posted
// portable control-ledger package.
type VerifyPortableControlLedgerPackageRequest struct {
	Package *evidence.PortableControlLedgerPackage `json:"package"`
}

// VerifyPortableControlLedgerPackageResponse reports the verification outcome
// for a portable control-ledger package.
type VerifyPortableControlLedgerPackageResponse struct {
	Valid            bool                                       `json:"valid"`
	LedgerID         string                                     `json:"ledger_id,omitempty"`
	PackageHash      string                                     `json:"package_hash,omitempty"`
	Summary          *evidence.ControlLedgerSummary             `json:"summary,omitempty"`
	AnchorMatches    []PortableControlLedgerPackageAnchorRecord `json:"anchor_matches,omitempty"`
	AnchorMatchCount int                                        `json:"anchor_match_count,omitempty"`
	Error            string                                     `json:"error,omitempty"`
}

// GetControlLedgerTrustCompliancePackagesRequest requests the embedded
// trust-compliance artifacts for a control ledger.
type GetControlLedgerTrustCompliancePackagesRequest struct {
	LedgerID string `json:"ledger_id"`
}

// GetControlLedgerTrustCompliancePackagesResponse returns the embedded
// trust-compliance artifacts for a control ledger.
type GetControlLedgerTrustCompliancePackagesResponse struct {
	LedgerID string                                    `json:"ledger_id"`
	Packages []evidence.TrustCompliancePackageEvidence `json:"packages"`
	Total    int                                       `json:"total"`
}

// GetControlLedgerApproverAttestationsRequest requests the embedded approver
// attestation artifacts for a control ledger.
type GetControlLedgerApproverAttestationsRequest struct {
	LedgerID string `json:"ledger_id"`
}

// GetControlLedgerApproverAttestationsResponse returns the embedded approver
// attestation artifacts for a control ledger.
type GetControlLedgerApproverAttestationsResponse struct {
	LedgerID     string                                 `json:"ledger_id"`
	Attestations []evidence.ApproverAttestationEvidence `json:"attestations"`
	Total        int                                    `json:"total"`
}

// GetControlLedgerValueSettlementsRequest requests the embedded value-settlement
// artifacts for a control ledger.
type GetControlLedgerValueSettlementsRequest struct {
	LedgerID string `json:"ledger_id"`
}

// GetControlLedgerValueSettlementsResponse returns the embedded value-settlement
// artifacts for a control ledger.
type GetControlLedgerValueSettlementsResponse struct {
	LedgerID    string                             `json:"ledger_id"`
	Settlements []evidence.ValueSettlementEvidence `json:"settlements"`
	Total       int                                `json:"total"`
}

// GetControlLedgerPackageAnchorsRequest requests audit records for anchored
// portable control-ledger packages.
type GetControlLedgerPackageAnchorsRequest struct {
	Filter *Filter `json:"filter,omitempty"`
}

// GetControlLedgerPackageAnchorsResponse contains audit records for anchored
// portable control-ledger packages.
type GetControlLedgerPackageAnchorsResponse struct {
	Records []keeper.AuditRecord                       `json:"records"`
	Anchors []PortableControlLedgerPackageAnchorRecord `json:"anchors,omitempty"`
	Total   int                                        `json:"total"`
}

// PortableControlLedgerPackageAnchorSummary captures the normalized metadata
// emitted when a portable control-ledger package is anchored into governance
// audit history.
type PortableControlLedgerPackageAnchorSummary struct {
	PackageHash                  string `json:"package_hash,omitempty"`
	LedgerID                     string `json:"ledger_id,omitempty"`
	FormatVersion                string `json:"format_version,omitempty"`
	PackagedAt                   string `json:"packaged_at,omitempty"`
	Framework                    string `json:"framework,omitempty"`
	BundleContentHash            string `json:"bundle_content_hash,omitempty"`
	ControlsTotal                int    `json:"controls_total,omitempty"`
	TrustCompliancePackagesTotal int    `json:"trust_compliance_packages_total,omitempty"`
	VerificationKeyCount         int    `json:"verification_key_count,omitempty"`
	TrustAnchorCount             int    `json:"trust_anchor_count,omitempty"`
	SchemaDefinition             string `json:"schema_definition,omitempty"`
	Signed                       bool   `json:"signed"`
	Signer                       string `json:"signer,omitempty"`
	SignatureKeyID               string `json:"signature_key_id,omitempty"`
	SignatureAlgorithm           string `json:"signature_algorithm,omitempty"`
	SignedAt                     string `json:"signed_at,omitempty"`
}

// PortableControlLedgerPackageAnchorRecord pairs the raw governance audit
// record with a normalized anchor summary for operator tooling.
type PortableControlLedgerPackageAnchorRecord struct {
	Record  keeper.AuditRecord                         `json:"record"`
	Summary *PortableControlLedgerPackageAnchorSummary `json:"summary,omitempty"`
}

// PortableControlLedgerPackageAnchorFilter narrows normalized anchored-package
// discovery beyond the underlying governance history filter.
type PortableControlLedgerPackageAnchorFilter struct {
	PackageHash string `json:"package_hash,omitempty"`
	LedgerID    string `json:"ledger_id,omitempty"`
	Signer      string `json:"signer,omitempty"`
	Signed      *bool  `json:"signed,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Offset      int    `json:"offset,omitempty"`
}

// PortableControlLedgerPackageSigner signs a portable control-ledger package.
type PortableControlLedgerPackageSigner func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// PortableControlLedgerPackageAnchorer anchors a portable control-ledger
// package into the governance audit chain.
type PortableControlLedgerPackageAnchorer func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// GetEnterpriseTrustRegistryRequest requests the active enterprise trust
// registry.
type GetEnterpriseTrustRegistryRequest struct{}

// GetEnterpriseTrustRegistryResponse contains the active enterprise trust
// registry.
type GetEnterpriseTrustRegistryResponse struct {
	Registry *EnterpriseControlLedgerTrustRegistry `json:"registry"`
}

// GetEnterpriseTrustRegistryStatusRequest requests a trust-registry status
// summary.
type GetEnterpriseTrustRegistryStatusRequest struct{}

// EnterpriseControlLedgerTrustRegistryStatus summarizes the active trust
// registry without returning full signer material.
type EnterpriseControlLedgerTrustRegistryStatus struct {
	Configured              bool   `json:"configured"`
	Version                 string `json:"version,omitempty"`
	Source                  string `json:"source,omitempty"`
	UpdatedAt               string `json:"updated_at,omitempty"`
	RequiredAction          string `json:"required_action,omitempty"`
	RequiredJurisdiction    string `json:"required_jurisdiction,omitempty"`
	PolicySignerCount       int    `json:"policy_signer_count"`
	ActivePolicySignerCount int    `json:"active_policy_signer_count"`
	AllowedSponsorCount     int    `json:"allowed_sponsor_count"`
	ActiveSponsorCount      int    `json:"active_sponsor_count"`
}

// GetEnterpriseTrustRegistryStatusResponse returns the current trust-registry
// status.
type GetEnterpriseTrustRegistryStatusResponse struct {
	Status *EnterpriseControlLedgerTrustRegistryStatus `json:"status"`
}

// GetEnterpriseTrustRegistryHistoryRequest requests the governance history for
// trust-registry mutations.
type GetEnterpriseTrustRegistryHistoryRequest struct {
	Filter *Filter `json:"filter,omitempty"`
}

// GetEnterpriseTrustRegistryHistoryResponse contains the governance audit
// records that mutated the trust registry.
type GetEnterpriseTrustRegistryHistoryResponse struct {
	Records []keeper.AuditRecord `json:"records"`
	Total   int                  `json:"total"`
}

// GetTrustComplianceExportAnchorsRequest requests audit records for anchored
// trust-compliance export packages.
type GetTrustComplianceExportAnchorsRequest struct {
	Filter *Filter `json:"filter,omitempty"`
}

// GetTrustComplianceExportAnchorsResponse contains audit records for anchored
// trust-compliance export packages.
type GetTrustComplianceExportAnchorsResponse struct {
	Records []keeper.AuditRecord `json:"records"`
	Total   int                  `json:"total"`
}

// PutEnterpriseTrustRegistryRequest validates and persists a trust registry.
type PutEnterpriseTrustRegistryRequest struct {
	Registry *EnterpriseControlLedgerTrustRegistry `json:"registry"`
	Actor    string                                `json:"actor,omitempty"`
	Reason   string                                `json:"reason,omitempty"`
}

// PutEnterpriseTrustRegistryResponse returns the stored trust registry and its
// normalized status.
type PutEnterpriseTrustRegistryResponse struct {
	Registry *EnterpriseControlLedgerTrustRegistry       `json:"registry"`
	Status   *EnterpriseControlLedgerTrustRegistryStatus `json:"status,omitempty"`
}

// DeleteEnterpriseTrustRegistryRequest clears the active trust registry.
type DeleteEnterpriseTrustRegistryRequest struct {
	Actor  string `json:"actor,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// DeleteEnterpriseTrustRegistryResponse reports the outcome of a trust-registry
// clear operation.
type DeleteEnterpriseTrustRegistryResponse struct {
	Cleared bool                                        `json:"cleared"`
	Status  *EnterpriseControlLedgerTrustRegistryStatus `json:"status,omitempty"`
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
	studio                       *Studio
	custodyStore                 *CustodyStore
	bundles                      map[string]*Bundle // In-memory bundle store for demonstration.
	controlLedgerStore           evidence.ControlLedgerStore
	controlLedgerWriteAuthz      ControlLedgerWriteAuthorizer
	controlLedgerPackageSigner   PortableControlLedgerPackageSigner
	controlLedgerPackageAnchorer PortableControlLedgerPackageAnchorer
	trustRegistryService         EnterpriseTrustRegistryService
	trustRegistryAdminAuthz      RequestAuthorizer
}

// NewAuditServer creates a new HTTP API server backed by the given studio.
func NewAuditServer(studio *Studio, custodyStore *CustodyStore) *AuditServer {
	return NewAuditServerWithControlLedgerStore(studio, custodyStore, evidence.NewInMemoryControlLedgerStore())
}

// NewPersistentAuditServer creates a new HTTP API server backed by a
// filesystem control-ledger store rooted at the provided directory.
func NewPersistentAuditServer(studio *Studio, custodyStore *CustodyStore, controlLedgerDir string) (*AuditServer, error) {
	controlLedgerStore, err := evidence.NewFileControlLedgerStore(controlLedgerDir)
	if err != nil {
		return nil, err
	}
	return NewAuditServerWithControlLedgerStore(studio, custodyStore, controlLedgerStore), nil
}

// NewAuditServerWithControlLedgerStore creates a new HTTP API server with an
// explicit control-ledger persistence backend.
func NewAuditServerWithControlLedgerStore(studio *Studio, custodyStore *CustodyStore, controlLedgerStore evidence.ControlLedgerStore) *AuditServer {
	if controlLedgerStore == nil {
		controlLedgerStore = evidence.NewInMemoryControlLedgerStore()
	}
	return &AuditServer{
		studio:             studio,
		custodyStore:       custodyStore,
		bundles:            make(map[string]*Bundle),
		controlLedgerStore: controlLedgerStore,
	}
}

// SetControlLedgerWriteAuthorizer configures authorization for mutating
// control-ledger HTTP endpoints. Nil allows unauthenticated writes.
func (s *AuditServer) SetControlLedgerWriteAuthorizer(authorizer ControlLedgerWriteAuthorizer) {
	if s == nil {
		return
	}
	s.controlLedgerWriteAuthz = authorizer
}

// SetPortableControlLedgerPackageSigner configures runtime signing for
// portable control-ledger packages.
func (s *AuditServer) SetPortableControlLedgerPackageSigner(signer PortableControlLedgerPackageSigner) {
	if s == nil {
		return
	}
	s.controlLedgerPackageSigner = signer
}

// SetPortableControlLedgerPackageAnchorer configures runtime audit anchoring
// for portable control-ledger packages.
func (s *AuditServer) SetPortableControlLedgerPackageAnchorer(anchorer PortableControlLedgerPackageAnchorer) {
	if s == nil {
		return
	}
	s.controlLedgerPackageAnchorer = anchorer
}

// SetEnterpriseTrustRegistryService configures live trust-registry management
// for the audit API.
func (s *AuditServer) SetEnterpriseTrustRegistryService(service EnterpriseTrustRegistryService) {
	if s == nil {
		return
	}
	s.trustRegistryService = service
}

// SetTrustRegistryAdminAuthorizer configures authorization for trust-registry
// mutations.
func (s *AuditServer) SetTrustRegistryAdminAuthorizer(authorizer RequestAuthorizer) {
	if s == nil {
		return
	}
	s.trustRegistryAdminAuthz = authorizer
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
	mux.HandleFunc("/api/v1/audit/control-ledgers", s.handleControlLedgers)
	mux.HandleFunc("/api/v1/audit/control-ledger-packages/anchors", s.handleControlLedgerPackageAnchors)
	mux.HandleFunc("/api/v1/audit/control-ledgers/package/verify", s.handleVerifyPortableControlLedgerPackage)
	mux.HandleFunc("/api/v1/audit/control-ledgers/", s.handleControlLedger)
	mux.HandleFunc("/api/v1/audit/trust-registry", s.handleEnterpriseTrustRegistry)
	mux.HandleFunc("/api/v1/audit/trust-registry/history", s.handleEnterpriseTrustRegistryHistory)
	mux.HandleFunc("/api/v1/audit/trust-compliance-exports", s.handleTrustComplianceExportAnchors)
	mux.HandleFunc("/api/v1/audit/trust-registry/status", s.handleEnterpriseTrustRegistryStatus)
	mux.HandleFunc("/api/v1/audit/retention", s.handleGetRetention)
	mux.HandleFunc("/api/v1/audit/custody/", s.handleGetCustody)
}

// Handler builds a standalone HTTP handler with all audit routes registered.
func (s *AuditServer) Handler() http.Handler {
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	return mux
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

func (s *AuditServer) GetControlLedger(ctx context.Context, req *GetControlLedgerRequest) (*GetControlLedgerResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.LedgerID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	return &GetControlLedgerResponse{Ledger: ledger}, nil
}

func (s *AuditServer) ListControlLedgers(ctx context.Context, _ *ListControlLedgersRequest) (*ListControlLedgersResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledgers, err := s.controlLedgerStore.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	return &ListControlLedgersResponse{
		Ledgers: ledgers,
		Total:   len(ledgers),
	}, nil
}

func (s *AuditServer) PutControlLedger(ctx context.Context, req *PutControlLedgerRequest) (*PutControlLedgerResponse, error) {
	if req == nil || req.Ledger == nil {
		return nil, fmt.Errorf("audit/api: %w: control ledger is required", ErrInvalidInput)
	}
	if req.Ledger.Bundle == nil {
		return nil, fmt.Errorf("audit/api: %w: control ledger bundle is required", ErrInvalidInput)
	}
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	if err := s.controlLedgerStore.Save(ctx, req.Ledger); err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.Ledger.Bundle.ID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	return &PutControlLedgerResponse{Ledger: ledger}, nil
}

func (s *AuditServer) ExportControlLedger(ctx context.Context, req *ExportControlLedgerRequest) (*ExportControlLedgerResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.LedgerID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "json"
	}

	resp := &ExportControlLedgerResponse{
		LedgerID: req.LedgerID,
		Format:   format,
	}

	switch format {
	case "json":
		payload, err := evidenceexport.ExportControlLedgerJSON(ledger)
		if err != nil {
			return nil, err
		}
		resp.ContentType = "application/json"
		resp.Payload = payload
	case "csv":
		payload, err := evidenceexport.ExportControlLedgerCSV(ledger)
		if err != nil {
			return nil, err
		}
		resp.ContentType = "text/csv"
		resp.Payload = payload
	case "oscal":
		payload, err := evidenceexport.ExportControlLedgerOSCAL(ledger)
		if err != nil {
			return nil, err
		}
		resp.ContentType = "application/json"
		resp.Payload = payload
	default:
		return nil, fmt.Errorf("audit/api: unsupported control ledger export format %q", req.Format)
	}

	return resp, nil
}

func (s *AuditServer) GetPortableControlLedgerPackage(ctx context.Context, req *GetPortableControlLedgerPackageRequest) (*GetPortableControlLedgerPackageResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.LedgerID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	pkg, err := evidence.PackagePortableControlLedger(ledger, req.IncludeVerificationKeys)
	if err != nil {
		return nil, err
	}
	if req.Sign {
		if s.controlLedgerPackageSigner == nil {
			return nil, fmt.Errorf("audit/api: %w: portable control-ledger package signing is unavailable", ErrWriteDisabled)
		}
		if err := s.controlLedgerPackageSigner(ctx, pkg); err != nil {
			return nil, err
		}
	}
	if req.Anchor {
		if s.controlLedgerPackageAnchorer == nil {
			return nil, fmt.Errorf("audit/api: %w: portable control-ledger package anchoring is unavailable", ErrWriteDisabled)
		}
		if err := s.controlLedgerPackageAnchorer(ctx, pkg); err != nil {
			return nil, err
		}
	}
	return &GetPortableControlLedgerPackageResponse{
		LedgerID: req.LedgerID,
		Package:  pkg,
	}, nil
}

func (s *AuditServer) VerifyPortableControlLedgerPackage(ctx context.Context, req *VerifyPortableControlLedgerPackageRequest) (*VerifyPortableControlLedgerPackageResponse, error) {
	if req == nil || req.Package == nil {
		return nil, fmt.Errorf("audit/api: %w: portable control ledger package is required", ErrInvalidInput)
	}
	resp := &VerifyPortableControlLedgerPackageResponse{
		Valid:       false,
		PackageHash: req.Package.PackageHash,
	}
	if req.Package.Ledger != nil && req.Package.Ledger.Bundle != nil {
		resp.LedgerID = req.Package.Ledger.Bundle.ID
		resp.Summary = &req.Package.Ledger.Summary
	}
	if err := evidence.VerifyPortableControlLedgerPackage(req.Package); err != nil {
		resp.Error = err.Error()
	} else {
		resp.Valid = true
	}
	if s != nil && s.studio != nil && strings.TrimSpace(resp.PackageHash) != "" {
		rawAnchors, err := s.GetControlLedgerPackageAnchors(ctx, &GetControlLedgerPackageAnchorsRequest{
			Filter: NewFilter().WithKeywords(resp.PackageHash),
		})
		if err == nil {
			filter := &PortableControlLedgerPackageAnchorFilter{
				PackageHash: resp.PackageHash,
			}
			if strings.TrimSpace(resp.LedgerID) != "" {
				filter.LedgerID = resp.LedgerID
			}
			resp.AnchorMatches, resp.AnchorMatchCount = FilterPortableControlLedgerPackageAnchors(rawAnchors.Anchors, filter)
		}
	}
	return resp, nil
}

func (s *AuditServer) GetControlLedgerTrustCompliancePackages(ctx context.Context, req *GetControlLedgerTrustCompliancePackagesRequest) (*GetControlLedgerTrustCompliancePackagesResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.LedgerID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	cloned, err := ledger.Clone()
	if err != nil {
		return nil, err
	}
	packages := cloned.Bundle.TrustCompliancePackages
	return &GetControlLedgerTrustCompliancePackagesResponse{
		LedgerID: req.LedgerID,
		Packages: packages,
		Total:    len(packages),
	}, nil
}

func (s *AuditServer) GetControlLedgerApproverAttestations(ctx context.Context, req *GetControlLedgerApproverAttestationsRequest) (*GetControlLedgerApproverAttestationsResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.LedgerID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	cloned, err := ledger.Clone()
	if err != nil {
		return nil, err
	}
	attestations := cloned.Bundle.ApproverAttestations
	return &GetControlLedgerApproverAttestationsResponse{
		LedgerID:     req.LedgerID,
		Attestations: attestations,
		Total:        len(attestations),
	}, nil
}

func (s *AuditServer) GetControlLedgerValueSettlements(ctx context.Context, req *GetControlLedgerValueSettlementsRequest) (*GetControlLedgerValueSettlementsResponse, error) {
	if s.controlLedgerStore == nil {
		return nil, fmt.Errorf("audit/api: control ledger store not configured")
	}
	ledger, err := s.controlLedgerStore.Get(ctx, req.LedgerID)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w", err)
	}
	cloned, err := ledger.Clone()
	if err != nil {
		return nil, err
	}
	settlements := cloned.Bundle.ValueSettlements
	return &GetControlLedgerValueSettlementsResponse{
		LedgerID:    req.LedgerID,
		Settlements: settlements,
		Total:       len(settlements),
	}, nil
}

func (s *AuditServer) GetControlLedgerPackageAnchors(ctx context.Context, req *GetControlLedgerPackageAnchorsRequest) (*GetControlLedgerPackageAnchorsResponse, error) {
	if s == nil || s.studio == nil {
		return nil, fmt.Errorf("audit/api: audit studio not configured")
	}
	filter := buildControlLedgerPackageAnchorFilter(nil)
	if req != nil {
		filter = buildControlLedgerPackageAnchorFilter(req.Filter)
	}
	records, err := s.studio.Query(ctx, filter)
	if err != nil {
		return nil, err
	}
	return &GetControlLedgerPackageAnchorsResponse{
		Records: records,
		Anchors: SummarizePortableControlLedgerPackageAnchors(records),
		Total:   len(records),
	}, nil
}

func (s *AuditServer) GetEnterpriseTrustRegistry(ctx context.Context, req *GetEnterpriseTrustRegistryRequest) (*GetEnterpriseTrustRegistryResponse, error) {
	if s.trustRegistryService == nil {
		return nil, fmt.Errorf("audit/api: trust registry service not configured")
	}
	return s.trustRegistryService.GetEnterpriseTrustRegistry(ctx, req)
}

func (s *AuditServer) GetEnterpriseTrustRegistryStatus(ctx context.Context, req *GetEnterpriseTrustRegistryStatusRequest) (*GetEnterpriseTrustRegistryStatusResponse, error) {
	if s.trustRegistryService == nil {
		return nil, fmt.Errorf("audit/api: trust registry service not configured")
	}
	return s.trustRegistryService.GetEnterpriseTrustRegistryStatus(ctx, req)
}

func (s *AuditServer) GetEnterpriseTrustRegistryHistory(ctx context.Context, req *GetEnterpriseTrustRegistryHistoryRequest) (*GetEnterpriseTrustRegistryHistoryResponse, error) {
	if s == nil || s.studio == nil {
		return nil, fmt.Errorf("audit/api: audit studio not configured")
	}
	filter := buildEnterpriseTrustRegistryHistoryFilter(nil)
	if req != nil {
		filter = buildEnterpriseTrustRegistryHistoryFilter(req.Filter)
	}
	records, err := s.studio.Query(ctx, filter)
	if err != nil {
		return nil, err
	}
	return &GetEnterpriseTrustRegistryHistoryResponse{
		Records: records,
		Total:   len(records),
	}, nil
}

func (s *AuditServer) GetTrustComplianceExportAnchors(ctx context.Context, req *GetTrustComplianceExportAnchorsRequest) (*GetTrustComplianceExportAnchorsResponse, error) {
	if s == nil || s.studio == nil {
		return nil, fmt.Errorf("audit/api: audit studio not configured")
	}
	filter := buildTrustComplianceExportAnchorFilter(nil)
	if req != nil {
		filter = buildTrustComplianceExportAnchorFilter(req.Filter)
	}
	records, err := s.studio.Query(ctx, filter)
	if err != nil {
		return nil, err
	}
	return &GetTrustComplianceExportAnchorsResponse{
		Records: records,
		Total:   len(records),
	}, nil
}

func (s *AuditServer) PutEnterpriseTrustRegistry(ctx context.Context, req *PutEnterpriseTrustRegistryRequest) (*PutEnterpriseTrustRegistryResponse, error) {
	if s.trustRegistryService == nil {
		return nil, fmt.Errorf("audit/api: trust registry service not configured")
	}
	return s.trustRegistryService.PutEnterpriseTrustRegistry(ctx, req)
}

func (s *AuditServer) DeleteEnterpriseTrustRegistry(ctx context.Context, req *DeleteEnterpriseTrustRegistryRequest) (*DeleteEnterpriseTrustRegistryResponse, error) {
	if s.trustRegistryService == nil {
		return nil, fmt.Errorf("audit/api: trust registry service not configured")
	}
	return s.trustRegistryService.DeleteEnterpriseTrustRegistry(ctx, req)
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

// StoreControlLedger adds a control ledger to the configured store for testing
// and local bootstrapping flows.
func (s *AuditServer) StoreControlLedger(ledger *evidence.ControlLedger) error {
	if ledger == nil || ledger.Bundle == nil {
		return fmt.Errorf("audit/api: %w: control ledger is required", ErrInvalidInput)
	}
	if s.controlLedgerStore == nil {
		return fmt.Errorf("audit/api: control ledger store not configured")
	}
	return s.controlLedgerStore.Save(context.Background(), ledger)
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

func (s *AuditServer) handleControlLedgers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp, err := s.ListControlLedgers(r.Context(), &ListControlLedgersRequest{})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		req, err := decodePutControlLedgerRequest(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.authorizeControlLedgerWrite(r, req); err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		resp, err := s.PutControlLedger(r.Context(), req)
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *AuditServer) handleControlLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/control-ledgers/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "missing control ledger identifier")
		return
	}

	if strings.HasSuffix(path, "/export") {
		ledgerID := strings.TrimSuffix(path, "/export")
		if ledgerID == "" {
			writeError(w, http.StatusBadRequest, "missing control ledger identifier")
			return
		}

		resp, err := s.ExportControlLedger(r.Context(), &ExportControlLedgerRequest{
			LedgerID: ledgerID,
			Format:   r.URL.Query().Get("format"),
		})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}

		w.Header().Set("Content-Type", resp.ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.Payload)
		return
	}

	if strings.HasSuffix(path, "/package") {
		ledgerID := strings.TrimSuffix(path, "/package")
		if ledgerID == "" {
			writeError(w, http.StatusBadRequest, "missing control ledger identifier")
			return
		}
		includeVerificationKeys, err := parseBoolQueryValue(r, "include_verification_keys")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		signPackage, err := parseBoolQueryValue(r, "sign")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		anchorPackage, err := parseBoolQueryValue(r, "anchor")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if anchorPackage && !signPackage && s.controlLedgerPackageSigner != nil {
			signPackage = true
		}
		resp, err := s.GetPortableControlLedgerPackage(r.Context(), &GetPortableControlLedgerPackageRequest{
			LedgerID:                ledgerID,
			IncludeVerificationKeys: includeVerificationKeys,
			Sign:                    signPackage,
			Anchor:                  anchorPackage,
		})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp.Package)
		return
	}

	if strings.HasSuffix(path, "/trust-compliance-packages") {
		ledgerID := strings.TrimSuffix(path, "/trust-compliance-packages")
		if ledgerID == "" {
			writeError(w, http.StatusBadRequest, "missing control ledger identifier")
			return
		}
		resp, err := s.GetControlLedgerTrustCompliancePackages(r.Context(), &GetControlLedgerTrustCompliancePackagesRequest{LedgerID: ledgerID})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if strings.HasSuffix(path, "/approver-attestations") {
		ledgerID := strings.TrimSuffix(path, "/approver-attestations")
		if ledgerID == "" {
			writeError(w, http.StatusBadRequest, "missing control ledger identifier")
			return
		}
		resp, err := s.GetControlLedgerApproverAttestations(r.Context(), &GetControlLedgerApproverAttestationsRequest{LedgerID: ledgerID})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if strings.HasSuffix(path, "/value-settlements") {
		ledgerID := strings.TrimSuffix(path, "/value-settlements")
		if ledgerID == "" {
			writeError(w, http.StatusBadRequest, "missing control ledger identifier")
			return
		}
		resp, err := s.GetControlLedgerValueSettlements(r.Context(), &GetControlLedgerValueSettlementsRequest{LedgerID: ledgerID})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp, err := s.GetControlLedger(r.Context(), &GetControlLedgerRequest{LedgerID: path})
	if err != nil {
		writeError(w, controlLedgerHTTPStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleVerifyPortableControlLedgerPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	req, err := decodeVerifyPortableControlLedgerPackageRequest(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := s.VerifyPortableControlLedgerPackage(r.Context(), req)
	if err != nil {
		writeError(w, controlLedgerHTTPStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleControlLedgerPackageAnchors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.GetControlLedgerPackageAnchors(r.Context(), &GetControlLedgerPackageAnchorsRequest{
		Filter: parseFilterFromQuery(r),
	})
	if err != nil {
		writeError(w, controlLedgerHTTPStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleEnterpriseTrustRegistryStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.GetEnterpriseTrustRegistryStatus(r.Context(), &GetEnterpriseTrustRegistryStatusRequest{})
	if err != nil {
		writeError(w, controlLedgerHTTPStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleEnterpriseTrustRegistryHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.GetEnterpriseTrustRegistryHistory(r.Context(), &GetEnterpriseTrustRegistryHistoryRequest{
		Filter: parseFilterFromQuery(r),
	})
	if err != nil {
		writeError(w, controlLedgerHTTPStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleTrustComplianceExportAnchors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := s.GetTrustComplianceExportAnchors(r.Context(), &GetTrustComplianceExportAnchorsRequest{
		Filter: parseFilterFromQuery(r),
	})
	if err != nil {
		writeError(w, controlLedgerHTTPStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *AuditServer) handleEnterpriseTrustRegistry(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp, err := s.GetEnterpriseTrustRegistry(r.Context(), &GetEnterpriseTrustRegistryRequest{})
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		if err := s.authorizeTrustRegistryAdmin(r); err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		req, err := decodePutEnterpriseTrustRegistryRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		applyRegistryMutationHeaders(r, &req.Actor, &req.Reason)
		resp, err := s.PutEnterpriseTrustRegistry(r.Context(), req)
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodDelete:
		if err := s.authorizeTrustRegistryAdmin(r); err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		req, err := decodeDeleteEnterpriseTrustRegistryRequest(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		applyRegistryMutationHeaders(r, &req.Actor, &req.Reason)
		resp, err := s.DeleteEnterpriseTrustRegistry(r.Context(), req)
		if err != nil {
			writeError(w, controlLedgerHTTPStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
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

func controlLedgerHTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrWriteDisabled):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrTrustRegistryNotConfigured):
		return http.StatusNotFound
	case errors.Is(err, evidence.ErrInvalidControlLedgerID):
		return http.StatusBadRequest
	case errors.Is(err, evidence.ErrControlLedgerNotFound):
		return http.StatusNotFound
	}
	if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (s *AuditServer) authorizeControlLedgerWrite(r *http.Request, req *PutControlLedgerRequest) error {
	if s == nil || s.controlLedgerWriteAuthz == nil {
		return nil
	}
	return s.controlLedgerWriteAuthz.Authorize(r, req)
}

func (s *AuditServer) authorizeTrustRegistryAdmin(r *http.Request) error {
	if s == nil || s.trustRegistryAdminAuthz == nil {
		return nil
	}
	return s.trustRegistryAdminAuthz.AuthorizeRequest(r)
}

func decodePutControlLedgerRequest(body io.Reader) (*PutControlLedgerRequest, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("audit/api: read request body: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("audit/api: %w: request body is required", ErrInvalidInput)
	}

	var wrapped PutControlLedgerRequest
	if err := json.Unmarshal(payload, &wrapped); err == nil && wrapped.Ledger != nil {
		return &wrapped, nil
	}

	var ledger evidence.ControlLedger
	if err := json.Unmarshal(payload, &ledger); err == nil && ledger.Bundle != nil {
		return &PutControlLedgerRequest{Ledger: &ledger}, nil
	}

	return nil, fmt.Errorf("audit/api: %w: invalid control ledger payload", ErrInvalidInput)
}

func decodeVerifyPortableControlLedgerPackageRequest(body io.Reader) (*VerifyPortableControlLedgerPackageRequest, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("audit/api: %w: unable to read request body: %v", ErrInvalidInput, err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("audit/api: %w: request body is required", ErrInvalidInput)
	}

	var wrapped VerifyPortableControlLedgerPackageRequest
	if err := json.Unmarshal(payload, &wrapped); err == nil && wrapped.Package != nil {
		return &wrapped, nil
	}

	var pkg evidence.PortableControlLedgerPackage
	if err := json.Unmarshal(payload, &pkg); err == nil && pkg.Ledger != nil {
		return &VerifyPortableControlLedgerPackageRequest{Package: &pkg}, nil
	}

	return nil, fmt.Errorf("audit/api: %w: invalid portable control ledger package payload", ErrInvalidInput)
}

func parseBoolQueryValue(r *http.Request, key string) (bool, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q", key, raw)
	}
	return value, nil
}

func decodePutEnterpriseTrustRegistryRequest(r *http.Request) (*PutEnterpriseTrustRegistryRequest, error) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("audit/api: read request body: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("audit/api: %w: request body is required", ErrInvalidInput)
	}

	var wrapped PutEnterpriseTrustRegistryRequest
	if err := json.Unmarshal(payload, &wrapped); err == nil && wrapped.Registry != nil {
		return &wrapped, nil
	}

	var registry EnterpriseControlLedgerTrustRegistry
	if err := json.Unmarshal(payload, &registry); err == nil && len(registry.PolicySigners) > 0 {
		return &PutEnterpriseTrustRegistryRequest{Registry: &registry}, nil
	}

	return nil, fmt.Errorf("audit/api: %w: invalid trust registry payload", ErrInvalidInput)
}

func decodeDeleteEnterpriseTrustRegistryRequest(body io.Reader) (*DeleteEnterpriseTrustRegistryRequest, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("audit/api: read request body: %w", err)
	}
	if len(payload) == 0 {
		return &DeleteEnterpriseTrustRegistryRequest{}, nil
	}

	var req DeleteEnterpriseTrustRegistryRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("audit/api: %w: invalid trust registry delete payload", ErrInvalidInput)
	}
	return &req, nil
}

func applyRegistryMutationHeaders(r *http.Request, actor *string, reason *string) {
	if r == nil {
		return
	}
	if actor != nil && strings.TrimSpace(*actor) == "" {
		*actor = strings.TrimSpace(r.Header.Get("X-Aethelred-Actor"))
	}
	if reason != nil && strings.TrimSpace(*reason) == "" {
		*reason = strings.TrimSpace(r.Header.Get("X-Aethelred-Reason"))
	}
}

func buildEnterpriseTrustRegistryHistoryFilter(base *Filter) *Filter {
	filter := NewFilter().
		WithCategories(keeper.AuditCategoryGovernance).
		WithActions(enterpriseTrustRegistryGovernanceActions()...)
	if base == nil {
		return filter
	}

	filter.Severities = append([]keeper.AuditSeverity(nil), base.Severities...)
	filter.Actors = append([]string(nil), base.Actors...)
	filter.Keywords = append([]string(nil), base.Keywords...)
	filter.Limit = base.Limit
	filter.Offset = base.Offset

	if base.FromTime != nil {
		fromTime := *base.FromTime
		filter.FromTime = &fromTime
	}
	if base.ToTime != nil {
		toTime := *base.ToTime
		filter.ToTime = &toTime
	}
	if base.FromBlock != nil {
		fromBlock := *base.FromBlock
		filter.FromBlock = &fromBlock
	}
	if base.ToBlock != nil {
		toBlock := *base.ToBlock
		filter.ToBlock = &toBlock
	}
	if base.FromSequence != nil {
		fromSequence := *base.FromSequence
		filter.FromSequence = &fromSequence
	}
	if base.ToSequence != nil {
		toSequence := *base.ToSequence
		filter.ToSequence = &toSequence
	}

	return filter
}

func buildTrustComplianceExportAnchorFilter(base *Filter) *Filter {
	filter := NewFilter().
		WithCategories(keeper.AuditCategoryGovernance).
		WithActions("trust_compliance_export_anchored")
	if base == nil {
		return filter
	}

	filter.Severities = append([]keeper.AuditSeverity(nil), base.Severities...)
	filter.Actors = append([]string(nil), base.Actors...)
	filter.Keywords = append([]string(nil), base.Keywords...)
	filter.Limit = base.Limit
	filter.Offset = base.Offset

	if base.FromTime != nil {
		fromTime := *base.FromTime
		filter.FromTime = &fromTime
	}
	if base.ToTime != nil {
		toTime := *base.ToTime
		filter.ToTime = &toTime
	}
	if base.FromBlock != nil {
		fromBlock := *base.FromBlock
		filter.FromBlock = &fromBlock
	}
	if base.ToBlock != nil {
		toBlock := *base.ToBlock
		filter.ToBlock = &toBlock
	}
	if base.FromSequence != nil {
		fromSequence := *base.FromSequence
		filter.FromSequence = &fromSequence
	}
	if base.ToSequence != nil {
		toSequence := *base.ToSequence
		filter.ToSequence = &toSequence
	}

	return filter
}

func buildControlLedgerPackageAnchorFilter(base *Filter) *Filter {
	filter := NewFilter().
		WithCategories(keeper.AuditCategoryGovernance).
		WithActions("control_ledger_package_anchored")
	if base == nil {
		return filter
	}

	filter.Severities = append([]keeper.AuditSeverity(nil), base.Severities...)
	filter.Actors = append([]string(nil), base.Actors...)
	filter.Keywords = append([]string(nil), base.Keywords...)
	filter.Limit = base.Limit
	filter.Offset = base.Offset

	if base.FromTime != nil {
		fromTime := *base.FromTime
		filter.FromTime = &fromTime
	}
	if base.ToTime != nil {
		toTime := *base.ToTime
		filter.ToTime = &toTime
	}
	if base.FromBlock != nil {
		fromBlock := *base.FromBlock
		filter.FromBlock = &fromBlock
	}
	if base.ToBlock != nil {
		toBlock := *base.ToBlock
		filter.ToBlock = &toBlock
	}
	if base.FromSequence != nil {
		fromSequence := *base.FromSequence
		filter.FromSequence = &fromSequence
	}
	if base.ToSequence != nil {
		toSequence := *base.ToSequence
		filter.ToSequence = &toSequence
	}

	return filter
}

// SummarizePortableControlLedgerPackageAnchors normalizes governance audit
// records for portable control-ledger package anchors into operator-friendly
// summaries.
func SummarizePortableControlLedgerPackageAnchors(records []keeper.AuditRecord) []PortableControlLedgerPackageAnchorRecord {
	summaries := make([]PortableControlLedgerPackageAnchorRecord, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, summarizePortableControlLedgerPackageAnchor(record))
	}
	return summaries
}

// FilterPortableControlLedgerPackageAnchors applies exact-match package filters
// to normalized anchor summaries after governance-history filtering.
func FilterPortableControlLedgerPackageAnchors(anchors []PortableControlLedgerPackageAnchorRecord, filter *PortableControlLedgerPackageAnchorFilter) ([]PortableControlLedgerPackageAnchorRecord, int) {
	if filter == nil {
		filter = &PortableControlLedgerPackageAnchorFilter{}
	}

	filtered := make([]PortableControlLedgerPackageAnchorRecord, 0, len(anchors))
	for _, anchor := range anchors {
		summary := anchor.Summary
		if summary == nil {
			if strings.TrimSpace(filter.PackageHash) != "" || strings.TrimSpace(filter.LedgerID) != "" || strings.TrimSpace(filter.Signer) != "" || filter.Signed != nil {
				continue
			}
		} else {
			if filter.PackageHash != "" && summary.PackageHash != filter.PackageHash {
				continue
			}
			if filter.LedgerID != "" && summary.LedgerID != filter.LedgerID {
				continue
			}
			if filter.Signer != "" && summary.Signer != filter.Signer {
				continue
			}
			if filter.Signed != nil && summary.Signed != *filter.Signed {
				continue
			}
		}
		filtered = append(filtered, anchor)
	}

	total := len(filtered)
	offset := clampNonNegative(filter.Offset)
	if offset >= len(filtered) {
		return []PortableControlLedgerPackageAnchorRecord{}, total
	}
	filtered = filtered[offset:]
	if filter.Limit > 0 && filter.Limit < len(filtered) {
		filtered = filtered[:filter.Limit]
	}
	return filtered, total
}

func summarizePortableControlLedgerPackageAnchor(record keeper.AuditRecord) PortableControlLedgerPackageAnchorRecord {
	summary := &PortableControlLedgerPackageAnchorSummary{
		PackageHash:                  strings.TrimSpace(record.Details["package_hash"]),
		LedgerID:                     strings.TrimSpace(record.Details["ledger_id"]),
		FormatVersion:                strings.TrimSpace(record.Details["format_version"]),
		PackagedAt:                   strings.TrimSpace(record.Details["packaged_at"]),
		Framework:                    strings.TrimSpace(record.Details["framework"]),
		BundleContentHash:            strings.TrimSpace(record.Details["bundle_content_hash"]),
		ControlsTotal:                parseAnchorInt(record.Details["controls_total"]),
		TrustCompliancePackagesTotal: parseAnchorInt(record.Details["trust_compliance_packages_total"]),
		VerificationKeyCount:         parseAnchorInt(record.Details["verification_key_count"]),
		TrustAnchorCount:             parseAnchorInt(record.Details["trust_anchor_count"]),
		SchemaDefinition:             strings.TrimSpace(record.Details["schema_definition"]),
		Signed:                       parseAnchorBool(record.Details["signed"]),
		Signer:                       strings.TrimSpace(record.Details["signer"]),
		SignatureKeyID:               strings.TrimSpace(record.Details["signature_key_id"]),
		SignatureAlgorithm:           strings.TrimSpace(record.Details["signature_algorithm"]),
		SignedAt:                     strings.TrimSpace(record.Details["signed_at"]),
	}
	return PortableControlLedgerPackageAnchorRecord{
		Record:  record,
		Summary: summary,
	}
}

func parseAnchorInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return value
}

func parseAnchorBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func clampNonNegative(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

// NewEd25519PortableControlLedgerPackageSigner builds a reusable signer for
// portable control-ledger packages.
func NewEd25519PortableControlLedgerPackageSigner(privateKey ed25519.PrivateKey, signer string) PortableControlLedgerPackageSigner {
	keyCopy := ed25519.PrivateKey(make([]byte, len(privateKey)))
	copy(keyCopy, privateKey)
	signerID := strings.TrimSpace(signer)
	return func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
		if pkg == nil {
			return fmt.Errorf("audit/api: %w: portable control-ledger package is required", ErrInvalidInput)
		}
		return pkg.SignEd25519(keyCopy, signerID)
	}
}

func enterpriseTrustRegistryGovernanceActions() []string {
	return []string{
		"enterprise_audit_trust_registry_updated",
		"enterprise_audit_trust_registry_cleared",
	}
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
