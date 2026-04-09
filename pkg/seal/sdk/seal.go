// Package sdk provides a high-level SDK for creating, verifying, and managing
// Digital Seals on the Aethelred blockchain. It wraps the protocol-level seal
// module (x/seal) into a product-ready API for enterprise integrations.
package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config holds configuration for the SealSDK.
type Config struct {
	// NetworkEndpoint is the gRPC or REST endpoint for the Aethelred node.
	NetworkEndpoint string

	// ChainID is the chain identifier (e.g., "aethelred-1").
	ChainID string

	// SignerAddress is the bech32-encoded address used to sign transactions.
	SignerAddress string

	// DefaultRegulatoryInfo is applied to all seal requests that omit it.
	DefaultRegulatoryInfo *RegulatoryConfig

	// Timeout is the maximum duration for network operations.
	Timeout time.Duration

	// MaxRetries is the number of retries for transient network failures.
	MaxRetries int

	// Logger provides structured logging. Defaults to no-op.
	Logger Logger

	// Metrics provides metrics collection hooks. Defaults to no-op.
	Metrics MetricsCollector
}

// RegulatoryConfig holds default regulatory settings.
type RegulatoryConfig struct {
	DataClassification       string
	ComplianceFrameworks     []string
	JurisdictionRestrictions []string
	RetentionPeriodDays      int64
	AuditRequired            bool
}

// SealSDK is the primary entry point for seal operations. It provides
// high-level methods for creating, querying, verifying, and managing
// Digital Seals.
type SealSDK struct {
	config  Config
	keeper  SealKeeper
	chainID string
	logger  Logger
	metrics MetricsCollector
}

// SealKeeper defines the interface for interacting with the on-chain seal store.
// This allows the SDK to operate against both a real keeper and a mock for testing.
type SealKeeper interface {
	CreateSeal(ctx context.Context, seal *types.DigitalSeal) error
	GetSeal(ctx context.Context, id string) (*types.DigitalSeal, error)
	SetSeal(ctx context.Context, seal *types.DigitalSeal) error
	RevokeSeal(ctx context.Context, id string, reason string) error
	VerifySeal(ctx context.Context, id string) (bool, error)
	ListSeals(ctx context.Context, limit int, offset int) ([]*types.DigitalSeal, error)
	ListSealsByModel(ctx context.Context, modelHash []byte) ([]*types.DigitalSeal, error)
	ListSealsByRequester(ctx context.Context, requester string) ([]*types.DigitalSeal, error)
}

// SealRequest contains the parameters for creating a new Digital Seal.
type SealRequest struct {
	// ModelHash is the SHA-256 hash of the AI model weights (32 bytes).
	ModelHash []byte

	// InputHash is the SHA-256 hash of the computation input (32 bytes).
	InputHash []byte

	// OutputHash is the SHA-256 hash of the computation output (32 bytes).
	OutputHash []byte

	// Purpose describes the use case (e.g., "credit_scoring", "fraud_detection").
	Purpose string

	// RegulatoryInfo provides compliance metadata. If nil, defaults from Config are used.
	RegulatoryInfo *RegulatoryConfig

	// Metadata holds optional key-value pairs attached to the seal.
	Metadata map[string]string

	// TEEAttestations are hardware attestations to include.
	TEEAttestations []*types.TEEAttestation

	// ZKProof is an optional zero-knowledge proof of the computation.
	ZKProof *types.ZKMLProof
}

// SealResponse is returned after a successful seal creation or query.
type SealResponse struct {
	// SealID is the unique identifier of the seal.
	SealID string

	// Status is the current seal status.
	Status types.SealStatus

	// Attestations are the TEE attestations attached to the seal.
	Attestations []*types.TEEAttestation

	// Proof is the zkML proof, if present.
	Proof *types.ZKMLProof

	// Timestamp is when the seal was created.
	Timestamp time.Time

	// RegulatoryInfo is the compliance metadata.
	RegulatoryInfo *types.RegulatoryInfo

	// BlockHeight is the chain height at which the seal was anchored.
	BlockHeight int64

	// RequestedBy is the address that requested the seal.
	RequestedBy string

	// Purpose describes the use case.
	Purpose string

	// ValidatorSet lists the validators who attested.
	ValidatorSet []string
}

// SealFilter specifies criteria for listing seals.
type SealFilter struct {
	// ModelHash filters by model commitment. Nil means no filter.
	ModelHash []byte

	// Requester filters by the address that requested the seal.
	Requester string

	// Status filters by seal status. Zero value means no filter.
	Status types.SealStatus

	// FromTime filters seals created at or after this time.
	FromTime *time.Time

	// ToTime filters seals created at or before this time.
	ToTime *time.Time

	// Framework filters by a specific compliance framework (e.g., "GDPR").
	Framework string

	// Jurisdiction filters by jurisdiction restriction.
	Jurisdiction string

	// Limit is the maximum number of results. Defaults to 100.
	Limit int

	// Offset for pagination.
	Offset int
}

// NewSealSDK creates a new SealSDK with the given configuration and keeper.
func NewSealSDK(config Config, keeper SealKeeper) (*SealSDK, error) {
	if keeper == nil {
		return nil, fmt.Errorf("NewSealSDK: %w: seal keeper is required", ErrInvalidInput)
	}
	if config.ChainID == "" {
		config.ChainID = "aethelred-1"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	logger := config.Logger
	if logger == nil {
		logger = NoopLogger{}
	}
	metrics := config.Metrics
	if metrics == nil {
		metrics = NoopMetrics{}
	}

	return &SealSDK{
		config:  config,
		keeper:  keeper,
		chainID: config.ChainID,
		logger:  logger,
		metrics: metrics,
	}, nil
}

// CreateSeal creates a new Digital Seal from the given request. It validates
// inputs, applies default regulatory info when not provided, constructs the
// on-chain seal object, and submits it to the keeper.
func (s *SealSDK) CreateSeal(ctx context.Context, req SealRequest) (*SealResponse, error) {
	if ctx == nil {
		return nil, fmt.Errorf("SealSDK.CreateSeal: %w: context is nil", ErrInvalidInput)
	}
	if err := validateSealRequest(req); err != nil {
		return nil, fmt.Errorf("SealSDK.CreateSeal: %w: %v", ErrInvalidInput, err)
	}

	regInfo := buildRegulatoryInfo(req.RegulatoryInfo, s.config.DefaultRegulatoryInfo)

	seal := types.NewDigitalSeal(
		req.ModelHash,
		req.InputHash,
		req.OutputHash,
		0, // block height set by keeper
		s.config.SignerAddress,
		req.Purpose,
	)
	seal.RegulatoryInfo = regInfo

	// Attach TEE attestations
	for _, att := range req.TEEAttestations {
		seal.AddAttestation(att)
	}

	// Attach ZK proof
	if req.ZKProof != nil {
		seal.SetZKProof(req.ZKProof)
	}

	// Activate if verification evidence is present
	if seal.IsVerified() {
		seal.Activate()
	}

	if err := s.keeper.CreateSeal(ctx, seal); err != nil {
		return nil, fmt.Errorf("SealSDK.CreateSeal: %w", err)
	}

	return sealToResponse(seal), nil
}

// VerifySeal checks the integrity and verification status of a seal.
func (s *SealSDK) VerifySeal(ctx context.Context, sealID string) (*SealResponse, error) {
	if sealID == "" {
		return nil, fmt.Errorf("SealSDK.VerifySeal: %w: seal ID is required", ErrInvalidInput)
	}

	valid, err := s.keeper.VerifySeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("SealSDK.VerifySeal: %w: %v", ErrVerificationFailed, err)
	}

	seal, err := s.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("SealSDK.VerifySeal: %w: %v", ErrSealNotFound, err)
	}

	resp := sealToResponse(seal)
	if !valid {
		resp.Status = types.SealStatusPending
	}

	return resp, nil
}

// GetSeal retrieves a seal by its unique identifier.
func (s *SealSDK) GetSeal(ctx context.Context, sealID string) (*SealResponse, error) {
	if sealID == "" {
		return nil, fmt.Errorf("SealSDK.GetSeal: %w: seal ID is required", ErrInvalidInput)
	}

	seal, err := s.keeper.GetSeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("SealSDK.GetSeal: %w: %v", ErrSealNotFound, err)
	}

	return sealToResponse(seal), nil
}

// ListSeals returns seals matching the given filter criteria.
func (s *SealSDK) ListSeals(ctx context.Context, filter SealFilter) ([]*SealResponse, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var seals []*types.DigitalSeal
	var err error

	switch {
	case len(filter.ModelHash) > 0:
		seals, err = s.keeper.ListSealsByModel(ctx, filter.ModelHash)
	case filter.Requester != "":
		seals, err = s.keeper.ListSealsByRequester(ctx, filter.Requester)
	default:
		seals, err = s.keeper.ListSeals(ctx, limit, filter.Offset)
	}
	if err != nil {
		return nil, fmt.Errorf("SealSDK.ListSeals: %w", err)
	}

	var results []*SealResponse
	for _, seal := range seals {
		if !matchesFilter(seal, filter) {
			continue
		}
		results = append(results, sealToResponse(seal))
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

// RevokeSeal revokes a seal with the given reason, creating an audit trail entry.
func (s *SealSDK) RevokeSeal(ctx context.Context, sealID string, reason string) error {
	if sealID == "" {
		return fmt.Errorf("SealSDK.RevokeSeal: %w: seal ID is required", ErrInvalidInput)
	}
	if reason == "" {
		return fmt.Errorf("SealSDK.RevokeSeal: %w: revocation reason is required", ErrInvalidInput)
	}

	if err := s.keeper.RevokeSeal(ctx, sealID, reason); err != nil {
		return fmt.Errorf("SealSDK.RevokeSeal: %w", err)
	}
	return nil
}

// ComputeHash computes the SHA-256 hash of the given data, returning a 32-byte slice.
// This is a convenience function for building seal requests.
func ComputeHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ComputeHashHex computes the SHA-256 hash and returns it as a hex string.
func ComputeHashHex(data []byte) string {
	return hex.EncodeToString(ComputeHash(data))
}

// --- internal helpers ---

func validateSealRequest(req SealRequest) error {
	if len(req.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes (SHA-256), got %d", len(req.ModelHash))
	}
	if len(req.InputHash) != 32 {
		return fmt.Errorf("input hash must be 32 bytes (SHA-256), got %d", len(req.InputHash))
	}
	if len(req.OutputHash) != 32 {
		return fmt.Errorf("output hash must be 32 bytes (SHA-256), got %d", len(req.OutputHash))
	}
	if req.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	return nil
}

func buildRegulatoryInfo(reqInfo, defaultInfo *RegulatoryConfig) *types.RegulatoryInfo {
	cfg := defaultInfo
	if reqInfo != nil {
		cfg = reqInfo
	}
	if cfg == nil {
		return nil
	}

	info := &types.RegulatoryInfo{
		DataClassification:       cfg.DataClassification,
		ComplianceFrameworks:     cfg.ComplianceFrameworks,
		JurisdictionRestrictions: cfg.JurisdictionRestrictions,
		AuditRequired:            cfg.AuditRequired,
	}
	if cfg.RetentionPeriodDays > 0 {
		info.RetentionPeriod = durationpb.New(time.Duration(cfg.RetentionPeriodDays) * 24 * time.Hour)
	}
	return info
}

func sealToResponse(seal *types.DigitalSeal) *SealResponse {
	resp := &SealResponse{
		SealID:         seal.Id,
		Status:         seal.Status,
		Attestations:   seal.TeeAttestations,
		Proof:          seal.ZkProof,
		RegulatoryInfo: seal.RegulatoryInfo,
		BlockHeight:    seal.BlockHeight,
		RequestedBy:    seal.RequestedBy,
		Purpose:        seal.Purpose,
		ValidatorSet:   seal.ValidatorSet,
	}
	if seal.Timestamp != nil {
		resp.Timestamp = seal.Timestamp.AsTime()
	}
	return resp
}

func matchesFilter(seal *types.DigitalSeal, filter SealFilter) bool {
	if filter.Status != types.SealStatus_SEAL_STATUS_UNSPECIFIED && seal.Status != filter.Status {
		return false
	}

	if filter.FromTime != nil && seal.Timestamp != nil {
		if seal.Timestamp.AsTime().Before(*filter.FromTime) {
			return false
		}
	}
	if filter.ToTime != nil && seal.Timestamp != nil {
		if seal.Timestamp.AsTime().After(*filter.ToTime) {
			return false
		}
	}

	if filter.Framework != "" && seal.RegulatoryInfo != nil {
		found := false
		for _, fw := range seal.RegulatoryInfo.ComplianceFrameworks {
			if strings.EqualFold(fw, filter.Framework) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if filter.Jurisdiction != "" && seal.RegulatoryInfo != nil {
		found := false
		for _, jr := range seal.RegulatoryInfo.JurisdictionRestrictions {
			if strings.EqualFold(jr, filter.Jurisdiction) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// sealTimestamp extracts the time from a seal's protobuf timestamp.
// Returns zero time if the timestamp is nil.
func sealTimestamp(seal *types.DigitalSeal) time.Time {
	if seal.Timestamp != nil {
		return seal.Timestamp.AsTime()
	}
	return time.Time{}
}

// newTimestamp creates a protobuf timestamp from the current time.
func newTimestamp() *timestamppb.Timestamp {
	return timestamppb.Now()
}
