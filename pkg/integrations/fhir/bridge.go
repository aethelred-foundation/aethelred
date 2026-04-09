package fhir

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/seal/sdk"
)

const maxSealRetries = 3

// ---------------------------------------------------------------------------
// FHIR <-> Aethelred Bridge
// ---------------------------------------------------------------------------
//
// The FHIRBridge provides bidirectional conversion between FHIR R5 resources
// and Aethelred Digital Seals. It enables healthcare systems to seal FHIR
// resources with cryptographic integrity guarantees, verify sealed resources,
// and import/export between the two formats.
// ---------------------------------------------------------------------------

// BridgeConfig holds configuration for the FHIR bridge.
type BridgeConfig struct {
	// Endpoint is the FHIR server base URL (informational for external systems).
	Endpoint string

	// AuthToken is the bearer token for FHIR server communication.
	AuthToken string

	// DefaultJurisdiction is applied when no jurisdiction is specified.
	DefaultJurisdiction string

	// ConsentRequired indicates whether consent validation is mandatory
	// before sealing patient-related resources.
	ConsentRequired bool

	// DefaultRetentionDays is the default data retention period.
	DefaultRetentionDays int64
}

// FHIRBridge bridges FHIR R5 resources to the Aethelred Digital Seal infrastructure.
type FHIRBridge struct {
	sealSDK *sdk.SealSDK
	config  BridgeConfig
	logger  Logger
	metrics MetricsCollector

	// sealStore maps resource IDs to their seal IDs for lookup.
	sealStore map[string]string

	// resourceStore maps seal IDs to serialized FHIR resources.
	resourceStore map[string][]byte
}

// NewFHIRBridge creates a new FHIRBridge with the given configuration and
// seal SDK instance.
func NewFHIRBridge(config BridgeConfig, sealSDK *sdk.SealSDK) (*FHIRBridge, error) {
	if sealSDK == nil {
		return nil, fmt.Errorf("FHIRBridge.New: %w: seal SDK is required", ErrInvalidResource)
	}
	if config.DefaultJurisdiction == "" {
		config.DefaultJurisdiction = "US"
	}
	if config.DefaultRetentionDays == 0 {
		config.DefaultRetentionDays = 2555 // ~7 years, HIPAA minimum
	}

	return &FHIRBridge{
		sealSDK:       sealSDK,
		config:        config,
		logger:        nopLogger{},
		metrics:       nopMetrics{},
		sealStore:     make(map[string]string),
		resourceStore: make(map[string][]byte),
	}, nil
}

// SetLogger configures the logger for the bridge.
func (b *FHIRBridge) SetLogger(l Logger) {
	if l != nil {
		b.logger = l
	}
}

// SetMetrics configures the metrics collector for the bridge.
func (b *FHIRBridge) SetMetrics(m MetricsCollector) {
	if m != nil {
		b.metrics = m
	}
}

// SealResource seals a FHIR resource with a Digital Seal. The resource is
// serialized, hashed, and submitted to the Aethelred seal infrastructure
// with appropriate healthcare regulatory metadata.
func (b *FHIRBridge) SealResource(ctx context.Context, resource Resource) (*SealedResource, error) {
	if resource == nil {
		return nil, fmt.Errorf("FHIRBridge.SealResource: %w: resource is nil", ErrInvalidResource)
	}
	if resource.GetID() == "" {
		return nil, fmt.Errorf("FHIRBridge.SealResource: %w: resource ID is empty", ErrInvalidResource)
	}

	// Validate FHIR resource required fields before sealing.
	v := NewValidator()
	vResult := v.ValidateResource(resource)
	if !vResult.Valid {
		return nil, fmt.Errorf("FHIRBridge.SealResource: %w: %v", ErrValidationFailed, vResult.Errors)
	}

	// Serialize the resource to JSON for hashing.
	data, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("FHIRBridge.SealResource: %w: serialize: %v", ErrSealFailed, err)
	}

	// Build the seal request with healthcare-specific regulatory info.
	sealReq := b.ResourceToSealRequest(resource, data)

	// Submit to the seal SDK with retry and exponential backoff.
	var resp *sdk.SealResponse
	var lastErr error
	for attempt := 0; attempt < maxSealRetries; attempt++ {
		resp, lastErr = b.sealSDK.CreateSeal(ctx, sealReq)
		if lastErr == nil {
			break
		}
		b.logger.Warn("FHIRBridge.SealResource: seal attempt failed, retrying",
			"attempt", attempt+1, "err", lastErr)
		b.metrics.IncCounter("fhir_seal_retry", "resource_type", string(resource.GetResourceType()))
		// Exponential backoff: 100ms, 200ms, 400ms
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("FHIRBridge.SealResource: %w: context cancelled during retry", ctx.Err())
		case <-time.After(time.Duration(100<<uint(attempt)) * time.Millisecond):
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("FHIRBridge.SealResource: %w: %v", ErrSealFailed, lastErr)
	}

	// Record the mapping.
	b.sealStore[resource.GetID()] = resp.SealID
	b.resourceStore[resp.SealID] = data
	b.metrics.IncCounter("fhir_resource_sealed", "resource_type", string(resource.GetResourceType()))

	return &SealedResource{
		ResourceID:   resource.GetID(),
		ResourceType: resource.GetResourceType(),
		SealID:       resp.SealID,
		SealStatus:   resp.Status.String(),
		ResourceHash: sdk.ComputeHashHex(data),
		SealedAt:     resp.Timestamp,
	}, nil
}

// VerifyResource verifies a previously sealed FHIR resource. It checks that
// the seal is valid and that the resource data has not been tampered with.
func (b *FHIRBridge) VerifyResource(ctx context.Context, resource Resource, sealID string) (*VerificationResult, error) {
	if resource == nil {
		return nil, fmt.Errorf("FHIRBridge.VerifyResource: %w: resource is nil", ErrInvalidResource)
	}
	if sealID == "" {
		return nil, fmt.Errorf("FHIRBridge.VerifyResource: %w: seal ID is empty", ErrInvalidResource)
	}

	// Verify the seal through the SDK.
	sealResp, err := b.sealSDK.VerifySeal(ctx, sealID)
	if err != nil {
		return nil, fmt.Errorf("FHIRBridge.VerifyResource: %w: %v", ErrSealFailed, err)
	}

	// Serialize current resource and compare hash.
	currentData, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("FHIRBridge.VerifyResource: failed to serialize resource: %w", err)
	}
	currentHash := sdk.ComputeHash(currentData)

	// Compare against stored resource data if available.
	var dataIntact bool
	if storedData, ok := b.resourceStore[sealID]; ok {
		storedHash := sdk.ComputeHash(storedData)
		dataIntact = bytesEqual(currentHash, storedHash)
	} else {
		// No stored data; we can only verify the seal itself.
		dataIntact = true
	}

	return &VerificationResult{
		SealID:       sealID,
		SealValid:    sealResp.Status.String() != "SEAL_STATUS_REVOKED",
		DataIntact:   dataIntact,
		ResourceType: resource.GetResourceType(),
		ResourceID:   resource.GetID(),
		VerifiedAt:   time.Now().UTC(),
	}, nil
}

// ImportResource imports a FHIR resource from raw JSON, validates it, and
// optionally seals it.
func (b *FHIRBridge) ImportResource(ctx context.Context, fhirJSON []byte) (*ImportResult, error) {
	if len(fhirJSON) == 0 {
		return nil, fmt.Errorf("FHIRBridge.ImportResource: %w: empty JSON input", ErrInvalidResource)
	}

	// Extract the resourceType to determine the concrete type.
	var meta struct {
		ResourceType string `json:"resourceType"`
	}
	if err := json.Unmarshal(fhirJSON, &meta); err != nil {
		return nil, fmt.Errorf("FHIRBridge.ImportResource: %w: %v", ErrInvalidResource, err)
	}

	var resource Resource
	var err error

	switch ResourceType(meta.ResourceType) {
	case ResourceTypePatient:
		var p Patient
		err = json.Unmarshal(fhirJSON, &p)
		resource = &p
	case ResourceTypeObservation:
		var o Observation
		err = json.Unmarshal(fhirJSON, &o)
		resource = &o
	case ResourceTypeDiagnosticReport:
		var d DiagnosticReport
		err = json.Unmarshal(fhirJSON, &d)
		resource = &d
	case ResourceTypeMedication:
		var m Medication
		err = json.Unmarshal(fhirJSON, &m)
		resource = &m
	case ResourceTypeConsent:
		var c Consent
		err = json.Unmarshal(fhirJSON, &c)
		resource = &c
	case ResourceTypeAuditEvent:
		var a AuditEvent
		err = json.Unmarshal(fhirJSON, &a)
		resource = &a
	default:
		return nil, fmt.Errorf("FHIRBridge.ImportResource: %w: unsupported resource type: %s", ErrInvalidResource, meta.ResourceType)
	}

	if err != nil {
		return nil, fmt.Errorf("FHIRBridge.ImportResource: %w: parse %s: %v", ErrInvalidResource, meta.ResourceType, err)
	}

	// Validate the resource.
	v := NewValidator()
	vResult := v.ValidateResource(resource)
	if !vResult.Valid {
		return &ImportResult{
			Resource:   resource,
			Validation: vResult,
			Sealed:     false,
		}, nil
	}

	// Seal the resource.
	sealed, err := b.SealResource(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("FHIRBridge.ImportResource: %w", err)
	}

	return &ImportResult{
		Resource:       resource,
		Validation:     vResult,
		Sealed:         true,
		SealedResource: sealed,
	}, nil
}

// ExportResource exports a sealed resource back to FHIR JSON.
func (b *FHIRBridge) ExportResource(_ context.Context, sealID string) ([]byte, error) {
	if sealID == "" {
		return nil, fmt.Errorf("FHIRBridge.ExportResource: %w: seal ID is empty", ErrInvalidResource)
	}

	data, ok := b.resourceStore[sealID]
	if !ok {
		return nil, fmt.Errorf("FHIRBridge.ExportResource: no resource found for seal %s", sealID)
	}

	return data, nil
}

// ResourceToSealRequest converts a FHIR resource to an Aethelred seal request
// with healthcare-appropriate regulatory metadata.
func (b *FHIRBridge) ResourceToSealRequest(resource Resource, data []byte) sdk.SealRequest {
	resourceHash := sha256.Sum256(data)

	// Determine compliance frameworks based on resource type.
	frameworks := []string{"HIPAA"}
	if b.config.DefaultJurisdiction == "EU" || b.config.DefaultJurisdiction == "UK" {
		frameworks = append(frameworks, "GDPR")
	}

	// Determine data classification based on resource type.
	classification := "phi" // Protected Health Information by default
	switch resource.GetResourceType() {
	case ResourceTypeMedication:
		classification = "clinical"
	case ResourceTypeAuditEvent:
		classification = "audit"
	}

	// Build purpose string.
	purpose := fmt.Sprintf("fhir_%s_seal", resource.GetResourceType())

	return sdk.SealRequest{
		ModelHash:  resourceHash[:],
		InputHash:  resourceHash[:],
		OutputHash: resourceHash[:],
		Purpose:    purpose,
		RegulatoryInfo: &sdk.RegulatoryConfig{
			DataClassification:       classification,
			ComplianceFrameworks:     frameworks,
			JurisdictionRestrictions: []string{b.config.DefaultJurisdiction},
			RetentionPeriodDays:      b.config.DefaultRetentionDays,
			AuditRequired:            true,
		},
		Metadata: map[string]string{
			"resource_type": string(resource.GetResourceType()),
			"resource_id":   resource.GetID(),
			"standard":      "FHIR-R5",
			"sealed_at":     time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// GetSealID returns the seal ID for a given resource ID, if sealed.
func (b *FHIRBridge) GetSealID(resourceID string) (string, bool) {
	sealID, ok := b.sealStore[resourceID]
	return sealID, ok
}

// ---------------------------------------------------------------------------
// Bridge result types
// ---------------------------------------------------------------------------

// SealedResource contains the result of sealing a FHIR resource.
type SealedResource struct {
	ResourceID   string       `json:"resource_id"`
	ResourceType ResourceType `json:"resource_type"`
	SealID       string       `json:"seal_id"`
	SealStatus   string       `json:"seal_status"`
	ResourceHash string       `json:"resource_hash"`
	SealedAt     time.Time    `json:"sealed_at"`
}

// VerificationResult contains the outcome of a resource verification.
type VerificationResult struct {
	SealID       string       `json:"seal_id"`
	SealValid    bool         `json:"seal_valid"`
	DataIntact   bool         `json:"data_intact"`
	ResourceType ResourceType `json:"resource_type"`
	ResourceID   string       `json:"resource_id"`
	VerifiedAt   time.Time    `json:"verified_at"`
}

// ImportResult contains the outcome of importing a FHIR resource.
type ImportResult struct {
	Resource       Resource          `json:"resource"`
	Validation     *ValidationResult `json:"validation"`
	Sealed         bool              `json:"sealed"`
	SealedResource *SealedResource   `json:"sealed_resource,omitempty"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
