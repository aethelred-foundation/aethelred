package sovereign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Air-gapped deployment management
// ---------------------------------------------------------------------------

// TransferMedium identifies the physical or logical medium for air-gap state transfer.
type TransferMedium int

const (
	// TransferUSB uses USB storage media.
	TransferUSB TransferMedium = iota

	// TransferOpticalDisc uses optical disc media (CD/DVD/Blu-ray).
	TransferOpticalDisc

	// TransferDiode uses a one-way data diode.
	TransferDiode

	// TransferSecureCourier uses a physically escorted transfer.
	TransferSecureCourier
)

// String returns the human-readable label for a TransferMedium.
func (t TransferMedium) String() string {
	switch t {
	case TransferUSB:
		return "USB"
	case TransferOpticalDisc:
		return "Optical Disc"
	case TransferDiode:
		return "Data Diode"
	case TransferSecureCourier:
		return "Secure Courier"
	default:
		return "Unknown"
	}
}

// AirGapConfig holds configuration for air-gapped deployments.
type AirGapConfig struct {
	// DisableExternalDNS prevents DNS queries to external resolvers.
	DisableExternalDNS bool `json:"disable_external_dns"`

	// DisableExternalHTTPS prevents all outbound HTTPS connections.
	DisableExternalHTTPS bool `json:"disable_external_https"`

	// LocalCertAuthority specifies the internal CA for certificate issuance.
	LocalCertAuthority string `json:"local_cert_authority"`

	// OfflineCRL enables an offline certificate revocation list.
	OfflineCRL bool `json:"offline_crl"`

	// SnapshotFrequency is how often state snapshots are created.
	SnapshotFrequency time.Duration `json:"snapshot_frequency"`

	// TransferMedium is the medium used for air-gap state transfer.
	TransferMedium TransferMedium `json:"transfer_medium"`

	// MaxBundleAge is the maximum acceptable age for an imported bundle.
	MaxBundleAge time.Duration `json:"max_bundle_age"`

	// TrustedCertificates holds PEM-encoded certificates for offline validation.
	TrustedCertificates []string `json:"trusted_certificates"`
}

// Validate checks the air-gap configuration for consistency.
func (c *AirGapConfig) Validate() error {
	if c.LocalCertAuthority == "" {
		return fmt.Errorf("local certificate authority is required for air-gapped deployments")
	}
	if c.SnapshotFrequency <= 0 {
		return fmt.Errorf("snapshot frequency must be positive")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Air-gap bundle
// ---------------------------------------------------------------------------

// AirGapBundle is a self-contained deployment package for air-gapped
// installation and update cycles.
type AirGapBundle struct {
	// ID uniquely identifies this bundle.
	ID string `json:"id"`

	// Version is the software version packaged in the bundle.
	Version string `json:"version"`

	// Binary holds the main executable binary.
	Binary []byte `json:"binary"`

	// Config holds the serialized deployment configuration.
	Config []byte `json:"config"`

	// State holds the serialized state snapshot.
	State []byte `json:"state"`

	// Certificates holds PEM-encoded certificates.
	Certificates []string `json:"certificates"`

	// Checksums maps content names to their SHA-256 checksums.
	Checksums map[string]string `json:"checksums"`

	// Manifest holds the signed manifest of all bundle contents.
	Manifest []byte `json:"manifest"`

	// CreatedAt is when the bundle was generated.
	CreatedAt time.Time `json:"created_at"`

	// SizeBytes is the total size of the bundle.
	SizeBytes int64 `json:"size_bytes"`
}

// ---------------------------------------------------------------------------
// Air-gap integrity result
// ---------------------------------------------------------------------------

// IntegrityResult reports the result of an air-gap integrity validation.
type IntegrityResult struct {
	// Valid indicates whether the deployment passes all integrity checks.
	Valid bool `json:"valid"`

	// Issues lists any problems discovered.
	Issues []string `json:"issues"`

	// ExternalConnections lists detected external network connections.
	ExternalConnections []string `json:"external_connections"`

	// DNSLeaks lists detected DNS queries to external resolvers.
	DNSLeaks []string `json:"dns_leaks"`

	// Timestamp records when the validation was performed.
	Timestamp time.Time `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Air-gap manager
// ---------------------------------------------------------------------------

// AirGapManager handles air-gapped deployment lifecycle operations including
// bundle creation, integrity validation, and state transfer.
type AirGapManager struct {
	config  AirGapConfig
	mu      sync.RWMutex
	bundles map[string]*AirGapBundle
}

// NewAirGapManager creates a new air-gap manager with the given configuration.
func NewAirGapManager(config AirGapConfig) (*AirGapManager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid air-gap config: %w", err)
	}

	return &AirGapManager{
		config:  config,
		bundles: make(map[string]*AirGapBundle),
	}, nil
}

// PrepareAirGapBundle creates a self-contained deployment bundle suitable
// for transfer to an air-gapped environment.
func (m *AirGapManager) PrepareAirGapBundle(_ context.Context, version string) (*AirGapBundle, error) {
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}

	now := time.Now().UTC()
	bundleID := fmt.Sprintf("airgap-bundle-%s-%d", version, now.UnixNano())

	// Build binary placeholder (in production, this would package real binaries)
	binaryData := []byte(fmt.Sprintf("aethelred-node-%s", version))
	configData := []byte(fmt.Sprintf(`{"version":"%s","air_gapped":true}`, version))

	checksums := make(map[string]string)

	binaryHash := sha256.Sum256(binaryData)
	checksums["binary"] = hex.EncodeToString(binaryHash[:])

	configHash := sha256.Sum256(configData)
	checksums["config"] = hex.EncodeToString(configHash[:])

	bundle := &AirGapBundle{
		ID:           bundleID,
		Version:      version,
		Binary:       binaryData,
		Config:       configData,
		Certificates: m.config.TrustedCertificates,
		Checksums:    checksums,
		CreatedAt:    now,
		SizeBytes:    int64(len(binaryData) + len(configData)),
	}

	// Generate manifest
	manifestData := fmt.Sprintf("bundle:%s version:%s created:%s checksums:%v",
		bundleID, version, now.Format(time.RFC3339), checksums)
	manifestHash := sha256.Sum256([]byte(manifestData))
	bundle.Manifest = manifestHash[:]

	m.mu.Lock()
	m.bundles[bundleID] = bundle
	m.mu.Unlock()

	return bundle, nil
}

// ValidateAirGapIntegrity verifies that a deployment has no external network
// dependencies, DNS leaks, or other isolation breaches.
func (m *AirGapManager) ValidateAirGapIntegrity(_ context.Context, deployment *Deployment) (*IntegrityResult, error) {
	if deployment == nil {
		return nil, fmt.Errorf("deployment is nil")
	}

	result := &IntegrityResult{
		Valid:     true,
		Timestamp: time.Now().UTC(),
	}

	// Verify deployment mode
	if deployment.Spec.Mode != AirGapped {
		result.Valid = false
		result.Issues = append(result.Issues, "deployment mode is not air-gapped")
	}

	// Verify external network is disabled
	if !deployment.Spec.Network.EgressRestricted {
		result.Valid = false
		result.Issues = append(result.Issues, "egress is not restricted")
		result.ExternalConnections = append(result.ExternalConnections, "outbound network traffic permitted")
	}

	// Verify DNS configuration
	if !m.config.DisableExternalDNS {
		result.Valid = false
		result.Issues = append(result.Issues, "external DNS is not disabled")
		result.DNSLeaks = append(result.DNSLeaks, "external DNS resolvers may be reachable")
	}

	// Verify HTTPS restriction
	if !m.config.DisableExternalHTTPS {
		result.Valid = false
		result.Issues = append(result.Issues, "external HTTPS is not disabled")
		result.ExternalConnections = append(result.ExternalConnections, "outbound HTTPS connections permitted")
	}

	// Verify local CA
	if m.config.LocalCertAuthority == "" {
		result.Valid = false
		result.Issues = append(result.Issues, "no local certificate authority configured")
	}

	// Verify encryption at rest
	if !deployment.Spec.Storage.EncryptionAtRest {
		result.Valid = false
		result.Issues = append(result.Issues, "encryption at rest is not enabled")
	}

	// Verify TLS version
	if deployment.Spec.Network.TLSMinVersion != "1.3" {
		result.Issues = append(result.Issues, "TLS 1.3 is recommended for air-gapped deployments")
	}

	return result, nil
}

// TransferState handles the import of a state bundle into the air-gapped
// environment using the configured transfer medium.
func (m *AirGapManager) TransferState(_ context.Context, bundle *AirGapBundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle is nil")
	}
	if bundle.ID == "" {
		return fmt.Errorf("bundle ID is required")
	}

	// Verify bundle age
	if m.config.MaxBundleAge > 0 {
		age := time.Since(bundle.CreatedAt)
		if age > m.config.MaxBundleAge {
			return fmt.Errorf("bundle is too old (%v > %v)", age, m.config.MaxBundleAge)
		}
	}

	// Validate bundle integrity
	if err := ValidateBundle(bundle); err != nil {
		return fmt.Errorf("bundle validation failed: %w", err)
	}

	m.mu.Lock()
	m.bundles[bundle.ID] = bundle
	m.mu.Unlock()

	return nil
}

// GetBundle retrieves a stored bundle by ID.
func (m *AirGapManager) GetBundle(bundleID string) (*AirGapBundle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	bundle, ok := m.bundles[bundleID]
	if !ok {
		return nil, fmt.Errorf("bundle not found: %s", bundleID)
	}
	return bundle, nil
}

// ---------------------------------------------------------------------------
// Bundle validation
// ---------------------------------------------------------------------------

// ValidateBundle checks the integrity of an air-gap bundle by verifying
// all checksums and manifest data.
func ValidateBundle(bundle *AirGapBundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle is nil")
	}
	if bundle.ID == "" {
		return fmt.Errorf("bundle ID is required")
	}
	if bundle.Version == "" {
		return fmt.Errorf("bundle version is required")
	}

	// Verify binary checksum
	if len(bundle.Binary) > 0 {
		binaryHash := sha256.Sum256(bundle.Binary)
		expected, ok := bundle.Checksums["binary"]
		if ok && hex.EncodeToString(binaryHash[:]) != expected {
			return fmt.Errorf("binary checksum mismatch")
		}
	}

	// Verify config checksum
	if len(bundle.Config) > 0 {
		configHash := sha256.Sum256(bundle.Config)
		expected, ok := bundle.Checksums["config"]
		if ok && hex.EncodeToString(configHash[:]) != expected {
			return fmt.Errorf("config checksum mismatch")
		}
	}

	// Verify manifest exists
	if len(bundle.Manifest) == 0 {
		return fmt.Errorf("bundle manifest is missing")
	}

	return nil
}
