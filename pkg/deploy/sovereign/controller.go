// Package sovereign provides a deployment controller for sovereign and
// regulated environments. It manages deployment configurations across
// multiple deployment modes including cloud, VPC, on-premises, air-gapped,
// hybrid, and edge-node topologies.
//
// The controller enforces data residency, compliance, and cryptographic
// key management requirements for each deployment, integrating with
// Aethelred's seal infrastructure and post-quantum cryptography stack.
package sovereign

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Deployment modes
// ---------------------------------------------------------------------------

// DeploymentMode identifies how infrastructure is provisioned and operated.
type DeploymentMode int

const (
	// Cloud is a fully managed cloud deployment (AWS, GCP, Azure).
	Cloud DeploymentMode = iota

	// VPC is a cloud deployment inside a customer-controlled Virtual Private Cloud.
	VPC

	// OnPrem is an on-premises deployment in a customer datacenter.
	OnPrem

	// AirGapped is a fully isolated deployment with no external network.
	AirGapped

	// Hybrid combines cloud and on-premises components.
	Hybrid

	// EdgeNode is a lightweight deployment at the network edge.
	EdgeNode
)

// String returns the human-readable label for a DeploymentMode.
func (m DeploymentMode) String() string {
	switch m {
	case Cloud:
		return "Cloud"
	case VPC:
		return "VPC"
	case OnPrem:
		return "On-Premises"
	case AirGapped:
		return "Air-Gapped"
	case Hybrid:
		return "Hybrid"
	case EdgeNode:
		return "Edge Node"
	default:
		return "Unknown"
	}
}

// RequiresLocalKMS returns true if the mode requires a locally managed
// key management system rather than a cloud-hosted one.
func (m DeploymentMode) RequiresLocalKMS() bool {
	return m == OnPrem || m == AirGapped || m == EdgeNode
}

// ---------------------------------------------------------------------------
// Deployment status
// ---------------------------------------------------------------------------

// DeploymentStatus tracks the lifecycle of a deployment.
type DeploymentStatus string

const (
	StatusPending     DeploymentStatus = "pending"
	StatusProvisioning DeploymentStatus = "provisioning"
	StatusRunning     DeploymentStatus = "running"
	StatusDegraded    DeploymentStatus = "degraded"
	StatusStopped     DeploymentStatus = "stopped"
	StatusFailed      DeploymentStatus = "failed"
	StatusTerminated  DeploymentStatus = "terminated"
)

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

// ControllerConfig holds configuration for the SovereignController.
type ControllerConfig struct {
	// DefaultMode is the deployment mode used when a spec does not specify one.
	DefaultMode DeploymentMode `json:"default_mode"`

	// AllowedRegions constrains which regions can host deployments.
	AllowedRegions []string `json:"allowed_regions"`

	// ComplianceRequirements lists frameworks that all deployments must satisfy.
	ComplianceRequirements []string `json:"compliance_requirements"`

	// KMSConfig holds the sovereign key management configuration.
	KMSConfig SovereignKMSConfig `json:"kms_config"`

	// MaxDeployments caps the number of concurrent deployments (0 = unlimited).
	MaxDeployments int `json:"max_deployments"`
}

// Validate checks the controller configuration for consistency.
func (c *ControllerConfig) Validate() error {
	if len(c.AllowedRegions) == 0 {
		return fmt.Errorf("ControllerConfig.Validate: %w: at least one allowed region is required", ErrInvalidDeployment)
	}
	return nil
}

// NetworkConfig specifies network requirements for a deployment.
type NetworkConfig struct {
	// VPCEnabled indicates whether a VPC should be provisioned.
	VPCEnabled bool `json:"vpc_enabled"`

	// PrivateSubnets lists CIDR ranges for private subnets.
	PrivateSubnets []string `json:"private_subnets"`

	// IngressAllowList restricts inbound traffic to specific CIDRs.
	IngressAllowList []string `json:"ingress_allow_list"`

	// EgressRestricted disables all outbound internet access.
	EgressRestricted bool `json:"egress_restricted"`

	// TLSMinVersion specifies the minimum TLS version (e.g., "1.3").
	TLSMinVersion string `json:"tls_min_version"`

	// MTLSRequired enables mutual TLS for all inter-service communication.
	MTLSRequired bool `json:"mtls_required"`
}

// StorageConfig specifies storage requirements for a deployment.
type StorageConfig struct {
	// EncryptionAtRest requires all storage to be encrypted.
	EncryptionAtRest bool `json:"encryption_at_rest"`

	// EncryptionAlgorithm specifies the encryption algorithm (e.g., "AES-256-GCM").
	EncryptionAlgorithm string `json:"encryption_algorithm"`

	// RetentionDays is the minimum data retention period.
	RetentionDays int `json:"retention_days"`

	// BackupEnabled enables automated backups.
	BackupEnabled bool `json:"backup_enabled"`

	// CrossRegionReplication enables replication across regions.
	CrossRegionReplication bool `json:"cross_region_replication"`
}

// ComputeConfig specifies compute requirements for a deployment.
type ComputeConfig struct {
	// TEERequired requires Trusted Execution Environment support.
	TEERequired bool `json:"tee_required"`

	// MinNodes is the minimum number of compute nodes.
	MinNodes int `json:"min_nodes"`

	// MaxNodes is the maximum number of compute nodes.
	MaxNodes int `json:"max_nodes"`

	// CPUArchitecture constrains the processor architecture (e.g., "x86_64", "arm64").
	CPUArchitecture string `json:"cpu_architecture"`

	// DedicatedHosts requires dedicated (non-shared) physical hosts.
	DedicatedHosts bool `json:"dedicated_hosts"`
}

// ---------------------------------------------------------------------------
// Deployment specification and result
// ---------------------------------------------------------------------------

// DeploymentSpec describes the desired state for a deployment.
type DeploymentSpec struct {
	// Name is a human-readable name for the deployment.
	Name string `json:"name"`

	// Mode is the deployment mode.
	Mode DeploymentMode `json:"mode"`

	// Region is the target region for the deployment.
	Region string `json:"region"`

	// Compliance lists the compliance frameworks this deployment must satisfy.
	Compliance []string `json:"compliance"`

	// KMS specifies key management requirements.
	KMS SovereignKMSConfig `json:"kms"`

	// Network specifies networking requirements.
	Network NetworkConfig `json:"network"`

	// Storage specifies storage requirements.
	Storage StorageConfig `json:"storage"`

	// Compute specifies compute requirements.
	Compute ComputeConfig `json:"compute"`

	// Labels are key-value labels for the deployment.
	Labels map[string]string `json:"labels,omitempty"`
}

// Validate checks the deployment spec for required fields.
// ValidateTLSVersion checks that a TLS version string is valid.
func ValidateTLSVersion(v string) error {
	if v == "" {
		return nil // optional
	}
	valid := map[string]bool{"1.2": true, "1.3": true}
	if !valid[v] {
		return fmt.Errorf("ValidateTLSVersion: %w: unsupported TLS version %q", ErrInvalidDeployment, v)
	}
	return nil
}

func (s *DeploymentSpec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("DeploymentSpec.Validate: %w: name is empty", ErrInvalidDeployment)
	}
	if s.Region == "" {
		return fmt.Errorf("DeploymentSpec.Validate: %w: region is empty", ErrInvalidDeployment)
	}
	// Validate TLS version format.
	if err := ValidateTLSVersion(s.Network.TLSMinVersion); err != nil {
		return fmt.Errorf("DeploymentSpec.Validate: %w", err)
	}
	return nil
}

// HealthCheck reports the health of a deployment.
type HealthCheck struct {
	// Healthy indicates overall health.
	Healthy bool `json:"healthy"`

	// LastChecked is when health was last verified.
	LastChecked time.Time `json:"last_checked"`

	// Components maps component names to their health status.
	Components map[string]bool `json:"components"`

	// Message provides additional context for unhealthy deployments.
	Message string `json:"message,omitempty"`
}

// Endpoint describes a network endpoint exposed by a deployment.
type Endpoint struct {
	// Name identifies the endpoint (e.g., "api", "grpc", "metrics").
	Name string `json:"name"`

	// URL is the endpoint address.
	URL string `json:"url"`

	// Internal indicates whether the endpoint is internal-only.
	Internal bool `json:"internal"`
}

// Deployment represents a sovereign deployment instance.
type Deployment struct {
	// ID uniquely identifies this deployment.
	ID string `json:"id"`

	// Spec is the deployment specification.
	Spec DeploymentSpec `json:"spec"`

	// Status is the current deployment status.
	Status DeploymentStatus `json:"status"`

	// CreatedAt is when the deployment was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the deployment was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// Endpoints lists the endpoints exposed by this deployment.
	Endpoints []Endpoint `json:"endpoints"`

	// HealthCheck is the most recent health check result.
	HealthCheck HealthCheck `json:"health_check"`

	// ComplianceStatus maps framework IDs to their compliance state.
	ComplianceStatus map[string]bool `json:"compliance_status"`
}

// ---------------------------------------------------------------------------
// Sovereign controller
// ---------------------------------------------------------------------------

// SovereignController manages deployment configurations across sovereign
// deployment modes. It enforces data residency, compliance requirements,
// and cryptographic key management policies.
type SovereignController struct {
	config      ControllerConfig
	mu          sync.RWMutex
	deployments map[string]*Deployment
}

// NewSovereignController creates a new controller with the given configuration.
func NewSovereignController(config ControllerConfig) (*SovereignController, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("SovereignController.New: %w", err)
	}

	// Copy AllowedRegions to protect from mutation during validation.
	regionsCopy := make([]string, len(config.AllowedRegions))
	copy(regionsCopy, config.AllowedRegions)
	config.AllowedRegions = regionsCopy

	return &SovereignController{
		config:      config,
		deployments: make(map[string]*Deployment),
	}, nil
}

// Deploy creates a new deployment based on the given specification.
// It validates the spec against controller constraints, provisions
// infrastructure, and returns the resulting deployment.
func (c *SovereignController) Deploy(ctx context.Context, spec DeploymentSpec) (*Deployment, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}

	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("SovereignController.Deploy: %w", err)
	}

	// Apply defaults
	if spec.Mode == 0 && c.config.DefaultMode != 0 {
		spec.Mode = c.config.DefaultMode
	}

	// Validate region is allowed
	if !c.isRegionAllowed(spec.Region) {
		return nil, fmt.Errorf("SovereignController.Deploy: %w: region %s", ErrRegionNotAllowed, spec.Region)
	}

	// Merge compliance requirements
	spec.Compliance = c.mergeCompliance(spec.Compliance)

	// Enforce mode-specific constraints
	if err := c.enforceConstraints(&spec); err != nil {
		return nil, fmt.Errorf("constraint enforcement failed: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check deployment limit
	if c.config.MaxDeployments > 0 && len(c.deployments) >= c.config.MaxDeployments {
		return nil, fmt.Errorf("SovereignController.Deploy: %w: limit %d", ErrMaxDeploymentsReached, c.config.MaxDeployments)
	}

	now := time.Now().UTC()
	deployment := &Deployment{
		ID:        fmt.Sprintf("deploy-%s-%d", spec.Region, now.UnixNano()),
		Spec:      spec,
		Status:    StatusProvisioning,
		CreatedAt: now,
		UpdatedAt: now,
		HealthCheck: HealthCheck{
			Healthy:     false,
			LastChecked: now,
			Components:  make(map[string]bool),
			Message:     "provisioning",
		},
		ComplianceStatus: make(map[string]bool),
	}

	// Initialize compliance status
	for _, fw := range spec.Compliance {
		deployment.ComplianceStatus[fw] = false
	}

	// Set initial endpoints based on mode
	deployment.Endpoints = c.generateEndpoints(spec)

	// Mark as running (in production, this would be async provisioning)
	deployment.Status = StatusRunning
	deployment.HealthCheck.Healthy = true
	deployment.HealthCheck.Message = "operational"

	c.deployments[deployment.ID] = deployment
	return deployment, nil
}

// ValidateDeployment checks that a deployment meets all sovereign requirements
// without modifying the deployment. It returns an error describing the first
// constraint violation found.
func (c *SovereignController) ValidateDeployment(_ context.Context, deployment *Deployment) error {
	if deployment == nil {
		return fmt.Errorf("deployment is nil")
	}

	// Validate region
	if !c.isRegionAllowed(deployment.Spec.Region) {
		return fmt.Errorf("deployment region %s is not allowed", deployment.Spec.Region)
	}

	// Validate network security for air-gapped
	if deployment.Spec.Mode == AirGapped && !deployment.Spec.Network.EgressRestricted {
		return fmt.Errorf("air-gapped deployments must have egress restricted")
	}

	// Validate encryption requirements
	if !deployment.Spec.Storage.EncryptionAtRest {
		return fmt.Errorf("encryption at rest is required for sovereign deployments")
	}

	// Validate on-prem requires mTLS
	if deployment.Spec.Mode == OnPrem && !deployment.Spec.Network.MTLSRequired {
		return fmt.Errorf("on-premises deployments must enable mutual TLS")
	}

	// Validate VPC mode requires VPC
	if deployment.Spec.Mode == VPC && !deployment.Spec.Network.VPCEnabled {
		return fmt.Errorf("VPC deployments must enable VPC networking")
	}

	return nil
}

// GetDeploymentStatus retrieves the current status of a deployment.
func (c *SovereignController) GetDeploymentStatus(_ context.Context, deploymentID string) (*Deployment, error) {
	if deploymentID == "" {
		return nil, fmt.Errorf("deployment ID is required")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	deployment, ok := c.deployments[deploymentID]
	if !ok {
		return nil, fmt.Errorf("deployment not found: %s", deploymentID)
	}

	return deployment, nil
}

// ListDeployments returns all managed deployments.
func (c *SovereignController) ListDeployments() []*Deployment {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*Deployment, 0, len(c.deployments))
	for _, d := range c.deployments {
		result = append(result, d)
	}
	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (c *SovereignController) isRegionAllowed(region string) bool {
	for _, r := range c.config.AllowedRegions {
		if r == region {
			return true
		}
	}
	return false
}

func (c *SovereignController) mergeCompliance(specCompliance []string) []string {
	seen := make(map[string]bool)
	var merged []string

	for _, fw := range c.config.ComplianceRequirements {
		if !seen[fw] {
			seen[fw] = true
			merged = append(merged, fw)
		}
	}
	for _, fw := range specCompliance {
		if !seen[fw] {
			seen[fw] = true
			merged = append(merged, fw)
		}
	}
	return merged
}

func (c *SovereignController) enforceConstraints(spec *DeploymentSpec) error {
	switch spec.Mode {
	case AirGapped:
		spec.Network.EgressRestricted = true
		spec.Storage.EncryptionAtRest = true
		if spec.Network.TLSMinVersion == "" {
			spec.Network.TLSMinVersion = "1.3"
		}

	case OnPrem:
		spec.Storage.EncryptionAtRest = true
		spec.Network.MTLSRequired = true

	case VPC:
		spec.Network.VPCEnabled = true
		spec.Storage.EncryptionAtRest = true

	case EdgeNode:
		if spec.Compute.MinNodes < 1 {
			spec.Compute.MinNodes = 1
		}
		if spec.Compute.MaxNodes < spec.Compute.MinNodes {
			spec.Compute.MaxNodes = spec.Compute.MinNodes
		}

	case Cloud, Hybrid:
		spec.Storage.EncryptionAtRest = true
	}

	// Universal constraints
	if spec.Network.TLSMinVersion == "" {
		spec.Network.TLSMinVersion = "1.2"
	}

	return nil
}

func (c *SovereignController) generateEndpoints(spec DeploymentSpec) []Endpoint {
	endpoints := []Endpoint{
		{Name: "api", URL: fmt.Sprintf("https://api.%s.aethelred.local", spec.Region), Internal: false},
		{Name: "grpc", URL: fmt.Sprintf("grpcs://grpc.%s.aethelred.local:9090", spec.Region), Internal: false},
		{Name: "metrics", URL: fmt.Sprintf("https://metrics.%s.aethelred.local:9100", spec.Region), Internal: true},
	}

	if spec.Mode == AirGapped {
		for i := range endpoints {
			endpoints[i].Internal = true
		}
	}

	return endpoints
}
