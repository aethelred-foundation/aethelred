package sovereign

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Transfer requirements
// ---------------------------------------------------------------------------

// TransferRequirement indicates the legal mechanism required for cross-border
// data transfer between jurisdictions.
type TransferRequirement int

const (
	// TransferNone means no special mechanism is required.
	TransferNone TransferRequirement = iota

	// TransferAdequacyDecision relies on an adequacy decision between jurisdictions.
	TransferAdequacyDecision

	// TransferSCCs requires Standard Contractual Clauses.
	TransferSCCs

	// TransferBCRs requires Binding Corporate Rules.
	TransferBCRs

	// TransferConsent requires explicit data subject consent.
	TransferConsent

	// TransferProhibited means transfer is not permitted.
	TransferProhibited
)

// String returns the human-readable label for a TransferRequirement.
func (t TransferRequirement) String() string {
	switch t {
	case TransferNone:
		return "None"
	case TransferAdequacyDecision:
		return "Adequacy Decision"
	case TransferSCCs:
		return "Standard Contractual Clauses"
	case TransferBCRs:
		return "Binding Corporate Rules"
	case TransferConsent:
		return "Explicit Consent"
	case TransferProhibited:
		return "Prohibited"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Region definition
// ---------------------------------------------------------------------------

// Region defines a deployment region with its regulatory jurisdiction
// and data residency constraints.
type Region struct {
	// ID is the region identifier (e.g., "eu-west-1").
	ID string `json:"id"`

	// Name is the human-readable region name.
	Name string `json:"name"`

	// Jurisdiction is the governing legal jurisdiction.
	Jurisdiction string `json:"jurisdiction"`

	// DataResidency describes the data residency requirements.
	DataResidency string `json:"data_residency"`

	// AllowedDestinations lists region IDs that data can be transferred to.
	AllowedDestinations []string `json:"allowed_destinations"`

	// Capabilities lists the compute capabilities available in this region.
	Capabilities []string `json:"capabilities"`

	// TransferRequirements maps destination region IDs to their transfer requirements.
	TransferRequirements map[string]TransferRequirement `json:"transfer_requirements"`
}

// CanTransferTo returns true if data from this region can be transferred
// to the given destination region.
func (r *Region) CanTransferTo(destID string) bool {
	for _, d := range r.AllowedDestinations {
		if d == destID {
			return true
		}
	}
	return false
}

// GetTransferRequirement returns the transfer requirement for sending data
// to the specified destination region.
func (r *Region) GetTransferRequirement(destID string) TransferRequirement {
	if req, ok := r.TransferRequirements[destID]; ok {
		return req
	}
	return TransferProhibited
}

// HasCapability returns true if the region supports the given capability.
func (r *Region) HasCapability(cap string) bool {
	for _, c := range r.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Pre-defined regions
// ---------------------------------------------------------------------------

// Pre-defined sovereign regions with their jurisdiction zones.
var (
	RegionEU = Region{
		ID:            "eu-west-1",
		Name:          "EU (Frankfurt)",
		Jurisdiction:  "EU",
		DataResidency: "European Union",
		AllowedDestinations: []string{
			"eu-west-1", "uk-south-1", "ch-zurich-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage", "hsm"},
		TransferRequirements: map[string]TransferRequirement{
			"eu-west-1":    TransferNone,
			"uk-south-1":   TransferAdequacyDecision,
			"ch-zurich-1":  TransferAdequacyDecision,
			"us-east-1":    TransferSCCs,
			"uae-dubai-1":  TransferSCCs,
			"sg-central-1": TransferSCCs,
			"au-east-1":    TransferSCCs,
			"jp-east-1":    TransferAdequacyDecision,
		},
	}

	RegionUS = Region{
		ID:            "us-east-1",
		Name:          "US East (Virginia)",
		Jurisdiction:  "US",
		DataResidency: "United States",
		AllowedDestinations: []string{
			"us-east-1", "uk-south-1", "au-east-1", "jp-east-1", "sg-central-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage", "hsm", "gpu"},
		TransferRequirements: map[string]TransferRequirement{
			"us-east-1":    TransferNone,
			"eu-west-1":    TransferSCCs,
			"uk-south-1":   TransferAdequacyDecision,
			"uae-dubai-1":  TransferConsent,
			"sg-central-1": TransferAdequacyDecision,
			"au-east-1":    TransferAdequacyDecision,
			"jp-east-1":    TransferAdequacyDecision,
			"ch-zurich-1":  TransferSCCs,
		},
	}

	RegionUK = Region{
		ID:            "uk-south-1",
		Name:          "UK South (London)",
		Jurisdiction:  "UK",
		DataResidency: "United Kingdom",
		AllowedDestinations: []string{
			"uk-south-1", "eu-west-1", "us-east-1", "ch-zurich-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage", "hsm"},
		TransferRequirements: map[string]TransferRequirement{
			"uk-south-1":   TransferNone,
			"eu-west-1":    TransferAdequacyDecision,
			"us-east-1":    TransferAdequacyDecision,
			"uae-dubai-1":  TransferSCCs,
			"sg-central-1": TransferSCCs,
			"au-east-1":    TransferSCCs,
			"jp-east-1":    TransferAdequacyDecision,
			"ch-zurich-1":  TransferAdequacyDecision,
		},
	}

	RegionUAE = Region{
		ID:            "uae-dubai-1",
		Name:          "UAE (Dubai)",
		Jurisdiction:  "UAE",
		DataResidency: "United Arab Emirates",
		AllowedDestinations: []string{
			"uae-dubai-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage"},
		TransferRequirements: map[string]TransferRequirement{
			"uae-dubai-1":  TransferNone,
			"eu-west-1":    TransferConsent,
			"us-east-1":    TransferConsent,
			"uk-south-1":   TransferConsent,
			"sg-central-1": TransferConsent,
			"au-east-1":    TransferProhibited,
			"jp-east-1":    TransferProhibited,
			"ch-zurich-1":  TransferProhibited,
		},
	}

	RegionSingapore = Region{
		ID:            "sg-central-1",
		Name:          "Singapore",
		Jurisdiction:  "SG",
		DataResidency: "Singapore",
		AllowedDestinations: []string{
			"sg-central-1", "au-east-1", "jp-east-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage", "hsm"},
		TransferRequirements: map[string]TransferRequirement{
			"sg-central-1": TransferNone,
			"eu-west-1":    TransferSCCs,
			"us-east-1":    TransferAdequacyDecision,
			"uk-south-1":   TransferSCCs,
			"uae-dubai-1":  TransferConsent,
			"au-east-1":    TransferAdequacyDecision,
			"jp-east-1":    TransferAdequacyDecision,
			"ch-zurich-1":  TransferSCCs,
		},
	}

	RegionAustralia = Region{
		ID:            "au-east-1",
		Name:          "Australia (Sydney)",
		Jurisdiction:  "AU",
		DataResidency: "Australia",
		AllowedDestinations: []string{
			"au-east-1", "sg-central-1", "jp-east-1",
		},
		Capabilities: []string{"tee", "seal", "compute", "storage"},
		TransferRequirements: map[string]TransferRequirement{
			"au-east-1":    TransferNone,
			"eu-west-1":    TransferSCCs,
			"us-east-1":    TransferAdequacyDecision,
			"uk-south-1":   TransferSCCs,
			"uae-dubai-1":  TransferProhibited,
			"sg-central-1": TransferAdequacyDecision,
			"jp-east-1":    TransferAdequacyDecision,
			"ch-zurich-1":  TransferSCCs,
		},
	}

	RegionJapan = Region{
		ID:            "jp-east-1",
		Name:          "Japan (Tokyo)",
		Jurisdiction:  "JP",
		DataResidency: "Japan",
		AllowedDestinations: []string{
			"jp-east-1", "sg-central-1", "au-east-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage", "hsm", "gpu"},
		TransferRequirements: map[string]TransferRequirement{
			"jp-east-1":    TransferNone,
			"eu-west-1":    TransferAdequacyDecision,
			"us-east-1":    TransferAdequacyDecision,
			"uk-south-1":   TransferAdequacyDecision,
			"uae-dubai-1":  TransferConsent,
			"sg-central-1": TransferAdequacyDecision,
			"au-east-1":    TransferAdequacyDecision,
			"ch-zurich-1":  TransferAdequacyDecision,
		},
	}

	RegionSwitzerland = Region{
		ID:            "ch-zurich-1",
		Name:          "Switzerland (Zurich)",
		Jurisdiction:  "CH",
		DataResidency: "Switzerland",
		AllowedDestinations: []string{
			"ch-zurich-1", "eu-west-1",
		},
		Capabilities: []string{"tee", "pqc", "seal", "compute", "storage", "hsm"},
		TransferRequirements: map[string]TransferRequirement{
			"ch-zurich-1":  TransferNone,
			"eu-west-1":    TransferAdequacyDecision,
			"us-east-1":    TransferSCCs,
			"uk-south-1":   TransferAdequacyDecision,
			"uae-dubai-1":  TransferProhibited,
			"sg-central-1": TransferSCCs,
			"au-east-1":    TransferSCCs,
			"jp-east-1":    TransferAdequacyDecision,
		},
	}
)

// AllRegions returns all pre-defined sovereign regions.
func AllRegions() []Region {
	return []Region{
		RegionEU, RegionUS, RegionUK, RegionUAE,
		RegionSingapore, RegionAustralia, RegionJapan, RegionSwitzerland,
	}
}

// GetRegionByID looks up a pre-defined region by ID.
func GetRegionByID(id string) (*Region, error) {
	for _, r := range AllRegions() {
		if r.ID == id {
			region := r
			return &region, nil
		}
	}
	return nil, fmt.Errorf("region not found: %s", id)
}

// GetRegionByJurisdiction returns regions matching the given jurisdiction code.
func GetRegionByJurisdiction(jurisdiction string) []Region {
	var result []Region
	for _, r := range AllRegions() {
		if r.Jurisdiction == jurisdiction {
			result = append(result, r)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Data residency policy
// ---------------------------------------------------------------------------

// DataResidencyPolicy defines where data may reside and the requirements
// for transferring it across borders.
type DataResidencyPolicy struct {
	// AllowedRegions lists the regions where data may be stored and processed.
	AllowedRegions []string `json:"allowed_regions"`

	// BlockedRegions lists regions where data must never be sent.
	BlockedRegions []string `json:"blocked_regions"`

	// TransferRequirements maps destination region IDs to their required
	// legal transfer mechanisms.
	TransferRequirements map[string]TransferRequirement `json:"transfer_requirements"`

	// RequireEncryptionInTransit mandates encryption for all cross-region transfers.
	RequireEncryptionInTransit bool `json:"require_encryption_in_transit"`
}

// IsRegionAllowed returns true if the policy permits data in the given region.
func (p *DataResidencyPolicy) IsRegionAllowed(regionID string) bool {
	// Check blocked first
	for _, r := range p.BlockedRegions {
		if r == regionID {
			return false
		}
	}

	// If allowed list is specified, region must be in it
	if len(p.AllowedRegions) > 0 {
		for _, r := range p.AllowedRegions {
			if r == regionID {
				return true
			}
		}
		return false
	}

	return true
}

// ---------------------------------------------------------------------------
// Computation routing
// ---------------------------------------------------------------------------

// ComputationJob represents a computation request that needs to be routed
// to a compliant region.
type ComputationJob struct {
	// ID uniquely identifies the job.
	ID string `json:"id"`

	// DataRegion is the region where the source data resides.
	DataRegion string `json:"data_region"`

	// RequiredCapabilities lists capabilities the target region must have.
	RequiredCapabilities []string `json:"required_capabilities"`

	// Priority determines scheduling priority.
	Priority int `json:"priority"`

	// MaxLatencyMS is the maximum acceptable latency in milliseconds.
	MaxLatencyMS int `json:"max_latency_ms"`

	// Metadata holds job-specific key-value data.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// RoutingResult describes the outcome of a computation routing decision.
type RoutingResult struct {
	// TargetRegion is the region selected for computation.
	TargetRegion Region `json:"target_region"`

	// TransferRequired indicates whether data must be transferred.
	TransferRequired bool `json:"transfer_required"`

	// TransferRequirement is the legal mechanism needed for transfer.
	TransferRequirement TransferRequirement `json:"transfer_requirement"`

	// RoutedAt is when the routing decision was made.
	RoutedAt time.Time `json:"routed_at"`
}

// CrossBorderResult describes the outcome of a cross-border data transfer.
type CrossBorderResult struct {
	// Permitted indicates whether the transfer is allowed.
	Permitted bool `json:"permitted"`

	// Requirement is the legal mechanism required.
	Requirement TransferRequirement `json:"requirement"`

	// FromRegion is the source region.
	FromRegion string `json:"from_region"`

	// ToRegion is the destination region.
	ToRegion string `json:"to_region"`

	// Conditions lists any conditions that must be met.
	Conditions []string `json:"conditions"`
}

// ---------------------------------------------------------------------------
// Region controller
// ---------------------------------------------------------------------------

// RegionController manages region-locked computation routing and data
// residency enforcement.
type RegionController struct {
	mu       sync.RWMutex
	regions  map[string]*Region
	policies map[string]*DataResidencyPolicy
}

// NewRegionController creates a new region controller pre-loaded with
// all defined sovereign regions.
func NewRegionController() *RegionController {
	rc := &RegionController{
		regions:  make(map[string]*Region),
		policies: make(map[string]*DataResidencyPolicy),
	}

	for _, r := range AllRegions() {
		region := r
		rc.regions[r.ID] = &region
	}

	return rc
}

// RouteComputation selects a compliant region for executing a computation
// job, taking into account data residency, capabilities, and transfer
// requirements.
func (rc *RegionController) RouteComputation(_ context.Context, job ComputationJob, policy *DataResidencyPolicy) (*RoutingResult, error) {
	if job.ID == "" {
		return nil, fmt.Errorf("job ID is required")
	}
	if job.DataRegion == "" {
		return nil, fmt.Errorf("data region is required")
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	sourceRegion, ok := rc.regions[job.DataRegion]
	if !ok {
		return nil, fmt.Errorf("source region not found: %s", job.DataRegion)
	}

	// Prefer same-region computation (no transfer needed)
	if rc.regionSatisfiesJob(sourceRegion, job, policy) {
		return &RoutingResult{
			TargetRegion:        *sourceRegion,
			TransferRequired:    false,
			TransferRequirement: TransferNone,
			RoutedAt:            time.Now().UTC(),
		}, nil
	}

	// Search allowed destinations for a suitable region
	for _, destID := range sourceRegion.AllowedDestinations {
		if destID == sourceRegion.ID {
			continue
		}

		destRegion, exists := rc.regions[destID]
		if !exists {
			continue
		}

		if !rc.regionSatisfiesJob(destRegion, job, policy) {
			continue
		}

		req := sourceRegion.GetTransferRequirement(destID)
		if req == TransferProhibited {
			continue
		}

		return &RoutingResult{
			TargetRegion:        *destRegion,
			TransferRequired:    true,
			TransferRequirement: req,
			RoutedAt:            time.Now().UTC(),
		}, nil
	}

	return nil, fmt.Errorf("no compliant region found for job %s from region %s", job.ID, job.DataRegion)
}

// ValidateDataResidency verifies that data in the given region complies
// with the specified data residency policy.
func (rc *RegionController) ValidateDataResidency(_ context.Context, dataRegionID string, policy *DataResidencyPolicy) error {
	if dataRegionID == "" {
		return fmt.Errorf("data region ID is required")
	}
	if policy == nil {
		return fmt.Errorf("data residency policy is required")
	}

	if !policy.IsRegionAllowed(dataRegionID) {
		return fmt.Errorf("data region %s is not permitted by the residency policy", dataRegionID)
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if _, ok := rc.regions[dataRegionID]; !ok {
		return fmt.Errorf("region not found: %s", dataRegionID)
	}

	return nil
}

// CrossBorderTransfer evaluates a proposed cross-border data transfer
// and returns the requirements and conditions.
func (rc *RegionController) CrossBorderTransfer(_ context.Context, fromRegionID, toRegionID string) (*CrossBorderResult, error) {
	if fromRegionID == "" {
		return nil, fmt.Errorf("source region ID is required")
	}
	if toRegionID == "" {
		return nil, fmt.Errorf("destination region ID is required")
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	fromRegion, ok := rc.regions[fromRegionID]
	if !ok {
		return nil, fmt.Errorf("source region not found: %s", fromRegionID)
	}

	if _, ok := rc.regions[toRegionID]; !ok {
		return nil, fmt.Errorf("destination region not found: %s", toRegionID)
	}

	// Same-region transfer is always permitted
	if fromRegionID == toRegionID {
		return &CrossBorderResult{
			Permitted:   true,
			Requirement: TransferNone,
			FromRegion:  fromRegionID,
			ToRegion:    toRegionID,
		}, nil
	}

	// Check if destination is in allowed list
	if !fromRegion.CanTransferTo(toRegionID) {
		return &CrossBorderResult{
			Permitted:   false,
			Requirement: TransferProhibited,
			FromRegion:  fromRegionID,
			ToRegion:    toRegionID,
			Conditions:  []string{"destination region is not in the allowed transfer list"},
		}, nil
	}

	req := fromRegion.GetTransferRequirement(toRegionID)
	if req == TransferProhibited {
		return &CrossBorderResult{
			Permitted:   false,
			Requirement: TransferProhibited,
			FromRegion:  fromRegionID,
			ToRegion:    toRegionID,
			Conditions:  []string{"cross-border transfer is prohibited between these jurisdictions"},
		}, nil
	}

	result := &CrossBorderResult{
		Permitted:   true,
		Requirement: req,
		FromRegion:  fromRegionID,
		ToRegion:    toRegionID,
	}

	switch req {
	case TransferSCCs:
		result.Conditions = append(result.Conditions,
			"Standard Contractual Clauses must be executed between parties",
			"data processing impact assessment required",
		)
	case TransferBCRs:
		result.Conditions = append(result.Conditions,
			"Binding Corporate Rules must be approved by supervisory authority",
		)
	case TransferConsent:
		result.Conditions = append(result.Conditions,
			"explicit data subject consent required for each transfer",
			"consent must be informed, specific, and freely given",
		)
	case TransferAdequacyDecision:
		result.Conditions = append(result.Conditions,
			"transfer permitted under existing adequacy decision",
		)
	}

	return result, nil
}

// SetPolicy assigns a data residency policy for the given policy ID.
func (rc *RegionController) SetPolicy(policyID string, policy *DataResidencyPolicy) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.policies[policyID] = policy
}

// GetPolicy retrieves a data residency policy by ID.
func (rc *RegionController) GetPolicy(policyID string) (*DataResidencyPolicy, error) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	policy, ok := rc.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	return policy, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (rc *RegionController) regionSatisfiesJob(region *Region, job ComputationJob, policy *DataResidencyPolicy) bool {
	// Check policy allows this region
	if policy != nil && !policy.IsRegionAllowed(region.ID) {
		return false
	}

	// Check all required capabilities
	for _, cap := range job.RequiredCapabilities {
		if !region.HasCapability(cap) {
			return false
		}
	}

	return true
}
