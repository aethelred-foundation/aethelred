package defense

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Defense Procurement Artifact Generation
// ---------------------------------------------------------------------------

// ProcurementGenerator produces structured defense procurement documents
// from compliance assessment data and platform configuration.
type ProcurementGenerator struct {
	organizationName string
	systemName       string
	assessor         *CMMCAssessor
}

// NewProcurementGenerator creates a generator for the given organization and system.
func NewProcurementGenerator(organizationName, systemName string) *ProcurementGenerator {
	return &ProcurementGenerator{
		organizationName: organizationName,
		systemName:       systemName,
		assessor:         NewCMMCAssessor(),
	}
}

// DD254Config holds input parameters for DD254 generation.
type DD254Config struct {
	ContractNumber     string    `json:"contract_number"`
	PrimeContractor    string    `json:"prime_contractor"`
	ClassificationLevel string   `json:"classification_level"`
	PerformancePeriod  string    `json:"performance_period"`
	FacilityClearance  string    `json:"facility_clearance"`
	SpecialAccess      []string  `json:"special_access"`
	GFEItems           []string  `json:"gfe_items"`
	IssuedDate         time.Time `json:"issued_date"`
}

// DD254 represents a Department of Defense Security Classification Specification.
type DD254 struct {
	// DocumentID uniquely identifies this DD254.
	DocumentID string `json:"document_id"`

	// ContractNumber is the associated contract.
	ContractNumber string `json:"contract_number"`

	// ContractorName is the performing organization.
	ContractorName string `json:"contractor_name"`

	// PrimeContractor is the prime contract holder.
	PrimeContractor string `json:"prime_contractor"`

	// ClassificationLevel is the highest level of classified information involved.
	ClassificationLevel string `json:"classification_level"`

	// PerformancePeriod describes the period of performance.
	PerformancePeriod string `json:"performance_period"`

	// FacilityClearance is the required facility clearance level.
	FacilityClearance string `json:"facility_clearance"`

	// SpecialAccessRequired lists any SAP/SCI requirements.
	SpecialAccessRequired []string `json:"special_access_required"`

	// GFEItems lists government-furnished equipment.
	GFEItems []string `json:"gfe_items"`

	// SecurityRequirements summarizes the security requirements.
	SecurityRequirements []string `json:"security_requirements"`

	// GeneratedAt records when this document was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// SystemName identifies the information system.
	SystemName string `json:"system_name"`
}

// GenerateDD254 produces a DD254 from the provided configuration.
func (g *ProcurementGenerator) GenerateDD254(_ context.Context, config DD254Config) (*DD254, error) {
	if config.ContractNumber == "" {
		return nil, fmt.Errorf("contract number is required")
	}
	if config.ClassificationLevel == "" {
		return nil, fmt.Errorf("classification level is required")
	}

	dd254 := &DD254{
		DocumentID:            fmt.Sprintf("DD254-%s-%d", config.ContractNumber, time.Now().UnixNano()),
		ContractNumber:        config.ContractNumber,
		ContractorName:        g.organizationName,
		PrimeContractor:       config.PrimeContractor,
		ClassificationLevel:   config.ClassificationLevel,
		PerformancePeriod:     config.PerformancePeriod,
		FacilityClearance:     config.FacilityClearance,
		SpecialAccessRequired: config.SpecialAccess,
		GFEItems:              config.GFEItems,
		GeneratedAt:           time.Now().UTC(),
		SystemName:            g.systemName,
		SecurityRequirements: []string{
			"All CUI must be processed within TEE-protected enclaves",
			"Cryptographic operations must use FIPS 140-3 validated modules",
			"Audit trails must be blockchain-anchored and tamper-evident",
			"Key material must be stored in HSM with PKCS#11 interface",
			"Network communications must use TLS 1.3 with post-quantum algorithms",
		},
	}

	return dd254, nil
}

// SSPConfig holds input parameters for System Security Plan generation.
type SSPConfig struct {
	SystemOwner          string   `json:"system_owner"`
	AuthorizingOfficial  string   `json:"authorizing_official"`
	SecurityOfficer      string   `json:"security_officer"`
	SystemBoundary       string   `json:"system_boundary"`
	DataTypes            []string `json:"data_types"`
	InterconnectedSystems []string `json:"interconnected_systems"`
	CMMCLevel            CMMCLevel `json:"cmmc_level"`
}

// SSP represents a System Security Plan.
type SSP struct {
	// DocumentID uniquely identifies this SSP.
	DocumentID string `json:"document_id"`

	// SystemName is the name of the information system.
	SystemName string `json:"system_name"`

	// OrganizationName is the responsible organization.
	OrganizationName string `json:"organization_name"`

	// SystemOwner is the system owner's name and title.
	SystemOwner string `json:"system_owner"`

	// AuthorizingOfficial is the AO responsible for authorization.
	AuthorizingOfficial string `json:"authorizing_official"`

	// SecurityOfficer is the information system security officer.
	SecurityOfficer string `json:"security_officer"`

	// SystemBoundary describes the authorization boundary.
	SystemBoundary string `json:"system_boundary"`

	// DataTypes lists types of data processed.
	DataTypes []string `json:"data_types"`

	// InterconnectedSystems lists systems with approved interconnections.
	InterconnectedSystems []string `json:"interconnected_systems"`

	// CMMCLevel is the target CMMC level.
	CMMCLevel CMMCLevel `json:"cmmc_level"`

	// ControlImplementation maps control IDs to implementation descriptions.
	ControlImplementation map[string]string `json:"control_implementation"`

	// GeneratedAt records when this SSP was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// Version is the SSP document version.
	Version string `json:"version"`
}

// GenerateSSP produces a System Security Plan.
func (g *ProcurementGenerator) GenerateSSP(ctx context.Context, config SSPConfig) (*SSP, error) {
	if config.SystemOwner == "" {
		return nil, fmt.Errorf("system owner is required")
	}
	if config.CMMCLevel < CMMCLevel1 || config.CMMCLevel > CMMCLevel3 {
		return nil, fmt.Errorf("invalid CMMC level: %d", config.CMMCLevel)
	}

	practices := g.assessor.GetRequiredPractices(config.CMMCLevel)
	controls := make(map[string]string, len(practices))
	for _, p := range practices {
		if p.AethelredMapping != "" {
			controls[p.ID] = p.AethelredMapping
		} else {
			controls[p.ID] = "Implementation pending"
		}
	}

	ssp := &SSP{
		DocumentID:            fmt.Sprintf("SSP-%d", time.Now().UnixNano()),
		SystemName:            g.systemName,
		OrganizationName:      g.organizationName,
		SystemOwner:           config.SystemOwner,
		AuthorizingOfficial:   config.AuthorizingOfficial,
		SecurityOfficer:       config.SecurityOfficer,
		SystemBoundary:        config.SystemBoundary,
		DataTypes:             config.DataTypes,
		InterconnectedSystems: config.InterconnectedSystems,
		CMMCLevel:             config.CMMCLevel,
		ControlImplementation: controls,
		GeneratedAt:           time.Now().UTC(),
		Version:               "1.0",
	}

	_ = ctx // reserved for future async operations
	return ssp, nil
}

// POAMItem represents a single Plan of Action and Milestones entry.
type POAMItem struct {
	// ID is the POAM item identifier.
	ID string `json:"id"`

	// ControlID references the control with a gap.
	ControlID string `json:"control_id"`

	// Weakness describes the identified gap.
	Weakness string `json:"weakness"`

	// MitigationPlan describes the planned remediation.
	MitigationPlan string `json:"mitigation_plan"`

	// Milestone is the target completion description.
	Milestone string `json:"milestone"`

	// ScheduledCompletion is the target completion date.
	ScheduledCompletion time.Time `json:"scheduled_completion"`

	// ResponsibleParty is the person or team responsible.
	ResponsibleParty string `json:"responsible_party"`

	// RiskLevel categorizes the severity.
	RiskLevel string `json:"risk_level"`

	// Status tracks the current state.
	Status string `json:"status"`
}

// POAM represents a Plan of Action and Milestones.
type POAM struct {
	// DocumentID uniquely identifies this POAM.
	DocumentID string `json:"document_id"`

	// SystemName is the system being assessed.
	SystemName string `json:"system_name"`

	// OrganizationName is the responsible organization.
	OrganizationName string `json:"organization_name"`

	// Items lists all POAM entries.
	Items []POAMItem `json:"items"`

	// GeneratedAt records when this POAM was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// TotalGaps is the number of gaps identified.
	TotalGaps int `json:"total_gaps"`
}

// GeneratePOAM creates a Plan of Action and Milestones from compliance gaps.
func (g *ProcurementGenerator) GeneratePOAM(_ context.Context, gaps []string) (*POAM, error) {
	if len(gaps) == 0 {
		return nil, fmt.Errorf("at least one gap is required to generate a POAM")
	}

	poam := &POAM{
		DocumentID:       fmt.Sprintf("POAM-%d", time.Now().UnixNano()),
		SystemName:       g.systemName,
		OrganizationName: g.organizationName,
		GeneratedAt:      time.Now().UTC(),
		TotalGaps:        len(gaps),
	}

	for i, gap := range gaps {
		item := POAMItem{
			ID:                  fmt.Sprintf("POAM-%d", i+1),
			ControlID:           gap,
			Weakness:            fmt.Sprintf("Control %s not fully implemented", gap),
			MitigationPlan:      fmt.Sprintf("Implement control %s with Aethelred platform capabilities", gap),
			Milestone:           "Control implementation and evidence collection",
			ScheduledCompletion: time.Now().UTC().AddDate(0, 3, 0),
			ResponsibleParty:    "Security Engineering",
			RiskLevel:           "Medium",
			Status:              "Open",
		}
		poam.Items = append(poam.Items, item)
	}

	return poam, nil
}

// ATOPackage represents an Authority to Operate package.
type ATOPackage struct {
	// DocumentID uniquely identifies this ATO package.
	DocumentID string `json:"document_id"`

	// SystemName is the system requesting authorization.
	SystemName string `json:"system_name"`

	// OrganizationName is the responsible organization.
	OrganizationName string `json:"organization_name"`

	// SSP is the System Security Plan.
	SSP *SSP `json:"ssp"`

	// POAM is the Plan of Action and Milestones (nil if no gaps).
	POAM *POAM `json:"poam,omitempty"`

	// Assessment is the CMMC compliance assessment.
	Assessment *CMMCAssessment `json:"assessment"`

	// RiskDetermination summarizes the overall risk posture.
	RiskDetermination string `json:"risk_determination"`

	// Recommendation is the authorization recommendation.
	Recommendation string `json:"recommendation"`

	// Artifacts lists all included artifacts by name.
	Artifacts []string `json:"artifacts"`

	// GeneratedAt records when this package was assembled.
	GeneratedAt time.Time `json:"generated_at"`
}

// GenerateATOPackage assembles a complete Authority to Operate package.
func (g *ProcurementGenerator) GenerateATOPackage(ctx context.Context) (*ATOPackage, error) {
	assessment, err := g.assessor.AssessCMMC(ctx, CMMCLevel2)
	if err != nil {
		return nil, fmt.Errorf("assessment failed: %w", err)
	}

	ssp, err := g.GenerateSSP(ctx, SSPConfig{
		SystemOwner: "System Owner",
		CMMCLevel:   CMMCLevel2,
		DataTypes:   []string{"CUI"},
	})
	if err != nil {
		return nil, fmt.Errorf("SSP generation failed: %w", err)
	}

	pkg := &ATOPackage{
		DocumentID:       fmt.Sprintf("ATO-%d", time.Now().UnixNano()),
		SystemName:       g.systemName,
		OrganizationName: g.organizationName,
		SSP:              ssp,
		Assessment:       assessment,
		GeneratedAt:      time.Now().UTC(),
		Artifacts: []string{
			"System Security Plan (SSP)",
			"CMMC Level 2 Assessment",
			"Network Diagram",
			"Data Flow Diagram",
		},
	}

	if len(assessment.Gaps) > 0 {
		poam, err := g.GeneratePOAM(ctx, assessment.Gaps)
		if err != nil {
			return nil, fmt.Errorf("POAM generation failed: %w", err)
		}
		pkg.POAM = poam
		pkg.Artifacts = append(pkg.Artifacts, "Plan of Action & Milestones (POA&M)")
		pkg.RiskDetermination = "Moderate"
		pkg.Recommendation = "Conditional Authorization with POA&M"
	} else {
		pkg.RiskDetermination = "Low"
		pkg.Recommendation = "Full Authorization"
	}

	return pkg, nil
}
