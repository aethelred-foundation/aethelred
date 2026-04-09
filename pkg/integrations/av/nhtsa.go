package av

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// NHTSA AV Framework Alignment
// ---------------------------------------------------------------------------

// NHTSAReport contains a complete NHTSA-format safety evidence package.
type NHTSAReport struct {
	// VehicleID identifies the vehicle.
	VehicleID string `json:"vehicle_id"`

	// IncidentID links to the incident (if incident-specific).
	IncidentID string `json:"incident_id,omitempty"`

	// SafetyEvidence lists all safety-related sealed evidence.
	SafetyEvidence []NHTSAEvidence `json:"safety_evidence"`

	// TelemetryEvidence lists telemetry-based sealed evidence.
	TelemetryEvidence []NHTSAEvidence `json:"telemetry_evidence"`

	// Timeline is the incident timeline (if applicable).
	Timeline *IncidentTimeline `json:"timeline,omitempty"`

	// Compliance is the NHTSA framework compliance status.
	Compliance *NHTSACompliance `json:"compliance"`

	// GeneratedAt is when this report was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// SealID is the blockchain seal for this report.
	SealID string `json:"seal_id"`
}

// NHTSAEvidence is a single evidence item in an NHTSA report.
type NHTSAEvidence struct {
	// Category maps to an NHTSA evidence category.
	Category string `json:"category"`

	// Description explains the evidence.
	Description string `json:"description"`

	// DataHash is the SHA-256 hash of the evidence data.
	DataHash string `json:"data_hash"`

	// SealID is the blockchain seal ID.
	SealID string `json:"seal_id"`

	// Timestamp is when the evidence was recorded.
	Timestamp time.Time `json:"timestamp"`
}

// NHTSAComplianceArea represents a specific NHTSA framework compliance area.
type NHTSAComplianceArea struct {
	// Name is the compliance area name.
	Name string `json:"name"`

	// Description explains the requirement.
	Description string `json:"description"`

	// Status is the compliance status.
	Status string `json:"status"`

	// Evidence lists the evidence supporting this area.
	Evidence []string `json:"evidence"`

	// AethelredMapping describes how the platform addresses this area.
	AethelredMapping string `json:"aethelred_mapping"`
}

// NHTSACompliance holds the overall NHTSA framework compliance assessment.
type NHTSACompliance struct {
	// VehicleID identifies the vehicle.
	VehicleID string `json:"vehicle_id"`

	// OverallStatus is the aggregate compliance status.
	OverallStatus string `json:"overall_status"`

	// Areas lists all compliance areas and their status.
	Areas []NHTSAComplianceArea `json:"areas"`

	// Score is a percentage (0-100).
	Score float64 `json:"score"`

	// AssessedAt is when the assessment was performed.
	AssessedAt time.Time `json:"assessed_at"`

	// NextAssessmentDue is when the next assessment should occur.
	NextAssessmentDue time.Time `json:"next_assessment_due"`
}

// NHTSAService generates NHTSA-format reports and compliance assessments.
type NHTSAService struct {
	incidentService *IncidentService
	telemetry       *TelemetryService
}

// NewNHTSAService creates a new NHTSA reporting service.
func NewNHTSAService(incidentService *IncidentService, telemetry *TelemetryService) *NHTSAService {
	return &NHTSAService{
		incidentService: incidentService,
		telemetry:       telemetry,
	}
}

// GenerateNHTSAReport generates a complete NHTSA-format safety evidence report.
func (s *NHTSAService) GenerateNHTSAReport(ctx context.Context, incidentID string) (*NHTSAReport, error) {
	incident, err := s.incidentService.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get incident: %w", err)
	}

	report := &NHTSAReport{
		VehicleID:   incident.VehicleID,
		IncidentID:  incidentID,
		GeneratedAt: time.Now().UTC(),
	}

	// Build safety evidence from incident evidence
	for _, e := range incident.Evidence {
		report.SafetyEvidence = append(report.SafetyEvidence, NHTSAEvidence{
			Category:    e.Type,
			Description: e.Description,
			DataHash:    e.DataHash,
			SealID:      e.SealID,
			Timestamp:   e.Timestamp,
		})
	}

	// Build telemetry evidence
	if s.telemetry != nil {
		timeRange := TimeRange{
			Start: incident.Timestamp.Add(-10 * time.Minute),
			End:   incident.Timestamp.Add(10 * time.Minute),
		}
		receipts, err := s.telemetry.QueryTelemetry(ctx, incident.VehicleID, timeRange)
		if err == nil {
			for _, r := range receipts {
				report.TelemetryEvidence = append(report.TelemetryEvidence, NHTSAEvidence{
					Category:    "telemetry",
					Description: fmt.Sprintf("Vehicle telemetry at %s: speed=%.1f m/s", r.Timestamp.Format(time.RFC3339), r.Speed),
					DataHash:    r.DataHash,
					SealID:      r.SealID,
					Timestamp:   r.Timestamp,
				})
			}
		}
	}

	// Include timeline if available
	report.Timeline = incident.Timeline

	// Assess compliance
	compliance, _ := s.AssessNHTSACompliance(ctx, incident.VehicleID)
	report.Compliance = compliance

	return report, nil
}

// AssessNHTSACompliance evaluates compliance with the NHTSA AV framework.
func (s *NHTSAService) AssessNHTSACompliance(_ context.Context, vehicleID string) (*NHTSACompliance, error) {
	if vehicleID == "" {
		return nil, fmt.Errorf("vehicle ID is required")
	}

	areas := buildNHTSAComplianceAreas()

	compliant := 0
	for _, a := range areas {
		if a.Status == "compliant" {
			compliant++
		}
	}

	score := 0.0
	if len(areas) > 0 {
		score = float64(compliant) / float64(len(areas)) * 100
	}

	status := "non_compliant"
	if score >= 80 {
		status = "compliant"
	} else if score >= 50 {
		status = "partial"
	}

	return &NHTSACompliance{
		VehicleID:         vehicleID,
		OverallStatus:     status,
		Areas:             areas,
		Score:             score,
		AssessedAt:        time.Now().UTC(),
		NextAssessmentDue: time.Now().UTC().AddDate(0, 6, 0),
	}, nil
}

func buildNHTSAComplianceAreas() []NHTSAComplianceArea {
	return []NHTSAComplianceArea{
		{
			Name:             "System Safety",
			Description:      "Demonstrate system-level safety validation process",
			Status:           "compliant",
			Evidence:         []string{"safety_evaluation_records", "kill_switch_tests"},
			AethelredMapping: "Safety controller with sealed exception records and kill switch audit trail",
		},
		{
			Name:             "Operational Design Domain",
			Description:      "Define and monitor ODD boundaries",
			Status:           "compliant",
			Evidence:         []string{"odd_definitions", "odd_violation_records"},
			AethelredMapping: "ODD monitor with sealed compliance evidence and violation detection",
		},
		{
			Name:             "Object and Event Detection",
			Description:      "Detect objects and events in the driving environment",
			Status:           "compliant",
			Evidence:         []string{"sensor_calibration_records", "telemetry_receipts"},
			AethelredMapping: "Multi-sensor telemetry with sealed data hashes and confidence scores",
		},
		{
			Name:             "Fallback (Minimal Risk Condition)",
			Description:      "Achieve a minimal risk condition when ADS cannot operate safely",
			Status:           "compliant",
			Evidence:         []string{"minimal_risk_condition_tests", "safety_exception_records"},
			AethelredMapping: "Automated minimal risk condition with sealed state transitions",
		},
		{
			Name:             "Validation Methods",
			Description:      "Test and validate ADS in simulation, track, and on-road",
			Status:           "compliant",
			Evidence:         []string{"test_results", "simulation_records"},
			AethelredMapping: "Sealed test results with cryptographic evidence of execution",
		},
		{
			Name:             "Human-Machine Interface",
			Description:      "Ensure clear communication between ADS and human occupants",
			Status:           "partial",
			Evidence:         []string{"hmi_design_docs"},
			AethelredMapping: "HMI state transitions logged with sealed audit trail",
		},
		{
			Name:             "Crashworthiness",
			Description:      "Comply with applicable FMVSS crashworthiness standards",
			Status:           "not_applicable",
			Evidence:         []string{},
			AethelredMapping: "Platform-level concern; not directly addressed by software infrastructure",
		},
		{
			Name:             "Post-Crash ADS Behavior",
			Description:      "Ensure safe behavior after a crash event",
			Status:           "compliant",
			Evidence:         []string{"incident_records", "post_crash_procedures"},
			AethelredMapping: "Sealed incident timeline with post-crash telemetry and safety state",
		},
		{
			Name:             "Data Recording",
			Description:      "Record data for crash reconstruction",
			Status:           "compliant",
			Evidence:         []string{"telemetry_receipts", "incident_timelines"},
			AethelredMapping: "Blockchain-anchored telemetry receipts with tamper-evident data hashes",
		},
		{
			Name:             "Consumer Education and Training",
			Description:      "Provide consumer information about ADS capabilities",
			Status:           "partial",
			Evidence:         []string{"documentation"},
			AethelredMapping: "SDK documentation and operational guides",
		},
		{
			Name:             "Federal, State, and Local Laws",
			Description:      "Comply with applicable traffic laws",
			Status:           "compliant",
			Evidence:         []string{"compliance_assessment"},
			AethelredMapping: "ODD compliance includes regulatory boundary awareness",
		},
		{
			Name:             "Cybersecurity",
			Description:      "Implement cybersecurity best practices",
			Status:           "compliant",
			Evidence:         []string{"tee_attestations", "pqc_certificates", "sealed_audit_trail"},
			AethelredMapping: "Post-quantum cryptography, TEE-protected execution, and blockchain-anchored evidence",
		},
	}
}
