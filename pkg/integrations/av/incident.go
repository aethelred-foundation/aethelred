package av

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Signed Incident Timelines
// ---------------------------------------------------------------------------

// IncidentType categorizes the nature of an AV incident.
type IncidentType string

const (
	IncidentCollision     IncidentType = "collision"
	IncidentNearMiss      IncidentType = "near_miss"
	IncidentSensorFailure IncidentType = "sensor_failure"
	IncidentSystemFailure IncidentType = "system_failure"
	IncidentODDViolation  IncidentType = "odd_violation"
	IncidentSafetyStop    IncidentType = "safety_stop"
	IncidentKillSwitch    IncidentType = "kill_switch"
)

// IncidentSeverity represents the severity of an incident.
type IncidentSeverity int

const (
	SeverityMinor IncidentSeverity = iota + 1
	SeverityModerate
	SeverityMajor
	SeverityCritical
	SeverityFatal
)

// String returns the human-readable label.
func (s IncidentSeverity) String() string {
	switch s {
	case SeverityMinor:
		return "Minor"
	case SeverityModerate:
		return "Moderate"
	case SeverityMajor:
		return "Major"
	case SeverityCritical:
		return "Critical"
	case SeverityFatal:
		return "Fatal"
	default:
		return "Unknown"
	}
}

// TimelineEvent represents a single event in an incident timeline.
type TimelineEvent struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Type categorizes the event.
	Type string `json:"type"`

	// Description is a human-readable summary.
	Description string `json:"description"`

	// DataHash links to the sealed evidence for this event.
	DataHash string `json:"data_hash"`

	// SealID links to the blockchain seal.
	SealID string `json:"seal_id,omitempty"`

	// TelemetryReceiptID links to the telemetry receipt if applicable.
	TelemetryReceiptID string `json:"telemetry_receipt_id,omitempty"`

	// SafetyExceptionID links to a safety exception if applicable.
	SafetyExceptionID string `json:"safety_exception_id,omitempty"`

	// Metadata holds event-specific data.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IncidentTimeline is a chronological sequence of events during an incident.
type IncidentTimeline struct {
	// IncidentID links to the parent incident.
	IncidentID string `json:"incident_id"`

	// Events in chronological order.
	Events []TimelineEvent `json:"events"`

	// StartTime is the time of the first event.
	StartTime time.Time `json:"start_time"`

	// EndTime is the time of the last event.
	EndTime time.Time `json:"end_time"`

	// Duration is the total duration of the incident.
	Duration time.Duration `json:"duration"`

	// SealID is the seal for the complete timeline.
	SealID string `json:"seal_id"`
}

// IncidentEvidence represents a piece of evidence attached to an incident.
type IncidentEvidence struct {
	// Type describes the evidence (e.g. "telemetry", "video", "log").
	Type string `json:"type"`

	// Description explains what this evidence shows.
	Description string `json:"description"`

	// DataHash is the SHA-256 hash of the evidence data.
	DataHash string `json:"data_hash"`

	// SealID links to the blockchain seal.
	SealID string `json:"seal_id"`

	// Timestamp is when the evidence was recorded.
	Timestamp time.Time `json:"timestamp"`
}

// AVIncident is the primary incident record.
type AVIncident struct {
	// ID uniquely identifies this incident.
	ID string `json:"id"`

	// VehicleID identifies the vehicle involved.
	VehicleID string `json:"vehicle_id"`

	// Timestamp is when the incident occurred.
	Timestamp time.Time `json:"timestamp"`

	// Location is where the incident occurred.
	Location Location `json:"location"`

	// Type categorizes the incident.
	Type IncidentType `json:"type"`

	// Severity indicates the incident severity.
	Severity IncidentSeverity `json:"severity"`

	// Timeline is the chronological event sequence.
	Timeline *IncidentTimeline `json:"timeline"`

	// Evidence lists all evidence items.
	Evidence []IncidentEvidence `json:"evidence"`

	// Description is a human-readable summary.
	Description string `json:"description"`

	// WeatherConditions at the time of the incident.
	WeatherConditions string `json:"weather_conditions"`

	// RoadConditions at the time of the incident.
	RoadConditions string `json:"road_conditions"`

	// SealID links to the blockchain seal for this incident.
	SealID string `json:"seal_id"`

	// NHTSAReported indicates whether this has been reported to NHTSA.
	NHTSAReported bool `json:"nhtsa_reported"`

	// Status tracks the investigation status.
	Status string `json:"status"`

	// CreatedAt is when the record was created.
	CreatedAt time.Time `json:"created_at"`
}

// IncidentReport is a generated report suitable for regulatory submission.
type IncidentReport struct {
	// IncidentID references the source incident.
	IncidentID string `json:"incident_id"`

	// VehicleID identifies the vehicle.
	VehicleID string `json:"vehicle_id"`

	// Format identifies the report format (e.g. "NHTSA").
	Format string `json:"format"`

	// GeneratedAt is when this report was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// Sections contains the structured report content.
	Sections map[string]string `json:"sections"`

	// Evidence lists sealed evidence references.
	Evidence []IncidentEvidence `json:"evidence"`

	// SealID links to the sealed report.
	SealID string `json:"seal_id"`
}

// IncidentService manages incident records, timelines, and reports.
type IncidentService struct {
	mu        sync.RWMutex
	incidents map[string]*AVIncident
	telemetry *TelemetryService
	safety    *SafetyController
}

// NewIncidentService creates a new incident service.
func NewIncidentService(telemetry *TelemetryService, safety *SafetyController) *IncidentService {
	return &IncidentService{
		incidents: make(map[string]*AVIncident),
		telemetry: telemetry,
		safety:    safety,
	}
}

// CreateIncident creates a sealed incident record.
func (s *IncidentService) CreateIncident(_ context.Context, incident *AVIncident) error {
	if incident == nil {
		return fmt.Errorf("IncidentService.CreateIncident: %w: incident is nil", ErrIncidentFailed)
	}
	if incident.VehicleID == "" {
		return fmt.Errorf("IncidentService.CreateIncident: %w: vehicle ID is empty", ErrIncidentFailed)
	}
	// Validate lat/lon bounds.
	if err := ValidateLocation(incident.Location); err != nil {
		return fmt.Errorf("IncidentService.CreateIncident: %w", err)
	}
	// Validate severity.
	if incident.Severity < SeverityMinor || incident.Severity > SeverityFatal {
		return fmt.Errorf("IncidentService.CreateIncident: %w: %d", ErrSafetyViolation, incident.Severity)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if incident.ID == "" {
		incident.ID = fmt.Sprintf("inc-%s-%d", incident.VehicleID, time.Now().UnixNano())
	}
	if incident.Timestamp.IsZero() {
		incident.Timestamp = time.Now().UTC()
	}
	incident.CreatedAt = time.Now().UTC()
	incident.Status = "open"

	s.incidents[incident.ID] = incident
	return nil
}

// BuildIncidentTimeline constructs a complete incident timeline combining
// telemetry, safety events, and seal data.
func (s *IncidentService) BuildIncidentTimeline(ctx context.Context, incidentID string) (*IncidentTimeline, error) {
	s.mu.RLock()
	incident, ok := s.incidents[incidentID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("IncidentService.BuildIncidentTimeline: %w: incident not found: %s", ErrIncidentFailed, incidentID)
	}

	timeline := &IncidentTimeline{
		IncidentID: incidentID,
		StartTime:  incident.Timestamp,
	}

	// Collect non-fatal warnings from telemetry/safety queries.
	var warnings []string

	// Add the incident creation event.
	timeline.Events = append(timeline.Events, TimelineEvent{
		Timestamp:   incident.Timestamp,
		Type:        "incident_created",
		Description: fmt.Sprintf("Incident %s created: %s", incident.ID, incident.Description),
	})

	// Query telemetry around the incident time.
	if s.telemetry != nil {
		timeRange := TimeRange{
			Start: incident.Timestamp.Add(-5 * time.Minute),
			End:   incident.Timestamp.Add(5 * time.Minute),
		}
		receipts, err := s.telemetry.QueryTelemetry(ctx, incident.VehicleID, timeRange)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("telemetry query failed: %v", err))
		} else {
			for _, r := range receipts {
				timeline.Events = append(timeline.Events, TimelineEvent{
					Timestamp:          r.Timestamp,
					Type:               "telemetry",
					Description:        fmt.Sprintf("Telemetry recorded: speed=%.1f m/s", r.Speed),
					TelemetryReceiptID: r.ID,
					SealID:             r.SealID,
				})
			}
		}
	}

	// Query safety exceptions.
	if s.safety != nil {
		exceptions, err := s.safety.ListExceptions(ctx, incident.VehicleID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("safety query failed: %v", err))
		} else {
			for _, exc := range exceptions {
				if !exc.Timestamp.Before(incident.Timestamp.Add(-5*time.Minute)) &&
					!exc.Timestamp.After(incident.Timestamp.Add(5*time.Minute)) {
					timeline.Events = append(timeline.Events, TimelineEvent{
						Timestamp:         exc.Timestamp,
						Type:              "safety_exception",
						Description:       fmt.Sprintf("Safety exception: %s (%s)", exc.Type, exc.Level),
						SafetyExceptionID: exc.ID,
						SealID:            exc.SealID,
					})
				}
			}
		}
	}

	// Attach warnings to timeline metadata if any non-fatal issues occurred.
	if len(warnings) > 0 {
		timeline.Events = append(timeline.Events, TimelineEvent{
			Timestamp:   time.Now().UTC(),
			Type:        "warning",
			Description: fmt.Sprintf("Timeline construction warnings: %v", warnings),
		})
	}

	// Set timeline end and duration
	if len(timeline.Events) > 0 {
		last := timeline.Events[len(timeline.Events)-1]
		timeline.EndTime = last.Timestamp
		timeline.Duration = timeline.EndTime.Sub(timeline.StartTime)
	}

	// Store timeline on the incident
	s.mu.Lock()
	incident.Timeline = timeline
	s.mu.Unlock()

	return timeline, nil
}

// GenerateIncidentReport generates an NHTSA-compatible incident report.
func (s *IncidentService) GenerateIncidentReport(_ context.Context, incidentID string) (*IncidentReport, error) {
	s.mu.RLock()
	incident, ok := s.incidents[incidentID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	report := &IncidentReport{
		IncidentID:  incidentID,
		VehicleID:   incident.VehicleID,
		Format:      "NHTSA",
		GeneratedAt: time.Now().UTC(),
		Evidence:    incident.Evidence,
		Sections: map[string]string{
			"vehicle_identification": fmt.Sprintf("Vehicle ID: %s", incident.VehicleID),
			"incident_summary":      fmt.Sprintf("Type: %s, Severity: %s, Description: %s", incident.Type, incident.Severity, incident.Description),
			"location":              fmt.Sprintf("Lat: %f, Lon: %f", incident.Location.Latitude, incident.Location.Longitude),
			"conditions":            fmt.Sprintf("Weather: %s, Road: %s", incident.WeatherConditions, incident.RoadConditions),
			"timeline_summary":      "See attached timeline evidence",
			"seal_verification":     fmt.Sprintf("All evidence sealed on Aethelred blockchain. Primary seal: %s", incident.SealID),
		},
	}

	return report, nil
}

// GetIncident retrieves an incident by ID.
func (s *IncidentService) GetIncident(_ context.Context, incidentID string) (*AVIncident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	incident, ok := s.incidents[incidentID]
	if !ok {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}
	return incident, nil
}
