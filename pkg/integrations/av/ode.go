package av

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Operational Design Domain (ODD)
// ---------------------------------------------------------------------------

// RoadType classifies types of roadway.
type RoadType string

const (
	RoadHighway    RoadType = "highway"
	RoadUrban      RoadType = "urban"
	RoadSuburban   RoadType = "suburban"
	RoadRural      RoadType = "rural"
	RoadParking    RoadType = "parking"
	RoadPrivate    RoadType = "private"
)

// WeatherCondition describes weather limits.
type WeatherCondition string

const (
	WeatherClear      WeatherCondition = "clear"
	WeatherRain       WeatherCondition = "rain"
	WeatherSnow       WeatherCondition = "snow"
	WeatherFog        WeatherCondition = "fog"
	WeatherIce        WeatherCondition = "ice"
	WeatherHeavyRain  WeatherCondition = "heavy_rain"
	WeatherHeavySnow  WeatherCondition = "heavy_snow"
)

// TimeOfDayCondition describes time-of-day limits.
type TimeOfDayCondition string

const (
	TimeDay       TimeOfDayCondition = "day"
	TimeNight     TimeOfDayCondition = "night"
	TimeDusk      TimeOfDayCondition = "dusk"
	TimeDawn      TimeOfDayCondition = "dawn"
	TimeAllHours  TimeOfDayCondition = "all_hours"
)

// TrafficCondition describes traffic density limits.
type TrafficCondition string

const (
	TrafficFreeFlow  TrafficCondition = "free_flow"
	TrafficModerate  TrafficCondition = "moderate"
	TrafficHeavy     TrafficCondition = "heavy"
	TrafficStop      TrafficCondition = "stop_and_go"
)

// GeographicBoundary defines the geographic limits of an ODD.
type GeographicBoundary struct {
	// CenterLat is the center latitude.
	CenterLat float64 `json:"center_lat"`

	// CenterLon is the center longitude.
	CenterLon float64 `json:"center_lon"`

	// RadiusKm is the radius in kilometers.
	RadiusKm float64 `json:"radius_km"`

	// GeoFencePoints defines a polygon boundary (optional).
	GeoFencePoints []Location `json:"geo_fence_points,omitempty"`
}

// SpeedLimit defines speed constraints.
type SpeedLimit struct {
	// MinSpeedMPS is the minimum speed in meters per second.
	MinSpeedMPS float64 `json:"min_speed_mps"`

	// MaxSpeedMPS is the maximum speed in meters per second.
	MaxSpeedMPS float64 `json:"max_speed_mps"`
}

// ODD defines an Operational Design Domain for an autonomous vehicle.
type ODD struct {
	// ID uniquely identifies this ODD.
	ID string `json:"id"`

	// Name is a human-readable name.
	Name string `json:"name"`

	// Description explains the ODD scope.
	Description string `json:"description"`

	// GeographicBoundary defines where the ODD is valid.
	GeographicBoundary GeographicBoundary `json:"geographic_boundary"`

	// RoadTypes lists the types of roads in this ODD.
	RoadTypes []RoadType `json:"road_types"`

	// SpeedLimits defines the speed constraints.
	SpeedLimits SpeedLimit `json:"speed_limits"`

	// WeatherConditions lists acceptable weather conditions.
	WeatherConditions []WeatherCondition `json:"weather_conditions"`

	// TimeOfDay lists acceptable time-of-day conditions.
	TimeOfDay []TimeOfDayCondition `json:"time_of_day"`

	// TrafficConditions lists acceptable traffic conditions.
	TrafficConditions []TrafficCondition `json:"traffic_conditions"`

	// Version is the ODD definition version.
	Version string `json:"version"`

	// EffectiveDate is when this ODD becomes active.
	EffectiveDate time.Time `json:"effective_date"`

	// ExpiryDate is when this ODD definition expires (zero for no expiry).
	ExpiryDate time.Time `json:"expiry_date,omitempty"`
}

// ODDViolation records a detected ODD boundary violation.
type ODDViolation struct {
	// ID uniquely identifies this violation.
	ID string `json:"id"`

	// ODDID identifies the ODD that was violated.
	ODDID string `json:"odd_id"`

	// Condition describes which ODD condition was violated.
	Condition string `json:"condition"`

	// Actual describes the actual conditions at the time.
	Actual string `json:"actual"`

	// Timestamp is when the violation was detected.
	Timestamp time.Time `json:"timestamp"`

	// VehicleID identifies the vehicle.
	VehicleID string `json:"vehicle_id"`

	// Location is where the violation occurred.
	Location Location `json:"location"`

	// SealID links to the sealed violation record.
	SealID string `json:"seal_id"`

	// Severity indicates how far outside the ODD the vehicle was.
	Severity string `json:"severity"`
}

// ODDEvidence records evidence of ODD compliance over a duration.
type ODDEvidence struct {
	// ID uniquely identifies this evidence record.
	ID string `json:"id"`

	// VehicleID identifies the vehicle.
	VehicleID string `json:"vehicle_id"`

	// ODDID identifies the ODD.
	ODDID string `json:"odd_id"`

	// StartTime is the start of the compliance window.
	StartTime time.Time `json:"start_time"`

	// EndTime is the end of the compliance window.
	EndTime time.Time `json:"end_time"`

	// Duration is the length of the compliance window.
	Duration time.Duration `json:"duration"`

	// Compliant indicates whether the vehicle stayed within the ODD.
	Compliant bool `json:"compliant"`

	// Violations lists any violations during the window.
	Violations []ODDViolation `json:"violations"`

	// SealID links to the sealed evidence.
	SealID string `json:"seal_id"`

	// GeneratedAt is when this evidence was generated.
	GeneratedAt time.Time `json:"generated_at"`
}

// ODDMonitor provides continuous monitoring of ODD compliance.
type ODDMonitor struct {
	mu         sync.RWMutex
	odds       map[string]*ODD
	violations map[string]*ODDViolation
	evidence   map[string]*ODDEvidence
}

// NewODDMonitor creates a new ODD monitor.
func NewODDMonitor() *ODDMonitor {
	return &ODDMonitor{
		odds:       make(map[string]*ODD),
		violations: make(map[string]*ODDViolation),
		evidence:   make(map[string]*ODDEvidence),
	}
}

// RegisterODD registers an ODD definition.
func (m *ODDMonitor) RegisterODD(_ context.Context, odd *ODD) error {
	if odd == nil {
		return fmt.Errorf("ODD is required")
	}
	if odd.ID == "" {
		return fmt.Errorf("ODD ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.odds[odd.ID] = odd
	return nil
}

// ValidateODD checks whether current telemetry is within the specified ODD.
func (m *ODDMonitor) ValidateODD(_ context.Context, telemetry *TelemetryReceipt, odd *ODD) ([]ODDViolation, error) {
	if telemetry == nil {
		return nil, fmt.Errorf("telemetry is required")
	}
	if odd == nil {
		return nil, fmt.Errorf("ODD is required")
	}

	var violations []ODDViolation

	// Check speed limits
	if telemetry.Speed < odd.SpeedLimits.MinSpeedMPS {
		violations = append(violations, ODDViolation{
			ID:        fmt.Sprintf("viol-%d", time.Now().UnixNano()),
			ODDID:     odd.ID,
			Condition: "speed_min",
			Actual:    fmt.Sprintf("%.1f m/s (min: %.1f)", telemetry.Speed, odd.SpeedLimits.MinSpeedMPS),
			Timestamp: telemetry.Timestamp,
			VehicleID: telemetry.VehicleID,
			Location:  telemetry.Location,
			Severity:  "minor",
		})
	}
	if odd.SpeedLimits.MaxSpeedMPS > 0 && telemetry.Speed > odd.SpeedLimits.MaxSpeedMPS {
		violations = append(violations, ODDViolation{
			ID:        fmt.Sprintf("viol-%d", time.Now().UnixNano()),
			ODDID:     odd.ID,
			Condition: "speed_max",
			Actual:    fmt.Sprintf("%.1f m/s (max: %.1f)", telemetry.Speed, odd.SpeedLimits.MaxSpeedMPS),
			Timestamp: telemetry.Timestamp,
			VehicleID: telemetry.VehicleID,
			Location:  telemetry.Location,
			Severity:  "major",
		})
	}

	// Check geographic boundary (simple radius check)
	if odd.GeographicBoundary.RadiusKm > 0 {
		dist := haversineDistance(
			telemetry.Location.Latitude, telemetry.Location.Longitude,
			odd.GeographicBoundary.CenterLat, odd.GeographicBoundary.CenterLon,
		)
		if dist > odd.GeographicBoundary.RadiusKm {
			violations = append(violations, ODDViolation{
				ID:        fmt.Sprintf("viol-%d", time.Now().UnixNano()),
				ODDID:     odd.ID,
				Condition: "geographic_boundary",
				Actual:    fmt.Sprintf("%.2f km from center (max: %.2f)", dist, odd.GeographicBoundary.RadiusKm),
				Timestamp: telemetry.Timestamp,
				VehicleID: telemetry.VehicleID,
				Location:  telemetry.Location,
				Severity:  "critical",
			})
		}
	}

	// Store violations
	m.mu.Lock()
	for i := range violations {
		m.violations[violations[i].ID] = &violations[i]
	}
	m.mu.Unlock()

	return violations, nil
}

// SealODDEvidence creates sealed evidence of ODD compliance over a duration.
func (m *ODDMonitor) SealODDEvidence(_ context.Context, vehicleID string, odd *ODD, duration time.Duration) (*ODDEvidence, error) {
	if vehicleID == "" {
		return nil, fmt.Errorf("vehicle ID is required")
	}
	if odd == nil {
		return nil, fmt.Errorf("ODD is required")
	}

	m.mu.RLock()
	var vehicleViolations []ODDViolation
	for _, v := range m.violations {
		if v.VehicleID == vehicleID && v.ODDID == odd.ID {
			vehicleViolations = append(vehicleViolations, *v)
		}
	}
	m.mu.RUnlock()

	now := time.Now().UTC()
	evidence := &ODDEvidence{
		ID:          fmt.Sprintf("odd-ev-%s-%d", vehicleID, now.UnixNano()),
		VehicleID:   vehicleID,
		ODDID:       odd.ID,
		StartTime:   now.Add(-duration),
		EndTime:     now,
		Duration:    duration,
		Compliant:   len(vehicleViolations) == 0,
		Violations:  vehicleViolations,
		GeneratedAt: now,
	}

	m.mu.Lock()
	m.evidence[evidence.ID] = evidence
	m.mu.Unlock()

	return evidence, nil
}

// GetODD retrieves an ODD by ID.
func (m *ODDMonitor) GetODD(_ context.Context, oddID string) (*ODD, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	odd, ok := m.odds[oddID]
	if !ok {
		return nil, fmt.Errorf("ODD not found: %s", oddID)
	}
	return odd, nil
}

// haversineDistance computes the distance in km between two lat/lon pairs.
// Simplified formula using the Haversine method.
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}
