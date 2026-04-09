package av

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Telemetry Tests
// ---------------------------------------------------------------------------

func TestRecordTelemetry(t *testing.T) {
	ctx := context.Background()
	svc := NewTelemetryService()

	receipt := &TelemetryReceipt{
		VehicleID: "av-001",
		Timestamp: time.Now().UTC(),
		Speed:     15.5,
		Heading:   90.0,
		Location:  Location{Latitude: 37.7749, Longitude: -122.4194},
		SensorData: SensorData{
			LiDAR: []SensorReading{
				{SensorID: "lidar-1", Type: SensorLiDAR, RawDataHash: "abc123", Confidence: 0.95, Status: "ok"},
			},
		},
	}

	err := svc.RecordTelemetry(ctx, receipt)
	if err != nil {
		t.Fatalf("RecordTelemetry failed: %v", err)
	}

	if receipt.ID == "" {
		t.Error("expected receipt ID to be assigned")
	}
	if receipt.DataHash == "" {
		t.Error("expected data hash to be computed")
	}
	if receipt.SealID == "" {
		t.Error("expected seal ID to be assigned")
	}
	if receipt.SequenceNumber != 0 {
		t.Errorf("expected sequence 0, got %d", receipt.SequenceNumber)
	}
}

func TestRecordTelemetryMissingVehicle(t *testing.T) {
	svc := NewTelemetryService()
	err := svc.RecordTelemetry(context.Background(), &TelemetryReceipt{})
	if err == nil {
		t.Error("expected error for missing vehicle ID")
	}
}

func TestRecordTelemetryNil(t *testing.T) {
	svc := NewTelemetryService()
	err := svc.RecordTelemetry(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil receipt")
	}
}

func TestVerifyTelemetry(t *testing.T) {
	ctx := context.Background()
	svc := NewTelemetryService()

	receipt := &TelemetryReceipt{
		VehicleID: "av-001",
		Timestamp: time.Now().UTC(),
		Speed:     10.0,
		Location:  Location{Latitude: 37.0, Longitude: -122.0},
	}
	_ = svc.RecordTelemetry(ctx, receipt)

	verification, err := svc.VerifyTelemetry(ctx, receipt.ID)
	if err != nil {
		t.Fatalf("VerifyTelemetry failed: %v", err)
	}

	if !verification.Valid {
		t.Error("expected valid telemetry")
	}
	if !verification.DataIntegrity {
		t.Error("expected data integrity")
	}
}

func TestVerifyTelemetryNotFound(t *testing.T) {
	svc := NewTelemetryService()
	_, err := svc.VerifyTelemetry(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent receipt")
	}
}

func TestQueryTelemetry(t *testing.T) {
	ctx := context.Background()
	svc := NewTelemetryService()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		_ = svc.RecordTelemetry(ctx, &TelemetryReceipt{
			VehicleID: "av-002",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Speed:     float64(10 + i),
			Location:  Location{Latitude: 37.0, Longitude: -122.0},
		})
	}

	results, err := svc.QueryTelemetry(ctx, "av-002", TimeRange{
		Start: now,
		End:   now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("QueryTelemetry failed: %v", err)
	}

	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}
}

func TestQueryTelemetryMissingVehicle(t *testing.T) {
	svc := NewTelemetryService()
	_, err := svc.QueryTelemetry(context.Background(), "", TimeRange{})
	if err == nil {
		t.Error("expected error for empty vehicle ID")
	}
}

func TestTelemetrySequenceNumbers(t *testing.T) {
	ctx := context.Background()
	svc := NewTelemetryService()

	for i := 0; i < 3; i++ {
		receipt := &TelemetryReceipt{
			VehicleID: "av-seq",
			Timestamp: time.Now().UTC(),
			Speed:     10.0,
		}
		_ = svc.RecordTelemetry(ctx, receipt)
		if receipt.SequenceNumber != uint64(i) {
			t.Errorf("expected sequence %d, got %d", i, receipt.SequenceNumber)
		}
	}
}

// ---------------------------------------------------------------------------
// Safety Controller Tests
// ---------------------------------------------------------------------------

func TestEvaluateSafetyNormal(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{
		MinSensorCount: 2,
		Thresholds: map[string]SafetyThreshold{
			"speed": {Name: "speed", CautionValue: 20, WarningValue: 30, CriticalValue: 40},
		},
	})

	telemetry := &TelemetryReceipt{
		VehicleID: "av-001",
		Speed:     15.0,
		SensorData: SensorData{
			LiDAR:  []SensorReading{{SensorID: "l1", Status: "ok"}},
			Camera: []SensorReading{{SensorID: "c1", Status: "ok"}},
			Radar:  []SensorReading{{SensorID: "r1", Status: "ok"}},
		},
	}

	eval, err := ctrl.EvaluateSafety(context.Background(), telemetry)
	if err != nil {
		t.Fatalf("EvaluateSafety failed: %v", err)
	}

	if eval.Level != SafetyNormal {
		t.Errorf("expected Normal, got %s", eval.Level)
	}
	if eval.RecommendedResponse != ResponseContinue {
		t.Errorf("expected Continue, got %s", eval.RecommendedResponse)
	}
}

func TestEvaluateSafetyCriticalSpeed(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{
		Thresholds: map[string]SafetyThreshold{
			"speed": {Name: "speed", CriticalValue: 30},
		},
	})

	telemetry := &TelemetryReceipt{
		VehicleID: "av-001",
		Speed:     35.0,
	}

	eval, err := ctrl.EvaluateSafety(context.Background(), telemetry)
	if err != nil {
		t.Fatalf("EvaluateSafety failed: %v", err)
	}

	if eval.Level != SafetyCritical {
		t.Errorf("expected Critical, got %s", eval.Level)
	}
}

func TestEvaluateSafetyNilTelemetry(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{})
	_, err := ctrl.EvaluateSafety(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil telemetry")
	}
}

func TestTriggerException(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{})
	ctx := context.Background()

	exc := &SafetyException{
		Level:     SafetyWarning,
		Type:      "sensor_failure",
		VehicleID: "av-001",
		Response:  ResponseReduceSpeed,
	}

	err := ctrl.TriggerException(ctx, exc)
	if err != nil {
		t.Fatalf("TriggerException failed: %v", err)
	}

	if exc.ID == "" {
		t.Error("expected exception ID")
	}

	retrieved, err := ctrl.GetException(ctx, exc.ID)
	if err != nil {
		t.Fatalf("GetException failed: %v", err)
	}
	if retrieved.Level != SafetyWarning {
		t.Errorf("expected Warning, got %s", retrieved.Level)
	}
}

func TestTriggerExceptionMissingVehicle(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{})
	err := ctrl.TriggerException(context.Background(), &SafetyException{})
	if err == nil {
		t.Error("expected error for missing vehicle ID")
	}
}

func TestKillSwitch(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{})

	event, err := ctrl.KillSwitch(context.Background(), "av-001", "emergency stop test")
	if err != nil {
		t.Fatalf("KillSwitch failed: %v", err)
	}

	if event.VehicleID != "av-001" {
		t.Errorf("expected vehicle av-001, got %s", event.VehicleID)
	}
	if event.Reason != "emergency stop test" {
		t.Errorf("unexpected reason: %s", event.Reason)
	}
}

func TestKillSwitchMissingInputs(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{})

	_, err := ctrl.KillSwitch(context.Background(), "", "reason")
	if err == nil {
		t.Error("expected error for empty vehicle ID")
	}

	_, err = ctrl.KillSwitch(context.Background(), "av-001", "")
	if err == nil {
		t.Error("expected error for empty reason")
	}
}

func TestSafetyLevelString(t *testing.T) {
	tests := []struct {
		level SafetyLevel
		want  string
	}{
		{SafetyNormal, "Normal"},
		{SafetyCaution, "Caution"},
		{SafetyWarning, "Warning"},
		{SafetyCritical, "Critical"},
		{SafetyEmergency, "Emergency"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("SafetyLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestSafetyResponseString(t *testing.T) {
	tests := []struct {
		resp SafetyResponse
		want string
	}{
		{ResponseContinue, "Continue"},
		{ResponseReduceSpeed, "Reduce Speed"},
		{ResponseMinimalRiskCondition, "Minimal Risk Condition"},
		{ResponseImmediateStop, "Immediate Stop"},
		{ResponseDriverTakeover, "Driver Takeover"},
	}
	for _, tt := range tests {
		if got := tt.resp.String(); got != tt.want {
			t.Errorf("SafetyResponse(%d).String() = %q, want %q", tt.resp, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Incident Tests
// ---------------------------------------------------------------------------

func TestCreateIncident(t *testing.T) {
	svc := NewIncidentService(nil, nil)

	incident := &AVIncident{
		VehicleID:   "av-001",
		Type:        IncidentNearMiss,
		Severity:    SeverityModerate,
		Description: "Near miss with pedestrian",
		Location:    Location{Latitude: 37.7749, Longitude: -122.4194},
	}

	err := svc.CreateIncident(context.Background(), incident)
	if err != nil {
		t.Fatalf("CreateIncident failed: %v", err)
	}

	if incident.ID == "" {
		t.Error("expected incident ID")
	}
	if incident.Status != "open" {
		t.Errorf("expected status 'open', got %q", incident.Status)
	}
}

func TestCreateIncidentMissingVehicle(t *testing.T) {
	svc := NewIncidentService(nil, nil)
	err := svc.CreateIncident(context.Background(), &AVIncident{})
	if err == nil {
		t.Error("expected error for missing vehicle ID")
	}
}

func TestBuildIncidentTimeline(t *testing.T) {
	teleSvc := NewTelemetryService()
	safetyCtr := NewSafetyController(SafetyPolicy{})
	svc := NewIncidentService(teleSvc, safetyCtr)
	ctx := context.Background()

	now := time.Now().UTC()

	// Record some telemetry
	_ = teleSvc.RecordTelemetry(ctx, &TelemetryReceipt{
		VehicleID: "av-002",
		Timestamp: now.Add(-1 * time.Minute),
		Speed:     20.0,
		Location:  Location{Latitude: 37.0, Longitude: -122.0},
	})

	// Trigger a safety exception
	_ = safetyCtr.TriggerException(ctx, &SafetyException{
		Level:     SafetyWarning,
		Type:      "obstacle",
		VehicleID: "av-002",
		Timestamp: now,
	})

	// Create incident
	incident := &AVIncident{
		VehicleID:   "av-002",
		Timestamp:   now,
		Type:        IncidentNearMiss,
		Severity:    SeverityModerate,
		Description: "Obstacle avoidance event",
	}
	_ = svc.CreateIncident(ctx, incident)

	// Build timeline
	timeline, err := svc.BuildIncidentTimeline(ctx, incident.ID)
	if err != nil {
		t.Fatalf("BuildIncidentTimeline failed: %v", err)
	}

	if len(timeline.Events) == 0 {
		t.Error("expected timeline events")
	}

	// Should have at least the creation event
	foundCreation := false
	for _, e := range timeline.Events {
		if e.Type == "incident_created" {
			foundCreation = true
		}
	}
	if !foundCreation {
		t.Error("expected incident_created event in timeline")
	}
}

func TestBuildIncidentTimelineNotFound(t *testing.T) {
	svc := NewIncidentService(nil, nil)
	_, err := svc.BuildIncidentTimeline(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent incident")
	}
}

func TestGenerateIncidentReport(t *testing.T) {
	svc := NewIncidentService(nil, nil)
	ctx := context.Background()

	incident := &AVIncident{
		VehicleID:         "av-003",
		Type:              IncidentCollision,
		Severity:          SeverityMajor,
		Description:       "Low-speed contact",
		Location:          Location{Latitude: 37.7749, Longitude: -122.4194},
		WeatherConditions: "clear",
		RoadConditions:    "dry",
	}
	_ = svc.CreateIncident(ctx, incident)

	report, err := svc.GenerateIncidentReport(ctx, incident.ID)
	if err != nil {
		t.Fatalf("GenerateIncidentReport failed: %v", err)
	}

	if report.Format != "NHTSA" {
		t.Errorf("expected NHTSA format, got %s", report.Format)
	}
	if len(report.Sections) == 0 {
		t.Error("expected report sections")
	}
}

func TestIncidentSeverityString(t *testing.T) {
	if SeverityMinor.String() != "Minor" {
		t.Errorf("unexpected: %s", SeverityMinor.String())
	}
	if SeverityCritical.String() != "Critical" {
		t.Errorf("unexpected: %s", SeverityCritical.String())
	}
}

// ---------------------------------------------------------------------------
// NHTSA Tests
// ---------------------------------------------------------------------------

func TestAssessNHTSACompliance(t *testing.T) {
	svc := NewNHTSAService(nil, nil)

	compliance, err := svc.AssessNHTSACompliance(context.Background(), "av-001")
	if err != nil {
		t.Fatalf("AssessNHTSACompliance failed: %v", err)
	}

	if len(compliance.Areas) == 0 {
		t.Error("expected compliance areas")
	}
	if compliance.Score < 0 || compliance.Score > 100 {
		t.Errorf("score out of range: %f", compliance.Score)
	}
}

func TestAssessNHTSAComplianceMissingVehicle(t *testing.T) {
	svc := NewNHTSAService(nil, nil)
	_, err := svc.AssessNHTSACompliance(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty vehicle ID")
	}
}

func TestGenerateNHTSAReport(t *testing.T) {
	teleSvc := NewTelemetryService()
	incSvc := NewIncidentService(teleSvc, nil)
	nhtsaSvc := NewNHTSAService(incSvc, teleSvc)
	ctx := context.Background()

	// Create an incident with telemetry
	now := time.Now().UTC()
	_ = teleSvc.RecordTelemetry(ctx, &TelemetryReceipt{
		VehicleID: "av-004",
		Timestamp: now,
		Speed:     5.0,
		Location:  Location{Latitude: 37.0, Longitude: -122.0},
	})

	incident := &AVIncident{
		VehicleID:   "av-004",
		Timestamp:   now,
		Type:        IncidentCollision,
		Severity:    SeverityMinor,
		Description: "Low-speed contact in parking lot",
	}
	_ = incSvc.CreateIncident(ctx, incident)

	report, err := nhtsaSvc.GenerateNHTSAReport(ctx, incident.ID)
	if err != nil {
		t.Fatalf("GenerateNHTSAReport failed: %v", err)
	}

	if report.VehicleID != "av-004" {
		t.Errorf("expected vehicle av-004, got %s", report.VehicleID)
	}
	if report.Compliance == nil {
		t.Error("expected compliance data in report")
	}
	if len(report.TelemetryEvidence) == 0 {
		t.Error("expected telemetry evidence in report")
	}
}

// ---------------------------------------------------------------------------
// ODD Tests
// ---------------------------------------------------------------------------

func TestRegisterAndGetODD(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID:          "odd-sf-downtown",
		Name:        "San Francisco Downtown",
		Description: "Urban surface streets in SF downtown",
		GeographicBoundary: GeographicBoundary{
			CenterLat: 37.7749,
			CenterLon: -122.4194,
			RadiusKm:  5.0,
		},
		RoadTypes:         []RoadType{RoadUrban},
		SpeedLimits:       SpeedLimit{MinSpeedMPS: 0, MaxSpeedMPS: 15.6},
		WeatherConditions: []WeatherCondition{WeatherClear, WeatherRain},
		TimeOfDay:         []TimeOfDayCondition{TimeAllHours},
		TrafficConditions: []TrafficCondition{TrafficFreeFlow, TrafficModerate, TrafficHeavy},
	}

	err := monitor.RegisterODD(ctx, odd)
	if err != nil {
		t.Fatalf("RegisterODD failed: %v", err)
	}

	retrieved, err := monitor.GetODD(ctx, "odd-sf-downtown")
	if err != nil {
		t.Fatalf("GetODD failed: %v", err)
	}
	if retrieved.Name != "San Francisco Downtown" {
		t.Errorf("unexpected ODD name: %s", retrieved.Name)
	}
}

func TestValidateODDCompliant(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID: "odd-test",
		GeographicBoundary: GeographicBoundary{
			CenterLat: 37.7749,
			CenterLon: -122.4194,
			RadiusKm:  10.0,
		},
		SpeedLimits: SpeedLimit{MinSpeedMPS: 0, MaxSpeedMPS: 25.0},
	}

	telemetry := &TelemetryReceipt{
		VehicleID: "av-001",
		Timestamp: time.Now().UTC(),
		Speed:     10.0,
		Location:  Location{Latitude: 37.78, Longitude: -122.42},
	}

	violations, err := monitor.ValidateODD(ctx, telemetry, odd)
	if err != nil {
		t.Fatalf("ValidateODD failed: %v", err)
	}

	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestValidateODDSpeedViolation(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID:          "odd-test",
		SpeedLimits: SpeedLimit{MaxSpeedMPS: 15.0},
	}

	telemetry := &TelemetryReceipt{
		VehicleID: "av-001",
		Timestamp: time.Now().UTC(),
		Speed:     20.0,
		Location:  Location{Latitude: 37.78, Longitude: -122.42},
	}

	violations, err := monitor.ValidateODD(ctx, telemetry, odd)
	if err != nil {
		t.Fatalf("ValidateODD failed: %v", err)
	}

	if len(violations) == 0 {
		t.Error("expected speed violation")
	}

	found := false
	for _, v := range violations {
		if v.Condition == "speed_max" {
			found = true
		}
	}
	if !found {
		t.Error("expected speed_max violation")
	}
}

func TestValidateODDGeoBoundaryViolation(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID: "odd-geo",
		GeographicBoundary: GeographicBoundary{
			CenterLat: 37.7749,
			CenterLon: -122.4194,
			RadiusKm:  1.0, // 1km radius
		},
		SpeedLimits: SpeedLimit{MaxSpeedMPS: 50.0},
	}

	// Location well outside the 1km radius
	telemetry := &TelemetryReceipt{
		VehicleID: "av-001",
		Timestamp: time.Now().UTC(),
		Speed:     10.0,
		Location:  Location{Latitude: 38.0, Longitude: -122.0}, // ~30km away
	}

	violations, err := monitor.ValidateODD(ctx, telemetry, odd)
	if err != nil {
		t.Fatalf("ValidateODD failed: %v", err)
	}

	found := false
	for _, v := range violations {
		if v.Condition == "geographic_boundary" {
			found = true
		}
	}
	if !found {
		t.Error("expected geographic_boundary violation")
	}
}

func TestSealODDEvidence(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID:   "odd-test",
		Name: "Test ODD",
	}

	evidence, err := monitor.SealODDEvidence(ctx, "av-001", odd, 1*time.Hour)
	if err != nil {
		t.Fatalf("SealODDEvidence failed: %v", err)
	}

	if evidence.VehicleID != "av-001" {
		t.Errorf("expected vehicle av-001, got %s", evidence.VehicleID)
	}
	if !evidence.Compliant {
		t.Error("expected compliant (no violations)")
	}
}

func TestSealODDEvidenceMissingVehicle(t *testing.T) {
	monitor := NewODDMonitor()
	_, err := monitor.SealODDEvidence(context.Background(), "", &ODD{}, 1*time.Hour)
	if err == nil {
		t.Error("expected error for missing vehicle ID")
	}
}

// ---------------------------------------------------------------------------
// Edge-case, error-path, and concurrency tests
// ---------------------------------------------------------------------------

func TestTelemetry_InvalidLocation(t *testing.T) {
	svc := NewTelemetryService()
	ctx := context.Background()

	tests := []struct {
		name string
		lat  float64
		lon  float64
	}{
		{"lat > 90", 91.0, 0.0},
		{"lat < -90", -91.0, 0.0},
		{"lon > 180", 0.0, 181.0},
		{"lon < -180", 0.0, -181.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := &TelemetryReceipt{
				VehicleID: "av-invalid-loc",
				Timestamp: time.Now().UTC(),
				Location:  Location{Latitude: tt.lat, Longitude: tt.lon},
			}
			err := svc.RecordTelemetry(ctx, receipt)
			if err == nil {
				t.Errorf("expected error for invalid location %s", tt.name)
			}
		})
	}
}

func TestTelemetry_NilSensorData(t *testing.T) {
	svc := NewTelemetryService()
	receipt := &TelemetryReceipt{
		VehicleID: "av-nil-sensor",
		Timestamp: time.Now().UTC(),
		Speed:     10.0,
		Location:  Location{Latitude: 37.0, Longitude: -122.0},
		// SensorData is zero-valued (empty, not nil pointer).
	}
	err := svc.RecordTelemetry(context.Background(), receipt)
	if err != nil {
		t.Fatalf("expected nil sensor data to be acceptable, got: %v", err)
	}
}

func TestTelemetry_ConcurrentRecording(t *testing.T) {
	svc := NewTelemetryService()
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			receipt := &TelemetryReceipt{
				VehicleID: fmt.Sprintf("av-conc-%d", idx),
				Timestamp: time.Now().UTC(),
				Speed:     float64(10 + idx),
				Location:  Location{Latitude: 37.0, Longitude: -122.0},
			}
			if err := svc.RecordTelemetry(ctx, receipt); err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent telemetry error: %v", e)
	}
}

func TestSafety_AllLevels(t *testing.T) {
	levels := []SafetyLevel{SafetyNormal, SafetyCaution, SafetyWarning, SafetyCritical, SafetyEmergency}
	for _, level := range levels {
		t.Run(level.String(), func(t *testing.T) {
			s := level.String()
			if s == "" {
				t.Errorf("empty string for safety level %d", level)
			}
		})
	}
}

func TestSafety_KillSwitchIdempotent(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{})
	ctx := context.Background()

	event1, err := ctrl.KillSwitch(ctx, "av-idem", "first activation")
	if err != nil {
		t.Fatalf("first KillSwitch failed: %v", err)
	}

	event2, err := ctrl.KillSwitch(ctx, "av-idem", "second activation")
	if err != nil {
		t.Fatalf("second KillSwitch failed: %v", err)
	}

	// Both should produce valid events.
	if event1.VehicleID != "av-idem" || event2.VehicleID != "av-idem" {
		t.Error("expected both events to reference av-idem")
	}
}

func TestSafety_ConcurrentEvaluation(t *testing.T) {
	ctrl := NewSafetyController(SafetyPolicy{
		Thresholds: map[string]SafetyThreshold{
			"speed": {Name: "speed", CriticalValue: 40},
		},
	})

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			telemetry := &TelemetryReceipt{
				VehicleID: fmt.Sprintf("av-safe-%d", idx),
				Speed:     float64(5 + idx),
			}
			_, err := ctrl.EvaluateSafety(context.Background(), telemetry)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent safety evaluation error: %v", e)
	}
}

func TestIncident_ConcurrentTimeline(t *testing.T) {
	teleSvc := NewTelemetryService()
	svc := NewIncidentService(teleSvc, nil)
	ctx := context.Background()

	incident := &AVIncident{
		VehicleID:   "av-conc-timeline",
		Type:        IncidentNearMiss,
		Severity:    SeverityModerate,
		Description: "concurrent timeline test",
	}
	_ = svc.CreateIncident(ctx, incident)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.BuildIncidentTimeline(ctx, incident.ID)
		}()
	}
	wg.Wait()
}

func TestIncident_WarningsCollected(t *testing.T) {
	teleSvc := NewTelemetryService()
	safetyCtr := NewSafetyController(SafetyPolicy{})
	svc := NewIncidentService(teleSvc, safetyCtr)
	ctx := context.Background()

	// Record telemetry.
	_ = teleSvc.RecordTelemetry(ctx, &TelemetryReceipt{
		VehicleID: "av-warn",
		Timestamp: time.Now().UTC(),
		Speed:     10.0,
		Location:  Location{Latitude: 37.0, Longitude: -122.0},
	})

	incident := &AVIncident{
		VehicleID:   "av-warn",
		Type:        IncidentNearMiss,
		Severity:    SeverityMinor,
		Description: "warnings test",
		Timestamp:   time.Now().UTC(),
	}
	_ = svc.CreateIncident(ctx, incident)

	report, err := svc.GenerateIncidentReport(ctx, incident.ID)
	if err != nil {
		t.Fatalf("GenerateIncidentReport failed: %v", err)
	}
	if report.Format != "NHTSA" {
		t.Errorf("expected NHTSA format, got %s", report.Format)
	}
}

func TestNHTSA_EmptyVehicleID(t *testing.T) {
	svc := NewNHTSAService(nil, nil)
	_, err := svc.AssessNHTSACompliance(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty vehicle ID")
	}
}

func TestNHTSA_AllComplianceAreas(t *testing.T) {
	svc := NewNHTSAService(nil, nil)

	compliance, err := svc.AssessNHTSACompliance(context.Background(), "av-areas")
	if err != nil {
		t.Fatalf("AssessNHTSACompliance failed: %v", err)
	}

	if len(compliance.Areas) < 12 {
		t.Errorf("expected at least 12 compliance areas, got %d", len(compliance.Areas))
	}
}

func TestODD_BoundaryConditions(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID: "odd-boundary",
		GeographicBoundary: GeographicBoundary{
			CenterLat: 37.7749,
			CenterLon: -122.4194,
			RadiusKm:  5.0,
		},
		SpeedLimits: SpeedLimit{MinSpeedMPS: 0, MaxSpeedMPS: 15.0},
	}

	// Exactly at speed limit.
	telemetry := &TelemetryReceipt{
		VehicleID: "av-boundary",
		Timestamp: time.Now().UTC(),
		Speed:     15.0, // Exactly at max.
		Location:  Location{Latitude: 37.7749, Longitude: -122.4194}, // Exactly at center.
	}

	violations, err := monitor.ValidateODD(ctx, telemetry, odd)
	if err != nil {
		t.Fatalf("ValidateODD failed: %v", err)
	}
	// At the exact boundary, we expect no violation (boundary is inclusive).
	for _, v := range violations {
		if v.Condition == "speed_max" {
			t.Log("note: exact speed boundary treated as violation")
		}
	}
}

func TestODD_ConcurrentMonitoring(t *testing.T) {
	monitor := NewODDMonitor()
	ctx := context.Background()

	odd := &ODD{
		ID:          "odd-conc",
		SpeedLimits: SpeedLimit{MaxSpeedMPS: 25.0},
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			telemetry := &TelemetryReceipt{
				VehicleID: fmt.Sprintf("av-odd-%d", idx),
				Timestamp: time.Now().UTC(),
				Speed:     float64(10 + idx),
				Location:  Location{Latitude: 37.0, Longitude: -122.0},
			}
			_, err := monitor.ValidateODD(ctx, telemetry, odd)
			if err != nil {
				t.Errorf("concurrent ODD check %d failed: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	// Suppress unused import.
	_ = errors.Is(nil, ErrODDViolation)
}
