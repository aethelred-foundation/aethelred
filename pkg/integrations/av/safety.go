package av

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Safety Exception Controls
// ---------------------------------------------------------------------------

// SafetyLevel represents the severity of a safety condition.
type SafetyLevel int

const (
	SafetyNormal SafetyLevel = iota
	SafetyCaution
	SafetyWarning
	SafetyCritical
	SafetyEmergency
)

// String returns the human-readable label.
func (l SafetyLevel) String() string {
	switch l {
	case SafetyNormal:
		return "Normal"
	case SafetyCaution:
		return "Caution"
	case SafetyWarning:
		return "Warning"
	case SafetyCritical:
		return "Critical"
	case SafetyEmergency:
		return "Emergency"
	default:
		return "Unknown"
	}
}

// SafetyResponse defines the action to take in response to a safety condition.
type SafetyResponse int

const (
	ResponseContinue SafetyResponse = iota
	ResponseReduceSpeed
	ResponseMinimalRiskCondition
	ResponseImmediateStop
	ResponseDriverTakeover
)

// String returns the human-readable label.
func (r SafetyResponse) String() string {
	switch r {
	case ResponseContinue:
		return "Continue"
	case ResponseReduceSpeed:
		return "Reduce Speed"
	case ResponseMinimalRiskCondition:
		return "Minimal Risk Condition"
	case ResponseImmediateStop:
		return "Immediate Stop"
	case ResponseDriverTakeover:
		return "Driver Takeover"
	default:
		return "Unknown"
	}
}

// SafetyException represents a recorded safety exception event.
type SafetyException struct {
	// ID uniquely identifies this exception.
	ID string `json:"id"`

	// Level is the severity level.
	Level SafetyLevel `json:"level"`

	// Type categorizes the exception (e.g. "sensor_failure", "obstacle_detected").
	Type string `json:"type"`

	// Description is a human-readable description.
	Description string `json:"description"`

	// Timestamp is when the exception occurred.
	Timestamp time.Time `json:"timestamp"`

	// VehicleID identifies the affected vehicle.
	VehicleID string `json:"vehicle_id"`

	// Location is where the exception occurred.
	Location Location `json:"location"`

	// Response is the action taken.
	Response SafetyResponse `json:"response"`

	// SealID links to the sealed audit record.
	SealID string `json:"seal_id"`

	// TelemetryReceiptID links to the telemetry at the time of exception.
	TelemetryReceiptID string `json:"telemetry_receipt_id"`

	// Resolved indicates whether the exception has been resolved.
	Resolved bool `json:"resolved"`

	// ResolvedAt is when the exception was resolved.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// SafetyEvaluation holds the result of a safety evaluation.
type SafetyEvaluation struct {
	// Level is the determined safety level.
	Level SafetyLevel `json:"level"`

	// RecommendedResponse is the suggested action.
	RecommendedResponse SafetyResponse `json:"recommended_response"`

	// Factors lists the contributing safety factors.
	Factors []string `json:"factors"`

	// SensorHealth summarizes sensor operational status.
	SensorHealth map[SensorType]string `json:"sensor_health"`

	// Timestamp is when the evaluation was performed.
	Timestamp time.Time `json:"timestamp"`
}

// SafetyThreshold defines the threshold values for a specific safety check.
type SafetyThreshold struct {
	// Name identifies the threshold.
	Name string `json:"name"`

	// CautionValue triggers a caution.
	CautionValue float64 `json:"caution_value"`

	// WarningValue triggers a warning.
	WarningValue float64 `json:"warning_value"`

	// CriticalValue triggers a critical alert.
	CriticalValue float64 `json:"critical_value"`
}

// SafetyPolicy defines the safety rules and response mappings.
type SafetyPolicy struct {
	// Thresholds maps metric names to their threshold values.
	Thresholds map[string]SafetyThreshold `json:"thresholds"`

	// ResponseMap maps safety levels to their default responses.
	ResponseMap map[SafetyLevel]SafetyResponse `json:"response_map"`

	// KillSwitchConditions lists conditions that trigger an immediate kill switch.
	KillSwitchConditions []string `json:"kill_switch_conditions"`

	// MinSensorCount is the minimum number of operational sensors required.
	MinSensorCount int `json:"min_sensor_count"`
}

// KillSwitchEvent records the use of the emergency kill switch.
type KillSwitchEvent struct {
	// ID uniquely identifies this event.
	ID string `json:"id"`

	// VehicleID is the vehicle that was stopped.
	VehicleID string `json:"vehicle_id"`

	// Reason explains why the kill switch was activated.
	Reason string `json:"reason"`

	// Timestamp is when the kill switch was activated.
	Timestamp time.Time `json:"timestamp"`

	// Location is where the vehicle was stopped.
	Location Location `json:"location"`

	// Speed is the vehicle speed at the time of activation.
	Speed float64 `json:"speed"`

	// SealID links to the sealed audit record.
	SealID string `json:"seal_id"`
}

// SafetyController manages safety evaluations and exception handling.
type SafetyController struct {
	policy     SafetyPolicy
	mu         sync.RWMutex
	exceptions map[string]*SafetyException
	killEvents map[string]*KillSwitchEvent
}

// NewSafetyController creates a new controller with the given policy.
func NewSafetyController(policy SafetyPolicy) *SafetyController {
	if policy.ResponseMap == nil {
		policy.ResponseMap = defaultResponseMap()
	}
	return &SafetyController{
		policy:     policy,
		exceptions: make(map[string]*SafetyException),
		killEvents: make(map[string]*KillSwitchEvent),
	}
}

// EvaluateSafety assesses the safety level based on telemetry data.
func (c *SafetyController) EvaluateSafety(_ context.Context, telemetry *TelemetryReceipt) (*SafetyEvaluation, error) {
	if telemetry == nil {
		return nil, fmt.Errorf("telemetry data is required")
	}

	eval := &SafetyEvaluation{
		Level:               SafetyNormal,
		RecommendedResponse: ResponseContinue,
		SensorHealth:        make(map[SensorType]string),
		Timestamp:           time.Now().UTC(),
	}

	// Check sensor health
	sensorCount := 0
	sensorTypes := map[SensorType][]SensorReading{
		SensorLiDAR:      telemetry.SensorData.LiDAR,
		SensorCamera:     telemetry.SensorData.Camera,
		SensorRadar:      telemetry.SensorData.Radar,
		SensorUltrasonic: telemetry.SensorData.Ultrasonic,
		SensorIMU:        telemetry.SensorData.IMU,
		SensorGPS:        telemetry.SensorData.GPS,
	}

	for sType, readings := range sensorTypes {
		if len(readings) > 0 {
			sensorCount++
			allOk := true
			for _, r := range readings {
				if r.Status != "ok" && r.Status != "operational" {
					allOk = false
				}
			}
			if allOk {
				eval.SensorHealth[sType] = "operational"
			} else {
				eval.SensorHealth[sType] = "degraded"
				eval.Factors = append(eval.Factors, fmt.Sprintf("%s sensor degraded", sType))
				if eval.Level < SafetyWarning {
					eval.Level = SafetyWarning
				}
			}
		} else {
			eval.SensorHealth[sType] = "offline"
		}
	}

	// Check minimum sensor count
	if c.policy.MinSensorCount > 0 && sensorCount < c.policy.MinSensorCount {
		eval.Level = SafetyCritical
		eval.Factors = append(eval.Factors, fmt.Sprintf("insufficient sensors: %d < %d", sensorCount, c.policy.MinSensorCount))
	}

	// Check speed thresholds
	if threshold, ok := c.policy.Thresholds["speed"]; ok {
		if telemetry.Speed > threshold.CriticalValue {
			eval.Level = SafetyCritical
			eval.Factors = append(eval.Factors, "speed exceeds critical threshold")
		} else if telemetry.Speed > threshold.WarningValue {
			if eval.Level < SafetyWarning {
				eval.Level = SafetyWarning
			}
			eval.Factors = append(eval.Factors, "speed exceeds warning threshold")
		}
	}

	// Map level to response
	if resp, ok := c.policy.ResponseMap[eval.Level]; ok {
		eval.RecommendedResponse = resp
	}

	return eval, nil
}

// TriggerException records a safety exception with an audit trail.
func (c *SafetyController) TriggerException(_ context.Context, exception *SafetyException) error {
	if exception == nil {
		return fmt.Errorf("exception is required")
	}
	if exception.VehicleID == "" {
		return fmt.Errorf("vehicle ID is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if exception.ID == "" {
		exception.ID = fmt.Sprintf("exc-%s-%d", exception.VehicleID, time.Now().UnixNano())
	}
	if exception.Timestamp.IsZero() {
		exception.Timestamp = time.Now().UTC()
	}

	c.exceptions[exception.ID] = exception
	return nil
}

// KillSwitch triggers an emergency vehicle halt.
func (c *SafetyController) KillSwitch(_ context.Context, vehicleID string, reason string) (*KillSwitchEvent, error) {
	if vehicleID == "" {
		return nil, fmt.Errorf("vehicle ID is required")
	}
	if reason == "" {
		return nil, fmt.Errorf("reason is required")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	event := &KillSwitchEvent{
		ID:        fmt.Sprintf("kill-%s-%d", vehicleID, time.Now().UnixNano()),
		VehicleID: vehicleID,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	}

	c.killEvents[event.ID] = event
	return event, nil
}

// GetException retrieves a safety exception by ID.
func (c *SafetyController) GetException(_ context.Context, exceptionID string) (*SafetyException, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	exc, ok := c.exceptions[exceptionID]
	if !ok {
		return nil, fmt.Errorf("exception not found: %s", exceptionID)
	}
	return exc, nil
}

// ListExceptions returns all exceptions for a vehicle.
func (c *SafetyController) ListExceptions(_ context.Context, vehicleID string) ([]*SafetyException, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var results []*SafetyException
	for _, exc := range c.exceptions {
		if exc.VehicleID == vehicleID {
			results = append(results, exc)
		}
	}
	return results, nil
}

func defaultResponseMap() map[SafetyLevel]SafetyResponse {
	return map[SafetyLevel]SafetyResponse{
		SafetyNormal:    ResponseContinue,
		SafetyCaution:   ResponseContinue,
		SafetyWarning:   ResponseReduceSpeed,
		SafetyCritical:  ResponseMinimalRiskCondition,
		SafetyEmergency: ResponseImmediateStop,
	}
}
