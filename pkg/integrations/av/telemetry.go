// Package av provides integration types and services for autonomous vehicle
// safety evidence, telemetry recording, incident management, NHTSA framework
// alignment, and Operational Design Domain monitoring.
package av

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Telemetry Receipt Types
// ---------------------------------------------------------------------------

// SensorType identifies the type of AV sensor.
type SensorType string

const (
	SensorLiDAR      SensorType = "lidar"
	SensorCamera     SensorType = "camera"
	SensorRadar      SensorType = "radar"
	SensorUltrasonic SensorType = "ultrasonic"
	SensorIMU        SensorType = "imu"
	SensorGPS        SensorType = "gps"
)

// SensorReading holds a single reading from an AV sensor.
type SensorReading struct {
	// SensorID uniquely identifies the sensor hardware.
	SensorID string `json:"sensor_id"`

	// Type is the sensor type.
	Type SensorType `json:"type"`

	// Timestamp is when the reading was captured.
	Timestamp time.Time `json:"timestamp"`

	// RawDataHash is the SHA-256 hash of the raw sensor data.
	RawDataHash string `json:"raw_data_hash"`

	// Confidence is the sensor confidence score (0.0 - 1.0).
	Confidence float64 `json:"confidence"`

	// Status is the sensor health status.
	Status string `json:"status"`
}

// SensorData aggregates readings from all sensor types on a vehicle.
type SensorData struct {
	LiDAR      []SensorReading `json:"lidar"`
	Camera     []SensorReading `json:"camera"`
	Radar      []SensorReading `json:"radar"`
	Ultrasonic []SensorReading `json:"ultrasonic"`
	IMU        []SensorReading `json:"imu"`
	GPS        []SensorReading `json:"gps"`
}

// Location represents a geographic position.
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Altitude  float64 `json:"altitude"`
	Accuracy  float64 `json:"accuracy"`
}

// TelemetryReceipt is a sealed record of vehicle telemetry data.
type TelemetryReceipt struct {
	// ID uniquely identifies this receipt.
	ID string `json:"id"`

	// VehicleID identifies the autonomous vehicle.
	VehicleID string `json:"vehicle_id"`

	// Timestamp is when this telemetry was recorded.
	Timestamp time.Time `json:"timestamp"`

	// SensorData contains the aggregated sensor readings.
	SensorData SensorData `json:"sensor_data"`

	// Location is the vehicle's geographic position.
	Location Location `json:"location"`

	// Speed is the vehicle speed in meters per second.
	Speed float64 `json:"speed"`

	// Heading is the vehicle heading in degrees (0-360).
	Heading float64 `json:"heading"`

	// SealID links to the blockchain seal for this receipt.
	SealID string `json:"seal_id"`

	// DataHash is the SHA-256 hash of all telemetry data.
	DataHash string `json:"data_hash"`

	// SequenceNumber orders receipts within a vehicle session.
	SequenceNumber uint64 `json:"sequence_number"`
}

// TelemetryVerification holds the result of a telemetry verification.
type TelemetryVerification struct {
	// ReceiptID is the receipt that was verified.
	ReceiptID string `json:"receipt_id"`

	// Valid indicates whether the telemetry is authentic.
	Valid bool `json:"valid"`

	// SealValid indicates whether the seal is valid.
	SealValid bool `json:"seal_valid"`

	// DataIntegrity indicates whether the data hash matches.
	DataIntegrity bool `json:"data_integrity"`

	// Timestamp is when verification was performed.
	Timestamp time.Time `json:"timestamp"`
}

// TimeRange specifies a time window for queries.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// TelemetryService manages the recording and verification of AV telemetry.
type TelemetryService struct {
	mu       sync.RWMutex
	receipts map[string]*TelemetryReceipt
	byVehicle map[string][]string // vehicleID -> receipt IDs
	seqNums  map[string]uint64   // vehicleID -> next sequence number
}

// NewTelemetryService creates a new telemetry service.
func NewTelemetryService() *TelemetryService {
	return &TelemetryService{
		receipts:  make(map[string]*TelemetryReceipt),
		byVehicle: make(map[string][]string),
		seqNums:   make(map[string]uint64),
	}
}

// RecordTelemetry records and seals a telemetry receipt.
// ValidateLocation checks that lat/lon bounds are valid.
func ValidateLocation(loc Location) error {
	if loc.Latitude < -90 || loc.Latitude > 90 {
		return fmt.Errorf("ValidateLocation: %w: latitude out of range [-90, 90]: %f", ErrInvalidTelemetry, loc.Latitude)
	}
	if loc.Longitude < -180 || loc.Longitude > 180 {
		return fmt.Errorf("ValidateLocation: %w: longitude out of range [-180, 180]: %f", ErrInvalidTelemetry, loc.Longitude)
	}
	return nil
}

// ValidateSensorReading checks that a sensor reading has valid data.
func ValidateSensorReading(r SensorReading) error {
	if r.Confidence < 0 {
		return fmt.Errorf("ValidateSensorReading: %w: negative confidence: %f", ErrInvalidTelemetry, r.Confidence)
	}
	if r.Timestamp.IsZero() {
		return fmt.Errorf("ValidateSensorReading: %w: zero timestamp", ErrInvalidTelemetry)
	}
	return nil
}

func (s *TelemetryService) RecordTelemetry(_ context.Context, receipt *TelemetryReceipt) error {
	if receipt == nil {
		return fmt.Errorf("TelemetryService.RecordTelemetry: %w: receipt is nil", ErrInvalidTelemetry)
	}
	if receipt.VehicleID == "" {
		return fmt.Errorf("TelemetryService.RecordTelemetry: %w: vehicle ID is empty", ErrInvalidTelemetry)
	}
	// Validate lat/lon bounds.
	if err := ValidateLocation(receipt.Location); err != nil {
		return fmt.Errorf("TelemetryService.RecordTelemetry: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Assign sequence number
	seq := s.seqNums[receipt.VehicleID]
	receipt.SequenceNumber = seq
	s.seqNums[receipt.VehicleID] = seq + 1

	// Generate ID if not set
	if receipt.ID == "" {
		receipt.ID = fmt.Sprintf("tel-%s-%d", receipt.VehicleID, receipt.SequenceNumber)
	}

	// Compute data hash
	receipt.DataHash = computeTelemetryHash(receipt)

	// Generate seal ID (in production, this would create an actual blockchain seal)
	if receipt.SealID == "" {
		h := sha256.Sum256([]byte(receipt.DataHash + receipt.ID))
		receipt.SealID = "seal-" + hex.EncodeToString(h[:])[:16]
	}

	s.receipts[receipt.ID] = receipt
	s.byVehicle[receipt.VehicleID] = append(s.byVehicle[receipt.VehicleID], receipt.ID)

	return nil
}

// VerifyTelemetry verifies the authenticity of a telemetry receipt.
func (s *TelemetryService) VerifyTelemetry(_ context.Context, receiptID string) (*TelemetryVerification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	receipt, ok := s.receipts[receiptID]
	if !ok {
		return nil, fmt.Errorf("TelemetryService: %w: receipt not found: %s", ErrInvalidTelemetry, receiptID)
	}

	computedHash := computeTelemetryHash(receipt)
	dataIntegrity := computedHash == receipt.DataHash

	return &TelemetryVerification{
		ReceiptID:     receiptID,
		Valid:         dataIntegrity && receipt.SealID != "",
		SealValid:     receipt.SealID != "",
		DataIntegrity: dataIntegrity,
		Timestamp:     time.Now().UTC(),
	}, nil
}

// QueryTelemetry returns telemetry receipts for a vehicle within a time range.
func (s *TelemetryService) QueryTelemetry(_ context.Context, vehicleID string, timeRange TimeRange) ([]*TelemetryReceipt, error) {
	if vehicleID == "" {
		return nil, fmt.Errorf("vehicle ID is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ids, ok := s.byVehicle[vehicleID]
	if !ok {
		return nil, nil
	}

	var results []*TelemetryReceipt
	for _, id := range ids {
		receipt := s.receipts[id]
		if receipt == nil {
			continue
		}
		if (timeRange.Start.IsZero() || !receipt.Timestamp.Before(timeRange.Start)) &&
			(timeRange.End.IsZero() || !receipt.Timestamp.After(timeRange.End)) {
			results = append(results, receipt)
		}
	}

	return results, nil
}

// GetReceipt retrieves a single telemetry receipt.
func (s *TelemetryService) GetReceipt(_ context.Context, receiptID string) (*TelemetryReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	receipt, ok := s.receipts[receiptID]
	if !ok {
		return nil, fmt.Errorf("TelemetryService: %w: receipt not found: %s", ErrInvalidTelemetry, receiptID)
	}
	return receipt, nil
}

func computeTelemetryHash(receipt *TelemetryReceipt) string {
	h := sha256.New()
	h.Write([]byte(receipt.VehicleID))
	h.Write([]byte(receipt.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(fmt.Sprintf("%f", receipt.Speed)))
	h.Write([]byte(fmt.Sprintf("%f", receipt.Heading)))
	h.Write([]byte(fmt.Sprintf("%f%f", receipt.Location.Latitude, receipt.Location.Longitude)))

	for _, r := range receipt.SensorData.LiDAR {
		h.Write([]byte(r.RawDataHash))
	}
	for _, r := range receipt.SensorData.Camera {
		h.Write([]byte(r.RawDataHash))
	}
	for _, r := range receipt.SensorData.Radar {
		h.Write([]byte(r.RawDataHash))
	}

	return hex.EncodeToString(h.Sum(nil))
}
