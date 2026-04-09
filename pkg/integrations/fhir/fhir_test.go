package fhir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/seal/sdk"
	"github.com/aethelred/aethelred/x/pouw/keeper"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// ---------------------------------------------------------------------------
// Mock SealKeeper for testing
// ---------------------------------------------------------------------------

type mockSealKeeper struct {
	seals map[string]*sealtypes.DigitalSeal
}

func newMockSealKeeper() *mockSealKeeper {
	return &mockSealKeeper{seals: make(map[string]*sealtypes.DigitalSeal)}
}

func (m *mockSealKeeper) CreateSeal(_ context.Context, seal *sealtypes.DigitalSeal) error {
	m.seals[seal.Id] = seal
	return nil
}

func (m *mockSealKeeper) GetSeal(_ context.Context, id string) (*sealtypes.DigitalSeal, error) {
	s, ok := m.seals[id]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockSealKeeper) SetSeal(_ context.Context, seal *sealtypes.DigitalSeal) error {
	m.seals[seal.Id] = seal
	return nil
}

func (m *mockSealKeeper) RevokeSeal(_ context.Context, id string, _ string) error {
	if s, ok := m.seals[id]; ok {
		s.Status = sealtypes.SealStatusRevoked
	}
	return nil
}

func (m *mockSealKeeper) VerifySeal(_ context.Context, id string) (bool, error) {
	s, ok := m.seals[id]
	if !ok {
		return false, nil
	}
	return s.Status == sealtypes.SealStatusActive, nil
}

func (m *mockSealKeeper) ListSeals(_ context.Context, _ int, _ int) ([]*sealtypes.DigitalSeal, error) {
	var out []*sealtypes.DigitalSeal
	for _, s := range m.seals {
		out = append(out, s)
	}
	return out, nil
}

func (m *mockSealKeeper) ListSealsByModel(_ context.Context, _ []byte) ([]*sealtypes.DigitalSeal, error) {
	return nil, nil
}

func (m *mockSealKeeper) ListSealsByRequester(_ context.Context, _ string) ([]*sealtypes.DigitalSeal, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestBridge(t *testing.T) *FHIRBridge {
	t.Helper()
	keeper := newMockSealKeeper()
	sealSDK, err := sdk.NewSealSDK(sdk.Config{
		ChainID:       "test-chain-1",
		SignerAddress: "aethelred1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tp2",
	}, keeper)
	if err != nil {
		t.Fatalf("failed to create seal SDK: %v", err)
	}

	bridge, err := NewFHIRBridge(BridgeConfig{
		Endpoint:             "https://fhir.example.com",
		DefaultJurisdiction:  "US",
		ConsentRequired:      true,
		DefaultRetentionDays: 2555,
	}, sealSDK)
	if err != nil {
		t.Fatalf("failed to create FHIR bridge: %v", err)
	}

	return bridge
}

func testPatient() *Patient {
	return &Patient{
		ResourceType: "Patient",
		ID:           "patient-001",
		Active:       true,
		Name: []HumanName{
			{Family: "Smith", Given: []string{"John"}, Use: "official"},
		},
		Gender:    "male",
		BirthDate: "1990-01-15",
		Identifier: []Identifier{
			{System: "http://hospital.example.org", Value: "MRN-12345", Use: "usual"},
		},
	}
}

func testObservation() *Observation {
	now := time.Now().UTC()
	return &Observation{
		ResourceType: "Observation",
		ID:           "obs-001",
		Status:       ObservationStatusFinal,
		Code: CodeableConcept{
			Coding: []Coding{
				{System: "http://loinc.org", Code: "8867-4", Display: "Heart rate"},
			},
			Text: "Heart rate",
		},
		Subject: &Reference{
			Reference: "Patient/patient-001",
			Display:   "John Smith",
		},
		ValueQuantity: &Quantity{
			Value: 72,
			Unit:  "beats/minute",
			System: "http://unitsofmeasure.org",
			Code:  "/min",
		},
		EffectiveDateTime: &now,
	}
}

func testConsent() Consent {
	now := time.Now().UTC()
	return Consent{
		ResourceType: "Consent",
		ID:           "consent-001",
		Status:       ConsentStatusActive,
		Scope: CodeableConcept{
			Coding: []Coding{
				{System: "http://terminology.hl7.org/CodeSystem/consentscope", Code: "patient-privacy", Display: "Privacy Consent"},
			},
		},
		Category: []CodeableConcept{
			{
				Coding: []Coding{
					{System: "http://loinc.org", Code: "59284-0", Display: "Patient Consent"},
				},
			},
		},
		Patient: &Reference{
			Reference: "Patient/patient-001",
			Display:   "John Smith",
		},
		DateTime: &now,
		Provision: &ConsentProvision{
			Type: "permit",
			Purpose: []Coding{
				{System: "http://terminology.hl7.org/CodeSystem/v3-ActReason", Code: "TREAT", Display: "Treatment"},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Resource tests
// ---------------------------------------------------------------------------

func TestPatientResourceType(t *testing.T) {
	p := testPatient()
	if p.GetResourceType() != ResourceTypePatient {
		t.Errorf("expected ResourceTypePatient, got %s", p.GetResourceType())
	}
	if p.GetID() != "patient-001" {
		t.Errorf("expected 'patient-001', got %s", p.GetID())
	}
}

func TestObservationResourceType(t *testing.T) {
	o := testObservation()
	if o.GetResourceType() != ResourceTypeObservation {
		t.Errorf("expected ResourceTypeObservation, got %s", o.GetResourceType())
	}
}

func TestPatientJSON(t *testing.T) {
	p := testPatient()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("failed to marshal patient: %v", err)
	}

	var decoded Patient
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal patient: %v", err)
	}

	if decoded.ID != p.ID {
		t.Errorf("expected ID %s, got %s", p.ID, decoded.ID)
	}
	if decoded.Gender != p.Gender {
		t.Errorf("expected Gender %s, got %s", p.Gender, decoded.Gender)
	}
	if len(decoded.Name) != 1 || decoded.Name[0].Family != "Smith" {
		t.Errorf("unexpected name: %+v", decoded.Name)
	}
}

// ---------------------------------------------------------------------------
// Validator tests
// ---------------------------------------------------------------------------

func TestValidatePatient_Valid(t *testing.T) {
	v := NewValidator()
	result := v.ValidatePatient(testPatient())
	if !result.Valid {
		t.Errorf("expected valid patient, got errors: %v", result.Errors)
	}
}

func TestValidatePatient_MissingID(t *testing.T) {
	v := NewValidator()
	p := testPatient()
	p.ID = ""
	result := v.ValidatePatient(p)
	if result.Valid {
		t.Error("expected invalid patient with missing ID")
	}
}

func TestValidatePatient_InvalidGender(t *testing.T) {
	v := NewValidator()
	p := testPatient()
	p.Gender = "invalid"
	result := v.ValidatePatient(p)
	if result.Valid {
		t.Error("expected invalid patient with bad gender")
	}
}

func TestValidatePatient_Nil(t *testing.T) {
	v := NewValidator()
	result := v.ValidatePatient(nil)
	if result.Valid {
		t.Error("expected invalid for nil patient")
	}
}

func TestValidateObservation_Valid(t *testing.T) {
	v := NewValidator()
	result := v.ValidateObservation(testObservation())
	if !result.Valid {
		t.Errorf("expected valid observation, got errors: %v", result.Errors)
	}
}

func TestValidateObservation_MissingStatus(t *testing.T) {
	v := NewValidator()
	o := testObservation()
	o.Status = ""
	result := v.ValidateObservation(o)
	if result.Valid {
		t.Error("expected invalid observation with missing status")
	}
}

func TestValidateObservation_MissingCode(t *testing.T) {
	v := NewValidator()
	o := testObservation()
	o.Code = CodeableConcept{}
	result := v.ValidateObservation(o)
	if result.Valid {
		t.Error("expected invalid observation with missing code")
	}
}

func TestValidateConsent_Valid(t *testing.T) {
	v := NewValidator()
	c := testConsent()
	result := v.ValidateConsent(&c)
	if !result.Valid {
		t.Errorf("expected valid consent, got errors: %v", result.Errors)
	}
}

func TestValidateConsent_MissingScope(t *testing.T) {
	v := NewValidator()
	c := testConsent()
	c.Scope = CodeableConcept{}
	result := v.ValidateConsent(&c)
	if result.Valid {
		t.Error("expected invalid consent with missing scope")
	}
}

func TestValidateConsent_InvalidStatus(t *testing.T) {
	v := NewValidator()
	c := testConsent()
	c.Status = "bogus"
	result := v.ValidateConsent(&c)
	if result.Valid {
		t.Error("expected invalid consent with bad status")
	}
}

func TestValidateResource_Dispatch(t *testing.T) {
	v := NewValidator()
	result := v.ValidateResource(testPatient())
	if !result.Valid {
		t.Errorf("expected valid patient via dispatch, got errors: %v", result.Errors)
	}

	result = v.ValidateResource(nil)
	if result.Valid {
		t.Error("expected invalid for nil resource")
	}
}

func TestValidateBundle(t *testing.T) {
	v := NewValidator()
	b := &Bundle{
		ResourceType: "Bundle",
		ID:           "bundle-001",
		Type:         BundleTypeCollection,
		Total:        1,
		Entry: []BundleEntry{
			{FullURL: "urn:uuid:patient-001", Resource: testPatient()},
		},
	}
	result := v.ValidateBundle(b)
	if !result.Valid {
		t.Errorf("expected valid bundle, got errors: %v", result.Errors)
	}
}

func TestValidateBundle_MissingType(t *testing.T) {
	v := NewValidator()
	b := &Bundle{ID: "bundle-002"}
	result := v.ValidateBundle(b)
	if result.Valid {
		t.Error("expected invalid bundle with missing type")
	}
}

// ---------------------------------------------------------------------------
// Bridge tests
// ---------------------------------------------------------------------------

func TestSealResource(t *testing.T) {
	bridge := newTestBridge(t)
	ctx := context.Background()

	patient := testPatient()
	sealed, err := bridge.SealResource(ctx, patient)
	if err != nil {
		t.Fatalf("SealResource failed: %v", err)
	}

	if sealed.SealID == "" {
		t.Error("expected non-empty seal ID")
	}
	if sealed.ResourceID != "patient-001" {
		t.Errorf("expected resource ID 'patient-001', got '%s'", sealed.ResourceID)
	}
	if sealed.ResourceType != ResourceTypePatient {
		t.Errorf("expected Patient resource type, got %s", sealed.ResourceType)
	}
	if sealed.ResourceHash == "" {
		t.Error("expected non-empty resource hash")
	}
}

func TestVerifyResource(t *testing.T) {
	bridge := newTestBridge(t)
	ctx := context.Background()

	patient := testPatient()
	sealed, err := bridge.SealResource(ctx, patient)
	if err != nil {
		t.Fatalf("SealResource failed: %v", err)
	}

	result, err := bridge.VerifyResource(ctx, patient, sealed.SealID)
	if err != nil {
		t.Fatalf("VerifyResource failed: %v", err)
	}

	if !result.DataIntact {
		t.Error("expected data to be intact")
	}
	if result.ResourceType != ResourceTypePatient {
		t.Errorf("expected Patient, got %s", result.ResourceType)
	}
}

func TestImportResource_Patient(t *testing.T) {
	bridge := newTestBridge(t)
	ctx := context.Background()

	patientJSON := `{
		"resourceType": "Patient",
		"id": "patient-import-001",
		"active": true,
		"gender": "female",
		"birthDate": "1985-03-22",
		"name": [{"family": "Doe", "given": ["Jane"]}]
	}`

	result, err := bridge.ImportResource(ctx, []byte(patientJSON))
	if err != nil {
		t.Fatalf("ImportResource failed: %v", err)
	}

	if !result.Sealed {
		t.Error("expected resource to be sealed")
	}
	if result.Resource.GetID() != "patient-import-001" {
		t.Errorf("expected ID 'patient-import-001', got '%s'", result.Resource.GetID())
	}
	if result.SealedResource == nil {
		t.Error("expected sealed resource to be set")
	}
}

func TestImportResource_UnsupportedType(t *testing.T) {
	bridge := newTestBridge(t)
	ctx := context.Background()

	badJSON := `{"resourceType": "Procedure", "id": "proc-001"}`
	_, err := bridge.ImportResource(ctx, []byte(badJSON))
	if err == nil {
		t.Error("expected error for unsupported resource type")
	}
}

func TestExportResource(t *testing.T) {
	bridge := newTestBridge(t)
	ctx := context.Background()

	patient := testPatient()
	sealed, err := bridge.SealResource(ctx, patient)
	if err != nil {
		t.Fatalf("SealResource failed: %v", err)
	}

	exported, err := bridge.ExportResource(ctx, sealed.SealID)
	if err != nil {
		t.Fatalf("ExportResource failed: %v", err)
	}

	var decoded Patient
	if err := json.Unmarshal(exported, &decoded); err != nil {
		t.Fatalf("failed to unmarshal exported resource: %v", err)
	}
	if decoded.ID != patient.ID {
		t.Errorf("expected ID %s, got %s", patient.ID, decoded.ID)
	}
}

func TestResourceToSealRequest(t *testing.T) {
	bridge := newTestBridge(t)
	patient := testPatient()
	data, _ := json.Marshal(patient)

	req := bridge.ResourceToSealRequest(patient, data)
	if req.Purpose == "" {
		t.Error("expected non-empty purpose")
	}
	if req.RegulatoryInfo == nil {
		t.Fatal("expected regulatory info to be set")
	}
	if req.RegulatoryInfo.DataClassification != "phi" {
		t.Errorf("expected 'phi' classification, got '%s'", req.RegulatoryInfo.DataClassification)
	}
	if len(req.RegulatoryInfo.ComplianceFrameworks) == 0 {
		t.Error("expected at least one compliance framework")
	}
}

func TestGetSealID(t *testing.T) {
	bridge := newTestBridge(t)
	ctx := context.Background()

	patient := testPatient()
	_, err := bridge.SealResource(ctx, patient)
	if err != nil {
		t.Fatalf("SealResource failed: %v", err)
	}

	sealID, ok := bridge.GetSealID("patient-001")
	if !ok {
		t.Error("expected seal ID to be found")
	}
	if sealID == "" {
		t.Error("expected non-empty seal ID")
	}
}

// ---------------------------------------------------------------------------
// Consent Manager tests
// ---------------------------------------------------------------------------

func TestConsentManager_CreateAndValidate(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{
		RequireExplicit: true,
		AllowedPurposes: []string{"TREAT", "HPAYMT", "RESEARCH"},
	})
	ctx := context.Background()

	consent := testConsent()
	sealed, err := cm.CreateConsent(ctx, consent)
	if err != nil {
		t.Fatalf("CreateConsent failed: %v", err)
	}
	if sealed.ConsentID != "consent-001" {
		t.Errorf("expected consent-001, got %s", sealed.ConsentID)
	}

	// Validate consent.
	valid, err := cm.ValidateConsent(ctx, "Patient/patient-001", "TREAT")
	if err != nil {
		t.Fatalf("ValidateConsent failed: %v", err)
	}
	if !valid {
		t.Error("expected consent to be valid for TREAT purpose")
	}

	// Validate disallowed purpose.
	valid, err = cm.ValidateConsent(ctx, "Patient/patient-001", "MARKETING")
	if err != nil {
		t.Fatalf("ValidateConsent failed: %v", err)
	}
	if valid {
		t.Error("expected consent to be invalid for MARKETING purpose")
	}
}

func TestConsentManager_RequireExplicit(t *testing.T) {
	cm := NewConsentManager(nil, ConsentPolicy{
		RequireExplicit: true,
	})
	ctx := context.Background()

	// No consents exist; explicit mode should deny.
	valid, err := cm.ValidateConsent(ctx, "Patient/unknown", "TREAT")
	if err != nil {
		t.Fatalf("ValidateConsent failed: %v", err)
	}
	if valid {
		t.Error("expected denial when no explicit consent exists")
	}
}

func TestConsentManager_ImpliedConsent(t *testing.T) {
	cm := NewConsentManager(nil, ConsentPolicy{
		RequireExplicit: false,
	})
	ctx := context.Background()

	// No consents exist; implied mode should allow.
	valid, err := cm.ValidateConsent(ctx, "Patient/unknown", "TREAT")
	if err != nil {
		t.Fatalf("ValidateConsent failed: %v", err)
	}
	if !valid {
		t.Error("expected approval under implied consent model")
	}
}

func TestConsentManager_Revoke(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{
		RequireExplicit: true,
		AllowedPurposes: []string{"TREAT"},
	})
	ctx := context.Background()

	consent := testConsent()
	_, err := cm.CreateConsent(ctx, consent)
	if err != nil {
		t.Fatalf("CreateConsent failed: %v", err)
	}

	// Revoke.
	if err := cm.RevokeConsent(ctx, "consent-001"); err != nil {
		t.Fatalf("RevokeConsent failed: %v", err)
	}

	// Validate should now deny.
	valid, err := cm.ValidateConsent(ctx, "Patient/patient-001", "TREAT")
	if err != nil {
		t.Fatalf("ValidateConsent failed: %v", err)
	}
	if valid {
		t.Error("expected denial after revocation")
	}
}

func TestConsentManager_RevokeNotFound(t *testing.T) {
	cm := NewConsentManager(nil, ConsentPolicy{})
	ctx := context.Background()

	err := cm.RevokeConsent(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error when revoking non-existent consent")
	}
}

func TestConsentManager_GetActiveConsents(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{})
	ctx := context.Background()

	consent := testConsent()
	_, err := cm.CreateConsent(ctx, consent)
	if err != nil {
		t.Fatalf("CreateConsent failed: %v", err)
	}

	active, err := cm.GetActiveConsents(ctx, "Patient/patient-001")
	if err != nil {
		t.Fatalf("GetActiveConsents failed: %v", err)
	}
	if len(active) != 1 {
		t.Errorf("expected 1 active consent, got %d", len(active))
	}
}

func TestConsentManager_ConsentCount(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{})
	ctx := context.Background()

	if cm.ConsentCount() != 0 {
		t.Error("expected 0 consents initially")
	}

	consent := testConsent()
	_, _ = cm.CreateConsent(ctx, consent)
	if cm.ConsentCount() != 1 {
		t.Errorf("expected 1 consent, got %d", cm.ConsentCount())
	}
}

// ---------------------------------------------------------------------------
// Audit Event Generator tests
// ---------------------------------------------------------------------------

func TestGenerateAuditEvent(t *testing.T) {
	gen := NewAuditEventGenerator("Device/aethelred-node-1", "Aethelred Node 1")

	record := &keeper.AuditRecord{
		Sequence:     1,
		RecordHash:   "abc123",
		PreviousHash: "genesis",
		Category:     keeper.AuditCategorySecurity,
		Severity:     keeper.AuditSeverityCritical,
		Action:       "security_alert",
		BlockHeight:  100,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Actor:        "system",
		Details: map[string]string{
			"alert_type": "intrusion",
		},
	}

	event, err := gen.GenerateAuditEvent(record)
	if err != nil {
		t.Fatalf("GenerateAuditEvent failed: %v", err)
	}

	if event.ID == "" {
		t.Error("expected non-empty event ID")
	}
	if event.ResourceType != "AuditEvent" {
		t.Errorf("expected 'AuditEvent', got '%s'", event.ResourceType)
	}
	if event.Recorded.IsZero() {
		t.Error("expected non-zero recorded time")
	}
	if len(event.Agent) == 0 {
		t.Error("expected at least one agent")
	}
}

func TestGenerateAccessAuditEvent(t *testing.T) {
	gen := NewAuditEventGenerator("Device/aethelred-node-1", "Aethelred Node 1")

	event, err := gen.GenerateAccessAuditEvent("Practitioner/dr-smith", "Patient/patient-001", "read")
	if err != nil {
		t.Fatalf("GenerateAccessAuditEvent failed: %v", err)
	}

	if event.Action != AuditEventActionRead {
		t.Errorf("expected Read action, got %s", event.Action)
	}
	if len(event.Entity) == 0 {
		t.Error("expected entity to reference the patient")
	}
}

func TestGenerateConsentAuditEvent(t *testing.T) {
	gen := NewAuditEventGenerator("Device/aethelred-node-1", "Aethelred Node 1")

	consent := testConsent()
	event, err := gen.GenerateConsentAuditEvent(&consent, "create")
	if err != nil {
		t.Fatalf("GenerateConsentAuditEvent failed: %v", err)
	}

	if event.Action != AuditEventActionCreate {
		t.Errorf("expected Create action, got %s", event.Action)
	}
}

func TestExportAuditEvents(t *testing.T) {
	gen := NewAuditEventGenerator("Device/aethelred-node-1", "Aethelred Node 1")
	ctx := context.Background()

	// Generate several events.
	consent := testConsent()
	_, _ = gen.GenerateConsentAuditEvent(&consent, "create")
	_, _ = gen.GenerateAccessAuditEvent("Practitioner/dr-smith", "Patient/patient-001", "read")
	_, _ = gen.GenerateAccessAuditEvent("Practitioner/dr-jones", "Patient/patient-002", "update")

	// Export all.
	events, err := gen.ExportAuditEvents(ctx, nil)
	if err != nil {
		t.Fatalf("ExportAuditEvents failed: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}

	// Export with action filter.
	events, err = gen.ExportAuditEvents(ctx, &AuditEventFilter{Action: AuditEventActionRead})
	if err != nil {
		t.Fatalf("ExportAuditEvents with filter failed: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 Read event, got %d", len(events))
	}

	// Export with limit.
	events, err = gen.ExportAuditEvents(ctx, &AuditEventFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ExportAuditEvents with limit failed: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events with limit, got %d", len(events))
	}
}

func TestEventCount(t *testing.T) {
	gen := NewAuditEventGenerator("Device/test", "Test")
	if gen.EventCount() != 0 {
		t.Error("expected 0 events initially")
	}

	consent := testConsent()
	_, _ = gen.GenerateConsentAuditEvent(&consent, "create")
	if gen.EventCount() != 1 {
		t.Errorf("expected 1 event, got %d", gen.EventCount())
	}
}

// ---------------------------------------------------------------------------
// Strict validator tests
// ---------------------------------------------------------------------------

func TestStrictValidator_PatientNoName(t *testing.T) {
	v := NewStrictValidator()
	p := &Patient{
		ResourceType: "Patient",
		ID:           "patient-strict-001",
		Gender:       "female",
	}
	result := v.ValidatePatient(p)
	if !result.Valid {
		t.Error("patient without name should be valid (name is recommended, not required)")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning about missing name in strict mode")
	}
}

// ---------------------------------------------------------------------------
// FHIR Date validation tests
// ---------------------------------------------------------------------------

func TestIsValidFHIRDate(t *testing.T) {
	validDates := []string{"2024-01-15", "2024-01", "2024"}
	for _, d := range validDates {
		if !isValidFHIRDate(d) {
			t.Errorf("expected '%s' to be a valid FHIR date", d)
		}
	}

	invalidDates := []string{"15-01-2024", "not-a-date"}
	for _, d := range invalidDates {
		if isValidFHIRDate(d) {
			t.Errorf("expected '%s' to be an invalid FHIR date", d)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge-case, error-path, and concurrency tests
// ---------------------------------------------------------------------------

func TestBridge_NilResource(t *testing.T) {
	bridge := newTestBridge(t)
	_, err := bridge.SealResource(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil resource")
	}
	if !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected ErrInvalidResource, got %v", err)
	}
}

func TestBridge_EmptyResourceID(t *testing.T) {
	bridge := newTestBridge(t)
	p := testPatient()
	p.ID = ""
	_, err := bridge.SealResource(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for empty resource ID")
	}
	if !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected ErrInvalidResource, got %v", err)
	}
}

func TestBridge_SealSDKFailure(t *testing.T) {
	// Use a keeper that always fails on CreateSeal.
	failKeeper := &failingSealKeeper{fail: true}
	sealSDK, err := sdk.NewSealSDK(sdk.Config{
		ChainID:       "test-chain-1",
		SignerAddress: "aethelred1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tp2",
	}, failKeeper)
	if err != nil {
		t.Fatalf("failed to create seal SDK: %v", err)
	}

	bridge, err := NewFHIRBridge(BridgeConfig{
		DefaultJurisdiction:  "US",
		DefaultRetentionDays: 2555,
	}, sealSDK)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = bridge.SealResource(ctx, testPatient())
	if err == nil {
		t.Fatal("expected error when SDK always fails")
	}
	if !errors.Is(err, ErrSealFailed) {
		t.Fatalf("expected ErrSealFailed, got %v", err)
	}
}

func TestBridge_RetrySucceedsOnSecondAttempt(t *testing.T) {
	retryKeeper := &retrySealKeeper{
		inner:      newMockSealKeeper(),
		failCount:  1,
		callCount:  0,
	}
	sealSDK, err := sdk.NewSealSDK(sdk.Config{
		ChainID:       "test-chain-1",
		SignerAddress: "aethelred1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tp2",
	}, retryKeeper)
	if err != nil {
		t.Fatalf("failed to create seal SDK: %v", err)
	}

	bridge, err := NewFHIRBridge(BridgeConfig{
		DefaultJurisdiction: "US",
	}, sealSDK)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	sealed, err := bridge.SealResource(context.Background(), testPatient())
	if err != nil {
		t.Fatalf("expected retry success, got error: %v", err)
	}
	if sealed.SealID == "" {
		t.Fatal("expected non-empty seal ID after retry")
	}
}

func TestConsent_ConcurrentValidation(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{
		RequireExplicit: true,
		AllowedPurposes: []string{"TREAT"},
	})
	ctx := context.Background()

	consent := testConsent()
	_, err := cm.CreateConsent(ctx, consent)
	if err != nil {
		t.Fatalf("CreateConsent failed: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			valid, err := cm.ValidateConsent(ctx, "Patient/patient-001", "TREAT")
			if err != nil {
				errs <- err
				return
			}
			if !valid {
				errs <- fmt.Errorf("expected consent to be valid")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent validation error: %v", e)
	}
}

func TestConsent_ConcurrentCreateRevoke(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{
		RequireExplicit: true,
		AllowedPurposes: []string{"TREAT"},
	})
	ctx := context.Background()

	var wg sync.WaitGroup
	// Create 10 consents concurrently.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := testConsent()
			c.ID = fmt.Sprintf("consent-race-%d", idx)
			c.Patient = &Reference{Reference: fmt.Sprintf("Patient/race-%d", idx)}
			_, _ = cm.CreateConsent(ctx, c)
		}(i)
	}
	wg.Wait()

	// Revoke some concurrently.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = cm.RevokeConsent(ctx, fmt.Sprintf("consent-race-%d", idx))
		}(i)
	}
	wg.Wait()

	if cm.ConsentCount() != 10 {
		t.Errorf("expected 10 consents, got %d", cm.ConsentCount())
	}
}

func TestConsent_RevokedConsent(t *testing.T) {
	bridge := newTestBridge(t)
	cm := NewConsentManager(bridge, ConsentPolicy{
		RequireExplicit: true,
		AllowedPurposes: []string{"TREAT"},
	})
	ctx := context.Background()

	consent := testConsent()
	_, err := cm.CreateConsent(ctx, consent)
	if err != nil {
		t.Fatalf("CreateConsent failed: %v", err)
	}

	err = cm.RevokeConsent(ctx, "consent-001")
	if err != nil {
		t.Fatalf("RevokeConsent failed: %v", err)
	}

	// Revoking again should yield ErrConsentRevoked.
	err = cm.RevokeConsent(ctx, "consent-001")
	if err == nil {
		t.Fatal("expected error revoking already revoked consent")
	}
	if !errors.Is(err, ErrConsentRevoked) {
		t.Fatalf("expected ErrConsentRevoked, got %v", err)
	}
}

func TestValidator_NilResource(t *testing.T) {
	v := NewValidator()
	result := v.ValidateResource(nil)
	if result.Valid {
		t.Error("expected invalid for nil resource")
	}
}

func TestValidator_AllResourceTypes(t *testing.T) {
	v := NewValidator()
	now := time.Now().UTC()

	tests := []struct {
		name     string
		resource Resource
	}{
		{"Patient", &Patient{ResourceType: "Patient", ID: "p1"}},
		{"Observation", &Observation{
			ResourceType: "Observation", ID: "o1", Status: ObservationStatusFinal,
			Code: CodeableConcept{Text: "test"},
		}},
		{"DiagnosticReport", &DiagnosticReport{
			ResourceType: "DiagnosticReport", ID: "d1", Status: "final",
			Code: CodeableConcept{Text: "test"},
		}},
		{"Medication", &Medication{
			ResourceType: "Medication", ID: "m1",
			Code: CodeableConcept{Text: "aspirin"},
		}},
		{"Consent", &Consent{
			ResourceType: "Consent", ID: "c1", Status: ConsentStatusActive,
			Scope: CodeableConcept{Text: "privacy"},
		}},
		{"AuditEvent", &AuditEvent{
			ResourceType: "AuditEvent", ID: "a1", Recorded: now,
			Code:   CodeableConcept{Text: "test"},
			Agent:  []AuditEventAgent{{Who: Reference{Reference: "sys"}, Requestor: true}},
			Source: AuditEventSource{Observer: Reference{Reference: "Device/test"}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateResource(tt.resource)
			if !result.Valid {
				t.Errorf("expected valid %s, got errors: %v", tt.name, result.Errors)
			}
		})
	}
}

func TestValidator_InvalidStatus(t *testing.T) {
	v := NewValidator()

	obs := testObservation()
	obs.Status = "bogus-status"
	result := v.ValidateObservation(obs)
	if result.Valid {
		t.Error("expected invalid for bogus observation status")
	}

	c := testConsent()
	c.Status = "not-a-status"
	cResult := v.ValidateConsent(&c)
	if cResult.Valid {
		t.Error("expected invalid for bogus consent status")
	}
}

func TestAuditEvent_NilRecord(t *testing.T) {
	gen := NewAuditEventGenerator("Device/test", "Test")
	_, err := gen.GenerateAuditEvent(nil)
	if err == nil {
		t.Fatal("expected error for nil record")
	}
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("expected ErrAuditFailed, got %v", err)
	}
}

func TestAuditEvent_AllCategories(t *testing.T) {
	gen := NewAuditEventGenerator("Device/test", "Test")

	categories := []keeper.AuditCategory{
		keeper.AuditCategorySecurity,
		keeper.AuditCategoryVerification,
		keeper.AuditCategoryJob,
		keeper.AuditCategoryGovernance,
	}

	for _, cat := range categories {
		record := &keeper.AuditRecord{
			Category:  cat,
			Severity:  keeper.AuditSeverityInfo,
			Action:    "test_action",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Actor:     "test-actor",
		}
		event, err := gen.GenerateAuditEvent(record)
		if err != nil {
			t.Errorf("GenerateAuditEvent(%s) failed: %v", cat, err)
			continue
		}
		if event.ID == "" {
			t.Errorf("expected non-empty ID for category %s", cat)
		}
		if len(event.Category) == 0 {
			t.Errorf("expected category for %s", cat)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper mock: failing keeper for seal retry tests
// ---------------------------------------------------------------------------

type failingSealKeeper struct {
	fail bool
}

func (f *failingSealKeeper) CreateSeal(_ context.Context, _ *sealtypes.DigitalSeal) error {
	if f.fail {
		return fmt.Errorf("simulated CreateSeal failure")
	}
	return nil
}
func (f *failingSealKeeper) GetSeal(_ context.Context, _ string) (*sealtypes.DigitalSeal, error) {
	return nil, nil
}
func (f *failingSealKeeper) SetSeal(_ context.Context, _ *sealtypes.DigitalSeal) error { return nil }
func (f *failingSealKeeper) RevokeSeal(_ context.Context, _ string, _ string) error    { return nil }
func (f *failingSealKeeper) VerifySeal(_ context.Context, _ string) (bool, error)      { return false, nil }
func (f *failingSealKeeper) ListSeals(_ context.Context, _ int, _ int) ([]*sealtypes.DigitalSeal, error) {
	return nil, nil
}
func (f *failingSealKeeper) ListSealsByModel(_ context.Context, _ []byte) ([]*sealtypes.DigitalSeal, error) {
	return nil, nil
}
func (f *failingSealKeeper) ListSealsByRequester(_ context.Context, _ string) ([]*sealtypes.DigitalSeal, error) {
	return nil, nil
}

// retrySealKeeper fails the first N create calls, then delegates to inner.
type retrySealKeeper struct {
	inner     *mockSealKeeper
	failCount int
	callCount int
}

func (r *retrySealKeeper) CreateSeal(ctx context.Context, seal *sealtypes.DigitalSeal) error {
	r.callCount++
	if r.callCount <= r.failCount {
		return fmt.Errorf("simulated transient failure %d", r.callCount)
	}
	return r.inner.CreateSeal(ctx, seal)
}
func (r *retrySealKeeper) GetSeal(ctx context.Context, id string) (*sealtypes.DigitalSeal, error) {
	return r.inner.GetSeal(ctx, id)
}
func (r *retrySealKeeper) SetSeal(ctx context.Context, seal *sealtypes.DigitalSeal) error {
	return r.inner.SetSeal(ctx, seal)
}
func (r *retrySealKeeper) RevokeSeal(ctx context.Context, id string, reason string) error {
	return r.inner.RevokeSeal(ctx, id, reason)
}
func (r *retrySealKeeper) VerifySeal(ctx context.Context, id string) (bool, error) {
	return r.inner.VerifySeal(ctx, id)
}
func (r *retrySealKeeper) ListSeals(ctx context.Context, offset int, limit int) ([]*sealtypes.DigitalSeal, error) {
	return r.inner.ListSeals(ctx, offset, limit)
}
func (r *retrySealKeeper) ListSealsByModel(ctx context.Context, model []byte) ([]*sealtypes.DigitalSeal, error) {
	return r.inner.ListSealsByModel(ctx, model)
}
func (r *retrySealKeeper) ListSealsByRequester(ctx context.Context, req string) ([]*sealtypes.DigitalSeal, error) {
	return r.inner.ListSealsByRequester(ctx, req)
}
