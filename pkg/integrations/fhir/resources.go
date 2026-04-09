// Package fhir provides a bidirectional bridge between FHIR R5 healthcare
// data standards and the Aethelred trust infrastructure. It enables sealing,
// verification, consent management, and audit event generation for healthcare
// resources, supporting HIPAA and GDPR compliance workflows.
package fhir

import (
	"time"
)

// ---------------------------------------------------------------------------
// FHIR R5 Resource Types
// ---------------------------------------------------------------------------
//
// These types model the core FHIR R5 resources used for healthcare data
// exchange. Field names and JSON tags follow the HL7 FHIR R5 specification
// (https://hl7.org/fhir/R5/) to ensure interoperability with conformant
// systems.
// ---------------------------------------------------------------------------

// ResourceType identifies the kind of FHIR resource.
type ResourceType string

const (
	ResourceTypePatient          ResourceType = "Patient"
	ResourceTypeObservation      ResourceType = "Observation"
	ResourceTypeDiagnosticReport ResourceType = "DiagnosticReport"
	ResourceTypeMedication       ResourceType = "Medication"
	ResourceTypeConsent          ResourceType = "Consent"
	ResourceTypeAuditEvent       ResourceType = "AuditEvent"
	ResourceTypeBundle           ResourceType = "Bundle"
)

// ---------------------------------------------------------------------------
// Common Types
// ---------------------------------------------------------------------------

// Reference is a FHIR Reference to another resource.
type Reference struct {
	Reference string `json:"reference,omitempty"`
	Type      string `json:"type,omitempty"`
	Display   string `json:"display,omitempty"`
}

// CodeableConcept represents a value defined by one or more coding systems.
type CodeableConcept struct {
	Coding []Coding `json:"coding,omitempty"`
	Text   string   `json:"text,omitempty"`
}

// Coding is a reference to a terminology or classification code.
type Coding struct {
	System  string `json:"system,omitempty"`
	Code    string `json:"code,omitempty"`
	Display string `json:"display,omitempty"`
}

// Identifier is a business identifier for a resource.
type Identifier struct {
	System string `json:"system,omitempty"`
	Value  string `json:"value,omitempty"`
	Use    string `json:"use,omitempty"`
}

// HumanName represents a person's name in FHIR format.
type HumanName struct {
	Use    string   `json:"use,omitempty"`
	Family string   `json:"family,omitempty"`
	Given  []string `json:"given,omitempty"`
	Prefix []string `json:"prefix,omitempty"`
	Suffix []string `json:"suffix,omitempty"`
	Text   string   `json:"text,omitempty"`
}

// Period represents a time range.
type Period struct {
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

// Quantity is a measured amount with a unit.
type Quantity struct {
	Value  float64 `json:"value,omitempty"`
	Unit   string  `json:"unit,omitempty"`
	System string  `json:"system,omitempty"`
	Code   string  `json:"code,omitempty"`
}

// ---------------------------------------------------------------------------
// Patient
// ---------------------------------------------------------------------------

// Patient represents a FHIR R5 Patient resource — an individual receiving
// care or other health-related services.
type Patient struct {
	ResourceType string       `json:"resourceType"`
	ID           string       `json:"id,omitempty"`
	Identifier   []Identifier `json:"identifier,omitempty"`
	Active       bool         `json:"active"`
	Name         []HumanName  `json:"name,omitempty"`
	Gender       string       `json:"gender,omitempty"`
	BirthDate    string       `json:"birthDate,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (p *Patient) GetResourceType() ResourceType { return ResourceTypePatient }

// GetID returns the logical ID.
func (p *Patient) GetID() string { return p.ID }

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

// ObservationStatus defines allowed status values per the FHIR R5 spec.
type ObservationStatus string

const (
	ObservationStatusRegistered ObservationStatus = "registered"
	ObservationStatusPreliminary ObservationStatus = "preliminary"
	ObservationStatusFinal       ObservationStatus = "final"
	ObservationStatusAmended     ObservationStatus = "amended"
	ObservationStatusCorrected   ObservationStatus = "corrected"
	ObservationStatusCancelled   ObservationStatus = "cancelled"
	ObservationStatusEnteredInError ObservationStatus = "entered-in-error"
	ObservationStatusUnknown     ObservationStatus = "unknown"
)

// Observation represents a FHIR R5 Observation — measurements or assertions
// about a patient or other subject.
type Observation struct {
	ResourceType      string            `json:"resourceType"`
	ID                string            `json:"id,omitempty"`
	Status            ObservationStatus `json:"status"`
	Code              CodeableConcept   `json:"code"`
	Subject           *Reference        `json:"subject,omitempty"`
	ValueQuantity     *Quantity         `json:"valueQuantity,omitempty"`
	ValueString       string            `json:"valueString,omitempty"`
	EffectiveDateTime *time.Time        `json:"effectiveDateTime,omitempty"`
	Performer         []Reference       `json:"performer,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (o *Observation) GetResourceType() ResourceType { return ResourceTypeObservation }

// GetID returns the logical ID.
func (o *Observation) GetID() string { return o.ID }

// ---------------------------------------------------------------------------
// DiagnosticReport
// ---------------------------------------------------------------------------

// DiagnosticReportStatus defines allowed diagnostic report statuses.
type DiagnosticReportStatus string

const (
	DiagnosticReportStatusRegistered    DiagnosticReportStatus = "registered"
	DiagnosticReportStatusPartial       DiagnosticReportStatus = "partial"
	DiagnosticReportStatusPreliminary   DiagnosticReportStatus = "preliminary"
	DiagnosticReportStatusFinal         DiagnosticReportStatus = "final"
	DiagnosticReportStatusAmended       DiagnosticReportStatus = "amended"
	DiagnosticReportStatusCorrected     DiagnosticReportStatus = "corrected"
	DiagnosticReportStatusAppended      DiagnosticReportStatus = "appended"
	DiagnosticReportStatusCancelled     DiagnosticReportStatus = "cancelled"
	DiagnosticReportStatusEnteredInError DiagnosticReportStatus = "entered-in-error"
)

// DiagnosticReport represents a FHIR R5 DiagnosticReport.
type DiagnosticReport struct {
	ResourceType string                 `json:"resourceType"`
	ID           string                 `json:"id,omitempty"`
	Status       DiagnosticReportStatus `json:"status"`
	Code         CodeableConcept        `json:"code"`
	Subject      *Reference             `json:"subject,omitempty"`
	Issued       *time.Time             `json:"issued,omitempty"`
	Result       []Reference            `json:"result,omitempty"`
	Conclusion   string                 `json:"conclusion,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (d *DiagnosticReport) GetResourceType() ResourceType { return ResourceTypeDiagnosticReport }

// GetID returns the logical ID.
func (d *DiagnosticReport) GetID() string { return d.ID }

// ---------------------------------------------------------------------------
// Medication
// ---------------------------------------------------------------------------

// MedicationStatus defines allowed medication statuses.
type MedicationStatus string

const (
	MedicationStatusActive         MedicationStatus = "active"
	MedicationStatusInactive       MedicationStatus = "inactive"
	MedicationStatusEnteredInError MedicationStatus = "entered-in-error"
)

// Ingredient describes a medication ingredient.
type Ingredient struct {
	Item     CodeableConcept `json:"item"`
	IsActive bool            `json:"isActive"`
	Strength *Quantity       `json:"strength,omitempty"`
}

// Medication represents a FHIR R5 Medication resource.
type Medication struct {
	ResourceType string           `json:"resourceType"`
	ID           string           `json:"id,omitempty"`
	Code         CodeableConcept  `json:"code"`
	Status       MedicationStatus `json:"status"`
	Form         *CodeableConcept `json:"doseForm,omitempty"`
	Ingredient   []Ingredient     `json:"ingredient,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (m *Medication) GetResourceType() ResourceType { return ResourceTypeMedication }

// GetID returns the logical ID.
func (m *Medication) GetID() string { return m.ID }

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

// ConsentStatus defines allowed consent statuses per FHIR R5.
type ConsentStatus string

const (
	ConsentStatusDraft    ConsentStatus = "draft"
	ConsentStatusActive   ConsentStatus = "active"
	ConsentStatusInactive ConsentStatus = "inactive"
	ConsentStatusNotDone  ConsentStatus = "not-done"
	ConsentStatusEnteredInError ConsentStatus = "entered-in-error"
)

// ConsentProvision describes a consent rule tree.
type ConsentProvision struct {
	Type   string          `json:"type,omitempty"` // "deny" or "permit"
	Period *Period         `json:"period,omitempty"`
	Actor  []ConsentActor  `json:"actor,omitempty"`
	Action []CodeableConcept `json:"action,omitempty"`
	Purpose []Coding        `json:"purpose,omitempty"`
}

// ConsentActor identifies an actor in a consent provision.
type ConsentActor struct {
	Role      CodeableConcept `json:"role"`
	Reference Reference       `json:"reference"`
}

// Consent represents a FHIR R5 Consent resource — a record of a
// healthcare consumer's privacy choices.
type Consent struct {
	ResourceType string             `json:"resourceType"`
	ID           string             `json:"id,omitempty"`
	Status       ConsentStatus      `json:"status"`
	Scope        CodeableConcept    `json:"scope"`
	Category     []CodeableConcept  `json:"category,omitempty"`
	Patient      *Reference         `json:"subject,omitempty"`
	DateTime     *time.Time         `json:"dateTime,omitempty"`
	Grantor      []Reference        `json:"grantor,omitempty"`
	PolicyRule   *CodeableConcept   `json:"policyRule,omitempty"`
	Provision    *ConsentProvision  `json:"provision,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (c *Consent) GetResourceType() ResourceType { return ResourceTypeConsent }

// GetID returns the logical ID.
func (c *Consent) GetID() string { return c.ID }

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

// AuditEventAction defines the action that was audited per FHIR R5.
type AuditEventAction string

const (
	AuditEventActionCreate  AuditEventAction = "C"
	AuditEventActionRead    AuditEventAction = "R"
	AuditEventActionUpdate  AuditEventAction = "U"
	AuditEventActionDelete  AuditEventAction = "D"
	AuditEventActionExecute AuditEventAction = "E"
)

// AuditEventOutcome describes the outcome severity per FHIR R5.
type AuditEventOutcome struct {
	Code    Coding `json:"code"`
	Detail  []CodeableConcept `json:"detail,omitempty"`
}

// AuditEventAgent identifies the user or system that performed the action.
type AuditEventAgent struct {
	Type      *CodeableConcept `json:"type,omitempty"`
	Who       Reference        `json:"who"`
	Requestor bool             `json:"requestor"`
	Network   string           `json:"networkString,omitempty"`
}

// AuditEventSource identifies the source system of the event.
type AuditEventSource struct {
	Observer Reference        `json:"observer"`
	Type     []CodeableConcept `json:"type,omitempty"`
}

// AuditEventEntity identifies the data objects involved.
type AuditEventEntity struct {
	What   *Reference       `json:"what,omitempty"`
	Role   *CodeableConcept `json:"role,omitempty"`
	Query  []byte           `json:"query,omitempty"`
}

// AuditEvent represents a FHIR R5 AuditEvent resource — a record of a
// security-relevant event.
type AuditEvent struct {
	ResourceType string             `json:"resourceType"`
	ID           string             `json:"id,omitempty"`
	Category     []CodeableConcept  `json:"category,omitempty"`
	Code         CodeableConcept    `json:"code"`
	Action       AuditEventAction   `json:"action,omitempty"`
	Recorded     time.Time          `json:"recorded"`
	Outcome      *AuditEventOutcome `json:"outcome,omitempty"`
	Agent        []AuditEventAgent  `json:"agent,omitempty"`
	Source       AuditEventSource   `json:"source"`
	Entity       []AuditEventEntity `json:"entity,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (a *AuditEvent) GetResourceType() ResourceType { return ResourceTypeAuditEvent }

// GetID returns the logical ID.
func (a *AuditEvent) GetID() string { return a.ID }

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

// BundleType defines the FHIR R5 bundle types.
type BundleType string

const (
	BundleTypeDocument    BundleType = "document"
	BundleTypeMessage     BundleType = "message"
	BundleTypeTransaction BundleType = "transaction"
	BundleTypeBatch       BundleType = "batch"
	BundleTypeSearchset   BundleType = "searchset"
	BundleTypeCollection  BundleType = "collection"
)

// BundleEntry is a single entry in a FHIR Bundle.
type BundleEntry struct {
	FullURL  string      `json:"fullUrl,omitempty"`
	Resource interface{} `json:"resource,omitempty"`
}

// Bundle represents a FHIR R5 Bundle — a container for a collection
// of resources.
type Bundle struct {
	ResourceType string        `json:"resourceType"`
	ID           string        `json:"id,omitempty"`
	Type         BundleType    `json:"type"`
	Total        int           `json:"total,omitempty"`
	Entry        []BundleEntry `json:"entry,omitempty"`
}

// GetResourceType returns the FHIR resource type.
func (b *Bundle) GetResourceType() ResourceType { return ResourceTypeBundle }

// GetID returns the logical ID.
func (b *Bundle) GetID() string { return b.ID }

// ---------------------------------------------------------------------------
// Resource Interface
// ---------------------------------------------------------------------------

// Resource is the common interface implemented by all FHIR resource types.
type Resource interface {
	GetResourceType() ResourceType
	GetID() string
}
