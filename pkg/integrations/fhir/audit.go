package fhir

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// FHIR AuditEvent Generation
// ---------------------------------------------------------------------------
//
// AuditEventGenerator converts Aethelred audit records into FHIR R5
// AuditEvent resources. This enables healthcare systems to consume
// Aethelred's cryptographic audit trail in a standards-compliant format.
// ---------------------------------------------------------------------------

// AuditEventGenerator converts between Aethelred audit records and FHIR
// AuditEvent resources.
type AuditEventGenerator struct {
	mu     sync.Mutex
	events []AuditEvent

	// sourceObserver identifies this system as the audit event source.
	sourceObserver Reference

	// sequenceCounter generates unique event IDs.
	sequenceCounter uint64
}

// NewAuditEventGenerator creates a new generator with the given system
// identity.
func NewAuditEventGenerator(systemID, systemDisplay string) *AuditEventGenerator {
	return &AuditEventGenerator{
		events: make([]AuditEvent, 0),
		sourceObserver: Reference{
			Reference: systemID,
			Type:      "Device",
			Display:   systemDisplay,
		},
	}
}

// GenerateAuditEvent converts an Aethelred AuditRecord to a FHIR R5
// AuditEvent resource.
func (g *AuditEventGenerator) GenerateAuditEvent(record *keeper.AuditRecord) (*AuditEvent, error) {
	if record == nil {
		return nil, fmt.Errorf("AuditEventGenerator.GenerateAuditEvent: %w: record is nil", ErrAuditFailed)
	}

	g.mu.Lock()
	g.sequenceCounter++
	eventID := fmt.Sprintf("audit-event-%d", g.sequenceCounter)
	g.mu.Unlock()

	// Map Aethelred audit category to FHIR AuditEvent category.
	category := mapAuditCategory(record.Category)

	// Map action to FHIR action code.
	action := mapAuditAction(record.Action)

	// Parse the timestamp.
	recorded, err := time.Parse(time.RFC3339, record.Timestamp)
	if err != nil {
		recorded = time.Now().UTC()
	}

	// Map severity to FHIR outcome.
	outcome := mapAuditOutcome(record.Severity)

	event := &AuditEvent{
		ResourceType: "AuditEvent",
		ID:           eventID,
		Category:     []CodeableConcept{category},
		Code: CodeableConcept{
			Coding: []Coding{
				{
					System:  "https://aethelred.io/fhir/audit-event-type",
					Code:    record.Action,
					Display: record.Action,
				},
			},
			Text: record.Action,
		},
		Action:   action,
		Recorded: recorded,
		Outcome:  outcome,
		Agent: []AuditEventAgent{
			{
				Who: Reference{
					Reference: record.Actor,
					Display:   record.Actor,
				},
				Requestor: true,
			},
		},
		Source: AuditEventSource{
			Observer: g.sourceObserver,
			Type: []CodeableConcept{
				{
					Coding: []Coding{
						{
							System:  "http://terminology.hl7.org/CodeSystem/security-source-type",
							Code:    "4",
							Display: "Application Server",
						},
					},
				},
			},
		},
	}

	// Add entity entries from record details.
	if record.Details != nil {
		for key, value := range record.Details {
			event.Entity = append(event.Entity, AuditEventEntity{
				What: &Reference{
					Reference: value,
					Display:   key,
				},
			})
		}
	}

	// Store the event.
	g.mu.Lock()
	g.events = append(g.events, *event)
	g.mu.Unlock()

	return event, nil
}

// GenerateAccessAuditEvent generates a FHIR AuditEvent for a data access
// action. This is used when a healthcare resource is read or queried.
func (g *AuditEventGenerator) GenerateAccessAuditEvent(actor, resource, action string) (*AuditEvent, error) {
	if actor == "" {
		return nil, fmt.Errorf("AuditEventGenerator.GenerateAccessAuditEvent: %w: actor is empty", ErrAuditFailed)
	}
	if resource == "" {
		return nil, fmt.Errorf("AuditEventGenerator.GenerateAccessAuditEvent: %w: resource is empty", ErrAuditFailed)
	}

	g.mu.Lock()
	g.sequenceCounter++
	eventID := fmt.Sprintf("access-audit-%d", g.sequenceCounter)
	g.mu.Unlock()

	fhirAction := AuditEventActionRead
	switch action {
	case "create":
		fhirAction = AuditEventActionCreate
	case "update":
		fhirAction = AuditEventActionUpdate
	case "delete":
		fhirAction = AuditEventActionDelete
	case "execute":
		fhirAction = AuditEventActionExecute
	}

	event := &AuditEvent{
		ResourceType: "AuditEvent",
		ID:           eventID,
		Category: []CodeableConcept{
			{
				Coding: []Coding{
					{
						System:  "http://dicom.nema.org/resources/ontology/DCM",
						Code:    "110114",
						Display: "User Authentication",
					},
				},
			},
		},
		Code: CodeableConcept{
			Coding: []Coding{
				{
					System:  "https://aethelred.io/fhir/audit-event-type",
					Code:    "data-access",
					Display: "Data Access",
				},
			},
			Text: fmt.Sprintf("Data access: %s on %s", action, resource),
		},
		Action:   fhirAction,
		Recorded: time.Now().UTC(),
		Outcome: &AuditEventOutcome{
			Code: Coding{
				System:  "http://terminology.hl7.org/CodeSystem/audit-event-outcome",
				Code:    "success",
				Display: "Success",
			},
		},
		Agent: []AuditEventAgent{
			{
				Who: Reference{
					Reference: actor,
					Display:   actor,
				},
				Requestor: true,
			},
		},
		Source: AuditEventSource{
			Observer: g.sourceObserver,
		},
		Entity: []AuditEventEntity{
			{
				What: &Reference{
					Reference: resource,
					Display:   resource,
				},
			},
		},
	}

	g.mu.Lock()
	g.events = append(g.events, *event)
	g.mu.Unlock()

	return event, nil
}

// GenerateConsentAuditEvent generates a FHIR AuditEvent for a consent-related
// action such as creation, revocation, or verification.
func (g *AuditEventGenerator) GenerateConsentAuditEvent(consent *Consent, action string) (*AuditEvent, error) {
	if consent == nil {
		return nil, fmt.Errorf("AuditEventGenerator.GenerateConsentAuditEvent: %w: consent is nil", ErrAuditFailed)
	}
	if action == "" {
		return nil, fmt.Errorf("AuditEventGenerator.GenerateConsentAuditEvent: %w: action is empty", ErrAuditFailed)
	}

	g.mu.Lock()
	g.sequenceCounter++
	eventID := fmt.Sprintf("consent-audit-%d", g.sequenceCounter)
	g.mu.Unlock()

	fhirAction := AuditEventActionCreate
	switch action {
	case "revoke":
		fhirAction = AuditEventActionDelete
	case "verify":
		fhirAction = AuditEventActionRead
	case "update":
		fhirAction = AuditEventActionUpdate
	}

	patientRef := ""
	if consent.Patient != nil {
		patientRef = consent.Patient.Reference
	}

	event := &AuditEvent{
		ResourceType: "AuditEvent",
		ID:           eventID,
		Category: []CodeableConcept{
			{
				Coding: []Coding{
					{
						System:  "http://terminology.hl7.org/CodeSystem/audit-event-type",
						Code:    "110112",
						Display: "Query",
					},
				},
			},
		},
		Code: CodeableConcept{
			Coding: []Coding{
				{
					System:  "https://aethelred.io/fhir/audit-event-type",
					Code:    fmt.Sprintf("consent-%s", action),
					Display: fmt.Sprintf("Consent %s", action),
				},
			},
			Text: fmt.Sprintf("Consent %s for %s", action, consent.ID),
		},
		Action:   fhirAction,
		Recorded: time.Now().UTC(),
		Outcome: &AuditEventOutcome{
			Code: Coding{
				System:  "http://terminology.hl7.org/CodeSystem/audit-event-outcome",
				Code:    "success",
				Display: "Success",
			},
		},
		Agent: []AuditEventAgent{
			{
				Who: Reference{
					Reference: patientRef,
					Display:   "Patient",
				},
				Requestor: true,
			},
		},
		Source: AuditEventSource{
			Observer: g.sourceObserver,
		},
		Entity: []AuditEventEntity{
			{
				What: &Reference{
					Reference: fmt.Sprintf("Consent/%s", consent.ID),
					Type:      "Consent",
					Display:   consent.ID,
				},
			},
		},
	}

	g.mu.Lock()
	g.events = append(g.events, *event)
	g.mu.Unlock()

	return event, nil
}

// AuditEventFilter specifies criteria for filtering exported audit events.
type AuditEventFilter struct {
	// FromTime filters events recorded at or after this time.
	FromTime *time.Time

	// ToTime filters events recorded at or before this time.
	ToTime *time.Time

	// Action filters by FHIR audit action code.
	Action AuditEventAction

	// Category filters by category code.
	Category string

	// Actor filters by agent reference.
	Actor string

	// Limit caps the number of returned events.
	Limit int
}

// ExportAuditEvents returns audit events matching the given filter in FHIR
// format.
func (g *AuditEventGenerator) ExportAuditEvents(_ context.Context, filter *AuditEventFilter) ([]AuditEvent, error) {
	g.mu.Lock()
	events := make([]AuditEvent, len(g.events))
	copy(events, g.events)
	g.mu.Unlock()

	if filter == nil {
		return events, nil
	}

	var filtered []AuditEvent
	for _, e := range events {
		// Apply time filters.
		if filter.FromTime != nil && e.Recorded.Before(*filter.FromTime) {
			continue
		}
		if filter.ToTime != nil && e.Recorded.After(*filter.ToTime) {
			continue
		}

		// Apply action filter.
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}

		// Apply actor filter.
		if filter.Actor != "" {
			actorFound := false
			for _, agent := range e.Agent {
				if agent.Who.Reference == filter.Actor {
					actorFound = true
					break
				}
			}
			if !actorFound {
				continue
			}
		}

		// Apply category filter.
		if filter.Category != "" {
			catFound := false
			for _, cat := range e.Category {
				for _, coding := range cat.Coding {
					if coding.Code == filter.Category {
						catFound = true
						break
					}
				}
			}
			if !catFound {
				continue
			}
		}

		filtered = append(filtered, e)

		if filter.Limit > 0 && len(filtered) >= filter.Limit {
			break
		}
	}

	return filtered, nil
}

// EventCount returns the total number of stored audit events.
func (g *AuditEventGenerator) EventCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.events)
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

// mapAuditCategory maps an Aethelred audit category to a FHIR CodeableConcept.
func mapAuditCategory(cat keeper.AuditCategory) CodeableConcept {
	code := string(cat)
	display := string(cat)

	switch cat {
	case keeper.AuditCategorySecurity:
		code = "110126"
		display = "Security Alert"
	case keeper.AuditCategoryVerification:
		code = "110100"
		display = "Application Activity"
	case keeper.AuditCategoryJob:
		code = "110112"
		display = "Query"
	case keeper.AuditCategoryGovernance:
		code = "110106"
		display = "Export"
	}

	return CodeableConcept{
		Coding: []Coding{
			{
				System:  "http://dicom.nema.org/resources/ontology/DCM",
				Code:    code,
				Display: display,
			},
		},
		Text: string(cat),
	}
}

// mapAuditAction maps an Aethelred action string to a FHIR AuditEventAction.
func mapAuditAction(action string) AuditEventAction {
	switch action {
	case "job_submitted", "validator_registered":
		return AuditEventActionCreate
	case "job_completed", "consensus_reached":
		return AuditEventActionExecute
	case "params_updated":
		return AuditEventActionUpdate
	case "slashing_applied":
		return AuditEventActionDelete
	default:
		return AuditEventActionRead
	}
}

// mapAuditOutcome maps an Aethelred severity to a FHIR AuditEventOutcome.
func mapAuditOutcome(severity keeper.AuditSeverity) *AuditEventOutcome {
	code := "success"
	display := "Success"

	switch severity {
	case keeper.AuditSeverityWarning:
		code = "warning"
		display = "Minor failure"
	case keeper.AuditSeverityCritical:
		code = "serious-failure"
		display = "Serious failure"
	}

	return &AuditEventOutcome{
		Code: Coding{
			System:  "http://terminology.hl7.org/CodeSystem/audit-event-outcome",
			Code:    code,
			Display: display,
		},
	}
}
