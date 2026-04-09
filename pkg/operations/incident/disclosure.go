package incident

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Incident Disclosure Workflow
// ---------------------------------------------------------------------------
//
// Jurisdictional disclosure requirements vary widely. This module provides
// pre-built requirements for major regulations and generates disclosure
// documents that meet each jurisdiction's format and timeline requirements.
//
// Supported jurisdictions:
//   - GDPR (EU):    72 hours to supervisory authority
//   - HIPAA (US):   60 calendar days to HHS
//   - SEC (US):     4 business days on Form 8-K
//   - NYDFS (US):   72 hours to DFS superintendent
// ---------------------------------------------------------------------------

// DisclosureRequirement describes a jurisdiction-specific disclosure obligation.
type DisclosureRequirement struct {
	Jurisdiction string `json:"jurisdiction"`
	Regulation   string `json:"regulation"`
	Deadline     string `json:"deadline"` // Human-readable (e.g., "72 hours")
	DeadlineHours int   `json:"deadline_hours"` // Machine-readable hours.
	Authority    string `json:"authority"`
	Format       string `json:"format"` // "written", "electronic", "form_8k"
	NotificationTemplate string `json:"notification_template,omitempty"`
	ApplicableTypes []IncidentType `json:"applicable_types"`
}

// DisclosureDocument is a generated disclosure document for a specific
// jurisdiction.
type DisclosureDocument struct {
	ID                string              `json:"id"`
	IncidentID        string              `json:"incident_id"`
	Jurisdiction      string              `json:"jurisdiction"`
	Regulation        string              `json:"regulation"`
	Authority         string              `json:"authority"`
	Deadline          string              `json:"deadline"`
	DeadlineTimestamp string              `json:"deadline_timestamp"`
	Status            DisclosureStatus    `json:"status"`
	Content           string              `json:"content"`
	GeneratedAt       string              `json:"generated_at"`
	SubmittedAt       string              `json:"submitted_at,omitempty"`
	Acknowledgement   string              `json:"acknowledgement,omitempty"`
}

// DisclosureStatus tracks the lifecycle of a disclosure.
type DisclosureStatus string

const (
	DisclosurePending   DisclosureStatus = "pending"
	DisclosureDrafted   DisclosureStatus = "drafted"
	DisclosureReviewed  DisclosureStatus = "reviewed"
	DisclosureSubmitted DisclosureStatus = "submitted"
	DisclosureAcknowledged DisclosureStatus = "acknowledged"
)

// DisclosureService manages incident disclosure workflows.
type DisclosureService struct {
	requirements []DisclosureRequirement
}

// NewDisclosureService creates a new disclosure service with pre-built
// jurisdictional requirements.
func NewDisclosureService() *DisclosureService {
	return &DisclosureService{
		requirements: defaultDisclosureRequirements(),
	}
}

// GetDisclosureRequirements determines which disclosure requirements apply
// to the given incident based on its type and severity.
func (ds *DisclosureService) GetDisclosureRequirements(_ context.Context, inc *Incident) ([]DisclosureRequirement, error) {
	if inc == nil {
		return nil, fmt.Errorf("incident/disclosure: nil incident")
	}

	var applicable []DisclosureRequirement
	for _, req := range ds.requirements {
		for _, t := range req.ApplicableTypes {
			if t == inc.Type {
				applicable = append(applicable, req)
				break
			}
		}
	}

	return applicable, nil
}

// GenerateDisclosure generates disclosure documents for all applicable
// jurisdictions.
func (ds *DisclosureService) GenerateDisclosure(_ context.Context, inc *Incident) ([]DisclosureDocument, error) {
	if inc == nil {
		return nil, fmt.Errorf("incident/disclosure: nil incident")
	}

	requirements, _ := ds.GetDisclosureRequirements(context.Background(), inc)
	if len(requirements) == 0 {
		return nil, nil
	}

	var documents []DisclosureDocument
	now := time.Now().UTC()

	for _, req := range requirements {
		detectedAt, err := time.Parse(time.RFC3339, inc.DetectedAt)
		if err != nil {
			detectedAt = now
		}
		deadline := detectedAt.Add(time.Duration(req.DeadlineHours) * time.Hour)

		content := generateDisclosureContent(inc, req)

		doc := DisclosureDocument{
			ID:                fmt.Sprintf("disc-%s-%s", inc.ID[:8], req.Jurisdiction),
			IncidentID:        inc.ID,
			Jurisdiction:      req.Jurisdiction,
			Regulation:        req.Regulation,
			Authority:         req.Authority,
			Deadline:          req.Deadline,
			DeadlineTimestamp: deadline.Format(time.RFC3339),
			Status:            DisclosureDrafted,
			Content:           content,
			GeneratedAt:       now.Format(time.RFC3339),
		}
		documents = append(documents, doc)
	}

	return documents, nil
}

// AddRequirement adds a custom disclosure requirement.
func (ds *DisclosureService) AddRequirement(req DisclosureRequirement) {
	ds.requirements = append(ds.requirements, req)
}

// ---------------------------------------------------------------------------
// Pre-built disclosure requirements
// ---------------------------------------------------------------------------

func defaultDisclosureRequirements() []DisclosureRequirement {
	return []DisclosureRequirement{
		{
			Jurisdiction:  "EU",
			Regulation:    "GDPR",
			Deadline:      "72 hours",
			DeadlineHours: 72,
			Authority:     "Supervisory Authority (Data Protection Authority of lead establishment)",
			Format:        "written",
			ApplicableTypes: []IncidentType{
				IncidentSecurityBreach,
				IncidentDataCorruption,
				IncidentComplianceViolation,
			},
			NotificationTemplate: gdprNotificationTemplate(),
		},
		{
			Jurisdiction:  "US-Federal",
			Regulation:    "HIPAA",
			Deadline:      "60 calendar days",
			DeadlineHours: 60 * 24, // 60 days.
			Authority:     "U.S. Department of Health and Human Services (HHS)",
			Format:        "electronic",
			ApplicableTypes: []IncidentType{
				IncidentSecurityBreach,
				IncidentDataCorruption,
			},
			NotificationTemplate: hipaaNotificationTemplate(),
		},
		{
			Jurisdiction:  "US-Federal",
			Regulation:    "SEC",
			Deadline:      "4 business days",
			DeadlineHours: 4 * 24, // Approximate.
			Authority:     "U.S. Securities and Exchange Commission",
			Format:        "form_8k",
			ApplicableTypes: []IncidentType{
				IncidentSecurityBreach,
				IncidentConsensusHalt,
				IncidentSafetyViolation,
			},
			NotificationTemplate: secNotificationTemplate(),
		},
		{
			Jurisdiction:  "US-NY",
			Regulation:    "NYDFS 23 NYCRR 500",
			Deadline:      "72 hours",
			DeadlineHours: 72,
			Authority:     "New York Department of Financial Services Superintendent",
			Format:        "electronic",
			ApplicableTypes: []IncidentType{
				IncidentSecurityBreach,
				IncidentDataCorruption,
				IncidentComplianceViolation,
			},
			NotificationTemplate: nydfsNotificationTemplate(),
		},
	}
}

// ---------------------------------------------------------------------------
// Disclosure content generation
// ---------------------------------------------------------------------------

func generateDisclosureContent(inc *Incident, req DisclosureRequirement) string {
	return fmt.Sprintf(
		"INCIDENT DISCLOSURE\n"+
			"====================\n\n"+
			"Regulation: %s (%s)\n"+
			"Authority: %s\n"+
			"Deadline: %s\n\n"+
			"INCIDENT DETAILS\n"+
			"Incident ID: %s\n"+
			"Type: %s\n"+
			"Severity: %s\n"+
			"Status: %s\n"+
			"Detected At: %s\n"+
			"Title: %s\n"+
			"Description: %s\n\n"+
			"AFFECTED SYSTEMS\n"+
			"%s\n\n"+
			"TIMELINE (%d entries)\n"+
			"See attached timeline for full chronological event log.\n\n"+
			"ROOT CAUSE\n"+
			"%s\n\n"+
			"RESOLUTION\n"+
			"%s\n",
		req.Regulation, req.Jurisdiction,
		req.Authority,
		req.Deadline,
		inc.ID,
		inc.Type,
		inc.Severity,
		inc.Status,
		inc.DetectedAt,
		inc.Title,
		inc.Description,
		formatSystems(inc.AffectedSystems),
		len(inc.Timeline),
		defaultIfEmpty(inc.RootCause, "Under investigation"),
		defaultIfEmpty(inc.Resolution, "Mitigation in progress"),
	)
}

func formatSystems(systems []string) string {
	if len(systems) == 0 {
		return "None identified"
	}
	result := ""
	for _, s := range systems {
		result += "- " + s + "\n"
	}
	return result
}

func defaultIfEmpty(s, defaultVal string) string {
	if s == "" {
		return defaultVal
	}
	return s
}

// ---------------------------------------------------------------------------
// Notification templates
// ---------------------------------------------------------------------------

func gdprNotificationTemplate() string {
	return "GDPR Article 33 Breach Notification: " +
		"A personal data breach has been detected that is likely to result in " +
		"a risk to the rights and freedoms of natural persons."
}

func hipaaNotificationTemplate() string {
	return "HIPAA Breach Notification (45 CFR 164.408): " +
		"Notification of a breach of unsecured protected health information " +
		"as required by the Health Insurance Portability and Accountability Act."
}

func secNotificationTemplate() string {
	return "SEC Form 8-K Item 1.05 Material Cybersecurity Incident: " +
		"This filing reports a material cybersecurity incident as required " +
		"by the Securities and Exchange Commission."
}

func nydfsNotificationTemplate() string {
	return "NYDFS 23 NYCRR 500 Cybersecurity Event Notification: " +
		"Notification of a cybersecurity event to the Superintendent of " +
		"Financial Services as required by 23 NYCRR 500.17."
}
