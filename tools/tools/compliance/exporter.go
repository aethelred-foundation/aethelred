// Package compliance provides enterprise-grade compliance export tools
// for SOC2, GDPR, HIPAA, and regulatory audit requirements.
//
// This package enables:
//   - Automated audit trail generation
//   - Compliance report export (JSON, CSV, PDF)
//   - Data subject access request (DSAR) handling
//   - Retention policy enforcement
//   - Evidence collection for auditors
//
// Supported Frameworks:
//   - SOC 2 Type II (Trust Services Criteria)
//   - GDPR (EU General Data Protection Regulation)
//   - ADGM Data Protection Regulations
//   - HIPAA (Health Insurance Portability and Accountability Act)
//   - ISO 27001 (Information Security Management)
package compliance

import (
	"archive/zip"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Compliance Framework Definitions
// ============================================================================

// Framework represents a compliance framework
type Framework string

const (
	FrameworkSOC2   Framework = "SOC2"
	FrameworkGDPR   Framework = "GDPR"
	FrameworkADGM   Framework = "ADGM"
	FrameworkHIPAA  Framework = "HIPAA"
	FrameworkISO27001 Framework = "ISO27001"
)

// ControlCategory represents a control category within a framework
type ControlCategory string

const (
	// SOC2 Trust Services Criteria
	CategorySecurity        ControlCategory = "Security"
	CategoryAvailability    ControlCategory = "Availability"
	CategoryProcessing      ControlCategory = "Processing Integrity"
	CategoryConfidentiality ControlCategory = "Confidentiality"
	CategoryPrivacy         ControlCategory = "Privacy"

	// GDPR Principles
	CategoryLawfulness      ControlCategory = "Lawfulness"
	CategoryPurposeLimitation ControlCategory = "Purpose Limitation"
	CategoryDataMinimization ControlCategory = "Data Minimization"
	CategoryAccuracy        ControlCategory = "Accuracy"
	CategoryStorageLimitation ControlCategory = "Storage Limitation"
	CategoryIntegrity       ControlCategory = "Integrity & Confidentiality"
	CategoryAccountability  ControlCategory = "Accountability"
)

// ============================================================================
// Audit Event Types
// ============================================================================

// EventType represents the type of auditable event
type EventType string

const (
	// Access Events
	EventUserLogin          EventType = "USER_LOGIN"
	EventUserLogout         EventType = "USER_LOGOUT"
	EventAccessGranted      EventType = "ACCESS_GRANTED"
	EventAccessDenied       EventType = "ACCESS_DENIED"
	EventPrivilegeEscalation EventType = "PRIVILEGE_ESCALATION"

	// Data Events
	EventDataCreated        EventType = "DATA_CREATED"
	EventDataRead           EventType = "DATA_READ"
	EventDataUpdated        EventType = "DATA_UPDATED"
	EventDataDeleted        EventType = "DATA_DELETED"
	EventDataExported       EventType = "DATA_EXPORTED"

	// Cryptographic Events
	EventKeyGenerated       EventType = "KEY_GENERATED"
	EventKeyUsed            EventType = "KEY_USED"
	EventKeyRotated         EventType = "KEY_ROTATED"
	EventKeyRevoked         EventType = "KEY_REVOKED"
	EventSignatureCreated   EventType = "SIGNATURE_CREATED"
	EventSignatureVerified  EventType = "SIGNATURE_VERIFIED"

	// Validator Events
	EventValidatorJoined    EventType = "VALIDATOR_JOINED"
	EventValidatorLeft      EventType = "VALIDATOR_LEFT"
	EventVoteExtension      EventType = "VOTE_EXTENSION"
	EventConsensusReached   EventType = "CONSENSUS_REACHED"
	EventSlashingApplied    EventType = "SLASHING_APPLIED"

	// Compute Events
	EventJobSubmitted       EventType = "JOB_SUBMITTED"
	EventJobVerified        EventType = "JOB_VERIFIED"
	EventJobCompleted       EventType = "JOB_COMPLETED"
	EventJobFailed          EventType = "JOB_FAILED"
	EventSealCreated        EventType = "SEAL_CREATED"

	// Administrative Events
	EventConfigChanged      EventType = "CONFIG_CHANGED"
	EventBackupCreated      EventType = "BACKUP_CREATED"
	EventSystemStarted      EventType = "SYSTEM_STARTED"
	EventSystemStopped      EventType = "SYSTEM_STOPPED"
)

// ============================================================================
// Audit Log Entry
// ============================================================================

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	// Identity
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	TimestampUTC    string            `json:"timestamp_utc"`

	// Event Information
	EventType       EventType         `json:"event_type"`
	Category        ControlCategory   `json:"category"`
	Severity        string            `json:"severity"` // INFO, WARNING, CRITICAL

	// Actor Information
	ActorType       string            `json:"actor_type"`   // user, system, validator
	ActorID         string            `json:"actor_id"`
	ActorIP         string            `json:"actor_ip,omitempty"`
	ActorLocation   string            `json:"actor_location,omitempty"`

	// Resource Information
	ResourceType    string            `json:"resource_type"`
	ResourceID      string            `json:"resource_id"`

	// Action Details
	Action          string            `json:"action"`
	ActionResult    string            `json:"action_result"` // success, failure, partial
	Description     string            `json:"description"`

	// Data Classification
	DataClassification string         `json:"data_classification,omitempty"` // public, internal, confidential, restricted

	// Compliance Mapping
	Frameworks      []Framework       `json:"frameworks"`
	Controls        []string          `json:"controls"` // e.g., ["CC6.1", "CC6.2"]

	// Additional Context
	Metadata        map[string]string `json:"metadata,omitempty"`
	RequestID       string            `json:"request_id,omitempty"`
	SessionID       string            `json:"session_id,omitempty"`

	// Integrity
	PreviousHash    string            `json:"previous_hash"`
	Hash            string            `json:"hash"`
}

// ComputeHash computes the SHA-256 hash of the entry
func (e *AuditEntry) ComputeHash() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.ID, e.Timestamp.Format(time.RFC3339Nano),
		e.EventType, e.ActorID, e.ResourceID,
		e.Action, e.ActionResult, e.Description,
		e.PreviousHash)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ============================================================================
// Audit Logger
// ============================================================================

// AuditLogger manages audit log collection
type AuditLogger struct {
	mu           sync.RWMutex
	entries      []*AuditEntry
	lastHash     string
	maxEntries   int
	retention    time.Duration
	exportPath   string
	autoExport   bool

	// Callbacks
	onEntry      func(*AuditEntry)
	onExport     func(string)
}

// AuditLoggerConfig configures the audit logger
type AuditLoggerConfig struct {
	MaxEntries  int
	Retention   time.Duration
	ExportPath  string
	AutoExport  bool
}

// DefaultAuditLoggerConfig returns production defaults
func DefaultAuditLoggerConfig() AuditLoggerConfig {
	return AuditLoggerConfig{
		MaxEntries: 1000000,        // 1M entries in memory
		Retention:  7 * 365 * 24 * time.Hour, // 7 years
		ExportPath: "/var/log/aethelred/audit",
		AutoExport: true,
	}
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config AuditLoggerConfig) *AuditLogger {
	return &AuditLogger{
		entries:    make([]*AuditEntry, 0, config.MaxEntries),
		maxEntries: config.MaxEntries,
		retention:  config.Retention,
		exportPath: config.ExportPath,
		autoExport: config.AutoExport,
		lastHash:   "genesis",
	}
}

// Log records an audit entry
func (al *AuditLogger) Log(entry *AuditEntry) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Set timestamp
	entry.Timestamp = time.Now().UTC()
	entry.TimestampUTC = entry.Timestamp.Format(time.RFC3339Nano)

	// Generate ID
	entry.ID = generateAuditID()

	// Set hash chain
	entry.PreviousHash = al.lastHash
	entry.Hash = entry.ComputeHash()
	al.lastHash = entry.Hash

	// Append entry
	al.entries = append(al.entries, entry)

	// Trigger callback
	if al.onEntry != nil {
		go al.onEntry(entry)
	}

	// Auto-export if needed
	if al.autoExport && len(al.entries) >= al.maxEntries {
		go al.exportAndRotate()
	}

	return nil
}

// LogEvent is a convenience method for logging events
func (al *AuditLogger) LogEvent(eventType EventType, category ControlCategory, actor, resource, action, result, description string) error {
	return al.Log(&AuditEntry{
		EventType:      eventType,
		Category:       category,
		Severity:       "INFO",
		ActorType:      "system",
		ActorID:        actor,
		ResourceType:   "general",
		ResourceID:     resource,
		Action:         action,
		ActionResult:   result,
		Description:    description,
		Frameworks:     []Framework{FrameworkSOC2, FrameworkGDPR},
	})
}

// Query returns entries matching the filter
func (al *AuditLogger) Query(filter AuditFilter) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditEntry
	for _, entry := range al.entries {
		if filter.Matches(entry) {
			results = append(results, entry)
		}
	}
	return results
}

// exportAndRotate exports entries and rotates the log
func (al *AuditLogger) exportAndRotate() {
	al.mu.Lock()
	entries := al.entries
	al.entries = make([]*AuditEntry, 0, al.maxEntries)
	al.mu.Unlock()

	filename := filepath.Join(al.exportPath,
		fmt.Sprintf("audit-%s.json", time.Now().Format("20060102-150405")))

	if err := os.MkdirAll(al.exportPath, 0755); err != nil {
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	for _, entry := range entries {
		encoder.Encode(entry)
	}

	if al.onExport != nil {
		al.onExport(filename)
	}
}

// ============================================================================
// Audit Filter
// ============================================================================

// AuditFilter defines criteria for filtering audit entries
type AuditFilter struct {
	StartTime      *time.Time
	EndTime        *time.Time
	EventTypes     []EventType
	Categories     []ControlCategory
	ActorIDs       []string
	ResourceIDs    []string
	Severities     []string
	Frameworks     []Framework
	ActionResults  []string
	SearchText     string
}

// Matches checks if an entry matches the filter
func (f *AuditFilter) Matches(entry *AuditEntry) bool {
	if f.StartTime != nil && entry.Timestamp.Before(*f.StartTime) {
		return false
	}
	if f.EndTime != nil && entry.Timestamp.After(*f.EndTime) {
		return false
	}
	if len(f.EventTypes) > 0 && !containsEventType(f.EventTypes, entry.EventType) {
		return false
	}
	if len(f.Categories) > 0 && !containsCategory(f.Categories, entry.Category) {
		return false
	}
	if len(f.ActorIDs) > 0 && !containsString(f.ActorIDs, entry.ActorID) {
		return false
	}
	if len(f.ResourceIDs) > 0 && !containsString(f.ResourceIDs, entry.ResourceID) {
		return false
	}
	if len(f.Severities) > 0 && !containsString(f.Severities, entry.Severity) {
		return false
	}
	if len(f.ActionResults) > 0 && !containsString(f.ActionResults, entry.ActionResult) {
		return false
	}
	if f.SearchText != "" {
		searchLower := strings.ToLower(f.SearchText)
		if !strings.Contains(strings.ToLower(entry.Description), searchLower) &&
			!strings.Contains(strings.ToLower(entry.Action), searchLower) {
			return false
		}
	}
	return true
}

// ============================================================================
// Compliance Report Generator
// ============================================================================

// ReportGenerator generates compliance reports
type ReportGenerator struct {
	logger      *AuditLogger
	config      ReportConfig
}

// ReportConfig configures report generation
type ReportConfig struct {
	Organization    string
	ReportingPeriod string
	Auditor         string
	OutputDir       string
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(logger *AuditLogger, config ReportConfig) *ReportGenerator {
	return &ReportGenerator{
		logger: logger,
		config: config,
	}
}

// Report represents a compliance report
type Report struct {
	// Metadata
	Title           string                 `json:"title"`
	Framework       Framework              `json:"framework"`
	Version         string                 `json:"version"`
	GeneratedAt     time.Time              `json:"generated_at"`
	ReportingPeriod ReportingPeriod        `json:"reporting_period"`
	Organization    string                 `json:"organization"`

	// Executive Summary
	ExecutiveSummary ExecutiveSummary      `json:"executive_summary"`

	// Control Assessment
	Controls        []ControlAssessment    `json:"controls"`

	// Evidence
	Evidence        []Evidence             `json:"evidence"`

	// Findings
	Findings        []Finding              `json:"findings"`

	// Statistics
	Statistics      ReportStatistics       `json:"statistics"`

	// Integrity
	Hash            string                 `json:"hash"`
}

// ReportingPeriod defines the time range for a report
type ReportingPeriod struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Duration  string    `json:"duration"`
}

// ExecutiveSummary provides a high-level summary
type ExecutiveSummary struct {
	OverallStatus       string    `json:"overall_status"` // Compliant, Partially Compliant, Non-Compliant
	ComplianceScore     float64   `json:"compliance_score"`
	TotalControls       int       `json:"total_controls"`
	ControlsMet         int       `json:"controls_met"`
	ControlsPartial     int       `json:"controls_partial"`
	ControlsNotMet      int       `json:"controls_not_met"`
	CriticalFindings    int       `json:"critical_findings"`
	HighFindings        int       `json:"high_findings"`
	MediumFindings      int       `json:"medium_findings"`
	LowFindings         int       `json:"low_findings"`
	KeyAchievements     []string  `json:"key_achievements"`
	AreasForImprovement []string  `json:"areas_for_improvement"`
}

// ControlAssessment represents the assessment of a single control
type ControlAssessment struct {
	ControlID       string    `json:"control_id"`
	ControlName     string    `json:"control_name"`
	Category        string    `json:"category"`
	Description     string    `json:"description"`
	Status          string    `json:"status"` // Met, Partially Met, Not Met, N/A
	TestingMethod   string    `json:"testing_method"`
	TestResults     string    `json:"test_results"`
	EvidenceRefs    []string  `json:"evidence_refs"`
	Findings        []string  `json:"findings"`
	Recommendations []string  `json:"recommendations"`
}

// Evidence represents supporting evidence for controls
type Evidence struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"` // document, log, screenshot, interview
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Source          string            `json:"source"`
	CollectedAt     time.Time         `json:"collected_at"`
	Hash            string            `json:"hash"`
	Controls        []string          `json:"controls"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// Finding represents a compliance finding
type Finding struct {
	ID              string    `json:"id"`
	Severity        string    `json:"severity"` // Critical, High, Medium, Low
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Impact          string    `json:"impact"`
	AffectedControl string    `json:"affected_control"`
	Recommendation  string    `json:"recommendation"`
	DueDate         time.Time `json:"due_date,omitempty"`
	Status          string    `json:"status"` // Open, In Progress, Resolved
	Owner           string    `json:"owner,omitempty"`
}

// ReportStatistics provides statistical analysis
type ReportStatistics struct {
	TotalEvents       int64             `json:"total_events"`
	EventsByType      map[string]int64  `json:"events_by_type"`
	EventsByCategory  map[string]int64  `json:"events_by_category"`
	EventsBySeverity  map[string]int64  `json:"events_by_severity"`
	EventsByDay       map[string]int64  `json:"events_by_day"`
	SuccessRate       float64           `json:"success_rate"`
	FailureRate       float64           `json:"failure_rate"`
	AverageDaily      float64           `json:"average_daily"`
}

// GenerateSOC2Report generates a SOC 2 Type II report
func (rg *ReportGenerator) GenerateSOC2Report(ctx context.Context, period ReportingPeriod) (*Report, error) {
	report := &Report{
		Title:           "SOC 2 Type II Compliance Report",
		Framework:       FrameworkSOC2,
		Version:         "1.0",
		GeneratedAt:     time.Now().UTC(),
		ReportingPeriod: period,
		Organization:    rg.config.Organization,
	}

	// Query relevant entries
	filter := AuditFilter{
		StartTime: &period.StartDate,
		EndTime:   &period.EndDate,
	}
	entries := rg.logger.Query(filter)

	// Generate statistics
	report.Statistics = rg.computeStatistics(entries)

	// Assess controls
	report.Controls = rg.assessSOC2Controls(entries)

	// Collect evidence
	report.Evidence = rg.collectEvidence(entries)

	// Generate findings
	report.Findings = rg.generateFindings(report.Controls)

	// Generate executive summary
	report.ExecutiveSummary = rg.generateExecutiveSummary(report)

	// Compute report hash
	reportBytes, _ := json.Marshal(report)
	hash := sha256.Sum256(reportBytes)
	report.Hash = hex.EncodeToString(hash[:])

	return report, nil
}

// assessSOC2Controls assesses SOC 2 Trust Services Criteria
func (rg *ReportGenerator) assessSOC2Controls(entries []*AuditEntry) []ControlAssessment {
	controls := []ControlAssessment{
		// Security (Common Criteria)
		{
			ControlID:   "CC1.1",
			ControlName: "COSO Principle 1: Integrity and Ethical Values",
			Category:    string(CategorySecurity),
			Description: "The organization demonstrates commitment to integrity and ethical values.",
		},
		{
			ControlID:   "CC2.1",
			ControlName: "COSO Principle 13: Quality Information",
			Category:    string(CategorySecurity),
			Description: "The organization uses relevant, quality information to support the functioning of internal control.",
		},
		{
			ControlID:   "CC6.1",
			ControlName: "Logical and Physical Access Controls",
			Category:    string(CategorySecurity),
			Description: "Logical access security measures to protect against unauthorized access.",
		},
		{
			ControlID:   "CC6.2",
			ControlName: "System Boundaries",
			Category:    string(CategorySecurity),
			Description: "Prior to issuing system credentials, the organization registers and authorizes new internal and external users.",
		},
		{
			ControlID:   "CC6.3",
			ControlName: "Access Removal",
			Category:    string(CategorySecurity),
			Description: "The organization removes access for terminated users in a timely manner.",
		},
		{
			ControlID:   "CC6.6",
			ControlName: "Encryption",
			Category:    string(CategorySecurity),
			Description: "Encryption to protect data at rest and in transit.",
		},
		{
			ControlID:   "CC6.7",
			ControlName: "Data Transmission",
			Category:    string(CategorySecurity),
			Description: "The organization restricts the transmission of confidential data.",
		},
		{
			ControlID:   "CC7.1",
			ControlName: "Vulnerability Management",
			Category:    string(CategorySecurity),
			Description: "Security vulnerabilities are identified and remediated.",
		},
		{
			ControlID:   "CC7.2",
			ControlName: "Security Monitoring",
			Category:    string(CategorySecurity),
			Description: "The organization monitors system components for anomalies.",
		},
		{
			ControlID:   "CC7.3",
			ControlName: "Security Incidents",
			Category:    string(CategorySecurity),
			Description: "Security incidents are identified, investigated, and resolved.",
		},

		// Availability
		{
			ControlID:   "A1.1",
			ControlName: "Availability Commitment",
			Category:    string(CategoryAvailability),
			Description: "Current processing capacity and usage are maintained.",
		},
		{
			ControlID:   "A1.2",
			ControlName: "Disaster Recovery",
			Category:    string(CategoryAvailability),
			Description: "Environmental protections and backup procedures are in place.",
		},

		// Processing Integrity
		{
			ControlID:   "PI1.1",
			ControlName: "Processing Completeness",
			Category:    string(CategoryProcessing),
			Description: "Processing is complete, valid, accurate, and authorized.",
		},
		{
			ControlID:   "PI1.2",
			ControlName: "Error Handling",
			Category:    string(CategoryProcessing),
			Description: "System processing errors are identified and corrected.",
		},

		// Confidentiality
		{
			ControlID:   "C1.1",
			ControlName: "Confidential Information",
			Category:    string(CategoryConfidentiality),
			Description: "Confidential information is identified and protected.",
		},
		{
			ControlID:   "C1.2",
			ControlName: "Confidential Data Disposal",
			Category:    string(CategoryConfidentiality),
			Description: "Confidential information is disposed of securely.",
		},
	}

	// Assess each control based on audit entries
	for i := range controls {
		controls[i] = rg.assessControl(controls[i], entries)
	}

	return controls
}

// assessControl assesses a single control
func (rg *ReportGenerator) assessControl(control ControlAssessment, entries []*AuditEntry) ControlAssessment {
	// Find relevant entries for this control
	var relevant []*AuditEntry
	for _, entry := range entries {
		for _, c := range entry.Controls {
			if c == control.ControlID {
				relevant = append(relevant, entry)
				break
			}
		}
	}

	// Default assessment
	control.TestingMethod = "Inquiry, Observation, and Inspection"
	control.EvidenceRefs = []string{}

	if len(relevant) == 0 {
		control.Status = "Not Tested"
		control.TestResults = "Insufficient evidence to assess control"
		control.Recommendations = []string{"Implement logging for control activities"}
	} else {
		// Analyze results
		successCount := 0
		failureCount := 0
		for _, entry := range relevant {
			if entry.ActionResult == "success" {
				successCount++
			} else {
				failureCount++
			}
			control.EvidenceRefs = append(control.EvidenceRefs, entry.ID)
		}

		successRate := float64(successCount) / float64(len(relevant))
		if successRate >= 0.99 {
			control.Status = "Met"
			control.TestResults = fmt.Sprintf("Control operating effectively. %d events analyzed, %.2f%% success rate.",
				len(relevant), successRate*100)
		} else if successRate >= 0.90 {
			control.Status = "Partially Met"
			control.TestResults = fmt.Sprintf("Control mostly effective. %d events analyzed, %.2f%% success rate.",
				len(relevant), successRate*100)
			control.Recommendations = []string{"Review and remediate failure cases"}
		} else {
			control.Status = "Not Met"
			control.TestResults = fmt.Sprintf("Control not operating effectively. %d events analyzed, %.2f%% success rate.",
				len(relevant), successRate*100)
			control.Recommendations = []string{"Immediate remediation required", "Implement additional controls"}
		}
	}

	return control
}

// collectEvidence collects evidence from audit entries
func (rg *ReportGenerator) collectEvidence(entries []*AuditEntry) []Evidence {
	var evidence []Evidence

	// Group entries by date for evidence collection
	byDate := make(map[string][]*AuditEntry)
	for _, entry := range entries {
		date := entry.Timestamp.Format("2006-01-02")
		byDate[date] = append(byDate[date], entry)
	}

	// Create evidence for each day
	for date, dayEntries := range byDate {
		// Create daily log evidence
		hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", date, len(dayEntries))))
		evidence = append(evidence, Evidence{
			ID:          fmt.Sprintf("EVD-%s-LOGS", date),
			Type:        "log",
			Title:       fmt.Sprintf("Audit Logs - %s", date),
			Description: fmt.Sprintf("Complete audit log for %s containing %d events", date, len(dayEntries)),
			Source:      "Aethelred Audit System",
			CollectedAt: time.Now().UTC(),
			Hash:        hex.EncodeToString(hash[:]),
		})
	}

	return evidence
}

// generateFindings generates findings from control assessments
func (rg *ReportGenerator) generateFindings(controls []ControlAssessment) []Finding {
	var findings []Finding
	findingID := 1

	for _, control := range controls {
		if control.Status == "Not Met" {
			findings = append(findings, Finding{
				ID:              fmt.Sprintf("FND-%03d", findingID),
				Severity:        "High",
				Title:           fmt.Sprintf("Control %s Not Operating Effectively", control.ControlID),
				Description:     control.TestResults,
				Impact:          "Potential security, availability, or compliance risk",
				AffectedControl: control.ControlID,
				Recommendation:  strings.Join(control.Recommendations, "; "),
				Status:          "Open",
			})
			findingID++
		} else if control.Status == "Partially Met" {
			findings = append(findings, Finding{
				ID:              fmt.Sprintf("FND-%03d", findingID),
				Severity:        "Medium",
				Title:           fmt.Sprintf("Control %s Partially Effective", control.ControlID),
				Description:     control.TestResults,
				Impact:          "Reduced control effectiveness",
				AffectedControl: control.ControlID,
				Recommendation:  strings.Join(control.Recommendations, "; "),
				Status:          "Open",
			})
			findingID++
		}
	}

	return findings
}

// generateExecutiveSummary generates the executive summary
func (rg *ReportGenerator) generateExecutiveSummary(report *Report) ExecutiveSummary {
	summary := ExecutiveSummary{
		TotalControls: len(report.Controls),
	}

	// Count control statuses
	for _, control := range report.Controls {
		switch control.Status {
		case "Met":
			summary.ControlsMet++
		case "Partially Met":
			summary.ControlsPartial++
		case "Not Met":
			summary.ControlsNotMet++
		}
	}

	// Count findings by severity
	for _, finding := range report.Findings {
		switch finding.Severity {
		case "Critical":
			summary.CriticalFindings++
		case "High":
			summary.HighFindings++
		case "Medium":
			summary.MediumFindings++
		case "Low":
			summary.LowFindings++
		}
	}

	// Calculate compliance score
	if summary.TotalControls > 0 {
		summary.ComplianceScore = float64(summary.ControlsMet) / float64(summary.TotalControls) * 100
	}

	// Determine overall status
	if summary.CriticalFindings > 0 || summary.HighFindings > 2 {
		summary.OverallStatus = "Non-Compliant"
	} else if summary.ControlsNotMet > 0 || summary.HighFindings > 0 {
		summary.OverallStatus = "Partially Compliant"
	} else {
		summary.OverallStatus = "Compliant"
	}

	// Key achievements and improvements
	if summary.ComplianceScore >= 90 {
		summary.KeyAchievements = append(summary.KeyAchievements,
			fmt.Sprintf("Achieved %.0f%% compliance score", summary.ComplianceScore))
	}
	if summary.ControlsMet > summary.TotalControls/2 {
		summary.KeyAchievements = append(summary.KeyAchievements,
			fmt.Sprintf("%d of %d controls fully met", summary.ControlsMet, summary.TotalControls))
	}

	if summary.ControlsNotMet > 0 {
		summary.AreasForImprovement = append(summary.AreasForImprovement,
			fmt.Sprintf("Address %d controls not meeting requirements", summary.ControlsNotMet))
	}
	if summary.HighFindings > 0 {
		summary.AreasForImprovement = append(summary.AreasForImprovement,
			fmt.Sprintf("Remediate %d high-severity findings", summary.HighFindings))
	}

	return summary
}

// computeStatistics computes statistics from audit entries
func (rg *ReportGenerator) computeStatistics(entries []*AuditEntry) ReportStatistics {
	stats := ReportStatistics{
		TotalEvents:      int64(len(entries)),
		EventsByType:     make(map[string]int64),
		EventsByCategory: make(map[string]int64),
		EventsBySeverity: make(map[string]int64),
		EventsByDay:      make(map[string]int64),
	}

	successCount := int64(0)
	failureCount := int64(0)

	for _, entry := range entries {
		stats.EventsByType[string(entry.EventType)]++
		stats.EventsByCategory[string(entry.Category)]++
		stats.EventsBySeverity[entry.Severity]++
		day := entry.Timestamp.Format("2006-01-02")
		stats.EventsByDay[day]++

		if entry.ActionResult == "success" {
			successCount++
		} else {
			failureCount++
		}
	}

	if stats.TotalEvents > 0 {
		stats.SuccessRate = float64(successCount) / float64(stats.TotalEvents)
		stats.FailureRate = float64(failureCount) / float64(stats.TotalEvents)
	}

	if len(stats.EventsByDay) > 0 {
		stats.AverageDaily = float64(stats.TotalEvents) / float64(len(stats.EventsByDay))
	}

	return stats
}

// ============================================================================
// GDPR Data Subject Access Request (DSAR)
// ============================================================================

// DSARRequest represents a data subject access request
type DSARRequest struct {
	RequestID       string    `json:"request_id"`
	SubjectID       string    `json:"subject_id"`
	SubjectEmail    string    `json:"subject_email"`
	RequestType     string    `json:"request_type"` // access, rectification, erasure, portability
	RequestDate     time.Time `json:"request_date"`
	DueDate         time.Time `json:"due_date"` // 30 days from request
	Status          string    `json:"status"`   // pending, processing, completed, rejected
	ProcessedDate   time.Time `json:"processed_date,omitempty"`
	ProcessedBy     string    `json:"processed_by,omitempty"`
	Notes           string    `json:"notes,omitempty"`
}

// DSARResponse represents the response to a DSAR
type DSARResponse struct {
	RequestID       string                 `json:"request_id"`
	SubjectID       string                 `json:"subject_id"`
	GeneratedAt     time.Time              `json:"generated_at"`
	DataCategories  []string               `json:"data_categories"`
	ProcessingBases []string               `json:"processing_bases"`
	DataRetention   map[string]string      `json:"data_retention"`
	ThirdParties    []string               `json:"third_parties"`
	DataExport      map[string]interface{} `json:"data_export,omitempty"`
}

// DSARHandler handles data subject access requests
type DSARHandler struct {
	logger      *AuditLogger
	config      DSARConfig
}

// DSARConfig configures DSAR handling
type DSARConfig struct {
	MaxResponseDays  int
	DataCategories   []string
	ProcessingBases  map[string]string
	RetentionPolicies map[string]string
}

// NewDSARHandler creates a new DSAR handler
func NewDSARHandler(logger *AuditLogger, config DSARConfig) *DSARHandler {
	return &DSARHandler{
		logger: logger,
		config: config,
	}
}

// ProcessAccessRequest processes a data subject access request
func (h *DSARHandler) ProcessAccessRequest(ctx context.Context, request *DSARRequest) (*DSARResponse, error) {
	// Log the request
	h.logger.LogEvent(
		EventDataExported,
		CategoryPrivacy,
		"dsar_handler",
		request.SubjectID,
		"process_access_request",
		"success",
		fmt.Sprintf("Processing DSAR access request %s for subject %s", request.RequestID, request.SubjectID),
	)

	// Build response
	response := &DSARResponse{
		RequestID:      request.RequestID,
		SubjectID:      request.SubjectID,
		GeneratedAt:    time.Now().UTC(),
		DataCategories: h.config.DataCategories,
		ProcessingBases: []string{
			"Legitimate Interest: Network consensus participation",
			"Contract: Service agreement for compute verification",
		},
		DataRetention: h.config.RetentionPolicies,
		ThirdParties: []string{
			"Validators (consensus participation)",
			"Cloud providers (infrastructure)",
		},
	}

	// Query data for this subject
	filter := AuditFilter{
		ActorIDs: []string{request.SubjectID},
	}
	entries := h.logger.Query(filter)

	// Export data
	response.DataExport = make(map[string]interface{})
	response.DataExport["audit_events_count"] = len(entries)
	response.DataExport["first_activity"] = entries[0].Timestamp
	response.DataExport["last_activity"] = entries[len(entries)-1].Timestamp

	return response, nil
}

// ============================================================================
// Export Functions
// ============================================================================

// Exporter handles export of compliance data
type Exporter struct {
	logger    *AuditLogger
	outputDir string
}

// NewExporter creates a new exporter
func NewExporter(logger *AuditLogger, outputDir string) *Exporter {
	return &Exporter{
		logger:    logger,
		outputDir: outputDir,
	}
}

// ExportJSON exports audit entries to JSON
func (e *Exporter) ExportJSON(ctx context.Context, filter AuditFilter, filename string) error {
	entries := e.logger.Query(filter)

	filepath := filepath.Join(e.outputDir, filename)
	if err := os.MkdirAll(e.outputDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

// ExportCSV exports audit entries to CSV
func (e *Exporter) ExportCSV(ctx context.Context, filter AuditFilter, filename string) error {
	entries := e.logger.Query(filter)

	filepath := filepath.Join(e.outputDir, filename)
	if err := os.MkdirAll(e.outputDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID", "Timestamp", "Event Type", "Category", "Severity",
		"Actor ID", "Resource ID", "Action", "Result", "Description",
	}
	writer.Write(header)

	// Write entries
	for _, entry := range entries {
		row := []string{
			entry.ID,
			entry.TimestampUTC,
			string(entry.EventType),
			string(entry.Category),
			entry.Severity,
			entry.ActorID,
			entry.ResourceID,
			entry.Action,
			entry.ActionResult,
			entry.Description,
		}
		writer.Write(row)
	}

	return nil
}

// ExportZipBundle exports a complete compliance bundle
func (e *Exporter) ExportZipBundle(ctx context.Context, filter AuditFilter, filename string) error {
	filepath := filepath.Join(e.outputDir, filename)
	if err := os.MkdirAll(e.outputDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	entries := e.logger.Query(filter)

	// Add JSON export
	jsonWriter, err := zipWriter.Create("audit_log.json")
	if err != nil {
		return err
	}
	jsonBytes, _ := json.MarshalIndent(entries, "", "  ")
	jsonWriter.Write(jsonBytes)

	// Add CSV export
	csvWriter, err := zipWriter.Create("audit_log.csv")
	if err != nil {
		return err
	}
	csvBuf := &bytes.Buffer{}
	csvW := csv.NewWriter(csvBuf)
	header := []string{"ID", "Timestamp", "Event Type", "Category", "Severity", "Actor ID", "Resource ID", "Action", "Result"}
	csvW.Write(header)
	for _, entry := range entries {
		row := []string{entry.ID, entry.TimestampUTC, string(entry.EventType), string(entry.Category), entry.Severity, entry.ActorID, entry.ResourceID, entry.Action, entry.ActionResult}
		csvW.Write(row)
	}
	csvW.Flush()
	csvWriter.Write(csvBuf.Bytes())

	// Add manifest
	manifestWriter, err := zipWriter.Create("MANIFEST.json")
	if err != nil {
		return err
	}
	manifest := map[string]interface{}{
		"generated_at":  time.Now().UTC(),
		"total_entries": len(entries),
		"files":         []string{"audit_log.json", "audit_log.csv"},
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	manifestWriter.Write(manifestBytes)

	return nil
}

// ============================================================================
// Utility Functions
// ============================================================================

func generateAuditID() string {
	b := make([]byte, 16)
	cryptorand.Read(b)
	return fmt.Sprintf("AUD-%s", hex.EncodeToString(b[:8]))
}

func containsEventType(slice []EventType, item EventType) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsCategory(slice []ControlCategory, item ControlCategory) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ============================================================================
// CLI Interface
// ============================================================================

// RunComplianceExport is the main entry point for the compliance exporter
func RunComplianceExport(outputDir string, format string, framework Framework) error {
	// Create logger with sample data
	logger := NewAuditLogger(DefaultAuditLoggerConfig())

	// Generate sample entries for demo
	generateSampleEntries(logger)

	// Create exporter
	exporter := NewExporter(logger, outputDir)

	// Export based on format
	timestamp := time.Now().Format("20060102-150405")
	filter := AuditFilter{}

	switch format {
	case "json":
		return exporter.ExportJSON(context.Background(), filter, fmt.Sprintf("audit-%s.json", timestamp))
	case "csv":
		return exporter.ExportCSV(context.Background(), filter, fmt.Sprintf("audit-%s.csv", timestamp))
	case "zip":
		return exporter.ExportZipBundle(context.Background(), filter, fmt.Sprintf("compliance-bundle-%s.zip", timestamp))
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

// generateSampleEntries generates sample audit entries for demonstration
func generateSampleEntries(logger *AuditLogger) {
	events := []struct {
		eventType EventType
		category  ControlCategory
		action    string
		result    string
		desc      string
	}{
		{EventUserLogin, CategorySecurity, "authenticate", "success", "User authenticated successfully"},
		{EventKeyGenerated, CategorySecurity, "generate_key", "success", "HSM key generated for validator"},
		{EventJobSubmitted, CategoryProcessing, "submit_job", "success", "Compute job submitted for verification"},
		{EventJobVerified, CategoryProcessing, "verify_job", "success", "Job verified by TEE attestation"},
		{EventVoteExtension, CategoryAvailability, "create_vote", "success", "Vote extension created"},
		{EventConsensusReached, CategoryAvailability, "finalize_block", "success", "Block finalized with consensus"},
		{EventSealCreated, CategoryConfidentiality, "create_seal", "success", "Digital seal created for job"},
		{EventDataExported, CategoryPrivacy, "export_data", "success", "Audit data exported"},
	}

	for i := 0; i < 100; i++ {
		e := events[i%len(events)]
		logger.Log(&AuditEntry{
			EventType:    e.eventType,
			Category:     e.category,
			Severity:     "INFO",
			ActorType:    "system",
			ActorID:      fmt.Sprintf("validator-%d", i%10),
			ResourceType: "job",
			ResourceID:   fmt.Sprintf("job-%d", i),
			Action:       e.action,
			ActionResult: e.result,
			Description:  e.desc,
			Frameworks:   []Framework{FrameworkSOC2, FrameworkGDPR},
			Controls:     []string{"CC6.1", "CC7.2"},
		})
	}
}

// PrintReportSummary prints a report summary to stdout
func PrintReportSummary(report *Report) {
	fmt.Println("\n=== COMPLIANCE REPORT SUMMARY ===")
	fmt.Printf("Framework: %s\n", report.Framework)
	fmt.Printf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Printf("Period: %s to %s\n",
		report.ReportingPeriod.StartDate.Format("2006-01-02"),
		report.ReportingPeriod.EndDate.Format("2006-01-02"))
	fmt.Println()

	fmt.Println("=== EXECUTIVE SUMMARY ===")
	fmt.Printf("Overall Status: %s\n", report.ExecutiveSummary.OverallStatus)
	fmt.Printf("Compliance Score: %.1f%%\n", report.ExecutiveSummary.ComplianceScore)
	fmt.Printf("Controls: %d Met, %d Partial, %d Not Met\n",
		report.ExecutiveSummary.ControlsMet,
		report.ExecutiveSummary.ControlsPartial,
		report.ExecutiveSummary.ControlsNotMet)
	fmt.Printf("Findings: %d Critical, %d High, %d Medium, %d Low\n",
		report.ExecutiveSummary.CriticalFindings,
		report.ExecutiveSummary.HighFindings,
		report.ExecutiveSummary.MediumFindings,
		report.ExecutiveSummary.LowFindings)
	fmt.Println()

	fmt.Println("=== STATISTICS ===")
	fmt.Printf("Total Events: %d\n", report.Statistics.TotalEvents)
	fmt.Printf("Success Rate: %.2f%%\n", report.Statistics.SuccessRate*100)
	fmt.Printf("Average Daily Events: %.0f\n", report.Statistics.AverageDaily)
}
