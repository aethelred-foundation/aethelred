package export

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/pkg/audit"
)

// ---------------------------------------------------------------------------
// JSON Export
// ---------------------------------------------------------------------------
//
// Exports audit bundles, timelines, and assessment reports as JSON. The
// JSON format follows the evidence-bundle-schema-v1 for bundles and uses
// structured formats for timelines and reports.
// ---------------------------------------------------------------------------

// JSONExportOptions controls JSON export formatting.
type JSONExportOptions struct {
	// Indent produces human-readable JSON with the given indentation.
	Indent string `json:"indent,omitempty"`

	// IncludeMetadata includes metadata fields in the export.
	IncludeMetadata bool `json:"include_metadata"`
}

// DefaultJSONOptions returns sensible defaults for JSON export.
func DefaultJSONOptions() JSONExportOptions {
	return JSONExportOptions{
		Indent:          "  ",
		IncludeMetadata: true,
	}
}

// ExportJSON serializes an evidence bundle to JSON bytes.
func ExportJSON(bundle *audit.Bundle) ([]byte, error) {
	return ExportJSONWithOptions(bundle, DefaultJSONOptions())
}

// ExportJSONWithOptions serializes an evidence bundle to JSON with options.
func ExportJSONWithOptions(bundle *audit.Bundle, opts JSONExportOptions) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("export/json: nil bundle")
	}

	if opts.Indent != "" {
		return json.MarshalIndent(bundle, "", opts.Indent)
	}
	return json.Marshal(bundle)
}

// ---------------------------------------------------------------------------
// Timeline export
// ---------------------------------------------------------------------------

// TimelineExport is the JSON structure for an exported timeline.
type TimelineExport struct {
	ExportVersion string                 `json:"export_version"`
	ExportedAt    string                 `json:"exported_at"`
	Context       string                 `json:"context"`
	TotalEvents   int                    `json:"total_events"`
	StartTime     *time.Time             `json:"start_time,omitempty"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	Events        []TimelineEventExport  `json:"events"`
}

// TimelineEventExport is a single event in the exported timeline.
type TimelineEventExport struct {
	Timestamp    string            `json:"timestamp"`
	Category     string            `json:"category"`
	Severity     string            `json:"severity"`
	Action       string            `json:"action"`
	Actor        string            `json:"actor"`
	Sequence     uint64            `json:"sequence"`
	BlockHeight  int64             `json:"block_height"`
	RecordHash   string            `json:"record_hash"`
	Details      map[string]string `json:"details,omitempty"`
	LinkedEvents []uint64          `json:"linked_events,omitempty"`
}

// ExportJSONTimeline serializes a timeline to JSON bytes.
func ExportJSONTimeline(tl *audit.Timeline) ([]byte, error) {
	return ExportJSONTimelineWithOptions(tl, DefaultJSONOptions())
}

// ExportJSONTimelineWithOptions serializes a timeline to JSON with options.
func ExportJSONTimelineWithOptions(tl *audit.Timeline, opts JSONExportOptions) ([]byte, error) {
	if tl == nil {
		return nil, fmt.Errorf("export/json: nil timeline")
	}

	export := TimelineExport{
		ExportVersion: "1.0.0",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Context:       tl.Context,
		TotalEvents:   tl.TotalEvents,
		StartTime:     tl.StartTime,
		EndTime:       tl.EndTime,
		Events:        make([]TimelineEventExport, 0, len(tl.Events)),
	}

	for _, e := range tl.Events {
		export.Events = append(export.Events, TimelineEventExport{
			Timestamp:    e.Timestamp.Format(time.RFC3339),
			Category:     string(e.Category),
			Severity:     string(e.Severity),
			Action:       e.Action,
			Actor:        e.Actor,
			Sequence:     e.Sequence,
			BlockHeight:  e.BlockHeight,
			RecordHash:   e.RecordHash,
			Details:      e.Details,
			LinkedEvents: e.LinkedEvents,
		})
	}

	if opts.Indent != "" {
		return json.MarshalIndent(export, "", opts.Indent)
	}
	return json.Marshal(export)
}

// ---------------------------------------------------------------------------
// Assessment report export
// ---------------------------------------------------------------------------

// AssessmentReport is a compliance assessment summary.
type AssessmentReport struct {
	ExportVersion string                   `json:"export_version"`
	ExportedAt    string                   `json:"exported_at"`
	Framework     string                   `json:"framework"`
	BundleID      string                   `json:"bundle_id"`
	Summary       AssessmentSummary        `json:"summary"`
	Controls      []ControlAssessment      `json:"controls"`
}

// AssessmentSummary provides aggregate assessment metrics.
type AssessmentSummary struct {
	TotalControls    int `json:"total_controls"`
	Satisfied        int `json:"satisfied"`
	PartialSatisfied int `json:"partially_satisfied"`
	NotSatisfied     int `json:"not_satisfied"`
	NotApplicable    int `json:"not_applicable"`
	NotAssessed      int `json:"not_assessed"`
	TotalRecords     int `json:"total_records"`
	TotalSeals       int `json:"total_seals"`
	ChainIntact      bool `json:"chain_intact"`
}

// ControlAssessment is the assessment result for a single control.
type ControlAssessment struct {
	ControlID   string   `json:"control_id"`
	ControlName string   `json:"control_name"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	EvidenceCount int    `json:"evidence_count"`
	Findings    []string `json:"findings,omitempty"`
}

// ExportJSONReport generates a JSON assessment report from a bundle.
func ExportJSONReport(bundle *audit.Bundle) ([]byte, error) {
	return ExportJSONReportWithOptions(bundle, DefaultJSONOptions())
}

// ExportJSONReportWithOptions generates a JSON assessment report with options.
func ExportJSONReportWithOptions(bundle *audit.Bundle, opts JSONExportOptions) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("export/json: nil bundle")
	}

	report := AssessmentReport{
		ExportVersion: "1.0.0",
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Framework:     string(bundle.Framework),
		BundleID:      bundle.ID,
		Summary: AssessmentSummary{
			TotalControls: len(bundle.Controls),
			TotalRecords:  len(bundle.Records),
			TotalSeals:    len(bundle.Seals),
			ChainIntact:   audit.VerifyChain(bundle.Records) == nil,
		},
		Controls: make([]ControlAssessment, 0, len(bundle.Controls)),
	}

	for _, ctrl := range bundle.Controls {
		ca := ControlAssessment{
			ControlID:     ctrl.ControlID,
			ControlName:   ctrl.ControlName,
			Status:        string(ctrl.Status),
			Description:   ctrl.Description,
			EvidenceCount: len(ctrl.EvidenceRefs),
			Findings:      ctrl.Findings,
		}
		report.Controls = append(report.Controls, ca)

		// Tally summaries.
		switch ctrl.Status {
		case audit.ControlSatisfied:
			report.Summary.Satisfied++
		case audit.ControlPartial:
			report.Summary.PartialSatisfied++
		case audit.ControlNotSatisfied:
			report.Summary.NotSatisfied++
		case audit.ControlNotApplicable:
			report.Summary.NotApplicable++
		case audit.ControlNotAssessed:
			report.Summary.NotAssessed++
		}
	}

	if opts.Indent != "" {
		return json.MarshalIndent(report, "", opts.Indent)
	}
	return json.Marshal(report)
}
