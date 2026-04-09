package export

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/audit"
)

// ---------------------------------------------------------------------------
// CSV Export -- Control Matrix and Timeline
// ---------------------------------------------------------------------------
//
// CSV exports are designed for import into spreadsheet tools and GRC
// platforms. The control matrix format maps compliance controls to evidence,
// while the timeline format provides a flat event log.
// ---------------------------------------------------------------------------

// ExportCSV generates a CSV control matrix from an evidence bundle. The
// matrix has one row per control, with columns for control metadata and
// evidence summary.
func ExportCSV(bundle *audit.Bundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("export/csv: nil bundle")
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header row.
	header := []string{
		"Control ID",
		"Control Name",
		"Framework",
		"Status",
		"Description",
		"Evidence Count",
		"Evidence Sequences",
		"Findings",
		"Bundle ID",
		"Export Date",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("export/csv: failed to write header: %w", err)
	}

	exportDate := time.Now().UTC().Format(time.RFC3339)

	for _, ctrl := range bundle.Controls {
		// Build evidence sequence list.
		seqStrs := make([]string, 0, len(ctrl.EvidenceRefs))
		for _, seq := range ctrl.EvidenceRefs {
			seqStrs = append(seqStrs, strconv.FormatUint(seq, 10))
		}

		row := []string{
			ctrl.ControlID,
			ctrl.ControlName,
			string(bundle.Framework),
			string(ctrl.Status),
			ctrl.Description,
			strconv.Itoa(len(ctrl.EvidenceRefs)),
			strings.Join(seqStrs, ";"),
			strings.Join(ctrl.Findings, "; "),
			bundle.ID,
			exportDate,
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("export/csv: failed to write control row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("export/csv: flush error: %w", err)
	}

	return buf.Bytes(), nil
}

// ExportCSVTimeline generates a CSV timeline from a timeline structure. Each
// row represents a single event.
func ExportCSVTimeline(tl *audit.Timeline) ([]byte, error) {
	if tl == nil {
		return nil, fmt.Errorf("export/csv: nil timeline")
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header row.
	header := []string{
		"Sequence",
		"Timestamp",
		"Category",
		"Severity",
		"Action",
		"Actor",
		"Block Height",
		"Record Hash",
		"Details",
		"Linked Events",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("export/csv: failed to write header: %w", err)
	}

	for _, e := range tl.Events {
		// Serialize details as key=value pairs.
		detailParts := make([]string, 0, len(e.Details))
		for k, v := range e.Details {
			detailParts = append(detailParts, k+"="+v)
		}

		// Serialize linked events.
		linkedParts := make([]string, 0, len(e.LinkedEvents))
		for _, seq := range e.LinkedEvents {
			linkedParts = append(linkedParts, strconv.FormatUint(seq, 10))
		}

		row := []string{
			strconv.FormatUint(e.Sequence, 10),
			e.Timestamp.Format(time.RFC3339),
			string(e.Category),
			string(e.Severity),
			e.Action,
			e.Actor,
			strconv.FormatInt(e.BlockHeight, 10),
			e.RecordHash,
			strings.Join(detailParts, "; "),
			strings.Join(linkedParts, ";"),
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("export/csv: failed to write event row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("export/csv: flush error: %w", err)
	}

	return buf.Bytes(), nil
}

// ExportCSVRecords generates a flat CSV of audit records from a bundle.
func ExportCSVRecords(bundle *audit.Bundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("export/csv: nil bundle")
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{
		"Sequence",
		"Record Hash",
		"Previous Hash",
		"Category",
		"Severity",
		"Action",
		"Block Height",
		"Timestamp",
		"Actor",
		"Details",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("export/csv: failed to write header: %w", err)
	}

	for _, r := range bundle.Records {
		detailParts := make([]string, 0, len(r.Details))
		for k, v := range r.Details {
			detailParts = append(detailParts, k+"="+v)
		}

		row := []string{
			strconv.FormatUint(r.Sequence, 10),
			r.RecordHash,
			r.PreviousHash,
			string(r.Category),
			string(r.Severity),
			r.Action,
			strconv.FormatInt(r.BlockHeight, 10),
			r.Timestamp,
			r.Actor,
			strings.Join(detailParts, "; "),
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("export/csv: failed to write record row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("export/csv: flush error: %w", err)
	}

	return buf.Bytes(), nil
}
