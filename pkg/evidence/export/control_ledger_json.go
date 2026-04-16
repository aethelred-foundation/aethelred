package export

import (
	"encoding/json"
)

// ControlLedgerJSONOptions controls JSON formatting for control ledger exports.
type ControlLedgerJSONOptions struct {
	Indent string `json:"indent,omitempty"`
}

// DefaultControlLedgerJSONOptions returns a human-readable export preset.
func DefaultControlLedgerJSONOptions() ControlLedgerJSONOptions {
	return ControlLedgerJSONOptions{Indent: "  "}
}

// ExportControlLedgerJSON serializes a control ledger to JSON bytes.
func ExportControlLedgerJSON(ledger any) ([]byte, error) {
	return ExportControlLedgerJSONWithOptions(ledger, DefaultControlLedgerJSONOptions())
}

// ExportControlLedgerJSONWithOptions serializes a control ledger with formatting options.
func ExportControlLedgerJSONWithOptions(ledger any, opts ControlLedgerJSONOptions) ([]byte, error) {
	snap, err := normalizeControlLedger(ledger)
	if err != nil {
		return nil, err
	}

	if opts.Indent != "" {
		return json.MarshalIndent(snap.ControlLedgerExport, "", opts.Indent)
	}
	return json.Marshal(snap.ControlLedgerExport)
}

// ExportControlLedgerJSONPretty is a convenience wrapper for human-readable output.
func ExportControlLedgerJSONPretty(ledger any) ([]byte, error) {
	return ExportControlLedgerJSONWithOptions(ledger, DefaultControlLedgerJSONOptions())
}

// ExportControlLedgerJSONCompact emits a compact machine-oriented payload.
func ExportControlLedgerJSONCompact(ledger any) ([]byte, error) {
	return ExportControlLedgerJSONWithOptions(ledger, ControlLedgerJSONOptions{})
}
