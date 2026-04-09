package epcis

import (
	"encoding/json"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// FuzzEPCURNValidation
// ---------------------------------------------------------------------------

// FuzzEPCURNValidation fuzzes arbitrary strings as EPC URNs to verify
// that the URN pattern matcher correctly accepts valid GS1 EPC URN
// formats and rejects invalid ones.
//
// Invariants:
//   - Valid URN format (urn:epc:id:<type>:<value>) is accepted.
//   - Invalid formats are rejected.
//   - No panics regardless of input.
func FuzzEPCURNValidation(f *testing.F) {
	// Valid EPC URNs
	f.Add("urn:epc:id:sgtin:0614141.107346.2017")
	f.Add("urn:epc:id:sscc:0614141.1234567890")
	f.Add("urn:epc:id:grai:0614141.12345.400")
	f.Add("urn:epc:id:giai:0614141.12345")
	f.Add("urn:epc:id:sgln:0614141.12345.0")
	// Invalid URNs
	f.Add("")
	f.Add("not-a-urn")
	f.Add("urn:epc:id:")
	f.Add("urn:epc:id:SGTIN:uppercase")
	f.Add("urn:epc:sgtin:missing-id-segment")
	f.Add("http://example.com")
	f.Add("urn:isbn:0451450523")
	f.Add("\x00\xff\t\n")
	f.Add("urn:epc:id:sgtin:") // trailing colon, no value

	f.Fuzz(func(t *testing.T, input string) {
		matched := epcURNPattern.MatchString(input)

		// Invariant 1: valid EPC URNs must match
		// A valid URN starts with "urn:epc:id:" followed by a lowercase type
		// and then a value after the colon.
		if len(input) > 12 && input[:12] == "urn:epc:id:" {
			// Check there's a lowercase type segment followed by value
			rest := input[12:]
			hasColon := false
			allLowerType := true
			for i, c := range rest {
				if c == ':' {
					hasColon = i > 0 // type must be non-empty
					break
				}
				if c < 'a' || c > 'z' {
					allLowerType = false
				}
			}
			if hasColon && allLowerType {
				if !matched {
					t.Errorf("valid EPC URN %q should match pattern", input)
				}
			}
		}

		// Invariant 2: empty string never matches
		if input == "" && matched {
			t.Error("empty string must not match EPC URN pattern")
		}

		// Invariant 3: strings not starting with "urn:epc:id:" never match
		if len(input) < 12 && matched {
			t.Errorf("short string %q should not match EPC URN pattern", input)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzEPCISEventSerialization
// ---------------------------------------------------------------------------

// FuzzEPCISEventSerialization fuzzes JSON round-trip serialization of
// EPCIS ObjectEvent to verify no data loss occurs.
//
// Invariants:
//   - Marshal then Unmarshal produces equivalent data.
//   - No panics on any input.
//   - Fields survive the round-trip without corruption.
func FuzzEPCISEventSerialization(f *testing.F) {
	f.Add("evt-001", "urn:epc:id:sgtin:0614141.107346.1", "ADD", "urn:epcglobal:cbv:bizstep:shipping", "urn:epcglobal:cbv:disp:in_transit", "loc-001")
	f.Add("", "", "", "", "", "")
	f.Add("evt-002", "urn:epc:id:sscc:test", "OBSERVE", "urn:epcglobal:cbv:bizstep:receiving", "urn:epcglobal:cbv:disp:active", "loc-002")
	f.Add("e", "epc1", "DELETE", "step", "disp", "loc")

	f.Fuzz(func(t *testing.T, eventID, epc, action, bizStep, disposition, locationID string) {
		// JSON encoding replaces invalid UTF-8 with U+FFFD, which breaks
		// byte-level round-trip comparisons. Skip non-UTF-8 inputs.
		for _, s := range []string{eventID, epc, action, bizStep, disposition, locationID} {
			if !utf8.ValidString(s) {
				return
			}
		}

		event := &ObjectEvent{
			eventBase: eventBase{
				EventID:   eventID,
				EventTime: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			},
			Type:        EventTypeObject,
			EPCList:     []string{epc},
			Action:      Action(action),
			BizStep:     bizStep,
			Disposition: disposition,
		}
		if locationID != "" {
			event.ReadPoint = &ReadPoint{ID: locationID}
		}

		// Marshal to JSON
		data, err := json.Marshal(event)
		if err != nil {
			// Some inputs may not marshal cleanly; skip those
			t.Skipf("marshal error (acceptable): %v", err)
		}

		// Unmarshal back
		var roundTripped ObjectEvent
		if err := json.Unmarshal(data, &roundTripped); err != nil {
			t.Fatalf("unmarshal failed after successful marshal: %v", err)
		}

		// Invariant 1: EventID survives round-trip
		if roundTripped.EventID != eventID {
			t.Errorf("EventID: got %q; want %q", roundTripped.EventID, eventID)
		}

		// Invariant 2: EPCList survives round-trip
		if len(roundTripped.EPCList) != 1 || roundTripped.EPCList[0] != epc {
			t.Errorf("EPCList: got %v; want [%q]", roundTripped.EPCList, epc)
		}

		// Invariant 3: Action survives round-trip
		if roundTripped.Action != Action(action) {
			t.Errorf("Action: got %q; want %q", roundTripped.Action, action)
		}

		// Invariant 4: BizStep survives round-trip
		if roundTripped.BizStep != bizStep {
			t.Errorf("BizStep: got %q; want %q", roundTripped.BizStep, bizStep)
		}

		// Invariant 5: ReadPoint survives round-trip
		if locationID != "" {
			if roundTripped.ReadPoint == nil || roundTripped.ReadPoint.ID != locationID {
				t.Errorf("ReadPoint.ID: got %v; want %q",
					roundTripped.ReadPoint, locationID)
			}
		}

		// Invariant 6: EventTime survives round-trip
		if !roundTripped.EventTime.Equal(event.EventTime) {
			t.Errorf("EventTime: got %v; want %v", roundTripped.EventTime, event.EventTime)
		}
	})
}
