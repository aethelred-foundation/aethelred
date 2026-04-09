// Package epcis provides an EPCIS 2.0 supply chain adapter that bridges
// Aethelred Digital Seals to supply chain traceability standards. It supports
// event capture, querying, provenance chain construction, and recall workflows
// per the GS1 EPCIS 2.0 specification.
package epcis

import (
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------------------
// EPCIS 2.0 Event Types
// ---------------------------------------------------------------------------
//
// These types model the core EPCIS 2.0 event structures for supply chain
// traceability. Field names and semantics follow the GS1 EPCIS 2.0
// specification (https://www.gs1.org/standards/epcis).
// ---------------------------------------------------------------------------

// EventType identifies the kind of EPCIS event.
type EventType string

const (
	EventTypeObject         EventType = "ObjectEvent"
	EventTypeAggregation    EventType = "AggregationEvent"
	EventTypeTransaction    EventType = "TransactionEvent"
	EventTypeTransformation EventType = "TransformationEvent"
)

// Action is the EPCIS event action indicating what happened.
type Action string

const (
	ActionADD     Action = "ADD"
	ActionOBSERVE Action = "OBSERVE"
	ActionDELETE  Action = "DELETE"
)

// ---------------------------------------------------------------------------
// Business Step (bizStep) constants per CBV 2.0
// ---------------------------------------------------------------------------

const (
	BizStepCommissioning    = "urn:epcglobal:cbv:bizstep:commissioning"
	BizStepShipping         = "urn:epcglobal:cbv:bizstep:shipping"
	BizStepReceiving        = "urn:epcglobal:cbv:bizstep:receiving"
	BizStepStoring          = "urn:epcglobal:cbv:bizstep:storing"
	BizStepPacking          = "urn:epcglobal:cbv:bizstep:packing"
	BizStepUnpacking        = "urn:epcglobal:cbv:bizstep:unpacking"
	BizStepLoading          = "urn:epcglobal:cbv:bizstep:loading"
	BizStepUnloading        = "urn:epcglobal:cbv:bizstep:unloading"
	BizStepTransporting     = "urn:epcglobal:cbv:bizstep:transporting"
	BizStepInspecting       = "urn:epcglobal:cbv:bizstep:inspecting"
	BizStepHolding          = "urn:epcglobal:cbv:bizstep:holding"
	BizStepCycleCount       = "urn:epcglobal:cbv:bizstep:cycle_counting"
	BizStepDestroying       = "urn:epcglobal:cbv:bizstep:destroying"
	BizStepDecommissioning  = "urn:epcglobal:cbv:bizstep:decommissioning"
	BizStepTransforming     = "urn:epcglobal:cbv:bizstep:transforming"
	BizStepSampling         = "urn:epcglobal:cbv:bizstep:sampling"
)

// ---------------------------------------------------------------------------
// Disposition constants per CBV 2.0
// ---------------------------------------------------------------------------

const (
	DispositionActive         = "urn:epcglobal:cbv:disp:active"
	DispositionInactive       = "urn:epcglobal:cbv:disp:inactive"
	DispositionInTransit      = "urn:epcglobal:cbv:disp:in_transit"
	DispositionReturned       = "urn:epcglobal:cbv:disp:returned"
	DispositionRecalled       = "urn:epcglobal:cbv:disp:recalled"
	DispositionDisposed       = "urn:epcglobal:cbv:disp:disposed"
	DispositionInProgress     = "urn:epcglobal:cbv:disp:in_progress"
	DispositionSellableAcc    = "urn:epcglobal:cbv:disp:sellable_accessible"
	DispositionSellableNotAcc = "urn:epcglobal:cbv:disp:sellable_not_accessible"
	DispositionDamaged        = "urn:epcglobal:cbv:disp:damaged"
	DispositionExpired        = "urn:epcglobal:cbv:disp:expired"
	DispositionDestroyed      = "urn:epcglobal:cbv:disp:destroyed"
	DispositionContainerOpen  = "urn:epcglobal:cbv:disp:container_open"
)

// ---------------------------------------------------------------------------
// EPCISEvent interface
// ---------------------------------------------------------------------------

// EPCISEvent is the common interface for all EPCIS event types.
type EPCISEvent interface {
	// GetEventType returns the EPCIS event type.
	GetEventType() EventType

	// GetEventTime returns the time the event occurred.
	GetEventTime() time.Time

	// GetEventID returns the unique event identifier.
	GetEventID() string

	// GetEPCList returns the EPCs associated with this event.
	GetEPCList() []string

	// GetBizStep returns the business step.
	GetBizStep() string

	// ToJSON serializes the event to JSON.
	ToJSON() ([]byte, error)
}

// ---------------------------------------------------------------------------
// Common event fields
// ---------------------------------------------------------------------------

// eventBase contains fields shared by all EPCIS events.
type eventBase struct {
	EventID             string            `json:"eventID,omitempty"`
	EventTime           time.Time         `json:"eventTime"`
	EventTimeZoneOffset string            `json:"eventTimeZoneOffset,omitempty"`
	RecordTime          *time.Time        `json:"recordTime,omitempty"`
	ErrorDeclaration    *ErrorDeclaration `json:"errorDeclaration,omitempty"`
}

// ErrorDeclaration records an error correction for a prior event.
type ErrorDeclaration struct {
	DeclarationTime    time.Time `json:"declarationTime"`
	Reason             string    `json:"reason,omitempty"`
	CorrectiveEventIDs []string  `json:"correctiveEventIDs,omitempty"`
}

// ---------------------------------------------------------------------------
// Common types
// ---------------------------------------------------------------------------

// BizTransaction represents a business transaction in EPCIS.
type BizTransaction struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"bizTransaction"`
}

// QuantityElement describes a quantity of items by class-level identifier.
type QuantityElement struct {
	EPCClass  string  `json:"epcClass"`
	Quantity  float64 `json:"quantity"`
	UOM       string  `json:"uom,omitempty"`
}

// SourceDestination identifies a source or destination in a transaction.
type SourceDestination struct {
	Type  string `json:"type"`
	Value string `json:"source,omitempty"`
}

// ReadPoint identifies a location where an event was observed.
type ReadPoint struct {
	ID string `json:"id"`
}

// BizLocation identifies the business location where an event occurred.
type BizLocation struct {
	ID string `json:"id"`
}

// ---------------------------------------------------------------------------
// ObjectEvent
// ---------------------------------------------------------------------------

// ObjectEvent captures information about one or more physical or digital
// objects identified by instance-level (EPC) or class-level identifiers.
type ObjectEvent struct {
	eventBase
	Type             EventType          `json:"type"`
	EPCList          []string           `json:"epcList,omitempty"`
	QuantityList     []QuantityElement  `json:"quantityList,omitempty"`
	Action           Action             `json:"action"`
	BizStep          string             `json:"bizStep,omitempty"`
	Disposition      string             `json:"disposition,omitempty"`
	ReadPoint        *ReadPoint         `json:"readPoint,omitempty"`
	BizLocation      *BizLocation       `json:"bizLocation,omitempty"`
	BizTransactions  []BizTransaction   `json:"bizTransactionList,omitempty"`
	Sources          []SourceDestination `json:"sourceList,omitempty"`
	Destinations     []SourceDestination `json:"destinationList,omitempty"`
	Extensions       map[string]string  `json:"extensions,omitempty"`
}

func (e *ObjectEvent) GetEventType() EventType   { return EventTypeObject }
func (e *ObjectEvent) GetEventTime() time.Time    { return e.EventTime }
func (e *ObjectEvent) GetEventID() string         { return e.EventID }
func (e *ObjectEvent) GetEPCList() []string       { return e.EPCList }
func (e *ObjectEvent) GetBizStep() string         { return e.BizStep }
func (e *ObjectEvent) ToJSON() ([]byte, error)    { return json.Marshal(e) }

// ---------------------------------------------------------------------------
// AggregationEvent
// ---------------------------------------------------------------------------

// AggregationEvent captures information about the aggregation or
// disaggregation of objects (e.g., packing items into a container).
type AggregationEvent struct {
	eventBase
	Type            EventType          `json:"type"`
	ParentID        string             `json:"parentID,omitempty"`
	ChildEPCs       []string           `json:"childEPCs,omitempty"`
	ChildQuantity   []QuantityElement  `json:"childQuantityList,omitempty"`
	Action          Action             `json:"action"`
	BizStep         string             `json:"bizStep,omitempty"`
	Disposition     string             `json:"disposition,omitempty"`
	ReadPoint       *ReadPoint         `json:"readPoint,omitempty"`
	BizLocation     *BizLocation       `json:"bizLocation,omitempty"`
	BizTransactions []BizTransaction   `json:"bizTransactionList,omitempty"`
	Sources         []SourceDestination `json:"sourceList,omitempty"`
	Destinations    []SourceDestination `json:"destinationList,omitempty"`
	Extensions      map[string]string  `json:"extensions,omitempty"`
}

func (e *AggregationEvent) GetEventType() EventType   { return EventTypeAggregation }
func (e *AggregationEvent) GetEventTime() time.Time    { return e.EventTime }
func (e *AggregationEvent) GetEventID() string         { return e.EventID }
func (e *AggregationEvent) GetEPCList() []string       { return e.ChildEPCs }
func (e *AggregationEvent) GetBizStep() string         { return e.BizStep }
func (e *AggregationEvent) ToJSON() ([]byte, error)    { return json.Marshal(e) }

// ---------------------------------------------------------------------------
// TransactionEvent
// ---------------------------------------------------------------------------

// TransactionEvent associates EPCs with one or more business transactions
// such as purchase orders or invoices.
type TransactionEvent struct {
	eventBase
	Type                EventType          `json:"type"`
	BizTransactionList  []BizTransaction   `json:"bizTransactionList"`
	ParentID            string             `json:"parentID,omitempty"`
	EPCList             []string           `json:"epcList,omitempty"`
	QuantityList        []QuantityElement  `json:"quantityList,omitempty"`
	Action              Action             `json:"action"`
	BizStep             string             `json:"bizStep,omitempty"`
	Disposition         string             `json:"disposition,omitempty"`
	ReadPoint           *ReadPoint         `json:"readPoint,omitempty"`
	BizLocation         *BizLocation       `json:"bizLocation,omitempty"`
	Sources             []SourceDestination `json:"sourceList,omitempty"`
	Destinations        []SourceDestination `json:"destinationList,omitempty"`
	Extensions          map[string]string  `json:"extensions,omitempty"`
}

func (e *TransactionEvent) GetEventType() EventType   { return EventTypeTransaction }
func (e *TransactionEvent) GetEventTime() time.Time    { return e.EventTime }
func (e *TransactionEvent) GetEventID() string         { return e.EventID }
func (e *TransactionEvent) GetEPCList() []string       { return e.EPCList }
func (e *TransactionEvent) GetBizStep() string         { return e.BizStep }
func (e *TransactionEvent) ToJSON() ([]byte, error)    { return json.Marshal(e) }

// ---------------------------------------------------------------------------
// TransformationEvent
// ---------------------------------------------------------------------------

// TransformationEvent captures the transformation of input EPCs into
// output EPCs (e.g., manufacturing or processing).
type TransformationEvent struct {
	eventBase
	Type                EventType          `json:"type"`
	InputEPCList        []string           `json:"inputEPCList,omitempty"`
	InputQuantityList   []QuantityElement  `json:"inputQuantityList,omitempty"`
	OutputEPCList       []string           `json:"outputEPCList,omitempty"`
	OutputQuantityList  []QuantityElement  `json:"outputQuantityList,omitempty"`
	TransformationID    string             `json:"transformationID,omitempty"`
	BizStep             string             `json:"bizStep,omitempty"`
	Disposition         string             `json:"disposition,omitempty"`
	ReadPoint           *ReadPoint         `json:"readPoint,omitempty"`
	BizLocation         *BizLocation       `json:"bizLocation,omitempty"`
	BizTransactions     []BizTransaction   `json:"bizTransactionList,omitempty"`
	Sources             []SourceDestination `json:"sourceList,omitempty"`
	Destinations        []SourceDestination `json:"destinationList,omitempty"`
	Extensions          map[string]string  `json:"extensions,omitempty"`
}

func (e *TransformationEvent) GetEventType() EventType   { return EventTypeTransformation }
func (e *TransformationEvent) GetEventTime() time.Time    { return e.EventTime }
func (e *TransformationEvent) GetEventID() string         { return e.EventID }
func (e *TransformationEvent) GetBizStep() string         { return e.BizStep }
func (e *TransformationEvent) ToJSON() ([]byte, error)    { return json.Marshal(e) }

// GetEPCList returns a combined list of input and output EPCs.
func (e *TransformationEvent) GetEPCList() []string {
	result := make([]string, 0, len(e.InputEPCList)+len(e.OutputEPCList))
	result = append(result, e.InputEPCList...)
	result = append(result, e.OutputEPCList...)
	return result
}

// ---------------------------------------------------------------------------
// EPCISDocument
// ---------------------------------------------------------------------------

// EPCISDocument is the root container for EPCIS events per the EPCIS 2.0
// standard.
type EPCISDocument struct {
	SchemaVersion string     `json:"schemaVersion"`
	CreationDate  time.Time  `json:"creationDate"`
	EPCISBody     EPCISBody  `json:"epcisBody"`
}

// EPCISBody contains the event list within an EPCIS document.
type EPCISBody struct {
	EventList []EPCISEvent `json:"-"`

	// rawEvents stores events for JSON marshaling; populated by MarshalJSON.
	RawEvents []json.RawMessage `json:"eventList,omitempty"`
}

// MarshalJSON serializes the EPCISBody, converting each EPCISEvent to
// its JSON representation.
func (b EPCISBody) MarshalJSON() ([]byte, error) {
	raw := make([]json.RawMessage, 0, len(b.EventList))
	for _, e := range b.EventList {
		data, err := e.ToJSON()
		if err != nil {
			return nil, err
		}
		raw = append(raw, data)
	}

	type alias struct {
		EventList []json.RawMessage `json:"eventList"`
	}
	return json.Marshal(alias{EventList: raw})
}

// NewEPCISDocument creates a new EPCIS 2.0 document.
func NewEPCISDocument(events ...EPCISEvent) *EPCISDocument {
	return &EPCISDocument{
		SchemaVersion: "2.0",
		CreationDate:  time.Now().UTC(),
		EPCISBody: EPCISBody{
			EventList: events,
		},
	}
}
