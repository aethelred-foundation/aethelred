package epcis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/seal/sdk"
)

func benchNewCapture(b *testing.B) *CaptureService {
	b.Helper()
	keeper := newMockSealKeeper()
	sealSDK, err := sdk.NewSealSDK(sdk.Config{
		ChainID:       "bench-chain",
		SignerAddress: "aethelred1bench",
	}, keeper)
	if err != nil {
		b.Fatalf("setup: NewSealSDK failed: %v", err)
	}

	return NewCaptureService(CaptureConfig{
		SealOnCapture:       true,
		DefaultBizLocation:  "urn:epc:id:sgln:benchmark.location",
		DefaultJurisdiction: "US",
	}, sealSDK)
}

func benchObjectEvent(idx int) *ObjectEvent {
	return &ObjectEvent{
		eventBase: eventBase{
			EventID:             fmt.Sprintf("evt-bench-%d", idx),
			EventTime:           time.Now().UTC(),
			EventTimeZoneOffset: "+00:00",
		},
		Type:        EventTypeObject,
		Action:      ActionADD,
		BizStep:     BizStepCommissioning,
		Disposition: DispositionActive,
		EPCList:     []string{fmt.Sprintf("urn:epc:id:sgtin:benchmark.product.%d", idx)},
		BizLocation: &BizLocation{ID: "urn:epc:id:sgln:benchmark.location"},
		ReadPoint:   &ReadPoint{ID: "urn:epc:id:sgln:benchmark.readpoint"},
	}
}

func BenchmarkCaptureEvent(b *testing.B) {
	capture := benchNewCapture(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = capture.CaptureEvent(ctx, benchObjectEvent(i))
	}
}

func BenchmarkTraceItem(b *testing.B) {
	capture := benchNewCapture(b)
	ctx := context.Background()
	epc := "urn:epc:id:sgtin:benchmark.trace.001"

	// Pre-populate events for the item.
	for j := 0; j < 10; j++ {
		evt := benchObjectEvent(j)
		evt.EPCList = []string{epc}
		_, _ = capture.CaptureEvent(ctx, evt)
	}

	query := NewQueryService(capture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = query.TraceItem(ctx, epc)
	}
}

func BenchmarkBuildProvenance(b *testing.B) {
	capture := benchNewCapture(b)
	ctx := context.Background()
	epc := "urn:epc:id:sgtin:benchmark.provenance.001"

	for j := 0; j < 5; j++ {
		evt := benchObjectEvent(j)
		evt.EPCList = []string{epc}
		_, _ = capture.CaptureEvent(ctx, evt)
	}

	query := NewQueryService(capture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// TraceItem serves as provenance chain builder.
		_, _ = query.TraceItem(ctx, epc)
	}
}
