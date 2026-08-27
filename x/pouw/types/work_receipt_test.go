package types_test

import (
	"bytes"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/aethelred/aethelred/x/pouw/types"
)

func sampleReceipt() types.WorkReceipt {
	return types.WorkReceipt{
		JobID:              "job-1",
		Validator:          "aethelredvaloper1abc",
		DeviceClass:        "nvidia-h100",
		DeviceMilliseconds: 3_600_000, // 1 hour
		AvgPowerMilliwatts: 1_000_000, // 1000 W
		Basis:              types.EnergyBasisMeasured,
		UsefulWorkUnits:    500,
	}
}

// ---------------------------------------------------------------------------
// Integer energy/cost/carbon math (deterministic, no floats)
// ---------------------------------------------------------------------------

func TestWorkReceiptEnergyMathIsExact(t *testing.T) {
	p := types.DefaultEnergyParams()
	r := sampleReceipt() // 1000 W for 1 h = 1 kWh at the device

	// device uJ = mW * ms = 1e6 * 3.6e6 = 3.6e12 uJ (exactly 1 kWh).
	if got := r.DeviceMicrojoules(); !got.Equal(sdkmath.NewInt(3_600_000_000_000)) {
		t.Fatalf("device microjoules: got %s, want 3.6e12", got)
	}
	// facility uJ = device * PUE(1.2) = 4.32e12 uJ.
	if got := r.FacilityMicrojoules(p); !got.Equal(sdkmath.NewInt(4_320_000_000_000)) {
		t.Fatalf("facility microjoules: got %s, want 4.32e12", got)
	}
	// cost = 1.2 kWh * $0.08 = $0.096 = 96000 micro-USD.
	if got := r.CostMicroUSD(p); !got.Equal(sdkmath.NewInt(96_000)) {
		t.Fatalf("cost micro-USD: got %s, want 96000", got)
	}
	// carbon = 1.2 kWh * 400 g/kWh = 480 g = 480000 mg.
	if got := r.CarbonMilligrams(p); !got.Equal(sdkmath.NewInt(480_000)) {
		t.Fatalf("carbon mg: got %s, want 480000", got)
	}
	// PoW-equivalent waste at 100% ratio = facility energy.
	if got := r.PoWEquivalentWasteMicrojoules(p); !got.Equal(sdkmath.NewInt(4_320_000_000_000)) {
		t.Fatalf("pow waste uJ: got %s, want 4.32e12", got)
	}
}

func TestWorkReceiptScalesLinearly(t *testing.T) {
	p := types.DefaultEnergyParams()
	r := sampleReceipt()
	half := r
	half.DeviceMilliseconds = r.DeviceMilliseconds / 2
	if !half.CostMicroUSD(p).MulRaw(2).Equal(r.CostMicroUSD(p)) {
		t.Fatal("cost should scale linearly with device time")
	}
	if !half.CarbonMilligrams(p).MulRaw(2).Equal(r.CarbonMilligrams(p)) {
		t.Fatal("carbon should scale linearly with device time")
	}
}

func TestWorkReceiptNoOverflowAtScale(t *testing.T) {
	// A full rack: 1 MW for a day. Must not overflow (sdkmath.Int is big-int).
	p := types.DefaultEnergyParams()
	r := sampleReceipt()
	r.AvgPowerMilliwatts = 1_000_000_000 // 1 MW
	r.DeviceMilliseconds = 86_400_000    // 24 h
	got := r.CostMicroUSD(p)
	if !got.IsPositive() {
		t.Fatalf("expected positive cost at scale, got %s", got)
	}
	// 1 MW * 24h = 24000 kWh device; *1.2 PUE = 28800 kWh; *$0.08 = $2304.
	if !got.Equal(sdkmath.NewInt(2_304_000_000)) { // micro-USD
		t.Fatalf("cost at scale: got %s, want 2.304e9 micro-USD", got)
	}
}

// ---------------------------------------------------------------------------
// Energy basis honesty label
// ---------------------------------------------------------------------------

func TestCombineEnergyBasis(t *testing.T) {
	M, E := types.EnergyBasisMeasured, types.EnergyBasisDeviceProfile
	if types.CombineEnergyBasis(M, M) != M {
		t.Fatal("measured + measured must stay measured")
	}
	for _, c := range [][2]types.EnergyBasis{{M, E}, {E, M}, {E, E}} {
		if types.CombineEnergyBasis(c[0], c[1]) != E {
			t.Fatalf("any estimate must degrade aggregate: %v", c)
		}
	}
}

func TestEnergyBasisValid(t *testing.T) {
	if !types.EnergyBasisMeasured.Valid() || !types.EnergyBasisDeviceProfile.Valid() {
		t.Fatal("known bases must be valid")
	}
	if types.EnergyBasis("guess").Valid() {
		t.Fatal("unknown basis must be invalid")
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestWorkReceiptValidate(t *testing.T) {
	if err := sampleReceipt().Validate(); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	mutate := map[string]func(*types.WorkReceipt){
		"empty job":        func(r *types.WorkReceipt) { r.JobID = "" },
		"empty validator":  func(r *types.WorkReceipt) { r.Validator = "" },
		"empty device":     func(r *types.WorkReceipt) { r.DeviceClass = "" },
		"zero device time": func(r *types.WorkReceipt) { r.DeviceMilliseconds = 0 },
		"zero power":       func(r *types.WorkReceipt) { r.AvgPowerMilliwatts = 0 },
		"bad basis":        func(r *types.WorkReceipt) { r.Basis = "made-up" },
	}
	for name, m := range mutate {
		r := sampleReceipt()
		m(&r)
		if err := r.Validate(); err == nil {
			t.Fatalf("%s: expected validation error, got nil", name)
		}
	}
}

func TestEnergyParamsValidate(t *testing.T) {
	if err := types.DefaultEnergyParams().Validate(); err != nil {
		t.Fatalf("default params rejected: %v", err)
	}
	bad := []types.EnergyParams{
		{PueMilli: 999, GridCarbonGramsPerKWh: 400, ElectricityCostMicroUSDPerKWh: 80000}, // PUE < 1.0
		{PueMilli: 1200, GridCarbonGramsPerKWh: 400, ElectricityCostMicroUSDPerKWh: 0},    // zero cost
		{PueMilli: 1200, GridCarbonGramsPerKWh: 0, ElectricityCostMicroUSDPerKWh: 80000},  // zero carbon
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Fatalf("bad params %d accepted", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Canonical hash binding (for the Digital Seal)
// ---------------------------------------------------------------------------

func TestWorkReceiptHashIsDeterministic(t *testing.T) {
	a := sampleReceipt()
	b := sampleReceipt()
	if !bytes.Equal(a.Hash(), b.Hash()) {
		t.Fatal("identical receipts must hash identically")
	}
	if len(a.Hash()) != 32 {
		t.Fatalf("hash must be 32 bytes, got %d", len(a.Hash()))
	}
}

func TestWorkReceiptHashIsSensitiveToEveryField(t *testing.T) {
	base := sampleReceipt()
	baseHash := base.Hash()
	mutations := []func(*types.WorkReceipt){
		func(r *types.WorkReceipt) { r.JobID = "job-2" },
		func(r *types.WorkReceipt) { r.Validator = "other" },
		func(r *types.WorkReceipt) { r.DeviceClass = "nvidia-a100" },
		func(r *types.WorkReceipt) { r.DeviceMilliseconds++ },
		func(r *types.WorkReceipt) { r.AvgPowerMilliwatts++ },
		func(r *types.WorkReceipt) { r.Basis = types.EnergyBasisDeviceProfile },
		func(r *types.WorkReceipt) { r.UsefulWorkUnits++ },
	}
	for i, m := range mutations {
		r := base
		m(&r)
		if bytes.Equal(r.Hash(), baseHash) {
			t.Fatalf("mutation %d did not change the hash (field not bound)", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Metadata transport (worker -> keeper, proto-free)
// ---------------------------------------------------------------------------

func goodEnergyMetadata() map[string]string {
	return map[string]string{
		types.MetaEnergyDeviceClass: "nvidia-h100",
		types.MetaEnergyDeviceMs:    "3600000",
		types.MetaEnergyAvgPowerMw:  "1000000",
		types.MetaEnergyBasis:       string(types.EnergyBasisMeasured),
	}
}

func TestParseWorkReceiptFromMetadataValid(t *testing.T) {
	r, ok := types.ParseWorkReceiptFromMetadata("job-1", "val-1", 500, goodEnergyMetadata())
	if !ok {
		t.Fatal("valid energy metadata should parse")
	}
	if r.JobID != "job-1" || r.Validator != "val-1" || r.UsefulWorkUnits != 500 {
		t.Fatal("identity fields not threaded through")
	}
	if r.DeviceMilliseconds != 3_600_000 || r.AvgPowerMilliwatts != 1_000_000 {
		t.Fatal("measurement fields not parsed")
	}
	if r.Basis != types.EnergyBasisMeasured {
		t.Fatal("basis not parsed")
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("parsed receipt should be valid: %v", err)
	}
}

func TestParseWorkReceiptFromMetadataSkips(t *testing.T) {
	// Each of these must yield ok=false so best-effort metering is simply skipped
	// — never an error that could block job completion.
	cases := map[string]map[string]string{
		"nil metadata":   nil,
		"empty metadata": {},
		"missing power": {
			types.MetaEnergyDeviceClass: "h100",
			types.MetaEnergyDeviceMs:    "1000",
			types.MetaEnergyBasis:       string(types.EnergyBasisMeasured),
		},
		"non-numeric device ms": {
			types.MetaEnergyDeviceClass: "h100",
			types.MetaEnergyDeviceMs:    "soon",
			types.MetaEnergyAvgPowerMw:  "1000",
			types.MetaEnergyBasis:       string(types.EnergyBasisMeasured),
		},
		"invalid basis": {
			types.MetaEnergyDeviceClass: "h100",
			types.MetaEnergyDeviceMs:    "1000",
			types.MetaEnergyAvgPowerMw:  "1000",
			types.MetaEnergyBasis:       "vibes",
		},
		"zero power": {
			types.MetaEnergyDeviceClass: "h100",
			types.MetaEnergyDeviceMs:    "1000",
			types.MetaEnergyAvgPowerMw:  "0",
			types.MetaEnergyBasis:       string(types.EnergyBasisMeasured),
		},
		"empty device class": {
			types.MetaEnergyDeviceMs:   "1000",
			types.MetaEnergyAvgPowerMw: "1000",
			types.MetaEnergyBasis:      string(types.EnergyBasisMeasured),
		},
	}
	for name, md := range cases {
		if _, ok := types.ParseWorkReceiptFromMetadata("job", "val", 1, md); ok {
			t.Fatalf("%s: expected skip (ok=false)", name)
		}
	}
}

// The length-prefix framing must prevent field-boundary collisions: the raw
// character stream "job" + "1val" equals "job1" + "val", but the receipts must
// still hash differently.
func TestWorkReceiptHashNoFieldBoundaryCollision(t *testing.T) {
	a := sampleReceipt()
	a.JobID, a.Validator = "job", "1val"
	b := sampleReceipt()
	b.JobID, b.Validator = "job1", "val"
	if bytes.Equal(a.Hash(), b.Hash()) {
		t.Fatal("length-prefix framing failed: field-boundary collision")
	}
}
