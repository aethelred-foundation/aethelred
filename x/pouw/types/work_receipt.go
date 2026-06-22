package types

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"

	sdkmath "cosmossdk.io/math"
)

// Metadata keys a worker uses to report a measurement on the compute job, so a
// receipt can be recorded at completion without a proto change to the result
// message. A receipt-hash key is written back to bind the receipt to the job.
const (
	MetaEnergyDeviceClass = "energy.device_class"
	MetaEnergyDeviceMs    = "energy.device_ms"
	MetaEnergyAvgPowerMw  = "energy.avg_power_mw"
	MetaEnergyBasis       = "energy.basis"
	MetaEnergyReceiptHash = "energy.receipt_hash"
)

// ParseWorkReceiptFromMetadata builds a receipt from worker-supplied job
// metadata. It returns ok=false (never an error) when the energy keys are absent
// or malformed, so best-effort metering can be skipped without ever blocking job
// completion.
func ParseWorkReceiptFromMetadata(jobID, validator string, uwu uint64, md map[string]string) (WorkReceipt, bool) {
	if md == nil {
		return WorkReceipt{}, false
	}
	deviceMs, err1 := strconv.ParseUint(md[MetaEnergyDeviceMs], 10, 64)
	powerMw, err2 := strconv.ParseUint(md[MetaEnergyAvgPowerMw], 10, 64)
	if err1 != nil || err2 != nil {
		return WorkReceipt{}, false
	}
	r := WorkReceipt{
		JobID:              jobID,
		Validator:          validator,
		DeviceClass:        md[MetaEnergyDeviceClass],
		DeviceMilliseconds: deviceMs,
		AvgPowerMilliwatts: powerMw,
		Basis:              EnergyBasis(md[MetaEnergyBasis]),
		UsefulWorkUnits:    uwu,
	}
	if r.Validate() != nil {
		return WorkReceipt{}, false
	}
	return r, true
}

// PoUW's promise — "every watt is spent on useful inference" — is only credible
// if the watts are measured on chain, not asserted in a slide. A WorkReceipt is
// the measured energy/cost record a validator submits for a completed compute
// job. All arithmetic here is integer-only and deterministic: consensus state
// can never depend on platform-specific floating point.

// EnergyBasis records where a power figure came from — the energy analogue of
// the TEE hardware boundary. An aggregate is only "measured" if every
// contributing receipt was.
type EnergyBasis string

const (
	// EnergyBasisMeasured: average power read from a live hardware meter
	// (RAPL, NVML, BMC, or PDU telemetry).
	EnergyBasisMeasured EnergyBasis = "measured"
	// EnergyBasisDeviceProfile: average power inferred from a device power
	// profile (rated TDP x utilization) because no live meter was available.
	// An honest estimate, labeled as such.
	EnergyBasisDeviceProfile EnergyBasis = "device_profile_estimate"
)

// Valid reports whether the basis is a recognized value.
func (b EnergyBasis) Valid() bool {
	return b == EnergyBasisMeasured || b == EnergyBasisDeviceProfile
}

// CombineEnergyBasis returns measured only if both inputs are measured;
// otherwise the result degrades to a device-profile estimate.
func CombineEnergyBasis(a, b EnergyBasis) EnergyBasis {
	if a == EnergyBasisMeasured && b == EnergyBasisMeasured {
		return EnergyBasisMeasured
	}
	return EnergyBasisDeviceProfile
}

// microjoulesPerKWh is the exact integer number of microjoules in one kWh:
// 1 kWh = 3.6e6 J = 3.6e12 uJ.
var microjoulesPerKWh = sdkmath.NewInt(3_600_000_000_000)

// EnergyParams holds the governance-set conversion factors. These are the only
// constants in the accounting, each an explicit, auditable parameter. Integers
// keep the math deterministic across validators.
type EnergyParams struct {
	// PueMilli is Power Usage Effectiveness x1000 (1200 = 1.2): total facility
	// power over IT power, covering cooling and delivery overhead.
	PueMilli uint64 `json:"pue_milli"`
	// GridCarbonGramsPerKWh is grid carbon intensity in grams CO2e per kWh.
	GridCarbonGramsPerKWh uint64 `json:"grid_carbon_grams_per_kwh"`
	// ElectricityCostMicroUSDPerKWh is delivered electricity cost in micro-USD
	// per kWh (80000 = $0.08/kWh).
	ElectricityCostMicroUSDPerKWh uint64 `json:"electricity_cost_micro_usd_per_kwh"`
	// PoWBaselineWastedRatioMilli x1000 is the fraction of equivalent-security
	// proof-of-work energy that yields no useful output (1000 = 100%). Used only
	// for the clearly-labeled "energy saved vs PoW" comparison.
	PoWBaselineWastedRatioMilli uint64 `json:"pow_baseline_wasted_ratio_milli"`
}

// DefaultEnergyParams returns documented, UAE-representative defaults that match
// the core router's EnergyModel.
func DefaultEnergyParams() EnergyParams {
	return EnergyParams{
		PueMilli:                      1200,  // 1.2
		GridCarbonGramsPerKWh:         400,   // 0.40 kg/kWh
		ElectricityCostMicroUSDPerKWh: 80000, // $0.08/kWh
		PoWBaselineWastedRatioMilli:   1000,  // 1.0
	}
}

// Validate rejects parameters that would make the accounting meaningless.
func (p EnergyParams) Validate() error {
	if p.PueMilli < 1000 {
		// PUE < 1.0 is physically impossible (facility >= IT power).
		return fmt.Errorf("pue_milli must be >= 1000 (PUE >= 1.0), got %d", p.PueMilli)
	}
	if p.ElectricityCostMicroUSDPerKWh == 0 {
		return fmt.Errorf("electricity_cost_micro_usd_per_kwh must be > 0")
	}
	if p.GridCarbonGramsPerKWh == 0 {
		return fmt.Errorf("grid_carbon_grams_per_kwh must be > 0")
	}
	return nil
}

// WorkReceipt is a validator's measured energy/cost record for one compute job.
type WorkReceipt struct {
	// JobID is the compute job this receipt accounts for.
	JobID string `json:"job_id"`
	// Validator is the operator address that performed the work.
	Validator string `json:"validator"`
	// DeviceClass identifies the accelerator (e.g. "nvidia-h100").
	DeviceClass string `json:"device_class"`
	// DeviceMilliseconds is device-time consumed: wall-clock ms x active
	// accelerators.
	DeviceMilliseconds uint64 `json:"device_milliseconds"`
	// AvgPowerMilliwatts is the average accelerator power draw during execution.
	AvgPowerMilliwatts uint64 `json:"avg_power_milliwatts"`
	// Basis records whether AvgPowerMilliwatts is a live reading or an estimate.
	Basis EnergyBasis `json:"basis"`
	// UsefulWorkUnits is the UWU credited for this job (matches the job record).
	UsefulWorkUnits uint64 `json:"useful_work_units"`
}

// Validate enforces the invariants a receipt must satisfy before it is trusted.
func (r WorkReceipt) Validate() error {
	if r.JobID == "" {
		return fmt.Errorf("work receipt: job_id is required")
	}
	if r.Validator == "" {
		return fmt.Errorf("work receipt: validator is required")
	}
	if r.DeviceClass == "" {
		return fmt.Errorf("work receipt: device_class is required")
	}
	if !r.Basis.Valid() {
		return fmt.Errorf("work receipt: invalid energy basis %q", r.Basis)
	}
	if r.DeviceMilliseconds == 0 {
		return fmt.Errorf("work receipt: device_milliseconds must be > 0")
	}
	if r.AvgPowerMilliwatts == 0 {
		return fmt.Errorf("work receipt: avg_power_milliwatts must be > 0")
	}
	return nil
}

// DeviceMicrojoules is energy at the accelerator: mW x ms = uJ exactly.
func (r WorkReceipt) DeviceMicrojoules() sdkmath.Int {
	return sdkmath.NewIntFromUint64(r.AvgPowerMilliwatts).Mul(sdkmath.NewIntFromUint64(r.DeviceMilliseconds))
}

// FacilityMicrojoules applies PUE to include cooling and delivery overhead.
func (r WorkReceipt) FacilityMicrojoules(p EnergyParams) sdkmath.Int {
	return r.DeviceMicrojoules().Mul(sdkmath.NewIntFromUint64(p.PueMilli)).QuoRaw(1000)
}

// CostMicroUSD is the delivered electricity cost of this job, in micro-USD.
func (r WorkReceipt) CostMicroUSD(p EnergyParams) sdkmath.Int {
	return r.FacilityMicrojoules(p).
		Mul(sdkmath.NewIntFromUint64(p.ElectricityCostMicroUSDPerKWh)).
		Quo(microjoulesPerKWh)
}

// CarbonMilligrams is the carbon footprint of this job, in milligrams CO2e.
// facility_kWh x grams/kWh x 1000 mg/g, folded into one integer division.
func (r WorkReceipt) CarbonMilligrams(p EnergyParams) sdkmath.Int {
	return r.FacilityMicrojoules(p).
		Mul(sdkmath.NewIntFromUint64(p.GridCarbonGramsPerKWh)).
		MulRaw(1000).
		Quo(microjoulesPerKWh)
}

// PoWEquivalentWasteMicrojoules is the facility energy an equivalent-security
// PoW chain would burn on useless hashing for the same useful output. A
// clearly-labeled comparison, not a measurement.
func (r WorkReceipt) PoWEquivalentWasteMicrojoules(p EnergyParams) sdkmath.Int {
	return r.FacilityMicrojoules(p).Mul(sdkmath.NewIntFromUint64(p.PoWBaselineWastedRatioMilli)).QuoRaw(1000)
}

// CanonicalBytes is a deterministic, length-prefixed encoding of the receipt for
// hashing. Field order and framing are fixed so every validator derives the same
// bytes regardless of map ordering or JSON whitespace.
func (r WorkReceipt) CanonicalBytes() []byte {
	var out []byte
	appendField := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	appendU64 := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		out = append(out, n[:]...)
	}
	appendField([]byte(r.JobID))
	appendField([]byte(r.Validator))
	appendField([]byte(r.DeviceClass))
	appendU64(r.DeviceMilliseconds)
	appendU64(r.AvgPowerMilliwatts)
	appendField([]byte(r.Basis))
	appendU64(r.UsefulWorkUnits)
	return out
}

// Hash binds the receipt to the Digital Seal: a 32-byte SHA-256 commitment that
// makes the measured energy/cost as tamper-evident as the job's IO.
func (r WorkReceipt) Hash() []byte {
	sum := sha256.Sum256(r.CanonicalBytes())
	return sum[:]
}
