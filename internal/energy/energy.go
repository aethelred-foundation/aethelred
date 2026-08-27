// Package energy measures the electrical energy a worker spends on a unit of
// compute, so PoUW's "every watt is useful" claim rests on real readings rather
// than assertions. It reads Linux RAPL where available (basis "measured") and
// otherwise falls back to a documented device power profile (basis
// "device_profile_estimate"), mirroring the on-chain EnergyBasis honesty label.
//
// The metadata keys and basis strings here are duplicated from x/pouw/types to
// keep this low-level package free of the Cosmos SDK dependency; a test
// (energy_chain_test.go) asserts they stay in lockstep with the chain.
package energy

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Energy basis labels (must match x/pouw/types.EnergyBasis*).
const (
	BasisMeasured       = "measured"
	BasisDeviceProfile  = "device_profile_estimate"
	MetaKeyDeviceClass  = "energy.device_class"
	MetaKeyDeviceMs     = "energy.device_ms"
	MetaKeyAvgPowerMw   = "energy.avg_power_mw"
	MetaKeyBasis        = "energy.basis"
	raplEnergyPath      = "/sys/class/powercap/intel-rapl:0/energy_uj"
	defaultUtilization  = 600 // per-mille of TDP assumed during active compute
	microjoulesPerMilli = 1   // uJ / ms == mW (1e-6 J / 1e-3 s = 1e-3 W)
)

// deviceProfiles maps a device class to its rated TDP in watts, used to
// estimate average power when no live meter is available.
var deviceProfiles = map[string]uint64{
	"cpu-generic": 150,
	"nvidia-h100": 700,
	"nvidia-a100": 400,
	"nvidia-l4":   72,
}

// Measurement is the measured energy for one execution.
type Measurement struct {
	DeviceClass        string
	DeviceMilliseconds uint64
	AvgPowerMilliwatts uint64
	Basis              string
}

// MetadataMap renders the measurement as the canonical energy.* job-metadata
// keys the keeper consumes. Returns nil for a zero measurement so a failed
// reading never injects garbage that the chain would have to reject.
func (m Measurement) MetadataMap() map[string]string {
	if m.DeviceClass == "" || m.DeviceMilliseconds == 0 || m.AvgPowerMilliwatts == 0 {
		return nil
	}
	return map[string]string{
		MetaKeyDeviceClass: m.DeviceClass,
		MetaKeyDeviceMs:    strconv.FormatUint(m.DeviceMilliseconds, 10),
		MetaKeyAvgPowerMw:  strconv.FormatUint(m.AvgPowerMilliwatts, 10),
		MetaKeyBasis:       m.Basis,
	}
}

// Meter measures energy around a unit of work for a declared device class.
type Meter struct {
	deviceClass      string
	tdpWatts         uint64
	utilizationMilli uint64
	raplPath         string // overridable for tests
}

// NewMeter builds a meter for the given device class. Unknown classes fall back
// to a generic CPU profile.
func NewMeter(deviceClass string) *Meter {
	tdp, ok := deviceProfiles[deviceClass]
	if !ok {
		deviceClass, tdp = "cpu-generic", deviceProfiles["cpu-generic"]
	}
	return &Meter{
		deviceClass:      deviceClass,
		tdpWatts:         tdp,
		utilizationMilli: defaultUtilization,
		raplPath:         raplEnergyPath,
	}
}

// Measure runs fn and returns the measured energy. It prefers a live RAPL
// reading for CPU work and otherwise falls back to the device power profile.
func (m *Meter) Measure(fn func()) Measurement {
	isCPU := strings.HasPrefix(m.deviceClass, "cpu")
	startUJ, raplOK := m.readRAPL()

	start := time.Now()
	fn()
	ms := uint64(time.Since(start).Milliseconds())
	if ms == 0 {
		ms = 1 // a sub-millisecond job still draws power; floor at 1ms
	}

	if isCPU && raplOK {
		// uJ delta over ms gives average power in mW directly.
		if endUJ, ok := m.readRAPL(); ok && endUJ >= startUJ {
			if avgMw := (endUJ - startUJ) / ms * microjoulesPerMilli; avgMw > 0 {
				return Measurement{
					DeviceClass:        "cpu-rapl",
					DeviceMilliseconds: ms,
					AvgPowerMilliwatts: avgMw,
					Basis:              BasisMeasured,
				}
			}
		}
	}

	// Device-profile estimate: average power = TDP x assumed utilization.
	avgMw := m.tdpWatts * 1000 * m.utilizationMilli / 1000
	return Measurement{
		DeviceClass:        m.deviceClass,
		DeviceMilliseconds: ms,
		AvgPowerMilliwatts: avgMw,
		Basis:              BasisDeviceProfile,
	}
}

// readRAPL returns the cumulative package energy counter in microjoules, or
// ok=false if RAPL is unavailable (e.g. non-Linux, or no permission).
func (m *Meter) readRAPL() (uint64, bool) {
	raw, err := os.ReadFile(m.raplPath)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
