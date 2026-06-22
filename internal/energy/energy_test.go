package energy

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestMeasureDeviceProfileEstimate(t *testing.T) {
	m := NewMeter("nvidia-h100")
	got := m.Measure(func() {})
	if got.Basis != BasisDeviceProfile {
		t.Fatalf("GPU without a live meter must be an estimate, got %s", got.Basis)
	}
	if got.DeviceClass != "nvidia-h100" {
		t.Fatalf("device class: got %s", got.DeviceClass)
	}
	// 700 W x 0.6 utilization = 420 W = 420000 mW.
	if got.AvgPowerMilliwatts != 420000 {
		t.Fatalf("avg power: got %d, want 420000", got.AvgPowerMilliwatts)
	}
	if got.DeviceMilliseconds < 1 {
		t.Fatal("device ms must be floored to >= 1")
	}
}

func TestUnknownDeviceFallsBackToCPUProfile(t *testing.T) {
	m := NewMeter("quantum-toaster")
	if m.deviceClass != "cpu-generic" {
		t.Fatalf("unknown class must fall back to cpu-generic, got %s", m.deviceClass)
	}
	// Force the estimate path by pointing RAPL at a missing file.
	m.raplPath = filepath.Join(t.TempDir(), "absent")
	got := m.Measure(func() {})
	if got.Basis != BasisDeviceProfile {
		t.Fatalf("want estimate, got %s", got.Basis)
	}
	// 150 W x 0.6 = 90 W = 90000 mW.
	if got.AvgPowerMilliwatts != 90000 {
		t.Fatalf("avg power: got %d, want 90000", got.AvgPowerMilliwatts)
	}
}

func TestMeasureRAPLMeasuredPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "energy_uj")
	if err := os.WriteFile(path, []byte("1000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewMeter("cpu-generic")
	m.raplPath = path

	const delta = uint64(90000)
	got := m.Measure(func() {
		// Simulate energy accumulating during the work.
		_ = os.WriteFile(path, []byte(strconv.FormatUint(1000000+delta, 10)), 0o644)
	})

	if got.Basis != BasisMeasured {
		t.Fatalf("RAPL present must be measured, got %s", got.Basis)
	}
	if got.DeviceClass != "cpu-rapl" {
		t.Fatalf("measured CPU must report cpu-rapl, got %s", got.DeviceClass)
	}
	if got.DeviceMilliseconds < 1 {
		t.Fatal("device ms must be floored to >= 1")
	}
	// Average power is the energy delta divided by the same elapsed ms.
	if want := delta / got.DeviceMilliseconds; got.AvgPowerMilliwatts != want {
		t.Fatalf("avg power: got %d, want %d (delta %d / %d ms)", got.AvgPowerMilliwatts, want, delta, got.DeviceMilliseconds)
	}
}

func TestRAPLIgnoredForGPUClass(t *testing.T) {
	// A GPU meter must not attribute CPU RAPL energy to the GPU.
	path := filepath.Join(t.TempDir(), "energy_uj")
	_ = os.WriteFile(path, []byte("1000000"), 0o644)
	m := NewMeter("nvidia-a100")
	m.raplPath = path
	got := m.Measure(func() {
		_ = os.WriteFile(path, []byte("9999999"), 0o644)
	})
	if got.Basis != BasisDeviceProfile {
		t.Fatalf("GPU must not use CPU RAPL, got %s", got.Basis)
	}
}

func TestMetadataMap(t *testing.T) {
	m := Measurement{DeviceClass: "cpu-rapl", DeviceMilliseconds: 5, AvgPowerMilliwatts: 90000, Basis: BasisMeasured}
	md := m.MetadataMap()
	if md[MetaKeyDeviceClass] != "cpu-rapl" || md[MetaKeyDeviceMs] != "5" ||
		md[MetaKeyAvgPowerMw] != "90000" || md[MetaKeyBasis] != BasisMeasured {
		t.Fatalf("metadata map wrong: %v", md)
	}
	// A zero/empty measurement must produce no metadata (never inject garbage).
	if (Measurement{}).MetadataMap() != nil {
		t.Fatal("empty measurement must map to nil")
	}
}
