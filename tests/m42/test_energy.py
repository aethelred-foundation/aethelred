"""Pilot energy accounting: integer math + receipt hash must match the chain."""

from __future__ import annotations

import m42_energy as e


def _kwh_measurement():
    # 1000 W for 1 hour = exactly 1 kWh at the device.
    return {"device_class": "cpu-rapl", "device_milliseconds": 3_600_000,
            "avg_power_milliwatts": 1_000_000, "basis": e.BASIS_MEASURED}


def test_integer_energy_math_matches_chain():
    m = _kwh_measurement()
    # facility = 1 kWh device x 1.2 PUE = 4.32e12 uJ.
    assert e.facility_microjoules(m) == 4_320_000_000_000
    # cost = 1.2 kWh x $0.08 = $0.096 = 96000 micro-USD.
    assert e.cost_micro_usd(m) == 96_000
    # carbon = 1.2 kWh x 400 g/kWh = 480 g = 480000 mg.
    assert e.carbon_milligrams(m) == 480_000


def test_receipt_hash_matches_go_encoding():
    # This hex is produced by the Go x/pouw/types WorkReceipt.Hash() for the same
    # fields (verified cross-language). If the canonical encoding drifts on either
    # side, a pilot receipt stops verifying against the chain — so pin it.
    receipt = {"job_id": "job-1", "validator": "val-1", "device_class": "cpu-rapl",
               "device_milliseconds": 1000, "avg_power_milliwatts": 90000,
               "basis": "measured", "useful_work_units": 500}
    assert e.receipt_hash(receipt) == "226df0dd10d2658cb873b2b86e5e3b0fdc350e2e5d07fe6a513e177b3be84189"


def test_receipt_hash_is_sensitive_to_every_field():
    base = {"job_id": "j", "validator": "v", "device_class": "cpu-rapl",
            "device_milliseconds": 1, "avg_power_milliwatts": 1,
            "basis": "measured", "useful_work_units": 1}
    h0 = e.receipt_hash(base)
    for key, val in [("job_id", "j2"), ("validator", "v2"), ("device_class", "gpu"),
                     ("device_milliseconds", 2), ("avg_power_milliwatts", 2),
                     ("basis", "device_profile_estimate"), ("useful_work_units", 2)]:
        mutated = dict(base, **{key: val})
        assert e.receipt_hash(mutated) != h0, f"hash insensitive to {key}"


def test_measure_offline_is_device_profile_estimate():
    # No RAPL on the test host -> honest estimate label, real wall-clock.
    result, m = e.measure(lambda: sum(range(10000)), "nvidia-h100")
    assert result == sum(range(10000))
    assert m["basis"] == e.BASIS_DEVICE_PROFILE
    assert m["device_class"] == "nvidia-h100"
    assert m["device_milliseconds"] >= 1
    # 700 W x 0.6 utilization = 420 W = 420000 mW.
    assert m["avg_power_milliwatts"] == 420_000


def test_projected_measurement_is_labeled_estimate():
    # 760 ms/inference x 10000 on an A100.
    m = e.projected_measurement("nvidia-a100", 760 * 10000)
    assert m["basis"] == e.BASIS_DEVICE_PROFILE
    assert m["device_milliseconds"] == 7_600_000
    assert m["avg_power_milliwatts"] == 240_000  # 400 W x 0.6


def test_energy_report_normalizes_per_inference():
    receipt = e.build_receipt("job", "val", e.projected_measurement("nvidia-a100", 760 * 10000), 10000)
    report = e.energy_report(receipt, inferences=10000)
    assert report["facility_energy_kwh"] > 0
    assert report["energy_wh_per_1k_inferences"] > 0
    assert report["cost_micro_usd_per_inference"] > 0
    assert report["receipt_hash"] == receipt["receipt_hash"]
    assert report["basis"] == e.BASIS_DEVICE_PROFILE


def test_unknown_device_falls_back_to_cpu_profile():
    m = e.projected_measurement("quantum-toaster", 1000)
    assert m["device_class"] == "cpu-generic"
    assert m["avg_power_milliwatts"] == 90_000  # 150 W x 0.6
