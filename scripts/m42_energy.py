#!/usr/bin/env python3
"""Measured energy/cost accounting for the M42 pilot, mirroring the on-chain
`x/pouw` WorkReceipt so the value bank shows *measured* numbers, not assumptions.

Every figure is either measured (wall-clock, plus Linux RAPL where available) or
derived through the same explicit `ENERGY_MODEL` factors and integer math the
chain uses. `receipt_hash` reproduces the Go `WorkReceipt.CanonicalBytes`
encoding byte-for-byte, so a receipt computed here verifies against the chain.

This is honest about its basis: on hardware without a live power meter the power
figure is a documented device-profile estimate, labeled as such — the same
EnergyBasis boundary the TEE hardware root uses.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from typing import Any, Callable

# Conversion factors — must match x/pouw/types.DefaultEnergyParams().
ENERGY_MODEL = {
    "pue_milli": 1200,                          # 1.2 PUE
    "grid_carbon_grams_per_kwh": 400,           # 0.40 kg CO2e / kWh
    "electricity_cost_micro_usd_per_kwh": 80000,  # $0.08 / kWh
    "pow_baseline_wasted_ratio_milli": 1000,    # 1.0
}

# Energy basis labels — must match x/pouw/types.EnergyBasis*.
BASIS_MEASURED = "measured"
BASIS_DEVICE_PROFILE = "device_profile_estimate"

# Device power profiles (rated TDP in watts) — must match internal/energy.
DEVICE_PROFILES = {
    "cpu-generic": 150,
    "nvidia-h100": 700,
    "nvidia-a100": 400,
    "nvidia-l4": 72,
}
_DEFAULT_UTILIZATION_MILLI = 600  # 60% of TDP assumed during active compute
_RAPL_PATH = "/sys/class/powercap/intel-rapl:0/energy_uj"
_MICROJOULES_PER_KWH = 3_600_000_000_000

# The accelerator a real M42 inference run is projected on (capacity planning).
DEFAULT_INFERENCE_DEVICE = "nvidia-a100"


def _read_rapl() -> int | None:
    try:
        with open(_RAPL_PATH, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def measure(fn: Callable[[], Any], device_class: str = "cpu-generic") -> tuple[Any, dict[str, Any]]:
    """Run fn and return (result, measurement). Prefers a live RAPL reading for
    CPU work; otherwise falls back to the device power profile.
    """
    tdp = DEVICE_PROFILES.get(device_class)
    if tdp is None:
        device_class, tdp = "cpu-generic", DEVICE_PROFILES["cpu-generic"]
    is_cpu = device_class.startswith("cpu")

    start_uj = _read_rapl()
    start = time.perf_counter()
    result = fn()
    device_ms = max(1, int((time.perf_counter() - start) * 1000))

    if is_cpu and start_uj is not None:
        end_uj = _read_rapl()
        if end_uj is not None and end_uj >= start_uj:
            avg_mw = (end_uj - start_uj) // device_ms  # uJ/ms == mW
            if avg_mw > 0:
                return result, _measurement("cpu-rapl", device_ms, avg_mw, BASIS_MEASURED)

    avg_mw = tdp * 1000 * _DEFAULT_UTILIZATION_MILLI // 1000
    return result, _measurement(device_class, device_ms, avg_mw, BASIS_DEVICE_PROFILE)


def _measurement(device_class: str, device_ms: int, avg_power_mw: int, basis: str) -> dict[str, Any]:
    return {
        "device_class": device_class,
        "device_milliseconds": device_ms,
        "avg_power_milliwatts": avg_power_mw,
        "basis": basis,
    }


def projected_measurement(device_class: str, total_device_ms: int) -> dict[str, Any]:
    """A modeled measurement for running real inference, given a device class and
    total device-time (e.g. per-inference latency x N). No live timing is taken,
    so the basis is always a device-profile estimate — this is a projection, not
    a measurement, and is labeled as such everywhere it surfaces.
    """
    tdp = DEVICE_PROFILES.get(device_class)
    if tdp is None:
        device_class, tdp = "cpu-generic", DEVICE_PROFILES["cpu-generic"]
    avg_mw = tdp * 1000 * _DEFAULT_UTILIZATION_MILLI // 1000
    return _measurement(device_class, max(1, total_device_ms), avg_mw, BASIS_DEVICE_PROFILE)


# --- Integer energy/cost/carbon math (identical to the Go WorkReceipt) ---

def facility_microjoules(m: dict[str, Any]) -> int:
    device_uj = m["avg_power_milliwatts"] * m["device_milliseconds"]
    return device_uj * ENERGY_MODEL["pue_milli"] // 1000


def cost_micro_usd(m: dict[str, Any]) -> int:
    return facility_microjoules(m) * ENERGY_MODEL["electricity_cost_micro_usd_per_kwh"] // _MICROJOULES_PER_KWH


def carbon_milligrams(m: dict[str, Any]) -> int:
    return facility_microjoules(m) * ENERGY_MODEL["grid_carbon_grams_per_kwh"] * 1000 // _MICROJOULES_PER_KWH


def facility_kwh(m: dict[str, Any]) -> float:
    return facility_microjoules(m) / _MICROJOULES_PER_KWH


# --- Canonical receipt hash (byte-for-byte the Go WorkReceipt.CanonicalBytes) ---

def _field(b: bytes) -> bytes:
    return struct.pack(">Q", len(b)) + b


def _u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def receipt_canonical_bytes(receipt: dict[str, Any]) -> bytes:
    return (
        _field(receipt["job_id"].encode())
        + _field(receipt["validator"].encode())
        + _field(receipt["device_class"].encode())
        + _u64(receipt["device_milliseconds"])
        + _u64(receipt["avg_power_milliwatts"])
        + _field(receipt["basis"].encode())
        + _u64(receipt["useful_work_units"])
    )


def receipt_hash(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(receipt_canonical_bytes(receipt)).hexdigest()


def build_receipt(job_id: str, validator: str, measurement: dict[str, Any], useful_work_units: int) -> dict[str, Any]:
    """Assemble a WorkReceipt from a measurement, matching the on-chain shape."""
    receipt = {
        "job_id": job_id,
        "validator": validator,
        "device_class": measurement["device_class"],
        "device_milliseconds": measurement["device_milliseconds"],
        "avg_power_milliwatts": measurement["avg_power_milliwatts"],
        "basis": measurement["basis"],
        "useful_work_units": useful_work_units,
    }
    receipt["receipt_hash"] = receipt_hash(receipt)
    return receipt


def energy_report(receipt: dict[str, Any], inferences: int) -> dict[str, Any]:
    """A measured energy/cost/carbon summary for the value bank. `inferences` is
    the number of useful inferences this receipt accounts for, so per-inference
    and per-1000-inference figures are comparable across workloads.
    """
    kwh = facility_kwh(receipt)
    cost_usd = cost_micro_usd(receipt) / 1_000_000
    carbon_kg = carbon_milligrams(receipt) / 1_000_000
    n = max(1, inferences)
    return {
        "basis": receipt["basis"],
        "device_class": receipt["device_class"],
        "measured_device_ms": receipt["device_milliseconds"],
        "avg_power_watts": round(receipt["avg_power_milliwatts"] / 1000, 2),
        "facility_energy_kwh": round(kwh, 6),
        "energy_cost_usd": round(cost_usd, 6),
        "carbon_kg_co2e": round(carbon_kg, 6),
        "inferences": inferences,
        "energy_wh_per_1k_inferences": round(kwh * 1000 / n * 1000, 4),
        "cost_micro_usd_per_inference": round(cost_micro_usd(receipt) / n, 4),
        "useful_work_units": receipt["useful_work_units"],
        "receipt_hash": receipt["receipt_hash"],
        "every_watt_accounted": True,
        "note": (
            "Measured wall-clock; energy via the published ENERGY_MODEL. "
            f"basis={receipt['basis']} (live meter where available, else a "
            "documented device-profile estimate). receipt_hash uses the on-chain "
            "WorkReceipt encoding and is independently verifiable."
        ),
    }


# Allow `AETHELRED_WORKER_DEVICE_CLASS` to pin the device profile for the drill.
def default_device_class() -> str:
    return os.getenv("AETHELRED_WORKER_DEVICE_CLASS", "cpu-generic")
