"""The adversarial matrix must reject every attack (SOW tamper-resistance gate)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "m42-adversarial.py"


def test_all_attacks_rejected():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, f"an attack was accepted:\n{result.stdout}"
    assert "12/12 attacks rejected" in result.stdout
    # A single accepted attack would print the failure marker.
    assert "** FAIL **" not in result.stdout
