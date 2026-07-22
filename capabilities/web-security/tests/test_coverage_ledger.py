from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[1]
    / "skills"
    / "initial-recon"
    / "scripts"
    / "write_coverage_ledger.py"
)


def test_writes_measured_phase(tmp_path: Path) -> None:
    output = tmp_path / "coverage.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--output",
            str(output),
            "--scope",
            "192.0.2.0/24",
            "--phase",
            "port-scan",
            "--tool",
            "naabu",
            "--status",
            "completed",
            "--targets-scheduled",
            "256",
            "--targets-completed",
            "256",
            "--ports-scheduled",
            "7",
            "--responsive-hosts",
            "12",
            "--artifact",
            "naabu.jsonl",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    ledger = json.loads(output.read_text())
    phase = ledger["phases"][0]
    assert ledger["schema_version"] == "web-security-coverage-v1"
    assert phase["address_port_checks"] == 1792
    assert phase["responsive_hosts"] == 12


def test_rejects_completed_count_above_scheduled(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--output",
            str(tmp_path / "coverage.json"),
            "--scope",
            "example.com",
            "--phase",
            "http-probe",
            "--tool",
            "httpx",
            "--status",
            "partial",
            "--targets-scheduled",
            "2",
            "--targets-completed",
            "3",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "cannot exceed" in result.stderr


def test_appends_only_when_scope_matches(tmp_path: Path) -> None:
    output = tmp_path / "coverage.json"
    base = [
        sys.executable,
        str(SCRIPT),
        "--output",
        str(output),
        "--scope",
        "example.com",
        "--phase",
        "passive",
        "--tool",
        "subfinder",
        "--status",
        "completed",
    ]
    assert subprocess.run(base, check=False).returncode == 0
    mismatch = base.copy()
    mismatch[mismatch.index("example.com")] = "example.org"

    result = subprocess.run(mismatch, text=True, capture_output=True, check=False)

    assert result.returncode != 0
    assert "scope does not match" in result.stderr
