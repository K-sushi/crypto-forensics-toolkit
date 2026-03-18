from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _write_report(path: Path, case_dir: str) -> None:
    payload = {
        "case_count": 1,
        "status_counts": {"OK": 1, "WARN": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0},
        "results": [
            {
                "case_dir": case_dir,
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "event_count": 1,
                "analysis_score": 1.0,
                "signals": [{"name": "a", "value": 1}],
                "analysis_status": "ok",
                "analysis_path": "analysis.json",
                "signal_count": 1,
                "status": "SKIP",
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


@pytest.mark.parametrize(
    "base_path,current_path",
    [
        ("C:\\\\Users\\\\hkmen\\\\crypto-forensics-toolkit\\\\artifacts\\\\osint_runs\\\\abra_reanalysis_20260318", "artifacts/osint_runs/abra_reanalysis_20260318"),
        (
            "/tmp/artifacts/osint_runs/abr_reanalysis_20260318",
            "/home/user/artifacts/osint_runs/abr_reanalysis_20260318",
        ),
        ("case_dir", "case_dir"),
        ("C:/Users/hkmen/crypto-forensics-toolkit/artifacts/osint_runs/abr", "C:\\\\Users\\\\hkmen\\\\artifacts\\\\osint_runs\\\\abr"),
        ("", "case_dir"),
        ("case_dir", ""),
        ("./case_dir", "./case_dir"),
        ("case_dir/", "./case_dir/"),
        ("  case_dir  ", "  case_dir  "),
    ],
)
def test_compare_handles_windows_and_posix_case_paths(tmp_path: Path, base_path: str, current_path: str):
    repo_root = Path(__file__).resolve().parent
    base = tmp_path / "base.json"
    current = tmp_path / "current.json"
    _write_report(base, base_path)
    _write_report(current, current_path)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/compare_reanalysis_reports.py",
            "--base-report",
            str(base),
            "--current-report",
            str(current),
            "--out-report",
            str(tmp_path / "drift.json"),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )

    if base_path.strip() and current_path.strip():
        assert result.returncode == 0
        payload = json.loads((tmp_path / "drift.json").read_text(encoding="utf-8"))
        assert payload["drift_count"] == 0
        assert payload["case_count"] == 1
    else:
        assert result.returncode != 0
