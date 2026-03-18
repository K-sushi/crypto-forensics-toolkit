#!/usr/bin/env python3
"""Lean entrypoint for report structure extraction + contract validation."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Run strict CI mode (require baseline + strict case coverage).",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Overwrite drift baseline with current metrics.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts/structured_reports",
    )
    parser.add_argument(
        "--summary-path",
        default="artifacts/feature_summary.json",
    )
    parser.add_argument(
        "--baseline-path",
        default="artifacts/structure_baseline.json",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
    )
    parser.add_argument(
        "--manifest-path",
        default="artifacts/current_state_manifest.json",
    )
    parser.add_argument(
        "--snapshot-path",
        default="artifacts/current_state_snapshot.json",
    )
    parser.add_argument(
        "--lead-packets-dir",
        default="artifacts/lead_packets",
    )
    parser.add_argument(
        "--dossier-dir",
        default="artifacts/case_dossiers",
    )
    return parser.parse_args()


def run_cmd(cmd: list[str]) -> None:
    result = subprocess.run([sys.executable] + cmd, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> None:
    args = parse_args()

    print("[1/6] Compile scripts")
    run_cmd(
        [
            "-m",
            "py_compile",
            "scripts/render_reports_html.py",
            "scripts/report_structure_miner.py",
            "scripts/build_current_state_manifest.py",
            "scripts/hydrate_current_state_manifest.py",
            "scripts/build_lead_packets.py",
            "scripts/build_case_dossiers.py",
            "scripts/reconcile_operational_scores.py",
            "scripts/validate_structure_contract.py",
        ]
    )

    print("[2/6] Render HTML reports")
    run_cmd(["scripts/render_reports_html.py", "--reports-dir", str(args.reports_dir)])

    print("[3/6] Build structured artifacts")
    run_cmd(
        [
            "scripts/report_structure_miner.py",
            "--reports-dir",
            str(args.reports_dir),
            "--out-dir",
            str(args.artifacts_dir),
            "--compare-out",
            str(args.summary_path),
        ]
    )

    print("[4/6] Build current-state manifest")
    run_cmd(
        [
            "scripts/build_current_state_manifest.py",
            "--artifacts-dir",
            str(args.artifacts_dir),
            "--out-path",
            str(args.manifest_path),
        ]
    )

    print("[5/6] Hydrate snapshot")
    run_cmd(
        [
            "scripts/hydrate_current_state_manifest.py",
            "--manifest-path",
            str(args.manifest_path),
            "--artifacts-dir",
            str(args.artifacts_dir),
            "--out-path",
            str(args.snapshot_path),
        ]
    )

    print("[6/8] Build case dossiers")
    run_cmd(
        [
            "scripts/build_case_dossiers.py",
            "--artifacts-dir",
            str(args.artifacts_dir),
            "--snapshot-path",
            str(args.snapshot_path),
            "--lead-packets-dir",
            str(args.lead_packets_dir),
            "--reanalysis-dir",
            str(Path(args.artifacts_dir).parent / "reanalysis_reports"),
            "--out-dir",
            str(args.dossier_dir),
        ]
    )

    print("[7/8] Reconcile operational scores")
    run_cmd(
        [
            "scripts/reconcile_operational_scores.py",
            "--artifacts-dir",
            str(args.artifacts_dir),
            "--summary-path",
            str(args.summary_path),
            "--snapshot-path",
            str(args.snapshot_path),
            "--lead-packets-dir",
            str(args.lead_packets_dir),
            "--reanalysis-dir",
            str(Path(args.artifacts_dir).parent / "reanalysis_reports"),
            "--dossier-dir",
            str(args.dossier_dir),
        ]
    )

    print("[8/8] Build lead packets")
    run_cmd(
        [
            "scripts/build_lead_packets.py",
            "--snapshot-path",
            str(args.snapshot_path),
            "--summary-path",
            str(args.summary_path),
            "--out-dir",
            str(args.lead_packets_dir),
        ]
    )

    print("[8/6] Validate contract and drift")
    cmd = [
        "scripts/validate_structure_contract.py",
        "--artifacts-dir",
        str(args.artifacts_dir),
        "--summary-path",
        str(args.summary_path),
        "--baseline-path",
        str(args.baseline_path),
    ]
    if args.update_baseline:
        cmd.append("--update-baseline")
    if args.ci:
        cmd.extend(["--require-baseline", "--strict-case-coverage"])

    run_cmd(cmd)
    print("[PASS] structured contract pipeline complete")


if __name__ == "__main__":
    main()
