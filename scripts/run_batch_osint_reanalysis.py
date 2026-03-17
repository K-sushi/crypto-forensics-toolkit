#!/usr/bin/env python3
"""Batch runner for offline OSINT reanalysis passes."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--osint-runs-dir",
        default=str(project_root() / "artifacts" / "osint_runs"),
        help="Directory containing per-case OSINT run directories.",
    )
    parser.add_argument(
        "--case-dir",
        action="append",
        default=[],
        help="Specific case directory (repeatable). If omitted, all eligible cases are processed.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter for invoking the runner.",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="API key forwarded to run_osint_reanalysis for repair runs.",
    )
    parser.add_argument(
        "--out-report",
        default=str(project_root() / "artifacts" / "osint_runs" / "batch_reanalysis_report.json"),
        help="Path to write batch execution summary.",
    )
    parser.add_argument(
        "--score-threshold",
        type=float,
        default=None,
        help="Fail cases with analysis_score below this value.",
    )
    parser.add_argument(
        "--min-signals",
        type=int,
        default=None,
        help="Fail cases with fewer than this many analysis signals.",
    )
    parser.add_argument(
        "--fail-on-under-threshold",
        action="store_true",
        help="Enable fail on any case below --score-threshold.",
    )
    parser.add_argument(
        "--fail-on-low-signals",
        action="store_true",
        help="Enable fail on any case with fewer than --min-signals.",
    )
    parser.add_argument(
        "--auto-repair-missing-events",
        action="store_true",
        help="Re-run collection+analysis for cases missing collected events and having report_path in manifest.",
    )
    parser.add_argument(
        "--smart",
        action="store_true",
        help="Skip reprocessing when manifest analysis is already fresh against collected_events.",
    )
    parser.add_argument(
        "--force-reprocess",
        action="store_true",
        help="Ignore smart-skip and rerun all selected cases.",
    )
    return parser.parse_args()


def load_manifest(case_dir: Path) -> Optional[Dict[str, Any]]:
    manifest_path = case_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None


def manifest_events_path(
    case_dir: Path, manifest: Optional[Dict[str, Any]]
) -> Tuple[Path, bool]:
    if manifest is None:
        return case_dir / "collected_events.jsonl", False

    events_path_value = str(manifest.get("events_path", "")).strip()
    if events_path_value:
        events_path = Path(events_path_value).expanduser()
        if not events_path.is_absolute():
            events_path = case_dir / events_path
    else:
        events_path = case_dir / "collected_events.jsonl"

    return events_path, events_path.exists()


def has_repair_source(manifest: Optional[Dict[str, Any]], case_dir: Optional[Path] = None) -> Tuple[bool, Path]:
    if manifest is None:
        return False, Path()
    report_path_value = str(manifest.get("report_path", "")).strip()
    if not report_path_value:
        return False, Path()
    report_path = Path(report_path_value).expanduser()
    if not report_path.exists() and case_dir is not None:
        candidate = case_dir / report_path
        if candidate.exists():
            report_path = candidate
    return report_path.exists(), report_path


def manifest_analysis_uptodate(case_dir: Path, manifest: Dict[str, Any], events_path: Path) -> bool:
    analysis = manifest.get("analysis")
    if not isinstance(analysis, dict):
        return False
    if not analysis:
        return False
    analysis_path_value = str(manifest.get("analysis_path", "")).strip()
    if not analysis_path_value:
        return False
    analysis_path = Path(analysis_path_value).expanduser()
    if not analysis_path.is_absolute():
        analysis_path = case_dir / analysis_path
    if not analysis_path.exists():
        return False
    if not events_path.exists():
        return False
    return analysis_path.stat().st_mtime >= events_path.stat().st_mtime


def manifest_to_result(case_dir: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    analysis = manifest.get("analysis", {})
    return {
        "case_dir": str(case_dir),
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "event_count": manifest.get("stats", {}).get("events"),
        "analysis_score": analysis.get("score"),
        "signals": analysis.get("signals", []),
        "analysis_status": analysis.get("analysis_status"),
        "analysis_path": str(manifest.get("analysis_path", "")),
        "skipped": True,
        "skipped_reason": "manifest_analysis_uptodate",
    }


def discover_case_dirs(root: Path, include_no_events: bool = False) -> List[Path]:
    if not root.exists():
        return []
    dirs = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        manifest = load_manifest(entry)
        if manifest is None:
            continue

        _, has_events_file = manifest_events_path(entry, manifest)
        can_repair, _ = has_repair_source(manifest, entry)

        if has_events_file or (include_no_events and can_repair):
            dirs.append(entry)
    return dirs


def run_analysis(python: str, case_dir: Path) -> Dict[str, Any]:
    runner = project_root() / "scripts" / "run_osint_reanalysis.py"
    cmd = [python, str(runner), "--analyze-only", "--case-dir", str(case_dir)]
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    summary: Dict[str, Any] = {
        "case_dir": str(case_dir),
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
    if completed.returncode != 0:
        return summary

    manifest_path = case_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        summary["analysis_score"] = manifest.get("analysis", {}).get("score")
        summary["signals"] = manifest.get("analysis", {}).get("signals", [])
        summary["analysis_status"] = manifest.get("analysis", {}).get("analysis_status")
        summary["event_count"] = manifest.get(
            "stats",
            {},
        ).get("events", manifest.get("analysis", {}).get("event_count"))
    return summary


def run_repair_with_collect(
    python: str,
    case_dir: Path,
    manifest: Dict[str, Any],
    api_key: str,
) -> Dict[str, Any]:
    can_repair, report_path = has_repair_source(manifest, case_dir)
    if not can_repair:
        return {
            "case_dir": str(case_dir),
            "returncode": 20,
            "stdout": "",
            "stderr": "repair skipped; manifest.report_path missing or missing file",
            "repaired": False,
        }

    runner = project_root() / "scripts" / "run_osint_reanalysis.py"
    cmd = [
        python,
        str(runner),
        "--report-path",
        str(report_path),
        "--case-name",
        case_dir.name,
        "--collect",
        "--analyze",
    ]
    if api_key:
        cmd.extend(["--api-key", api_key])

    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    return {
        "case_dir": str(case_dir),
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "repaired": completed.returncode == 0,
    }


def evaluate_status(
    result: Dict[str, Any],
    threshold: Optional[float],
    min_signals: Optional[int],
    enforce_threshold: bool,
    enforce_min_signals: bool,
) -> str:
    if result.get("returncode") != 0:
        return "ERROR"

    score = result.get("analysis_score")
    signals = result.get("signals", [])
    signal_count = len(signals) if isinstance(signals, list) else 0
    result["signal_count"] = signal_count

    status = "OK"
    if threshold is not None:
        try:
            score_value = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_value = None
        if score_value is None:
            if enforce_threshold:
                status = "FAIL"
                result["error"] = f"analysis_score is missing; threshold={threshold}"
                result["returncode"] = 2
            else:
                status = "WARN"
        elif score_value < threshold:
            if enforce_threshold:
                status = "FAIL"
                result["error"] = f"analysis_score {score_value} < threshold {threshold}"
                result["returncode"] = 3
            else:
                status = "WARN"

    if min_signals is not None:
        if signal_count < min_signals:
            if enforce_min_signals:
                status = "FAIL"
                result["error"] = f"signal_count {signal_count} < min_signals {min_signals}"
                result["returncode"] = 4
            else:
                if status == "OK":
                    status = "WARN"

    return status


def main() -> None:
    args = parse_args()
    runs_root = Path(args.osint_runs_dir)
    explicit_case_dirs = [Path(c).expanduser() for c in args.case_dir]

    if explicit_case_dirs:
        case_dirs = []
        for c in explicit_case_dirs:
            if c.is_absolute() and c.exists():
                case_dirs.append(c)
                continue
            if c.exists():
                case_dirs.append(c.resolve())
                continue
            candidate = (runs_root / c).resolve()
            case_dirs.append(candidate)
    else:
        case_dirs = discover_case_dirs(
            runs_root,
            include_no_events=args.auto_repair_missing_events,
        )

    if not case_dirs:
        raise SystemExit(f"No eligible case directories found in {runs_root}")

    print(f"[INFO] processing {len(case_dirs)} case(s)")
    results = []
    threshold = args.score_threshold
    enforce_threshold = args.fail_on_under_threshold
    min_signals = args.min_signals
    enforce_min_signals = args.fail_on_low_signals

    print(
        f"[INFO] gates: score_threshold={threshold}, fail_on_under_threshold={enforce_threshold}, "
        f"min_signals={min_signals}, fail_on_low_signals={enforce_min_signals}"
    )
    for case_dir in case_dirs:
        if not case_dir.exists():
            results.append({"case_dir": str(case_dir), "error": "case dir not found"})
            continue

        manifest = load_manifest(case_dir)
        if manifest is None:
            results.append(
                {
                    "case_dir": str(case_dir),
                    "returncode": 30,
                    "stdout": "",
                    "stderr": "manifest.json is invalid or missing",
                }
            )
            print(f"[WARN] ERROR {case_dir.name}: manifest missing/invalid")
            continue

        events_path, has_events_file = manifest_events_path(case_dir, manifest)
        if (
            args.smart
            and not args.force_reprocess
            and has_events_file
            and manifest_analysis_uptodate(case_dir, manifest, events_path)
        ):
            result = manifest_to_result(case_dir, manifest)
            status = evaluate_status(
                result=result,
                threshold=threshold,
                min_signals=min_signals,
                enforce_threshold=enforce_threshold,
                enforce_min_signals=enforce_min_signals,
            )
            if status == "OK":
                status = "SKIP"
            result["status"] = status
            print(f"[INFO] {status} {case_dir.name}: score={result.get('analysis_score')} (smart)")
            results.append(result)
            continue

        result = run_analysis(args.python, case_dir)
        if result.get("returncode") != 0 and args.auto_repair_missing_events and not has_events_file:
            repair_result = run_repair_with_collect(
                python=args.python,
                case_dir=case_dir,
                manifest=manifest,
                api_key=args.api_key,
            )
            result["repair_attempt"] = repair_result
            if repair_result.get("returncode") == 0:
                result = run_analysis(args.python, case_dir)

        results.append(result)
        status = evaluate_status(
            result=result,
            threshold=threshold,
            min_signals=min_signals,
            enforce_threshold=enforce_threshold,
            enforce_min_signals=enforce_min_signals,
        )
        result["status"] = status
        score = result.get("analysis_score")
        print(f"[INFO] {status} {case_dir.name}: score={score}")

    out_report = Path(args.out_report)
    out_report.parent.mkdir(parents=True, exist_ok=True)
    status_counts = {"OK": 0, "WARN": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}
    for r in results:
        status = r.get("status", "OK")
        if r.get("returncode") != 0:
            status_counts["ERROR"] += 1
            continue
        if status not in status_counts:
            status = "OK"
        status_counts[status] += 1

    out_report.write_text(json.dumps(
        {
            "case_count": len(case_dirs),
            "status_counts": status_counts,
            "results": results,
        },
        ensure_ascii=False,
        indent=2,
    ), encoding="utf-8")

    failures = []
    for r in results:
        if r.get("returncode", 0) != 0:
            failures.append(r)
            continue
        if args.fail_on_under_threshold and threshold is not None:
            score_raw = r.get("analysis_score")
            try:
                score_value = float(score_raw) if score_raw is not None else None
            except (TypeError, ValueError):
                score_value = None
            if score_value is None or score_value < threshold:
                failures.append(r)
        if args.fail_on_low_signals and args.min_signals is not None:
            signal_count = r.get("signal_count", None)
            if signal_count is None:
                signal_count = len(r.get("signals", []) or [])
            if signal_count < min_signals:
                failures.append(r)
    if failures:
        print(f"[WARN] {len(failures)} case(s) failed. See {out_report}")
        raise SystemExit(1)
    print(f"[INFO] batch complete: {out_report}")


if __name__ == "__main__":
    main()
