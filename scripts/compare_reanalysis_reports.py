#!/usr/bin/env python3
"""Compare two OSINT batch reanalysis reports and emit a deterministic drift report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-report", required=True, help="Baseline batch report JSON path.")
    parser.add_argument(
        "--current-report",
        required=True,
        help="Current batch report JSON path.",
    )
    parser.add_argument(
        "--out-report",
        default=str(
            Path("artifacts")
            / "osint_runs"
            / "reanalysis_drift_report.json"
        ),
        help="Path to write drift report JSON.",
    )
    parser.add_argument(
        "--max-event-delta",
        type=float,
        default=0.05,
        help="Allowed relative event count change (0.05 = 5 percent).",
    )
    parser.add_argument(
        "--max-score-delta",
        type=float,
        default=2.0,
        help="Allowed absolute score change.",
    )
    parser.add_argument(
        "--max-signal-delta",
        type=int,
        default=1,
        help="Allowed absolute signal count change.",
    )
    parser.add_argument(
        "--strict-status",
        action="store_true",
        help="Fail on any change in analysis_status.",
    )
    return parser.parse_args()


def load_report(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"report missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def case_index(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    cases = {}
    for result in report.get("results", []):
        case_dir = str(result.get("case_dir", "")).strip()
        if case_dir:
            case_dir = normalize_case_dir(case_dir)
            cases[case_dir] = result
    return cases


def normalize_case_dir(case_dir: str) -> str:
    case_dir = str(case_dir).strip()
    if not case_dir:
        return ""
    normalized = case_dir.replace("\\", "/").strip("/").strip()
    normalized = normalized.strip()
    return Path(normalized).name


def percent_delta(base: Optional[float], current: Optional[float]) -> Optional[float]:
    if base is None or current is None or base == 0:
        return None
    return (current - base) / base


def compare_case(
    case_dir: str,
    base: Optional[Dict[str, Any]],
    current: Optional[Dict[str, Any]],
    max_event_delta: float,
    max_score_delta: float,
    max_signal_delta: int,
    strict_status: bool,
) -> Dict[str, Any]:
    if base is None:
        return {
            "case_dir": case_dir,
            "status": "MISSING_IN_BASELINE",
            "drift": True,
            "reason": "new case appeared in current batch",
        }
    if current is None:
        return {
            "case_dir": case_dir,
            "status": "MISSING_IN_CURRENT",
            "drift": True,
            "reason": "case disappeared in current batch",
        }

    base_score = base.get("analysis_score")
    current_score = current.get("analysis_score")
    base_signal_count = len(base.get("signals", []) or [])
    current_signal_count = len(current.get("signals", []) or [])
    base_events = base.get("analysis", {}).get("analysis", {}).get("event_count")
    if base_events is None:
        base_events = base.get("event_count")
    current_events = current.get("analysis", {}).get("analysis", {}).get("event_count")
    if current_events is None:
        current_events = current.get("event_count")

    score_delta = None
    signal_delta = None
    event_ratio = None

    if base_score is not None and current_score is not None:
        score_delta = abs(float(current_score) - float(base_score))
    if base_signal_count is not None and current_signal_count is not None:
        signal_delta = abs(current_signal_count - base_signal_count)
    if base_events is not None and current_events is not None:
        event_ratio = percent_delta(float(base_events), float(current_events))

    status_drift = False
    causes: List[str] = []

    if score_delta is not None and score_delta > max_score_delta:
        status_drift = True
        causes.append(f"score_delta={score_delta:.4f} > {max_score_delta}")
    if signal_delta is not None and signal_delta > max_signal_delta:
        status_drift = True
        causes.append(f"signal_delta={signal_delta} > {max_signal_delta}")
    if event_ratio is not None and abs(event_ratio) > max_event_delta:
        status_drift = True
        causes.append(f"event_delta={event_ratio:.2%} > {max_event_delta:.2%}")

    if strict_status:
        base_status = base.get("analysis_status")
        current_status = current.get("analysis_status")
        if base_status != current_status:
            status_drift = True
            causes.append(f"analysis_status changed: {base_status} -> {current_status}")

    return {
        "case_dir": case_dir,
        "status": "DRIFT" if status_drift else "OK",
        "drift": status_drift,
        "causes": causes,
        "base": {
            "analysis_score": base_score,
            "signal_count": base_signal_count,
            "event_count": base_events,
            "analysis_status": base.get("analysis_status"),
        },
        "current": {
            "analysis_score": current_score,
            "signal_count": current_signal_count,
            "event_count": current_events,
            "analysis_status": current.get("analysis_status"),
        },
        "deltas": {
            "score_abs": score_delta,
            "signal_abs": signal_delta,
            "event_ratio": event_ratio,
        },
    }


def main() -> None:
    args = parse_args()
    base = load_report(Path(args.base_report))
    current = load_report(Path(args.current_report))

    base_cases = case_index(base)
    current_cases = case_index(current)

    all_case_dirs = sorted(set(base_cases) | set(current_cases))
    results = []
    drift_count = 0

    for case_dir in all_case_dirs:
        base_case = base_cases.get(case_dir)
        current_case = current_cases.get(case_dir)
        case_result = compare_case(
            case_dir=case_dir,
            base=base_case,
            current=current_case,
            max_event_delta=args.max_event_delta,
            max_score_delta=args.max_score_delta,
            max_signal_delta=args.max_signal_delta,
            strict_status=args.strict_status,
        )
        if case_result["drift"]:
            drift_count += 1
        results.append(case_result)

    drift_report = {
        "base_report": str(args.base_report),
        "current_report": str(args.current_report),
        "thresholds": {
            "max_event_delta": args.max_event_delta,
            "max_score_delta": args.max_score_delta,
            "max_signal_delta": args.max_signal_delta,
            "strict_status": args.strict_status,
        },
        "case_count": len(results),
        "drift_count": drift_count,
        "results": results,
    }

    out_report = Path(args.out_report)
    out_report.parent.mkdir(parents=True, exist_ok=True)
    out_report.write_text(json.dumps(drift_report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[INFO] drift count={drift_count} / cases={len(results)}")
    print(f"[INFO] drift report: {out_report}")

    if drift_count != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
