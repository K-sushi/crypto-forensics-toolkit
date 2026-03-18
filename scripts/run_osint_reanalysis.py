#!/usr/bin/env python3
"""End-to-end OSINT reanalysis orchestrator for markdown case studies."""

from __future__ import annotations

import argparse
import json
import re
import sys
import importlib
import subprocess
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


SUPPORTED_CHAIN_HINTS = {
    "ethereum": ("ethereum", "eth", "mainnet"),
    "arbitrum": ("arbitrum", "arb"),
    "base": ("base",),
    "polygon": ("polygon", "matic"),
    "sei": ("sei",),
}


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-path",
        default=str(project_root() / "reports" / "case_study_abracadabra_v1.md"),
        help="Markdown case study path.",
    )
    parser.add_argument(
        "--case-name",
        default="reanalysis_case",
        help="Case name for evidence and artifact output.",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=40,
        help="Maximum address targets to collect in one run.",
    )
    parser.add_argument(
        "--collect",
        action="store_true",
        help="Run live on-chain collection (requires ETHERSCAN_API_KEY).",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="ETHERSCAN API key (optional; if absent, loads from ETHERSCAN_API_KEY env).",
    )
    parser.add_argument(
        "--out-dir",
        default=str(project_root() / "artifacts" / "osint_runs"),
        help="Directory for manifests and summaries.",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run quick post-collection OSINT analysis.",
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="Run analysis only for an existing case directory (no live collection).",
    )
    parser.add_argument(
        "--case-dir",
        default="",
        help="Case directory to analyze when --analyze-only is used.",
    )
    return parser.parse_args()


def sanitize_case_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", value).strip("-").lower()
    return cleaned or "reanalysis"


def infer_chain_hints(line: str) -> List[str]:
    lowered = line.lower()
    hits: List[str] = []
    for canonical, aliases in SUPPORTED_CHAIN_HINTS.items():
        if any(alias in lowered for alias in aliases):
            hits.append(canonical)
    return hits


def extract_targets(report_path: Path) -> List[Dict[str, str]]:
    address_re = re.compile(r"0x[a-fA-F0-9]{40}")
    targets: Dict[Tuple[str, str], Dict[str, str]] = OrderedDict()

    for raw in report_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "|" not in raw:
            continue
        chain_hints = infer_chain_hints(raw)
        addresses = address_re.findall(raw)
        if not addresses:
            continue

        for addr in addresses:
            addr = addr.lower()
            chains = list(dict.fromkeys(chain_hints))
            if not chains:
                chains = ["ethereum"]

            for chain in chains:
                key = (addr, chain)
                if key not in targets:
                    targets[key] = {"address": addr, "chain": chain, "source_line": raw.strip()}

                if len(targets) >= 0 and len(targets) >= 400:
                    break

        if len(targets) >= 400:
            break

    return list(targets.values())


def run_live_collection(case_name: str, targets: Sequence[Dict[str, str]], api_key: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    sys.path.insert(0, str(project_root()))
    dc = importlib.import_module("templates.data_collector")

    if not api_key:
        raise RuntimeError("ETHERSCAN API key is required for live collection.")
    if not getattr(dc, "CHAIN_IDS", None):
        raise RuntimeError("templates.data_collector has invalid CHAIN_IDS configuration.")

    supported = set(dc.CHAIN_IDS.keys())
    active_targets = OrderedDict()
    filtered = 0
    for idx, target in enumerate(targets, start=1):
        chain = target["chain"]
        if chain not in supported:
            filtered += 1
            continue
        label = f"target_{idx:03d}"
        active_targets[label] = (target["address"], chain)

    if not active_targets:
        raise RuntimeError("No supported targets after chain filtering.")

    evidence_dir = Path("evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    previous_log = evidence_dir / f"{case_name.lower()}_api_log.jsonl"
    if previous_log.exists():
        previous_log.unlink()

    prev_case_name = dc.CASE_NAME
    prev_api_key = dc.ETHERSCAN_API_KEY
    prev_addresses = dc.ADDRESSES
    prev_log = dc.log_path

    try:
        dc.CASE_NAME = case_name
        dc.ETHERSCAN_API_KEY = api_key
        dc.ADDRESSES = active_targets
        dc.log_path = previous_log
        collected_rows: List[Tuple[int, str, float, str]] = dc.collect()
    finally:
        dc.CASE_NAME = prev_case_name
        dc.ETHERSCAN_API_KEY = prev_api_key
        dc.ADDRESSES = prev_addresses
        dc.log_path = prev_log

    evidence_rows = 0
    if previous_log.exists():
        evidence_rows = sum(1 for _ in previous_log.open("r", encoding="utf-8", errors="ignore"))

    return {
        "targets_used": len(active_targets),
        "targets_filtered": filtered,
        "events": len(collected_rows),
        "api_log_rows": evidence_rows,
        "event_samples": [
            {
                "timestamp": ts,
                "desc": desc,
                "value": value,
                "symbol": symbol,
            }
            for ts, desc, value, symbol in collected_rows[:50]
        ],
    }, [
        {
            "timestamp": ts,
            "desc": desc,
            "value": value,
            "symbol": symbol,
        }
        for ts, desc, value, symbol in collected_rows
    ]


def save_artifacts(
    out_dir: Path,
    case_name: str,
    report_path: Path,
    targets: Sequence[Dict[str, str]],
    stats: Dict[str, Any],
    collect: bool,
    api_available: bool,
    collection_error: Optional[str] = None,
    collected_rows: Optional[List[Dict[str, Any]]] = None,
) -> Path:
    run_dir = out_dir / sanitize_case_name(case_name)
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "case_name": case_name,
        "report_path": str(report_path),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "collect_requested": collect,
        "api_key_present": api_available,
        "targets_extracted": len(targets),
        "targets": targets[:500],
        "stats": stats,
    }
    if collection_error:
        manifest["collection_error"] = collection_error

    manifest_path = run_dir / "manifest.json"
    summary_path = run_dir / "collection_summary.json"

    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {
        "case_name": case_name,
        "collect_requested": collect,
        "api_key_present": api_available,
        "targets_extracted": len(targets),
        "collection_summary": stats,
        "schema_version": "osint-run-v1.1",
    }
    if collection_error:
        summary["collection_error"] = collection_error
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    if not collection_error and collected_rows is not None:
        events_path = run_dir / "collected_events.jsonl"
        with events_path.open("w", encoding="utf-8") as f:
            for row in collected_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        manifest["events_path"] = str(events_path)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return run_dir


def run_analysis(case_dir: Path) -> Path:
    analysis_path = case_dir / "analysis.json"
    cmd = [
        sys.executable,
        str(project_root() / "scripts" / "analyze_collected_events.py"),
        "--case-dir",
        str(case_dir),
        "--out-path",
        str(analysis_path),
    ]
    completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(f"analysis failed: {completed.stderr.strip() or completed.stdout.strip()}")
    return analysis_path


def attach_analysis_manifest(
    run_dir: Path,
    analysis_path: Path,
) -> Dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    summary_path = run_dir / "collection_summary.json"

    if not analysis_path.exists():
        raise FileNotFoundError(f"analysis file not found: {analysis_path}")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8", errors="ignore"))

    analysis_summary = {
        "analysis_status": analysis.get("status"),
        "event_count": analysis.get("event_count"),
        "score": analysis.get("analysis", {}).get("score"),
        "signals": analysis.get("analysis", {}).get("signals", []),
        "top_desc_prefixes": analysis.get("analysis", {}).get("top_desc_prefixes", []),
        "timeline_duration_hours": analysis.get("analysis", {})
        .get("timeline", {})
        .get("duration_hours"),
    }

    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        manifest["analysis"] = analysis_summary
        manifest["analysis_path"] = str(analysis_path)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8", errors="ignore"))
        summary["analysis"] = analysis_summary
        summary["analysis_path"] = str(analysis_path)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    return analysis_summary


def main() -> None:
    args = parse_args()
    if args.analyze_only and args.collect:
        raise SystemExit("--analyze-only cannot be used with --collect.")

    if args.analyze_only and not args.analyze:
        args.analyze = True

    case_name = sanitize_case_name(args.case_name)
    out_dir = Path(args.out_dir).resolve()
    api_key = args.api_key or ""

    if not api_key:
        import os
        api_key = os.environ.get("ETHERSCAN_API_KEY", "")

    if args.analyze_only:
        case_dir = Path(args.case_dir or str(out_dir / case_name)).resolve()
        if not case_dir.exists():
            raise SystemExit(f"case dir not found: {case_dir}")
        analysis_path = run_analysis(case_dir)
        analysis_summary = attach_analysis_manifest(case_dir, analysis_path)
        print(f"[INFO] analysis_summary: {analysis_summary}")
        print(f"[INFO] analysis: {analysis_path}")
        print(f"[INFO] artifacts: {case_dir}")
        return

    report_path = Path(args.report_path).expanduser().resolve()
    if not report_path.exists():
        raise SystemExit(f"report not found: {report_path}")

    targets = extract_targets(report_path)
    if args.max_targets:
        targets = targets[: args.max_targets]

    stats = {"status": "manifest_ready"}
    collection_error = None
    collected_rows = None
    if args.collect:
        try:
            stats, collected_rows = run_live_collection(case_name, targets, api_key)
            stats["status"] = "collect_complete"
        except Exception as exc:  # pragma: no cover - explicit failure channel
            stats = {"status": "collect_failed", "error": str(exc)}
            collection_error = str(exc)

    result_dir = save_artifacts(
        out_dir=out_dir,
        case_name=case_name,
        report_path=report_path,
        targets=targets,
        stats=stats,
        collect=args.collect,
        api_available=bool(api_key),
        collection_error=collection_error,
        collected_rows=collected_rows,
    )

    if args.collect and not collection_error and args.analyze:
        try:
            analysis_path = run_analysis(result_dir)
            analysis_summary = attach_analysis_manifest(result_dir, analysis_path)
            print(f"[INFO] analysis_summary: {analysis_summary}")
            print(f"[INFO] analysis: {analysis_path}")
        except Exception as exc:
            print(f"[WARN] analysis failed: {exc}")

    printable_stats = dict(stats)
    printable_stats.pop("event_samples", None)
    print(f"[INFO] report parsed: {report_path}")
    print(f"[INFO] targets extracted: {len(targets)}")
    print(f"[INFO] collect requested: {args.collect} (api_key_present={bool(api_key)})")
    print(f"[INFO] stats: {printable_stats}")
    print(f"[INFO] artifacts: {result_dir}")
    if collection_error:
        print(f"[ERROR] {collection_error}")


if __name__ == "__main__":
    main()
