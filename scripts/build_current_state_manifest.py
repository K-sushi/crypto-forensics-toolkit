#!/usr/bin/env python3
"""Build a lean current-state manifest from structured forensics report artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


MAX_MONITORED_ADDRESSES = 8


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts/structured_reports",
        help="Directory containing structured report JSON files.",
    )
    parser.add_argument(
        "--out-path",
        default="artifacts/current_state_manifest.json",
        help="Output manifest path.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def candidate_addresses(payload: Dict[str, Any]) -> List[str]:
    addresses: List[str] = []
    tier1_text = json.dumps(payload.get("case_profile", {}).get("tier1_lead", {}), ensure_ascii=False)
    open_loops = payload.get("case_profile", {}).get("open_loops", [])
    entity_addresses = payload.get("features", {}).get("entities", {}).get("unique_addresses", [])
    event_addresses = []
    for event in payload.get("events", []):
        event_addresses.extend(event.get("addresses", []))

    addresses.extend(event_addresses)
    addresses.extend(entity_addresses)

    prioritized = []
    for addr in dedupe_keep_order(addresses):
        if addr.lower() in tier1_text.lower():
            prioritized.append(addr)
            continue
        if any(addr.lower() in loop.lower() for loop in open_loops):
            prioritized.append(addr)

    ordered = dedupe_keep_order(prioritized + addresses)
    return ordered[:MAX_MONITORED_ADDRESSES]


def current_status(payload: Dict[str, Any]) -> str:
    open_loops = " ".join(payload.get("case_profile", {}).get("open_loops", [])).lower()
    if "live balance" in open_loops or "monitor" in open_loops:
        return "needs_live_check"
    if payload.get("validation", {}).get("passes_signal_gate"):
        return "analysis_ready"
    return "needs_review"


def build_case_row(payload: Dict[str, Any], generated_at: str) -> Dict[str, Any]:
    scorecard = payload.get("scorecard", {})
    case_profile = payload.get("case_profile", {})
    return {
        "case_id": payload.get("case_id"),
        "title": payload.get("title"),
        "last_checked_utc": generated_at,
        "status": current_status(payload),
        "tier1_lead": case_profile.get("tier1_lead", {}),
        "monitored_addresses": candidate_addresses(payload),
        "open_loops": case_profile.get("open_loops", []),
        "scorecard_total": scorecard.get("total"),
        "target_6000_gap": scorecard.get("target_6000_gap"),
        "target_10000_gap": scorecard.get("target_10000_gap"),
    }


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    out_path = Path(args.out_path)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    report_paths = sorted(path for path in artifacts_dir.glob("*.json") if path.is_file())
    if not report_paths:
        raise SystemExit(f"No structured report json found in {artifacts_dir}")

    cases = [build_case_row(load_json(path), generated_at) for path in report_paths]
    manifest = {
        "generated_at_utc": generated_at,
        "case_count": len(cases),
        "cases": cases,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out_path} with {len(cases)} case(s).")


if __name__ == "__main__":
    main()
