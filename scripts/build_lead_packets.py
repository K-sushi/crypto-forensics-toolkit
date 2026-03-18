#!/usr/bin/env python3
"""Build action-ready lead packets from hydrated current-state snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

LEAD_TARGETS = {
    "kucoin_kyc_link": {
        "disclosure_target": "KuCoin compliance / law-enforcement liaison",
        "request_basis": "CEX gas funding suggests a KYC-servable identity pivot.",
    },
    "bridge_metadata_request": {
        "disclosure_target": "LayerZero / Stargate operations or legal contact",
        "request_basis": "Bridge metadata can narrow operator infrastructure beyond public chain data.",
    },
    "live_destination_wallet_monitoring": {
        "disclosure_target": "Internal monitoring / alerting workflow",
        "request_basis": "Destination wallets remain actionable if new outbound movement appears.",
    },
    "law_firm_disclosure_path": {
        "disclosure_target": "External counsel / subpoena prep",
        "request_basis": "Report already contains disclosure-oriented packaging.",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot-path",
        default="artifacts/current_state_snapshot.json",
        help="Path to hydrated current-state snapshot.",
    )
    parser.add_argument(
        "--summary-path",
        default="artifacts/feature_summary.json",
        help="Path to feature_summary.json for reconciled totals.",
    )
    parser.add_argument(
        "--out-dir",
        default="artifacts/lead_packets",
        help="Output directory for lead packet JSON files.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def summarize_addresses(case: Dict[str, Any]) -> List[str]:
    addresses = []
    for row in case.get("address_states", []):
        addresses.append(row.get("address"))
    return [address for address in addresses if address][:5]


def summarize_why_now(case: Dict[str, Any]) -> str:
    freshness = case.get("freshness_status")
    live_count = case.get("live_monitored_count", 0)
    if freshness == "live_checked" and live_count:
        return f"{live_count} monitored address(es) were checked in the latest snapshot."
    return "This case still has unresolved monitored addresses and should remain operationally active."


def execution_priority(case: Dict[str, Any]) -> Dict[str, Any]:
    target_score = 10000
    gap = case.get("target_10000_gap")
    if gap is None:
        gap = case.get("target_6000_gap", 6000)
        target_score = 6000
    freshness = case.get("freshness_status")
    live_count = case.get("live_monitored_count", 0)
    score = max(0, min(1000, int((target_score - gap) / 10 + live_count * 30)))
    if freshness == "live_checked":
        score = min(1000, score + 150)
    elif freshness == "snapshot_attempted":
        score = min(1000, score + 80)
    label = "high" if score >= 650 else "medium" if score >= 350 else "low"
    return {"score": score, "label": label, "gap": gap, "target_score": target_score}


def recoverability(case: Dict[str, Any]) -> Dict[str, Any]:
    total = case.get("scorecard_total", 0) or 0
    addresses = case.get("addresses_of_interest", []) or summarize_addresses(case)
    score = min(100, int(total / 60) + len(addresses) * 4)
    return {
        "score": score,
        "addresses": addresses,
        "label": "high" if score >= 75 else "medium" if score >= 45 else "low",
        "hint": "Addresses with recent balance activity are prioritized.",
    }


def disclosure_readiness(case: Dict[str, Any]) -> Dict[str, Any]:
    tier1 = case.get("tier1_lead", {})
    label = tier1.get("label", "highest_confidence_open_loop")
    request_basis = tier1.get("reason", "")
    support_strength = (
        80
        if label in ("kucoin_kyc_link", "bridge_metadata_request", "law_firm_disclosure_path")
        else 40
    )
    return {
        "label": label,
        "request_basis": request_basis,
        "support_strength": support_strength,
        "status": "ready" if support_strength >= 80 else "monitor",
    }


def monetization(case: Dict[str, Any]) -> Dict[str, Any]:
    freshness = case.get("freshness_status")
    snapshot_count = case.get("live_monitored_count", 0)
    target_score = 10000
    gap = case.get("target_10000_gap")
    if gap is None:
        gap = case.get("target_6000_gap", 6000)
        target_score = 6000
    rising_signal = 1 if freshness == "live_checked" else 0
    score = max(0, min(100, snapshot_count * 5 + rising_signal * 20 + (target_score - gap) // 160))
    return {
        "score": score,
        "trend": "improving" if rising_signal else "stale",
        "engagement_hint": "Use this case for premium monitoring" if score >= 60 else "Monitor until evidence consolidates",
    }


def build_lead_packet(case: Dict[str, Any]) -> Dict[str, Any]:
    tier1 = case.get("tier1_lead", {})
    label = tier1.get("label", "highest_confidence_open_loop")
    template = LEAD_TARGETS.get(
        label,
        {
            "disclosure_target": "Internal investigation queue",
            "request_basis": tier1.get("reason", "Highest-confidence unresolved lead."),
        },
    )
    return {
        "case_id": case.get("case_id"),
        "title": case.get("title"),
        "tier1_lead": tier1,
        "disclosure_target": template["disclosure_target"],
        "request_basis": template["request_basis"],
        "addresses_of_interest": summarize_addresses(case),
        "why_now": summarize_why_now(case),
        "execution_priority": execution_priority(case),
        "recoverability": recoverability(case),
        "disclosure_readiness": disclosure_readiness(case),
        "monetization_potential": monetization(case),
        "scorecard_total": case.get("scorecard_total"),
        "target_6000_gap": case.get("target_6000_gap"),
        "target_10000_gap": case.get("target_10000_gap"),
        "freshness_status": case.get("freshness_status"),
    }


def merge_reconciled_scores(case: Dict[str, Any], summary_entry: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(case)
    if summary_entry:
        merged["scorecard_total"] = summary_entry.get("total", merged.get("scorecard_total"))
        merged["target_6000_gap"] = summary_entry.get("target_6000_gap", merged.get("target_6000_gap"))
        merged["target_10000_gap"] = summary_entry.get("target_10000_gap", merged.get("target_10000_gap"))
    return merged


def main() -> None:
    args = parse_args()
    snapshot = load_json(Path(args.snapshot_path))
    summary = load_json(Path(args.summary_path))
    scorecards = summary.get("scorecards", {})
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    active_case_ids = set()
    for case in snapshot.get("cases", []):
        case_id = case.get("case_id")
        active_case_ids.add(case_id)
        summary_entry = scorecards.get(case_id, {})
        packet = build_lead_packet(merge_reconciled_scores(case, summary_entry))
        path = out_dir / f"{packet['case_id']}.json"
        path.write_text(json.dumps(packet, ensure_ascii=False, indent=2), encoding="utf-8")
        count += 1

    for stale_path in sorted(out_dir.glob("*.json")):
        if stale_path.stem not in active_case_ids:
            stale_path.unlink()

    print(f"Wrote {count} lead packet(s) to {out_dir}.")


if __name__ == "__main__":
    main()
