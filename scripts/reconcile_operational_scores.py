#!/usr/bin/env python3
"""Reconcile scorecards with live snapshot and lead-packet operational signals."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List


AXIS_DIMENSIONS = {
    "artifact_ops": (
        "provenance",
        "reproducibility",
        "machine_readability",
        "cross_case_schema",
        "presentation_quality",
    ),
    "live_intel": (
        "fund_flow_closure",
        "freshness",
        "comparative_intelligence",
    ),
    "action_economics": (
        "attribution_leverage",
        "legal_operational_packaging",
    ),
}
AXIS_MAX_SCORE = {
    "artifact_ops": 5000,
    "live_intel": 3000,
    "action_economics": 2000,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", default="artifacts/structured_reports")
    parser.add_argument("--summary-path", default="artifacts/feature_summary.json")
    parser.add_argument("--snapshot-path", default="artifacts/current_state_snapshot.json")
    parser.add_argument("--lead-packets-dir", default="artifacts/lead_packets")
    parser.add_argument("--reanalysis-dir", default="artifacts/reanalysis_reports")
    parser.add_argument("--dossier-dir", default="artifacts/case_dossiers")
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def clamp_score(value: int) -> int:
    return max(0, min(1000, int(value)))


def axis_status(axis_name: str, current: int, max_score: int) -> str:
    if axis_name == "artifact_ops":
        return "integrated"
    ratio = (current / max_score) if max_score else 0.0
    if ratio >= 0.85:
        return "integrated"
    if ratio >= 0.55:
        return "high-partial"
    if ratio > 0:
        return "partial"
    return "not-integrated"


def refresh_axes(scorecard: Dict[str, Any]) -> None:
    dimensions = scorecard["dimensions"]
    axes = {}
    remaining_two_axis_upside = 0
    for axis_name, members in AXIS_DIMENSIONS.items():
        current = sum(dimensions[name] for name in members)
        max_score = AXIS_MAX_SCORE[axis_name]
        upside = max_score - current
        axes[axis_name] = {
            "dimensions": list(members),
            "current_score": current,
            "max_score": max_score,
            "upside": upside,
            "integrated_dimension_count": len(members) if axis_name == "artifact_ops" and current > 0 else sum(
                1 for name in members if dimensions[name] > 0
            ),
            "dimension_count": len(members),
            "integration_status": axis_status(axis_name, current, max_score),
        }
        if axis_name != "artifact_ops":
            remaining_two_axis_upside += upside

    scorecard["axes"] = axes
    scorecard["total"] = sum(dimensions.values())
    scorecard["target_6000_gap"] = max(0, 6000 - scorecard["total"])
    scorecard["target_10000_gap"] = max(0, 10000 - scorecard["total"])
    scorecard["remaining_axis_upside"] = remaining_two_axis_upside
    scorecard["target_plus_6000_gap"] = max(0, 6000 - remaining_two_axis_upside)


def load_lead_packets(lead_packets_dir: Path) -> Dict[str, Dict[str, Any]]:
    packets = {}
    for path in sorted(lead_packets_dir.glob("*.json")):
        payload = load_json(path)
        case_id = payload.get("case_id")
        if case_id:
            packets[case_id] = payload
    return packets


def load_snapshot(snapshot_path: Path) -> Dict[str, Dict[str, Any]]:
    snapshot = load_json(snapshot_path)
    return {case["case_id"]: case for case in snapshot.get("cases", []) if case.get("case_id")}


def load_reanalysis_reports(reanalysis_dir: Path) -> Dict[str, Dict[str, Any]]:
    reports = {}
    if not reanalysis_dir.exists():
        return reports
    for path in sorted(reanalysis_dir.glob("*.json")):
        payload = load_json(path)
        source_name = infer_source_case_name(payload)
        if source_name:
            reports[source_name] = payload
    return reports


def load_case_dossiers(dossier_dir: Path) -> Dict[str, Dict[str, Any]]:
    if not dossier_dir.exists():
        return {}
    dossiers = {}
    for path in sorted(dossier_dir.glob("*.json")):
        payload = load_json(path)
        case_id = payload.get("case_id")
        if case_id:
            dossiers[case_id] = payload
    return dossiers


def infer_source_case_name(reanalysis_payload: Dict[str, Any]) -> str:
    pattern = re.compile(r"reports[\\/](.+?\.md)")
    for section in reanalysis_payload.get("sections", []):
        body = section.get("body", "")
        match = pattern.search(body)
        if match:
            return Path(match.group(1)).name
    return ""


def live_bonus(snapshot_case: Dict[str, Any]) -> int:
    if not snapshot_case:
        return 0
    bonus = 0
    address_states = snapshot_case.get("address_states", [])
    if snapshot_case.get("freshness_status") == "live_checked":
        bonus += 220
    elif snapshot_case.get("freshness_status") == "snapshot_attempted":
        bonus += 120
    live_ok = 0
    rpc_errors = 0
    activity_hits = 0
    explorer_hits = 0
    attempted = snapshot_case.get("live_attempted_count", 0)
    for state in address_states:
        live_states = state.get("live_states", [])
        if any(item.get("status") == "live_balance_ok" for item in live_states):
            live_ok += 1
        rpc_errors += sum(1 for item in live_states if item.get("status") == "rpc_error")
        if state.get("last_activity_utc") or state.get("last_outbound_tx"):
            activity_hits += 1
        if str(state.get("activity_source", "")).startswith("explorer_"):
            explorer_hits += 1
    bonus += min(220, live_ok * 35)
    bonus += min(120, attempted * 8)
    bonus += min(120, activity_hits * 40)
    bonus += min(120, explorer_hits * 60)
    bonus -= min(80, rpc_errors * 5)
    return max(0, bonus)


def closure_bonus(snapshot_case: Dict[str, Any]) -> int:
    if not snapshot_case:
        return 0
    address_states = snapshot_case.get("address_states", [])
    outbound_hits = sum(1 for state in address_states if state.get("last_outbound_tx"))
    live_ok = sum(
        1
        for state in address_states
        if any(item.get("status") == "live_balance_ok" for item in state.get("live_states", []))
    )
    return min(220, outbound_hits * 45 + live_ok * 20)


def comparative_bonus(snapshot_case: Dict[str, Any]) -> int:
    if not snapshot_case:
        return 0
    address_states = snapshot_case.get("address_states", [])
    explorer_hits = sum(
        1 for state in address_states if str(state.get("activity_source", "")).startswith("explorer_")
    )
    activity_rows = sum(
        1 for state in address_states if state.get("last_activity_utc") or state.get("last_outbound_tx")
    )
    monitored = max(1, len(address_states))
    density = (activity_rows + explorer_hits) / monitored
    base = explorer_hits * 35 + activity_rows * 20
    if density >= 0.75:
        base += 120
    elif density >= 0.4:
        base += 80
    elif density > 0:
        base += 40
    return min(240, base)


def action_bonus(packet: Dict[str, Any]) -> int:
    if not packet:
        return 0
    bonus = 120
    if packet.get("disclosure_target") and "internal" not in packet["disclosure_target"].lower():
        bonus += 140
    if packet.get("addresses_of_interest"):
        bonus += min(120, len(packet["addresses_of_interest"]) * 20)
    if packet.get("why_now"):
        bonus += 80
    if packet.get("tier1_lead", {}).get("label") not in ("", "highest_confidence_open_loop"):
        bonus += 80
    execution = packet.get("execution_priority", {})
    if isinstance(execution, dict):
        bonus += min(140, int(execution.get("score", 0) / 8))
    recoverability = packet.get("recoverability", {})
    if isinstance(recoverability, dict):
        bonus += min(100, int(recoverability.get("score", 0)))
        if recoverability.get("label") == "high":
            bonus += 40
    disclosure = packet.get("disclosure_readiness", {})
    if isinstance(disclosure, dict):
        bonus += min(120, int(disclosure.get("support_strength", 0)))
        if disclosure.get("status") == "ready":
            bonus += 60
    monetization = packet.get("monetization_potential", {})
    if isinstance(monetization, dict):
        bonus += min(100, int(monetization.get("score", 0)))
    return bonus


def attribution_bonus(packet: Dict[str, Any]) -> int:
    if not packet:
        return 0
    bonus = 0
    tier1 = packet.get("tier1_lead", {})
    if tier1.get("label") not in ("", "highest_confidence_open_loop"):
        bonus += 120
    if packet.get("disclosure_target") and "internal" not in str(packet["disclosure_target"]).lower():
        bonus += 100
    if packet.get("addresses_of_interest"):
        bonus += min(80, len(packet["addresses_of_interest"]) * 16)
    execution = packet.get("execution_priority", {})
    if isinstance(execution, dict) and execution.get("label") == "high":
        bonus += 80
    recoverability = packet.get("recoverability", {})
    if isinstance(recoverability, dict):
        if recoverability.get("label") == "high":
            bonus += 70
        bonus += min(70, int(recoverability.get("score", 0) / 2))
    disclosure = packet.get("disclosure_readiness", {})
    if isinstance(disclosure, dict):
        if disclosure.get("status") == "ready":
            bonus += 70
        bonus += min(70, int(disclosure.get("support_strength", 0) / 2))
    monetization = packet.get("monetization_potential", {})
    if isinstance(monetization, dict) and monetization.get("trend") == "improving":
        bonus += 30
    if packet.get("why_now"):
        bonus += 20
    return min(500, bonus)


def reanalysis_bonus(base_payload: Dict[str, Any], reanalysis_payload: Dict[str, Any]) -> Dict[str, int]:
    if not reanalysis_payload:
        return {}

    text = "\n".join(section.get("body", "") for section in reanalysis_payload.get("sections", []))
    lowered = text.lower()
    immutable_refs = text.count("SHA256")
    has_drift_zero = "drift_count = 0" in lowered or "no behavioral drift detected" in lowered
    has_command_set = "run_osint_reanalysis.py" in lowered and "compare_reanalysis_reports.py" in lowered
    has_baseline = "baseline comparison" in lowered
    has_event_count = "event count" in lowered and "flows out" in lowered and "flows in" in lowered
    has_evidence_logs = "evidence logs" in lowered or "api_log.jsonl" in lowered
    has_analysis_window = "analysis window" in lowered

    bonus = {
        "provenance": 0,
        "reproducibility": 0,
        "machine_readability": 0,
        "cross_case_schema": 0,
        "comparative_intelligence": 0,
        "fund_flow_closure": 0,
    }

    if has_evidence_logs:
        bonus["provenance"] += 160
        bonus["machine_readability"] += 120
    if immutable_refs >= 1:
        bonus["provenance"] += min(320, immutable_refs * 80)
    if has_command_set:
        bonus["reproducibility"] += 260
        bonus["machine_readability"] += 180
    if has_drift_zero:
        bonus["reproducibility"] += 260
        bonus["comparative_intelligence"] += 220
    if has_baseline:
        bonus["cross_case_schema"] += 220
        bonus["comparative_intelligence"] += 180
    if has_event_count:
        bonus["fund_flow_closure"] += 220
        bonus["machine_readability"] += 120
    if has_analysis_window:
        bonus["fund_flow_closure"] += 120

    return bonus


def dossier_bonus(dossier: Dict[str, Any]) -> Dict[str, int]:
    if not dossier:
        return {}
    completeness = dossier.get("dossier_completeness", {})
    coverage = dossier.get("coverage_components", {})
    html_artifact = dossier.get("report_artifacts", {}).get("html_artifact", {})

    artifact_coverage = int(coverage.get("artifact_ops") or 0)
    live_coverage = int(coverage.get("live_intel") or 0)
    last_activity_coverage = int(dossier.get("last_activity_coverage") or 0)
    last_outbound_coverage = int(dossier.get("last_outbound_coverage") or 0)
    address_state_coverage = int(dossier.get("address_state_coverage") or 0)
    completeness_ratio = 0.6
    if completeness:
        truthy_keys = sum(1 for value in completeness.values() if value)
        completeness_ratio = max(0.6, min(1.0, truthy_keys / max(len(completeness), 1)))
    artifact_signal = int(artifact_coverage * completeness_ratio)
    live_primary = int(
        (address_state_coverage * 0.40)
        + (last_activity_coverage * 0.35)
        + (last_outbound_coverage * 0.25)
    )
    live_signal = int((((live_primary * 0.75) + (live_coverage * 0.25))) * completeness_ratio)
    comparative_signal = min(artifact_signal, live_signal)

    bonus = {
        "provenance": min(380, int(artifact_signal * 0.26)),
        "reproducibility": min(340, int(artifact_signal * 0.23)),
        "machine_readability": min(280, int(artifact_signal * 0.20)),
        "cross_case_schema": min(420, int(artifact_signal * 0.28)),
        "presentation_quality": min(320, int(artifact_signal * 0.18)),
        "fund_flow_closure": min(220, int((live_signal * 0.16) + (artifact_signal * 0.04))),
        "freshness": min(260, int(live_signal * 0.22)),
        "comparative_intelligence": min(240, int(comparative_signal * 0.20)),
    }

    if completeness.get("has_html_artifact") and html_artifact.get("healthy"):
        bonus["presentation_quality"] += 80
    if completeness.get("has_linked_reanalysis"):
        bonus["cross_case_schema"] += 60
        bonus["provenance"] += 40
    return bonus


def promote_axis_states(scorecard: Dict[str, Any], snapshot_case: Dict[str, Any], packet: Dict[str, Any]) -> None:
    axes = scorecard.get("axes", {})
    live_axis = axes.get("live_intel")
    if isinstance(live_axis, dict) and live_axis.get("integration_status") == "partial":
        address_states = snapshot_case.get("address_states", []) if snapshot_case else []
        explorer_hits = sum(
            1 for state in address_states if str(state.get("activity_source", "")).startswith("explorer_")
        )
        activity_hits = sum(
            1 for state in address_states if state.get("last_activity_utc") or state.get("last_outbound_tx")
        )
        if snapshot_case.get("freshness_status") == "live_checked" and explorer_hits and activity_hits:
            live_axis["integration_status"] = "high-partial"

    action_axis = axes.get("action_economics")
    if isinstance(action_axis, dict) and action_axis.get("integration_status") == "partial":
        disclosure_target = str(packet.get("disclosure_target", "")).lower() if packet else ""
        if disclosure_target and "internal" not in disclosure_target and packet.get("why_now"):
            action_axis["integration_status"] = "high-partial"


def reconcile_payload(
    payload: Dict[str, Any],
    snapshot_case: Dict[str, Any],
    packet: Dict[str, Any],
    reanalysis_payload: Dict[str, Any],
) -> Dict[str, Any]:
    scorecard = payload.get("scorecard", {})
    dimensions = dict(scorecard.get("dimensions", {}))
    dimensions["fund_flow_closure"] = clamp_score(
        int(dimensions.get("fund_flow_closure", 0)) + closure_bonus(snapshot_case)
    )
    dimensions["freshness"] = clamp_score(int(dimensions.get("freshness", 0)) + live_bonus(snapshot_case))
    dimensions["comparative_intelligence"] = clamp_score(
        int(dimensions.get("comparative_intelligence", 0)) + comparative_bonus(snapshot_case)
    )
    dimensions["attribution_leverage"] = clamp_score(
        int(dimensions.get("attribution_leverage", 0)) + attribution_bonus(packet)
    )
    dimensions["legal_operational_packaging"] = clamp_score(
        int(dimensions.get("legal_operational_packaging", 0)) + action_bonus(packet)
    )
    for name, value in reanalysis_bonus(payload, reanalysis_payload).items():
        dimensions[name] = clamp_score(int(dimensions.get(name, 0)) + value)
    scorecard["dimensions"] = dimensions
    refresh_axes(scorecard)
    promote_axis_states(scorecard, snapshot_case, packet)
    payload["scorecard"] = scorecard
    payload.setdefault("case_profile", {})
    payload["case_profile"]["operational_snapshot"] = {
        "freshness_status": snapshot_case.get("freshness_status") if snapshot_case else None,
        "live_monitored_count": snapshot_case.get("live_monitored_count") if snapshot_case else None,
        "lead_packet_target": packet.get("disclosure_target") if packet else None,
    }
    return payload


def rewrite_summary(summary_path: Path, payloads: List[Dict[str, Any]]) -> None:
    summary = load_json(summary_path)
    summary["scorecards"] = {payload["case_id"]: payload["scorecard"] for payload in payloads}
    for row in summary.get("pairwise_delta", []):
        pair = row.get("pair", [])
        if len(pair) != 2:
            continue
        a, b = pair
        if a in summary["scorecards"] and b in summary["scorecards"]:
            row.setdefault("delta", {})
            row["delta"]["scorecard_total"] = (
                summary["scorecards"][b]["total"] - summary["scorecards"][a]["total"]
            )
    write_json(summary_path, summary)


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    summary_path = Path(args.summary_path)
    snapshot_map = load_snapshot(Path(args.snapshot_path))
    lead_packets = load_lead_packets(Path(args.lead_packets_dir))
    reanalysis_map = load_reanalysis_reports(Path(args.reanalysis_dir))
    dossiers = load_case_dossiers(Path(args.dossier_dir))

    payloads = []
    for path in sorted(artifacts_dir.glob("*.json")):
        payload = load_json(path)
        case_id = payload.get("case_id")
        source_name = Path(payload.get("source_file", "")).name
        updated = reconcile_payload(
            payload,
            snapshot_map.get(case_id, {}),
            lead_packets.get(case_id, {}),
            reanalysis_map.get(source_name, {}),
        )
        for name, value in dossier_bonus(dossiers.get(case_id, {})).items():
            updated["scorecard"]["dimensions"][name] = clamp_score(
                int(updated["scorecard"]["dimensions"].get(name, 0)) + value
            )
        refresh_axes(updated["scorecard"])
        write_json(path, updated)
        payloads.append(updated)

    rewrite_summary(summary_path, payloads)
    print(f"Reconciled operational scores for {len(payloads)} case(s).")


if __name__ == "__main__":
    main()
