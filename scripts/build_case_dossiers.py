#!/usr/bin/env python3
"""Build fixed-schema case dossiers from structured case studies and linked artifacts."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", default="artifacts/structured_reports")
    parser.add_argument("--snapshot-path", default="artifacts/current_state_snapshot.json")
    parser.add_argument("--lead-packets-dir", default="artifacts/lead_packets")
    parser.add_argument("--reanalysis-dir", default="artifacts/reanalysis_reports")
    parser.add_argument("--out-dir", default="artifacts/case_dossiers")
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_snapshot_map(path: Path) -> Dict[str, Dict[str, Any]]:
    payload = load_json(path)
    return {case["case_id"]: case for case in payload.get("cases", []) if case.get("case_id")}


def load_dir_map(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    out = {}
    for item in sorted(path.glob("*.json")):
        payload = load_json(item)
        case_id = payload.get("case_id")
        if case_id:
            out[case_id] = payload
    return out


def infer_source_case_name(reanalysis_payload: Dict[str, Any]) -> str:
    pattern = re.compile(r"reports[\\/](.+?\.md)")
    for section in reanalysis_payload.get("sections", []):
        body = section.get("body", "")
        match = pattern.search(body)
        if match:
            return Path(match.group(1)).name
    return ""


def load_reanalysis_map(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    if not path.exists():
        return {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for item in sorted(path.glob("*.json")):
        payload = load_json(item)
        source_name = infer_source_case_name(payload)
        if not source_name:
            continue
        out.setdefault(source_name, []).append(payload)
    return out


def snapshot_summary(snapshot_case: Dict[str, Any]) -> Dict[str, Any]:
    address_states = snapshot_case.get("address_states", []) if snapshot_case else []
    explorer_hits = sum(
        1 for row in address_states if str(row.get("activity_source", "")).startswith("explorer_")
    )
    activity_rows = sum(
        1 for row in address_states if row.get("last_activity_utc") or row.get("last_outbound_tx")
    )
    return {
        "freshness_status": snapshot_case.get("freshness_status") if snapshot_case else None,
        "live_monitored_count": snapshot_case.get("live_monitored_count") if snapshot_case else 0,
        "activity_rows": activity_rows,
        "explorer_hits": explorer_hits,
        "monitored_addresses": [row.get("address") for row in address_states if row.get("address")],
    }


def lead_summary(lead_packet: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "disclosure_target": lead_packet.get("disclosure_target"),
        "execution_priority": lead_packet.get("execution_priority"),
        "recoverability": lead_packet.get("recoverability"),
        "disclosure_readiness": lead_packet.get("disclosure_readiness"),
        "monetization_potential": lead_packet.get("monetization_potential"),
    }


def reanalysis_summary(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for payload in items:
        text = "\n".join(section.get("body", "") for section in payload.get("sections", []))
        out.append(
            {
                "case_id": payload.get("case_id"),
                "source_sha256": payload.get("source_sha256"),
                "marker_hits": payload.get("classification", {}).get("marker_hits", []),
                "immutable_reference_count": text.count("SHA256"),
                "has_drift_zero": "drift_count = 0" in text.lower() or "no behavioral drift detected" in text.lower(),
                "has_command_set": "run_osint_reanalysis.py" in text and "compare_reanalysis_reports.py" in text,
            }
        )
    return out


def build_coverage(payload: Dict[str, Any], snapshot_case: Dict[str, Any], lead_packet: Dict[str, Any], linked_reanalysis: List[Dict[str, Any]]) -> Dict[str, Any]:
    standardized = payload.get("case_profile", {}).get("standardized_sections", {})
    html_artifact = payload.get("case_profile", {}).get("html_artifact", {})
    address_states = snapshot_case.get("address_states", []) if snapshot_case else []
    monitored_addresses = snapshot_case.get("monitored_addresses", []) if snapshot_case else []
    total_tracked = max(len(address_states), len(monitored_addresses), 1)
    explorer_hits = sum(
        1 for row in address_states if str(row.get("activity_source", "")).startswith("explorer_")
    )
    activity_rows = sum(
        1 for row in address_states if row.get("last_activity_utc") or row.get("last_outbound_tx")
    )
    last_activity_hits = sum(1 for row in address_states if row.get("last_activity_utc"))
    last_outbound_hits = sum(1 for row in address_states if row.get("last_outbound_tx"))
    address_state_hits = sum(
        1
        for row in address_states
        if any(
            str(state.get("status", "")).strip()
            and str(state.get("status", "")).strip().lower() != "rpc_error"
            for state in row.get("live_states", [])
        )
    )
    live_monitored = int(snapshot_case.get("live_monitored_count") or 0) if snapshot_case else 0
    evidence_chain_len = 1 + sum(1 for item in linked_reanalysis if item.get("source_sha256"))
    section_coverage = min(1000, int((len(standardized) / 8.0) * 1000))
    evidence_chain_coverage = min(1000, int((evidence_chain_len / 3.0) * 1000))
    reanalysis_linkage_score = 0
    if linked_reanalysis:
        max_immutable_refs = max(int(item.get("immutable_reference_count") or 0) for item in linked_reanalysis)
        if any(item.get("has_command_set") for item in linked_reanalysis):
            reanalysis_linkage_score += 250
        if any(item.get("has_drift_zero") for item in linked_reanalysis):
            reanalysis_linkage_score += 250
        if any(item.get("source_sha256") for item in linked_reanalysis):
            reanalysis_linkage_score += 200
        reanalysis_linkage_score += min(300, max_immutable_refs * 75)
    reanalysis_linkage_coverage = min(1000, reanalysis_linkage_score)
    last_activity_coverage = min(1000, int((last_activity_hits / total_tracked) * 1000))
    last_outbound_coverage = min(1000, int((last_outbound_hits / total_tracked) * 1000))
    address_state_coverage = min(1000, int((address_state_hits / total_tracked) * 1000))

    artifact_ops = 0
    artifact_ops += int(section_coverage * 0.36)
    artifact_ops += int(evidence_chain_coverage * 0.24)
    artifact_ops += int(reanalysis_linkage_coverage * 0.26)
    artifact_ops += 140 if html_artifact.get("healthy") else 60 if html_artifact.get("exists") else 0

    live_intel = 0
    live_intel += int(address_state_coverage * 0.35)
    live_intel += int(last_activity_coverage * 0.30)
    live_intel += int(last_outbound_coverage * 0.25)
    live_intel += min(80, live_monitored * 10)
    live_intel += min(70, explorer_hits * 12)
    live_intel += min(50, activity_rows * 8)
    if address_states:
        density = (explorer_hits + activity_rows) / max(1, len(address_states) * 2)
        if density >= 0.75:
            live_intel += 90
        elif density >= 0.5:
            live_intel += 60
        elif density > 0:
            live_intel += 30

    action = 0
    if lead_packet:
        action += 120
        if lead_packet.get("disclosure_target"):
            action += 100
        if lead_packet.get("addresses_of_interest"):
            action += min(120, len(lead_packet["addresses_of_interest"]) * 24)
        execution = lead_packet.get("execution_priority", {})
        if isinstance(execution, dict):
            action += min(120, int(execution.get("score", 0) / 10))
        recoverability = lead_packet.get("recoverability", {})
        if isinstance(recoverability, dict):
            action += min(100, int(recoverability.get("score", 0)))
        disclosure = lead_packet.get("disclosure_readiness", {})
        if isinstance(disclosure, dict):
            action += min(100, int(disclosure.get("support_strength", 0)))

    components = {
        "artifact_ops": min(1000, artifact_ops),
        "live_intel": min(1000, live_intel),
        "action_economics": min(1000, action),
    }
    return {
        "coverage_score": sum(components.values()),
        "components": components,
        "section_coverage": section_coverage,
        "evidence_chain_coverage": evidence_chain_coverage,
        "reanalysis_linkage_coverage": reanalysis_linkage_coverage,
        "last_activity_coverage": last_activity_coverage,
        "last_outbound_coverage": last_outbound_coverage,
        "address_state_coverage": address_state_coverage,
    }


def build_dossier(
    payload: Dict[str, Any],
    snapshot_case: Dict[str, Any],
    lead_packet: Dict[str, Any],
    reanalysis_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    standardized = payload.get("case_profile", {}).get("standardized_sections", {})
    html_artifact = payload.get("case_profile", {}).get("html_artifact", {})
    linked_reanalysis = reanalysis_summary(reanalysis_items)
    coverage = build_coverage(payload, snapshot_case, lead_packet, linked_reanalysis)
    evidence_chain = [payload.get("source_sha256")]
    evidence_chain.extend(item.get("source_sha256") for item in linked_reanalysis if item.get("source_sha256"))
    evidence_chain = [item for item in evidence_chain if item]

    return {
        "dossier_version": "case-dossier-1.0",
        "case_id": payload.get("case_id"),
        "title": payload.get("title"),
        "source_file": payload.get("source_file"),
        "source_sha256": payload.get("source_sha256"),
        "doc_class": payload.get("doc_class"),
        "standardized_section_keys": sorted(standardized.keys()),
        "report_artifacts": {
            "html_artifact": html_artifact,
            "stats": payload.get("stats", {}),
            "validation": payload.get("validation", {}),
        },
        "operational_artifacts": {
            "snapshot": snapshot_summary(snapshot_case),
            "lead_packet": lead_summary(lead_packet),
        },
        "linked_reanalysis": linked_reanalysis,
        "evidence_chain": evidence_chain,
        "coverage_score": coverage["coverage_score"],
        "coverage_components": coverage["components"],
        "section_coverage": coverage["section_coverage"],
        "evidence_chain_coverage": coverage["evidence_chain_coverage"],
        "reanalysis_linkage_coverage": coverage["reanalysis_linkage_coverage"],
        "last_activity_coverage": coverage["last_activity_coverage"],
        "last_outbound_coverage": coverage["last_outbound_coverage"],
        "address_state_coverage": coverage["address_state_coverage"],
        "dossier_completeness": {
            "has_html_artifact": bool(html_artifact.get("exists")),
            "has_snapshot": bool(snapshot_case),
            "has_lead_packet": bool(lead_packet),
            "has_linked_reanalysis": bool(linked_reanalysis),
            "section_count": len(standardized),
        },
    }


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    snapshot_map = load_snapshot_map(Path(args.snapshot_path))
    lead_map = load_dir_map(Path(args.lead_packets_dir))
    reanalysis_map = load_reanalysis_map(Path(args.reanalysis_dir))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    active_case_ids = set()
    for path in sorted(artifacts_dir.glob("*.json")):
        payload = load_json(path)
        case_id = payload.get("case_id")
        if not case_id:
            continue
        active_case_ids.add(case_id)
        dossier = build_dossier(
            payload,
            snapshot_map.get(case_id, {}),
            lead_map.get(case_id, {}),
            reanalysis_map.get(Path(payload.get("source_file", "")).name, []),
        )
        (out_dir / f"{case_id}.json").write_text(json.dumps(dossier, ensure_ascii=False, indent=2), encoding="utf-8")
        count += 1

    for stale in sorted(out_dir.glob("*.json")):
        if stale.stem not in active_case_ids:
            stale.unlink()

    print(f"Wrote {count} case dossier(s) to {out_dir}.")


if __name__ == "__main__":
    main()
