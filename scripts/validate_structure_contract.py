#!/usr/bin/env python3
"""Validate the structured output contract for report_structure_miner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


SCHEMA_PREFIX = "forensics-structure-"
REQUIRED_TOP_KEYS = {
    "schema_version",
    "case_id",
    "source_file",
    "source_sha256",
    "sections",
    "events",
    "features",
    "validation",
    "stats",
    "case_profile",
    "scorecard",
}
REQUIRED_EVENT_KEYS = {
    "event_id",
    "section",
    "line_no",
    "timestamp",
    "confidence",
    "signals",
    "context",
    "source",
}
REQUIRED_FEATURE_KEYS = {
    "cv_max",
    "event_count",
    "timeline_points",
    "bridge_signal_count",
    "risk_score",
}
REQUIRED_VALIDATION_KEYS = {
    "raw_events",
    "deduped_events",
    "event_ratio",
    "line_ratio",
    "risk_score",
    "passes_signal_gate",
}
REQUIRED_CASE_PROFILE_KEYS = {
    "standardized_sections",
    "open_loops",
    "tier1_lead",
    "current_state",
}
REQUIRED_SCORECARD_KEYS = {
    "dimensions",
    "axes",
    "total",
    "target_6000_gap",
    "target_10000_gap",
    "target_plus_6000_gap",
    "remaining_axis_upside",
    "scale",
    "dimension_count",
}
REQUIRED_SCORECARD_DIMENSIONS = {
    "provenance",
    "fund_flow_closure",
    "attribution_leverage",
    "freshness",
    "reproducibility",
    "machine_readability",
    "cross_case_schema",
    "presentation_quality",
    "legal_operational_packaging",
    "comparative_intelligence",
}
REQUIRED_SCORECARD_AXES = {
    "artifact_ops",
    "live_intel",
    "action_economics",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts/structured_reports",
        help="Directory containing structured report JSON files.",
    )
    parser.add_argument(
        "--summary-path",
        default="artifacts/feature_summary.json",
        help="Path to feature_summary.json.",
    )
    parser.add_argument(
        "--baseline-path",
        default="artifacts/structure_baseline.json",
        help="Path to drift baseline file.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Overwrite baseline with current metrics.",
    )
    parser.add_argument(
        "--min-event-ratio",
        type=float,
        default=0.05,
        help="Minimum allowed event ratio.",
    )
    parser.add_argument(
        "--min-deduped-events",
        type=int,
        default=15,
        help="Minimum deduplicated events per case.",
    )
    parser.add_argument(
        "--max-event-regression",
        type=float,
        default=0.30,
        help="Allowed relative event_count regression vs baseline (0.30 = 30% max drop).",
    )
    parser.add_argument(
        "--max-ratio-regression",
        type=float,
        default=0.03,
        help="Allowed absolute event_ratio drop vs baseline.",
    )
    parser.add_argument(
        "--min-dedup-ratio",
        type=float,
        default=0.60,
        help="Minimum allowed deduped_events / raw_events ratio.",
    )
    parser.add_argument(
        "--require-baseline",
        action="store_true",
        help="Fail if baseline file is missing.",
    )
    parser.add_argument(
        "--strict-case-coverage",
        action="store_true",
        help="Fail when baseline and current case-id sets are not equal.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_reports(dir_path: Path) -> List[Path]:
    return sorted(path for path in dir_path.glob("*.json") if path.is_file())


def validate_one(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    missing = REQUIRED_TOP_KEYS - payload.keys()
    if missing:
        errors.append(f"missing top-level keys: {sorted(missing)}")

    case_id = payload.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        errors.append("case_id missing or empty")
    if case_id and any(ch in case_id for ch in ("*", "`", "#")):
        errors.append(f"case_id contains markdown artifacts: {case_id}")

    schema = payload.get("schema_version", "")
    if not isinstance(schema, str) or not schema.startswith(SCHEMA_PREFIX):
        errors.append(f"unexpected schema_version: {schema}")

    if not isinstance(payload.get("source_sha256"), str) or not payload.get("source_sha256"):
        errors.append("source_sha256 missing")

    sections = payload.get("sections")
    if not isinstance(sections, list):
        errors.append("sections must be a list")

    events = payload.get("events")
    if not isinstance(events, list) or not events:
        errors.append("events empty or invalid")

    if isinstance(events, list):
        for idx, event in enumerate(events, 1):
            if not isinstance(event, dict):
                errors.append(f"event[{idx}] is not an object")
                continue
            missing_event = REQUIRED_EVENT_KEYS - event.keys()
            if missing_event:
                errors.append(f"event[{idx}] missing keys: {sorted(missing_event)}")
            source = event.get("source")
            if not isinstance(source, str) or not source.strip():
                errors.append(f"event[{idx}] source missing")

    features = payload.get("features", {})
    if not isinstance(features, dict):
        errors.append("features must be an object")
    else:
        vector = features.get("feature_vector")
        if not isinstance(vector, list):
            errors.append("features.feature_vector must be a list")
        else:
            names = {f.get("name") for f in vector if isinstance(f, dict) and "name" in f}
            missing_features = REQUIRED_FEATURE_KEYS - names
            if missing_features:
                errors.append(f"feature_vector missing required names: {sorted(missing_features)}")

        timeline = features.get("timeline")
        if not isinstance(timeline, dict) or "median_gap_min" not in timeline:
            errors.append("features.timeline.median_gap_min missing")

    validation = payload.get("validation", {})
    if not isinstance(validation, dict):
        errors.append("validation must be an object")
    else:
        missing_validation = REQUIRED_VALIDATION_KEYS - validation.keys()
        if missing_validation:
            errors.append(f"validation missing keys: {sorted(missing_validation)}")

    case_profile = payload.get("case_profile", {})
    if not isinstance(case_profile, dict):
        errors.append("case_profile must be an object")
    else:
        missing_case_profile = REQUIRED_CASE_PROFILE_KEYS - case_profile.keys()
        if missing_case_profile:
            errors.append(f"case_profile missing keys: {sorted(missing_case_profile)}")
        if not isinstance(case_profile.get("standardized_sections"), dict):
            errors.append("case_profile.standardized_sections must be an object")
        if not isinstance(case_profile.get("open_loops"), list):
            errors.append("case_profile.open_loops must be a list")
        tier1_lead = case_profile.get("tier1_lead")
        if not isinstance(tier1_lead, dict) or not tier1_lead.get("label"):
            errors.append("case_profile.tier1_lead.label missing")

    scorecard = payload.get("scorecard", {})
    if not isinstance(scorecard, dict):
        errors.append("scorecard must be an object")
    else:
        missing_scorecard = REQUIRED_SCORECARD_KEYS - scorecard.keys()
        if missing_scorecard:
            errors.append(f"scorecard missing keys: {sorted(missing_scorecard)}")
        dimensions = scorecard.get("dimensions")
        if not isinstance(dimensions, dict):
            errors.append("scorecard.dimensions must be an object")
        else:
            missing_dimensions = REQUIRED_SCORECARD_DIMENSIONS - dimensions.keys()
            if missing_dimensions:
                errors.append(f"scorecard.dimensions missing keys: {sorted(missing_dimensions)}")
        axes = scorecard.get("axes")
        if not isinstance(axes, dict):
            errors.append("scorecard.axes must be an object")
        else:
            missing_axes = REQUIRED_SCORECARD_AXES - axes.keys()
            if missing_axes:
                errors.append(f"scorecard.axes missing keys: {sorted(missing_axes)}")
            for axis_name in REQUIRED_SCORECARD_AXES & axes.keys():
                axis = axes.get(axis_name)
                if not isinstance(axis, dict):
                    errors.append(f"scorecard.axes.{axis_name} must be an object")
                    continue
                for key in (
                    "dimensions",
                    "current_score",
                    "max_score",
                    "upside",
                    "integrated_dimension_count",
                    "dimension_count",
                    "integration_status",
                ):
                    if key not in axis:
                        errors.append(f"scorecard.axes.{axis_name} missing key: {key}")
        total = scorecard.get("total")
        if not isinstance(total, int) or total < 0:
            errors.append("scorecard.total must be a non-negative integer")
        scale = scorecard.get("scale")
        if scale != 1000:
            errors.append(f"scorecard.scale must be 1000, got: {scale}")

    return errors


def extract_metrics(payload: Dict[str, Any]) -> Dict[str, float]:
    fv = payload.get("features", {}).get("feature_vector", [])
    to_val = {entry.get("name"): entry.get("value") for entry in fv if isinstance(entry, dict)}
    return {
        "schema_version": payload.get("schema_version"),
        "case_id": payload.get("case_id"),
        "event_count": to_val.get("event_count", 0),
        "event_ratio": payload.get("validation", {}).get("event_ratio", 0.0),
        "line_ratio": payload.get("validation", {}).get("line_ratio", 0.0),
    }


def load_baseline(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return load_json(path)


def validate_against_baseline(
    metrics: Dict[str, Dict[str, float]],
    baseline: Dict[str, Any],
    args: argparse.Namespace,
) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    if not baseline:
        if args.require_baseline:
            errors.append(f"baseline missing: {args.baseline_path}")
        return errors, warnings

    metric_cases = set(metrics.keys())
    base_cases = set(baseline.keys())
    if args.strict_case_coverage:
        missing_from_run = sorted(base_cases - metric_cases)
        if missing_from_run:
            errors.append(
                f"baseline has missing case(s): {', '.join(missing_from_run)}"
            )
        extra_in_run = sorted(metric_cases - base_cases)
        if extra_in_run:
            errors.append(
                f"run has un-baselined case(s): {', '.join(extra_in_run)}"
            )

    if not args.strict_case_coverage:
        missing_from_run = sorted((base_cases - metric_cases))
        if missing_from_run:
            warnings.append(f"DRIFT SKIP: baseline has no output for {', '.join(missing_from_run)}")

    for case_id, row in metrics.items():
        base_row = baseline.get(case_id)
        if not isinstance(base_row, dict):
            if args.strict_case_coverage:
                errors.append(f"{case_id}: no baseline row")
            else:
                warnings.append(f"DRIFT SKIP: {case_id} has no baseline row")
            continue

        event_count = row.get("event_count", 0.0) or 0.0
        base_event_count = base_row.get("event_count", 0.0) or 0.0
        if base_event_count:
            min_allowed = base_event_count * (1 - args.max_event_regression)
            if event_count < min_allowed:
                errors.append(
                    f"{case_id}: event_count regressed from {base_event_count} to {event_count}"
                )

        ratio = row.get("event_ratio", 0.0) or 0.0
        base_ratio = base_row.get("event_ratio", 0.0) or 0.0
        if base_ratio and (base_ratio - ratio) > args.max_ratio_regression:
            errors.append(
                f"{case_id}: event_ratio regressed from {base_ratio:.4f} to {ratio:.4f}"
            )

    return errors, warnings


def validate_summary(path: Path) -> List[str]:
    errors: List[str] = []
    if not path.exists():
        errors.append(f"summary file missing: {path}")
        return errors

    summary = load_json(path)
    if not isinstance(summary, dict):
        errors.append("summary is not an object")
        return errors
    if "scores" not in summary:
        errors.append("summary.scores missing")
    if "scorecards" not in summary:
        errors.append("summary.scorecards missing")
    if "pairwise_delta" not in summary:
        errors.append("summary.pairwise_delta missing")
    return errors


def validate_manifest(path: Path) -> List[str]:
    errors: List[str] = []
    if not path.exists():
        errors.append(f"current-state manifest missing: {path}")
        return errors

    manifest = load_json(path)
    if not isinstance(manifest, dict):
        return ["current-state manifest is not an object"]
    for key in ("generated_at_utc", "case_count", "cases"):
        if key not in manifest:
            errors.append(f"current-state manifest missing key: {key}")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("current-state manifest cases missing or empty")
        return errors
    for idx, row in enumerate(cases, 1):
        if not isinstance(row, dict):
            errors.append(f"current-state manifest case[{idx}] is not an object")
            continue
        for key in (
            "case_id",
            "last_checked_utc",
            "status",
            "tier1_lead",
            "monitored_addresses",
            "scorecard_total",
            "target_6000_gap",
            "target_10000_gap",
        ):
            if key not in row:
                errors.append(f"current-state manifest case[{idx}] missing key: {key}")
        monitored = row.get("monitored_addresses")
        if not isinstance(monitored, list) or not monitored:
            errors.append(f"current-state manifest case[{idx}] monitored_addresses missing or empty")
    return errors


def validate_snapshot(path: Path) -> List[str]:
    errors: List[str] = []
    if not path.exists():
        errors.append(f"current-state snapshot missing: {path}")
        return errors
    snapshot = load_json(path)
    if not isinstance(snapshot, dict):
        return ["current-state snapshot is not an object"]
    cases = snapshot.get("cases")
    if not isinstance(cases, list) or not cases:
        return ["current-state snapshot cases missing or empty"]
    for idx, row in enumerate(cases, 1):
        for key in ("case_id", "freshness_status", "live_monitored_count", "address_states"):
            if key not in row:
                errors.append(f"current-state snapshot case[{idx}] missing key: {key}")
        if not isinstance(row.get("address_states"), list) or not row.get("address_states"):
            errors.append(f"current-state snapshot case[{idx}] address_states missing or empty")
            continue
        for jdx, state in enumerate(row["address_states"], 1):
            for key in ("address", "chains", "last_checked_utc", "live_states"):
                if key not in state:
                    errors.append(f"current-state snapshot case[{idx}] address_state[{jdx}] missing key: {key}")
    return errors


def validate_lead_packets(dir_path: Path) -> List[str]:
    errors: List[str] = []
    if not dir_path.exists():
        errors.append(f"lead packet dir missing: {dir_path}")
        return errors
    files = sorted(path for path in dir_path.glob("*.json") if path.is_file())
    if not files:
        errors.append(f"lead packet dir empty: {dir_path}")
        return errors
    for path in files:
        payload = load_json(path)
        for key in (
            "case_id",
            "tier1_lead",
            "disclosure_target",
            "request_basis",
            "addresses_of_interest",
            "why_now",
            "execution_priority",
            "recoverability",
            "disclosure_readiness",
            "monetization_potential",
            "target_10000_gap",
        ):
            if key not in payload:
                errors.append(f"lead packet {path.name} missing key: {key}")
    return errors


def validate_case_dossiers(dir_path: Path) -> List[str]:
    errors: List[str] = []
    if not dir_path.exists():
        errors.append(f"case dossier dir missing: {dir_path}")
        return errors
    files = sorted(path for path in dir_path.glob("*.json") if path.is_file())
    if not files:
        errors.append(f"case dossier dir empty: {dir_path}")
        return errors
    for path in files:
        payload = load_json(path)
        for key in (
            "dossier_version",
            "case_id",
            "source_sha256",
            "standardized_section_keys",
            "report_artifacts",
            "operational_artifacts",
            "linked_reanalysis",
            "evidence_chain",
            "dossier_completeness",
        ):
            if key not in payload:
                errors.append(f"case dossier {path.name} missing key: {key}")
    return errors


def main() -> None:
    args = parse_args()
    artifact_dir = Path(args.artifacts_dir)
    summary_path = Path(args.summary_path)
    baseline_path = Path(args.baseline_path)
    manifest_path = summary_path.parent / "current_state_manifest.json"
    snapshot_path = summary_path.parent / "current_state_snapshot.json"
    lead_packets_dir = summary_path.parent / "lead_packets"
    case_dossiers_dir = summary_path.parent / "case_dossiers"

    report_paths = find_reports(artifact_dir)
    if not report_paths:
        raise SystemExit(f"No structured report json found in {artifact_dir}")

    all_errors: List[str] = []
    metrics: Dict[str, Dict[str, float]] = {}

    for path in report_paths:
        payload = load_json(path)
        errors = validate_one(payload)
        validation = payload.get("validation", {})
        if validation.get("raw_events", 0) <= 0:
            errors.append("validation.raw_events must be > 0")
        if validation.get("deduped_events", 0) < args.min_deduped_events:
            errors.append(f"validation.deduped_events < {args.min_deduped_events}")
        if validation.get("event_ratio", 0.0) < args.min_event_ratio:
            errors.append(f"validation.event_ratio < {args.min_event_ratio}")
        raw_events = validation.get("raw_events", 0) or 0
        deduped_events = validation.get("deduped_events", 0) or 0
        ratio = deduped_events / raw_events if raw_events > 0 else 0.0
        if ratio < args.min_dedup_ratio:
            errors.append(
                f"validation.deduped_events / raw_events < {args.min_dedup_ratio:.2f}: {ratio:.4f}"
            )
        if validation.get("passes_signal_gate") not in (True, False):
            errors.append("validation.passes_signal_gate missing")

        row = extract_metrics(payload)
        metrics[row["case_id"]] = row

        if errors:
            all_errors.append(f"[{path.name}]")
            all_errors.extend(f"  - {err}" for err in errors)

    summary_errors = validate_summary(summary_path)
    if summary_errors:
        all_errors.extend(summary_errors)
    manifest_errors = validate_manifest(manifest_path)
    if manifest_errors:
        all_errors.extend(manifest_errors)
    snapshot_errors = validate_snapshot(snapshot_path)
    if snapshot_errors:
        all_errors.extend(snapshot_errors)
    lead_packet_errors = validate_lead_packets(lead_packets_dir)
    if lead_packet_errors:
        all_errors.extend(lead_packet_errors)
    dossier_errors = validate_case_dossiers(case_dossiers_dir)
    if dossier_errors:
        all_errors.extend(dossier_errors)

    baseline = load_baseline(baseline_path)
    baseline_errors, baseline_warnings = validate_against_baseline(metrics, baseline, args)
    if baseline_errors:
        all_errors.extend(f"DRIFT: {err}" for err in baseline_errors)
    if baseline_warnings:
        for warn in baseline_warnings:
            print(f"[WARN] {warn}")

    if args.update_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(metrics, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[INFO] baseline updated: {baseline_path}")

    if all_errors:
        print("[FAIL]")
        for err in all_errors:
            print(f"- {err}")
        raise SystemExit(1)

    if baseline:
        print(f"[PASS] validated {len(report_paths)} report(s), drift checks passed")
    else:
        print(f"[PASS] validated {len(report_paths)} report(s), no baseline loaded")


if __name__ == "__main__":
    main()
