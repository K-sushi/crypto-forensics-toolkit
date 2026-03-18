from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_current_state_manifest as manifest_builder
import build_case_dossiers as dossier_builder
import report_structure_miner as miner
import validate_structure_contract as validator


def test_build_case_payload_includes_scorecard_and_case_profile():
    report_path = ROOT / "reports" / "case_study_abracadabra_v1.md"

    payload = miner.build_case_payload(report_path)

    assert payload["schema_version"] == "forensics-structure-1.3"
    assert payload["validation"]["passes_signal_gate"] is True
    assert "case_profile" in payload
    assert "scorecard" in payload
    assert payload["scorecard"]["total"] >= 3000
    assert "target_10000_gap" in payload["scorecard"]
    assert "axes" in payload["scorecard"]
    assert set(payload["scorecard"]["axes"]) == {"artifact_ops", "live_intel", "action_economics"}
    assert payload["case_profile"]["tier1_lead"]["label"]
    assert payload["case_profile"]["standardized_sections"]


def test_compare_features_emits_scorecards():
    report_paths = [
        ROOT / "reports" / "case_study_abracadabra_v1.md",
        ROOT / "reports" / "case_study_yei_finance_v1.md",
    ]
    payloads = [miner.build_case_payload(path) for path in report_paths]

    summary = miner.compare_features(payloads)

    assert "scores" in summary
    assert "scorecards" in summary
    assert "pairwise_delta" in summary
    assert summary["pairwise_delta"]


def test_reanalysis_ledger_is_classified_and_excluded_from_case_summary():
    report_paths = [
        ROOT / "reports" / "case_study_abracadabra_v1.md",
        ROOT / "reports" / "case_study_yei_finance_v1.md",
        ROOT / "reports" / "case_study_yei_finance_v2.md",
    ]
    payloads = [miner.build_case_payload(path) for path in report_paths]

    reanalysis = next(payload for payload in payloads if payload["case_id"] == "case_study_yei_finance_v2")
    case_payloads = [payload for payload in payloads if payload["doc_class"] == "case_study"]
    summary = miner.compare_features(case_payloads)

    assert reanalysis["doc_class"] == "reanalysis_ledger"
    assert "re-analysis execution" in reanalysis["classification"]["marker_hits"]
    assert "case_study_yei_finance_v2" not in summary["scorecards"]
    assert set(summary["scorecards"]) == {"ABRA-2025-001", "case_study_yei_finance_v1"}


def test_current_state_manifest_contains_cases_and_monitored_addresses(tmp_path):
    report_paths = [
        ROOT / "reports" / "case_study_abracadabra_v1.md",
        ROOT / "reports" / "case_study_yei_finance_v1.md",
    ]
    artifacts_dir = tmp_path / "structured_reports"
    artifacts_dir.mkdir()

    for path in report_paths:
        payload = miner.build_case_payload(path)
        miner.write_output(payload, artifacts_dir)

    out_path = tmp_path / "current_state_manifest.json"
    generated_at = "2026-03-18T00:00:00Z"
    cases = [
        manifest_builder.build_case_row(json.loads(path.read_text(encoding="utf-8")), generated_at)
        for path in sorted(artifacts_dir.glob("*.json"))
    ]

    manifest = {
        "generated_at_utc": generated_at,
        "case_count": len(cases),
        "cases": cases,
    }
    out_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    errors = validator.validate_manifest(out_path)
    assert errors == []
    assert manifest["case_count"] == 2
    assert all(case["monitored_addresses"] for case in manifest["cases"])


def test_validator_accepts_generated_outputs(tmp_path):
    report_paths = [
        ROOT / "reports" / "case_study_abracadabra_v1.md",
        ROOT / "reports" / "case_study_yei_finance_v1.md",
    ]
    artifacts_dir = tmp_path / "structured_reports"
    artifacts_dir.mkdir()

    payloads = []
    for path in report_paths:
        payload = miner.build_case_payload(path)
        miner.write_output(payload, artifacts_dir)
        payloads.append(payload)

    summary_path = tmp_path / "feature_summary.json"
    summary_path.write_text(
        json.dumps(miner.compare_features(payloads), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    manifest_path = tmp_path / "current_state_manifest.json"
    generated_at = "2026-03-18T00:00:00Z"
    manifest = {
        "generated_at_utc": generated_at,
        "case_count": len(payloads),
        "cases": [manifest_builder.build_case_row(payload, generated_at) for payload in payloads],
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    report_json_paths = validator.find_reports(artifacts_dir)
    assert len(report_json_paths) == 2
    assert validator.validate_summary(summary_path) == []
    assert validator.validate_manifest(manifest_path) == []

    for path in report_json_paths:
        payload = validator.load_json(path)
        assert validator.validate_one(payload) == []


def test_case_dossier_builder_links_snapshot_and_reanalysis(tmp_path):
    payload = miner.build_case_payload(ROOT / "reports" / "case_study_abracadabra_v1.md")
    snapshot_case = {
        "case_id": payload["case_id"],
        "freshness_status": "live_checked",
        "live_monitored_count": 2,
        "address_states": [
            {"address": "0x1", "activity_source": "explorer_html", "last_activity_utc": "2026-03-18T00:00:00Z", "last_outbound_tx": "0xabc"},
            {"address": "0x2", "activity_source": None, "last_activity_utc": None, "last_outbound_tx": None},
        ],
    }
    lead_packet = {
        "disclosure_target": "KuCoin compliance / law-enforcement liaison",
        "execution_priority": {"score": 1000, "label": "high"},
        "recoverability": {"score": 100, "label": "high"},
        "disclosure_readiness": {"support_strength": 80, "status": "ready"},
        "monetization_potential": {"score": 90, "trend": "improving"},
    }
    reanalysis_payload = {
        "case_id": "case_study_abracadabra_v2",
        "source_sha256": "abc123",
        "sections": [
            {"body": "Source case | `reports/case_study_abracadabra_v1.md` |"},
            {"body": "drift_count = 0\nrun_osint_reanalysis.py\ncompare_reanalysis_reports.py\nSHA256\nSHA256"},
        ],
        "classification": {"marker_hits": ["re-analysis execution"]},
    }

    dossier = dossier_builder.build_dossier(payload, snapshot_case, lead_packet, [reanalysis_payload])

    assert dossier["dossier_version"] == "case-dossier-1.0"
    assert dossier["operational_artifacts"]["snapshot"]["explorer_hits"] == 1
    assert dossier["dossier_completeness"]["has_linked_reanalysis"] is True
    assert dossier["linked_reanalysis"][0]["has_drift_zero"] is True
    assert dossier["last_activity_coverage"] == 500
    assert dossier["last_outbound_coverage"] == 500
    assert dossier["address_state_coverage"] == 0
