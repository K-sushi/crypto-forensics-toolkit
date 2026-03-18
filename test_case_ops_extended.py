from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_current_state_manifest as manifest_builder
import build_lead_packets as lead_packets
import hydrate_current_state_manifest as hydrator
import reconcile_operational_scores as reconcile_scores
import report_structure_miner as miner
import validate_structure_contract as validator


def test_infer_address_chains_finds_expected_networks():
    payload = miner.build_case_payload(ROOT / "reports" / "case_study_abracadabra_v1.md")

    chain_map = hydrator.infer_address_chains(payload)

    assert "0xAF9e33Aa03CAaa613c3Ba4221f7EA3eE2AC38649" in chain_map
    assert "arbitrum" in chain_map["0xAF9e33Aa03CAaa613c3Ba4221f7EA3eE2AC38649"]


def test_hydrate_case_row_adds_address_states_without_network_dependency():
    payload = miner.build_case_payload(ROOT / "reports" / "case_study_yei_finance_v1.md")
    base_row = manifest_builder.build_case_row(payload, "2026-03-18T00:00:00Z")

    def fake_fetcher(endpoint, method, params, timeout_sec):
        return {"result": hex(10**18)}

    hydrated = hydrator.hydrate_case_row(
        base_row,
        payload,
        "2026-03-18T00:00:00Z",
        timeout_sec=0.1,
        fetcher=fake_fetcher,
    )

    assert hydrated["freshness_status"] == "live_checked"
    assert hydrated["live_monitored_count"] >= 1
    assert hydrated["address_states"]
    assert hydrated["address_states"][0]["live_states"][0]["balance_native"] == 1.0


def test_fetch_explorer_activity_prefers_recent_api_signal():
    address = "0x1111111111111111111111111111111111111111"
    outbound_tx = "0x" + "a" * 64
    inbound_tx = "0x" + "b" * 64

    def fake_explorer_fetcher(url, timeout_sec):
        assert timeout_sec == 0.1
        if "blockscout" in url:
            return {
                "items": [
                    {
                        "timestamp": "2026-03-18T01:02:03Z",
                        "hash": inbound_tx,
                        "from": {"hash": "0x2222222222222222222222222222222222222222"},
                    },
                    {
                        "timestamp": "2026-03-17T01:02:03Z",
                        "hash": outbound_tx,
                        "from": {"hash": address},
                    },
                ]
            }
        return {"status": "0", "result": []}

    activity = hydrator.fetch_explorer_activity(
        address,
        ["base"],
        timeout_sec=0.1,
        fetcher=fake_explorer_fetcher,
    )

    assert activity["last_activity_utc"] == "2026-03-18T01:02:03Z"
    assert activity["last_seen_tx_hash"] == inbound_tx
    assert activity["last_outbound_tx"] == outbound_tx
    assert activity["activity_source"] == "explorer_api"
    assert activity["activity_chain"] == "base"


def test_fetch_explorer_html_activity_extracts_sent_tx_and_timestamp():
    address = "0x1111111111111111111111111111111111111111"
    outbound_tx = "0x" + "c" * 64

    def fake_html_fetcher(url, timeout_sec):
        assert timeout_sec == 0.1
        if "/address/" in url:
            return f'''
                <html>
                  <div><h4>Transactions Sent</h4>
                    <span>Latest:</span>
                    <a href="/tx/{outbound_tx}" class="link-dark">latest</a>
                  </div>
                </html>
            '''
        return """
            <html>
              <div>Timestamp</div>
              <span>Dec-02-2024 11:42:33 AM +UTC</span>
            </html>
        """

    activity = hydrator.fetch_explorer_html_activity(
        address,
        ["base"],
        timeout_sec=0.1,
        fetcher=fake_html_fetcher,
    )

    assert activity["last_activity_utc"] == "2024-12-02T11:42:33Z"
    assert activity["last_seen_tx_hash"] == outbound_tx
    assert activity["last_outbound_tx"] == outbound_tx
    assert activity["activity_source"] == "explorer_html"
    assert activity["activity_chain"] == "base"


def test_build_lead_packet_is_action_ready():
    case = {
        "case_id": "YEI-TEST",
        "title": "Yei Test",
        "tier1_lead": {"label": "kucoin_kyc_link", "reason": "KYC pivot"},
        "address_states": [{"address": "0xabc"}],
        "freshness_status": "live_checked",
        "live_monitored_count": 1,
        "scorecard_total": 4500,
        "target_6000_gap": 1500,
        "target_10000_gap": 5500,
    }

    packet = lead_packets.build_lead_packet(case)

    assert packet["disclosure_target"].lower().startswith("kucoin")
    assert packet["addresses_of_interest"] == ["0xabc"]
    assert packet["why_now"]
    assert packet["execution_priority"]["label"] in {"high", "medium", "low"}
    assert packet["execution_priority"]["target_score"] == 10000
    assert packet["recoverability"]["label"] in {"high", "medium", "low"}
    assert packet["disclosure_readiness"]["status"] in {"ready", "monitor"}
    assert packet["monetization_potential"]["trend"] in {"improving", "stale"}


def test_scorecard_axes_expose_remaining_two_axis_upside():
    payload = miner.build_case_payload(ROOT / "reports" / "case_study_yei_finance_v1.md")

    axes = payload["scorecard"]["axes"]

    assert axes["artifact_ops"]["integration_status"] == "integrated"
    assert axes["live_intel"]["upside"] >= 0
    assert axes["action_economics"]["upside"] >= 0
    assert payload["scorecard"]["remaining_axis_upside"] == (
        axes["live_intel"]["upside"] + axes["action_economics"]["upside"]
    )


def test_validator_accepts_snapshot_and_lead_packets(tmp_path):
    payload = miner.build_case_payload(ROOT / "reports" / "case_study_abracadabra_v1.md")
    base_row = manifest_builder.build_case_row(payload, "2026-03-18T00:00:00Z")

    def fake_fetcher(endpoint, method, params, timeout_sec):
        return {"result": hex(0)}

    snapshot = {
        "generated_at_utc": "2026-03-18T00:00:00Z",
        "case_count": 1,
        "cases": [
            hydrator.hydrate_case_row(
                base_row,
                payload,
                "2026-03-18T00:00:00Z",
                timeout_sec=0.1,
                fetcher=fake_fetcher,
            )
        ],
    }
    snapshot_path = tmp_path / "current_state_snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    lead_dir = tmp_path / "lead_packets"
    lead_dir.mkdir()
    packet = lead_packets.build_lead_packet(snapshot["cases"][0])
    (lead_dir / "ABRA.json").write_text(json.dumps(packet, ensure_ascii=False, indent=2), encoding="utf-8")

    assert validator.validate_snapshot(snapshot_path) == []
    assert validator.validate_lead_packets(lead_dir) == []


def test_reconcile_operational_scores_pushes_partial_axes_up():
    payload = miner.build_case_payload(ROOT / "reports" / "case_study_yei_finance_v1.md")
    original_closure = payload["scorecard"]["dimensions"]["fund_flow_closure"]
    original_attribution = payload["scorecard"]["dimensions"]["attribution_leverage"]
    original_freshness = payload["scorecard"]["dimensions"]["freshness"]
    original_comparative = payload["scorecard"]["dimensions"]["comparative_intelligence"]
    original_reproducibility = payload["scorecard"]["dimensions"]["reproducibility"]
    original_legal = payload["scorecard"]["dimensions"]["legal_operational_packaging"]

    snapshot_case = {
        "freshness_status": "live_checked",
        "live_monitored_count": 3,
        "live_attempted_count": 3,
        "address_states": [
            {
                "address": "0x1",
                "last_activity_utc": "2026-03-18T00:00:00Z",
                "last_outbound_tx": "0xabc",
                "activity_source": "explorer_api",
                "live_states": [{"status": "live_balance_ok"}],
            },
            {
                "address": "0x2",
                "last_activity_utc": None,
                "last_outbound_tx": None,
                "live_states": [{"status": "rpc_error"}],
            },
        ],
    }
    packet = {
        "case_id": payload["case_id"],
        "disclosure_target": "KuCoin compliance / law-enforcement liaison",
        "addresses_of_interest": ["0x1", "0x2"],
        "why_now": "2 monitored addresses were checked in the latest snapshot.",
        "tier1_lead": {"label": "kucoin_kyc_link"},
        "execution_priority": {"score": 1000, "label": "high"},
        "recoverability": {"score": 100, "label": "high"},
        "disclosure_readiness": {"support_strength": 80, "status": "ready"},
        "monetization_potential": {"score": 100, "trend": "improving"},
    }
    reanalysis_payload = {
        "sections": [
            {"body": "No behavioral drift detected. Baseline Comparison."},
            {
                "body": (
                    "run_osint_reanalysis.py\ncompare_reanalysis_reports.py\n"
                    "Evidence logs | api_log.jsonl |\n"
                    "Event count | Flows out | Flows in |\n"
                    "Analysis window | 2021-01-01T00:00:00Z -> 2026-03-16T00:00:00Z |\n"
                    "Immutable references | SHA256 | SHA256 | SHA256 | SHA256 |\n"
                    "drift_count = 0\n"
                )
            },
        ]
    }

    updated = reconcile_scores.reconcile_payload(payload, snapshot_case, packet, reanalysis_payload)

    assert updated["scorecard"]["dimensions"]["fund_flow_closure"] > original_closure
    assert updated["scorecard"]["dimensions"]["attribution_leverage"] > original_attribution
    assert updated["scorecard"]["dimensions"]["freshness"] > original_freshness
    assert updated["scorecard"]["dimensions"]["comparative_intelligence"] > original_comparative
    assert updated["scorecard"]["dimensions"]["legal_operational_packaging"] > original_legal
    assert updated["scorecard"]["axes"]["live_intel"]["integration_status"] in {"high-partial", "integrated"}
    assert updated["scorecard"]["axes"]["action_economics"]["integration_status"] in {"high-partial", "integrated"}
    assert updated["scorecard"]["dimensions"]["reproducibility"] > original_reproducibility


def test_dossier_bonus_uses_typed_live_coverage_as_primary_signal():
    dossier = {
        "coverage_components": {"artifact_ops": 800, "live_intel": 100},
        "section_coverage": 900,
        "evidence_chain_coverage": 1000,
        "reanalysis_linkage_coverage": 800,
        "last_activity_coverage": 900,
        "last_outbound_coverage": 800,
        "address_state_coverage": 700,
        "dossier_completeness": {
            "has_html_artifact": True,
            "has_snapshot": True,
            "has_lead_packet": True,
            "has_linked_reanalysis": True,
            "section_count": 8,
        },
        "report_artifacts": {"html_artifact": {"healthy": True}},
    }

    bonus = reconcile_scores.dossier_bonus(dossier)

    assert bonus["freshness"] >= 130
    assert bonus["fund_flow_closure"] >= 120
    assert bonus["comparative_intelligence"] >= 120
    assert bonus["provenance"] >= 220
    assert bonus["cross_case_schema"] >= 240
