# Case Study: Yei Finance Flash Loan Exploit ($2.4M) - v2 Re-analysis

**Analysis mode:** automated re-analysis with `run_osint_reanalysis.py`  
**Date (UTC):** 2026-03-17  
**Scope:** Yei Finance incident only (no modifications to v1 report)

---

## 1. Executive Summary

The v2 run re-collects and re-runs OSINT analysis for the same Yei Finance case using the current
pipeline and compares it against the existing baseline case (`yei_reanalysis_20260318`).

- Outcome: **No behavioral drift detected at the aggregate score/signal level**.
- Core risk signal score remains `45.0`.
- Event volume remains `11073`.
- Core temporal profile remains unchanged (`duration_hours=23177.6667`, `timeline_cv=12.1981`).

---

## 2. Re-analysis Execution

| Item | Value |
|:---|:---|
| Source case | `reports/case_study_yei_finance_v1.md` |
| Case dir | `artifacts/osint_runs/yei_reanalysis_20260318_v5` |
| Manifest | `artifacts/osint_runs/yei_reanalysis_20260318_v5/manifest.json` |
| Analysis | `artifacts/osint_runs/yei_reanalysis_20260318_v5/analysis.json` |
| Batch report | `artifacts/osint_runs/batch_reanalysis_report_yei_v5.json` |
| API key mode | `ETHERSCAN_API_KEY` provided (external) |
| Targets extracted | `19` |
| Targets used | `16` |
| Targets filtered (unsupported chains) | `3` |
| Collected events | `11073` |
| Evidence logs | `evidence/yei_reanalysis_20260318_v5_api_log.jsonl` |

---

## 3. Re-analysis Results

### 3.1 Aggregate indicators

| Metric | Value |
|:---|:---|
| Score | `45.0` |
| Event count | `11073` |
| Flows out | `5463` |
| Flows in | `5610` |
| Out/In ratio | `0.9738` |
| Event duration (hours) | `23177.6667` |

### 3.2 Signals

| Signal | Value | Evidence |
|:---|---:|:---|
| `high_value_tail` | `55.32632324186458` | top 5% threshold = 55.32632324 |
| `round_batch_hits` | `157` | integer round multiples observed |
| `burst_windows` | `5` | windowed event concentration above dynamic threshold |
| `timeline_cv` | `12.1980999746533` | inter-arrival CV (minutes) |

### 3.3 Top activity prefixes (first 5)

| Prefix | Count |
|:---|---:|
| `IN transfer (target_010)` | `5123` |
| `OUT transfer (target_010)` | `4432` |
| `OUT batchTransferEther (target_010)` | `445` |
| `OUT setVestingSchedule (target_019)` | `79` |
| `IN transfer (target_006)` | `54` |

---

## 4. Baseline Comparison

Compared with the existing baseline directory `yei_reanalysis_20260318`:

- `score`: `45.0` -> `45.0` (delta `0.0`)
- `event_count`: `11073` -> `11073` (delta `0`)
- `signal count`: `4` -> `4` (delta `0`)
- `timeline_cv`: `12.1980999746533` -> `12.1980999746533` (delta `0`)
- Baseline compare artifact: `artifacts/osint_runs/reanalysis_drift_report_yei_v5_vs_ci_yei_only.json`

**Conclusion:** This v2 run is reproducible against current extractor settings.

---

## 5. Notes

- This file is an **independent v2 artifact** and does not modify any existing v1 report files.
- Re-running with a different `case-name` would create another independent rerun branch.

## 6. Audit Reproducibility Ledger (Execution Trail)

### Command set used for this rerun

```powershell
$env:ETHERSCAN_API_KEY='<set this environment variable>'
python scripts/run_osint_reanalysis.py --report-path reports/case_study_yei_finance_v1.md --case-name yei_reanalysis_20260318_v5 --collect --analyze
python scripts/run_batch_osint_reanalysis.py --case-dir artifacts/osint_runs/yei_reanalysis_20260318_v5 --out-report artifacts/osint_runs/batch_reanalysis_report_yei_v5.json --smart --force-reprocess
python scripts/compare_reanalysis_reports.py --base-report artifacts/osint_runs/batch_reanalysis_report_ci_yei_only.json --current-report artifacts/osint_runs/batch_reanalysis_report_v5_norm.json --out-report artifacts/osint_runs/reanalysis_drift_report_yei_v5_vs_ci_yei_only.json
```

### Immutable references

| Artifact | SHA256 |
|:---|:---|
| `artifacts/osint_runs/yei_reanalysis_20260318_v5/manifest.json` | `C0F31CC3AFA07D10B01F1F7B9575F3352DA592B5328B511C48995470DD3022C1` |
| `artifacts/osint_runs/yei_reanalysis_20260318_v5/analysis.json` | `5E1E2DD273A48C4A7810662B16EDF53CF596356B3AB486A7C6EF0109474FCD53` |
| `artifacts/osint_runs/yei_reanalysis_20260318_v5/collected_events.jsonl` | `4373DB777640F0F295AF4361B42D29F70141AAB48D449158C9D8FDC4099E9989` |
| `evidence/yei_reanalysis_20260318_v5_api_log.jsonl` | `6956EA95136949A70C6BB83E56EC31AB655AD29C3A46DBFC6B0F8AE996FFE09A` |

### Required verification check

- Drift check pass condition: `drift_count == 0`
- Current result: `drift_count = 0`

