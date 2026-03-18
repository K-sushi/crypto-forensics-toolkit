# Case Study: Abracadabra gmETH Exploit ($13M) - v2 Re-analysis

**Analysis mode:** automated re-analysis with `run_osint_reanalysis.py`  
**Date (UTC):** 2026-03-17  
**Scope:** Abracadabra incident only (no modifications to v1 report)

---

## 1. Executive Summary

The v2 run re-collects and re-runs OSINT analysis for the same Abracadabra incident using the current
pipeline and compares it against the existing baseline case (`abra_reanalysis_20260318`).

- Outcome: **No behavioral drift detected at the aggregate score/signal level**.
- Core risk signal score remains `45.0`.
- Event volume remains `13,895`.
- Core temporal profile remains unchanged (`duration_hours=38739.9117`, `timeline_cv=10.0599`).

---

## 2. Re-analysis Execution

| Item | Value |
|:---|:---|
| Source case | `reports/case_study_abracadabra_v1.md` |
| Case dir | `artifacts/osint_runs/abra_reanalysis_20260318_v5` |
| Manifest | `artifacts/osint_runs/abra_reanalysis_20260318_v5/manifest.json` |
| Analysis | `artifacts/osint_runs/abra_reanalysis_20260318_v5/analysis.json` |
| Batch report | `artifacts/osint_runs/batch_reanalysis_report_abr_v5.json` |
| API key mode | `ETHERSCAN_API_KEY` provided (external) |
| Targets extracted | `30` |
| Targets used | `30` |
| Targets filtered (unsupported chains) | `0` |
| Collected events | `13895` |
| Evidence logs | `evidence/abra_reanalysis_20260318_v5_api_log.jsonl` |
| Analysis window | `2021-10-14T19:24:53Z` → `2026-03-16T23:19:35Z` |

---

## 3. Re-analysis Results

### 3.1 Aggregate indicators

| Metric | Value |
|:---|:---|
| Score | `45.0` |
| Event count | `13895` |
| Flows out | `4815` |
| Flows in | `9080` |
| Out/In ratio | `0.5303` |
| Event duration (hours) | `38739.9117` |

### 3.2 Signals

| Signal | Value | Evidence |
|:---|---:|:---|
| `high_value_tail` | `2369347.609792` | top 5% threshold = 2369347.60979200 |
| `round_batch_hits` | `1508` | integer round multiples observed |
| `burst_windows` | `5` | windowed event concentration above dynamic threshold |
| `timeline_cv` | `10.059904687200973` | inter-arrival CV (minutes) |

### 3.3 Top activity prefixes (first 5)

| Prefix | Count |
|:---|---:|
| `IN cook USTC (target_030)` | `3607` |
| `OUT cook MIM (target_030)` | `2848` |
| `IN withdraw (target_030)` | `1629` |
| `IN cook SPELL (target_030)` | `1062` |
| `IN cook MIM (target_013)` | `158` |

---

## 4. Baseline Comparison

Compared with the existing baseline directory `abra_reanalysis_20260318`:

- `score`: `45.0` -> `45.0` (delta `0.0`)
- `event_count`: `13895` -> `13895` (delta `0`)
- `signal count`: `4` -> `4` (delta `0`)
- `timeline_cv`: `10.059904687200973` -> `10.059904687200973` (delta `0`)
- Baseline compare artifact: `artifacts/osint_runs/reanalysis_drift_report_abr_v5_vs_ci_abr_only.json`

**Conclusion:** This v2 run is reproducible against current extractor settings.

---

## 5. Audit Reproducibility Ledger (Execution Trail)

### Command set used for this rerun

```powershell
$env:ETHERSCAN_API_KEY = "<set this environment variable>"
python scripts/run_osint_reanalysis.py --report-path reports/case_study_abracadabra_v1.md --case-name abra_reanalysis_20260318_v5 --collect --analyze
python scripts/run_batch_osint_reanalysis.py --case-dir artifacts/osint_runs/abra_reanalysis_20260318_v5 --out-report artifacts/osint_runs/batch_reanalysis_report_abr_v5.json --smart --force-reprocess
python scripts/compare_reanalysis_reports.py --base-report artifacts/osint_runs/batch_reanalysis_report_ci_abr_only.json --current-report artifacts/osint_runs/batch_reanalysis_report_abr_v5_norm.json --out-report artifacts/osint_runs/reanalysis_drift_report_abr_v5_vs_ci_abr_only.json
```

### Immutable references

| Artifact | SHA256 |
|:---|:---|
| `artifacts/osint_runs/abra_reanalysis_20260318_v5/manifest.json` | `E05DAFA1C0F5E3A88D3A93402BC4C087EFDA621AA2E3F2E1E6C9B82D7D355409` |
| `artifacts/osint_runs/abra_reanalysis_20260318_v5/analysis.json` | `0324A5B9BF3D91A249C6E46DEFBCA4D7AA081B3982C58BAEA5FE78AA4F70A748` |
| `artifacts/osint_runs/abra_reanalysis_20260318_v5/collected_events.jsonl` | `006CBAEA308AC0EA39D895F353EBB5511EB163F707C292A3CDA8E57111BF795F` |
| `evidence/abra_reanalysis_20260318_v5_api_log.jsonl` | `6E85831611438B7803DE95010FC223563D97FEF7DFF64717352E8AEB678780D3` |

### Required verification check

- Drift check pass condition: `drift_count == 0`
- Current result: `drift_count = 0`
