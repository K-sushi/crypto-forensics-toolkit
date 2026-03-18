# Report Structure Miner

`report_structure_miner.py` parses markdown case studies into machine-readable
artifacts for threat-preintelligence pipelines.

## What it produces

- `artifacts/structured_reports/<case_id>.json`
  - Sectionized report text
  - Extracted event candidates (timestamps, tx hashes, addresses, amounts)
  - Feature vector for model ingestion (`CV`, bridge/custody signals, failures, etc.)
- `artifacts/feature_summary.json`
  - Cross-case feature comparison from all processed reports

## Basic usage

```powershell
python scripts/report_structure_miner.py --reports-dir reports --out-dir artifacts/structured_reports --compare-out artifacts/feature_summary.json
```

## Notes

- This is a heuristic first-pass extractor for Phase 0.
- It is intentionally lightweight and avoids external dependencies.
- Next phase should replace heuristic event extraction with parser bindings and schema tests.
