# Report Structure Miner Roadmap (v1.2+)

This roadmap is the first execution artifact for the next wave.  
All work must follow this order: **specify → validate → implement → measure**.

## Scope
- Pipeline: `scripts/report_structure_miner.py`
- Inputs: Markdown case studies under `reports/*.md`
- Outputs: `artifacts/structured_reports/*.json` and `artifacts/feature_summary.json`

## Phase 0 — Contract Lock (current)
Goal: freeze data contract and validation gates before any feature expansion.

### Deliverables
1. Version policy
   - New changes require bumping `schema_version`.
   - Backward compatibility policy: add fields only; change semantics only on major schema bump.
2. Quality gates
   - `schema_version` must be present.
   - `validation.raw_events > 0`
   - `validation.deduped_events >= validation.raw_events * 0.6`
   - `validation.event_ratio >= 0.05`  
   - `validation.passes_signal_gate` is persisted.
3. Output contract
   - `events`: must include `event_id`, `section`, `line_no`, `timestamp`, `confidence`, `signals`, `context`.
   - `features.feature_vector`: must include at least the existing baseline keys  
     `cv_max`, `event_count`, `timeline_points`, `bridge_signal_count`, `risk_score`.
   - `features.timeline`: include `median_gap_min`.
   - `validation`: include `raw_events`, `deduped_events`, `event_ratio`, `line_ratio`, `risk_score`, `passes_signal_gate`.
4. Reproducibility
   - `source_sha256` must always be present.
   - `comparison` output must retain `scores` and `pairwise_delta`.

### Exit Criteria
- 2+ markdown reports process end-to-end without errors.
- At least one case passes `passes_signal_gate`.
- `README.md` updated to reflect v1.2 contract fields.

## Phase 1 — Quality Baseline (next)
Goal: stabilize extraction quality with tests and regression checks.

### Deliverables
1. Minimal regression suite
   - Add a small script or test that checks:
     - output schema contains required keys above
     - `case_id` is extracted and cleaned
     - `event_count` increases/decreases in expected range for known fixtures
2. Sanity snapshot
   - Capture a stable baseline for current `feature_summary.json` keys and score ordering.

### Exit Criteria
- Full suite passes on local run.
- No decrease in signal density from the previous stable baseline (by `event_ratio` and `event_count`).

## Phase 2 — Signal Expansion
Goal: add one new signal per cycle and measure impact before any further expansion.

### Candidate Additions (in order)
1. Cross-linking: wallet co-occurrence graph from `events`.
2. Temporal consistency: gap anomaly detection score.
3. Section-weight tuning: adjust section-level multipliers and document rationale.

### Guardrail
- Each signal can ship only if at least one baseline metric improves:
  - `risk_tags` diversity, or
  - `passes_signal_gate` pass rate, or
  - manual review false-positive reduction.

## Stop Conditions
- A run fails schema gate 2 consecutive times without a measurable data-contract improvement.
- Feature score distribution shifts without documented rationale.
- Cross-report comparability breaks (missing baseline feature fields).

## One-Action Rule
At any point, only one phase may be active.  
No additional feature work starts before current phase exit criteria are satisfied.
