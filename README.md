# Crypto Forensics Toolkit

Independent blockchain forensics analysis for DeFi exploit investigations.
Focused on deep behavioral profiling and evidence-preserving methodologies.

## What This Is

Most public exploit analyses focus on *how* the vulnerability was exploited.
This toolkit produces analyses that also answer:

- Who is the attacker? (human vs bot, timezone, cognitive patterns)
- Where did the funds go? (cross-chain tracing, mixer analysis, CEX touchpoints)
- What is recoverable? (triage scorecard with disposition percentages)
- What is novel? (delta analysis vs existing public reports)

Each case study is structured for legal admissibility: SHA256-hashed API responses,
UTC timestamps, reproducible methodology, and clear confidence ratings.

## Case Studies

### 1. Abracadabra Finance $13M gmCauldron Exploit (March 2025)

**Key novel findings (not in existing public analyses):**
- Tornado Cash sanctions lifted March 21, exploit March 25 (4-day correlation)
- Behavioral CV = 1.978 across 248 transactions
- Timezone estimation: UTC+5/+6 (Central/South Asia)
- Base-10 cognitive style (500/1000 ETH round batches)
- October 2025 attacker ruled out as same actor (0 address overlap)
- `AtInverseBrah` contract function indicates crypto-culture reference

> [Full Report (Markdown)](reports/case_study_abracadabra_v1.md) | [Full Report (HTML)](reports/case_study_abracadabra_v1.html)

### 2. Yei Finance $2.4M Serial Exploiter (2024-2025)

**Key novel findings:**
- KuCoin KYC linkage identified (2025-02-15 15:43:47 UTC deposit)
- Serial exploiter confirmed: 5+ incidents, $20M+ total
- `safe-relayer.eth` ENS connection to zkLend phishing
- Behavioral CV = 1.387 (Human)
- Timezone: UTC+2~+3 (Eastern Europe)

> [Full Report (Markdown)](reports/case_study_yei_finance_v1.md) | [Full Report (HTML)](reports/case_study_yei_finance_v1.html)

## Comparative Analysis

| Factor | Yei Finance | Abracadabra |
|:---|:---|:---|
| Amount | $2.4M | $13M |
| CV (Human?) | 1.387 (Human) | 1.978 (Human) |
| Timezone | UTC+2~+3 | UTC+5~+6 |
| CEX Linkage | KuCoin (Yes) | None |
| Serial Exploiter? | 5+ incidents | Single incident |
| Laundering | TC + Railgun | TC only |
| OPSEC Level | Medium | High |

## Data Collection

The `templates/` directory contains a basic data collection script for Etherscan V2 API:

- Multi-chain transaction collection
- Token transfer collection with spam filtering
- SHA256 evidence preservation (API response hashing)

**Note:** This template collects data only. The analytical framework and report generation
pipeline are proprietary.

## Evidence Standard

All API responses are SHA256-hashed and logged in JSONL format with UTC timestamps,
API key redaction, response status codes, and result counts.

## Reanalysis Drift Checks

```powershell
python scripts/compare_reanalysis_reports.py `
  --base-report artifacts/osint_runs/batch_reanalysis_report_ci.json `
  --current-report artifacts/osint_runs/batch_reanalysis_report_ci_current.json `
  --max-event-delta 0.05 `
  --max-score-delta 2.0 `
  --max-signal-delta 1 `
  --strict-status
```

## Operations

### Baseline refresh (one-line operation)

```powershell
python scripts/run_batch_osint_reanalysis.py --osint-runs-dir artifacts/osint_runs --case-dir abra_reanalysis_20260318 --case-dir yei_reanalysis_20260318 --smart --out-report artifacts/osint_runs/batch_reanalysis_report_ci_current.json; Copy-Item artifacts/osint_runs/batch_reanalysis_report_ci_current.json artifacts/osint_runs/batch_reanalysis_report_ci.json -Force
```

## Methodology

Reports follow a structured multi-phase pipeline:
1. Incident Intake: public report aggregation and verification
2. Address Verification: on-chain balance and transaction confirmation
3. Fund Flow Reconstruction: cross-chain tracing with bridge decode
4. Behavioral Profiling: human/bot classification, timezone, cognitive analysis
5. Attribution OSINT: off-chain identity stitching, cross-incident analysis
6. Report Generation: structured format with confidence ratings and evidence chain

## Contact

For forensics engagement inquiries: [TBD]

## License

Reports and data: [CC BY-NC 4.0](LICENSE). Commercial engagements available.

