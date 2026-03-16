# Evidence Preservation

All forensic analyses include SHA256-hashed API response logs in JSONL format.

## Format

Each line in an evidence log file contains:

```json
{
  "timestamp_utc": "2026-03-16T12:00:00.000000+00:00",
  "url": "https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address=0x...&apikey=REDACTED",
  "params": {"module": "account", "action": "txlist", "address": "0x...", "chainid": 1},
  "response_sha256": "a1b2c3d4...",
  "response_status": "1",
  "result_count": 42
}
```

## Properties

- **Timestamps**: UTC, ISO 8601, second precision
- **API keys**: Always REDACTED in logs
- **Hashing**: SHA256 of full JSON response (sorted keys, UTF-8)
- **Reproducibility**: Any third party with the same API access can verify hashes

## Availability

Full evidence logs for each case study are available on request for legal proceedings.
