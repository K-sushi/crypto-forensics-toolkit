#!/usr/bin/env python3
"""Etherscan V2 multi-chain data collector with evidence preservation.

Collects normal transactions and token transfers for specified addresses
across multiple EVM chains. All API responses are SHA256-hashed and logged
for forensic evidence preservation.

Usage:
    export ETHERSCAN_API_KEY=your_key
    python data_collector.py

Configure CASE_NAME, ADDRESSES, and CHAIN_IDS before running.
Free tier supports: Ethereum (1), Arbitrum (42161), Polygon (137), Sei (1329).
"""
import sys, os, json, time, hashlib, urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(line_buffering=True)

# =====================================================================
# CONFIGURATION — Edit these for each case
# =====================================================================

CASE_NAME = "EXAMPLE_CASE"
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"

# Chain IDs for Etherscan V2 (single API key for all chains)
CHAIN_IDS = {
    "ethereum": 1,
    "arbitrum": 42161,
    "polygon": 137,
    "sei": 1329,
    # Paid tier ($199/mo): "bsc": 56, "base": 8453, "optimism": 10
}

# Addresses to investigate: label -> (address, chain)
ADDRESSES = {
    "example_wallet_eth": ("0x0000000000000000000000000000000000000000", "ethereum"),
    # Add more addresses here
}

# Known legitimate tokens (spam filter whitelist)
LEGIT_TOKENS = {
    "USDC", "USDT", "DAI", "WETH", "WBTC", "ETH", "BNB", "WBNB",
    "USDC.e", "USDT.e", "DAI.e", "ARB", "OP", "MATIC",
}

# Spam keywords for token name filtering
SPAM_KW = {"visit", "claim", "reward", "airdrop", ".xyz", ".io", ".com", ".net", ".pro"}

# =====================================================================
# EVIDENCE PRESERVATION
# =====================================================================

evidence_dir = Path("evidence")
evidence_dir.mkdir(exist_ok=True)
log_path = evidence_dir / "{}_api_log.jsonl".format(CASE_NAME.lower())


def preserve(url_redacted, params_redacted, data, status):
    """Hash and log every API response for forensic admissibility."""
    response_hash = hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "url": url_redacted,
        "params": params_redacted,
        "response_sha256": response_hash,
        "response_status": status,
        "result_count": (
            len(data.get("result", []))
            if isinstance(data.get("result"), list)
            else 0
        ),
    }
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return response_hash


# =====================================================================
# API CLIENT
# =====================================================================


def api(chain, params):
    """Call Etherscan V2 API with retry, rate limiting, and evidence preservation."""
    cid = CHAIN_IDS.get(chain)
    if not cid:
        return []
    params["chainid"] = cid
    if ETHERSCAN_API_KEY:
        params["apikey"] = ETHERSCAN_API_KEY
    qs = "&".join("{}={}".format(k, v) for k, v in params.items())
    url = "{}?{}".format(ETHERSCAN_V2_BASE, qs)
    params_redacted = {k: v for k, v in params.items() if k != "apikey"}
    url_redacted = (
        url.replace(ETHERSCAN_API_KEY, "REDACTED") if ETHERSCAN_API_KEY else url
    )
    for attempt in range(3):
        try:
            time.sleep(0.3)  # Rate limit: ~3 req/sec
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            preserve(url_redacted, params_redacted, data, data.get("status"))
            if data.get("status") == "1":
                return data.get("result", [])
            elif data.get("message") == "No transactions found":
                return []
            else:
                print(
                    "    [API: {} chain={}]".format(data.get("message", "?"), chain)
                )
                return []
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
            else:
                print("    [FAIL: {}]".format(str(e)[:60]))
    return []


# =====================================================================
# DATA COLLECTION
# =====================================================================


def collect():
    """Collect all transactions for configured addresses."""
    all_tx = []
    for label, (addr, chain) in ADDRESSES.items():
        print("Collecting {} ({} on {})...".format(label, addr[:12], chain))

        # Normal transactions
        txs = api(
            chain,
            {
                "module": "account",
                "action": "txlist",
                "address": addr,
                "startblock": "0",
                "endblock": "99999999",
                "sort": "asc",
            },
        )
        native = {"sei": "SEI", "polygon": "MATIC"}.get(chain, "ETH")
        for tx in txs:
            ts = int(tx.get("timeStamp", 0))
            func = tx.get("functionName", "").split("(")[0] or "transfer"
            val = int(tx.get("value", "0")) / 1e18
            d = "OUT" if tx.get("from", "").lower() == addr.lower() else "IN"
            all_tx.append(
                (ts, "{} {} ({})".format(d, func, label), val, native)
            )

        # Token transfers (with spam filter)
        tokens = api(
            chain,
            {
                "module": "account",
                "action": "tokentx",
                "address": addr,
                "startblock": "0",
                "endblock": "99999999",
                "sort": "asc",
            },
        )
        for tx in tokens:
            ts = int(tx.get("timeStamp", 0))
            sym = tx.get("tokenSymbol", "?")
            tn = tx.get("tokenName", "").lower()
            dec = int(tx.get("tokenDecimal", "18"))
            val = int(tx.get("value", "0")) / (10**dec) if dec > 0 else 0
            if any(kw in tn for kw in SPAM_KW):
                continue
            if any(kw in sym.lower() for kw in SPAM_KW):
                continue
            if sym not in LEGIT_TOKENS and not sym.isascii():
                continue
            d = "OUT" if tx.get("from", "").lower() == addr.lower() else "IN"
            func = tx.get("functionName", "").split("(")[0] or "transfer"
            all_tx.append(
                (ts, "{} {} {} ({})".format(d, func, sym, label), val, sym)
            )

        print("  {} normal + {} token tx".format(len(txs), len(tokens)))

    all_tx.sort(key=lambda x: x[0])
    print("\nTotal: {} transactions collected".format(len(all_tx)))

    # Evidence summary
    if log_path.exists():
        with open(log_path) as f:
            entries = f.readlines()
        print("\nEvidence log: {}".format(log_path))
        print("API calls recorded: {}".format(len(entries)))
        if entries:
            last = json.loads(entries[-1])
            print("Last hash: {}...".format(last["response_sha256"][:24]))

    return all_tx


if __name__ == "__main__":
    if not ETHERSCAN_API_KEY:
        print("ERROR: Set ETHERSCAN_API_KEY environment variable")
        sys.exit(1)
    collect()
