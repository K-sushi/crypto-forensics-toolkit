#!/usr/bin/env python3
"""Hydrate current-state manifest with lean live balance checks and address activity."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


RPC_ENDPOINTS = {
    "ethereum": [
        os.environ.get("RPC_ETHEREUM", "https://1rpc.io/eth"),
        "https://ethereum-rpc.publicnode.com",
    ],
    "arbitrum": [
        os.environ.get("RPC_ARBITRUM", "https://1rpc.io/arb"),
        "https://arbitrum-one-rpc.publicnode.com",
    ],
    "base": [
        os.environ.get("RPC_BASE", "https://1rpc.io/base"),
        "https://base-rpc.publicnode.com",
    ],
    "bsc": [
        os.environ.get("RPC_BSC", "https://1rpc.io/bnb"),
        "https://bsc-rpc.publicnode.com",
    ],
    "sei": [
        os.environ.get("RPC_SEI", "https://evm-rpc.sei-apis.com"),
    ],
}
CHAIN_ALIASES = {
    "ethereum": ("ethereum", "eth", "[eth]"),
    "arbitrum": ("arbitrum", "arb", "[arb]"),
    "base": ("base", "[base]"),
    "bsc": ("bsc", "bnb", "[bsc]"),
    "sei": ("sei", "[sei]"),
}
NATIVE_SYMBOL = {
    "ethereum": "ETH",
    "arbitrum": "ETH",
    "base": "ETH",
    "bsc": "BNB",
    "sei": "SEI",
}
EXPLORER_API_CONFIG = {
    "ethereum": {
        "url": "https://api.etherscan.io/v2/api",
        "key_env": ("ETHERSCAN_API_KEY",),
        "chainid": "1",
    },
    "arbitrum": {
        "url": "https://api.arbiscan.io/api",
        "key_env": ("ARBISCAN_API_KEY", "ETHERSCAN_API_KEY"),
        "chainid": "42161",
    },
    "base": {
        "url": "https://api.basescan.org/api",
        "key_env": ("BASESCAN_API_KEY", "ETHERSCAN_API_KEY"),
        "chainid": "8453",
    },
    "bsc": {
        "url": "https://api.bscscan.com/api",
        "key_env": ("BSCSCAN_API_KEY",),
        "chainid": "56",
    },
}
BLOCKSCOUT_API_CONFIG = {
    "ethereum": "https://eth.blockscout.com/api/v2/addresses/{address}/transactions",
    "arbitrum": "https://arbitrum.blockscout.com/api/v2/addresses/{address}/transactions",
    "base": "https://base.blockscout.com/api/v2/addresses/{address}/transactions",
}
EXPLORER_HTML_CONFIG = {
    "ethereum": "https://etherscan.io",
    "arbitrum": "https://arbiscan.io",
    "base": "https://basescan.org",
    "bsc": "https://bscscan.com",
}
TIMESTAMP_WITH_Z_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")
TIMESTAMP_UTC_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}(?::\d{2})?\s+UTC\b")
TX_HASH_RE = re.compile(r"\b0x[a-fA-F0-9]{64}\b")
EXPLORER_PAGE_TS_RE = re.compile(r"\b[A-Z][a-z]{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\s+[AP]M\s+(?:\+UTC|\(UTC\))\b")
LATEST_SENT_TX_RE = re.compile(
    r"Transactions Sent.*?Latest:.*?/tx/(0x[a-fA-F0-9]{64})",
    re.S,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest-path",
        default="artifacts/current_state_manifest.json",
        help="Path to current state manifest.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts/structured_reports",
        help="Directory containing structured report JSON files.",
    )
    parser.add_argument(
        "--out-path",
        default="artifacts/current_state_snapshot.json",
        help="Output path for hydrated snapshot.",
    )
    parser.add_argument(
        "--timeout-sec",
        type=float,
        default=8.0,
        help="Timeout for JSON-RPC requests.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_payloads(artifacts_dir: Path) -> Dict[str, Dict[str, Any]]:
    payloads = {}
    for path in sorted(artifacts_dir.glob("*.json")):
        payload = load_json(path)
        case_id = payload.get("case_id")
        if case_id:
            payloads[case_id] = payload
    return payloads


def explorer_api_key(chain: str) -> Optional[str]:
    config = EXPLORER_API_CONFIG.get(chain)
    if not config:
        return None
    for env_name in config["key_env"]:
        value = os.environ.get(env_name)
        if value:
            return value
    return None


def normalize_chain(name: str) -> Optional[str]:
    lowered = name.lower()
    for canonical, aliases in CHAIN_ALIASES.items():
        if any(alias in lowered for alias in aliases):
            return canonical
    return None


def detect_chains(text: str) -> List[str]:
    lowered = text.lower()
    detected = []
    for canonical, aliases in CHAIN_ALIASES.items():
        if any(alias in lowered for alias in aliases):
            detected.append(canonical)
    return detected


def infer_address_chains(payload: Dict[str, Any]) -> Dict[str, List[str]]:
    chain_map: Dict[str, List[str]] = {}

    def add(addr: str, chain: str) -> None:
        chain_map.setdefault(addr, [])
        if chain not in chain_map[addr]:
            chain_map[addr].append(chain)

    for event in payload.get("events", []):
        addresses = event.get("addresses", [])
        text_parts = [event.get("source", "")]
        text_parts.extend(event.get("context", []))
        text_parts.append(event.get("section", ""))
        merged = " ".join(part for part in text_parts if part)
        chains = detect_chains(merged)
        if not chains:
            continue
        for addr in addresses:
            for chain in chains:
                add(addr, chain)

    for section in payload.get("sections", []):
        body = " ".join(
            part for part in (section.get("title", ""), section.get("body", "")) if part
        )
        chains = detect_chains(body)
        if not chains:
            continue
        for addr in payload.get("features", {}).get("entities", {}).get("unique_addresses", []):
            if addr in body:
                for chain in chains:
                    add(addr, chain)

    for addr in payload.get("features", {}).get("entities", {}).get("unique_addresses", []):
        chain_map.setdefault(addr, [])

    return chain_map


def parse_event_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if "T" in text:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%b-%d-%Y %I:%M:%S %p (UTC)", "%b-%d-%Y %I:%M:%S %p +UTC"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def isoformat_utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


def parse_section_timestamp(line: str) -> Optional[str]:
    for pattern in (TIMESTAMP_WITH_Z_RE, TIMESTAMP_UTC_RE, EXPLORER_PAGE_TS_RE):
        match = pattern.search(line)
        if match:
            ts = parse_event_time(match.group(0))
            if ts:
                return isoformat_utc(ts)
    return None


def scan_sections_for_address(payload: Dict[str, Any], address: str) -> Dict[str, Optional[str]]:
    address_lower = address.lower()
    best_time: Optional[str] = None
    best_tx: Optional[str] = None
    for section in payload.get("sections", []):
        for line in section.get("lines", []):
            clean = strip_html(line)
            if address_lower not in clean.lower():
                continue
            ts = parse_section_timestamp(clean)
            if ts:
                if not best_time or ts > best_time:
                    best_time = ts
            tx_match = TX_HASH_RE.search(clean)
            if tx_match:
                best_tx = tx_match.group(0)
    return {"last_activity_utc": best_time, "last_outbound_tx": best_tx}


def http_fetch_json(url: str, timeout_sec: float) -> Dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "crypto-forensics-toolkit/1.0"})
    with urlopen(request, timeout=timeout_sec) as response:
        return json.loads(response.read().decode("utf-8"))


def http_fetch_text(url: str, timeout_sec: float) -> str:
    request = Request(url, headers={"Accept": "text/html", "User-Agent": "Mozilla/5.0"})
    with urlopen(request, timeout=timeout_sec) as response:
        return response.read().decode("utf-8", "ignore")


def scan_sections_for_address(payload: Dict[str, Any], address: str) -> Dict[str, Optional[str]]:
    address_lower = address.lower()
    best_time: Optional[datetime] = None
    best_time_str: Optional[str] = None
    best_tx: Optional[str] = None
    for section in payload.get("sections", []):
        body = section.get("body", "")
        for line in body.splitlines():
            if address_lower not in line.lower():
                continue
            for ts_raw in TIMESTAMP_WITH_Z_RE.findall(line) + TIMESTAMP_UTC_RE.findall(line):
                ts = parse_event_time(ts_raw)
                if ts and (best_time is None or ts > best_time):
                    best_time = ts
                    best_time_str = isoformat_utc(ts)
            for tx_candidate in TX_HASH_RE.findall(line):
                if tx_candidate:
                    best_tx = tx_candidate
    return {
        "last_activity_utc": best_time_str,
        "activity_source": "section_scan" if best_time_str else None,
        "last_outbound_tx": best_tx,
    }


def latest_address_activity(payload: Dict[str, Any], address: str) -> Dict[str, Optional[str]]:
    latest_seen: Optional[datetime] = None
    latest_seen_raw: Optional[str] = None
    latest_tx: Optional[str] = None
    latest_outbound_tx: Optional[str] = None
    activity_source: Optional[str] = None

    for event in payload.get("events", []):
        if address not in event.get("addresses", []):
            continue
        ts_raw = event.get("timestamp")
        ts = parse_event_time(ts_raw)
        if ts and (latest_seen is None or ts > latest_seen):
            latest_seen = ts
            latest_seen_raw = isoformat_utc(ts)
            tx_hashes = event.get("tx_hashes", [])
            latest_tx = tx_hashes[0] if tx_hashes else None
            activity_source = "event_timeline"
            source = (event.get("source") or "").lower()
            if any(token in source for token in ("send", "transfer", "deposit", "withdraw", "bridge", "distribution")):
                latest_outbound_tx = latest_tx

    section_activity = scan_sections_for_address(payload, address)
    if section_activity["last_activity_utc"]:
        section_ts = parse_event_time(section_activity["last_activity_utc"])
        if section_ts and (latest_seen is None or section_ts > latest_seen):
            latest_seen = section_ts
            latest_seen_raw = section_activity["last_activity_utc"]
    if section_activity["last_outbound_tx"]:
        latest_outbound_tx = section_activity["last_outbound_tx"]

    section_activity = scan_sections_for_address(payload, address)
    if section_activity["last_activity_utc"]:
        section_ts = parse_event_time(section_activity["last_activity_utc"])
        if section_ts and (latest_seen is None or section_ts > latest_seen):
            latest_seen = section_ts
            latest_seen_raw = section_activity["last_activity_utc"]
            latest_tx = section_activity["last_outbound_tx"] or latest_tx
            activity_source = section_activity.get("activity_source")
    if section_activity["last_outbound_tx"]:
        latest_outbound_tx = section_activity["last_outbound_tx"]

    return {
        "last_activity_utc": latest_seen_raw,
        "last_seen_tx_hash": latest_tx,
        "last_outbound_tx": latest_outbound_tx,
        "activity_source": activity_source,
    }


def tx_hash_from_item(item: Dict[str, Any]) -> Optional[str]:
    for key in ("transaction_hash", "hash"):
        value = item.get(key)
        if isinstance(value, str) and TX_HASH_RE.fullmatch(value):
            return value
    return None


def tx_from_matches(item: Dict[str, Any], address: str) -> bool:
    address_lower = address.lower()
    from_field = item.get("from")
    candidates: List[str] = []
    if isinstance(from_field, dict):
        for key in ("hash", "address_hash"):
            value = from_field.get(key)
            if isinstance(value, str):
                candidates.append(value)
    elif isinstance(from_field, str):
        candidates.append(from_field)
    for key in ("from_address_hash", "from_address"):
        value = item.get(key)
        if isinstance(value, str):
            candidates.append(value)
    return any(candidate.lower() == address_lower for candidate in candidates)


def tx_timestamp(item: Dict[str, Any]) -> Optional[datetime]:
    for key in ("timestamp", "block_timestamp", "timestamp_iso8601"):
        value = item.get(key)
        ts = parse_event_time(value if isinstance(value, str) else None)
        if ts:
            return ts
    return None


def fetch_blockscout_activity(
    address: str,
    chain: str,
    timeout_sec: float,
    fetcher: Callable[[str, float], Dict[str, Any]],
) -> Dict[str, Optional[str]]:
    base_url = BLOCKSCOUT_API_CONFIG.get(chain)
    if not base_url:
        return {}
    url = f"{base_url.format(address=address)}?filter=to%20%7C%20from"
    payload = fetcher(url, timeout_sec)
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        return {}

    best_time: Optional[datetime] = None
    best_hash: Optional[str] = None
    best_outbound: Optional[str] = None
    for item in items:
        if not isinstance(item, dict):
            continue
        ts = tx_timestamp(item)
        tx_hash = tx_hash_from_item(item)
        if ts and (best_time is None or ts > best_time):
            best_time = ts
            best_hash = tx_hash
        if best_outbound is None and tx_hash and tx_from_matches(item, address):
            best_outbound = tx_hash

    if not best_time and not best_outbound and not best_hash:
        return {}
    return {
        "last_activity_utc": isoformat_utc(best_time) if best_time else None,
        "last_seen_tx_hash": best_hash,
        "last_outbound_tx": best_outbound,
        "activity_source": "explorer_api",
        "activity_chain": chain,
    }


def fetch_etherscan_activity(
    address: str,
    chain: str,
    timeout_sec: float,
    fetcher: Callable[[str, float], Dict[str, Any]],
) -> Dict[str, Optional[str]]:
    config = EXPLORER_API_CONFIG.get(chain)
    api_key = explorer_api_key(chain)
    if not config or not api_key:
        return {}
    query = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "sort": "desc",
        "page": 1,
        "offset": 10,
        "apikey": api_key,
    }
    if config.get("chainid"):
        query["chainid"] = config["chainid"]
    url = f"{config['url']}?{urlencode(query)}"
    payload = fetcher(url, timeout_sec)
    items = payload.get("result")
    if not isinstance(items, list) or not items:
        return {}

    best_time: Optional[datetime] = None
    best_hash: Optional[str] = None
    best_outbound: Optional[str] = None
    address_lower = address.lower()
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_ts = item.get("timeStamp")
        try:
            ts = datetime.fromtimestamp(int(raw_ts), tz=timezone.utc) if raw_ts is not None else None
        except (TypeError, ValueError, OSError):
            ts = None
        tx_hash = item.get("hash") if isinstance(item.get("hash"), str) else None
        if ts and (best_time is None or ts > best_time):
            best_time = ts
            best_hash = tx_hash
        from_address = item.get("from")
        if best_outbound is None and isinstance(from_address, str) and from_address.lower() == address_lower:
            best_outbound = tx_hash

    if not best_time and not best_outbound and not best_hash:
        return {}
    return {
        "last_activity_utc": isoformat_utc(best_time) if best_time else None,
        "last_seen_tx_hash": best_hash,
        "last_outbound_tx": best_outbound,
        "activity_source": "explorer_api",
        "activity_chain": chain,
    }


def fetch_explorer_activity(
    address: str,
    chains: Iterable[str],
    timeout_sec: float,
    fetcher: Callable[[str, float], Dict[str, Any]] = http_fetch_json,
) -> Dict[str, Optional[str]]:
    best: Dict[str, Optional[str]] = {}
    best_time: Optional[datetime] = None
    for chain in chains:
        for loader in (fetch_blockscout_activity, fetch_etherscan_activity):
            try:
                candidate = loader(address, chain, timeout_sec, fetcher)
            except (ValueError, URLError, TimeoutError, OSError, KeyError):
                continue
            if not candidate:
                continue
            candidate_time = parse_event_time(candidate.get("last_activity_utc"))
            if candidate.get("last_outbound_tx") and not best.get("last_outbound_tx"):
                best["last_outbound_tx"] = candidate["last_outbound_tx"]
            if candidate_time and (best_time is None or candidate_time > best_time):
                best_time = candidate_time
                best = candidate
            elif not best and candidate:
                best = candidate
    return best


def fetch_explorer_html_activity(
    address: str,
    chains: Iterable[str],
    timeout_sec: float,
    fetcher: Callable[[str, float], str] = http_fetch_text,
) -> Dict[str, Optional[str]]:
    for chain in chains:
        base_url = EXPLORER_HTML_CONFIG.get(chain)
        if not base_url:
            continue
        try:
            address_html = fetcher(f"{base_url}/address/{address}", timeout_sec)
        except (ValueError, URLError, TimeoutError, OSError):
            continue

        outbound_match = LATEST_SENT_TX_RE.search(address_html)
        tx_hash = outbound_match.group(1) if outbound_match else None
        if not tx_hash:
            any_tx = TX_HASH_RE.search(address_html)
            tx_hash = any_tx.group(0) if any_tx else None
        if not tx_hash:
            continue

        last_activity = None
        try:
            tx_html = fetcher(f"{base_url}/tx/{tx_hash}", timeout_sec)
            ts_match = EXPLORER_PAGE_TS_RE.search(tx_html)
            ts = parse_event_time(ts_match.group(0)) if ts_match else None
            if ts:
                last_activity = isoformat_utc(ts)
        except (ValueError, URLError, TimeoutError, OSError):
            last_activity = None

        return {
            "last_activity_utc": last_activity,
            "last_seen_tx_hash": tx_hash,
            "last_outbound_tx": tx_hash if outbound_match else None,
            "activity_source": "explorer_html",
            "activity_chain": chain,
        }
    return {}


def rpc_fetch(endpoint: str, method: str, params: List[Any], timeout_sec: float) -> Dict[str, Any]:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode("utf-8")
    request = Request(endpoint, data=body, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout_sec) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_live_address_state(
    address: str,
    chains: Iterable[str],
    timeout_sec: float,
    fetcher: Callable[[str, str, List[Any], float], Dict[str, Any]] = rpc_fetch,
) -> List[Dict[str, Any]]:
    states: List[Dict[str, Any]] = []
    for chain in chains:
        endpoints = RPC_ENDPOINTS.get(chain) or []
        if not endpoints:
            states.append(
                {
                    "chain": chain,
                    "status": "unsupported_chain",
                    "endpoint": None,
                    "balance_native": None,
                    "balance_wei": None,
                }
            )
            continue
        state = None
        for endpoint in endpoints:
            try:
                response = fetcher(endpoint, "eth_getBalance", [address, "latest"], timeout_sec)
                balance_hex = response.get("result")
                balance_wei = int(balance_hex, 16) if isinstance(balance_hex, str) else None
                native = (balance_wei / 10**18) if balance_wei is not None else None
                state = {
                    "chain": chain,
                    "status": "live_balance_ok",
                    "endpoint": endpoint,
                    "native_symbol": NATIVE_SYMBOL.get(chain, chain.upper()),
                    "balance_native": native,
                    "balance_wei": balance_wei,
                }
                break
            except (ValueError, URLError, TimeoutError, OSError, KeyError):
                state = {
                    "chain": chain,
                    "status": "rpc_error",
                    "endpoint": endpoint,
                    "native_symbol": NATIVE_SYMBOL.get(chain, chain.upper()),
                    "balance_native": None,
                    "balance_wei": None,
                }
        states.append(state)
    return states


def hydrate_case_row(
    row: Dict[str, Any],
    payload: Dict[str, Any],
    generated_at: str,
    timeout_sec: float,
    fetcher: Callable[[str, str, List[Any], float], Dict[str, Any]] = rpc_fetch,
    explorer_fetcher: Callable[[str, float], Dict[str, Any]] = http_fetch_json,
    explorer_html_fetcher: Callable[[str, float], str] = http_fetch_text,
) -> Dict[str, Any]:
    address_chains = infer_address_chains(payload)
    monitored = row.get("monitored_addresses", [])
    address_states = []
    healthy = 0
    attempted = 0
    for address in monitored:
        chains = address_chains.get(address) or ["ethereum"]
        live_states = fetch_live_address_state(address, chains, timeout_sec, fetcher)
        attempted += len(live_states)
        if any(state["status"] == "live_balance_ok" for state in live_states):
            healthy += 1
        activity = latest_address_activity(payload, address)
        explorer_activity = fetch_explorer_activity(address, chains, timeout_sec, explorer_fetcher)
        if not explorer_activity:
            explorer_activity = fetch_explorer_html_activity(address, chains, timeout_sec, explorer_html_fetcher)
        base_time = parse_event_time(activity.get("last_activity_utc"))
        explorer_time = parse_event_time(explorer_activity.get("last_activity_utc"))
        if explorer_time and (base_time is None or explorer_time >= base_time):
            activity.update({key: value for key, value in explorer_activity.items() if value is not None})
        elif explorer_activity.get("last_outbound_tx") and not activity.get("last_outbound_tx"):
            activity["last_outbound_tx"] = explorer_activity["last_outbound_tx"]
            activity["activity_source"] = explorer_activity.get("activity_source")
            activity["activity_chain"] = explorer_activity.get("activity_chain")
        address_states.append(
            {
                "address": address,
                "chains": chains,
                "last_checked_utc": generated_at,
                **activity,
                "live_states": live_states,
            }
        )

    hydrated = dict(row)
    hydrated["last_checked_utc"] = generated_at
    hydrated["freshness_status"] = (
        "live_checked"
        if healthy
        else "snapshot_attempted"
        if attempted
        else "live_unavailable"
    )
    hydrated["live_monitored_count"] = healthy
    hydrated["live_attempted_count"] = attempted
    hydrated["address_states"] = address_states
    return hydrated


def build_snapshot(
    manifest: Dict[str, Any],
    payloads: Dict[str, Dict[str, Any]],
    generated_at: str,
    timeout_sec: float,
    fetcher: Callable[[str, str, List[Any], float], Dict[str, Any]] = rpc_fetch,
) -> Dict[str, Any]:
    cases = []
    for row in manifest.get("cases", []):
        case_id = row.get("case_id")
        payload = payloads.get(case_id)
        if not payload:
            continue
        cases.append(hydrate_case_row(row, payload, generated_at, timeout_sec, fetcher))
    return {
        "generated_at_utc": generated_at,
        "case_count": len(cases),
        "cases": cases,
    }


def main() -> None:
    args = parse_args()
    manifest_path = Path(args.manifest_path)
    artifacts_dir = Path(args.artifacts_dir)
    out_path = Path(args.out_path)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    manifest = load_json(manifest_path)
    payloads = load_payloads(artifacts_dir)
    snapshot = build_snapshot(manifest, payloads, generated_at, args.timeout_sec)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out_path} with {snapshot['case_count']} hydrated case(s).")


if __name__ == "__main__":
    main()
