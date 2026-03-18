#!/usr/bin/env python3
"""Mine structured intelligence events and features from markdown forensics reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA_VERSION = "forensics-structure-1.3"
MIN_EVENT_SCORE = 4

TIMESTAMP_FULL_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2},?\s+\d{1,2}:\d{2}(?::\d{2})?\s*UTC)\b"
)
TIMESTAMP_HHMMSS_RE = re.compile(r"\b(\d{1,2}:\d{2}:\d{2}\s+UTC)\b")
TIMESTAMP_HHMM_RE = re.compile(r"\b(\d{1,2}:\d{2}\s+UTC)\b")
TIMESTAMP_PATTERNS = (
    ("full", TIMESTAMP_FULL_RE),
    ("time", TIMESTAMP_HHMMSS_RE),
    ("time_short", TIMESTAMP_HHMM_RE),
)

CV_RE = re.compile(r"\bCV\s*=?\s*([0-9]+\.[0-9]+)")
UTC_RE = re.compile(r"UTC[+-]\d+(?:~\+\d+)?")
AMOUNT_RE = re.compile(r"\b([0-9][0-9,.]*)\s*(ETH|DAI|USDC|USDT|WBTC|SEI|BTC|WETH|ARB)\b")
HASH_RE = re.compile(r"\b0x[a-fA-F0-9]{8,}\b")
ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
CHAIN_RE = re.compile(
    r"\b(Ethereum|Arbitrum|Base|Sei|BSC|Polygon|Optimism|Avalanche|Solana|Bitcoin|BTC)\b",
    re.IGNORECASE,
)
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

EVENT_KEYWORDS = (
    "attack",
    "attacker",
    "borrow",
    "bridge",
    "cook",
    "cross",
    "deploy",
    "deposit",
    "distribution",
    "dump",
    "exploit",
    "fund",
    "funding",
    "incident",
    "liquidat",
    "lending",
    "loan",
    "migrate",
    "preparation",
    "send",
    "snapshot",
    "swap",
    "topup",
    "transfer",
    "tx",
    "withdraw",
    "withdrawal",
    "weth",
    "aave",
    "tornado",
    "stargate",
)

SECTION_SIGNAL_HINTS = (
    "incident",
    "phase",
    "timeline",
    "fund flow",
    "attribution",
    "behavioral",
    "sequence",
    "methodology",
    "delta",
    "evidence",
    "signature",
)

SKIP_SECTION_HINTS = (
    "table of contents",
    "preamble",
    "appendix",
    "contact",
    "contact information",
    "evidence preservation",
)

STANDARD_SECTION_RULES = (
    ("incident", ("executive summary", "incident summary", "summary")),
    ("known_addresses", ("known addresses", "addresses")),
    ("fund_flow", ("fund flow reconstruction", "fund flow diagram", "fund flow")),
    ("terminal_destinations", ("destination classification", "terminal destinations", "terminal destination")),
    ("actionable_findings", ("actionable findings", "recommended actions", "next steps", "monitoring recommendations")),
    ("confidence_table", ("confidence table", "confidence assessment", "confidence")),
    ("limitations", ("limitations", "limitations and disclaimers", "disclaimer")),
    ("methodology", ("methodology",)),
    ("delta_analysis", ("delta analysis", "cross-incident analysis", "comparative analysis")),
    ("attribution_behavioral", ("attribution osint", "attacker profile", "behavioral profile", "deep behavioral profile")),
)
REANALYSIS_MARKERS = (
    "re-analysis execution",
    "baseline comparison",
    "audit reproducibility ledger",
    "drift check pass condition",
    "run_osint_reanalysis.py",
    "run_batch_osint_reanalysis.py",
    "compare_reanalysis_reports.py",
)

AXIS_DIMENSIONS = {
    "artifact_ops": (
        "provenance",
        "reproducibility",
        "machine_readability",
        "cross_case_schema",
        "presentation_quality",
    ),
    "live_intel": (
        "fund_flow_closure",
        "freshness",
        "comparative_intelligence",
    ),
    "action_economics": (
        "attribution_leverage",
        "legal_operational_packaging",
    ),
}

AXIS_MAX_SCORE = {
    "artifact_ops": 5000,
    "live_intel": 3000,
    "action_economics": 2000,
}

AXIS_STATUS = {
    "artifact_ops": "integrated",
    "live_intel": "partial",
    "action_economics": "partial",
}

BAD_GLYPH_MARKERS = ("竊", "窶", "荳", "繧", "縺", "ｽ", "｡", "･")

BRIDGE_RE = re.compile(
    r"\bbridge\b|\bbridg(?:ed|ing)\b|stargate|layerzero|across|symbiosis|chainflip|cctp|wormhole",
    re.IGNORECASE,
)
FAILURE_RE = re.compile(r"\bfailed\b|\breverted\b|\brevert\b", re.IGNORECASE)

ROUND_HINTS = ("100 ETH", "500 ETH", "1000 ETH", "1,000 ETH", "10,000 USDC", "1,000 USDC")
TABLE_ROW_RE = re.compile(r"^\|\s*.+\s*\|.*\|$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")

BAD_GLYPH_MAP = {
    "\u00a0": " ",
    "\ufeff": "",
    "→": "->",
    "—": " - ",
    "–": "-",
    "−": "-",
    "•": "-",
    "…": "...",
    "\u2028": " ",
}


def normalize(text: str) -> str:
    text = text.strip()
    for source, replacement in BAD_GLYPH_MAP.items():
        text = text.replace(source, replacement)
    text = text.replace("窶・", "->")
    text = text.replace("竊・", " - ")
    return text


def clean_signal_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def slug(text: str) -> str:
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in " -_":
            if out and out[-1] != "-":
                out.append("-")
    return "".join(out).strip("-")


def parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M UTC",
        "%H:%M:%S UTC",
        "%H:%M UTC",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def to_iso(ts: str) -> Optional[str]:
    ts_clean = ts.replace(",", "").replace("  ", " ").strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M UTC",
        "%Y-%m-%d",
        "%H:%M:%S UTC",
        "%H:%M UTC",
    ):
        try:
            parsed = datetime.strptime(ts_clean, fmt)
            if fmt.startswith("%H:%M"):
                return ts_clean
            return parsed.replace(tzinfo=None).isoformat() + "Z"
        except ValueError:
            continue
    return ts_clean


def detect_metadata(lines: Sequence[str]) -> Dict[str, Optional[str]]:
    meta = {"case_id": None, "analysis_date": None, "methodology": None}
    pattern_case = re.compile(r"^\s*\**\s*Case ID\s*\**\s*:\s*(.+)\s*$", re.IGNORECASE)
    pattern_date = re.compile(r"^\s*\**\s*(Analysis Date|Date)\s*\**\s*:\s*(.+)\s*$", re.IGNORECASE)
    pattern_method = re.compile(r"^\s*\**\s*Methodology\s*\**\s*:\s*(.+)\s*$", re.IGNORECASE)

    for line in lines[:120]:
        if not meta["case_id"]:
            case_match = pattern_case.search(line)
            if case_match:
                meta["case_id"] = clean_signal_text(case_match.group(1).strip(" *`_"))
                continue
        if not meta["analysis_date"]:
            date_match = pattern_date.search(line)
            if date_match:
                meta["analysis_date"] = clean_signal_text(date_match.group(2).strip(" *`_"))
                continue
        if not meta["methodology"]:
            method_match = pattern_method.search(line)
            if method_match:
                meta["methodology"] = clean_signal_text(method_match.group(1).strip(" *`_"))
                continue

    return meta


def parse_sections(lines: Sequence[str]) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    current_title = "Preamble"
    current_lines: List[str] = []

    for raw in lines:
        line = raw.rstrip("\n")
        heading = HEADING_RE.match(line)
        if heading and heading.group(1).startswith("##"):
            sections.append({"title": current_title, "lines": current_lines, "heading_depth": 2})
            current_title = heading.group(2).strip()
            current_lines = []
        else:
            current_lines.append(line)

    sections.append({"title": current_title, "lines": current_lines, "heading_depth": 1})
    return [
        section
        for section in sections
        if section["lines"] or section["title"] != "Preamble"
    ]


def canonical_section_key(title: str) -> Optional[str]:
    lowered = title.lower()
    for key, hints in STANDARD_SECTION_RULES:
        if any(hint in lowered for hint in hints):
            return key
    return None


def standardized_sections(sections: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for section in sections:
        key = canonical_section_key(section["title"])
        if not key or key in out:
            continue
        body = "\n".join(section["lines"]).strip()
        if not body:
            continue
        out[key] = {
            "title": section["title"],
            "body": body,
        }
    return out


def iter_action_lines(section: Dict[str, Any]) -> Iterable[str]:
    for raw in section["lines"]:
        compact = normalize(raw).strip()
        if is_noise_line(compact):
            continue
        if compact.startswith(("|:", "---")):
            continue
        if compact.startswith("|") and compact.endswith("|"):
            cells = [clean_signal_text(cell) for cell in compact.strip("|").split("|")]
            joined = " | ".join(cell for cell in cells if cell)
            if joined:
                yield joined
            continue
        if compact.startswith(("-", "*")):
            compact = compact[1:].strip()
        yield compact


def extract_open_loops(sections: Sequence[Dict[str, Any]]) -> List[str]:
    loops: List[str] = []
    for section in sections:
        title = section["title"].lower()
        if not any(token in title for token in ("next steps", "actionable", "recommended action", "monitoring")):
            continue
        for line in iter_action_lines(section):
            cleaned = clean_signal_text(line)
            if len(cleaned) < 12:
                continue
            if cleaned.lower() in {"priority | action | expected outcome", "action | priority | detail"}:
                continue
            loops.append(cleaned)
            if len(loops) == 5:
                return loops
    return loops


def infer_tier1_lead(text: str, sections: Sequence[Dict[str, Any]], open_loops: Sequence[str]) -> Dict[str, str]:
    joined = "\n".join(open_loops)
    merged = f"{text}\n{joined}".lower()
    if "kucoin" in merged or "kyc" in merged:
        return {
            "label": "kucoin_kyc_link",
            "reason": "CEX gas funding / KYC disclosure path is explicitly present in the report.",
        }
    if "stargate" in merged or "layerzero" in merged:
        return {
            "label": "bridge_metadata_request",
            "reason": "Bridge metadata is a concrete non-public lead repeatedly highlighted in the report.",
        }
    if "live balance" in merged or "dist wallet" in merged or "monitor" in merged:
        return {
            "label": "live_destination_wallet_monitoring",
            "reason": "Current balance / outbound movement on destination wallets remains unresolved.",
        }
    for section in sections:
        if "law firm" in section["title"].lower():
            return {
                "label": "law_firm_disclosure_path",
                "reason": "The report already contains disclosure-oriented packaging that can be operationalized.",
            }
    return {
        "label": "highest_confidence_open_loop",
        "reason": open_loops[0] if open_loops else "No actionable section found; defaulting to first unresolved lead.",
    }


def has_bad_glyphs(raw_text: str) -> bool:
    return any(marker in raw_text for marker in BAD_GLYPH_MARKERS)


def count_bad_glyphs(raw_text: str) -> int:
    return sum(raw_text.count(marker) for marker in BAD_GLYPH_MARKERS)


def clamp_score(value: int) -> int:
    return max(0, min(1000, int(value)))


def inspect_html_artifact(source_path: str) -> Dict[str, Any]:
    html_path = Path(source_path).with_suffix(".html")
    if not html_path.exists():
        return {
            "path": str(html_path),
            "exists": False,
            "bad_glyphs": None,
            "healthy": False,
        }
    raw_html = html_path.read_text(encoding="utf-8", errors="replace")
    bad_glyphs = count_bad_glyphs(raw_html)
    return {
        "path": str(html_path),
        "exists": True,
        "bad_glyphs": bad_glyphs,
        "healthy": bad_glyphs == 0,
    }


def build_scorecard(
    payload_core: Dict[str, Any],
    raw_text: str,
    standardized: Dict[str, Dict[str, Any]],
    open_loops: Sequence[str],
    tier1_lead: Dict[str, str],
    html_artifact: Dict[str, Any],
) -> Dict[str, Any]:
    text_lower = raw_text.lower()
    features = payload_core["features"]
    validation = payload_core["validation"]
    feature_values = {item["name"]: item["value"] for item in features["feature_vector"]}
    risk_score = int(feature_values.get("risk_score") or 0)
    event_count = int(feature_values.get("event_count") or 0)
    addresses = payload_core["stats"]["addresses"]
    chains = len(features["raw_signal_counts"]["chain_mentions"])
    score_dims = {
        "provenance": 150,
        "fund_flow_closure": 120,
        "attribution_leverage": 80,
        "freshness": 20,
        "reproducibility": 120,
        "machine_readability": 180,
        "cross_case_schema": 50,
        "presentation_quality": 150,
        "legal_operational_packaging": 80,
        "comparative_intelligence": 40,
    }

    if payload_core.get("source_sha256"):
        score_dims["provenance"] += 100
    if "sha256" in text_lower or "hashed" in text_lower:
        score_dims["provenance"] += 100
    if "evidence preservation" in text_lower or "evidence log" in text_lower:
        score_dims["provenance"] += 100
    if validation.get("passes_signal_gate"):
        score_dims["provenance"] += 50
    if "available on request" in text_lower:
        score_dims["provenance"] -= 40

    score_dims["fund_flow_closure"] += min(180, event_count)
    score_dims["fund_flow_closure"] += min(90, addresses * 6)
    score_dims["fund_flow_closure"] += min(75, chains * 15)
    if "fund_flow" in standardized:
        score_dims["fund_flow_closure"] += 60
    if "terminal_destinations" in standardized:
        score_dims["fund_flow_closure"] += 60
    unresolved_penalty = sum(
        35
        for item in open_loops
        if any(token in item.lower() for token in ("need", "monitor", "trace", "check", "request", "unresolved"))
    )
    score_dims["fund_flow_closure"] -= min(220, unresolved_penalty)

    if "timezone" in text_lower or "utc+" in text_lower or "utc-" in text_lower:
        score_dims["attribution_leverage"] += 90
    if "kucoin" in text_lower or "kyc" in text_lower:
        score_dims["attribution_leverage"] += 220
    if "behavioral" in text_lower or "cv =" in text_lower or "cv=" in text_lower:
        score_dims["attribution_leverage"] += 70
    if "attribution_behavioral" in standardized:
        score_dims["attribution_leverage"] += 90
    if tier1_lead.get("label") != "highest_confidence_open_loop":
        score_dims["attribution_leverage"] += 50

    if "current state" in text_lower or "live balance" in text_lower:
        score_dims["freshness"] += 180
    if "current balance" in text_lower:
        score_dims["freshness"] += 100
    if "monitor" in text_lower or "real-time" in text_lower:
        score_dims["freshness"] += 80
    freshness_penalty = 0
    if "needs live balance check" in text_lower:
        freshness_penalty += 160
    if "available on request" in text_lower:
        freshness_penalty += 60
    score_dims["freshness"] -= freshness_penalty

    if payload_core.get("methodology"):
        score_dims["reproducibility"] += 100
    if "methodology" in standardized:
        score_dims["reproducibility"] += 100
    if validation.get("event_ratio", 0) >= 0.1:
        score_dims["reproducibility"] += 80
    if event_count >= 25:
        score_dims["reproducibility"] += 60
    if "manual" in text_lower:
        score_dims["reproducibility"] -= 40

    score_dims["machine_readability"] += min(180, event_count)
    score_dims["machine_readability"] += min(90, len(standardized) * 10)
    if payload_core["events"]:
        score_dims["machine_readability"] += 70
    if payload_core["features"]["entities"]["unique_addresses"]:
        score_dims["machine_readability"] += 70

    score_dims["cross_case_schema"] += min(220, len(standardized) * 25)
    required_standard = {
        "incident",
        "known_addresses",
        "fund_flow",
        "terminal_destinations",
        "actionable_findings",
        "confidence_table",
        "limitations",
        "methodology",
    }
    present_required = len(required_standard & set(standardized))
    score_dims["cross_case_schema"] += present_required * 25

    if not has_bad_glyphs(raw_text):
        score_dims["presentation_quality"] += 150
    else:
        score_dims["presentation_quality"] -= min(250, count_bad_glyphs(raw_text) * 2)
    if len(raw_text.splitlines()) > 200:
        score_dims["presentation_quality"] += 80
    if "html" in payload_core["source_file"].lower():
        score_dims["presentation_quality"] -= 120
    if html_artifact.get("exists"):
        score_dims["presentation_quality"] += 60
        if html_artifact.get("healthy"):
            score_dims["presentation_quality"] += 120
        else:
            score_dims["presentation_quality"] -= min(180, int(html_artifact.get("bad_glyphs") or 0) * 2)
    else:
        score_dims["presentation_quality"] -= 80

    if "law firm" in text_lower or "disclosure request" in text_lower or "subpoena" in text_lower:
        score_dims["legal_operational_packaging"] += 180
    if "actionable_findings" in standardized:
        score_dims["legal_operational_packaging"] += 120
    if open_loops:
        score_dims["legal_operational_packaging"] += 60

    if "delta_analysis" in standardized:
        score_dims["comparative_intelligence"] += 140
    if "cross-incident" in text_lower or "comparative analysis" in text_lower:
        score_dims["comparative_intelligence"] += 110
    score_dims["comparative_intelligence"] += min(90, max(0, risk_score - 30) * 2)

    dimensions = {key: clamp_score(value) for key, value in score_dims.items()}
    total = sum(dimensions.values())
    axes = {}
    remaining_axes = 0
    for axis_name, members in AXIS_DIMENSIONS.items():
        axis_total = sum(dimensions[name] for name in members)
        axis_max = AXIS_MAX_SCORE[axis_name]
        missing = axis_max - axis_total
        if axis_name == "artifact_ops":
            integrated_dimensions = len(members) if axis_total > 0 else 0
        else:
            integrated_dimensions = sum(1 for name in members if dimensions[name] > 0)
        axes[axis_name] = {
            "dimensions": list(members),
            "current_score": axis_total,
            "max_score": axis_max,
            "upside": missing,
            "integrated_dimension_count": integrated_dimensions,
            "dimension_count": len(members),
            "integration_status": AXIS_STATUS[axis_name],
        }
        if axis_name != "artifact_ops":
            remaining_axes += missing
    return {
        "dimensions": dimensions,
        "axes": axes,
        "total": total,
        "target_6000_gap": max(0, 6000 - total),
        "target_10000_gap": max(0, 10000 - total),
        "target_plus_6000_gap": max(0, 6000 - remaining_axes),
        "remaining_axis_upside": remaining_axes,
        "scale": 1000,
        "dimension_count": len(dimensions),
    }


def build_case_profile(
    standardized: Dict[str, Dict[str, Any]],
    open_loops: Sequence[str],
    tier1_lead: Dict[str, str],
    payload_core: Dict[str, Any],
    html_artifact: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "standardized_sections": standardized,
        "open_loops": list(open_loops),
        "tier1_lead": tier1_lead,
        "current_state": {
            "analysis_date": payload_core.get("analysis_date"),
            "has_live_balance_gap": any("live balance" in item.lower() for item in open_loops),
            "passes_signal_gate": payload_core["validation"]["passes_signal_gate"],
        },
        "html_artifact": html_artifact,
    }


def classify_document(path: Path, text: str, standardized: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    lowered = text.lower()
    marker_hits = [marker for marker in REANALYSIS_MARKERS if marker in lowered]
    is_reanalysis = bool(marker_hits)
    if not is_reanalysis and path.stem.endswith("_v2"):
        if "re-analysis" in lowered or "re-analysis results" in lowered or "re-analysis execution" in lowered:
            is_reanalysis = True
            marker_hits.append("v2_reanalysis_name_pattern")
    return {
        "doc_class": "reanalysis_ledger" if is_reanalysis else "case_study",
        "marker_hits": marker_hits,
        "section_keys": sorted(standardized.keys()),
    }


def is_noise_line(line: str) -> bool:
    compact = line.strip()
    if not compact:
        return True
    if compact in {"---", "***", "```", "```python", "```json", "```bash", "```}"}:
        return True
    if compact.startswith("|:") and compact.endswith("|"):
        return True
    if all(ch in "|:- " for ch in compact):
        return True
    return False


def line_score(line: str, section_title: str, section_depth: int = 1) -> Tuple[int, List[str]]:
    compact = line.strip()
    lower = compact.lower()
    if is_noise_line(compact):
        return 0, []
    if compact.startswith(("#", "```")):
        return 0, []

    score = 0
    reasons: List[str] = []

    if any(pattern.search(compact) for _, pattern in TIMESTAMP_PATTERNS):
        score += 8
        reasons.append("timestamp")
    if ADDRESS_RE.search(compact):
        score += 3
        reasons.append("address")
    if HASH_RE.search(compact):
        score += 3
        reasons.append("hash")
    if AMOUNT_RE.search(compact):
        score += 2
        reasons.append("amount")
    if BRIDGE_RE.search(lower):
        score += 1
        reasons.append("bridge")
    if FAILURE_RE.search(lower):
        score += 1
        reasons.append("failure")

    keyword_hits = sum(1 for kw in EVENT_KEYWORDS if kw in lower)
    if keyword_hits:
        score += min(5, keyword_hits)
        reasons.append("keyword")
    if any(hint in section_title.lower() for hint in SECTION_SIGNAL_HINTS):
        score += 1
        reasons.append("section_signal")
    if section_depth <= 2:
        score += 1

    if compact.startswith("|") and compact.endswith("|") and compact.count("|") >= 2:
        score -= 2

    if compact.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.", "-", "*")):
        score += 1
        reasons.append("list_like")

    return score, reasons


def collect_timestamps(line: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for kind, pattern in TIMESTAMP_PATTERNS:
        for match in pattern.finditer(line):
            out.append((kind, to_iso(match.group(1))))
    return out


def line_context(lines: Sequence[str], idx: int, span: int = 1) -> List[str]:
    before = lines[max(0, idx - span) : idx]
    after = lines[idx + 1 : idx + 1 + span]
    return [x.strip() for x in before + after if x.strip()]


def event_payload(
    case_id: str,
    section: Dict[str, Any],
    line_no: int,
    source: str,
    timestamp: Optional[str],
    ts_src: str,
    score: int,
    reasons: List[str],
    context: Sequence[str],
) -> Dict[str, Any]:
    return {
        "event_id": f"{slug(case_id)}:{slug(section['title'])}:{line_no}:{ts_src if timestamp else 'meta'}",
        "section": section["title"],
        "line_no": line_no,
        "timestamp_source": ts_src,
        "timestamp": timestamp,
        "source": source.strip(),
        "confidence": score,
        "signals": sorted(set(reasons)),
        "addresses": sorted(set(ADDRESS_RE.findall(source))),
        "tx_hashes": sorted(set(HASH_RE.findall(source))),
        "amounts": AMOUNT_RE.findall(source),
        "context": list(context),
    }


def parse_events(section: Dict[str, Any], case_id: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    title = section["title"]
    if any(hint in title.lower() for hint in SKIP_SECTION_HINTS):
        return events

    lines = section["lines"]
    for idx, line in enumerate(lines):
        line_no = idx + 1
        compact = line.strip()
        score, reasons = line_score(line, title, section.get("heading_depth", 1))
        if score < MIN_EVENT_SCORE:
            continue

        context = line_context(lines, idx, span=1)
        ts_hits = collect_timestamps(compact)
        if ts_hits:
            for ts_src, timestamp in ts_hits:
                events.append(
                    event_payload(
                        case_id=case_id,
                        section=section,
                        line_no=line_no,
                        source=compact,
                        timestamp=timestamp,
                        ts_src=ts_src,
                        score=score,
                        reasons=list(reasons),
                        context=context,
                    )
                )
            continue

        if TABLE_ROW_RE.match(compact):
            cells = [cell.strip() for cell in compact.strip("|").split("|")]
            if cells:
                first_cell = cells[0]
                row_ts = collect_timestamps(first_cell)
                if row_ts and any(kw in first_cell.lower() for kw in ("time", "utc", "phase", "attack")):
                    ts_src, timestamp = row_ts[0]
                    row_reasons = list(reasons)
                    row_reasons.append("table_timeline")
                    events.append(
                        event_payload(
                            case_id=case_id,
                            section=section,
                            line_no=line_no,
                            source=compact,
                            timestamp=timestamp,
                            ts_src=ts_src,
                            score=score,
                            reasons=row_reasons,
                            context=context,
                        )
                    )
                    continue

        if compact.startswith(("-", "*", "|", "1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
            events.append(
                event_payload(
                    case_id=case_id,
                    section=section,
                    line_no=line_no,
                    source=compact,
                    timestamp=None,
                    ts_src="none",
                    score=score,
                    reasons=list(reasons),
                    context=context,
                )
            )

    return events


def section_event_counts(events: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter()
    for event in events:
        counter[event.get("section", "unknown")] += 1
    return dict(counter)


def entity_degree(events: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    degrees: Counter[str] = Counter()
    for event in events:
        for addr in event.get("addresses", []):
            degrees[addr] += 1
        for tx_hash in event.get("tx_hashes", []):
            degrees[tx_hash] += 1
    return dict(degrees)


def extract_features(text: str, sections: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    flat = "\n".join(section["title"] + "\n" + "\n".join(section["lines"]) for section in sections)
    cv_vals = [float(v) for v in CV_RE.findall(flat)]
    utc_mentions = sorted(set(UTC_RE.findall(flat)))
    chain_mentions = sorted(set(CHAIN_RE.findall(flat)))
    failed = len(FAILURE_RE.findall(flat))
    custody = len(re.findall(r"\bcustody break|aethweth|aave|atoken\b", flat, flags=re.IGNORECASE))
    bridges = len(BRIDGE_RE.findall(flat))
    round_hits = sum(flat.count(tok) for tok in ROUND_HINTS)

    times = [evt for evt in events if evt.get("timestamp")]
    parsed_times = [parse_iso(evt["timestamp"]) for evt in times if parse_iso(evt["timestamp"])]
    parsed_times = [ts for ts in parsed_times if ts is not None]
    gaps = [
        (parsed_times[i + 1] - parsed_times[i]).total_seconds() / 60
        for i in range(len(parsed_times) - 1)
    ]

    addresses = set()
    tx_hashes = set()
    total_confidence = 0.0
    for evt in events:
        addresses.update(evt.get("addresses", []))
        tx_hashes.update(evt.get("tx_hashes", []))
        total_confidence += float(evt.get("confidence", 0))
    avg_confidence = total_confidence / len(events) if events else 0.0
    meaningful = [evt for evt in events if evt.get("confidence", 0) >= 4]
    event_signal_ratio = len(meaningful) / len(events) if events else 0.0

    prep_ts = first_timestamp_by_label(sections, "preparation")
    exploit_ts = first_timestamp_by_label(sections, "exploit begins")
    phase_gap = None
    if prep_ts and exploit_ts:
        dt1 = parse_iso(prep_ts)
        dt2 = parse_iso(exploit_ts)
        if dt1 and dt2:
            phase_gap = int((dt2 - dt1).total_seconds() / 60)

    degree_values = list(entity_degree(events).values())
    entropy_like = None
    if degree_values and sum(degree_values) > 0:
        entropy_like = round(statistics.pstdev(degree_values) / sum(degree_values), 4)

    feature_vector = [
        {"name": "cv_max", "value": max(cv_vals) if cv_vals else None, "evidence": [f"CV={v}" for v in cv_vals]},
        {"name": "cv_mean", "value": round(sum(cv_vals) / len(cv_vals), 4) if cv_vals else None, "evidence": [f"n={len(cv_vals)}"]},
        {"name": "cv_min", "value": min(cv_vals) if cv_vals else None, "evidence": [f"CV={v}" for v in cv_vals]},
        {"name": "event_count", "value": len(events), "evidence": ["parsed event lines after scoring"]},
        {"name": "event_signal_ratio", "value": round(event_signal_ratio, 3), "evidence": ["confidence >= 4 subset"]},
        {"name": "avg_confidence", "value": round(avg_confidence, 2), "evidence": ["mean event confidence score"]},
        {"name": "timeline_points", "value": len(times), "evidence": ["timestamp-matched lines"]},
        {"name": "timeline_gap_p95_min", "value": round(statistics.quantiles(gaps, n=20)[18], 3) if len(gaps) >= 2 else None, "evidence": ["pairwise event minute gaps"]},
        {"name": "bridge_signal_count", "value": bridges, "evidence": ["bridge keywords in body"]},
        {"name": "custody_break_signal_count", "value": custody, "evidence": ["custody/aave related keywords"]},
        {"name": "round_batch_score", "value": round_hits, "evidence": [repr(ROUND_HINTS)]},
        {"name": "failed_tx_markers", "value": failed, "evidence": ["failed/revert markers"]},
        {"name": "chain_coverage", "value": chain_mentions, "evidence": ["chain keyword scans"]},
        {"name": "utc_coverage", "value": utc_mentions, "evidence": ["UTC format markers"]},
        {"name": "prep_to_exploit_min", "value": phase_gap, "evidence": [f"prep={prep_ts}", f"exploit={exploit_ts}"]},
        {"name": "event_density", "value": round(len(events) / max(1, len(text.splitlines())), 4), "evidence": ["events / total lines"]},
        {"name": "address_count", "value": len(addresses), "evidence": ["unique addresses in events"]},
        {"name": "tx_count", "value": len(tx_hashes), "evidence": ["unique tx hashes in events"]},
        {"name": "entity_weighted_scatter", "value": entropy_like, "evidence": ["address/tx appearance distribution"]},
        {"name": "risk_score", "value": 0, "evidence": ["derived"]},
    ]

    risk_score = compute_risk_score(feature_vector, len(events), len(times), len(gaps))
    for item in feature_vector:
        if item["name"] == "risk_score":
            item["value"] = risk_score

    return {
        "feature_vector": feature_vector,
        "raw_signal_counts": {
            "cv_samples": cv_vals,
            "timestamps": len(times),
            "failed_markers": failed,
            "chain_mentions": chain_mentions,
            "bridge_markers": bridges,
            "custody_markers": custody,
            "sections": len(sections),
            "total_lines": len(text.splitlines()),
        },
        "risk_tags": derive_tags(feature_vector, cv_vals, failed, bridges, custody, round_hits, risk_score),
        "timeline": {
            "event_count": len(times),
            "time_gaps_min": gaps[:40],
            "median_gap_min": round(statistics.median(gaps), 3) if gaps else None,
        },
        "entities": {
            "unique_addresses": sorted(addresses),
            "unique_tx_hashes": sorted(tx_hashes),
            "section_event_distribution": section_event_counts(events),
            "entity_degree_sample": dict(
                sorted(entity_degree(events).items(), key=lambda item: item[1], reverse=True)[:10]
            ),
        },
    }


def compute_risk_score(
    feature_vector: List[Dict[str, Any]],
    event_count: int,
    timeline_points: int,
    gap_count: int,
) -> int:
    values = {f["name"]: f["value"] for f in feature_vector}
    score = 10.0
    if values.get("cv_max") is not None and values["cv_max"] > 1.5:
        score += 12
    if (values.get("failed_tx_markers") or 0) >= 1:
        score += 8
    if (values.get("bridge_signal_count") or 0) > 20:
        score += 15
    if (values.get("custody_break_signal_count") or 0) >= 1:
        score += 10
    if (values.get("round_batch_score") or 0) >= 15:
        score += 8
    if event_count > 200:
        score += 12
    if timeline_points >= 8:
        score += 8
    if (values.get("event_signal_ratio") or 0.0) < 0.45:
        score -= 10
    if (values.get("avg_confidence") or 0.0) < 5:
        score -= 8
    if gap_count > 30:
        score -= 4
    return min(100, max(0, int(round(score))))


def derive_tags(
    feature_vector: List[Dict[str, Any]],
    cv_vals: List[float],
    failed: int,
    bridges: int,
    custody: int,
    round_hits: int,
    risk_score: int,
) -> List[str]:
    tags: List[str] = []
    if cv_vals:
        cv_max = max(cv_vals)
        if cv_max > 1.5:
            tags.append("human_like_timing")
        elif cv_max < 0.8:
            tags.append("bot_like_timing")
    if failed >= 1:
        tags.append("retry_or_failure_signal")
    if custody >= 1:
        tags.append("chain_of_custody_break")
    if bridges >= 4:
        tags.append("multi_chain_or_bridge_heavy")
    if round_hits >= 2:
        tags.append("round_batch_behaviour")
    if bridges >= 1 and custody >= 1:
        tags.append("high_structural_complexity")
    if risk_score >= 70:
        tags.append("high_alertability")
    elif risk_score <= 30:
        tags.append("low_signal_confidence")
    if not cv_vals:
        tags.append("cv_missing")
    return tags


def first_timestamp_by_label(sections: List[Dict[str, Any]], label: str) -> Optional[str]:
    for section in sections:
        if label.lower() in section["title"].lower():
            for line in section["lines"]:
                for _, pattern in TIMESTAMP_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        return match.group(1).replace(",", "").strip()
    return None


def build_case_payload(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    raw_text = raw.decode("utf-8", errors="replace")
    text = normalize(raw_text)
    lines = text.splitlines()
    title = lines[0].lstrip("# ").strip() if lines else path.stem
    meta = detect_metadata(lines)
    case_id = meta.get("case_id") or path.stem
    sections = parse_sections(lines[1:])

    events: List[Dict[str, Any]] = []
    for section in sections:
        events.extend(parse_events(section, case_id))

    dedup_events = []
    seen = set()
    for event in events:
        key = (
            event.get("section"),
            event.get("line_no"),
            event.get("timestamp") or "none",
            event.get("source"),
            tuple(event.get("context", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        dedup_events.append(event)

    features = extract_features(text, sections, dedup_events)
    risk_score = next((item["value"] for item in features["feature_vector"] if item["name"] == "risk_score"), 0)

    raw_events = len(events)
    deduped_events = len(dedup_events)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "title": title,
        "source_file": str(path),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "analysis_date": meta.get("analysis_date"),
        "methodology": meta.get("methodology"),
        "sections": [{"title": s["title"], "body": "\n".join(s["lines"]).strip()} for s in sections],
        "events": dedup_events,
        "features": features,
        "validation": {
            "raw_events": raw_events,
            "deduped_events": deduped_events,
            "event_ratio": round(deduped_events / max(1, raw_events), 4),
            "line_ratio": round(deduped_events / max(1, len(lines)), 4),
            "has_case_id": bool(meta.get("case_id")),
            "risk_score": risk_score,
            "passes_signal_gate": bool(risk_score >= 35 and deduped_events >= 15),
        },
        "stats": {
            "sections": len(sections),
            "lines": len(lines),
            "events": deduped_events,
            "addresses": len(features["entities"]["unique_addresses"]),
            "tx_hashes": len(features["entities"]["unique_tx_hashes"]),
            "raw_lines": len(text.splitlines()),
        },
    }
    standardized = standardized_sections(sections)
    classification = classify_document(path, text, standardized)
    open_loops = extract_open_loops(sections)
    tier1_lead = infer_tier1_lead(text, sections, open_loops)
    html_artifact = inspect_html_artifact(payload["source_file"])
    payload["case_profile"] = build_case_profile(standardized, open_loops, tier1_lead, payload, html_artifact)
    payload["scorecard"] = build_scorecard(payload, raw_text, standardized, open_loops, tier1_lead, html_artifact)
    payload["doc_class"] = classification["doc_class"]
    payload["classification"] = classification
    return payload


def sanitize_filename(value: str) -> str:
    value = value.replace(" ", "-")
    return SAFE_FILENAME_RE.sub("-", value).strip("-")


def write_output(payload: Dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    file_safe_case_id = sanitize_filename(payload["case_id"]).replace("__", "-")
    out_path = out_dir / f"{file_safe_case_id}.json"
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def compare_features(payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    scores: Dict[str, Dict[str, Any]] = {}
    scorecards: Dict[str, Dict[str, Any]] = {}
    for payload in payloads:
        feature_list = payload["features"]["feature_vector"]
        scores[payload["case_id"]] = {
            k: v["value"]
            for item in feature_list
            for k, v in ((item["name"], item),)
            if item["name"]
            in {
                "cv_max",
                "failed_tx_markers",
                "bridge_signal_count",
                "custody_break_signal_count",
                "round_batch_score",
                "event_count",
                "timeline_points",
                "risk_score",
                "timeline_gap_p95_min",
            }
        }
        scorecards[payload["case_id"]] = payload.get("scorecard", {})

    if len(scores) < 2:
        return {"scores": scores, "scorecards": scorecards, "pairwise_delta": []}

    case_ids = list(scores.keys())
    pairwise = []
    for i in range(len(case_ids)):
        for j in range(i + 1, len(case_ids)):
            a = case_ids[i]
            b = case_ids[j]
            delta = {}
            keys = set(scores[a]) | set(scores[b])
            for key in sorted(keys):
                va = scores[a].get(key)
                vb = scores[b].get(key)
                if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
                    delta[key] = vb - va
                else:
                    delta[key] = {"a": va, "b": vb, "changed": va != vb}
            if scorecards.get(a) and scorecards.get(b):
                delta["scorecard_total"] = scorecards[b].get("total", 0) - scorecards[a].get("total", 0)
            pairwise.append({"pair": [a, b], "delta": delta})

    return {"scores": scores, "scorecards": scorecards, "pairwise_delta": pairwise}


def find_reports(report_glob: str) -> List[Path]:
    base = Path(report_glob).resolve()
    if base.is_file():
        return [base]
    return sorted(base.glob("*.md"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports-dir",
        dest="reports",
        default=str(Path("reports").resolve()),
        help="Directory containing case study markdown files.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(Path("artifacts/structured_reports")),
        help="Output directory for structured JSON.",
    )
    parser.add_argument(
        "--compare-out",
        default=str(Path("artifacts/feature_summary.json")),
        help="Output path for cross-case feature comparison.",
    )
    args = parser.parse_args()
    args.out_dir = Path(args.out_dir)
    args.compare_out = Path(args.compare_out)
    return args


def main() -> None:
    args = parse_args()
    report_paths = find_reports(args.reports)
    if not report_paths:
        raise SystemExit(f"No reports found at: {args.reports}")

    payloads = []
    case_payloads = []
    reanalysis_payloads = []
    reanalysis_out_dir = args.out_dir.parent / "reanalysis_reports"
    for path in report_paths:
        payload = build_case_payload(path)
        if payload.get("doc_class") == "reanalysis_ledger":
            stale_case_path = args.out_dir / f"{sanitize_filename(payload['case_id']).replace('__', '-')}.json"
            if stale_case_path.exists():
                stale_case_path.unlink()
            write_output(payload, reanalysis_out_dir)
            reanalysis_payloads.append(payload)
        else:
            write_output(payload, args.out_dir)
            case_payloads.append(payload)
        payloads.append(payload)

    args.compare_out.parent.mkdir(parents=True, exist_ok=True)
    args.compare_out.write_text(
        json.dumps(compare_features(case_payloads), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"Processed {len(payloads)} report(s).")
    print(f"Structured outputs: {args.out_dir.resolve()}")
    print(f"Cross-case comparison: {args.compare_out.resolve()}")
    if reanalysis_payloads:
        print(f"Reanalysis outputs: {reanalysis_out_dir.resolve()} ({len(reanalysis_payloads)} file(s))")
    for payload in payloads:
        print(
            f"- {payload['case_id']} | class={payload.get('doc_class')} | events={payload['stats']['events']} "
            f"addresses={payload['stats']['addresses']} hashes={payload['stats']['tx_hashes']} "
            f"risk={payload['validation']['risk_score']} ratio={payload['validation']['event_ratio']} "
            f"gate={payload['validation']['passes_signal_gate']}"
        )


if __name__ == "__main__":
    main()
