#!/usr/bin/env python3
"""Turn collected on-chain events into focused OSINT heuristics."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import re
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ROUND_MARKERS = (10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)
WINDOW_SECONDS = 600


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case-dir",
        help="Directory produced by run_osint_reanalysis.py (contains manifest.json).",
    )
    parser.add_argument(
        "--events-path",
        default="",
        help="Direct path to collected_events.jsonl (overrides --case-dir).",
    )
    parser.add_argument(
        "--out-path",
        default="",
        help="Output JSON path; default is <case-dir>/analysis.json or stdout.",
    )
    return parser.parse_args()


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            rows.append(json.loads(raw))
    return rows


def parse_label(row: Dict[str, Any]) -> str:
    desc = str(row.get("desc", ""))
    match = re.search(r"\(target_(\d+)\)", desc)
    return match.group(1) if match else "unlabeled"


def parse_direction(row: Dict[str, Any]) -> str:
    desc = str(row.get("desc", "")).strip().upper()
    if desc.startswith("OUT "):
        return "out"
    if desc.startswith("IN "):
        return "in"
    return "unknown"


def calc_cv(seconds: Sequence[float]) -> Optional[float]:
    if len(seconds) < 2:
        return None
    if not seconds:
        return None
    mean = statistics.fmean(seconds)
    if mean <= 0:
        return None
    stdev = statistics.pstdev(seconds)
    if stdev <= 0:
        return 0.0
    return stdev / mean


def quantile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(math.floor((len(ordered) - 1) * q))))
    return ordered[idx]


def is_round_batch(v: float) -> bool:
    if not math.isfinite(v) or v <= 0:
        return False
    rounded = round(v)
    if rounded <= 1:
        return False
    if abs(v - rounded) > 1e-9:
        return False
    return any((rounded % m) == 0 for m in ROUND_MARKERS)


def burst_windows(ts_list: List[int]) -> List[Dict[str, Any]]:
    if not ts_list:
        return []
    times = sorted(ts_list)
    q = deque()
    peaks: List[Tuple[int, int]] = []
    left = 0
    for t in times:
        q.append(t)
        while q and t - q[0] > WINDOW_SECONDS:
            q.popleft()
        peaks.append((t, len(q)))

    if not peaks:
        return []
    counts = [c for _, c in peaks]
    med = quantile(counts, 0.5)
    threshold = max(5, math.ceil(med * 2.5))
    candidates = []
    for t, c in peaks:
        if c >= threshold:
            candidates.append(
                {
                    "window_start_utc": datetime.fromtimestamp(t - WINDOW_SECONDS, tz=timezone.utc).isoformat(),
                    "window_event_count": c,
                    "window_end_utc": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                }
            )
    candidates = sorted(candidates, key=lambda x: x["window_event_count"], reverse=True)
    return candidates[:5]


def analyze_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not rows:
        return {
            "event_count": 0,
            "status": "empty",
            "signals": [],
            "analysis": {},
        }

    rows_sorted = sorted(rows, key=lambda r: int(r["timestamp"]))
    timestamps = [int(r["timestamp"]) for r in rows_sorted]
    values = [float(r.get("value", 0.0) or 0.0) for r in rows_sorted]

    direction = Counter(parse_direction(r) for r in rows_sorted)
    labels = Counter(parse_label(r) for r in rows_sorted)
    symbols = Counter(str(r.get("symbol", "UNK")) for r in rows_sorted)
    desc_freq = Counter(str(r.get("desc", ""))[:80] for r in rows_sorted)

    if len(timestamps) >= 2:
        deltas = [float(b - a) for a, b in zip(timestamps, timestamps[1:])]
        timeline_gaps = [d / 60 for d in deltas]
    else:
        timeline_gaps = []

    round_batch_hits = [
        {
            "timestamp_utc": datetime.fromtimestamp(int(r["timestamp"]), tz=timezone.utc).isoformat(),
            "value": r.get("value"),
            "symbol": r.get("symbol"),
            "desc": r.get("desc"),
        }
        for r in rows_sorted
        if is_round_batch(float(r.get("value", 0.0) or 0.0))
    ]

    values_sorted = sorted(values)
    p95 = quantile(values_sorted, 0.95)
    top_values = sorted(rows_sorted, key=lambda r: float(r.get("value", 0.0) or 0.0), reverse=True)[:20]

    label_activity = {}
    for label, label_rows in Counter((parse_label(r) for r in rows_sorted)).items():
        relevant = [r for r in rows_sorted if parse_label(r) == label]
        rel_ts = [int(r["timestamp"]) for r in relevant]
        rel_gaps = [float(b - a) for a, b in zip(rel_ts, rel_ts[1:])]
        rel_vals = [float(r.get("value", 0.0) or 0.0) for r in relevant]
        label_activity[label] = {
            "events": len(relevant),
            "out_in_ratio": round((Counter(parse_direction(r) for r in relevant).get("out", 0) + 1) /
                                   max(1, Counter(parse_direction(r) for r in relevant).get("in", 0) + 1), 4),
            "interarrival_cv": calc_cv([v / 60.0 for v in rel_gaps if v >= 0]),
            "value_p95": quantile([v for v in rel_vals if v > 0], 0.95),
        }

    peaks = burst_windows(timestamps)

    signals: List[Dict[str, Any]] = []

    if p95 > 0:
        signals.append({
            "name": "high_value_tail",
            "value": p95,
            "evidence": f"top 5% threshold={p95:.8f}"
        })
    if round_batch_hits:
        signals.append({
            "name": "round_batch_hits",
            "value": len(round_batch_hits),
            "evidence": "integer round multiples observed"
        })
    if peaks:
        signals.append({
            "name": "burst_windows",
            "value": len(peaks),
            "evidence": "windowed event concentration above dynamic threshold"
        })
    if timeline_gaps:
        gap_cv = calc_cv(timeline_gaps)
        if gap_cv is not None:
            signals.append({
                "name": "timeline_cv",
                "value": gap_cv,
                "evidence": "inter-arrival CV (minutes)"
            })

    score = 0.0
    if direction.get("out", 0) > direction.get("in", 0) * 2:
        score += 25
    if len(peaks) > 0:
        score += 15
    if p95 > 0 and (round_batch_hits):
        score += 20
    if label_activity:
        heavy_label = max(label_activity.items(), key=lambda kv: kv[1]["events"])[0]
        if label_activity[heavy_label]["events"] > 0:
            score += 10

    return {
        "event_count": len(rows_sorted),
        "status": "ok",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "analysis": {
            "window_seconds": WINDOW_SECONDS,
            "timeline": {
                "first_ts": min(timestamps),
                "last_ts": max(timestamps),
                "duration_hours": round((max(timestamps) - min(timestamps)) / 3600, 4),
                "events_per_hour": round(len(rows_sorted) / max(1e-9, (max(timestamps) - min(timestamps)) / 3600), 4),
                "gap_median_min": quantile(timeline_gaps, 0.5),
                "gap_p95_min": quantile(timeline_gaps, 0.95),
            },
            "flows": {
                "out": direction["out"],
                "in": direction["in"],
                "unknown": direction["unknown"],
                "out_in_ratio": direction["out"] / max(1, direction["in"]),
            },
            "top_symbols": symbols.most_common(12),
            "top_labels": labels.most_common(12),
            "top_desc_prefixes": desc_freq.most_common(12),
            "round_batch_hits": round_batch_hits[:20],
            "burst_windows": peaks,
            "label_activity": label_activity,
            "top_values": [
                {
                    "timestamp_utc": datetime.fromtimestamp(int(r["timestamp"]), tz=timezone.utc).isoformat(),
                    "desc": r.get("desc"),
                    "value": r.get("value"),
                    "symbol": r.get("symbol"),
                }
                for r in top_values
            ],
            "score": round(min(100.0, score), 1),
            "signals": signals,
            "p95_value": p95,
        },
        "summary": {
            "events_sorted": True,
            "round_batch_hits": len(round_batch_hits),
            "burst_count": len(peaks),
            "distinct_symbols": len(symbols),
            "distinct_labels": len(labels),
        },
    }


def resolve_events_path(case_dir: Optional[str], explicit_path: str) -> Tuple[Path, Path]:
    if explicit_path:
        events_path = Path(explicit_path).expanduser().resolve()
        return Path(explicit_path).parent, events_path

    if not case_dir:
        raise SystemExit("either --case-dir or --events-path is required")

    case_root = Path(case_dir).expanduser().resolve()
    manifest = case_root / "manifest.json"
    if not manifest.exists():
        raise SystemExit(f"manifest not found: {manifest}")

    manifest_data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
    events_path_value = str(manifest_data.get("events_path", "")).strip()
    if events_path_value:
        events_path = Path(events_path_value).expanduser()
    else:
        events_path = case_root / "collected_events.jsonl"
    if not events_path.is_absolute():
        events_path = case_root / events_path

    if not events_path.exists():
        raise SystemExit(f"events file not found: {events_path}")

    return case_root, events_path


def main() -> None:
    args = parse_args()
    case_dir, events_path = resolve_events_path(args.case_dir, args.events_path)
    rows = read_jsonl(events_path)
    results = analyze_rows(rows)
    if args.out_path:
        out_path = Path(args.out_path).expanduser()
    else:
        out_path = case_dir / "analysis.json"

    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": "analysis_complete", "out_path": str(out_path), "events": len(rows)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
