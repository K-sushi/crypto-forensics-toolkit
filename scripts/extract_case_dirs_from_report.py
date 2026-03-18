#!/usr/bin/env python3
"""Extract normalized case directory names from an OSINT batch report."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def extract_case_dirs(report_path: str) -> list[str]:
    path = Path(report_path)
    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    case_dirs: list[str] = []
    for result in data.get("results", []):
        case_dir = str(result.get("case_dir", "")).strip()
        if not case_dir:
            continue
        case_dir = case_dir.replace("\\", "/")
        normalized = Path(case_dir).name
        if normalized:
            case_dirs.append(normalized)
    return case_dirs


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: extract_case_dirs_from_report.py <report_path>")
    for case_dir in extract_case_dirs(sys.argv[1]):
        print(case_dir)


if __name__ == "__main__":
    main()
