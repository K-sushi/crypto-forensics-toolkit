#!/usr/bin/env python3
"""Render markdown forensics reports into clean UTF-8 HTML."""

from __future__ import annotations

import argparse
import html
import re
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
TABLE_SEPARATOR_RE = re.compile(r"^\|\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?$")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
ITALIC_RE = re.compile(r"\*([^*]+)\*")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports-dir",
        default="reports",
        help="Directory containing markdown reports.",
    )
    parser.add_argument(
        "--pattern",
        default="case_study_*.md",
        help="Glob pattern for markdown reports.",
    )
    return parser.parse_args()


def slugify(text: str) -> str:
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in {" ", "-", "_"}:
            if out and out[-1] != "-":
                out.append("-")
    return "".join(out).strip("-")


def inline_markup(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = LINK_RE.sub(lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">{m.group(1)}</a>', escaped)
    escaped = INLINE_CODE_RE.sub(r"<code>\1</code>", escaped)
    escaped = BOLD_RE.sub(r"<strong>\1</strong>", escaped)
    escaped = ITALIC_RE.sub(r"<em>\1</em>", escaped)
    return escaped


def is_table_row(line: str) -> bool:
    compact = line.strip()
    return compact.startswith("|") and compact.endswith("|") and compact.count("|") >= 2


def split_table_row(line: str) -> List[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def build_toc(headings: Sequence[Tuple[int, str, str]]) -> str:
    items = []
    for level, title, anchor in headings:
        if level > 2:
            continue
        cls = "toc-sub" if level == 2 else "toc-main"
        items.append(f'<li class="{cls}"><a href="#{anchor}">{html.escape(title)}</a></li>')
    if not items:
        return ""
    return (
        '<nav class="toc"><div class="eyebrow">Contents</div><ul>'
        + "".join(items)
        + "</ul></nav>"
    )


def render_blocks(lines: Sequence[str]) -> Tuple[str, List[Tuple[int, str, str]]]:
    html_parts: List[str] = []
    headings: List[Tuple[int, str, str]] = []
    paragraph: List[str] = []
    list_items: List[str] = []
    in_code = False
    code_lines: List[str] = []
    idx = 0

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            text = " ".join(chunk.strip() for chunk in paragraph if chunk.strip())
            html_parts.append(f"<p>{inline_markup(text)}</p>")
            paragraph = []

    def flush_list() -> None:
        nonlocal list_items
        if list_items:
            html_parts.append("<ul>" + "".join(f"<li>{item}</li>" for item in list_items) + "</ul>")
            list_items = []

    while idx < len(lines):
        line = lines[idx].rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("```"):
            flush_paragraph()
            flush_list()
            if in_code:
                html_parts.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            idx += 1
            continue

        if in_code:
            code_lines.append(line)
            idx += 1
            continue

        if not stripped:
            flush_paragraph()
            flush_list()
            idx += 1
            continue

        heading = HEADING_RE.match(stripped)
        if heading:
            flush_paragraph()
            flush_list()
            level = len(heading.group(1))
            title = heading.group(2).strip()
            anchor = slugify(title) or f"section-{len(headings)+1}"
            headings.append((level, title, anchor))
            tag = f"h{min(level, 3)}"
            html_parts.append(f'<section id="{anchor}"><{tag}>{html.escape(title)}</{tag}>')
            idx += 1
            continue

        if is_table_row(stripped):
            flush_paragraph()
            flush_list()
            rows = [split_table_row(stripped)]
            idx += 1
            if idx < len(lines) and TABLE_SEPARATOR_RE.match(lines[idx].strip()):
                idx += 1
            while idx < len(lines) and is_table_row(lines[idx].strip()):
                rows.append(split_table_row(lines[idx].strip()))
                idx += 1
            if rows:
                header = rows[0]
                body = rows[1:]
                table_html = ["<div class=\"table-wrap\"><table><thead><tr>"]
                table_html.extend(f"<th>{inline_markup(cell)}</th>" for cell in header)
                table_html.append("</tr></thead><tbody>")
                for row in body:
                    table_html.append("<tr>")
                    padded = row + [""] * max(0, len(header) - len(row))
                    table_html.extend(f"<td>{inline_markup(cell)}</td>" for cell in padded[: len(header)])
                    table_html.append("</tr>")
                table_html.append("</tbody></table></div>")
                html_parts.append("".join(table_html))
            continue

        if stripped.startswith(("- ", "* ")):
            flush_paragraph()
            list_items.append(inline_markup(stripped[2:].strip()))
            idx += 1
            continue

        paragraph.append(stripped)
        idx += 1

    flush_paragraph()
    flush_list()
    if in_code:
        html_parts.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")

    rendered = "\n".join(part + ("</section>" if part.startswith("<section ") else "") for part in html_parts)
    return rendered, headings


def extract_title(lines: Sequence[str], fallback: str) -> str:
    for line in lines:
        match = HEADING_RE.match(line.strip())
        if match and len(match.group(1)) == 1:
            return match.group(2).strip()
    return fallback


def render_document(title: str, body_html: str, toc_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<style>
  :root {{
    --bg: #f7f4ef;
    --paper: #fffdf8;
    --ink: #1c1a17;
    --muted: #6e6457;
    --accent: #9a3412;
    --line: #e8dece;
    --code: #f3ede2;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: radial-gradient(circle at top, #efe4d3 0%, var(--bg) 45%);
    color: var(--ink);
    font: 16px/1.7 Georgia, "Times New Roman", serif;
  }}
  .wrap {{
    max-width: 960px;
    margin: 0 auto;
    padding: 32px 20px 64px;
  }}
  .back {{
    display: inline-block;
    margin-bottom: 20px;
    color: var(--accent);
    text-decoration: none;
    font: 600 13px/1.2 ui-monospace, SFMono-Regular, Consolas, monospace;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}
  .hero {{
    background: var(--paper);
    border: 1px solid var(--line);
    padding: 32px;
    box-shadow: 0 12px 40px rgba(63, 40, 16, 0.08);
  }}
  h1, h2, h3 {{
    font-family: "Segoe UI", Arial, sans-serif;
    line-height: 1.2;
    letter-spacing: -0.02em;
    margin: 0 0 16px;
  }}
  h1 {{ font-size: clamp(30px, 5vw, 46px); }}
  h2 {{ font-size: 28px; margin-top: 12px; }}
  h3 {{ font-size: 22px; margin-top: 12px; }}
  p {{ margin: 0 0 16px; }}
  .toc {{
    margin: 28px 0 0;
    padding-top: 24px;
    border-top: 1px solid var(--line);
  }}
  .eyebrow {{
    color: var(--accent);
    font: 700 12px/1 ui-monospace, SFMono-Regular, Consolas, monospace;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 14px;
  }}
  .toc ul {{
    list-style: none;
    padding: 0;
    margin: 0;
    columns: 2;
    column-gap: 24px;
  }}
  .toc li {{ margin: 0 0 8px; }}
  .toc a {{
    color: var(--muted);
    text-decoration: none;
  }}
  .toc a:hover {{ color: var(--accent); }}
  main {{
    margin-top: 28px;
    background: var(--paper);
    border: 1px solid var(--line);
    padding: 32px;
    box-shadow: 0 12px 40px rgba(63, 40, 16, 0.08);
  }}
  section {{
    padding: 20px 0 8px;
    border-top: 1px solid var(--line);
  }}
  section:first-child {{ border-top: 0; padding-top: 0; }}
  ul {{ padding-left: 20px; margin: 0 0 16px; }}
  code {{
    background: var(--code);
    padding: 0.1em 0.35em;
    border-radius: 4px;
    font: 0.92em ui-monospace, SFMono-Regular, Consolas, monospace;
  }}
  pre {{
    margin: 0 0 16px;
    overflow: auto;
    background: var(--code);
    padding: 16px;
    border: 1px solid var(--line);
  }}
  pre code {{ background: transparent; padding: 0; }}
  .table-wrap {{
    overflow-x: auto;
    margin: 0 0 18px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }}
  th, td {{
    border-bottom: 1px solid var(--line);
    padding: 10px 12px;
    vertical-align: top;
    text-align: left;
  }}
  th {{
    color: var(--accent);
    font: 700 12px/1.2 ui-monospace, SFMono-Regular, Consolas, monospace;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}
  a {{ color: var(--accent); }}
  @media (max-width: 720px) {{
    .toc ul {{ columns: 1; }}
    .hero, main {{ padding: 22px; }}
  }}
</style>
</head>
<body>
  <div class="wrap">
    <a class="back" href="../index.html">&larr; Back to Toolkit</a>
    <header class="hero">
      <h1>{html.escape(title)}</h1>
      {toc_html}
    </header>
    <main>
      {body_html}
    </main>
  </div>
</body>
</html>
"""


def render_one(path: Path) -> Path:
    source = path.read_text(encoding="utf-8", errors="replace")
    lines = source.splitlines()
    title = extract_title(lines, path.stem)
    body_html, headings = render_blocks(lines)
    toc_html = build_toc(headings)
    document = render_document(title, body_html, toc_html)
    out_path = path.with_suffix(".html")
    out_path.write_text(document, encoding="utf-8")
    return out_path


def find_reports(reports_dir: Path, pattern: str) -> Iterable[Path]:
    return sorted(reports_dir.glob(pattern))


def main() -> None:
    args = parse_args()
    reports_dir = Path(args.reports_dir)
    outputs = []
    for path in find_reports(reports_dir, args.pattern):
        outputs.append(render_one(path))
    if not outputs:
        raise SystemExit(f"No markdown reports matched {args.pattern} in {reports_dir}")
    for out in outputs:
        print(f"rendered {out}")


if __name__ == "__main__":
    main()
