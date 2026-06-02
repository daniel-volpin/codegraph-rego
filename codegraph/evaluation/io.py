from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def render_markdown_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    header_line = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join(["---"] * len(headers)) + " |"
    body_lines = []
    for row in rows:
        body_lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join([header_line, divider, *body_lines]) + "\n"


def render_latex_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    caption: str | None = None,
    label: str | None = None,
) -> str:
    column_format = "l" * len(headers)
    lines = [f"\\begin{{tabular}}{{{column_format}}}", "\\hline"]
    lines.append(" & ".join(headers) + " \\\\")
    lines.append("\\hline")
    for row in rows:
        lines.append(" & ".join(str(cell) for cell in row) + " \\\\")
    lines.append("\\hline")
    lines.append("\\end{tabular}")
    if caption:
        lines = [r"\begin{table}[h]", r"\centering", *lines]
        lines.append(f"\\caption{{{caption}}}")
        if label:
            lines.append(f"\\label{{{label}}}")
        lines.append("\\end{table}")
    return "\n".join(lines) + "\n"
