#!/usr/bin/env python3
"""Keep Markdown prose paragraphs on one line per paragraph.

Hard-wrapped prose renders identically -- a single newline inside a paragraph is
a soft break -- but every later edit reflows the whole paragraph, so diffs show
churn that has nothing to do with the change. One line per paragraph keeps a
diff to the sentences that actually moved.

Only prose paragraphs are joined. Fenced and indented code, tables, headings,
list items, block quotes, HTML blocks, link-reference definitions and anything
ending in a hard break are left exactly as they are, because in those contexts a
newline is significant.

``--check`` reports files that need joining and exits non-zero; ``--fix``
rewrites them. Every rewrite is verified to change nothing but line breaks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_FENCE = re.compile(r"^\s{0,3}(?:```|~~~)")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s")
_SETEXT_UNDERLINE = re.compile(r"^\s{0,3}(?:=+|-{2,})\s*$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s)")
_TABLE_ROW = re.compile(r"^\s*\|")
_BLOCKQUOTE = re.compile(r"^\s{0,3}>")
_HTML_BLOCK = re.compile(r"^\s{0,3}<")
_LINK_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:")
_THEMATIC_BREAK = re.compile(r"^\s{0,3}(?:\*\s*){3,}$|^\s{0,3}(?:-\s*){3,}$|^\s{0,3}(?:_\s*){3,}$")
_INDENTED_CODE = re.compile(r"^(?: {4,}|\t)")
_FRONT_MATTER = re.compile(r"^---\s*$")


def _is_prose(line: str) -> bool:
    if not line.strip():
        return False
    return not any(
        pattern.match(line)
        for pattern in (
            _HEADING,
            _LIST_ITEM,
            _TABLE_ROW,
            _BLOCKQUOTE,
            _HTML_BLOCK,
            _LINK_DEFINITION,
            _THEMATIC_BREAK,
            _INDENTED_CODE,
            _SETEXT_UNDERLINE,
        )
    )


def _ends_with_hard_break(line: str) -> bool:
    """A hard break is meaningful markup, so such a line must not be joined."""
    return line.endswith("  ") or line.rstrip().endswith("\\")


def join_prose(text: str) -> str:
    lines = text.split("\n")
    output: list[str] = []
    index = 0
    in_fence = False
    in_front_matter = bool(lines and _FRONT_MATTER.match(lines[0]))

    while index < len(lines):
        line = lines[index]

        if _FENCE.match(line):
            in_fence = not in_fence
            output.append(line)
            index += 1
            continue
        if in_front_matter:
            output.append(line)
            if index > 0 and _FRONT_MATTER.match(line):
                in_front_matter = False
            index += 1
            continue
        if in_fence or not _is_prose(line):
            output.append(line)
            index += 1
            continue

        # A prose paragraph: absorb following prose lines into one line.
        paragraph = [line.rstrip()]
        index += 1
        while index < len(lines) and _is_prose(lines[index]) and not _ends_with_hard_break(lines[index - 1]):
            # A setext underline turns the previous line into a heading; stop.
            if _SETEXT_UNDERLINE.match(lines[index]):
                break
            paragraph.append(lines[index].strip())
            index += 1
        output.append(" ".join(part for part in paragraph if part))

    return "\n".join(output)


def _normalized(text: str) -> str:
    """Whitespace-collapsed content, for proving only breaks changed."""
    return re.sub(r"\s+", " ", text).strip()


def process(path: Path, *, fix: bool) -> bool:
    original = path.read_text(encoding="utf-8")
    joined = join_prose(original)
    if joined == original:
        return False
    if _normalized(joined) != _normalized(original):
        raise SystemExit(f"{path}: refusing to rewrite; content would change beyond line breaks")
    if fix:
        path.write_text(joined, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to inspect")
    parser.add_argument("--fix", action="store_true", help="Rewrite files instead of reporting them")
    parser.add_argument(
        "--exclude",
        action="append",
        default=["outputs", "node_modules", ".venv", ".git", ".pytest_cache", "BenchmarkJava", "target"],
        help="Directory names to skip",
    )
    args = parser.parse_args()

    targets: list[Path] = []
    for raw in args.paths:
        path = Path(raw)
        if path.is_file() and path.suffix == ".md":
            targets.append(path)
        elif path.is_dir():
            targets.extend(
                candidate
                for candidate in sorted(path.rglob("*.md"))
                if not set(candidate.parts).intersection(args.exclude)
            )

    changed = [target for target in targets if process(target, fix=args.fix)]
    if not changed:
        print(f"{len(targets)} Markdown files already use one line per paragraph")
        return 0
    verb = "rewrote" if args.fix else "would rewrite"
    print(f"{verb} {len(changed)} of {len(targets)} files:")
    for target in changed:
        print(f"  {target}")
    return 0 if args.fix else 1


if __name__ == "__main__":
    sys.exit(main())
