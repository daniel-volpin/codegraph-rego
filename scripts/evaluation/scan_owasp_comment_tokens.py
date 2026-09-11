"""Scan OWASP Benchmark Java comments for lexical-noise trigger tokens."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from codegraph.evaluation.owasp_lexical_eval import resolve_owasp_root  # noqa: E402
from codegraph.evaluation.provenance import collect_provenance, write_provenance  # noqa: E402

TOKENS = (
    "MD5",
    "MessageDigest",
    "executeQuery",
    "ProcessBuilder",
    "new Random",
    "XPathFactory",
)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _git_sha(path: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def iter_java_comments(source: str) -> Iterable[str]:
    """Yield Java line and block comments without parsing string literals."""

    i = 0
    n = len(source)
    state = "code"
    start = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == '"' and source[i : i + 3] == '"""':
                state = "text_block"
                i += 3
                continue
            if ch == '"':
                state = "string"
                i += 1
                continue
            if ch == "'":
                state = "char"
                i += 1
                continue
            if ch == "/" and nxt == "/":
                start = i
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                start = i
                i += 2
                state = "block_comment"
                continue
        elif state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                state = "code"
        elif state == "text_block":
            if source[i : i + 3] == '"""':
                state = "code"
                i += 3
                continue
        elif state == "line_comment":
            if ch in "\r\n":
                yield source[start:i]
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                yield source[start : i + 2]
                i += 2
                state = "code"
                continue
        i += 1
    if state == "line_comment":
        yield source[start:n]


def scan(java_files: Iterable[Path]) -> dict[str, object]:
    counts = Counter({token: 0 for token in TOKENS})
    files_with_comment_hits: list[dict[str, object]] = []
    total_comment_blocks = 0
    for path in java_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        file_counts = Counter({token: 0 for token in TOKENS})
        for comment in iter_java_comments(text):
            total_comment_blocks += 1
            for token in TOKENS:
                count = comment.count(token)
                if count:
                    counts[token] += count
                    file_counts[token] += count
        if any(file_counts.values()):
            files_with_comment_hits.append(
                {
                    "file": path.as_posix(),
                    "token_counts": dict(file_counts),
                    "total": sum(file_counts.values()),
                }
            )
    return {
        "token_counts_in_comments": dict(counts),
        "total_comment_occurrences": sum(counts.values()),
        "total_comment_blocks_scanned": total_comment_blocks,
        "files_with_comment_hits": files_with_comment_hits,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owasp-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    owasp_root = resolve_owasp_root(args.owasp_root)
    if owasp_root is None:
        parser.error("OWASP Benchmark root not found")
    java_root = owasp_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    java_files = sorted(java_root.glob("BenchmarkTest*.java"))

    summary = {
        "generated_at": _now(),
        "script_path": Path(__file__).as_posix(),
        "owasp_root": owasp_root.as_posix(),
        "owasp_git_sha": _git_sha(owasp_root),
        "codegraph_git_sha": _git_sha(ROOT),
        "total_java_cases_scanned": len(java_files),
        "expected_total_java_cases": 2740,
        "tokens": list(TOKENS),
        **scan(java_files),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_provenance(
        collect_provenance(
            eval_kind="owasp_comment_token_scan_v1",
            output_dir=args.output_dir,
            extra={
                "owasp_root": owasp_root.as_posix(),
                "owasp_git_sha": summary["owasp_git_sha"],
                "tokens": list(TOKENS),
                "total_java_cases_scanned": len(java_files),
            },
        ),
        args.output_dir,
    )
    print(f"wrote {args.output_dir / 'summary.json'}")
    print(json.dumps({k: summary[k] for k in ("total_java_cases_scanned", "total_comment_occurrences")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
