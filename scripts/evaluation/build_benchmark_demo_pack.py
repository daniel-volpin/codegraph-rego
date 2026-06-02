"""
Build a curated OWASP Benchmark subset for live framework demos.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "demo" / "benchmark-framework-demo" / "manifest.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the curated OWASP Benchmark demo pack.")
    parser.add_argument(
        "--benchmark-root",
        default=os.environ.get("OWASP_BENCHMARK_ROOT"),
        help="Path to the BenchmarkJava checkout (defaults to OWASP_BENCHMARK_ROOT).",
    )
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST.as_posix(),
        help="Path to the demo manifest JSON.",
    )
    parser.add_argument(
        "--output-dir",
        default=(REPO_ROOT / "demo" / "benchmark-framework-demo" / "build").as_posix(),
        help="Directory where the generated demo tree and zip should be written.",
    )
    return parser.parse_args()


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Manifest must be a JSON object.")
    testcases = payload.get("testcases")
    if not isinstance(testcases, list) or not testcases:
        raise ValueError("Manifest must include a non-empty 'testcases' list.")
    return payload


def _copy_if_exists(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _iter_testcase_ids(manifest: dict[str, Any]) -> Iterable[str]:
    for entry in manifest.get("testcases", []):
        if isinstance(entry, dict):
            testcase_id = entry.get("testcase_id")
            if isinstance(testcase_id, str) and testcase_id.strip():
                yield testcase_id.strip()


def _stage_selected_testcases(benchmark_root: Path, destination_root: Path, testcase_ids: list[str]) -> list[str]:
    source_root = benchmark_root / "src" / "main" / "java"
    destination_source_root = destination_root / "src" / "main" / "java"
    missing: list[str] = []

    for testcase_id in testcase_ids:
        matches = list(source_root.rglob(f"{testcase_id}.java"))
        if not matches:
            missing.append(testcase_id)
            continue
        source_file = matches[0]
        relative = source_file.relative_to(source_root)
        target = destination_source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target)

    return missing


def build_demo_pack(benchmark_root: Path, manifest_path: Path, output_dir: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    pack_name = str(manifest.get("name") or "benchmark-framework-demo")
    pack_root = output_dir / pack_name
    if pack_root.exists():
        shutil.rmtree(pack_root)
    pack_root.mkdir(parents=True, exist_ok=True)

    _copy_if_exists(benchmark_root / "pom.xml", pack_root / "pom.xml")
    _copy_if_exists(benchmark_root / ".mvn", pack_root / ".mvn")
    _copy_if_exists(benchmark_root / "mvnw", pack_root / "mvnw")
    _copy_if_exists(benchmark_root / "mvnw.cmd", pack_root / "mvnw.cmd")
    _copy_if_exists(benchmark_root / "src" / "main" / "resources", pack_root / "src" / "main" / "resources")
    _copy_if_exists(
        benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "helpers",
        pack_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "helpers",
    )

    testcase_ids = list(_iter_testcase_ids(manifest))
    missing = _stage_selected_testcases(benchmark_root, pack_root, testcase_ids)
    if missing:
        raise FileNotFoundError(f"Missing benchmark testcase files: {', '.join(missing)}")

    (pack_root / "DEMO_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    zip_base = output_dir / pack_name
    archive_path = shutil.make_archive(zip_base.as_posix(), "zip", root_dir=pack_root.parent, base_dir=pack_root.name)
    return {
        "pack_root": pack_root.as_posix(),
        "zip_path": archive_path,
        "testcase_ids": testcase_ids,
    }


def main() -> int:
    args = parse_args()
    if not args.benchmark_root:
        raise SystemExit("benchmark root is required; pass --benchmark-root or set OWASP_BENCHMARK_ROOT")

    benchmark_root = Path(args.benchmark_root).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    result = build_demo_pack(benchmark_root, manifest_path, output_dir)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
