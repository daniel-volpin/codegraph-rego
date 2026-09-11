"""Per-run provenance manifest.

``collect_provenance`` captures git SHA, OPA version, config sha256,
lock-file hashes, seed, and LLM block; ``write_provenance`` persists it
as ``provenance.json`` next to other run artifacts. Every probe is
wrapped so a missing tool degrades to ``{"error": "..."}`` rather than
aborting the run.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codegraph.config import settings

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]


def _now_iso_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _safe_run(cmd: list[str], *, cwd: Path | None = None, timeout: float = 5.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except FileNotFoundError as exc:
        return {"error": f"command_not_found: {exc.filename or cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except OSError as exc:
        return {"error": f"os_error: {exc}"}


def _git_info(repo: Path = _PROJECT_ROOT) -> dict[str, Any]:
    info: dict[str, Any] = {}
    sha = _safe_run(["git", "rev-parse", "HEAD"], cwd=repo)
    info["sha"] = sha.get("stdout") if sha.get("returncode") == 0 else None
    info["sha_error"] = sha.get("error") or sha.get("stderr") if "stdout" not in sha or sha.get("returncode") != 0 else None

    branch = _safe_run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo)
    info["branch"] = branch.get("stdout") if branch.get("returncode") == 0 else None

    status = _safe_run(["git", "status", "--porcelain"], cwd=repo)
    info["dirty"] = bool(status.get("stdout")) if status.get("returncode") == 0 else None
    info["dirty_files"] = (
        [line.strip() for line in status.get("stdout", "").splitlines() if line.strip()]
        if status.get("returncode") == 0
        else None
    )

    last_msg = _safe_run(["git", "log", "-1", "--pretty=%s"], cwd=repo)
    info["last_commit_subject"] = last_msg.get("stdout") if last_msg.get("returncode") == 0 else None

    return {k: v for k, v in info.items() if v is not None}


def _opa_version() -> dict[str, Any]:
    result = _safe_run(["opa", "version"])
    if result.get("returncode") == 0:
        return {"raw": result.get("stdout")}
    return {"error": result.get("error") or result.get("stderr") or "opa_failed"}


def _file_sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _git_sha_for_path(path: Path) -> str | None:
    """Best-effort git SHA of the repo containing ``path`` (pins the OWASP corpus)."""
    anchor = path if path.is_dir() else path.parent
    result = _safe_run(["git", "-C", str(anchor), "rev-parse", "HEAD"])
    if result.get("returncode") == 0:
        return result.get("stdout") or None
    return None


def _git_root_for_path(path: Path) -> Path | None:
    """Best-effort root of the git repository containing ``path``."""
    anchor = path if path.is_dir() else path.parent
    result = _safe_run(["git", "-C", str(anchor), "rev-parse", "--show-toplevel"])
    if result.get("returncode") != 0 or not result.get("stdout"):
        return None
    return Path(result["stdout"])


def _portable_path(
    path: str | os.PathLike | None,
    *,
    repo_root: Path,
    external_root: Path | None = None,
) -> str | None:
    """Return a reproducible path without exposing a machine-specific prefix."""
    if path is None:
        return None

    path_obj = Path(path)
    if not path_obj.is_absolute():
        return path_obj.as_posix()

    try:
        resolved_path = path_obj.resolve(strict=False)
    except OSError:
        resolved_path = path_obj

    for candidate_root in (repo_root, external_root):
        if candidate_root is None:
            continue
        try:
            return resolved_path.relative_to(candidate_root.resolve(strict=False)).as_posix()
        except (OSError, ValueError):
            continue

    return path_obj.name or None


def _portable_metadata(value: Any, *, repo_root: Path, key: str | None = None) -> Any:
    """Normalize path-like values nested in optional provenance metadata."""
    if isinstance(value, dict):
        return {
            item_key: _portable_metadata(item_value, repo_root=repo_root, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_portable_metadata(item, repo_root=repo_root, key=key) for item in value]
    if isinstance(value, os.PathLike):
        return _portable_path(value, repo_root=repo_root)
    if isinstance(value, str) and key:
        normalized_key = key.lower()
        if normalized_key in {"path", "root", "dir", "file", "executable"} or normalized_key.endswith(
            ("_path", "_root", "_dir", "_file", "_executable")
        ):
            return _portable_path(value, repo_root=repo_root)
    return value


def _ground_truth_info(
    ground_truth_path: str | os.PathLike | None,
    *,
    repo_root: Path,
) -> dict[str, Any] | None:
    """Hash the ground-truth labels and pin the corpus commit they were scored against."""
    if not ground_truth_path:
        return None
    path = Path(ground_truth_path)
    corpus_root = _git_root_for_path(path) if path.exists() else None
    info: dict[str, Any] = {
        "path": _portable_path(path, repo_root=repo_root, external_root=corpus_root),
    }
    if path.exists():
        info["sha256"] = _file_sha256(path)
        info["corpus_git_sha"] = _git_sha_for_path(path)
    else:
        info["error"] = "ground_truth_not_found"
    return info


def _package_version() -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("codegraph")
        except PackageNotFoundError:
            return None
    except ImportError:
        return None


def _redact_uri(uri: str | None) -> str | None:
    """Strip embedded credentials from a connection URI before recording it."""
    if not uri:
        return uri
    if "@" not in uri:
        return uri
    scheme, _, rest = uri.partition("://")
    if not rest:
        return uri
    creds, _, host = rest.rpartition("@")
    if not creds:
        return uri
    return f"{scheme}://***@{host}"


def _neo4j_settings() -> dict[str, Any]:
    return {
        "uri": _redact_uri(getattr(settings, "neo4j_uri", None)),
        "user": getattr(settings, "neo4j_user", None),
    }


def collect_provenance(
    *,
    eval_kind: str,
    config_path: str | os.PathLike | None = None,
    output_dir: str | os.PathLike | None = None,
    ground_truth_path: str | os.PathLike | None = None,
    seed: int | None = None,
    llm: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Return a JSON-serialisable snapshot of inputs influencing this run.

    Flat top level so ``jq .git.sha provenance.json`` works directly.
    """
    root = Path(repo_root) if repo_root else _PROJECT_ROOT
    config_path_obj = Path(config_path) if config_path else None
    uv_lock = root / "uv.lock"
    pyproject = root / "pyproject.toml"

    provenance: dict[str, Any] = {
        "schema_version": 2,
        "eval_kind": eval_kind,
        "generated_at": _now_iso_utc(),
        "git": _git_info(root),
        "python": {
            "version": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "executable": Path(sys.executable).name,
        },
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
        },
        "package_version": _package_version(),
        "uv_lock_sha256": _file_sha256(uv_lock) if uv_lock.exists() else None,
        "pyproject_sha256": _file_sha256(pyproject) if pyproject.exists() else None,
        "opa": _opa_version(),
        "neo4j": _neo4j_settings(),
        "config": {
            "path": _portable_path(config_path_obj, repo_root=root),
            "sha256": _file_sha256(config_path_obj) if config_path_obj and config_path_obj.exists() else None,
        },
        "ground_truth": _ground_truth_info(ground_truth_path, repo_root=root),
        "output_dir": _portable_path(output_dir, repo_root=root),
        "seed": seed,
        "llm": dict(llm) if llm else None,
    }
    if extra:
        provenance["extra"] = _portable_metadata(dict(extra), repo_root=root)
    return provenance


def write_provenance(provenance: dict[str, Any], output_dir: str | os.PathLike) -> Path:
    """Write ``provenance.json`` into ``output_dir`` and return the path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "provenance.json"
    with path.open("w", encoding="utf-8") as handle:
        json.dump(provenance, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path
