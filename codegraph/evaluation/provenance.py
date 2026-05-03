"""Provenance capture for benchmark eval runs.

Every run script under ``run_*_eval.py`` should write a ``provenance.json``
next to its other artifacts so that a future reader can answer: which code,
which configs, which dependency versions, which LLM model and temperature,
and which seed produced this number?

Usage:

    from codegraph.evaluation.provenance import collect_provenance, write_provenance

    provenance = collect_provenance(
        eval_kind="detection",
        config_path=args.config,
        output_dir=args.output_dir,
        seed=args.seed,
        llm={"model": settings.llm_model, "temperature": settings.llm_temperature},
    )
    write_provenance(provenance, args.output_dir)

The collector never raises: every probe is wrapped so a missing tool degrades
to ``{"error": "..."}`` in the manifest rather than aborting the run.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from codegraph.config import settings

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_run(cmd: list[str], *, cwd: Optional[Path] = None, timeout: float = 5.0) -> Dict[str, Any]:
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


def _git_info(repo: Path = _PROJECT_ROOT) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
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


def _opa_version() -> Dict[str, Any]:
    result = _safe_run(["opa", "version"])
    if result.get("returncode") == 0:
        return {"raw": result.get("stdout")}
    return {"error": result.get("error") or result.get("stderr") or "opa_failed"}


def _file_sha256(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _package_version() -> Optional[str]:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("codegraph")
        except PackageNotFoundError:
            return None
    except ImportError:
        return None


def _redact_uri(uri: Optional[str]) -> Optional[str]:
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


def _neo4j_settings() -> Dict[str, Any]:
    return {
        "uri": _redact_uri(getattr(settings, "neo4j_uri", None)),
        "user": getattr(settings, "neo4j_user", None),
    }


def collect_provenance(
    *,
    eval_kind: str,
    config_path: Optional[str | os.PathLike] = None,
    output_dir: Optional[str | os.PathLike] = None,
    seed: Optional[int] = None,
    llm: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Capture a snapshot of everything that influences this eval run.

    The result is JSON-serializable and intentionally flat at the top level so
    that ``jq .git.sha provenance.json`` works without indirection.
    """
    root = Path(repo_root) if repo_root else _PROJECT_ROOT
    config_path_obj = Path(config_path) if config_path else None
    uv_lock = root / "uv.lock"
    pyproject = root / "pyproject.toml"

    provenance: Dict[str, Any] = {
        "schema_version": 1,
        "eval_kind": eval_kind,
        "generated_at": _now_iso_utc(),
        "git": _git_info(root),
        "python": {
            "version": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
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
            "path": str(config_path_obj) if config_path_obj else None,
            "sha256": _file_sha256(config_path_obj) if config_path_obj and config_path_obj.exists() else None,
        },
        "output_dir": str(output_dir) if output_dir else None,
        "seed": seed,
        "llm": dict(llm) if llm else None,
    }
    if extra:
        provenance["extra"] = dict(extra)
    return provenance


def write_provenance(provenance: Dict[str, Any], output_dir: str | os.PathLike) -> Path:
    """Write ``provenance.json`` into ``output_dir``. Returns the path written."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "provenance.json"
    with path.open("w", encoding="utf-8") as handle:
        json.dump(provenance, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path
