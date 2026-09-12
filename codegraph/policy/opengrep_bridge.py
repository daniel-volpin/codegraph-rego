"""Pluggable taint-analysis engine: discovers OpenGrep rules and imports their
findings through the existing SARIF bridge.

Adding a new taint-backed rule requires no code changes here: drop a new
OpenGrep rule YAML file under ``policy/opengrep/`` with its ``id:`` set to the
canonical rule id, and tag that rule's ``evidence_source`` as ``"opengrep"``
in the policy registry. This module discovers whatever rule files exist at
call time and runs them all in a single scan.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml
from neo4j import Driver

from codegraph.policy.sarif_import import import_findings_from_sarif

LOGGER = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES_DIR = PROJECT_ROOT / "policy" / "opengrep"


def discover_rule_files(rules_dir: Path = DEFAULT_RULES_DIR) -> list[Path]:
    if not rules_dir.is_dir():
        return []
    return sorted({*rules_dir.glob("*.yaml"), *rules_dir.glob("*.yml")})


def discover_rule_ids(rules_dir: Path = DEFAULT_RULES_DIR) -> set[str]:
    """Rule ids declared across every discovered OpenGrep rule file."""
    rule_ids: set[str] = set()
    for rule_file in discover_rule_files(rules_dir):
        try:
            doc = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as exc:
            LOGGER.warning("Could not parse OpenGrep rule file %s: %s", rule_file, exc)
            continue
        for rule in doc.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rule_ids.add(str(rule["id"]))
    return rule_ids


def _active_revision_file_paths(driver: Driver, *, workspace_root: str | None) -> list[str]:
    with driver.session() as session:
        records = session.run(
            """
            MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision)
            MATCH (m:Method {workspace_id: wr.workspace_id, revision_id: wr.revision_id})
            WHERE wr.schema_version = 'codegraph-jdt/v1'
              AND m.file_path IS NOT NULL
              AND ($workspace_root IS NULL OR m.file_path STARTS WITH $workspace_root)
            RETURN DISTINCT m.file_path AS file_path
            """,
            workspace_root=workspace_root,
        )
        return [record["file_path"] for record in records if record["file_path"]]


def run_opengrep_scan(
    file_paths: list[str],
    *,
    rules_dir: Path = DEFAULT_RULES_DIR,
    binary: str = "opengrep",
    timeout: float = 120.0,
) -> dict[str, Any] | None:
    """Run OpenGrep taint-mode over *file_paths*, returning the parsed SARIF document."""
    if not shutil.which(binary):
        LOGGER.warning("%s not found on PATH; skipping OpenGrep-backed rules.", binary)
        return None
    if not file_paths:
        return None

    with tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False) as handle:
        sarif_path = Path(handle.name)
    try:
        cmd = [
            binary,
            "scan",
            "--taint-intrafile",
            "--dataflow-traces",
            "--no-rewrite-rule-ids",
            "--config",
            str(rules_dir),
            "--sarif-output",
            str(sarif_path),
            "--quiet",
            *file_paths,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode not in (0, 1):  # 1 == findings present, still success
            LOGGER.error("OpenGrep scan failed (exit %s): %s", result.returncode, result.stderr[-2000:])
            return None
        if not sarif_path.is_file() or sarif_path.stat().st_size == 0:
            return None
        return json.loads(sarif_path.read_text(encoding="utf-8"))
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        LOGGER.error("OpenGrep scan failed: %s", exc)
        return None
    finally:
        sarif_path.unlink(missing_ok=True)


def verify_candidate_source(
    *,
    rule_id: str,
    candidate_file_source: str,
    source_file_name: str,
    rules_dir: Path = DEFAULT_RULES_DIR,
    timeout: float = 120.0,
) -> list[dict[str, Any]]:
    """Re-run OpenGrep over a candidate compilation unit and return findings for *rule_id*.

    Raises on engine failure: a remediation gate must fail closed rather than
    treat "the scanner did not run" as "the finding is fixed".
    """
    if not shutil.which("opengrep"):
        raise RuntimeError("opengrep_unavailable")

    with tempfile.TemporaryDirectory(prefix="opengrep-verify-") as tmp_dir:
        # Java resolution expects the file name to match its public type, so the
        # candidate keeps the original file's name.
        candidate_path = Path(tmp_dir) / Path(source_file_name).name
        candidate_path.write_text(candidate_file_source, encoding="utf-8")
        sarif_doc = run_opengrep_scan([str(candidate_path)], rules_dir=rules_dir, timeout=timeout)
        if sarif_doc is None:
            raise RuntimeError("opengrep_verification_failed")

    findings: list[dict[str, Any]] = []
    for run in sarif_doc.get("runs") or []:
        for result in run.get("results") or []:
            if str(result.get("ruleId") or "") != rule_id:
                continue
            message = str((result.get("message") or {}).get("text") or "OpenGrep taint finding")
            findings.append({"violation_id": rule_id, "rule_id": rule_id, "reason": message})
    return findings


def evaluate_opengrep_rules(
    *,
    workspace_root: str | None,
    neo4j_driver: Driver,
    rules_dir: Path = DEFAULT_RULES_DIR,
    timeout: float = 120.0,
) -> list[dict[str, Any]]:
    """Run every discovered OpenGrep rule and return violations in the same shape as OPA-native ones."""
    if not discover_rule_files(rules_dir):
        return []

    file_paths = _active_revision_file_paths(neo4j_driver, workspace_root=workspace_root)
    sarif_doc = run_opengrep_scan(file_paths, rules_dir=rules_dir, timeout=timeout)
    if not sarif_doc:
        return []

    return import_findings_from_sarif(sarif_doc, workspace_root=workspace_root, neo4j_driver=neo4j_driver)
