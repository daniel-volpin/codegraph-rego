"""SARIF v2.1.0 ingestion and Neo4j AST method resolution bridge."""

from __future__ import annotations

import json
import logging
from typing import Any

from neo4j import Driver

from codegraph.policy.packs.loader import get_policy_pack_registry
from codegraph.remediation.capabilities import remediation_capability_dict

LOGGER = logging.getLogger(__name__)

SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _taint_paths_from_code_flows(result: dict[str, Any], *, rule_id: str) -> list[dict[str, Any]]:
    """Translate SARIF codeFlows/threadFlows into verified taint propagation paths.

    Each threadFlow is an ordered source → propagator → sink dataflow trace
    produced by the analyzer, so the emitted chain reflects observed data
    dependencies rather than call-graph reachability.
    """
    taint_paths: list[dict[str, Any]] = []
    for code_flow in result.get("codeFlows") or []:
        if not isinstance(code_flow, dict):
            continue
        for thread_flow in code_flow.get("threadFlows") or []:
            if not isinstance(thread_flow, dict):
                continue
            chain: list[dict[str, Any]] = []
            for entry in thread_flow.get("locations") or []:
                location = (entry or {}).get("location") or {}
                physical = location.get("physicalLocation") or {}
                region = physical.get("region") or {}
                text = str((location.get("message") or {}).get("text") or "").strip()
                chain.append(
                    {
                        "signature": text,
                        "file_path": (physical.get("artifactLocation") or {}).get("uri"),
                        "line": region.get("startLine"),
                        "snippet": (region.get("snippet") or {}).get("text"),
                    }
                )
            if not chain:
                continue
            taint_paths.append(
                {
                    "sink_type": rule_id,
                    "hops": len(chain) - 1,
                    "chain": chain,
                }
            )
    return taint_paths


def _resolve_method_for_location(
    driver: Driver,
    *,
    file_path: str,
    start_line: int,
    workspace_root: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Find the enclosing method only within an active workspace revision."""
    try:
        clean_path = file_path.replace("\\", "/").lstrip("/")
        with driver.session() as session:
            record = session.run(
                """
                MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision)
                MATCH (m:Method {workspace_id: wr.workspace_id, revision_id: wr.revision_id})
                WHERE (m.file_path ENDS WITH $clean_path OR m.relative_path = $clean_path OR m.relative_path ENDS WITH $clean_path)
                  AND wr.schema_version = 'codegraph-jdt/v1'
                  AND (m.start_line IS NULL OR m.start_line <= $start_line)
                  AND (m.end_line IS NULL OR m.end_line >= $start_line)
                  AND ($workspace_root IS NULL OR m.file_path STARTS WITH $workspace_root)
                RETURN m.method_key AS method_key, m.signature AS signature, m.file_path AS file_path
                ORDER BY (m.end_line - m.start_line) ASC
                LIMIT 1
                """,
                clean_path=clean_path,
                start_line=start_line,
                workspace_root=workspace_root,
            ).single()
            if record:
                return (
                    record.get("method_key"),
                    record.get("signature"),
                    record.get("file_path"),
                )
    except Exception as exc:
        LOGGER.debug("Could not resolve method for %s:%d in Neo4j: %s", file_path, start_line, exc)
    return None, None, None


def _resolve_active_method_key(
    driver: Driver,
    *,
    method_key: str,
    workspace_root: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Validate a SARIF-supplied method key against the active graph revision."""
    try:
        with driver.session() as session:
            record = session.run(
                """
                MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision)
                MATCH (m:Method {workspace_id: wr.workspace_id, revision_id: wr.revision_id})
                WHERE m.method_key = $method_key
                  AND wr.schema_version = 'codegraph-jdt/v1'
                  AND ($workspace_root IS NULL OR m.file_path STARTS WITH $workspace_root)
                RETURN m.method_key AS method_key, m.signature AS signature, m.file_path AS file_path
                LIMIT 1
                """,
                method_key=method_key,
                workspace_root=workspace_root,
            ).single()
            if record:
                return (
                    record.get("method_key"),
                    record.get("signature"),
                    record.get("file_path"),
                )
    except Exception as exc:
        LOGGER.debug("Could not validate SARIF method key %s in Neo4j: %s", method_key, exc)
    return None, None, None


def import_findings_from_sarif(
    sarif_data: str | dict[str, Any],
    *,
    workspace_root: str | None = None,
    neo4j_driver: Driver | None = None,
) -> list[dict[str, Any]]:
    """Parse an OASIS SARIF v2.1.0 document and ground findings against CodeGraph AST identities."""
    if isinstance(sarif_data, str):
        try:
            sarif_doc = json.loads(sarif_data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid SARIF JSON payload: {exc}") from exc
    elif isinstance(sarif_data, dict):
        sarif_doc = sarif_data
    else:
        raise TypeError("sarif_data must be a JSON string or dict")

    if not isinstance(sarif_doc, dict) or sarif_doc.get("version") != "2.1.0":
        raise ValueError("Unsupported SARIF document: version must be '2.1.0'")

    runs = sarif_doc.get("runs") or []
    if not isinstance(runs, list):
        return []

    pack_registry = get_policy_pack_registry()
    violations: list[dict[str, Any]] = []

    for run in runs:
        if not isinstance(run, dict):
            continue

        # Extract rules metadata map from driver
        driver_rules = (run.get("tool") or {}).get("driver", {}).get("rules") or []
        rules_meta = {r["id"]: r for r in driver_rules if isinstance(r, dict) and r.get("id")}

        results = run.get("results") or []
        for result in results:
            if not isinstance(result, dict):
                continue

            rule_id = str(result.get("ruleId") or "UNKNOWN_RULE")
            level = str(result.get("level") or "warning").lower()
            severity = SARIF_LEVEL_TO_SEVERITY.get(level, "medium")
            message_obj = result.get("message") or {}
            reason = str(message_obj.get("text") or result.get("text") or "External SAST violation detected.")

            # Locations
            locations = result.get("locations") or []
            physical_loc = {}
            if locations and isinstance(locations[0], dict):
                physical_loc = locations[0].get("physicalLocation") or {}

            artifact_loc = physical_loc.get("artifactLocation") or {}
            file_uri = str(artifact_loc.get("uri") or "Unknown.java")
            region = physical_loc.get("region") or {}
            start_line = int(region.get("startLine") or 1)
            end_line = int(region.get("endLine") or start_line)
            code_snippet = (region.get("snippet") or {}).get("text")

            # Check properties for existing method_key
            props = result.get("properties") or {}
            supplied_method_key = props.get("methodKey") or props.get("method_key")
            method_key = None
            target_method = props.get("targetMethod") or props.get("target_method")
            resolved_file_path = props.get("filePath") or props.get("file_path") or file_uri

            # Treat external identities as hints: only active graph identities are operational.
            if neo4j_driver is not None:
                mk, sig, fp = (None, None, None)
                if supplied_method_key:
                    mk, sig, fp = _resolve_active_method_key(
                        neo4j_driver,
                        method_key=str(supplied_method_key),
                        workspace_root=workspace_root,
                    )
                if not mk:
                    mk, sig, fp = _resolve_method_for_location(
                        neo4j_driver,
                        file_path=file_uri,
                        start_line=start_line,
                        workspace_root=workspace_root,
                    )
                if mk:
                    method_key = mk
                    target_method = sig or target_method
                    resolved_file_path = fp or resolved_file_path

            # Retrieve rule definition from registry or SARIF metadata
            registered_rule = pack_registry.get_rule(rule_id)
            sarif_rule_def = rules_meta.get(rule_id) or {}

            control_title = (
                (registered_rule.title if registered_rule else None)
                or sarif_rule_def.get("shortDescription", {}).get("text")
                or rule_id
            )
            control_desc = (
                (registered_rule.description if registered_rule else None)
                or sarif_rule_def.get("fullDescription", {}).get("text")
                or reason
            )

            control_metadata = {
                "id": rule_id,
                "title": control_title,
                "description": control_desc,
                "control": registered_rule.control if registered_rule else rule_id,
            }

            violation_record: dict[str, Any] = {
                "violation_id": rule_id,
                "rule_id": rule_id,
                "method_key": method_key,
                "target_method": target_method or f"{resolved_file_path}:{start_line}",
                "file_path": resolved_file_path,
                "severity": severity,
                "reason": reason,
                "snippet_start_line": start_line,
                "snippet_end_line": end_line,
                "code_snippet": code_snippet,
                "control_metadata": control_metadata,
                "remediation": remediation_capability_dict(rule_id),
                "evidence": {
                    "file_path": resolved_file_path,
                    "method_key": method_key,
                    "external_method_key": supplied_method_key,
                    "method_key_verified": method_key is not None,
                    "target_method": target_method,
                    "start_line": start_line,
                    "end_line": end_line,
                    "source_code": code_snippet,
                    "imported_from_sarif": True,
                    "taint_paths": _taint_paths_from_code_flows(result, rule_id=rule_id),
                },
            }
            violations.append(violation_record)

    return violations
