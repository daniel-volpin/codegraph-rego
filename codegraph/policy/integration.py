"""
policy_integration.py

Extracts code facts from Neo4j and evaluates Rego policies (OPA) against them.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from codegraph.common.snippet_utils import extract_code_snippet, extract_snippet_by_lines
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.db import get_neo4j_driver
from codegraph.remediation.capabilities import remediation_capability_dict
from codegraph.search.service import HybridSearchService

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir))
POLICY_DIR = os.path.join(_PROJECT_ROOT, "policy")
POLICY_QUERY = "data.iso27001.violations"
CATALOG_PATH = os.path.join(POLICY_DIR, "catalog.json")
ISO_RULES_PATH = os.path.join(POLICY_DIR, "iso_rules.json")
LOGGER = logging.getLogger(__name__)

_CATALOG_CACHE: Dict[str, Dict[str, Any]] | None = None
_CATALOG_ENTRIES_CACHE: List[Dict[str, Any]] | None = None
_ISO_RULES_CACHE: Dict[str, Any] | None = None
_HYBRID_SEARCH: Optional[HybridSearchService] = None


def _load_hybrid_search() -> Optional[HybridSearchService]:
    global _HYBRID_SEARCH
    if _HYBRID_SEARCH is not None:
        return _HYBRID_SEARCH
    try:
        _HYBRID_SEARCH = HybridSearchService()
    except Exception as exc:  # pragma: no cover - optional dependency
        LOGGER.warning("Hybrid search unavailable for evidence bundles: %s", exc)
        _HYBRID_SEARCH = None
    return _HYBRID_SEARCH


def _is_test_source_path(file_path: Any) -> bool:
    if not isinstance(file_path, str):
        return False
    normalized = file_path.replace("\\", "/")
    return "/src/test/" in normalized


def load_policy_catalog() -> Dict[str, Dict[str, Any]]:
    global _CATALOG_CACHE, _CATALOG_ENTRIES_CACHE, raw
    if _CATALOG_CACHE is None or _CATALOG_ENTRIES_CACHE is None:
        try:
            with open(CATALOG_PATH, "r") as file:
                raw = json.load(file)
        except FileNotFoundError:
            raw = []
        except json.JSONDecodeError as exc:
            raise ValueError(f"Failed to parse policy catalog at {CATALOG_PATH}: {exc}") from exc
        if isinstance(raw, dict):
            entries = raw.get("controls", [])
        elif isinstance(raw, list):
            entries = raw
        else:
            entries = []
        catalog_lookup: Dict[str, Dict[str, Any]] = {}
        catalog_entries: List[Dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_id = entry.get("id")
            if not isinstance(entry_id, str) or not entry_id.strip():
                continue
            catalog_entries.append(entry)
            catalog_lookup[entry_id] = entry
            aliases = entry.get("alias_ids") or []
            if isinstance(aliases, list):
                for alias in aliases:
                    if isinstance(alias, str) and alias.strip():
                        catalog_lookup[alias] = entry
        _CATALOG_CACHE = catalog_lookup
        _CATALOG_ENTRIES_CACHE = catalog_entries
    return _CATALOG_CACHE or {}


def get_policy_catalog_entries() -> List[Dict[str, Any]]:
    load_policy_catalog()
    return list(_CATALOG_ENTRIES_CACHE or [])


def _violation_id_variants(violation_id: str) -> List[str]:
    text = str(violation_id).strip()
    if not text:
        return []
    variants = [text]
    if text.startswith("ISO-27001-"):
        base = text[len("ISO-27001-") :]
    elif text.startswith("ISO-"):
        base = text[len("ISO-") :]
    else:
        base = text
    for candidate in (base, f"ISO-{base}", f"ISO-27001-{base}"):
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants


def _resolve_catalog_entry(violation_id: Any, catalog: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not violation_id:
        return None
    for candidate in _violation_id_variants(str(violation_id)):
        entry = catalog.get(candidate)
        if entry is not None:
            return entry
    return None


def load_iso_rules() -> Dict[str, Any]:
    global _ISO_RULES_CACHE
    if _ISO_RULES_CACHE is None:
        try:
            with open(ISO_RULES_PATH, "r") as file:
                _ISO_RULES_CACHE = json.load(file) or {}
        except FileNotFoundError:
            _ISO_RULES_CACHE = {}
    return _ISO_RULES_CACHE or {}


def build_policy_input(*, max_bundles: int | None = None) -> Dict[str, Any]:
    driver = get_neo4j_driver()
    try:
        methods = _fetch_methods_with_context(driver, max_bundles=max_bundles)
    finally:
        driver.close()
    hybrid_search = _load_hybrid_search()

    # Build evidence bundles concurrently (file I/O + FAISS).
    # This is CPU/IO bound, so we use available CPU cores to maximize throughput.
    workers = min(32, (os.cpu_count() or 4) + 4)
    bundles: List[Dict[str, Any]] = [None] * len(methods)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {
            pool.submit(build_evidence_bundle, m, hybrid_search): i
            for i, m in enumerate(methods)
        }
        for future in as_completed(future_to_idx):
            bundles[future_to_idx[future]] = future.result()

    return {
        "bundles": bundles,
        "rules_catalog": load_iso_rules(),
        "catalog": get_policy_catalog_entries(),
    }


def _fetch_methods_with_context(driver, *, max_bundles: int | None = None) -> List[Dict[str, Any]]:
    cypher = (
        "MATCH (m:Method) "
        "OPTIONAL MATCH (cls:Class)-[:DECLARES]->(m) "
        "OPTIONAL MATCH (m)-[:ANNOTATED_WITH]->(ann:Annotation) "
        "OPTIONAL MATCH (m)-[:USES]->(usedField:Field) "
        "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
        "OPTIONAL MATCH (caller:Method)-[:CALLS]->(m) "
        "RETURN coalesce(m.full_signature, m.signature) AS signature, "
        "       m.name AS name, "
        "       m.file_path AS file_path, "
        "       m.start_line AS start_line, "
        "       m.end_line AS end_line, "
        "       m.modifiers AS modifiers, "
        "       m.annotations AS property_annotations, "
        "       cls.fqn AS class_fqn, "
        "       collect(DISTINCT ann.name) AS annotation_nodes, "
        "       collect(DISTINCT CASE WHEN usedField IS NULL "
        "                             THEN NULL "
        "                             ELSE {"
        "                                 name: usedField.name, "
        "                                 type: usedField.type, "
        "                                 class_fqn: usedField.class_fqn"
        "                             } END) AS uses_fields, "
        "       collect(DISTINCT coalesce(callee.full_signature, callee.signature)) AS calls, "
        "       collect(DISTINCT coalesce(caller.full_signature, caller.signature)) AS callers "
    )
    params: Dict[str, Any] = {}
    if isinstance(max_bundles, int) and max_bundles > 0:
        cypher += " LIMIT $max_bundles"
        params["max_bundles"] = max_bundles
    snapshots: List[Dict[str, Any]] = []
    with driver.session() as session:
        for rec in session.run(cypher, params):
            signature = rec.get("signature")
            if not signature:
                continue
            file_path = rec.get("file_path")
            if _is_test_source_path(file_path):
                continue
            uses_fields = [field for field in (rec.get("uses_fields") or []) if field and field.get("name")]
            annotations = rec.get("property_annotations") or []
            annotation_nodes = rec.get("annotation_nodes") or []
            combined_annotations = sorted({a for a in annotations + annotation_nodes if a})
            snapshots.append(
                {
                    "signature": signature,
                    "name": rec.get("name"),
                    "class_fqn": rec.get("class_fqn"),
                    "file_path": file_path,
                    "start_line": rec.get("start_line"),
                    "end_line": rec.get("end_line"),
                    "modifiers": rec.get("modifiers") or [],
                    "annotations": combined_annotations,
                    "uses_fields": uses_fields,
                    "calls": rec.get("calls") or [],
                    "callers": rec.get("callers") or [],
                }
            )
    return snapshots


def _fetch_method_snapshot(driver, method_signature: str) -> Dict[str, Any] | None:
    cypher = (
        "MATCH (m:Method) "
        "WHERE coalesce(m.full_signature, m.signature) = $method_signature "
        "   OR m.signature = $method_signature "
        "   OR m.full_signature = $method_signature "
        "OPTIONAL MATCH (cls:Class)-[:DECLARES]->(m) "
        "OPTIONAL MATCH (m)-[:ANNOTATED_WITH]->(ann:Annotation) "
        "OPTIONAL MATCH (m)-[:USES]->(usedField:Field) "
        "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
        "OPTIONAL MATCH (caller:Method)-[:CALLS]->(m) "
        "RETURN coalesce(m.full_signature, m.signature) AS signature, "
        "       m.name AS name, "
        "       m.file_path AS file_path, "
        "       m.start_line AS start_line, "
        "       m.end_line AS end_line, "
        "       m.modifiers AS modifiers, "
        "       m.annotations AS property_annotations, "
        "       cls.fqn AS class_fqn, "
        "       collect(DISTINCT ann.name) AS annotation_nodes, "
        "       collect(DISTINCT CASE WHEN usedField IS NULL "
        "                             THEN NULL "
        "                             ELSE {"
        "                                 name: usedField.name, "
        "                                 type: usedField.type, "
        "                                 class_fqn: usedField.class_fqn"
        "                             } END) AS uses_fields, "
        "       collect(DISTINCT coalesce(callee.full_signature, callee.signature)) AS calls, "
        "       collect(DISTINCT coalesce(caller.full_signature, caller.signature)) AS callers "
        "LIMIT 1"
    )
    with driver.session() as session:
        record = session.run(cypher, method_signature=method_signature).single()
        if not record:
            return None
        uses_fields = [field for field in (record.get("uses_fields") or []) if field and field.get("name")]
        annotations = record.get("property_annotations") or []
        annotation_nodes = record.get("annotation_nodes") or []
        combined_annotations = sorted({a for a in annotations + annotation_nodes if a})
        return {
            "signature": record.get("signature"),
            "name": record.get("name"),
            "class_fqn": record.get("class_fqn"),
            "file_path": record.get("file_path"),
            "start_line": record.get("start_line"),
            "end_line": record.get("end_line"),
            "modifiers": record.get("modifiers") or [],
            "annotations": combined_annotations,
            "uses_fields": uses_fields,
            "calls": record.get("calls") or [],
            "callers": record.get("callers") or [],
        }


def _resolve_source_path(file_path: Optional[str]) -> Optional[Path]:
    if not file_path:
        return None
    path = Path(file_path)
    if path.is_file():
        return path
    candidate = Path(_PROJECT_ROOT) / path
    if candidate.is_file():
        return candidate
    return None


def build_evidence_bundle(
    method_snapshot: Dict[str, Any], search_service: Optional[HybridSearchService] = None
) -> Dict[str, Any]:
    file_path = method_snapshot.get("file_path")
    resolved_path = _resolve_source_path(file_path)
    source_code = ""
    if resolved_path is not None:
        source_code = extract_snippet_by_lines(
            resolved_path.as_posix(),
            method_snapshot.get("start_line"),
            method_snapshot.get("end_line"),
            padding=2,
        )
        if not source_code and method_snapshot.get("name"):
            source_code = extract_code_snippet(resolved_path.as_posix(), method_snapshot.get("name", ""))
    graph_context = {
        "annotations": method_snapshot.get("annotations") or [],
        "uses_fields": method_snapshot.get("uses_fields") or [],
        "calls": method_snapshot.get("calls") or [],
        "callers": method_snapshot.get("callers") or [],
    }
    analysis_flags = analyze_policy_indicators(source_code)
    vector_context: List[str] = []
    if search_service is not None:
        try:
            vector_context = search_service.similar_to_signature(method_snapshot["signature"], top_k=3)
        except Exception as exc:  # pragma: no cover - optional dependency
            LOGGER.debug("Vector lookup failed for %s: %s", method_snapshot["signature"], exc)
    return {
        "target_method": method_snapshot["signature"],
        "method_name": method_snapshot.get("name"),
        "class_fqn": method_snapshot.get("class_fqn"),
        "file_path": resolved_path.as_posix() if resolved_path else file_path,
        "start_line": method_snapshot.get("start_line"),
        "end_line": method_snapshot.get("end_line"),
        "modifiers": method_snapshot.get("modifiers") or [],
        "source_code": source_code,
        "graph_context": graph_context,
        "vector_context": vector_context,
        "analysis_flags": analysis_flags,
    }


def _normalize_violation_payload(payload: Any) -> Optional[Dict[str, Any]]:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            LOGGER.warning("Skipping non-JSON violation payload: %s", payload)
            return None
        if isinstance(parsed, dict):
            return parsed
        LOGGER.warning("Skipping violation payload (unexpected type): %s", payload)
        return None
    LOGGER.warning("Skipping unexpected OPA violation payload: %r", payload)
    return None


def _build_violation_response(
    normalized: Dict[str, Any],
    bundle: Dict[str, Any],
    control_meta: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    violation_id = normalized.get("violation_id") or normalized.get("id")
    source_code = bundle.get("source_code", "") or ""
    start_line = bundle.get("start_line")
    end_line = bundle.get("end_line")
    evidence = {
        "source_code": source_code,
        "graph_context": bundle.get("graph_context", {}),
        "vector_context": bundle.get("vector_context", []),
        "file_path": bundle.get("file_path"),
        "target_method": bundle.get("target_method"),
        "start_line": start_line,
        "end_line": end_line,
        "analysis_flags": bundle.get("analysis_flags", {}),
    }
    return {
        "violation_id": violation_id,
        "target_method": bundle.get("target_method"),
        "file_path": bundle.get("file_path"),
        "reason": normalized.get("reason"),
        "severity": normalized.get("severity") or "high",
        "control_metadata": control_meta,
        "remediation": remediation_capability_dict(str(violation_id) if violation_id else None),
        "code_snippet": source_code,
        "snippet_available": bool(source_code),
        "snippet_start_line": start_line,
        "snippet_end_line": end_line,
        "evidence": evidence,
    }


def evaluate_policies(
    *,
    max_bundles: int | None = None,
    max_total_violations: int | None = None,
    max_per_violation_id: int | None = None,
    rule_ids: List[str] | None = None,
) -> Dict[str, Any]:
    if not shutil.which("opa"):
        return {
            "error": "OPA CLI not found on PATH",
            "hint": "Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa",
        }

    policy_input = build_policy_input(max_bundles=max_bundles)
    bundles = policy_input.get("bundles") or []
    catalog = load_policy_catalog()
    rules_catalog = load_iso_rules()
    violations: List[Dict[str, Any]] = []
    violation_counts_by_id: Dict[str, int] = {}
    truncated = False
    allowed_rule_ids = {str(rule_id).strip() for rule_id in (rule_ids or []) if str(rule_id).strip()}
    include_limit_metadata = any(
        value is not None for value in (max_bundles, max_total_violations, max_per_violation_id, rule_ids)
    )

    # Evaluate OPA for all bundles concurrently.
    # OPA subprocesses are CPU-bound, so we maximize thread usage independent of LLM limits.
    workers = min(32, (os.cpu_count() or 4) + 4)
    opa_results: List[Any] = [None] * len(bundles)  # preserve order
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {pool.submit(_evaluate_bundle, b): i for i, b in enumerate(bundles)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                opa_results[idx] = future.result()
            except RuntimeError as exc:
                return {"error": str(exc), "bundle": bundles[idx].get("target_method")}

    opa_runs = len(bundles)
    for bundle, opa_result in zip(bundles, opa_results):
        for violation in (opa_result or []):
            normalized = _normalize_violation_payload(violation)
            if normalized is None:
                continue
            violation_id = normalized.get("violation_id") or normalized.get("id")
            if allowed_rule_ids and str(violation_id or "").strip() not in allowed_rule_ids:
                continue
            if violation_id is not None:
                current_count = violation_counts_by_id.get(str(violation_id), 0)
                if isinstance(max_per_violation_id, int) and max_per_violation_id > 0:
                    if current_count >= max_per_violation_id:
                        continue
            control_meta = _resolve_catalog_entry(violation_id, catalog)
            violations.append(_build_violation_response(normalized, bundle, control_meta))
            if violation_id is not None:
                violation_counts_by_id[str(violation_id)] = current_count + 1
            if isinstance(max_total_violations, int) and max_total_violations > 0:
                if len(violations) >= max_total_violations:
                    truncated = True
                    break
        if truncated:
            break
    response: Dict[str, Any] = {
        "violations": violations,
        "rules_catalog": rules_catalog,
        "catalog": get_policy_catalog_entries(),
        "opa_runs": opa_runs,
        "bundle_count": len(bundles),
    }
    if include_limit_metadata:
        response.update(
            {
                "truncated": truncated,
                "limits": {
                    "max_bundles": max_bundles,
                    "max_total_violations": max_total_violations,
                    "max_per_violation_id": max_per_violation_id,
                    "rule_ids": sorted(allowed_rule_ids) if allowed_rule_ids else None,
                },
                "violation_counts_by_id": violation_counts_by_id,
            }
        )
    return response


def evaluate_bundle(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Public wrapper to evaluate a single method bundle with OPA. This reuses the
    same query and policy directory as the main evaluation path, but accepts an
    in-memory bundle (e.g., for virtual remediation previews).
    """
    return _evaluate_bundle(bundle)


def normalize_violation_payload(payload: Any) -> Optional[Dict[str, Any]]:
    """Public helper to coerce OPA outputs into a dict or return None."""
    return _normalize_violation_payload(payload)


def _evaluate_bundle(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = os.path.join(tmp, "input.json")
        with open(input_path, "w") as file:
            json.dump(bundle, file)
        cmd = [
            "opa",
            "eval",
            "-f",
            "json",
            "-d",
            POLICY_DIR,
            "-i",
            input_path,
            POLICY_QUERY,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"OPA evaluation failed for {bundle.get('target_method')}: {proc.stderr}")
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Failed to parse OPA output") from exc
        result = out.get("result") or []
        if not result:
            return []
        expressions = result[0].get("expressions") or []
        if not expressions:
            return []
        return expressions[0].get("value") or []


class PolicyEvaluator:
    """Evaluate policies against a single method signature."""

    def __init__(self) -> None:
        self._catalog = load_policy_catalog()
        self._rules = load_iso_rules()

    def evaluate(self, method_signature: str) -> Dict[str, Any]:
        driver = get_neo4j_driver()
        try:
            snapshot = _fetch_method_snapshot(driver, method_signature)
        finally:
            driver.close()
        if not snapshot:
            return {
                "target_method": method_signature,
                "violations": [],
                "error": "method_not_found",
            }
        bundle = build_evidence_bundle(snapshot, _load_hybrid_search())
        try:
            opa_output = _evaluate_bundle(bundle)
        except RuntimeError as exc:
            return {
                "target_method": method_signature,
                "violations": [],
                "error": str(exc),
            }
        catalog = self._catalog
        violations: List[Dict[str, Any]] = []
        for violation in opa_output:
            normalized = _normalize_violation_payload(violation)
            if normalized is None:
                continue
            violation_id = normalized.get("violation_id") or normalized.get("id")
            control_meta = _resolve_catalog_entry(violation_id, catalog)
            violations.append(_build_violation_response(normalized, bundle, control_meta))
        return {
            "target_method": method_signature,
            "violations": violations,
            "rules_catalog": self._rules,
            "catalog": get_policy_catalog_entries(),
        }


if __name__ == "__main__":
    print(json.dumps(evaluate_policies(), indent=2))
