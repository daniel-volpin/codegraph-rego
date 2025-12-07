"""
policy_integration.py

Extracts code facts from Neo4j and evaluates Rego policies (OPA) against them.
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List

from neo4j import GraphDatabase

from codegraph.config import NEO4J_PASS, NEO4J_URI, NEO4J_USER

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir))
POLICY_DIR = os.path.join(_PROJECT_ROOT, "policy")
POLICY_QUERY = "data.iso27001.violations"
CATALOG_PATH = os.path.join(POLICY_DIR, "catalog.json")
ISO_RULES_PATH = os.path.join(POLICY_DIR, "iso_rules.json")

_CATALOG_CACHE: Dict[str, Dict[str, Any]] | None = None
_ISO_RULES_CACHE: Dict[str, Any] | None = None


def _get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def load_policy_catalog() -> Dict[str, Dict[str, Any]]:
    global _CATALOG_CACHE, raw
    if _CATALOG_CACHE is None:
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
        _CATALOG_CACHE = {entry.get("control") or entry.get("id"): entry for entry in entries}
    return _CATALOG_CACHE or {}


def get_policy_catalog_entries() -> List[Dict[str, Any]]:
    return list(load_policy_catalog().values())


def load_iso_rules() -> Dict[str, Any]:
    global _ISO_RULES_CACHE
    if _ISO_RULES_CACHE is None:
        try:
            with open(ISO_RULES_PATH, "r") as file:
                _ISO_RULES_CACHE = json.load(file) or {}
        except FileNotFoundError:
            _ISO_RULES_CACHE = {}
    return _ISO_RULES_CACHE or {}


def build_policy_input() -> Dict[str, Any]:
    methods: List[Dict[str, Any]] = []
    classes: List[Dict[str, Any]] = []
    fields: List[Dict[str, Any]] = []
    driver = _get_driver()
    with driver.session() as session:
        method_cypher = (
            "MATCH (m:Method) "
            "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
            "OPTIONAL MATCH (m)-[:USES]->(usedClass:Class) "
            "OPTIONAL MATCH (m)-[:USES]->(usedField:Field) "
            "OPTIONAL MATCH (m)-[:ANNOTATED_WITH]->(ann:Annotation) "
            "OPTIONAL MATCH (cls:Class)-[:DECLARES]->(m) "
            "WITH m, cls, "
            "     collect(DISTINCT coalesce(callee.full_signature, callee.signature)) AS called_signatures, "
            "     collect(DISTINCT usedClass.fqn) AS uses_classes, "
            "     collect(DISTINCT CASE WHEN usedField IS NULL "
            "                          THEN NULL "
            "                          ELSE {class_fqn: usedField.class_fqn, name: usedField.name} "
            "                     END) AS uses_fields, "
            "     collect(DISTINCT ann.name) AS annotation_nodes "
            "RETURN coalesce(m.full_signature, m.signature) AS sig, "
            "       m.name AS name, "
            "       m.annotations AS annotations, "
            "       m.modifiers AS modifiers, "
            "       m.file_path AS file_path, "
            "       cls.fqn AS class_fqn, "
            "       m.start_line AS start_line, "
            "       m.end_line AS end_line, "
            "       called_signatures, "
            "       uses_classes, "
            "       uses_fields, "
            "       annotation_nodes"
        )
        for rec in session.run(method_cypher):
            uses_fields = [
                field for field in (rec.get("uses_fields") or []) if field and field.get("name")
            ]
            annotations = rec.get("annotations") or []
            annotation_nodes = rec.get("annotation_nodes") or []
            combined_annotations = sorted({a for a in annotations + annotation_nodes if a})
            methods.append(
                {
                    "signature": rec["sig"],
                    "name": rec.get("name"),
                    "annotations": combined_annotations,
                    "annotation_nodes": annotation_nodes,
                    "modifiers": rec.get("modifiers") or [],
                    "file_path": rec.get("file_path"),
                    "class_fqn": rec.get("class_fqn"),
                    "called_signatures": rec.get("called_signatures") or [],
                    "uses_classes": rec.get("uses_classes") or [],
                    "uses_fields": uses_fields,
                    "start_line": rec.get("start_line"),
                    "end_line": rec.get("end_line"),
                }
            )

        class_cypher = (
            "MATCH (c:Class) "
            "OPTIONAL MATCH (c)-[:EXTENDS]->(parent:Class) "
            "OPTIONAL MATCH (c)-[:IMPLEMENTS]->(iface:Class) "
            "OPTIONAL MATCH (c)-[:DEPENDS_ON]->(dep:Class) "
            "OPTIONAL MATCH (c)-[:DECLARES]->(m:Method) "
            "OPTIONAL MATCH (c)-[:DECLARES_FIELD]->(field:Field) "
            "RETURN c.fqn AS fqn, "
            "       collect(DISTINCT parent.fqn) AS extends, "
            "       collect(DISTINCT iface.fqn) AS implements, "
            "       collect(DISTINCT dep.fqn) AS depends_on, "
            "       collect(DISTINCT coalesce(m.full_signature, m.signature)) AS declares, "
            "       collect(DISTINCT CASE WHEN field IS NULL "
            "                            THEN NULL "
            "                            ELSE {"
            "                                 name: field.name, "
            "                                 type: field.type, "
            "                                 annotations: field.annotations, "
            "                                 modifiers: field.modifiers, "
            "                                 file_path: field.file_path, "
            "                                 start_line: field.start_line, "
            "                                 end_line: field.end_line"
            "                            } END) AS declared_fields"
        )
        for rec in session.run(class_cypher):
            declared_fields = [field for field in (rec.get("declared_fields") or []) if field]
            classes.append(
                {
                    "fqn": rec.get("fqn"),
                    "extends": rec.get("extends") or [],
                    "implements": rec.get("implements") or [],
                    "depends_on": rec.get("depends_on") or [],
                    "declares": rec.get("declares") or [],
                    "fields": declared_fields,
                }
            )

        field_cypher = (
            "MATCH (cls:Class)-[:DECLARES_FIELD]->(f:Field) "
            "RETURN cls.fqn AS class_fqn, "
            "       f.name AS name, "
            "       f.type AS type, "
            "       f.annotations AS annotations, "
            "       f.modifiers AS modifiers, "
            "       f.file_path AS file_path, "
            "       f.start_line AS start_line, "
            "       f.end_line AS end_line"
        )
        for rec in session.run(field_cypher):
            fields.append(
                {
                    "class_fqn": rec.get("class_fqn"),
                    "name": rec.get("name"),
                    "type": rec.get("type"),
                    "annotations": rec.get("annotations") or [],
                    "modifiers": rec.get("modifiers") or [],
                    "file_path": rec.get("file_path"),
                    "start_line": rec.get("start_line"),
                    "end_line": rec.get("end_line"),
                }
            )
    driver.close()
    return {
        "methods": methods,
        "classes": classes,
        "fields": fields,
        "rules_catalog": load_iso_rules(),
    }


def evaluate_policies() -> Dict[str, Any]:
    if not shutil.which("opa"):
        return {
            "error": "OPA CLI not found on PATH",
            "hint": "Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa",
        }

    policy_input = build_policy_input()

    with tempfile.TemporaryDirectory() as tmp:
        input_path = os.path.join(tmp, "input.json")
        with open(input_path, "w") as file:
            json.dump(policy_input, file)

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
            return {
                "error": "OPA evaluation failed",
                "stderr": proc.stderr,
                "stdout": proc.stdout,
                "cmd": " ".join(cmd),
            }

        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"error": "Failed to parse OPA output", "stdout": proc.stdout}

        result = out.get("result", [])
        violations: List[Dict[str, Any]] = []
        if result:
            expressions = result[0].get("expressions", [])
            if expressions:
                violations = expressions[0].get("value", []) or []
        catalog = load_policy_catalog()
        rules_catalog = load_iso_rules()
        enriched = []
        for violation in violations:
            item = dict(violation)
            control_id = violation.get("id")
            meta = catalog.get(control_id) if control_id else None
            if not meta and control_id:
                meta = catalog.get(f"ISO-27001-{control_id}")
            if meta:
                item["control_metadata"] = meta
            enriched.append(item)
        return {
            "violations": enriched,
            "opa_output": out,
            "catalog": get_policy_catalog_entries(),
            "rules_catalog": rules_catalog,
        }


if __name__ == "__main__":
    print(json.dumps(evaluate_policies(), indent=2))
