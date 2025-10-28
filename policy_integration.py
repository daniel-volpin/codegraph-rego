"""
policy_integration.py

Extracts code facts from Neo4j and evaluates Rego policies (OPA) against them.
Provides a helper function to call from FastAPI and a small CLI.
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict

from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASS

POLICY_DIR = os.path.join(os.path.dirname(__file__), "policy")
POLICY_QUERY = "data.iso27001.violations"


def _get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def build_policy_input() -> Dict[str, Any]:
    """
    Build OPA input from the current Neo4j code graph.
    Collects methods with annotations, modifiers, and file paths.
    """
    items = []
    driver = _get_driver()
    with driver.session() as session:
        cypher = (
            "MATCH (m:Method) "
            "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
            "WITH m, collect(DISTINCT coalesce(callee.full_signature, callee.signature)) AS called_signatures "
            "RETURN coalesce(m.full_signature, m.signature) AS sig, "
            "       m.name AS name, "
            "       m.annotations AS annotations, "
            "       m.modifiers AS modifiers, "
            "       m.file_path AS file_path, "
            "       called_signatures"
        )
        for rec in session.run(cypher):
            items.append(
                {
                    "signature": rec["sig"],
                    "name": rec.get("name"),
                    "annotations": rec.get("annotations") or [],
                    "modifiers": rec.get("modifiers") or [],
                    "file_path": rec.get("file_path"),
                    "called_signatures": rec.get("called_signatures") or [],
                }
            )
    driver.close()
    return {"methods": items}


def evaluate_policies() -> Dict[str, Any]:
    """
    Evaluate Rego policies using OPA CLI. Returns violations and raw OPA output.

    Requires `opa` to be available on PATH. Policies are loaded from the `policy/` directory.
    """
    if not shutil.which("opa"):
        return {
            "error": "OPA CLI not found on PATH",
            "hint": "Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa",
        }

    policy_input = build_policy_input()

    with tempfile.TemporaryDirectory() as tmp:
        input_path = os.path.join(tmp, "input.json")
        with open(input_path, "w") as f:
            json.dump(policy_input, f)

        # Load all policies under policy/ dir; iso_rules.json is optional data and will be ignored if absent
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

        # Typical shape: {"result":[{"expressions":[{"value":[...]}]}]}
        result = out.get("result", [])
        violations = []
        if result:
            exprs = result[0].get("expressions", [])
            if exprs:
                violations = exprs[0].get("value", []) or []
        return {"violations": violations, "opa_output": out}


if __name__ == "__main__":
    res = evaluate_policies()
    print(json.dumps(res, indent=2))
