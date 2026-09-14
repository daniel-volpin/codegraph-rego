"""SARIF 2.1.0 (Static Analysis Results Interchange Format) exporter for CodeGraph findings."""

from __future__ import annotations

from typing import Any

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "CodeGraph"
TOOL_VERSION = "0.6.0"
TOOL_INFO_URI = "https://github.com/daniel-volpin/codegraph-rego"

SEVERITY_LEVEL_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_level(severity: str | None) -> str:
    if not severity:
        return "warning"
    return SEVERITY_LEVEL_MAP.get(severity.lower().strip(), "warning")


def export_findings_to_sarif(
    violations: list[dict[str, Any]],
    *,
    rules_catalog: dict[str, Any] | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Convert CodeGraph policy evaluation violations into an OASIS SARIF v2.1.0 log."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in violations:
        rule_id = str(finding.get("violation_id") or finding.get("rule_id") or "UNKNOWN_RULE")
        severity = str(finding.get("severity") or "high")
        reason = str(finding.get("reason") or "Security violation detected by policy rule.")
        file_path = str(finding.get("file_path") or "Unknown.java")
        start_line = finding.get("snippet_start_line") or finding.get("start_line") or 1
        end_line = finding.get("snippet_end_line") or finding.get("end_line") or start_line
        snippet_text = finding.get("code_snippet") or (finding.get("evidence") or {}).get("source_code")

        relative_uri = file_path
        if workspace_root and file_path.startswith(workspace_root):
            relative_uri = file_path[len(workspace_root) :].lstrip("/")

        if rule_id not in rules_by_id:
            ctrl_meta = finding.get("control_metadata") or {}
            title = ctrl_meta.get("title") or rule_id
            desc = ctrl_meta.get("description") or ctrl_meta.get("summary") or reason
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": title.replace(" ", "_"),
                "shortDescription": {"text": title},
                "fullDescription": {"text": desc},
                "defaultConfiguration": {"level": _rule_level(severity)},
                "properties": {
                    "tags": ["security", "compliance", "iso-27001"],
                    "precision": "high",
                },
            }

        region: dict[str, Any] = {
            "startLine": max(1, int(start_line)),
            "endLine": max(1, int(end_line)),
        }
        if snippet_text:
            region["snippet"] = {"text": snippet_text}

        result_obj: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _rule_level(severity),
            "message": {"text": reason},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": relative_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            ],
            "properties": {
                "methodKey": finding.get("method_key"),
                "targetMethod": finding.get("target_method"),
                "decisionId": finding.get("decision_id"),
                "remediation": finding.get("remediation"),
            },
        }
        sarif_results.append(result_obj)

    sarif_log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return sarif_log
