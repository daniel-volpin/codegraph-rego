from __future__ import annotations

import difflib
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from codegraph.db import get_neo4j_driver
from codegraph.ingestion.service import process_single_file
from codegraph.llm.client import generate_chat_completion
from codegraph.policy.integration import PolicyEvaluator, evaluate_policies

LOGGER = logging.getLogger(__name__)


class RemediationService:
    """Agentic fix-verify loop orchestrator."""

    def __init__(
        self,
        *,
        llm_client=generate_chat_completion,
        policy_evaluator: Optional[PolicyEvaluator] = None,
    ) -> None:
        self._llm_client = llm_client
        self._policy = policy_evaluator or PolicyEvaluator()
        self._context: Dict[str, Any] = {}

    def generate_fix(self, violation: Dict[str, Any]) -> str:
        evidence = violation.get("evidence") or violation
        source_code = (evidence.get("source_code") or "").strip()
        graph_context = evidence.get("graph_context") or {}
        violation_id = violation.get("violation_id") or violation.get("id") or "reported issue"
        system_prompt = (
            f"You are a security expert. Fix the {violation_id} in the provided Java code. "
            "Return ONLY the corrected method code. Do not refactor unrelated parts."
        )
        if str(violation_id).upper() == "ISO-A.10":
            system_prompt += " Replace MD5 with SHA-256 or BCrypt where applicable."
        user_payload = [
            "Java source snippet:",
            "```java",
            source_code,
            "```",
        ]
        if graph_context:
            user_payload.extend(
                [
                    "Graph annotations:",
                    "```json",
                    json.dumps(graph_context, indent=2),
                    "```",
                ]
            )
        response = self._llm_client(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "\n".join(user_payload)},
            ]
        )
        return response.strip()

    def apply_provisional_patch(self, file_path: str, new_code: str) -> str:
        new_code = new_code.strip()
        if not new_code:
            raise ValueError("LLM returned an empty fix.")
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Target file not found: {file_path}")
        temp_dir = Path(tempfile.mkdtemp(prefix="remediation_"))
        temp_path = temp_dir / path.name
        shutil.copy2(path, temp_path)
        metadata = self._context.get("method_metadata") or {}
        updated_contents = self._rewrite_file(temp_path, metadata, new_code)
        temp_path.write_text(updated_contents, encoding="utf-8")
        return temp_path.as_posix()

    def verify_fix(self, temp_file_path: str, method_signature: str) -> Dict[str, Any]:
        build_ok, build_output = self._run_javac(temp_file_path)
        if not build_ok:
            return {
                "status": "BUILD_FAILED",
                "message": "Result: Build Failed",
                "details": build_output,
            }
        try:
            process_single_file(temp_file_path)
        except Exception as exc:
            LOGGER.exception("Single-file ingestion failed for %s", temp_file_path)
            return {
                "status": "INGEST_FAILED",
                "message": "Result: Fix Failed (Graph ingest error)",
                "details": str(exc),
            }
        policy_result = self._policy.evaluate(method_signature)
        violations = policy_result.get("violations") or []
        if violations:
            return {
                "status": "POLICY_FAILED",
                "message": "Result: Fix Failed (Still Vulnerable)",
                "details": policy_result,
            }
        return {
            "status": "VERIFIED",
            "message": "Result: Verified Fix",
            "details": policy_result,
        }

    def orchestrate_fix(self, violation_id: str) -> Dict[str, Any]:
        violation = self._resolve_violation(violation_id)
        if violation is None:
            return {
                "status": "NOT_FOUND",
                "error": f"No violation found for {violation_id}",
            }
        evidence = violation.get("evidence") or {}
        file_path = violation.get("file_path")
        method_signature = violation.get("target_method")
        if not file_path or not method_signature:
            return {
                "status": "INVALID",
                "error": "Violation missing file_path or target_method.",
            }
        metadata = self._fetch_method_metadata(method_signature, file_path)
        self._context = {
            "source_code": evidence.get("source_code", ""),
            "method_metadata": metadata,
            "method_signature": method_signature,
        }
        fix = self.generate_fix(violation)
        temp_path = self.apply_provisional_patch(metadata.get("file_path") or file_path, fix)
        verification = self.verify_fix(temp_path, method_signature)
        diff_text = self._build_diff(file_path, temp_path)
        status = "VERIFIED" if verification.get("status") == "VERIFIED" else "FAILED"
        self._context = {}
        return {
            "status": status,
            "original_file": file_path,
            "patched_file": temp_path,
            "diff": diff_text,
            "verification": verification,
        }

    def _resolve_violation(self, violation_id: str) -> Optional[Dict[str, Any]]:
        result = evaluate_policies()
        violations = result.get("violations") or []
        for violation in violations:
            current_id = violation.get("violation_id") or violation.get("id")
            if current_id and str(current_id) == str(violation_id):
                return violation
        return None

    def _fetch_method_metadata(
        self, method_signature: str, fallback_file: str
    ) -> Dict[str, Any]:
        driver = get_neo4j_driver()
        try:
            with driver.session() as session:
                record = session.run(
                    """
                    MATCH (m:Method)
                    WHERE coalesce(m.full_signature, m.signature) = $sig
                       OR m.signature = $sig
                       OR m.full_signature = $sig
                    RETURN coalesce(m.full_signature, m.signature) AS signature,
                           m.file_path AS file_path,
                           m.start_line AS start_line,
                           m.end_line AS end_line
                    LIMIT 1
                    """,
                    sig=method_signature,
                ).single()
        finally:
            driver.close()
        if not record:
            return {"file_path": fallback_file}
        return {
            "file_path": record.get("file_path") or fallback_file,
            "start_line": record.get("start_line"),
            "end_line": record.get("end_line"),
        }

    def _rewrite_file(self, temp_path: Path, metadata: Dict[str, Any], new_code: str) -> str:
        original = temp_path.read_text(encoding="utf-8")
        start_line = metadata.get("start_line")
        end_line = metadata.get("end_line")
        if start_line and end_line:
            lines = original.splitlines(keepends=True)
            start_idx = max(start_line - 1, 0)
            end_idx = max(end_line - 1, start_idx)
            normalized = self._normalize_new_code(new_code)
            updated_lines = lines[:start_idx] + normalized + lines[end_idx + 1 :]
            return "".join(updated_lines)
        snippet = (self._context.get("source_code") or "").strip()
        normalized_text = "".join(self._normalize_new_code(new_code))
        if snippet and snippet in original:
            return original.replace(snippet, normalized_text, 1)
        LOGGER.warning(
            "Could not locate snippet for %s; appending fix at end.", metadata.get("file_path")
        )
        return f"{original.rstrip()}\n\n{normalized_text}"

    @staticmethod
    def _normalize_new_code(new_code: str) -> list[str]:
        snippet = new_code.strip("\n")
        if not snippet:
            return ["\n"]
        lines = snippet.splitlines()
        return [f"{line}\n" for line in lines]

    def _run_javac(self, file_path: str) -> tuple[bool, str]:
        try:
            proc = subprocess.run(
                ["javac", file_path], capture_output=True, check=False, text=True
            )
        except FileNotFoundError:
            return False, "javac not found on PATH"
        output = f"{proc.stdout}\n{proc.stderr}".strip()
        return proc.returncode == 0, output

    def _build_diff(self, original_path: str, temp_path: str) -> str:
        try:
            original = Path(original_path).read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            original = []
        patched = Path(temp_path).read_text(encoding="utf-8").splitlines()
        diff = difflib.unified_diff(
            original,
            patched,
            fromfile=original_path,
            tofile=temp_path,
            lineterm="",
        )
        return "\n".join(diff)
