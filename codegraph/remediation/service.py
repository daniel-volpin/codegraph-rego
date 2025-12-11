from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import javalang
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from javalang.tree import MemberReference, MethodInvocation, MethodDeclaration

from codegraph.db import get_neo4j_driver
from codegraph.ingestion.service import process_single_file
from codegraph.llm.client import generate_chat_completion
from codegraph.policy.integration import (
    PolicyEvaluator,
    evaluate_policies,
    evaluate_bundle,
    normalize_violation_payload,
    load_policy_catalog,
)

LOGGER = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RemediationState(str, Enum):
    INIT = "INIT"
    GATHER_CONTEXT = "GATHER_CONTEXT"
    PROPOSE_PATCH = "PROPOSE_PATCH"
    APPLY_PATCH = "APPLY_PATCH"
    COMPILE = "COMPILE"
    POLICY_CHECK = "POLICY_CHECK"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass
class RemediationRun:
    id: str
    violation_id: str
    file_path: Optional[str]
    rule_id: Optional[str]
    target_method: Optional[str]
    state: RemediationState = RemediationState.INIT
    attempts: int = 0
    max_attempts: int = 3
    patch: Optional[str] = None
    raw_llm_output: Optional[str] = None
    explanation: Optional[str] = None
    compile_error: Optional[str] = None
    policy_error: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None
    workspace: Optional[str] = None
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    errors: List[str] = field(default_factory=list)
    skip_compile: bool = True

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload.pop("workspace", None)
        return payload


class RemediationService:
    """Agentic remediation loop with retries and policy verification."""

    def __init__(
        self,
        *,
        llm_client=generate_chat_completion,
        policy_evaluator: Optional[PolicyEvaluator] = None,
    ) -> None:
        self._llm_client = llm_client
        self._policy = policy_evaluator or PolicyEvaluator()
        self._runs: Dict[str, RemediationRun] = {}
        self._lock = Lock()

    # --- Public API -----------------------------------------------------------------
    def start_run(
        self,
        violation_id: str,
        max_attempts: int = 3,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
        skip_compile: bool = True,
    ) -> RemediationRun:
        return self.start_run_with_context(
            violation_id,
            max_attempts=max_attempts,
            target_method=target_method,
            file_path=file_path,
            skip_compile=skip_compile,
        )

    def start_run_with_context(
        self,
        violation_id: str,
        *,
        max_attempts: int = 3,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
        skip_compile: bool = True,
    ) -> RemediationRun:
        context = self.get_violation_context(violation_id, target_method, file_path)
        if context is None:
            raise ValueError(f"Violation {violation_id} not found")
        run = RemediationRun(
            id=str(uuid4()),
            violation_id=violation_id,
            file_path=context.get("file_path"),
            rule_id=context.get("rule_id"),
            target_method=context.get("target_method"),
            max_attempts=max(1, max_attempts),
            skip_compile=skip_compile,
        )
        self._save_run(run)
        return self._execute_run(run, context)

    def orchestrate_fix(self, violation_id: str) -> Dict[str, Any]:
        run = self.start_run(violation_id, max_attempts=1)
        return run.to_dict()

    def get_run(self, run_id: str) -> Optional[RemediationRun]:
        with self._lock:
            return self._runs.get(run_id)

    # --- Virtual remediation preview (no workspace mutations) -----------------------
    def preview_virtual_fix(
        self,
        violation_id: str,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        context = self.get_violation_context(violation_id, target_method, file_path)
        if context is None:
            return {
                "status": "NOT_FOUND",
                "error": f"Violation {violation_id} not found",
                "violation_id": violation_id,
            }

        llm_output = self.propose_full_method(context)
        updated_source = llm_output.get("updated_source_code")
        explanation = llm_output.get("explanation")
        if not updated_source:
            return {
                "status": "ERROR",
                "error": "LLM did not return updated_source_code",
                "violation_id": violation_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
            }

        virtual_graph = self.build_virtual_graph_context(updated_source)
        base_graph = (context.get("evidence") or {}).get("graph_context") or {}
        # Preserve caller information from the original bundle if available.
        virtual_graph["callers"] = base_graph.get("callers") or []

        bundle = self._build_virtual_bundle(context, updated_source, virtual_graph)
        try:
            opa_output = evaluate_bundle(bundle)
        except Exception as exc:  # pragma: no cover - runtime guard
            LOGGER.exception("OPA evaluation failed for virtual fix: %s", exc)
            return {
                "status": "ERROR",
                "error": str(exc),
                "violation_id": violation_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
                "rule_id": context.get("rule_id"),
                "updated_source_code": updated_source,
                "explanation": explanation,
            }

        failing = []
        normalized_output: List[Dict[str, Any]] = []
        for raw in opa_output:
            normalized = normalize_violation_payload(raw)
            if normalized:
                normalized_output.append(normalized)
                if (normalized.get("violation_id") or normalized.get("id")) == context.get("rule_id"):
                    failing.append(normalized)
        opa_status = "PASS" if not failing else "FAIL"
        return {
            "status": "OK",
            "violation_id": violation_id,
            "rule_id": context.get("rule_id"),
            "target_method": context.get("target_method"),
            "file_path": context.get("file_path"),
            "updated_source_code": updated_source,
            "explanation": explanation,
            "opa_status": opa_status,
            "opa_details": normalized_output or opa_output,
        }

    # --- Core loop ------------------------------------------------------------------
    def _execute_run(self, run: RemediationRun, context: Dict[str, Any]) -> RemediationRun:
        workspace = self.create_workspace_for_run(run.id)
        self._update_run(run.id, workspace=workspace, state=RemediationState.GATHER_CONTEXT)
        previous_errors: List[str] = []
        changed_files: List[str] = []

        for attempt in range(run.max_attempts):
            self._update_run(run.id, attempts=attempt + 1, state=RemediationState.PROPOSE_PATCH)
            proposed = self.propose_patch(context, previous_errors)
            raw_output = proposed.get("raw_output")
            patch_text = proposed.get("patch")
            explanation = proposed.get("explanation")
            self._update_run(
                run.id,
                raw_llm_output=raw_output,
                patch=patch_text,
                explanation=explanation,
            )
            if not patch_text:
                previous_errors.append("LLM returned no patch.")
                self._update_run(run.id, errors=list(previous_errors))
                continue

            self._update_run(run.id, state=RemediationState.APPLY_PATCH)
            apply_ok, apply_err = self.apply_patch_to_workspace(workspace, patch_text)
            if not apply_ok:
                previous_errors.append(apply_err)
                self._update_run(run.id, compile_error=apply_err, errors=list(previous_errors))
                continue

            changed_files = self._extract_files_from_patch(patch_text)
            self._update_run(run.id, state=RemediationState.COMPILE)
            compile_ok = True
            compile_output = ""
            if not run.skip_compile:
                compile_ok, compile_output = self._compile_workspace(workspace, changed_files)
                if not compile_ok:
                    previous_errors.append(self._bounded_error(compile_output or "Compilation failed."))
                self._update_run(
                    run.id, compile_error=compile_output or None, errors=list(previous_errors)
                )
            else:
                compile_output = "Compile skipped (skip_compile=true)."
                self._update_run(run.id, compile_error=compile_output)

            self._update_run(run.id, state=RemediationState.POLICY_CHECK)
            context["skip_compile"] = run.skip_compile
            verification = self._verify_policy(context, workspace, changed_files)
            self._update_run(run.id, verification=verification)
            status = (verification.get("status") or "").upper()
            if status == "VERIFIED":
                self._update_run(run.id, state=RemediationState.SUCCESS, policy_error=None)
                return self.get_run(run.id)  # type: ignore

            policy_error = verification.get("details") or verification.get("message")
            if policy_error:
                previous_errors.append(str(policy_error))
            self._update_run(run.id, policy_error=str(policy_error), errors=list(previous_errors))

        self._update_run(run.id, state=RemediationState.FAILED)
        return self.get_run(run.id)  # type: ignore

    # --- Context gathering -----------------------------------------------------------
    def get_violation_context(
        self, violation_id: str, target_method: Optional[str] = None, file_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        result = evaluate_policies()
        if result.get("error"):
            LOGGER.error("Policy evaluation failed while gathering context: %s", result["error"])
            return None
        violations = result.get("violations") or []
        catalog = load_policy_catalog()
        for violation in violations:
            current_id = violation.get("violation_id") or violation.get("id")
            if not current_id or str(current_id) != str(violation_id):
                continue
            method = violation.get("target_method") or violation.get("method")
            path = violation.get("file_path")
            if target_method and method and target_method != method:
                continue
            if file_path and path and file_path != path:
                continue
            target_method = violation.get("target_method") or violation.get("method")
            file_path = violation.get("file_path")
            evidence = violation.get("evidence") or {}
            catalog_entry = catalog.get(current_id) if isinstance(catalog, dict) else None
            return {
                "violation": violation,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": current_id,
                "evidence": evidence,
                "catalog_entry": catalog_entry,
            }
        return None

    # --- LLM interaction -------------------------------------------------------------
    def propose_full_method(
        self, context: Dict[str, Any], previous_errors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        violation = context.get("violation") or {}
        evidence = context.get("evidence") or {}
        catalog_entry = context.get("catalog_entry") or {}
        source_code = (evidence.get("source_code") or "").strip()
        graph_context = evidence.get("graph_context") or {}
        vector_context = evidence.get("vector_context") or []
        file_path = context.get("file_path") or "<unknown>"
        policy_reason = violation.get("reason") or violation.get("description") or ""
        policy_title = catalog_entry.get("title") if isinstance(catalog_entry, dict) else ""
        errors_note = "\n".join(previous_errors or [])

        system_prompt = (
            "You are a senior Java engineer improving code for ISO 27001 policy compliance. "
            "Return STRICT JSON with keys: updated_source_code (a full replacement method with the SAME signature) "
            "and explanation (one or two sentences). Do not include markdown fences."
        )
        if errors_note:
            system_prompt += " Adjust the method to address previous errors."

        user_sections = [
            f"Violation: {violation}",
            f"Policy: {policy_title or ''} — {policy_reason}",
            f"File path: {file_path}",
            f"Target method: {context.get('target_method') or 'unknown'}",
            "Source snippet:",
            "```java",
            source_code,
            "```",
            "Graph context:",
            json.dumps(graph_context, indent=2),
            "Similar methods:",
            json.dumps(vector_context, indent=2),
        ]
        if errors_note:
            user_sections.append(f"Previous errors:\n{errors_note}")

        response = self._llm_client(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "\n".join(user_sections)},
            ]
        )
        parsed = self._parse_llm_virtual_json(response)
        parsed["raw_output"] = response
        return parsed

    def propose_patch(
        self, context: Dict[str, Any], previous_errors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        violation = context.get("violation") or {}
        evidence = context.get("evidence") or {}
        catalog_entry = context.get("catalog_entry") or {}
        source_code = (evidence.get("source_code") or "").strip()
        graph_context = evidence.get("graph_context") or {}
        vector_context = evidence.get("vector_context") or []
        file_path = context.get("file_path") or "<unknown>"
        policy_reason = violation.get("reason") or violation.get("description") or ""
        policy_title = catalog_entry.get("title") if isinstance(catalog_entry, dict) else ""
        errors_note = "\n".join(previous_errors or [])

        system_prompt = (
            "You are a senior application security engineer. "
            "Generate a minimal unified diff to fix the policy violation. "
            "Output STRICT JSON with keys: patch_type ('unified_diff'), patch, explanation. "
            f"The diff must apply to the repository root path and target the file {file_path}. "
            "Preserve existing behavior and imports."
        )
        if errors_note:
            system_prompt += " Adjust the patch to address previous errors."

        user_sections = [
            f"Violation: {violation}",
            f"Policy: {policy_title or ''} — {policy_reason}",
            f"File path: {file_path}",
            f"Target method: {context.get('target_method') or 'unknown'}",
            "Source snippet:",
            "```java",
            source_code,
            "```",
            "Graph context:",
            json.dumps(graph_context, indent=2),
            "Similar methods:",
            json.dumps(vector_context, indent=2),
        ]
        if errors_note:
            user_sections.append(f"Previous errors:\n{errors_note}")

        response = self._llm_client(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "\n".join(user_sections)},
            ]
        )
        parsed = self._parse_llm_json(response)
        parsed["raw_output"] = response
        return parsed

    @staticmethod
    def _parse_llm_json(text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            parts = cleaned.split("\n", 1)
            if len(parts) == 2:
                cleaned = parts[1]
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                patch = data.get("patch") or data.get("diff")
                explanation = data.get("explanation") or data.get("summary")
                return {"patch": patch, "explanation": explanation}
        except json.JSONDecodeError:
            LOGGER.warning("LLM output was not valid JSON: %s", cleaned[:200])
        return {"patch": None, "explanation": None}

    @staticmethod
    def _parse_llm_virtual_json(text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            parts = cleaned.split("\n", 1)
            if len(parts) == 2:
                cleaned = parts[1]
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return {
                    "updated_source_code": data.get("updated_source_code") or data.get("source"),
                    "explanation": data.get("explanation") or data.get("summary"),
                }
        except json.JSONDecodeError:
            LOGGER.warning("LLM output was not valid JSON for virtual fix: %s", cleaned[:200])
        return {"updated_source_code": None, "explanation": None}

    # --- Workspace + tooling ---------------------------------------------------------
    def create_workspace_for_run(self, run_id: str) -> str:
        base = _PROJECT_ROOT
        temp_dir = Path(tempfile.mkdtemp(prefix=f"remediation_{run_id}_"))
        workspace = temp_dir / "workspace"
        shutil.copytree(
            base,
            workspace,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                "__pycache__",
                ".pytest_cache",
                "node_modules",
                "index",
                "*.index",
                "*.faiss",
                "*.bin",
                "*.lock",
            ),
        )
        return workspace.as_posix()

    def apply_patch_to_workspace(self, workspace: str, patch_text: str) -> Tuple[bool, str]:
        patch_file = Path(workspace) / "remediation.patch"
        patch_file.write_text(patch_text, encoding="utf-8")
        for strip in ("0", "1"):
            cmd = ["patch", f"-p{strip}", "-i", patch_file.name]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                return False, "patch command not found"
            if proc.returncode == 0:
                return True, ""
        error = proc.stderr.strip() or proc.stdout.strip() or "patch apply failed"
        return False, error

    def _compile_workspace(self, workspace: str, files: List[str]) -> Tuple[bool, str]:
        if not files:
            return True, "No files to compile."
        paths = [str(self._workspace_path(workspace, f)) for f in files]
        try:
            proc = subprocess.run(
                ["javac", *paths],
                capture_output=True,
                text=True,
                check=False,
                cwd=workspace,
            )
        except FileNotFoundError:
            return False, "javac not found on PATH"
        output = f"{proc.stdout}\n{proc.stderr}".strip()
        return proc.returncode == 0, output

    # --- Verification ---------------------------------------------------------------
    def _verify_policy(
        self, context: Dict[str, Any], workspace: str, changed_files: List[str]
    ) -> Dict[str, Any]:
        target_method = context.get("target_method")
        workspace_files = [self._workspace_path(workspace, f) for f in changed_files]
        if not workspace_files and context.get("file_path"):
            workspace_files = [self._workspace_path(workspace, str(context["file_path"]))]
        for file_path in workspace_files:
            if not file_path.is_file():
                continue
            try:
                process_single_file(file_path.as_posix())
            except Exception as exc:  # pragma: no cover - runtime guard
                LOGGER.exception("Single-file ingestion failed for %s", file_path)
                return {
                    "status": "INGEST_FAILED",
                    "message": "Graph ingest failed",
                    "details": str(exc),
                }
        if not target_method:
            return {
                "status": "FAILED",
                "message": "Missing method signature for policy verification",
            }
        policy_result = self._policy.evaluate(target_method)
        violations = policy_result.get("violations") or []
        still_failing = [
            v for v in violations if (v.get("violation_id") or v.get("id")) == context.get("rule_id")
        ]
        if still_failing:
            return {
                "status": "POLICY_FAILED",
                "message": "Policy still failing",
                "details": policy_result,
            }
        return {
            "status": "VERIFIED",
            "message": "Result: Verified Fix",
            "details": policy_result,
            "compile_warning": "Compile skipped" if context.get("skip_compile") else None,
        }

    def build_virtual_graph_context(self, source_code: str) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "annotations": [],
            "uses_fields": [],
            "calls": [],
            "callers": [],
        }
        if not source_code:
            return context
        wrapped = f"class VirtualPreview {{\n{source_code}\n}}"
        try:
            tree = javalang.parse.parse(wrapped)
        except Exception as exc:  # pragma: no cover - parser guard
            LOGGER.warning("Failed to parse virtual method snippet: %s", exc)
            return context
        if not getattr(tree, "types", None):
            return context
        type_decl = tree.types[0]
        methods = getattr(type_decl, "methods", None) or []
        if not methods:
            return context
        method: MethodDeclaration = methods[0]
        context["annotations"] = [
            ann.name for ann in (method.annotations or []) if getattr(ann, "name", None)
        ]
        calls: set[str] = set()
        uses_fields: List[Dict[str, Any]] = []
        for _, node in method:
            if isinstance(node, MethodInvocation):
                parts = [p for p in (node.qualifier, node.member) if p]
                call = ".".join(parts) if parts else node.member
                if call:
                    calls.add(call)
            elif isinstance(node, MemberReference):
                member = node.member
                if member:
                    uses_fields.append({"name": member, "type": None, "class_fqn": None})
        context["calls"] = sorted(calls)
        context["uses_fields"] = uses_fields
        return context

    def _build_virtual_bundle(
        self, context: Dict[str, Any], updated_source: str, virtual_graph: Dict[str, Any]
    ) -> Dict[str, Any]:
        graph_context = {
            "annotations": virtual_graph.get("annotations") or [],
            "uses_fields": virtual_graph.get("uses_fields") or [],
            "calls": virtual_graph.get("calls") or [],
            "callers": virtual_graph.get("callers") or [],
        }
        evidence = context.get("evidence") or {}
        target_method = context.get("target_method")
        return {
            "target_method": target_method,
            "method_name": self._method_name_from_signature(target_method),
            "class_fqn": context.get("violation", {}).get("class_fqn"),
            "file_path": context.get("file_path"),
            "modifiers": context.get("violation", {}).get("modifiers") or [],
            "source_code": updated_source,
            "graph_context": graph_context,
            "vector_context": evidence.get("vector_context") or [],
        }

    # --- Helpers --------------------------------------------------------------------
    @staticmethod
    def _extract_files_from_patch(patch_text: str) -> List[str]:
        files: List[str] = []
        for line in patch_text.splitlines():
            if line.startswith("+++ "):
                candidate = line[4:].strip()
                if candidate.startswith("b/"):
                    candidate = candidate[2:]
                if candidate and candidate != "/dev/null":
                    files.append(candidate)
        return files

    def _save_run(self, run: RemediationRun) -> None:
        with self._lock:
            self._runs[run.id] = run

    def _update_run(self, run_id: str, **kwargs: Any) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                return
            for key, value in kwargs.items():
                if hasattr(run, key):
                    setattr(run, key, value)
            run.updated_at = _iso_now()
            self._runs[run_id] = run

    @staticmethod
    def _workspace_path(workspace: str, file_path: str) -> Path:
        candidate = Path(file_path)
        if candidate.is_absolute():
            try:
                rel = candidate.relative_to(_PROJECT_ROOT)
                return Path(workspace) / rel
            except ValueError:
                return candidate
        return Path(workspace) / candidate

    @staticmethod
    def _bounded_error(message: str, limit: int = 3000) -> str:
        if len(message) <= limit:
            return message
        return f"{message[:limit]}... [truncated]"

    @staticmethod
    def _method_name_from_signature(signature: Optional[str]) -> Optional[str]:
        if not signature:
            return None
        base = signature.split("(")[0]
        if not base:
            return None
        return base.split(".")[-1] or None


def orchestrate_remediation(violation_id: str) -> Dict[str, Any]:
    """
    Legacy wrapper for synchronous remediation. Runs a single remediation attempt.
    """
    service = RemediationService()
    try:
        run = service.start_run(violation_id, max_attempts=1)
        payload = run.to_dict()
        status = payload.get("state")
        payload["status"] = "VERIFIED" if status == RemediationState.SUCCESS.value else "FAILED"
        return payload
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception("Remediation orchestration failed: %s", exc)
        return {"status": "ERROR", "error": str(exc)}
