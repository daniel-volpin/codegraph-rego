from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from codegraph.telemetry import get_tracer

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_tracer = get_tracer("codegraph.remediation.verification")


def violation_key(violation: dict[str, Any]) -> str:
    return str(
        violation.get("violation_id") or violation.get("id") or violation.get("control") or violation.get("rule") or ""
    )


def build_verification_summary(
    rule_id: str | None,
    baseline: list[dict[str, Any]] | None,
    after: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    baseline_list = list(baseline or [])
    after_list = list(after or [])
    baseline_ids = {violation_key(v) for v in baseline_list if violation_key(v)}
    after_ids = {violation_key(v) for v in after_list if violation_key(v)}
    new_ids = after_ids - baseline_ids
    new_violations = [v for v in after_list if violation_key(v) in new_ids]
    remaining_violations = [v for v in after_list if violation_key(v) in baseline_ids]
    target_rule_status = "PASS"
    if rule_id and rule_id in after_ids:
        target_rule_status = "FAIL"
    overall_status = "PASS" if target_rule_status == "PASS" and not new_violations else "FAIL"
    with _tracer.start_as_current_span("policy.recheck") as recheck_span:
        recheck_span.set_attribute("rule_id", str(rule_id or ""))
        recheck_span.set_attribute("target_rule_status", target_rule_status)
        recheck_span.set_attribute("overall_status", overall_status)
        recheck_span.set_attribute("new_violations_count", len(new_violations))
        recheck_span.set_attribute("remaining_violations_count", len(remaining_violations))
        recheck_span.set_attribute("baseline_count", len(baseline_list))
        recheck_span.set_attribute("after_count", len(after_list))
    return {
        "target_rule_status": target_rule_status,
        "overall_status": overall_status,
        "baseline": baseline_list,
        "after": after_list,
        "new_violations": new_violations,
        "remaining_violations": remaining_violations,
    }


def detect_build_root(source_path: Path) -> Path | None:
    build_files = {"pom.xml", "build.gradle", "build.gradle.kts"}
    for ancestor in source_path.parents:
        if any((ancestor / name).exists() for name in build_files):
            return ancestor
    for ancestor in [_PROJECT_ROOT, *_PROJECT_ROOT.parents]:
        if any((ancestor / name).exists() for name in build_files):
            return ancestor
    return None


def prepare_temp_workspace(temp_root: Path, source_path: Path) -> tuple[Path, Path, Path | None]:
    build_root = detect_build_root(source_path)
    if build_root and build_root.exists():
        target_root = temp_root / build_root.name
        shutil.copytree(build_root, target_root)
        try:
            relative = source_path.relative_to(build_root)
        except ValueError:
            relative = Path(source_path.name)
        temp_file_path = target_root / relative
        temp_file_path.parent.mkdir(parents=True, exist_ok=True)
        return target_root, temp_file_path, target_root
    temp_file_path = temp_root / source_path.name
    temp_file_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, temp_file_path)
    return temp_root, temp_file_path, None


def compile_project(
    build_root: Path | None,
    build_command: str | None = None,
    *,
    run_command=subprocess.run,
) -> dict[str, Any]:
    with _tracer.start_as_current_span("build.verify") as span:
        if not build_root:
            span.set_attribute("build_skipped", True)
            span.set_attribute("build_skipped_reason", "No build system detected")
            return {
                "attempted": False,
                "success": False,
                "output_snippet": None,
                "skipped_reason": "No build system detected",
            }
        mvn_file = build_root / "pom.xml"
        gradle_file = build_root / "build.gradle"
        gradle_kts_file = build_root / "build.gradle.kts"
        if not any(path.exists() for path in [mvn_file, gradle_file, gradle_kts_file]):
            span.set_attribute("build_skipped", True)
            span.set_attribute("build_skipped_reason", "No build system detected")
            return {
                "attempted": False,
                "success": False,
                "output_snippet": None,
                "skipped_reason": "No build system detected",
            }

        if build_command:
            cmd = shlex.split(build_command)
            build_tool = "custom"
        elif mvn_file.exists():
            cmd = ["mvn", "-q", "-DskipTests", "compile"]
            build_tool = "maven"
        else:
            gradlew = build_root / "gradlew"
            if gradlew.exists():
                cmd = [gradlew.as_posix(), "-q", "compileJava"]
            else:
                cmd = ["gradle", "-q", "compileJava"]
            build_tool = "gradle"

        span.set_attribute("build_tool", build_tool)
        span.set_attribute("build_skipped", False)
        t0 = time.monotonic()
        try:
            proc = run_command(
                cmd,
                cwd=build_root,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            span.set_attribute("build_success", False)
            span.set_attribute("build_duration_ms", round((time.monotonic() - t0) * 1000))
            span.set_attribute("build_error_snippet", str(exc)[:200])
            return {
                "attempted": True,
                "success": False,
                "output_snippet": str(exc),
                "skipped_reason": "Build tool not available",
            }
        except subprocess.TimeoutExpired:
            span.set_attribute("build_success", False)
            span.set_attribute("build_duration_ms", 120000)
            span.set_attribute("build_error_snippet", "Compilation timed out")
            return {
                "attempted": True,
                "success": False,
                "output_snippet": "Compilation timed out",
                "skipped_reason": "Timeout",
            }

        output = "\n".join([proc.stdout.strip(), proc.stderr.strip()]).strip()
        output_snippet = output[:2000] if output else None
        success = proc.returncode == 0
        span.set_attribute("build_success", success)
        span.set_attribute("build_duration_ms", round((time.monotonic() - t0) * 1000))
        if not success and output_snippet:
            span.set_attribute("build_error_snippet", output_snippet[:200])
        return {
            "attempted": True,
            "success": success,
            "output_snippet": output_snippet,
        }


def method_name_from_signature(signature: str | None) -> str | None:
    if not signature:
        return None
    base = signature.split("(")[0]
    if not base:
        return None
    return base.split(".")[-1] or None


def build_virtual_bundle(
    context: dict[str, Any],
    updated_source: str,
    virtual_graph: dict[str, Any],
) -> dict[str, Any]:
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
        "method_name": method_name_from_signature(target_method),
        "class_fqn": context.get("violation", {}).get("class_fqn"),
        "file_path": context.get("file_path"),
        "modifiers": context.get("violation", {}).get("modifiers") or [],
        "source_code": updated_source,
        "graph_context": graph_context,
        "vector_context": evidence.get("vector_context") or [],
    }
