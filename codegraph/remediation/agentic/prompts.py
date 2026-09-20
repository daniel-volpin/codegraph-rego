from __future__ import annotations

from typing import TYPE_CHECKING, Any

from codegraph.remediation.contracts import get_fix_strategy

if TYPE_CHECKING:
    from codegraph.optimization.trajectory_bank import TrajectoryBank

SYSTEM_PROMPT_TEMPLATE = """You are an autonomous security refactoring agent.
Your objective is to assess a flagged security finding and remediate it at its root cause with minimal, surgical edits.

Invariant Gates (Must Pass 100%):
1. Compilation Gate: JDT / javac must compile with 0 errors.
2. Regression Gate: Project test suite must pass without regressions.
3. Policy Gate: The targeted security rule must be satisfied (0 remaining violations). Taint reaching sink arguments must be neutralized via safe parameterization (e.g. PreparedStatement, XPathVariableResolver, ProcessBuilder string arrays), framework sanitization (e.g. ESAPI), or constant decoupling. Prohibit custom runtime string-escaping loops.

Action Protocol & Parallel Execution:
- You may execute multiple tool calls in a single turn (e.g., `add_import` + `edit_file` + `run_verification`) to save turns and verify immediately.
- Use `inspect_class_api` to check available constructors, methods, and fields of any referenced class/helper without guessing.
- If the finding is a false positive (already sanitized/safe) or requires human architectural redesign, call `refuse_remediation`.
- Otherwise, use `edit_file` (and `add_import` if needed) to apply a minimal, sound patch.
- Every turn must execute a concrete tool call (`read_file`, `edit_file`, `add_import`, `inspect_class_api`, `run_verification`, or `finish_remediation`).
- Call `run_verification` to check all 3 gates. If diagnostics report errors, iteratively fix them.
- Once all 3 gates pass, call `finish_remediation`.
"""


def format_taint_path_dossier(taint_paths: list[dict[str, Any]]) -> str:
    """Format interprocedural call-graph trace for multi-file context grounding."""
    lines = ["\nInterprocedural Taint Propagation Trace (Call Graph):"]
    for idx, tp in enumerate(taint_paths, start=1):
        sink_type = tp.get("sink_type", "unknown")
        hops = tp.get("hops", 1)
        chain = tp.get("chain") or []
        if chain:
            chain_str = " -> ".join(f"`{hop.get('signature') or hop.get('method_key')}`" for hop in chain)
            lines.append(f"  Path {idx} ({sink_type.upper()} sink, {hops} hops): {chain_str}")
        else:
            lines.append(f"  Path {idx} ({sink_type.upper()} sink, {hops} hops)")
    return "\n".join(lines)


def build_initial_user_prompt(
    finding: dict[str, Any],
    *,
    trajectory_bank: TrajectoryBank | None = None,
) -> str:
    rule_id = str(finding.get("violation_id") or finding.get("rule_id") or "")
    method_key = str(finding.get("method_key") or "")
    target_method = str(finding.get("target_method") or method_key)
    file_path = str(finding.get("file_path") or "")
    if "uploaded_code/" in file_path:
        file_path = file_path.split("uploaded_code/", 1)[1]
    reason = str(finding.get("reason") or "Security finding detected")
    code_snippet = str(finding.get("code_snippet") or (finding.get("evidence") or {}).get("source_code") or "")

    prompt_parts = [
        f"Target Security Violation: {rule_id}",
        f"Target Method: {target_method}",
        f"File Path: {file_path}",
        f"Reason: {reason}",
    ]

    start_line = finding.get("start_line") or finding.get("snippet_start_line") or (finding.get("evidence") or {}).get("start_line")
    end_line = finding.get("end_line") or finding.get("snippet_end_line") or (finding.get("evidence") or {}).get("end_line")
    if start_line and end_line:
        prompt_parts.append(f"Target AST Location: Lines {start_line} to {end_line}")

    if code_snippet:
        prompt_parts.append(f"Target Method Snippet:\n```java\n{code_snippet}\n```")

    strategy = get_fix_strategy(rule_id, finding=finding, agentic=True)
    if strategy:
        prompt_parts.append("\nRecommended Fix Guidance:")
        prompt_parts.append(f"- Objective: {strategy.get('objective', '')}")
        allowed = strategy.get("allowed_transformations") or []
        if allowed:
            prompt_parts.append("- Allowed Transformations:")
            for t in allowed:
                prompt_parts.append(f"  * {t}")
        non_goals = strategy.get("non_goals") or []
        if non_goals:
            prompt_parts.append("- Non-Goals:")
            for ng in non_goals:
                prompt_parts.append(f"  * {ng}")

    taint_paths = finding.get("taint_paths") or (finding.get("evidence") or {}).get("taint_paths") or []
    if taint_paths:
        prompt_parts.append(format_taint_path_dossier(taint_paths))

    if trajectory_bank is not None:
        exemplars = trajectory_bank.query_exemplars(rule_id, limit=1)
        if exemplars:
            demo = exemplars[0]
            prompt_parts.append(
                f"\nVerified Exemplar Refactoring for `{rule_id}`:\n"
                f"```diff\n{demo.sanitized_diff()}\n```"
            )

    prompt_parts.append(
        "\nAction Plan:\n"
        "1. Inspect the Target Method Snippet and AST location (use `read_file` only if wider context is required).\n"
        "2. If needed, call `inspect_class_api` to check helper method/type signatures.\n"
        "3. Apply `edit_file` (and batch with `add_import` / `run_verification` in the same turn for speed).\n"
        "4. Call `finish_remediation` once verification passes."
    )
    return "\n".join(prompt_parts)
