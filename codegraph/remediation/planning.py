from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from codegraph.java.fragments import JavaFragmentError, parse_strict_method_fragment
from codegraph.java.models import InvocationDTO, MethodDeclarationDTO


@dataclass(frozen=True)
class InvocationContract:
    member: str
    arg_count: int
    occurrence_count: int
    source_kind: str


@dataclass(frozen=True)
class RemediationPlan:
    transformation_class: str
    invariants: list[str] = field(default_factory=list)
    terminal_invocation_contracts: list[InvocationContract] = field(default_factory=list)

    def to_prompt_payload(self) -> dict[str, Any]:
        return {
            "transformation_class": self.transformation_class,
            "invariants": list(self.invariants),
            "terminal_invocation_contracts": [asdict(contract) for contract in self.terminal_invocation_contracts],
        }


def _sanitize_method_snippet(source_code: str) -> str:
    lines = source_code.splitlines()
    while lines and (lines[0].strip() == "" or lines[0].strip() == "}"):
        lines.pop(0)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("@") or stripped.startswith(("public", "private", "protected")):
            return "\n".join(lines[index:])
    return "\n".join(lines)


def _parse_method_wrapper(source_code: str) -> MethodDeclarationDTO | None:
    snippet = _sanitize_method_snippet(source_code)
    if not snippet.strip():
        return None
    try:
        return parse_strict_method_fragment(snippet.encode("utf-8"), require_body=False).method
    except JavaFragmentError:
        return None


def _source_kind(invocation: InvocationDTO) -> str:
    qualifier = invocation.qualifier_source or ""
    if qualifier.startswith("new "):
        return "constructor_chain"
    if len(invocation.chain_members) > 1 or "." in qualifier:
        return "factory_chain"
    return "direct_call"


def _collect_terminal_invocation_contracts(method: MethodDeclarationDTO) -> list[InvocationContract]:
    counts: dict[tuple[str, int, str], int] = {}
    for invocation in method.invocations:
        if not invocation.terminal_chain_member or invocation.kind != "method":
            continue
        source_kind = _source_kind(invocation)
        if source_kind == "direct_call":
            continue
        key = (invocation.name, invocation.argument_count, source_kind)
        counts[key] = counts.get(key, 0) + 1

    contracts = [
        InvocationContract(
            member=member,
            arg_count=arg_count,
            occurrence_count=occurrence_count,
            source_kind=source_kind,
        )
        for (member, arg_count, source_kind), occurrence_count in sorted(counts.items())
    ]
    return contracts


def build_remediation_plan(source_code: str) -> RemediationPlan:
    method = _parse_method_wrapper(source_code)
    if method is None:
        return RemediationPlan(transformation_class="unknown")

    contracts = _collect_terminal_invocation_contracts(method)
    if not contracts:
        return RemediationPlan(
            transformation_class="local_literal_or_call_edit",
            invariants=[
                "Preserve the method-local API behavior and keep edits focused on the risky literal or receiver expression.",
            ],
        )

    invariants = [
        "Preserve the downstream invocation contract when the risky code is in a constructor or factory receiver chain.",
    ]
    for contract in contracts:
        invariants.append(
            f"Keep terminal call {contract.member} with arity {contract.arg_count} available in the updated method at least {contract.occurrence_count} time(s)."
        )
    return RemediationPlan(
        transformation_class="receiver_chain_upgrade",
        invariants=invariants,
        terminal_invocation_contracts=contracts,
    )


def validate_remediation_plan(plan: RemediationPlan | None, updated_source: str) -> str | None:
    if plan is None or not plan.terminal_invocation_contracts:
        return None

    method = _parse_method_wrapper(updated_source)
    if method is None:
        return "plan_invariant_violation: parse_error"

    invocation_counts: dict[tuple[str, int], int] = {}
    for invocation in method.invocations:
        if invocation.kind != "method":
            continue
        key = (invocation.name, invocation.argument_count)
        invocation_counts[key] = invocation_counts.get(key, 0) + 1

    for contract in plan.terminal_invocation_contracts:
        current_count = invocation_counts.get((contract.member, contract.arg_count), 0)
        if current_count < contract.occurrence_count:
            return f"plan_invariant_violation: missing_terminal_invocation:{contract.member}/{contract.arg_count}"
    return None
