from __future__ import annotations

from typing import Any, Dict, List, TypedDict


class ExplanationEvidenceCard(TypedDict):
    id: str
    kind: str
    title: str
    citation: str
    summary: str


def format_citation(file_path: str | None, start_line: Any, end_line: Any) -> str:
    normalized_path = (file_path or "").strip()
    if normalized_path and isinstance(start_line, int) and isinstance(end_line, int):
        if start_line == end_line:
            return f"{normalized_path} line {start_line}"
        return f"{normalized_path} lines {start_line}-{end_line}"
    return normalized_path or "No file citation available"


def build_evidence_cards(
    *,
    file_path: str | None,
    target_method: str | None,
    start_line: Any,
    end_line: Any,
    source_code: str,
    graph_context: Dict[str, Any],
    vector_context: List[Any],
    analysis_flags: Dict[str, Any],
    include_graph_context: bool,
    evidence_mode: str,
) -> List[ExplanationEvidenceCard]:
    if not include_graph_context:
        return []

    citation = format_citation(file_path, start_line, end_line)
    cards: List[ExplanationEvidenceCard] = []
    if citation != "No file citation available" or source_code.strip():
        title = "Primary code evidence"
        if target_method:
            title = f"{title} for {target_method}"
        cards.append(
            {
                "id": "E1",
                "kind": "primary_snippet",
                "title": title,
                "citation": citation,
                "summary": "The finding is anchored to the provided source snippet and line range.",
            }
        )

    if graph_context:
        calls = graph_context.get("calls") or []
        annotations = graph_context.get("annotations") or []
        summaries: list[str] = []
        if annotations:
            summaries.append(f"annotations={len(annotations)}")
        if calls:
            summaries.append(f"calls={len(calls)}")
        if analysis_flags:
            summaries.append(
                "flags=" + ",".join(sorted(str(key) for key, value in analysis_flags.items() if value))
            )
        cards.append(
            {
                "id": "E2",
                "kind": "graph_summary",
                "title": "Graph-derived evidence summary",
                "citation": citation,
                "summary": "; ".join(summaries) if summaries else "Graph context is available for this finding.",
            }
        )

    if evidence_mode == "full" and vector_context:
        cards.append(
            {
                "id": "E3",
                "kind": "related_examples",
                "title": "Related benchmark examples",
                "citation": citation,
                "summary": f"{len(vector_context)} similar methods are available as supporting context.",
            }
        )

    return cards


def resolve_evidence_card(
    evidence_cards: List[ExplanationEvidenceCard],
    evidence_id: str | None,
) -> ExplanationEvidenceCard | None:
    if not evidence_id:
        return None
    normalized = evidence_id.strip()
    if not normalized:
        return None
    for card in evidence_cards:
        if card["id"] == normalized:
            return card
    return None
