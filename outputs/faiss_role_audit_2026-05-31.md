# FAISS Role Audit

FAISS/vector search is used as evidence enrichment for LLM-facing explanation and remediation prompts. It is not part of the Rego detection decision path in the reported benchmark evaluation, and this thesis does not claim a separate detection improvement from FAISS.

| Question | Answer |
|---|---|
| vector_context_used_by_rego | False |
| faiss_affects_detection | False |
| faiss_used_for_explanation_prompt_context | True |
| faiss_used_for_remediation_prompt_context | True |
| ablation_artifact_exists | False |

## Source Evidence

- codegraph/policy/runtime/bundles.py builds vector_context from HybridSearchService before bundle serialization.
- policy/*.rego contains no vector_context references.
- codegraph/llm/tasks/explanation.py includes vector_context only in full evidence mode and not in lean mode.
- codegraph/llm/tasks/remediation.py includes vector_context in LLM-facing prompt sections when present.
