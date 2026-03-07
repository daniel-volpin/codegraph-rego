# Thesis Context

## Thesis
- Title: `Operationalizing Security Policies: Graph-Based Code Understanding and LLM-Driven Compliance Enforcement`
- Project goal: build a neurosymbolic compliance workflow that translates security controls into executable checks, grounds findings in graph-structured code evidence, and uses LLMs for explanations and remediation.

## What This Repo Is Trying To Prove
- Natural-language security requirements can be operationalized into machine-actionable policy checks.
- Graph-based code understanding is useful as an evidence layer for policy evaluation and retrieval.
- LLMs are most useful after symbolic evidence retrieval, not as standalone detectors.
- The full workflow is:
  1. ingest JVM code into Neo4j
  2. evaluate controls with OPA/Rego
  3. generate grounded explanations
  4. attempt remediation
  5. re-verify in a fix-and-scan loop

## Scope
- Main implementation target: JVM microservices, especially Java/Spring style codebases.
- Main benchmark/evaluation target and primary demo substrate: OWASP Benchmark.
- Core evaluated categories currently include weak crypto/hash, insecure randomness, SQL injection, path traversal, command injection, LDAP injection, and XPath injection checks.
- Realistic sample apps such as JHipster are secondary qualitative case studies for upload/search/policy browsing, not the primary remediation evidence surface.

## Important Thesis Framing
- Prefer the phrase `graph-based code understanding` or `graph-structured evidence`.
- Do not overclaim full Code Property Graph / control-flow / data-dependency support unless it is explicitly implemented and verified.
- The strongest thesis contribution is the integrated compliance workflow, not just one isolated model or one isolated detector.

## Current System Design
- Symbolic layer:
  - Java parsing + graph ingestion into Neo4j
  - policy evaluation with OPA/Rego
- Neural layer:
  - LLM explanations over retrieved evidence
  - remediation proposals in a guarded apply/verify loop
- Retrieval layer:
  - graph evidence from Neo4j
  - optional vector/FAISS support where useful

## Current Validated Explanation-Eval Setup
- Preferred evaluation configuration:
  - `evidence_mode=lean`
  - `llm_max_tokens_eval=192`
  - `LLM_CONCURRENCY=1`
  - structured output enabled for explanation evaluation
- Important recent finding:
  - plain-text prompting led to poor citation compliance and `Thinking Process` leakage
  - structured JSON-schema output materially improved explanation citation quality
  - explicit stop sequences for local Qwen/LM Studio requests were added to stop repeated `<|im_end|>` token spam

## What Future Agents Should Preserve
- Keep evaluation changes isolated from remediation unless there is a clear reason to couple them.
- Keep explanation-eval optimizations measurable:
  - compare throughput
  - compare citation quality
  - do not accept speedups that materially degrade quality
- Prefer minimal, standards-based fixes over local hacks.
- Preserve reproducibility:
  - separate output directories per evaluation run
  - keep metrics artifacts
  - avoid overwriting baseline runs

## Practical Evaluation Guidance
- Detection benchmark is the foundation.
- Explanation evaluation should measure grounded citations, not generic prose quality.
- Remediation should be judged by fix success and re-verification, not only by patch appearance.
- Benchmark-centered live demos should show both:
  - bounded success on full-support categories
  - explicit safe refusal on guarded categories when the evidence is insufficient
  - explanation/manual-review coverage across multiple non-remediated benchmark families
- If a local LLM behaves badly, first look at:
  - output contract
  - stop behavior
  - token budget
  - prompt size
  - concurrency

## Current State Of The Branch
- Performance bottlenecks were already reduced substantially in ingestion and evaluation orchestration.
- Explanation evaluation now has:
  - live progress reporting
  - partial metrics
  - request-level telemetry
  - structured explanation output
- Before changing evaluation behavior again, check whether the change helps both:
  - throughput
  - citation/grounding quality

## Read Together With
- [architecture overview](./../copilot-context/architecture.md)
- [remediation prompting design](./remediation_prompting_design.md)
