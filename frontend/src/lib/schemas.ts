import { z } from "zod";

// Schemas at the API boundary. Goals:
// - One source of truth for every wire shape.
// - Loose object types so unknown backend fields pass through (notably the
//   full violation payload that we hand back to /policy/explain_one).
// - Sensible defaults / .catch fallbacks so the UI degrades instead of
//   crashing when a non-critical field is missing or unknown.

// Common

export const RemediationCapabilitySchema = z.object({
  supported: z.boolean().default(false),
  support_tier: z.enum(["full", "guarded", "manual"]).catch("manual"),
  reason_code: z.string().default("unsupported_rule_for_auto_fix"),
  strategy: z.string().nullish(),
  preview_available: z.boolean().default(false),
  verify_available: z.boolean().default(false),
  ui_apply_mode: z.literal("dry_run").catch("dry_run"),
  rationale: z
    .string()
    .default("Automatic remediation is not available for this rule."),
  safe_refusal_possible: z.boolean().default(false),
});
export type RemediationCapability = z.infer<typeof RemediationCapabilitySchema>;

const EvidenceSchema = z
  .object({
    source_code: z.string().optional(),
  })
  .loose();

// Each violation passes through loose so the explain endpoint still receives
// the full original payload when we hand `violation.raw` back.
export const ViolationSchema = z
  .object({
    method_key: z.string().min(1),
    violation_id: z.string().optional(),
    rule_id: z.string().optional(),
    target_method: z.string().optional(),
    file_path: z.string().optional(),
    severity: z.string().optional(),
    reason: z.string().optional(),
    description: z.string().optional(),
    code_snippet: z.string().optional(),
    updated_source_code: z.string().optional(),
    evidence: EvidenceSchema.optional(),
    remediation: RemediationCapabilitySchema.optional(),
  })
  .loose();
export type Violation = z.infer<typeof ViolationSchema>;

// Upload / status

export const UploadResponseSchema = z
  .object({
    status: z.string(),
    java_root: z.string().nullish(),
    java_roots: z.array(z.string()).optional(),
    error: z.string().nullish(),
    request_id: z.string().nullish(),
  })
  .loose();
export type UploadResponse = z.infer<typeof UploadResponseSchema>;

export const UploadStatusSchema = z
  .object({
    phase: z.string(),
    message: z.string(),
    progress: z.number(),
    complete: z.boolean(),
    error: z.string().nullish(),
    updated_at: z.string(),
    started_at: z.string().nullish(),
    request_id: z.string().nullish(),
  })
  .loose();
export type UploadStatus = z.infer<typeof UploadStatusSchema>;

// Search

export const SearchMatchSchema = z
  .object({
    method: z.string(),
    neighbors: z.array(z.record(z.string(), z.unknown())).default([]),
  })
  .loose();
export type SearchMatch = z.infer<typeof SearchMatchSchema>;

export const SearchResponseSchema = z
  .object({
    matches: z.array(z.string()).default([]),
    contexts: z.array(z.array(SearchMatchSchema)).default([]),
    error: z.string().optional(),
  })
  .loose();
export type SearchResponse = z.infer<typeof SearchResponseSchema>;

// Policy

export const PolicyEvaluationSummarySchema = z.object({
  status: z.enum(["complete", "partial", "failed"]),
  attempted_bundles: z.number().int().nonnegative(),
  evaluated_bundles: z.number().int().nonnegative(),
  failed_bundles: z.number().int().nonnegative(),
  omitted_findings: z.number().int().nonnegative(),
  excluded_findings: z.number().int().nonnegative(),
  truncated: z.boolean(),
  scope_limited: z.boolean(),
  rule_ids: z.array(z.string()),
});

export const PolicyEvaluateResponseSchema = z
  .object({
    violations: z.array(ViolationSchema).optional(),
    opa_output: z.record(z.string(), z.unknown()).optional(),
    enriched: z.array(z.record(z.string(), z.unknown())).optional(),
    error: z.string().optional(),
    evaluation: PolicyEvaluationSummarySchema.optional(),
    failed_bundle_count: z.number().int().nonnegative().optional(),
    truncated: z.boolean().optional(),
  })
  .loose();
export type PolicyEvaluateResponse = z.infer<typeof PolicyEvaluateResponseSchema>;

export const PolicyExplanationStructuredSchema = z
  .object({
    evidence_id: z.string().nullish(),
    citation: z.string(),
    why: z.string(),
    fix: z.string(),
  })
  .loose();
export type PolicyExplanationStructured = z.infer<
  typeof PolicyExplanationStructuredSchema
>;

export const PolicyExplainOneResponseSchema = z
  .object({
    status: z.string(),
    explanation: z.string().nullish(),
    explanation_structured: PolicyExplanationStructuredSchema.nullish(),
    model: z.string().nullish(),
    include_graph_context: z.boolean().default(false),
    error: z.string().nullish(),
  })
  .loose();
export type PolicyExplainOneResponse = z.infer<
  typeof PolicyExplainOneResponseSchema
>;

// Policy reviews

export const PolicyReviewCreateResponseSchema = z
  .object({
    status: z.string(),
    review_id: z.string().nullish(),
    store_path: z.string().nullish(),
    scrub_warnings: z.array(z.string()).default([]),
    error: z.string().nullish(),
  })
  .loose();
export type PolicyReviewCreateResponse = z.infer<
  typeof PolicyReviewCreateResponseSchema
>;

export const PolicyReviewListResponseSchema = z
  .object({
    status: z.string(),
    reviews: z.array(z.record(z.string(), z.unknown())).default([]),
    error: z.string().nullish(),
  })
  .loose();
export type PolicyReviewListResponse = z.infer<
  typeof PolicyReviewListResponseSchema
>;

// Policy catalog

export const PolicyBenchmarkCategorySchema = z
  .object({
    category_id: z.string(),
    label: z.string(),
    cwes: z.array(z.string()).default([]),
    rego_rule_ids: z.array(z.string()).default([]),
    control_ids: z.array(z.string()).default([]),
    remediation_tier: z.enum(["full", "guarded", "manual"]).catch("manual"),
    framework_demo: z.boolean().default(false),
  })
  .loose();
export type PolicyBenchmarkCategory = z.infer<
  typeof PolicyBenchmarkCategorySchema
>;

export const PolicyCatalogResponseSchema = z
  .object({
    controls: z.array(z.record(z.string(), z.unknown())).default([]),
    rules: z.array(z.record(z.string(), z.unknown())).default([]),
    benchmark_categories: z.array(PolicyBenchmarkCategorySchema).default([]),
    framework_demo_rule_ids: z.array(z.string()).default([]),
    error: z.string().optional(),
  })
  .loose();
export type PolicyCatalogResponse = z.infer<typeof PolicyCatalogResponseSchema>;

// Policy Packs

export const PolicyPackRuleSchema = z
  .object({
    id: z.string(),
    control: z.string().default(""),
    title: z.string().default(""),
    summary: z.string().default(""),
    rego_module: z.string().default(""),
    rego_rule: z.string().default(""),
    category: z.string().default(""),
    severity: z.string().default("high"),
    reference: z.string().default(""),
    description: z.string().default(""),
    alias_ids: z.array(z.string()).default([]),
  })
  .loose();
export type PolicyPackRule = z.infer<typeof PolicyPackRuleSchema>;

export const PolicyPackSpecSchema = z
  .object({
    pack_id: z.string(),
    name: z.string(),
    standard: z.string(),
    version: z.string(),
    rego_dir: z.string().optional(),
    query_entrypoints: z.array(z.string()).default([]),
    enabled: z.boolean().default(true),
    description: z.string().default(""),
    rules_count: z.number().default(0),
    rules: z.array(PolicyPackRuleSchema).default([]),
  })
  .loose();
export type PolicyPackSpec = z.infer<typeof PolicyPackSpecSchema>;

export const PolicyPacksResponseSchema = z
  .object({
    status: z.string().default("OK"),
    packs: z.array(PolicyPackSpecSchema).default([]),
    error: z.string().optional(),
  })
  .loose();
export type PolicyPacksResponse = z.infer<typeof PolicyPacksResponseSchema>;

// Policy SARIF export / import

export const SarifExportResponseSchema = z
  .object({
    $schema: z.string().optional(),
    version: z.string().default("2.1.0"),
    runs: z.array(z.record(z.string(), z.unknown())).default([]),
  })
  .loose();
export type SarifExportResponse = z.infer<typeof SarifExportResponseSchema>;

export const SarifImportResponseSchema = z
  .object({
    status: z.string().default("OK"),
    count: z.number().default(0),
    violations: z.array(ViolationSchema).default([]),
    error: z.string().optional(),
  })
  .loose();
export type SarifImportResponse = z.infer<typeof SarifImportResponseSchema>;

// Remediation

export const RemediationGenerationResultSchema = z
  .object({
    decision: z.enum(["apply_edits", "no_fix"]).nullish(),
    edits: z
      .array(
        z.object({
          start_line: z.number(),
          end_line: z.number(),
          original_lines: z.array(z.string()),
          replacement_lines: z.array(z.string()),
        }),
      )
      .nullish(),
    replacement_method_lines: z.array(z.string()).nullish(),
    replacement_method_code: z.string().nullish(),
    reason: z.string().nullish(),
    raw_response_valid: z.boolean().default(false),
    // Explicitly null on success, not absent: `.optional()` alone rejected
    // every successful generation and surfaced it in the UI as a preview
    // failure, while the request itself had succeeded.
    schema_error: z.string().nullish(),
  })
  .loose();
export type RemediationGenerationResult = z.infer<
  typeof RemediationGenerationResultSchema
>;

// Confidence is a display-only surface. Every field uses `.catch()` so an
// out-of-range score (e.g. 1.0000001 from float rounding) or an unexpected
// band value degrades that field to null rather than failing the parse of
// the entire remediation response it is nested inside.
export const RemediationConfidenceSchema = z
  .object({
    score: z.number().min(0).max(1).nullish().catch(null),
    band: z.enum(["abstain", "review", "apply"]).nullish().catch(null),
    threshold_apply: z.number().min(0).max(1).nullish().catch(null),
    threshold_review: z.number().min(0).max(1).nullish().catch(null),
    rationale: z.string().nullish().catch(null),
  })
  .loose();
export type RemediationConfidence = z.infer<
  typeof RemediationConfidenceSchema
>;

export const RemediationVerificationSummarySchema = z
  .object({
    target_rule_status: z.string().nullish(),
    overall_status: z.string().nullish(),
    baseline: z.array(z.record(z.string(), z.unknown())).nullish(),
    after: z.array(z.record(z.string(), z.unknown())).nullish(),
    new_violations: z
      .array(z.record(z.string(), z.unknown()))
      .nullish(),
    remaining_violations: z
      .array(z.record(z.string(), z.unknown()))
      .nullish(),
    error: z.string().nullish(),
  })
  .loose();
export type RemediationVerificationSummary = z.infer<
  typeof RemediationVerificationSummarySchema
>;

export const RemediationCompilationResultSchema = z
  .object({
    attempted: z.boolean().default(false),
    success: z.boolean().default(false),
    output_snippet: z.string().nullish(),
    skipped_reason: z.string().nullish(),
  })
  .loose();
export type RemediationCompilationResult = z.infer<
  typeof RemediationCompilationResultSchema
>;

export const RemediationPreviewResponseSchema = z
  .object({
    method_key: z.string().nullish(),
    status: z.string(),
    violation_id: z.string(),
    rule_id: z.string().nullish(),
    target_method: z.string().nullish(),
    file_path: z.string().nullish(),
    updated_source_code: z.string().nullish(),
    explanation: z.string().nullish(),
    opa_status: z.string().nullish(),
    opa_details: z.unknown().optional(),
    diff: z.string().nullish(),
    verification: RemediationVerificationSummarySchema.nullish(),
    generation: RemediationGenerationResultSchema.nullish(),
    confidence: RemediationConfidenceSchema.nullish(),
    error: z.string().nullish(),
  })
  .loose();
export type RemediationPreviewResponse = z.infer<
  typeof RemediationPreviewResponseSchema
>;

export const RemediationApplyResponseSchema = z
  .object({
    method_key: z.string().nullish(),
    status: z.string(),
    violation_id: z.string(),
    rule_id: z.string().nullish(),
    target_method: z.string().nullish(),
    file_path: z.string().nullish(),
    updated_source_code: z.string().nullish(),
    diff: z.string().nullish(),
    verification: RemediationVerificationSummarySchema.nullish(),
    compilation: RemediationCompilationResultSchema.nullish(),
    metadata: z.record(z.string(), z.unknown()).nullish(),
    generation: RemediationGenerationResultSchema.nullish(),
    confidence: RemediationConfidenceSchema.nullish(),
    error: z.string().nullish(),
  })
  .loose();
export type RemediationApplyResponse = z.infer<
  typeof RemediationApplyResponseSchema
>;

export const AgenticRemediationResponseSchema = z
  .object({
    status: z.string(),
    rule_id: z.string().nullish(),
    method_key: z.string().nullish(),
    target_method: z.string().nullish(),
    workspace_root: z.string().nullish(),
    modified_files: z.array(z.string()).default([]),
    diff: z.string().default(""),
    verification: z.record(z.string(), z.unknown()).nullish(),
    reason: z.string().default(""),
    iterations: z.number().default(0),
    turns_count: z.number().default(0),
    error: z.string().nullish(),
  })
  .loose();
export type AgenticRemediationResponse = z.infer<
  typeof AgenticRemediationResponseSchema
>;

// Health

export const HealthStartupStatusSchema = z
  .object({
    ready: z.boolean(),
    phase: z.enum(["pending", "running", "ready", "degraded"]).catch("degraded"),
    checks: z.record(z.string(), z.boolean()).default({}),
    errors: z.record(z.string(), z.string()).default({}),
  })
  .loose();
export type HealthStartupStatus = z.infer<typeof HealthStartupStatusSchema>;

export const HealthCheckResponseSchema = z
  .object({
    status: z.enum(["ok", "degraded"]).catch("degraded"),
    startup_ready: z.boolean(),
    neo4j: z.boolean(),
    graph_generation: z.boolean(),
    faiss_index: z.boolean(),
    signature_map: z.boolean(),
    embedding_model: z.boolean(),
    opa: z.boolean(),
    startup: HealthStartupStatusSchema,
    details: z.record(z.string(), z.unknown()).default({}),
  })
  .loose();
export type HealthCheckResponse = z.infer<typeof HealthCheckResponseSchema>;
