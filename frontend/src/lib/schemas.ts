import { z } from "zod";

// Schemas at the API boundary. Goals:
// - One source of truth for every wire shape.
// - Loose object types so unknown backend fields pass through (notably the
//   full violation payload that we hand back to /policy/explain_one).
// - Sensible defaults / .catch fallbacks so the UI degrades instead of
//   crashing when a non-critical field is missing or unknown.

// ---- Common ----

export const RemediationCapabilitySchema = z.object({
  supported: z.boolean().default(false),
  support_tier: z.enum(["full", "guarded", "manual"]).catch("manual"),
  reason_code: z.string().default("unsupported_rule_for_auto_fix"),
  strategy: z.string().nullable().optional(),
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

// ---- Upload / status ----

export const UploadResponseSchema = z
  .object({
    status: z.string(),
    java_root: z.string().nullable().optional(),
    java_roots: z.array(z.string()).optional(),
    error: z.string().nullable().optional(),
    request_id: z.string().nullable().optional(),
  })
  .loose();
export type UploadResponse = z.infer<typeof UploadResponseSchema>;

export const UploadStatusSchema = z
  .object({
    phase: z.string(),
    message: z.string(),
    progress: z.number(),
    complete: z.boolean(),
    error: z.string().nullable().optional(),
    updated_at: z.string(),
    started_at: z.string().nullable().optional(),
    request_id: z.string().nullable().optional(),
  })
  .loose();
export type UploadStatus = z.infer<typeof UploadStatusSchema>;

// ---- Search ----

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

// ---- Policy ----

export const PolicyEvaluateResponseSchema = z
  .object({
    violations: z.array(ViolationSchema).optional(),
    opa_output: z.record(z.string(), z.unknown()).optional(),
    enriched: z.array(z.record(z.string(), z.unknown())).optional(),
    error: z.string().optional(),
  })
  .loose();
export type PolicyEvaluateResponse = z.infer<typeof PolicyEvaluateResponseSchema>;

export const PolicyExplanationStructuredSchema = z
  .object({
    evidence_id: z.string().nullable().optional(),
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
    explanation: z.string().nullable().optional(),
    explanation_structured: PolicyExplanationStructuredSchema.nullable().optional(),
    model: z.string().nullable().optional(),
    include_graph_context: z.boolean().default(false),
    error: z.string().nullable().optional(),
  })
  .loose();
export type PolicyExplainOneResponse = z.infer<
  typeof PolicyExplainOneResponseSchema
>;

// ---- Policy reviews ----

export const PolicyReviewCreateResponseSchema = z
  .object({
    status: z.string(),
    review_id: z.string().nullable().optional(),
    store_path: z.string().nullable().optional(),
    scrub_warnings: z.array(z.string()).default([]),
    error: z.string().nullable().optional(),
  })
  .loose();
export type PolicyReviewCreateResponse = z.infer<
  typeof PolicyReviewCreateResponseSchema
>;

export const PolicyReviewListResponseSchema = z
  .object({
    status: z.string(),
    reviews: z.array(z.record(z.string(), z.unknown())).default([]),
    error: z.string().nullable().optional(),
  })
  .loose();
export type PolicyReviewListResponse = z.infer<
  typeof PolicyReviewListResponseSchema
>;

// ---- Policy catalog ----

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

// ---- Remediation ----

export const RemediationGenerationResultSchema = z
  .object({
    decision: z.enum(["apply_edits", "no_fix"]).nullable().optional(),
    edits: z
      .array(
        z.object({
          start_line: z.number(),
          end_line: z.number(),
          original_lines: z.array(z.string()),
          replacement_lines: z.array(z.string()),
        }),
      )
      .nullable()
      .optional(),
    replacement_method_lines: z.array(z.string()).nullable().optional(),
    replacement_method_code: z.string().nullable().optional(),
    reason: z.string().nullable().optional(),
    raw_response_valid: z.boolean().default(false),
    schema_error: z.string().optional(),
  })
  .loose();
export type RemediationGenerationResult = z.infer<
  typeof RemediationGenerationResultSchema
>;

export const RemediationConfidenceSchema = z
  .object({
    score: z.number().min(0).max(1).nullable().optional(),
    band: z.enum(["abstain", "review", "apply"]).nullable().optional(),
    threshold_apply: z.number().min(0).max(1).nullable().optional(),
    threshold_review: z.number().min(0).max(1).nullable().optional(),
    rationale: z.string().nullable().optional(),
  })
  .loose();
export type RemediationConfidence = z.infer<
  typeof RemediationConfidenceSchema
>;

export const RemediationVerificationSummarySchema = z
  .object({
    target_rule_status: z.string().nullable().optional(),
    overall_status: z.string().nullable().optional(),
    baseline: z.array(z.record(z.string(), z.unknown())).nullable().optional(),
    after: z.array(z.record(z.string(), z.unknown())).nullable().optional(),
    new_violations: z
      .array(z.record(z.string(), z.unknown()))
      .nullable()
      .optional(),
    remaining_violations: z
      .array(z.record(z.string(), z.unknown()))
      .nullable()
      .optional(),
    error: z.string().nullable().optional(),
  })
  .loose();
export type RemediationVerificationSummary = z.infer<
  typeof RemediationVerificationSummarySchema
>;

export const RemediationCompilationResultSchema = z
  .object({
    attempted: z.boolean().default(false),
    success: z.boolean().default(false),
    output_snippet: z.string().nullable().optional(),
    skipped_reason: z.string().nullable().optional(),
  })
  .loose();
export type RemediationCompilationResult = z.infer<
  typeof RemediationCompilationResultSchema
>;

export const RemediationPreviewResponseSchema = z
  .object({
    status: z.string(),
    violation_id: z.string(),
    rule_id: z.string().nullable().optional(),
    target_method: z.string().nullable().optional(),
    file_path: z.string().nullable().optional(),
    updated_source_code: z.string().nullable().optional(),
    explanation: z.string().nullable().optional(),
    opa_status: z.string().nullable().optional(),
    opa_details: z.unknown().optional(),
    diff: z.string().nullable().optional(),
    verification: RemediationVerificationSummarySchema.nullable().optional(),
    generation: RemediationGenerationResultSchema.nullable().optional(),
    confidence: RemediationConfidenceSchema.nullable().optional(),
    error: z.string().nullable().optional(),
  })
  .loose();
export type RemediationPreviewResponse = z.infer<
  typeof RemediationPreviewResponseSchema
>;

export const RemediationApplyResponseSchema = z
  .object({
    status: z.string(),
    violation_id: z.string(),
    rule_id: z.string().nullable().optional(),
    target_method: z.string().nullable().optional(),
    file_path: z.string().nullable().optional(),
    updated_source_code: z.string().nullable().optional(),
    diff: z.string().nullable().optional(),
    verification: RemediationVerificationSummarySchema.nullable().optional(),
    compilation: RemediationCompilationResultSchema.nullable().optional(),
    metadata: z.record(z.string(), z.unknown()).nullable().optional(),
    generation: RemediationGenerationResultSchema.nullable().optional(),
    confidence: RemediationConfidenceSchema.nullable().optional(),
    error: z.string().nullable().optional(),
  })
  .loose();
export type RemediationApplyResponse = z.infer<
  typeof RemediationApplyResponseSchema
>;

// ---- Health ----

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
    faiss_index: z.boolean(),
    signature_map: z.boolean(),
    embedding_model: z.boolean(),
    opa: z.boolean(),
    startup: HealthStartupStatusSchema,
    details: z.record(z.string(), z.unknown()).default({}),
  })
  .loose();
export type HealthCheckResponse = z.infer<typeof HealthCheckResponseSchema>;
