import { z } from "zod";

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
    schema_error: z.string().nullish(),
  })
  .loose();
export type RemediationGenerationResult = z.infer<
  typeof RemediationGenerationResultSchema
>;

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
