import { z } from "zod";

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
