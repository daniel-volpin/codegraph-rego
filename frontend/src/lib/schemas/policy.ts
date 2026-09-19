import { z } from "zod";
import { ViolationSchema } from "./common";

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
