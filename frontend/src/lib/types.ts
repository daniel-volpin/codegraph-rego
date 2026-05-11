export interface UploadResponse {
  status: string;
  java_root?: string | null;
  java_roots?: string[];
  error?: string | null;
  request_id?: string | null;
}

export interface UploadStatus {
  phase: string;
  message: string;
  progress: number;
  complete: boolean;
  error?: string | null;
  updated_at: string;
  started_at?: string | null;
  request_id?: string | null;
}

export interface SearchMatch {
  method: string;
  neighbors: Record<string, unknown>[];
}

export interface SearchResponse {
  matches: string[];
  contexts: SearchMatch[][];
  error?: string;
}

export interface PolicyEvaluateResponse {
  violations?: Record<string, unknown>[];
  opa_output?: Record<string, unknown>;
  enriched?: Record<string, unknown>[];
  error?: string;
}

export interface PolicyEvaluateOptions {
  maxBundles?: number;
  maxTotalViolations?: number;
  maxPerViolationId?: number;
  ruleIds?: string[];
}

export interface RemediationCapability {
  supported: boolean;
  support_tier: "full" | "guarded" | "manual";
  reason_code: string;
  strategy?: string | null;
  preview_available: boolean;
  verify_available: boolean;
  ui_apply_mode: "dry_run";
  rationale: string;
  safe_refusal_possible: boolean;
}

export interface PolicyExplainOneRequest {
  violation: Record<string, unknown>;
  include_graph_context?: boolean;
  model?: string | null;
}

export interface PolicyExplanationStructured {
  evidence_id?: string | null;
  citation: string;
  why: string;
  fix: string;
}

export interface PolicyExplainOneResponse {
  status: string;
  explanation?: string | null;
  explanation_structured?: PolicyExplanationStructured | null;
  model?: string | null;
  include_graph_context: boolean;
  error?: string | null;
}

export type PolicyReviewLabel = "TP" | "FP" | "UNCLEAR";

export interface PolicyReviewCreateRequest {
  label: PolicyReviewLabel;
  notes?: string | null;
  violation: Record<string, unknown>;
  explanation?: string | null;
  llm_model?: string | null;
  include_graph_context?: boolean;
  remediation_preview?: Record<string, unknown> | null;
  remediation_apply?: Record<string, unknown> | null;
}

export interface PolicyReviewCreateResponse {
  status: string;
  review_id?: string | null;
  store_path?: string | null;
  scrub_warnings: string[];
  error?: string | null;
}

export interface PolicyReviewListResponse {
  status: string;
  reviews: Record<string, unknown>[];
  error?: string | null;
}

export interface PolicyCatalogEntry {
  id?: string;
  control?: string;
  title?: string;
  description?: string;
  [key: string]: unknown;
}

export interface PolicyRuleEntry {
  id?: string;
  standard?: string;
  description?: string;
  [key: string]: unknown;
}

export interface PolicyBenchmarkCategory {
  category_id: string;
  label: string;
  cwes: string[];
  rego_rule_ids: string[];
  control_ids: string[];
  remediation_tier: "full" | "guarded" | "manual";
  framework_demo: boolean;
}

export interface PolicyCatalogResponse {
  controls: PolicyCatalogEntry[];
  rules: PolicyRuleEntry[];
  benchmark_categories: PolicyBenchmarkCategory[];
  framework_demo_rule_ids: string[];
  error?: string;
}

export interface RemediationPreviewResponse {
  status: string;
  violation_id: string;
  rule_id?: string | null;
  target_method?: string | null;
  file_path?: string | null;
  updated_source_code?: string | null;
  explanation?: string | null;
  opa_status?: string | null;
  opa_details?: unknown;
  diff?: string | null;
  verification?: Record<string, unknown> | null;
  generation?: RemediationGenerationResult | null;
  error?: string | null;
}

export interface RemediationGenerationResult {
  decision?: "apply_edits" | "no_fix" | null;
  edits?:
    | {
        start_line: number;
        end_line: number;
        original_lines: string[];
        replacement_lines: string[];
      }[]
    | null;
  replacement_method_lines?: string[] | null;
  replacement_method_code?: string | null;
  reason?: string | null;
  raw_response_valid: boolean;
  schema_error?: string | null;
}

export interface RemediationVerificationSummary {
  target_rule_status?: string | null;
  overall_status?: string | null;
  baseline?: Record<string, unknown>[] | null;
  after?: Record<string, unknown>[] | null;
  new_violations?: Record<string, unknown>[] | null;
  remaining_violations?: Record<string, unknown>[] | null;
  error?: string | null;
}

export interface RemediationCompilationResult {
  attempted: boolean;
  success: boolean;
  output_snippet?: string | null;
  skipped_reason?: string | null;
}

export interface RemediationApplyResponse {
  status: string;
  violation_id: string;
  rule_id?: string | null;
  target_method?: string | null;
  file_path?: string | null;
  updated_source_code?: string | null;
  diff?: string | null;
  verification?: RemediationVerificationSummary | null;
  compilation?: RemediationCompilationResult | null;
  metadata?: Record<string, unknown> | null;
  generation?: RemediationGenerationResult | null;
  error?: string | null;
}

export interface HealthStartupStatus {
  ready: boolean;
  phase: "pending" | "running" | "ready" | "degraded";
  checks: Record<string, boolean>;
  errors: Record<string, string>;
}

export interface HealthCheckResponse {
  status: "ok" | "degraded";
  startup_ready: boolean;
  neo4j: boolean;
  faiss_index: boolean;
  signature_map: boolean;
  embedding_model: boolean;
  opa: boolean;
  startup: HealthStartupStatus;
  details: Record<string, unknown>;
}

export interface PolicyViolationSummary {
  raw: Record<string, unknown>;
  violationId?: string;
  filePath?: string;
  targetMethod?: string;
  title: string;
  reason?: string;
  severity: string;
  control: string;
  autoRemediationSupported: boolean;
}

export interface AutoRemediationResult {
  status: string;
  opa_status?: string;
  rule_id?: string;
  explanation?: string;
  error?: string;
  updated_source_code?: string;
  diff?: string;
  verification?: Record<string, unknown>;
  compilation?: Record<string, unknown>;
}
