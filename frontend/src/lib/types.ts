export interface UploadResponse {
  status: string;
  java_root?: string | null;
  error?: string | null;
}

export interface UploadStatus {
  phase: string;
  message: string;
  progress: number;
  complete: boolean;
  error?: string | null;
  updated_at: string;
  started_at?: string | null;
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

export interface PolicyCatalogEntry {
  id?: string;
  control?: string;
  title?: string;
  description?: string;
  [key: string]: unknown;
}

export interface PolicyCatalogResponse {
  controls: PolicyCatalogEntry[];
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
  error?: string | null;
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
  error?: string | null;
}

export interface HealthCheckResponse {
  neo4j: boolean;
  faiss_index: boolean;
  signature_map: boolean;
  embedding_model: boolean;
  opa: boolean;
  details: Record<string, unknown>;
}
