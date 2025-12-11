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

export type RemediationState =
  | "INIT"
  | "GATHER_CONTEXT"
  | "PROPOSE_PATCH"
  | "APPLY_PATCH"
  | "COMPILE"
  | "POLICY_CHECK"
  | "SUCCESS"
  | "FAILED";

export interface RemediationRun {
  id: string;
  violation_id: string;
  state: RemediationState;
  file_path?: string | null;
  rule_id?: string | null;
  target_method?: string | null;
  skip_compile?: boolean | null;
  attempts: number;
  max_attempts: number;
  patch?: string | null;
  explanation?: string | null;
  raw_llm_output?: string | null;
  compile_error?: string | null;
  compile_warning?: string | null;
  policy_error?: string | null;
  verification?: Record<string, unknown> | null;
  created_at?: string | null;
  updated_at?: string | null;
  errors?: string[] | null;
  status?: string | null;
}

export interface RemediationRunRequest {
  violation_id: string;
  target_method?: string;
  file_path?: string;
  max_attempts?: number;
  skip_compile?: boolean;
}

export interface RemediationResponse {
  status: string;
  original_file?: string;
  patched_file?: string;
  diff?: string;
  verification?: Record<string, unknown>;
  error?: string;
}

export interface HealthCheckResponse {
  neo4j: boolean;
  faiss_index: boolean;
  signature_map: boolean;
  embedding_model: boolean;
  opa: boolean;
  details: Record<string, unknown>;
}
