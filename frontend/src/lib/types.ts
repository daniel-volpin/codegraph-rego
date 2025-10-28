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

export interface HealthCheckResponse {
  neo4j: boolean;
  faiss_index: boolean;
  signature_map: boolean;
  embedding_model: boolean;
  opa: boolean;
  details: Record<string, unknown>;
}
