import type { HealthCheckResponse } from "../schemas";

export const DEMO_HEALTH: HealthCheckResponse = {
  status: "ok",
  startup_ready: true,
  neo4j: true,
  graph_generation: true,
  faiss_index: true,
  signature_map: true,
  embedding_model: true,
  opa: true,
  startup: {
    ready: true,
    phase: "ready",
    checks: {
      graph: true,
      embeddings: true,
      symbol_index: true,
      opa_engine: true,
    },
    errors: {},
  },
  details: {
    mode: "interactive_thesis_demo",
    version: "0.6.0-demo",
  },
};
