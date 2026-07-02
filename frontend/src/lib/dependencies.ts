export type BackendDependencyKey =
  | "startup"
  | "startup_ready"
  | "neo4j"
  | "faiss_index"
  | "signature_map"
  | "embedding_model"
  | "opa";

interface BackendDependencyLabel {
  description: string;
  homeLabel: string;
  shortLabel: string;
  aliases: string[];
}

export const BACKEND_DEPENDENCY_LABELS: Record<BackendDependencyKey, BackendDependencyLabel> = {
  startup: {
    description: "Startup preload (graph sync, indexes)",
    homeLabel: "Startup preload",
    shortLabel: "startup",
    aliases: ["startup", "preload"],
  },
  startup_ready: {
    description: "Startup preload (graph sync, indexes)",
    homeLabel: "Startup preload",
    shortLabel: "startup",
    aliases: ["startup", "preload"],
  },
  neo4j: {
    description: "Neo4j graph database",
    homeLabel: "Graph database",
    shortLabel: "graph",
    aliases: ["neo4j", "graph database", "graph"],
  },
  faiss_index: {
    description: "FAISS semantic search index",
    homeLabel: "Search index",
    shortLabel: "search index",
    aliases: ["faiss", "faiss index", "search index"],
  },
  signature_map: {
    description: "Method signature map",
    homeLabel: "Signature map",
    shortLabel: "signatures",
    aliases: ["signature map", "signatures"],
  },
  embedding_model: {
    description: "Embedding model",
    homeLabel: "Embeddings",
    shortLabel: "embeddings",
    aliases: ["embedding", "embeddings", "embedding model"],
  },
  opa: {
    description: "OPA policy engine",
    homeLabel: "Policy engine",
    shortLabel: "OPA",
    aliases: ["opa", "policy engine"],
  },
};

const COMMON_BACKEND_FAILURE_TERMS = [
  "backend",
  "dependency",
  "startup",
  "unavailable",
  "connection",
  "connect",
  "refused",
  "unreachable",
];

export const messageMentionsBackendDependency = (
  message: string | null | undefined,
  keys: BackendDependencyKey[] = Object.keys(BACKEND_DEPENDENCY_LABELS) as BackendDependencyKey[],
) => {
  const normalized = message?.toLowerCase() ?? "";
  if (!normalized.trim()) return false;
  const aliases = keys.flatMap((key) => BACKEND_DEPENDENCY_LABELS[key].aliases);
  const scopedAliasHit = aliases.some((term) => normalized.includes(term));
  if (scopedAliasHit) return true;

  const allAliases = Object.values(BACKEND_DEPENDENCY_LABELS).flatMap((item) => item.aliases);
  const mentionsKnownDependency = allAliases.some((term) => normalized.includes(term));
  if (mentionsKnownDependency) return false;

  return COMMON_BACKEND_FAILURE_TERMS.some((term) => normalized.includes(term));
};
