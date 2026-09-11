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
    description: "Workspace runtime & index sync",
    homeLabel: "Workspace initialization",
    shortLabel: "runtime",
    aliases: ["startup", "preload", "workspace", "initialization"],
  },
  startup_ready: {
    description: "Workspace runtime & index sync",
    homeLabel: "Workspace initialization",
    shortLabel: "runtime",
    aliases: ["startup", "preload", "workspace", "initialization"],
  },
  neo4j: {
    description: "Neo4j code knowledge graph",
    homeLabel: "Code knowledge graph",
    shortLabel: "graph",
    aliases: ["neo4j", "graph database", "graph", "knowledge graph"],
  },
  faiss_index: {
    description: "Semantic code search index",
    homeLabel: "Semantic search index",
    shortLabel: "search index",
    aliases: ["faiss", "faiss index", "search index", "vector index"],
  },
  signature_map: {
    description: "Method symbol & signature catalog",
    homeLabel: "Method symbol catalog",
    shortLabel: "symbol catalog",
    aliases: ["signature map", "signatures", "symbol catalog", "symbols"],
  },
  embedding_model: {
    description: "Neural code embedding engine",
    homeLabel: "Neural embeddings",
    shortLabel: "embeddings",
    aliases: ["embedding", "embeddings", "embedding model", "neural model"],
  },
  opa: {
    description: "OPA policy compliance engine",
    homeLabel: "Policy compliance engine",
    shortLabel: "policy engine",
    aliases: ["opa", "policy engine", "rego", "compliance engine"],
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

