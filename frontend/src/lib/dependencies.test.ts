import {
  BACKEND_DEPENDENCY_LABELS,
  messageMentionsBackendDependency,
} from "./dependencies";

describe("dependencies", () => {
  it("provides stable dependency labels for health summaries", () => {
    expect(BACKEND_DEPENDENCY_LABELS.neo4j.description).toBe("Neo4j graph database");
    expect(BACKEND_DEPENDENCY_LABELS.faiss_index.homeLabel).toBe("Search index");
    expect(BACKEND_DEPENDENCY_LABELS.opa.description).toBe("OPA policy engine");
  });

  it("classifies backend dependency failure messages", () => {
    expect(messageMentionsBackendDependency("Neo4j unavailable")).toBe(true);
    expect(messageMentionsBackendDependency("FAISS index unavailable", ["faiss_index"])).toBe(true);
    expect(messageMentionsBackendDependency("Neo4j unavailable", ["faiss_index", "embedding_model"])).toBe(false);
    expect(messageMentionsBackendDependency("backend connection refused", ["faiss_index"])).toBe(true);
  });
});
