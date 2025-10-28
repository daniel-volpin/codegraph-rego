import { FormEvent, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { searchCode } from "../lib/api";
import type { SearchResponse } from "../lib/types";

const SearchPage = () => {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<SearchResponse | null>(null);

  const searchMutation = useMutation({
    mutationFn: searchCode,
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (error: Error) => {
      setResult({ matches: [], contexts: [], error: error.message });
    }
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!query.trim()) {
      return;
    }
    searchMutation.mutate(query.trim());
  };

  return (
    <section className="card">
      <h1>Semantic Search</h1>
      <p>
        Query the embedded codebase. Results blend semantic similarity from the
        FAISS index with graph context from Neo4j.
      </p>
      <form className="search-form" onSubmit={handleSubmit}>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Describe a method or control you are looking for…"
        />
        <button type="submit" disabled={searchMutation.isLoading}>
          {searchMutation.isLoading ? "Searching…" : "Search"}
        </button>
      </form>
      {result && (
        <div className="search-results">
          {result.error && (
            <div className="callout callout-error">Error: {result.error}</div>
          )}
          {!result.error && result.matches.length === 0 && (
            <p>No matches yet. Try another query.</p>
          )}
          {result.matches.map((signature, index) => (
            <article className="search-result" key={signature}>
              <h2>{signature}</h2>
              {result.contexts[index]?.length ? (
                <ul className="context-list">
                  {result.contexts[index].map((ctx, ctxIndex) => (
                    <li key={`${signature}-${ctxIndex}`}>
                      <div className="context-header">
                        <p className="context-method">{ctx.method}</p>
                        <span className="context-count">
                          {ctx.neighbors.length} related
                        </span>
                      </div>
                      {ctx.neighbors.length > 0 && (
                        <div className="neighbor-grid">
                          {ctx.neighbors.map((neighbor, neighborIndex) => {
                            const entries = Object.entries(neighbor ?? {});
                            return (
                              <section className="neighbor-card" key={neighborIndex}>
                                <header>
                                  <span>Neighbor {neighborIndex + 1}</span>
                                </header>
                                <dl>
                                  {entries.length === 0 && (
                                    <div className="neighbor-empty">No metadata</div>
                                  )}
                                  {entries.map(([key, value]) => (
                                    <div key={key} className="neighbor-row">
                                      <dt>{key}</dt>
                                      <dd>{String(value)}</dd>
                                    </div>
                                  ))}
                                </dl>
                              </section>
                            );
                          })}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No additional graph context available.</p>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
};

export default SearchPage;
