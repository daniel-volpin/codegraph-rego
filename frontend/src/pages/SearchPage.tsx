import { FormEvent, ReactNode, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { searchCode } from "../lib/api";
import type { SearchResponse } from "../lib/types";
import { toast } from "react-hot-toast";
import { SearchResultCard } from "../components/features/search/SearchResultCard";

const SearchPage = () => {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<SearchResponse | null>(null);

  const searchMutation = useMutation({
    mutationFn: searchCode,
    onSuccess: (data) => {
      setResult(data);
      const matchCount = data.matches.length;
      toast.success(
        matchCount > 0
          ? `Found ${matchCount} match${matchCount === 1 ? "" : "es"}.`
          : "Search completed."
      );
    },
    onError: (error: Error) => {
      setResult({ matches: [], contexts: [], error: error.message });
      toast.error(`Search failed: ${error.message}`);
    }
  });

  const searchPending = searchMutation.status === "pending";

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!query.trim()) {
      return;
    }
    setResult(null);
    searchMutation.mutate(query.trim());
  };

  return (
    <section className="card">
      <header className="page-header">
        <h1>Semantic Search</h1>
        <p>
          Find relevant code snippets using natural language. Results combine vector-based semantic similarity
          with graph-based structural context.
        </p>
      </header>
      <form className="search-form" onSubmit={handleSubmit}>
        <div className="input-group">
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Describe a method or control..."
          />
          <button type="submit" className="btn-primary" disabled={searchPending || !query.trim()}>
            {searchPending ? "Searching..." : "Search"}
          </button>
        </div>
      </form>
      {result && (
        <div className="search-results">
          {result.error && (
            <div className="callout callout-error">
              <p>Search failed: {result.error}</p>
              <button
                type="button"
                className="callout-action"
                onClick={() => {
                  searchMutation.reset();
                  setResult(null);
                }}
              >
                Retry search
              </button>
            </div>
          )}
          {!result.error && result.matches.length === 0 && (
            <p>No matches yet. Try another query.</p>
          )}
          {result.matches.map((signature, index) => (
            <SearchResultCard
              key={signature}
              signature={signature}
              context={result.contexts[index]}
            />
          ))}
        </div>
      )}
    </section>
  );
};

export default SearchPage;
