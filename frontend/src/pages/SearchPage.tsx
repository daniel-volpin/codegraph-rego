import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Search, Sparkles } from "lucide-react";
import { searchCode } from "../lib/api";
import type { SearchResponse } from "../lib/types";
import { toast } from "sonner";
import { SearchResultCard } from "../components/features/search/SearchResultCard";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Button } from "../components/ui/button";

const EXAMPLE_QUERIES = [
  "methods using MessageDigest",
  "SQL query construction",
  "file upload handlers",
  "password hashing logic",
  "cryptographic key generation",
];

const SearchPage = () => {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<SearchResponse | null>(null);
  // Per-call AbortController. A second submit cancels any in-flight call so
  // a stale late response can't overwrite the latest UI state, and unmount
  // aborts whatever is in flight.
  const abortRef = useRef<AbortController | null>(null);
  useEffect(() => () => abortRef.current?.abort(), []);

  const searchMutation = useMutation({
    mutationFn: (q: string) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      return searchCode(q, ctrl.signal);
    },
    onSuccess: (data) => {
      setResult(data);
      const matchCount = data.matches.length;
      toast.success(
        matchCount > 0
          ? `Found ${matchCount} match${matchCount === 1 ? "" : "es"}.`
          : "Search completed.",
      );
    },
    onError: (error: Error) => {
      if (error.name === "AbortError") return;
      setResult({ matches: [], contexts: [], error: error.message });
      toast.error(`Search failed: ${error.message}`);
    },
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
    <div className="space-y-4">
      <Card className="p-6">
        <h1 className="text-2xl font-semibold text-slate-900">Semantic Search</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Find relevant methods with natural-language prompts and inspect structural neighbors in one place.
        </p>
        <form className="mt-5 flex flex-col gap-3 md:flex-row" onSubmit={handleSubmit}>
          <Input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Describe a method, vulnerability pattern, or control..."
          />
          <Button type="submit" disabled={searchPending || !query.trim()} className="md:min-w-36">
            <Search className="mr-1 h-4 w-4" />
            {searchPending ? "Searching..." : "Search"}
          </Button>
        </form>
      </Card>

      {!result && !searchPending && (
        <Card className="px-6 py-10 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-indigo-50">
            <Sparkles className="h-7 w-7 text-indigo-400" />
          </div>
          <h3 className="mt-4 text-base font-medium text-slate-700">Start searching</h3>
          <p className="mt-1 text-sm text-slate-500">
            Try one of these example queries:
          </p>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            {EXAMPLE_QUERIES.map((q) => (
              <button
                key={q}
                type="button"
                onClick={() => setQuery(q)}
                className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-600 transition hover:border-indigo-300 hover:bg-indigo-50 hover:text-indigo-700"
              >
                {q}
              </button>
            ))}
          </div>
        </Card>
      )}

      {searchPending && (
        <Card role="status" aria-live="polite" className="flex items-center gap-3 p-4 text-sm text-slate-600">
          <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin text-indigo-500" />
          Searching the code graph. Results will appear here when the backend responds.
        </Card>
      )}

      {result?.error && (
        <Card role="alert" className="border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
          <p className="font-medium text-rose-800">Search failed.</p>
          <p className="mt-1 break-words">{result.error}</p>
          <p className="mt-2 text-xs text-rose-700">
            If this mentions the search index or embeddings, upload and index a codebase first or wait for backend startup to finish.
          </p>
        </Card>
      )}

      {result && !result.error && result.matches.length === 0 && (
        <Card className="p-4 text-sm text-slate-600">No matches yet. Try a more specific query.</Card>
      )}

      {result && !result.error && result.matches.length > 0 && (
        <div className="space-y-4">
          {result.matches.map((signature, index) => (
            <SearchResultCard
              key={signature}
              signature={signature}
              context={result.contexts[index]}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default SearchPage;
