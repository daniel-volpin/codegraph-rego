import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Loader2, Search, Sparkles } from "lucide-react";
import { searchCode } from "../lib/api";
import type { SearchResponse } from "../lib/types";
import { toast } from "sonner";
import { messageMentionsBackendDependency } from "../lib/dependencies";
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

const SEARCH_INPUT_ID = "semantic-search-query";

const compactSignature = (signature: string) => {
  const openParen = signature.indexOf("(");
  const prefix = openParen >= 0 ? signature.slice(0, openParen) : signature;
  const suffix = openParen >= 0 ? signature.slice(openParen) : "";
  const parts = prefix.split(".").filter(Boolean);
  if (parts.length < 2) return signature;
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}${suffix}`;
};

const searchErrorTitle = (message: string | undefined) =>
  messageMentionsBackendDependency(message, ["faiss_index", "embedding_model"])
    ? "Search failed: backend search dependency unavailable."
    : "Search failed.";

interface SearchStatusProps {
  pending: boolean;
  result: SearchResponse | null;
}

const SearchStatus = ({ pending, result }: SearchStatusProps) => {
  if (!pending && !result) return null;
  if (pending) {
    return (
      <Card
        role="status"
        aria-label="Search status"
        aria-live="polite"
        className="flex items-center gap-3 border-indigo-200 bg-indigo-50 p-4 text-sm text-indigo-900"
      >
        <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin text-indigo-600" />
        Searching the code graph. Results will appear here when the backend responds.
      </Card>
    );
  }
  if (result?.error) return null;
  const count = result?.matches.length ?? 0;
  return (
    <Card
      role="status"
      aria-label="Search status"
      aria-live="off"
      className={`flex items-center gap-3 p-4 text-sm ${
        count > 0
          ? "border-emerald-200 bg-emerald-50 text-emerald-900"
          : "border-slate-200 bg-slate-50 text-slate-700"
      }`}
    >
      <CheckCircle2 aria-hidden="true" className="h-4 w-4 text-emerald-700" />
      <span>
        Search completed with {count} result{count === 1 ? "" : "s"}.
      </span>
    </Card>
  );
};

const SearchPage = () => {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<SearchResponse | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
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
      setSelectedIndex(data.matches.length > 0 ? 0 : null);
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
      setSelectedIndex(null);
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
    setSelectedIndex(null);
    searchMutation.mutate(query.trim());
  };

  const selectedSignature =
    result && !result.error && selectedIndex != null ? result.matches[selectedIndex] : null;
  const selectedContext =
    result && !result.error && selectedIndex != null ? result.contexts[selectedIndex] ?? [] : [];

  return (
    <div className="space-y-4">
      <Card className="p-6">
        <h1 className="text-2xl font-semibold text-slate-900">Semantic Search</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Find relevant methods with natural-language prompts and inspect structural neighbors in one place.
        </p>
        <form className="mt-5 flex flex-col gap-3 md:flex-row" role="search" onSubmit={handleSubmit}>
          <label htmlFor={SEARCH_INPUT_ID} className="sr-only">
            Search query
          </label>
          <Input
            id={SEARCH_INPUT_ID}
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Describe a method, vulnerability pattern, or control..."
            autoComplete="off"
          />
          <Button type="submit" disabled={searchPending || !query.trim()} className="md:min-w-36">
            <Search className="mr-1 h-4 w-4" />
            {searchPending ? "Searching..." : "Search"}
          </Button>
        </form>
      </Card>

      <SearchStatus pending={searchPending} result={result} />

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

      {result?.error && (
        <Card role="alert" className="border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
          <div className="flex items-start gap-2">
            <AlertTriangle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <p className="font-medium text-rose-800">{searchErrorTitle(result.error)}</p>
              <p className="mt-1 break-words">{result.error}</p>
            </div>
          </div>
          <p className="mt-2 text-xs text-rose-700">
            If this mentions the search index or embeddings, upload and index a codebase first or wait for backend startup to finish.
          </p>
        </Card>
      )}

      {result && !result.error && result.matches.length === 0 && (
        <Card className="p-4 text-sm text-slate-600">
          <p className="font-medium text-slate-800">No results found.</p>
          <p className="mt-1">
            Try a more specific method name, API, vulnerability pattern, or control phrase. Confirm a codebase has been uploaded and indexed if the query should match.
          </p>
        </Card>
      )}

      {result && !result.error && result.matches.length > 0 && (
        <div className="grid gap-4 xl:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)] xl:items-start">
          <Card className="overflow-hidden">
            <div className="border-b border-slate-200 px-4 py-3">
              <h2 className="text-sm font-semibold text-slate-900">Search results</h2>
              <p className="mt-1 text-xs text-slate-500">
                Select a result to inspect graph context returned by the backend.
              </p>
            </div>
            <ul aria-label="Search results" className="divide-y divide-slate-200">
              {result.matches.map((signature, index) => {
                const contextCount = result.contexts[index]?.length ?? 0;
                const selected = selectedIndex === index;
                return (
                  <li key={`${signature}-${index}`}>
                    <button
                      type="button"
                      aria-current={selected ? "true" : undefined}
                      onClick={() => setSelectedIndex(index)}
                      className={`block w-full min-w-0 px-4 py-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500 ${
                        selected ? "bg-indigo-50" : "bg-white hover:bg-slate-50"
                      }`}
                    >
                      <span className="block break-words font-mono text-sm font-semibold text-slate-900">
                        {compactSignature(signature)}
                      </span>
                      <span className="mt-1 block break-words font-mono text-xs text-slate-500">
                        {signature}
                      </span>
                      <span className="mt-2 block text-xs text-slate-500">
                        {contextCount} graph context{contextCount === 1 ? "" : "s"}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>

          {selectedSignature && (
            <SearchResultCard
              signature={selectedSignature}
              context={selectedContext}
            />
          )}
        </div>
      )}
    </div>
  );
};

export default SearchPage;
