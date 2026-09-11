import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Loader2, Search, Sparkles, Terminal } from "lucide-react";
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
        className="flex items-center gap-3 border-indigo-200/80 bg-indigo-50/60 p-4 text-sm text-indigo-950 shadow-2xs"
      >
        <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin text-indigo-600 shrink-0" />
        <span className="font-medium">Searching the code graph. Results will appear here when the backend responds.</span>
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
      className={`flex items-center gap-3 p-4 text-sm shadow-2xs ${
        count > 0
          ? "border-emerald-200/80 bg-emerald-50/60 text-emerald-950 font-medium"
          : "border-slate-200 bg-slate-50 text-slate-700"
      }`}
    >
      <CheckCircle2 aria-hidden="true" className="h-4 w-4 text-emerald-600 shrink-0" />
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
    <div className="space-y-6">
      <Card className="p-6 sm:p-8">
        <div className="max-w-3xl space-y-1">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Semantic Search</h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Query codebase methods using natural-language intent. Embeddings match semantic signatures, and Neo4j
            resolves structural graph neighbors.
          </p>
        </div>

        <form className="mt-6 flex flex-col gap-3 md:flex-row" role="search" onSubmit={handleSubmit}>
          <label htmlFor={SEARCH_INPUT_ID} className="sr-only">
            Search query
          </label>
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-400" />
            <Input
              id={SEARCH_INPUT_ID}
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Describe a method, vulnerability pattern, or control..."
              autoComplete="off"
              className="pl-10 h-10"
            />
          </div>
          <Button
            type="submit"
            disabled={searchPending || !query.trim()}
            className="md:min-w-36 h-10 shadow-xs"
          >
            <Search className="mr-1.5 h-4 w-4" />
            {searchPending ? "Searching..." : "Search"}
          </Button>
        </form>
      </Card>

      <SearchStatus pending={searchPending} result={result} />

      {!result && !searchPending && (
        <Card className="px-6 py-12 text-center border-dashed border-slate-300/80 bg-slate-50/40">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-indigo-50 text-indigo-600 shadow-2xs">
            <Sparkles className="h-6 w-6" />
          </div>
          <h3 className="mt-4 text-base font-semibold text-slate-800">Start searching</h3>
          <p className="mt-1 text-xs sm:text-sm text-slate-500 max-w-md mx-auto">
            Try one of these example queries:
          </p>
          <div className="mt-5 flex flex-wrap justify-center gap-2 max-w-2xl mx-auto">
            {EXAMPLE_QUERIES.map((q) => (
              <button
                key={q}
                type="button"
                onClick={() => setQuery(q)}
                className="group inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-2xs transition-all hover:border-indigo-300 hover:bg-indigo-50/50 hover:text-indigo-700 active:scale-95"
              >
                <Terminal className="h-3 w-3 text-slate-400 group-hover:text-indigo-600" />
                {q}
              </button>
            ))}
          </div>
        </Card>
      )}

      {result?.error && (
        <Card role="alert" className="border-rose-200 bg-rose-50/70 p-4 text-sm text-rose-800 shadow-2xs">
          <div className="flex items-start gap-2.5">
            <AlertTriangle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
            <div>
              <p className="font-semibold text-rose-900">{searchErrorTitle(result.error)}</p>
              <p className="mt-1 break-words text-xs text-rose-800">{result.error}</p>
            </div>
          </div>
          <p className="mt-3 border-t border-rose-200/60 pt-2 text-xs text-rose-700">
            If this mentions the search index or embeddings, upload and index a codebase first or wait for backend startup to finish.
          </p>
        </Card>
      )}

      {result && !result.error && result.matches.length === 0 && (
        <Card className="p-6 text-sm text-slate-600 text-center">
          <p className="font-semibold text-slate-800">No results found.</p>
          <p className="mt-1 max-w-md mx-auto text-xs text-slate-500">
            Try a more specific method name, API, vulnerability pattern, or control phrase. Confirm a codebase has been uploaded and indexed if the query should match.
          </p>
        </Card>
      )}

      {result && !result.error && result.matches.length > 0 && (
        <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6 xl:grid-cols-[minmax(20rem,26rem)_minmax(0,1fr)] xl:items-start">
          <Card className="overflow-hidden border-slate-200/90 shadow-soft">
            <div className="border-b border-slate-100 bg-slate-50/60 px-4 py-3">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                  Search results ({result.matches.length})
                </h2>
              </div>
              <p className="mt-0.5 text-[11px] text-slate-500">
                Select a result to inspect graph context returned by the backend.
              </p>
            </div>
            <ul aria-label="Search results" className="divide-y divide-slate-100 max-h-[calc(100vh-20rem)] overflow-y-auto">
              {result.matches.map((signature, index) => {
                const contextCount = result.contexts[index]?.length ?? 0;
                const selected = selectedIndex === index;
                return (
                  <li key={`${signature}-${index}`}>
                    <button
                      type="button"
                      aria-current={selected ? "true" : undefined}
                      onClick={() => setSelectedIndex(index)}
                      className={`relative block w-full min-w-0 px-4 py-3 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500 ${
                        selected
                          ? "bg-indigo-50/80 font-medium text-indigo-950"
                          : "bg-white hover:bg-slate-50/80 text-slate-800"
                      }`}
                    >
                      {selected && (
                        <div className="absolute left-0 top-0 bottom-0 w-1 bg-indigo-600" />
                      )}
                      <span className="block break-words font-mono text-xs font-semibold">
                        {compactSignature(signature)}
                      </span>
                      <span className="mt-1 block break-words font-mono text-[11px] text-slate-500 truncate">
                        {signature}
                      </span>
                      <span className="mt-2 inline-flex items-center gap-1 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600">
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

