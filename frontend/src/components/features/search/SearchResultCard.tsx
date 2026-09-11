import React, { ReactNode } from "react";
import CodeHighlight from "../../ui/CodeHighlight";
import { Card } from "../../ui/card";
import { Badge } from "../../ui/badge";
import type { SearchMatch } from "../../../lib/types";
import { Sparkles, GitFork, FileCode, Check, Copy } from "lucide-react";

interface SearchResultCardProps {
  signature: string;
  context: SearchMatch[];
}

export const SearchResultCard: React.FC<SearchResultCardProps> = ({
  signature,
  context,
}) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(signature);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard write failed
    }
  };

  const renderNeighborValue = (key: string, value: unknown): ReactNode => {
    if (typeof value === "string") {
      const normalized = key.toLowerCase();
      const language =
        normalized.includes("json") || value.trim().startsWith("{")
          ? "json"
          : normalized.includes("code") || normalized.includes("snippet")
            ? "java"
            : "text";
      if (
        normalized.includes("code") ||
        normalized.includes("snippet") ||
        value.includes("\n")
      ) {
        return (
          <CodeHighlight
            code={value}
            language={language as "java" | "json" | "text"}
          />
        );
      }
      return <span className="break-all font-mono text-xs text-zinc-700 dark:text-zinc-300">{value}</span>;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300">{String(value)}</span>;
    }
    if (value && typeof value === "object") {
      return (
        <CodeHighlight code={JSON.stringify(value, null, 2)} language="json" />
      );
    }
    return <span className="text-zinc-400">—</span>;
  };

  return (
    <Card className="min-w-0 p-5 shadow-xs border-zinc-200 dark:border-zinc-800" aria-label="Selected search result detail">
      <div className="mb-4 flex min-w-0 flex-wrap items-start justify-between gap-3 border-b border-zinc-100 pb-4 dark:border-zinc-800/80">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Selected Symbol Insight</h2>
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <p className="min-w-0 break-words font-mono text-xs font-medium text-zinc-800 dark:text-zinc-200 bg-zinc-100 dark:bg-zinc-800/60 px-2 py-1 rounded">
              {signature}
            </p>
            <button
              type="button"
              onClick={handleCopy}
              title="Copy signature"
              aria-label="Copy method signature"
              className="inline-flex h-7 w-7 items-center justify-center rounded border border-zinc-200 bg-white text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
        <Badge variant="secondary" className="font-mono text-xs">
          {context?.length ?? 0} contexts
        </Badge>
      </div>

      {context?.length ? (
        <ul className="space-y-4">
          {context.map((ctx, ctxIndex) => (
            <li
              key={`${signature}-${ctxIndex}`}
              className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-4 dark:border-zinc-800 dark:bg-zinc-900/40"
            >
              <div className="mb-3 flex min-w-0 flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <FileCode className="h-4 w-4 text-zinc-500 shrink-0" />
                  <p className="min-w-0 break-words font-mono text-xs font-semibold text-zinc-800 dark:text-zinc-200">
                    {ctx.method}
                  </p>
                </div>
                <span className="flex items-center gap-1 text-xs text-zinc-500 font-medium">
                  <GitFork className="h-3 w-3" />
                  {ctx.neighbors.length} related
                </span>
              </div>

              {ctx.neighbors.length > 0 ? (
                <div className="grid gap-3 lg:grid-cols-2">
                  {ctx.neighbors.map((neighbor, neighborIndex) => {
                    const entries = Object.entries(neighbor ?? {});
                    return (
                      <section
                        className="min-w-0 rounded-md border border-zinc-200/80 bg-white p-3 shadow-2xs dark:border-zinc-800 dark:bg-zinc-900"
                        key={neighborIndex}
                      >
                        <header className="mb-2 flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                          <span>Graph Citation #{neighborIndex + 1}</span>
                        </header>
                        <dl className="space-y-2">
                          {entries.length === 0 && (
                            <div className="text-xs text-zinc-500">No metadata recorded</div>
                          )}
                          {entries.map(([key, value]) => (
                            <div key={key} className="space-y-1">
                              <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                                {key.replace(/_/g, " ")}
                              </dt>
                              <dd className="m-0 text-xs">{renderNeighborValue(key, value)}</dd>
                            </div>
                          ))}
                        </dl>
                      </section>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-zinc-500">No neighbors available.</p>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-zinc-500">No context found.</p>
      )}
    </Card>
  );
};

