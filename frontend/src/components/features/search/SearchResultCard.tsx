import React, { ReactNode } from "react";
import CodeHighlight from "../../ui/CodeHighlight";
import { Card } from "../../ui/card";
import { Badge } from "../../ui/badge";
import type { SearchMatch } from "../../../lib/types";

interface SearchResultCardProps {
  signature: string;
  context: SearchMatch[];
}

export const SearchResultCard: React.FC<SearchResultCardProps> = ({
  signature,
  context,
}) => {
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
      return <span className="break-all text-slate-700">{value}</span>;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return <span className="text-slate-700">{String(value)}</span>;
    }
    if (value && typeof value === "object") {
      return (
        <CodeHighlight code={JSON.stringify(value, null, 2)} language="json" />
      );
    }
    return <span className="text-slate-400">—</span>;
  };

  return (
    <Card className="p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="truncate font-semibold text-slate-900">{signature}</h3>
        <Badge variant="secondary">{context?.length ?? 0} contexts</Badge>
      </div>

      {context?.length ? (
        <ul className="space-y-4">
          {context.map((ctx, ctxIndex) => (
            <li key={`${signature}-${ctxIndex}`} className="rounded-lg border border-slate-200 bg-slate-50 p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <p className="font-medium text-slate-800">{ctx.method}</p>
                <span className="text-xs text-slate-500">{ctx.neighbors.length} related</span>
              </div>

              {ctx.neighbors.length > 0 ? (
                <div className="grid gap-3 lg:grid-cols-2">
                  {ctx.neighbors.map((neighbor, neighborIndex) => {
                    const entries = Object.entries(neighbor ?? {});
                    return (
                      <section className="rounded-md border border-slate-200 bg-white p-3" key={neighborIndex}>
                        <header className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                          Neighbor {neighborIndex + 1}
                        </header>
                        <dl className="space-y-2">
                          {entries.length === 0 && (
                            <div className="text-sm text-slate-500">No metadata</div>
                          )}
                          {entries.map(([key, value]) => (
                            <div key={key} className="space-y-1">
                              <dt className="text-xs font-semibold uppercase text-slate-500">{key}</dt>
                              <dd className="m-0 text-sm">{renderNeighborValue(key, value)}</dd>
                            </div>
                          ))}
                        </dl>
                      </section>
                    );
                  })}
                </div>
              ) : (
                <p className="text-sm text-slate-500">No neighbors available.</p>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-500">No context found.</p>
      )}
    </Card>
  );
};
