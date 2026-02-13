import React, { ReactNode } from "react";
import CodeHighlight from "../../ui/CodeHighlight";
import type { SearchMatch } from "../../../lib/types";

interface SearchResultCardProps {
    signature: string;
    context: SearchMatch[];
}

export const SearchResultCard: React.FC<SearchResultCardProps> = ({ signature, context }) => {

    const renderNeighborValue = (key: string, value: unknown): ReactNode => {
        if (typeof value === "string") {
            const normalized = key.toLowerCase();
            const language =
                normalized.includes("json") || value.trim().startsWith("{")
                    ? "json"
                    : normalized.includes("code") || normalized.includes("snippet")
                        ? "java"
                        : "text";
            if (normalized.includes("code") || normalized.includes("snippet") || value.includes("\n")) {
                return <CodeHighlight code={value} language={language as "java" | "json" | "text"} />;
            }
            return value;
        }
        if (typeof value === "number" || typeof value === "boolean") {
            return String(value);
        }
        if (value && typeof value === "object") {
            return <CodeHighlight code={JSON.stringify(value, null, 2)} language="json" />;
        }
        return "—";
    };

    return (
        <article className="result-card">
            <div className="result-header">
                <span className="result-title">{signature}</span>
            </div>

            {context?.length ? (
                <ul className="context-list">
                    {context.map((ctx, ctxIndex) => (
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
                                                            <dd>{renderNeighborValue(key, value)}</dd>
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
                <p className="neighbor-empty">No context found.</p>
            )}
        </article>
    );
};
