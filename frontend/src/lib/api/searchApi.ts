import {
  SearchResponseSchema,
  type SearchResponse,
} from "../schemas";
import { getRuntimeApiBase } from "../runtimeConfig";
import { DEMO_SEARCH_MATCHES } from "../demoDataset";
import { defaultHeaders, isDemoMode, parseApiResponse, ApiError } from "./client";

export async function searchCode(query: string, signal?: AbortSignal): Promise<SearchResponse> {
  if (isDemoMode()) {
    const q = query.toLowerCase();
    const filteredMatches = DEMO_SEARCH_MATCHES.matches.filter((m) =>
      m.toLowerCase().includes(q) || q.includes("hash") || q.includes("crypto") || q.includes("pass") || q.includes("sql") || q.length === 0,
    );
    return {
      matches: filteredMatches.length > 0 ? filteredMatches : DEMO_SEARCH_MATCHES.matches,
      contexts: DEMO_SEARCH_MATCHES.contexts,
    };
  }

  const response = await fetch(`${getRuntimeApiBase()}/search`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query }),
    signal,
  });

  const data = await parseApiResponse(response, SearchResponseSchema);
  if (!response.ok) {
    throw new ApiError(data.error || response.statusText || "Search failed", response.status, data);
  }
  return data;
}
