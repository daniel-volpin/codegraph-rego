import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { UploadStatusSchema } from "../lib/schemas";
import { buildRuntimeApiUrl } from "../lib/runtimeConfig";

export function useUploadStatusStream(requestId: string | null) {
  const queryClient = useQueryClient();
  const [streamConnected, setStreamConnected] = useState(false);

  useEffect(() => {
    if (!requestId || typeof window === "undefined" || typeof window.EventSource === "undefined") {
      return;
    }

    const streamUrl = buildRuntimeApiUrl("/upload/status/stream");
    streamUrl.searchParams.set("request_id", requestId);
    const source = new EventSource(streamUrl.toString());

    const handlePayload = (raw: string) => {
      let json: unknown;
      try {
        json = JSON.parse(raw);
      } catch {
        // Ignore non-JSON stream messages.
        return;
      }
      // Validate through the same schema as the polling path so the stream
      // can't write an untyped payload into the shared query cache.
      const parsed = UploadStatusSchema.safeParse(json);
      if (!parsed.success) return;
      queryClient.setQueryData(["uploadStatus", requestId], parsed.data);
      if (parsed.data.complete) {
        source.close();
        setStreamConnected(false);
      }
    };

    source.onopen = () => setStreamConnected(true);
    source.onmessage = (event) => handlePayload(event.data);
    source.addEventListener("status", (event) => {
      const message = event as MessageEvent<string>;
      handlePayload(message.data);
    });
    source.onerror = () => {
      setStreamConnected(false);
      source.close();
    };

    return () => {
      setStreamConnected(false);
      source.close();
    };
  }, [queryClient, requestId]);

  return { streamConnected };
}
