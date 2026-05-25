import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { UploadStatus } from "../lib/types";
import { getRuntimeApiBase } from "../lib/runtimeConfig";

export function useUploadStatusStream(requestId: string | null) {
  const queryClient = useQueryClient();
  const [streamConnected, setStreamConnected] = useState(false);

  useEffect(() => {
    if (!requestId || typeof window === "undefined" || typeof window.EventSource === "undefined") {
      return;
    }

    const streamUrl = new URL(`${getRuntimeApiBase()}/upload/status/stream`);
    streamUrl.searchParams.set("request_id", requestId);
    const source = new EventSource(streamUrl.toString());

    const handlePayload = (raw: string) => {
      try {
        const payload = JSON.parse(raw) as UploadStatus;
        queryClient.setQueryData(["uploadStatus", requestId], payload);
        if (payload.complete) {
          source.close();
          setStreamConnected(false);
        }
      } catch {
        // Ignore malformed stream messages.
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
