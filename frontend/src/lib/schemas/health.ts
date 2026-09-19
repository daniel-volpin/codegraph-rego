import { z } from "zod";

export const HealthStartupStatusSchema = z
  .object({
    ready: z.boolean(),
    phase: z.enum(["pending", "running", "ready", "degraded"]).catch("degraded"),
    checks: z.record(z.string(), z.boolean()).default({}),
    errors: z.record(z.string(), z.string()).default({}),
  })
  .loose();
export type HealthStartupStatus = z.infer<typeof HealthStartupStatusSchema>;

export const HealthCheckResponseSchema = z
  .object({
    status: z.enum(["ok", "degraded"]).catch("degraded"),
    startup_ready: z.boolean(),
    neo4j: z.boolean(),
    graph_generation: z.boolean(),
    faiss_index: z.boolean(),
    signature_map: z.boolean(),
    embedding_model: z.boolean(),
    opa: z.boolean(),
    startup: HealthStartupStatusSchema,
    details: z.record(z.string(), z.unknown()).default({}),
  })
  .loose();
export type HealthCheckResponse = z.infer<typeof HealthCheckResponseSchema>;
