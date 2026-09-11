import { del, get, set } from "idb-keyval";
import {
  PolicyEvaluateResponseSchema,
  UploadResponseSchema,
  type PolicyEvaluateResponse,
  type UploadResponse,
} from "./schemas";
import type { PolicyViewPreset } from "../components/features/policy/policyUtils";
import { uniqueSortedModuleLabels } from "./workspace";

// IndexedDB-backed persistence for large response payloads. Replaces the
// previous main-thread `JSON.stringify(localStorage.setItem(...))` path,
// which blocked rendering on multi-MB OPA evaluation payloads.
//
// Schema versioning: bump SCHEMA_VERSION when the wire shape changes in a
// way that older stored payloads can no longer parse. The version is part
// of the key so old entries get garbage-collected naturally.

const SCHEMA_VERSION = 3;

const evaluationKey = (preset: PolicyViewPreset) =>
  `codegraph:policy:eval:v${SCHEMA_VERSION}:${preset}`;
const lastUploadKey = `codegraph:upload:last:v${SCHEMA_VERSION}`;

interface PersistedEnvelope<T> {
  v: number;
  savedAt: number;
  data: T;
}

export interface PersistedPolicyEvaluation {
  data: PolicyEvaluateResponse;
  savedAt: number;
  preset: PolicyViewPreset;
}

export async function readPersistedPolicyEvaluation(
  preset: PolicyViewPreset,
): Promise<PersistedPolicyEvaluation | null> {
  try {
    const envelope = await get<PersistedEnvelope<unknown>>(evaluationKey(preset));
    if (!envelope || envelope.v !== SCHEMA_VERSION) return null;

    // Re-validate persisted payloads through the schema — they may have
    // been written by an older build whose shape no longer parses.
    const parsed = PolicyEvaluateResponseSchema.safeParse(envelope.data);
    if (!parsed.success) return null;

    return { data: parsed.data, savedAt: envelope.savedAt, preset };
  } catch {
    return null;
  }
}

export async function persistPolicyEvaluation(
  data: PolicyEvaluateResponse,
  preset: PolicyViewPreset,
): Promise<void> {
  try {
    const envelope: PersistedEnvelope<PolicyEvaluateResponse> = {
      v: SCHEMA_VERSION,
      savedAt: Date.now(),
      data,
    };
    await set(evaluationKey(preset), envelope);
  } catch {
    /* ignore storage errors */
  }
}

export async function clearPersistedPolicyEvaluations(): Promise<void> {
  try {
    await Promise.all([del(evaluationKey("all")), del(evaluationKey("framework_demo"))]);
  } catch {
    /* ignore storage errors */
  }
}

export async function readPersistedLastUpload(): Promise<UploadResponse | null> {
  try {
    const saved = await get<unknown>(lastUploadKey);
    const parsed = UploadResponseSchema.safeParse(saved);
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export async function persistLastUpload(data: UploadResponse): Promise<void> {
  try {
    await set(lastUploadKey, data);
  } catch {
    /* ignore storage errors */
  }
}

export async function readPersistedUploadedModules(): Promise<string[]> {
  const upload = await readPersistedLastUpload();
  if (!upload) return [];
  const roots = upload.java_roots?.length
    ? upload.java_roots
    : upload.java_root
      ? [upload.java_root]
      : [];
  return uniqueSortedModuleLabels(roots.filter(Boolean));
}
