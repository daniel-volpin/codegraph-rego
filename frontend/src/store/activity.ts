import { useMemo } from "react";
import { create } from "zustand";
import { useShallow } from "zustand/react/shallow";

export type ActivityStatus = "idle" | "running" | "success" | "error";

export interface Activity {
  key: string;
  label: string;
  status: ActivityStatus;
  message?: string;
  progress?: number;
  updatedAt: string;
}

interface ActivityState {
  activities: Record<string, Activity>;
  upsert: (activity: Activity) => void;
  clear: (key: string) => void;
  reset: () => void;
}

// Store actions are referentially stable (defined inside `create`), so
// components that only need writers do not re-render when other writers
// fire activity updates.
export const useActivityStore = create<ActivityState>((set) => ({
  activities: {},
  upsert: (activity) =>
    set((state) => ({
      activities: { ...state.activities, [activity.key]: activity },
    })),
  clear: (key) =>
    set((state) => {
      if (!(key in state.activities)) return state;
      const next = { ...state.activities };
      delete next[key];
      return { activities: next };
    }),
  reset: () => set({ activities: {} }),
}));

// Writer-only selectors — referentially stable, never cause re-renders.
export const useUpsertActivity = () => useActivityStore((s) => s.upsert);
export const useClearActivity = () => useActivityStore((s) => s.clear);
export const useResetActivities = () => useActivityStore((s) => s.reset);

// Reader selector with shallow equality on the values array; sorting is
// memoized so consumers only re-render when the activity set actually
// changes.
export const useActivities = (): Activity[] => {
  const values = useActivityStore(useShallow((s) => Object.values(s.activities)));
  return useMemo(
    () => [...values].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
    [values],
  );
};
