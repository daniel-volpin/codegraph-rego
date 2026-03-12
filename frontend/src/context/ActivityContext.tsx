/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  ReactNode,
} from "react";

export type ActivityStatus = "idle" | "running" | "success" | "error";

export interface Activity {
  key: string;
  label: string;
  status: ActivityStatus;
  message?: string;
  progress?: number;
  updatedAt: string;
}

type ActivityState = Record<string, Activity>;

type Action =
  | { type: "upsert"; activity: Activity }
  | { type: "clear"; key: string }
  | { type: "reset" };

interface ActivityContextValue {
  activities: Activity[];
  upsert: (activity: Activity) => void;
  clear: (key: string) => void;
  reset: () => void;
}

const ActivityContext = createContext<ActivityContextValue | undefined>(
  undefined,
);

function activityReducer(state: ActivityState, action: Action): ActivityState {
  switch (action.type) {
    case "upsert": {
      return {
        ...state,
        [action.activity.key]: action.activity,
      };
    }
    case "clear": {
      const copy = { ...state };
      delete copy[action.key];
      return copy;
    }
    case "reset":
      return {};
    default:
      return state;
  }
}

export const ActivityProvider = ({ children }: { children: ReactNode }) => {
  const [state, dispatch] = useReducer(activityReducer, {});
  const upsert = useCallback((activity: Activity) => {
    dispatch({ type: "upsert", activity });
  }, []);
  const clear = useCallback((key: string) => {
    dispatch({ type: "clear", key });
  }, []);
  const reset = useCallback(() => {
    dispatch({ type: "reset" });
  }, []);
  const activities = useMemo(
    () =>
      Object.values(state).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
    [state],
  );

  const value = useMemo<ActivityContextValue>(() => {
    return {
      activities,
      upsert,
      clear,
      reset,
    };
  }, [activities, clear, reset, upsert]);

  return (
    <ActivityContext.Provider value={value}>
      {children}
    </ActivityContext.Provider>
  );
};

export const useActivityContext = () => {
  const ctx = useContext(ActivityContext);
  if (!ctx) {
    throw new Error("useActivityContext must be used within ActivityProvider");
  }
  return ctx;
};
