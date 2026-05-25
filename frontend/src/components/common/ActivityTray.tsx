import { useActivityContext } from "../../context/ActivityContext";

const statusClassMap: Record<string, string> = {
  running: "text-amber-700 bg-amber-50",
  success: "text-emerald-700 bg-emerald-50",
  error: "text-rose-700 bg-rose-50",
  idle: "text-slate-600 bg-slate-100",
};

const ActivityTray = () => {
  const { activities } = useActivityContext();
  if (!activities.length) return null;

  return (
    <aside
      aria-label="Background activity"
      aria-live="polite"
      className="w-full shrink-0 space-y-3 rounded-xl border border-slate-200 bg-white p-4 lg:w-80"
    >
      <h3 className="text-sm font-semibold text-slate-900">Activity</h3>
      {activities.map((activity) => (
        <div key={activity.key} className="rounded-lg border border-slate-200 p-3">
          <div className="mb-1 flex items-center justify-between text-xs">
            <span className="font-medium">{activity.label}</span>
            <span className={`rounded-full px-2 py-0.5 ${statusClassMap[activity.status] ?? ""}`}>{activity.status}</span>
          </div>
          {activity.message && <p className="text-xs text-slate-600">{activity.message}</p>}
          {typeof activity.progress === "number" && (
            <div
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.min(Math.max(activity.progress, 0), 100)}
              aria-label={`${activity.label} progress`}
              className="mt-2 h-1.5 rounded-full bg-slate-100"
            >
              <div className="h-1.5 rounded-full bg-indigo-600" style={{ width: `${Math.min(Math.max(activity.progress, 0), 100)}%` }} />
            </div>
          )}
        </div>
      ))}
    </aside>
  );
};

export default ActivityTray;
