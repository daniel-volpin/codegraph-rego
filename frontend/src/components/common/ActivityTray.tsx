import { useActivities } from "../../store/activity";

const statusClassMap: Record<string, string> = {
  running: "text-amber-700 bg-amber-50 border-amber-200",
  success: "text-emerald-700 bg-emerald-50 border-emerald-200",
  error: "text-rose-700 bg-rose-50 border-rose-200",
  idle: "text-slate-600 bg-slate-100 border-slate-200",
};

const ActivityTray = () => {
  const activities = useActivities();
  if (!activities.length) return null;

  return (
    <aside
      aria-label="Background activity"
      aria-live="polite"
      className="w-full shrink-0 space-y-3 rounded-xl border border-slate-200/80 bg-white p-4 shadow-soft lg:w-80"
    >
      <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          Background Activity
        </h3>
        <span className="flex h-2 w-2 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500" />
        </span>
      </div>
      {activities.map((activity) => (
        <div key={activity.key} className="rounded-lg border border-slate-200/70 bg-slate-50/50 p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-900">{activity.label}</span>
            <span className={`rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${statusClassMap[activity.status] ?? ""}`}>
              {activity.status}
            </span>
          </div>
          {activity.message && <p className="text-xs text-slate-600 leading-relaxed">{activity.message}</p>}
          {typeof activity.progress === "number" && (
            <div
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.min(Math.max(activity.progress, 0), 100)}
              aria-label={`${activity.label} progress`}
              className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200/70"
            >
              <div
                className="h-1.5 rounded-full bg-indigo-600 transition-all duration-300"
                style={{ width: `${Math.min(Math.max(activity.progress, 0), 100)}%` }}
              />
            </div>
          )}
        </div>
      ))}
    </aside>
  );
};

export default ActivityTray;

