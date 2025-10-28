import { useActivityContext } from "../context/ActivityContext";
import HealthStatus from "./HealthStatus";

const statusClassMap: Record<string, string> = {
  running: "activity-running",
  success: "activity-success",
  error: "activity-error",
  idle: "activity-idle"
};

const ActivityTray = () => {
  const { activities } = useActivityContext();
  const hasActivities = activities.length > 0;

  return (
    <aside className="activity-tray" aria-live="polite">
      {hasActivities && (
        <>
          <h3>Activity</h3>
          <ul>
            {activities.map((activity) => (
              <li key={activity.key} className={statusClassMap[activity.status] ?? ""}>
                <div className="activity-header">
                  <span className="activity-label">{activity.label}</span>
                  <span className="activity-status">{activity.status}</span>
                </div>
                {activity.message && (
                  <p className="activity-message">{activity.message}</p>
                )}
                {typeof activity.progress === "number" && !Number.isNaN(activity.progress) && (
                  <div className="activity-progress">
                    <div
                      className="activity-progress-bar"
                      style={{ width: `${Math.min(Math.max(activity.progress, 0), 100)}%` }}
                    />
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
      <HealthStatus />
    </aside>
  );
};

export default ActivityTray;
