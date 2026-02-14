import { Card } from "../components/ui/card";

const SettingsPage = () => {
  return (
    <Card className="p-6">
      <h1 className="text-2xl font-semibold text-slate-900">Settings</h1>
      <p className="mt-2 text-sm text-slate-600">
        Configure API endpoint behavior through <code>VITE_API_BASE_URL</code> and policy evaluation limits.
      </p>
    </Card>
  );
};

export default SettingsPage;
