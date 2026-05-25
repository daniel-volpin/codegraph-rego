import { ShieldCheck, Search, Scale, UploadCloud } from "lucide-react";
import { Card } from "../components/ui/card";

const highlights = [
  {
    title: "Ingest & Index",
    description:
      "Parse Java source into graph relationships and semantic embeddings for enterprise-grade discovery.",
    icon: UploadCloud,
  },
  {
    title: "Semantic Search",
    description:
      "Query code in natural language and retrieve context-rich structural neighbors for fast triage.",
    icon: Search,
  },
  {
    title: "Policy & Remediation",
    description:
      "Evaluate ISO controls, inspect violations, and orchestrate preview/apply remediation workflows.",
    icon: Scale,
  },
];

const HomePage = () => {
  return (
    <div className="space-y-6">
      <Card className="p-8">
        <div className="flex items-start gap-4">
          <div className="rounded-xl bg-indigo-100 p-3 text-indigo-700">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold text-slate-900">Security Research Dashboard</h1>
            <p className="max-w-3xl text-sm text-slate-600">
              Unified workspace for Java ingestion, semantic graph search, policy evaluation, and LLM-guided remediation.
            </p>
          </div>
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        {highlights.map((item) => {
          const Icon = item.icon;
          return (
            <Card key={item.title} className="p-6">
              <div className="mb-4 inline-flex rounded-lg bg-slate-100 p-2 text-slate-700">
                <Icon className="h-5 w-5" />
              </div>
              <h2 className="text-lg font-semibold text-slate-900">{item.title}</h2>
              <p className="mt-2 text-sm text-slate-600">{item.description}</p>
            </Card>
          );
        })}
      </div>

      <Card className="border-dashed p-4">
        <p className="text-sm text-slate-600">
          <span className="font-semibold text-slate-800">Tip:</span> set API base at runtime with <code className="rounded bg-slate-100 px-1 py-0.5">/config.json</code> (fallbacks: meta tag, then <code className="rounded bg-slate-100 px-1 py-0.5">VITE_API_BASE_URL</code>).
        </p>
      </Card>
    </div>
  );
};

export default HomePage;
