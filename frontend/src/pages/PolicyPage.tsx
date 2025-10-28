import { FormEvent, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  evaluatePolicies,
  evaluatePoliciesWithLLM,
  fetchPolicyCatalog
} from "../lib/api";
import type {
  PolicyCatalogResponse,
  PolicyEvaluateResponse
} from "../lib/types";

const PolicyPage = () => {
  const [limit, setLimit] = useState(5);
  const [model, setModel] = useState("");
  const [evaluation, setEvaluation] =
    useState<PolicyEvaluateResponse | null>(null);
  const [llmEvaluation, setLlmEvaluation] =
    useState<PolicyEvaluateResponse | null>(null);

  const catalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: fetchPolicyCatalog
  });

  const baseEvalMutation = useMutation({
    mutationFn: evaluatePolicies,
    onSuccess: (data) => setEvaluation(data),
    onError: (error: Error) => setEvaluation({ error: error.message })
  });

  const llmEvalMutation = useMutation({
    mutationFn: () => evaluatePoliciesWithLLM(limit, model || undefined),
    onSuccess: (data) => setLlmEvaluation(data),
    onError: (error: Error) => setLlmEvaluation({ error: error.message })
  });

  const handleLlmSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    llmEvalMutation.mutate();
  };

  return (
    <section className="card">
      <h1>Policy Evaluation</h1>
      <p>
        Run ISO 27001 policy checks against the ingested knowledge graph and
        optionally request LLM-authored explanations for any violations.
      </p>
      <div className="policy-actions">
        <button
          onClick={() => baseEvalMutation.mutate()}
          disabled={baseEvalMutation.isLoading}
        >
          {baseEvalMutation.isLoading ? "Checking…" : "Evaluate Policies"}
        </button>
        <form className="policy-llm-form" onSubmit={handleLlmSubmit}>
          <label>
            Limit
            <input
              type="number"
              min={1}
              max={50}
              value={limit}
              onChange={(event) => setLimit(Number(event.target.value))}
            />
          </label>
          <label>
            LLM model (optional)
            <input
              type="text"
              value={model}
              onChange={(event) => setModel(event.target.value)}
              placeholder="Override backend default"
            />
          </label>
          <button type="submit" disabled={llmEvalMutation.isLoading}>
            {llmEvalMutation.isLoading ? "Requesting…" : "Evaluate with LLM"}
          </button>
        </form>
      </div>

      {evaluation && (
        <div className="policy-results">
          <h2>Evaluation Result</h2>
          {evaluation.error ? (
            <div className="callout callout-error">
              Error: {evaluation.error}
            </div>
          ) : (
            <pre>{JSON.stringify(evaluation, null, 2)}</pre>
          )}
        </div>
      )}

      {llmEvaluation && (
        <div className="policy-results">
          <h2>LLM Enriched Result</h2>
          {llmEvaluation.error ? (
            <div className="callout callout-error">
              Error: {llmEvaluation.error}
            </div>
          ) : (
            <pre>{JSON.stringify(llmEvaluation, null, 2)}</pre>
          )}
        </div>
      )}

      <section className="policy-catalog">
        <h2>ISO 27001 Catalog</h2>
        {catalogQuery.isLoading && <p>Loading catalog…</p>}
        {catalogQuery.error && (
          <div className="callout callout-error">
            Error loading catalog: {catalogQuery.error.message}
          </div>
        )}
        {catalogQuery.data && (
          <ul>
            {catalogQuery.data.controls.map((control, index) => (
              <li key={control.control ?? control.id ?? index}>
                <strong>{control.control ?? control.id ?? "Control"}</strong>{" "}
                {control.title && <span>- {control.title}</span>}
                {control.description && (
                  <p className="muted">{control.description}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </section>
  );
};

export default PolicyPage;
