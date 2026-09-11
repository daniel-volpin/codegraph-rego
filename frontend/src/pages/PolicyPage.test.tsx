import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import PolicyPage from "./PolicyPage";
import { evaluatePolicies } from "../lib/api";
import { renderWithProviders } from "../test/render";
import type { PolicyEvaluateResponse } from "../lib/types";

vi.mock("../lib/api", () => ({
  fetchPolicyCatalog: vi.fn().mockResolvedValue({
    benchmark_categories: [],
    framework_demo_rule_ids: [],
  }),
  evaluatePolicies: vi.fn(),
}));

vi.mock("../lib/persistence", () => ({
  persistPolicyEvaluation: vi.fn().mockResolvedValue(undefined),
  readPersistedUploadedModules: vi.fn().mockResolvedValue([]),
  readPersistedPolicyEvaluation: vi.fn().mockResolvedValue(null),
}));

describe("PolicyPage", () => {
  beforeEach(() => {
    vi.mocked(evaluatePolicies).mockReset();
  });

  it("renders a top-level page heading", async () => {
    renderWithProviders(<PolicyPage />);

    expect(
      await screen.findByRole("heading", { level: 1, name: /policy evaluation/i }),
    ).toBeInTheDocument();
  });

  it("shows a persistent error when policy evaluation fails", async () => {
    vi.mocked(evaluatePolicies).mockRejectedValue(new Error("internal"));
    const user = userEvent.setup();

    renderWithProviders(<PolicyPage />);

    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);

    expect(await screen.findByRole("alert")).toHaveTextContent("Policy evaluation failed.");
    expect(screen.getByRole("alert")).toHaveTextContent("internal");
  });

  it("uses explicit completeness for a live zero-finding scan", async () => {
    vi.mocked(evaluatePolicies).mockResolvedValue({
      violations: [],
      evaluation: {
        status: "complete",
        attempted_bundles: 2,
        evaluated_bundles: 2,
        failed_bundles: 0,
        omitted_findings: 0,
        excluded_findings: 0,
        truncated: false,
        scope_limited: false,
        rule_ids: [],
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<PolicyPage />);
    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);
    expect(await screen.findByRole("status", { name: /policy evaluation status/i })).toHaveTextContent(
      /evaluation completed successfully/i,
    );
  });

  it("does not present a failed-bundle scan as clean despite legacy metadata", async () => {
    vi.mocked(evaluatePolicies).mockResolvedValue({
      violations: [],
      opa_output: {},
      enriched: [],
      evaluation: {
        status: "partial",
        attempted_bundles: 2,
        evaluated_bundles: 1,
        failed_bundles: 1,
        omitted_findings: 0,
        excluded_findings: 0,
        truncated: false,
        scope_limited: false,
        rule_ids: [],
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<PolicyPage />);
    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);
    expect(await screen.findByRole("status", { name: /policy evaluation status/i })).toHaveTextContent(
      /evaluation response is partial/i,
    );
    expect(screen.queryByText(/evaluation completed successfully with zero findings/i)).not.toBeInTheDocument();
  });

  it("announces loading and then distinguishes a successful zero-findings evaluation", async () => {
    vi.mocked(evaluatePolicies).mockResolvedValue({
      violations: [],
      opa_output: {},
      enriched: [],
    });
    const user = userEvent.setup();

    renderWithProviders(<PolicyPage />);

    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);

    expect(await screen.findByRole("status", { name: /policy evaluation status/i })).toHaveTextContent(
      /evaluation completed successfully/i,
    );
    expect(screen.getByText(/zero findings were returned/i)).toBeInTheDocument();
    expect(screen.getByText(/this means the policy engine evaluated the current workspace/i)).toBeInTheDocument();
  });

  it("renders findings with control, CWE, evidence, and remediation capability", async () => {
    vi.mocked(evaluatePolicies).mockResolvedValue(policyResponseWithFinding());
    const user = userEvent.setup();

    renderWithProviders(<PolicyPage />);

    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);

    expect((await screen.findAllByText("ISO-A.8-SQL-INJECTION"))[0]).toBeInTheDocument();
    expect(screen.getAllByText(/CWE-89/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/ISO A.8/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Manual review required/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/automatic remediation unavailable/i)).toBeInTheDocument();

    const evidenceDisclosure = screen.getByRole("group", { name: /evidence and source context/i });
    expect(evidenceDisclosure).toHaveAttribute("open");

    expect(within(evidenceDisclosure).getByText(/DemoController.java:21-28/i)).toBeInTheDocument();
    expect(within(evidenceDisclosure).getByText(/com.acme.QueryBuilder.build/i)).toBeInTheDocument();
  });

  it("keeps policy results inside a narrow-safe scroll region", async () => {
    vi.mocked(evaluatePolicies).mockResolvedValue(policyResponseWithFinding());
    const user = userEvent.setup();

    renderWithProviders(<PolicyPage />);

    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);

    expect((await screen.findAllByText("ISO-A.8-SQL-INJECTION"))[0]).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /expand rule group/i })).toBeInTheDocument();
    expect(screen.getByTestId("policy-results-layout")).toHaveClass("min-w-0", "grid-cols-[minmax(0,1fr)]");
    expect(screen.getByTestId("policy-results-region")).toHaveClass("min-w-0");
    expect(screen.getByTestId("policy-group-table-scroll")).toHaveClass("max-w-full", "overflow-x-auto");
  });

  it("communicates backend dependency failures as degraded or unavailable evaluation state", async () => {
    vi.mocked(evaluatePolicies).mockRejectedValue(new Error("Neo4j unavailable"));
    const user = userEvent.setup();

    renderWithProviders(<PolicyPage />);

    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);

    expect(await screen.findByRole("alert")).toHaveTextContent(/backend dependency unavailable/i);
    expect(screen.getByRole("alert")).toHaveTextContent(/neo4j unavailable/i);
  });
});

const policyResponseWithFinding = (): PolicyEvaluateResponse => ({
  violations: [
    {
      violation_id: "ISO-A.8-SQL-INJECTION",
      target_method: "com.acme.DemoController.search(String)",
      method_key: "test@revision:DemoController.java#search",
      file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/DemoController.java",
      severity: "high",
      reason: "Query string is built from request input.",
      code_snippet: "String sql = \"select * from users where name = '\" + input + \"'\";",
      snippet_start_line: 21,
      snippet_end_line: 28,
      control_metadata: {
        control: "ISO A.8",
        cwes: ["CWE-89"],
      },
      evidence: {
        graph_context: {
          callers: ["com.acme.QueryBuilder.build(String)"],
        },
        vector_context: ["com.acme.Repository.search(String)"],
      },
      remediation: {
        supported: false,
        support_tier: "manual",
        reason_code: "manual_injection_family",
        preview_available: false,
        verify_available: false,
        ui_apply_mode: "dry_run",
        rationale: "Injection findings require manual review of query semantics.",
        safe_refusal_possible: true,
      },
    },
  ],
  opa_output: {},
  enriched: [],
});
