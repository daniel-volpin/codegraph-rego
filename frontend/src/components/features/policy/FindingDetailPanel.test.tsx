import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import FindingDetailPanel from "./FindingDetailPanel";
import { normalizeViolation } from "./policyUtils";
import { renderWithProviders } from "../../../test/render";
import type {
  PolicyExplainOneResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
} from "../../../lib/types";

const mutationSpies = {
  explain: vi.fn(),
  preview: vi.fn(),
  apply: vi.fn(),
};

const hookState: {
  explainResult: PolicyExplainOneResponse | undefined;
  previewResult: RemediationPreviewResponse | undefined;
  applyResult: RemediationApplyResponse | undefined;
  pendingAction: "explain" | "preview" | "apply" | undefined;
} = {
  explainResult: undefined,
  previewResult: undefined,
  applyResult: undefined,
  pendingAction: undefined,
};

function useExplainResultMock() {
  return hookState.explainResult;
}

function usePreviewResultMock() {
  return hookState.previewResult;
}

function useApplyResultMock() {
  return hookState.applyResult;
}

vi.mock("../../../hooks/usePolicyArtifacts", () => ({
  useExplainResult: () => useExplainResultMock(),
  usePreviewResult: () => usePreviewResultMock(),
  useApplyResult: () => useApplyResultMock(),
  usePendingAction: () => hookState.pendingAction,
  useExplainMutation: () => ({ mutate: mutationSpies.explain }),
  usePreviewMutation: () => ({ mutate: mutationSpies.preview }),
  useApplyMutation: () => ({ mutate: mutationSpies.apply }),
}));

const finding = normalizeViolation({
  violation_id: "ISO-A.10-WEAK-HASH",
  target_method: "com.acme.Demo.hash(String)",
  file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java",
  severity: "HIGH",
  reason: "Weak hash usage detected",
  code_snippet: "public void hash(String input) {\n  md5(input);\n}",
  snippet_start_line: 40,
  snippet_end_line: 42,
  evidence: {
    graph_context: {
      callers: ["com.acme.DemoController.submit()"],
    },
    vector_context: ["com.acme.HashHelper.hashValue()"],
  },
  remediation: {
    supported: true,
    support_tier: "full",
    reason_code: "supported_rule_for_auto_fix",
    preview_available: true,
    verify_available: true,
    ui_apply_mode: "dry_run",
    rationale: "Bounded replacement is supported.",
    safe_refusal_possible: false,
  },
});

describe("FindingDetailPanel", () => {
  beforeEach(() => {
    mutationSpies.explain.mockReset();
    mutationSpies.preview.mockReset();
    mutationSpies.apply.mockReset();
    hookState.explainResult = undefined;
    hookState.previewResult = undefined;
    hookState.applyResult = undefined;
    hookState.pendingAction = undefined;
  });

  it("renders evidence hierarchy and prompts for explanation", async () => {
    const user = userEvent.setup();
    renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getByText(/1\. Policy Finding \(Authoritative OPA Rule\)/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Source Evidence & Graph Grounding/i)).toBeInTheDocument();
    expect(screen.getByText(/3\. Generated LLM Explanation/i)).toBeInTheDocument();
    expect(screen.getByText(/4\. Remediation & Virtual Verification/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /explain finding/i }));
    expect(mutationSpies.explain).toHaveBeenCalledWith(finding);
  });

  it("renders structured explanation with model metadata", async () => {
    hookState.explainResult = {
      status: "OK",
      model: "qwen3.5-9b-mlx",
      explanation_structured: {
        citation: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java:40-42",
        why: "MD5 is cryptographically broken.",
        fix: "Migrate to SHA-256.",
      },
    };

    renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getByText(/Model: qwen3\.5-9b-mlx/i)).toBeInTheDocument();
    expect(screen.getByText(/AI Analysis \(Non-Authoritative\)/i)).toBeInTheDocument();
    expect(screen.getByText(/migrate to sha-256/i)).toBeInTheDocument();
  });

  it("renders read-only preview diff with copy control", async () => {
    hookState.previewResult = {
      status: "OK",
      violation_id: "ISO-A.10-WEAK-HASH",
      diff: "@@ -1,3 +1,3 @@\n-MD5\n+SHA-256",
      confidence: {
        score: 0.92,
        band: "apply",
        threshold_apply: 0.75,
        threshold_review: 0.5,
        rationale: "High confidence bounded fix.",
      },
    };

    renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getByText(/Read-Only Virtual Fix Preview/i)).toBeInTheDocument();
    expect(screen.getByText(/\+SHA-256/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /copy diff/i })).toBeInTheDocument();
  });

  it("opens confirmation dialog before running dry-run apply", async () => {
    const user = userEvent.setup();
    renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    await user.click(screen.getByRole("button", { name: /verify fix \(dry run\)/i }));

    expect(screen.getByTestId("remediation-confirm-modal")).toBeInTheDocument();
    expect(screen.getByText(/Confirm Dry-Run Remediation/i)).toBeInTheDocument();
    expect(screen.getByText(/Verify fix evaluates the patch against the virtual workspace/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /confirm & verify fix/i }));
    expect(mutationSpies.apply).toHaveBeenCalledWith(finding);
  });

  it("renders categorized pipeline outcome for fully verified apply", async () => {
    const user = userEvent.setup();
    hookState.applyResult = {
      status: "OK",
      violation_id: "ISO-A.10-WEAK-HASH",
      generation: {
        decision: "apply_edits",
        reason: "Replaced MD5 with SHA-256.",
      },
      verification: {
        overall_status: "PASS",
        target_rule_status: "PASS",
        remaining_violations: [],
        new_violations: [],
      },
      compilation: {
        attempted: true,
        success: true,
        output_snippet: "BUILD SUCCESSFUL in 1s",
      },
      confidence: {
        score: 0.95,
        band: "apply",
      },
    };

    renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getAllByText(/Fix Fully Verified/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Patch applied cleanly in dry-run mode/i)).toBeInTheDocument();
    expect(screen.getByText(/1\. Generation Decision:/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /view metrics detail/i }));
    expect(screen.getByText(/Remaining Violations:/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /view compilation log/i }));
    expect(screen.getByText(/Compiler Output Log/i)).toBeInTheDocument();
    expect(screen.getByText(/BUILD SUCCESSFUL in 1s/i)).toBeInTheDocument();
  });

  it("renders categorized outcome for no_fix abstention", () => {
    hookState.applyResult = {
      status: "OK",
      violation_id: "ISO-A.10-WEAK-HASH",
      generation: {
        decision: "no_fix",
        reason: "No safe method-local fix could be generated.",
      },
      verification: {
        overall_status: "NOT_RUN",
        target_rule_status: "NOT_RUN",
        remaining_violations: [],
        new_violations: [],
      },
      compilation: {
        attempted: false,
        success: false,
      },
    };

    renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getAllByText(/Remediation Abstained \(NO_FIX\)/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Abstained \/ No Fix/i)).toBeInTheDocument();
    expect(screen.getAllByText(/No safe method-local fix could be generated/i)[0]).toBeInTheDocument();
  });
});
