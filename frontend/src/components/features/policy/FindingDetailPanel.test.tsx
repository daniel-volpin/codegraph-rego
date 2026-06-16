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

  it("renders idle, running, and ready states for explain/preview/verify", async () => {
    const user = userEvent.setup();
    const { rerender } = renderWithProviders(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getByText(/no explanation generated yet/i)).toBeInTheDocument();
    expect(screen.getByText(/confidence score will appear after preview or verification completes/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /explain finding/i }));
    expect(mutationSpies.explain).toHaveBeenCalledWith(finding);

    hookState.pendingAction = "explain";
    rerender(<FindingDetailPanel selectedFinding={finding} />);
    expect(screen.getByRole("button", { name: /explaining/i })).toBeDisabled();

    hookState.pendingAction = undefined;
    hookState.explainResult = {
      status: "OK",
      explanation_structured: {
        citation: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java:40-42",
        why: "MD5 is weak and should not be used for security-sensitive hashing.",
        fix: "Replace MD5 with SHA-256.",
      },
    };
    rerender(<FindingDetailPanel selectedFinding={finding} />);
    expect(screen.getByText(/replace md5 with sha-256/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /preview suggested fix/i }));
    expect(mutationSpies.preview).toHaveBeenCalledWith(finding);

    hookState.pendingAction = "preview";
    rerender(<FindingDetailPanel selectedFinding={finding} />);
    expect(screen.getByRole("button", { name: /previewing/i })).toBeDisabled();

    hookState.pendingAction = undefined;
    hookState.previewResult = {
      status: "OK",
      diff: "@@ -1,3 +1,3 @@\n-MD5\n+SHA-256",
      confidence: {
        score: 0.95,
        band: "apply",
        threshold_apply: 0.75,
        threshold_review: 0.5,
        rationale: "High-confidence bounded replacement.",
      },
    };
    rerender(<FindingDetailPanel selectedFinding={finding} />);
    expect(screen.getByText(/proposed diff/i)).toBeInTheDocument();
    expect(screen.getByText(/high-confidence bounded replacement/i)).toBeInTheDocument();
    expect(screen.getByText(/score 95% against thesis review\/apply thresholds/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /verify fix/i }));
    expect(mutationSpies.apply).toHaveBeenCalledWith(finding);

    hookState.pendingAction = "apply";
    rerender(<FindingDetailPanel selectedFinding={finding} />);
    expect(screen.getByRole("button", { name: /verifying/i })).toBeDisabled();

    hookState.pendingAction = undefined;
    hookState.applyResult = {
      status: "OK",
      generation: {
        decision: "apply_edits",
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
      },
      confidence: {
        score: 0.95,
        band: "apply",
        threshold_apply: 0.75,
        threshold_review: 0.5,
        rationale: "High-confidence bounded replacement.",
      },
    };
    rerender(<FindingDetailPanel selectedFinding={finding} />);

    expect(screen.getByText(/verification summary/i)).toBeInTheDocument();
    expect(screen.getByText(/overall pass/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /view details/i }));
    expect(screen.getByText(/remaining violations:/i)).toBeInTheDocument();
    expect(screen.getByText(/decision:/i)).toBeInTheDocument();
  });

  it("shows non-OK remediation outcomes as issues", () => {
    hookState.applyResult = {
      status: "GENERATION_ERROR",
      error: "Model refused to produce a bounded method-local change.",
      generation: {
        decision: "no_fix",
        reason: "No safe replacement was evident from the local context.",
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

    expect(screen.getAllByText(/verification issue/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/model refused to produce/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/error/i).length).toBeGreaterThan(0);
  });
});
