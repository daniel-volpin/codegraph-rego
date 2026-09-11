import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import EvaluationStatusCard from "./EvaluationStatusCard";

describe("EvaluationStatusCard", () => {
  it("renders running state when isFetching is true", () => {
    render(
      <EvaluationStatusCard
        isFetching={true}
        hasEvaluationResult={false}
        findingCount={0}
        totalFindingCount={0}
        ruleCount={0}
        errorMessage={null}
        responseIsPartial={false}
      />,
    );

    expect(screen.getByRole("status", { name: /policy evaluation status/i })).toHaveTextContent(
      /policy evaluation is running/i,
    );
  });

  it("renders empty successful state when 0 findings returned", () => {
    render(
      <EvaluationStatusCard
        isFetching={false}
        hasEvaluationResult={true}
        findingCount={0}
        totalFindingCount={0}
        ruleCount={0}
        errorMessage={null}
        responseIsPartial={false}
      />,
    );

    expect(screen.getByText(/evaluation completed successfully/i)).toBeInTheDocument();
    expect(screen.getByText(/zero findings were returned/i)).toBeInTheDocument();
  });

  it("renders partial state when response is partial", () => {
    render(
      <EvaluationStatusCard
        isFetching={false}
        hasEvaluationResult={true}
        findingCount={1}
        totalFindingCount={1}
        ruleCount={1}
        errorMessage={null}
        responseIsPartial={true}
      />,
    );

    expect(screen.getByText(/evaluation response is partial/i)).toBeInTheDocument();
  });

  it("renders findings state with count summary", () => {
    render(
      <EvaluationStatusCard
        isFetching={false}
        hasEvaluationResult={true}
        findingCount={5}
        totalFindingCount={5}
        ruleCount={3}
        errorMessage={null}
        responseIsPartial={false}
      />,
    );

    expect(screen.getByText(/evaluation completed with findings/i)).toBeInTheDocument();
    expect(screen.getByText(/5 visible findings across 3 rule groups/i)).toBeInTheDocument();
  });

  it("renders nothing when errorMessage is present", () => {
    const { container } = render(
      <EvaluationStatusCard
        isFetching={false}
        hasEvaluationResult={false}
        findingCount={0}
        totalFindingCount={0}
        ruleCount={0}
        errorMessage="Backend error"
        responseIsPartial={false}
      />,
    );

    expect(container.firstChild).toBeNull();
  });
});
