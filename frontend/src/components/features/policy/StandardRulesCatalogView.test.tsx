import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StandardRulesCatalogView } from "./StandardRulesCatalogView";
import type { PolicyPackSpec } from "../../../lib/types";
import type { ViolationRow } from "./policyUtils";

const pack = (overrides: Partial<PolicyPackSpec> = {}): PolicyPackSpec => ({
  pack_id: "owasp-top10",
  name: "OWASP Top 10",
  standard: "owasp",
  version: "2021",
  query_entrypoints: [],
  enabled: true,
  description: "",
  rules_count: 2,
  rules: [
    {
      id: "owasp.injection",
      control: "A03",
      title: "SQL Injection",
      summary: "Untrusted input reaches a query.",
      rego_module: "",
      rego_rule: "",
      category: "Injection",
      severity: "high",
      reference: "",
      description: "",
      alias_ids: [],
    },
    {
      id: "owasp.broken_auth",
      control: "A07",
      title: "Broken Authentication",
      summary: "Session tokens are predictable.",
      rego_module: "",
      rego_rule: "",
      category: "Auth",
      severity: "medium",
      reference: "",
      description: "",
      alias_ids: [],
    },
  ],
  ...overrides,
});

const finding = (ruleId: string): ViolationRow =>
  ({
    id: `${ruleId}-1`,
    ruleId,
  }) as ViolationRow;

describe("StandardRulesCatalogView", () => {
  it("marks a rule compliant when no finding references it, and failing when one does", () => {
    render(
      <StandardRulesCatalogView
        packs={[pack()]}
        findings={[finding("owasp.injection")]}
        selectedStandard="all"
        onSelectRuleInFindings={vi.fn()}
      />,
    );

    expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("Broken Authentication")).toBeInTheDocument();
    expect(screen.getByText("1 finding")).toBeInTheDocument();
    expect(screen.getByText("0 Violations")).toBeInTheDocument();
  });

  it("filters the rule list as the user types in the search box", async () => {
    const user = userEvent.setup();
    render(
      <StandardRulesCatalogView
        packs={[pack()]}
        findings={[]}
        selectedStandard="all"
        onSelectRuleInFindings={vi.fn()}
      />,
    );

    await user.type(
      screen.getByPlaceholderText("Search standard rules by name, control, or category…"),
      "injection",
    );

    expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    expect(screen.queryByText("Broken Authentication")).not.toBeInTheDocument();
  });

  it("shows only failing rules when the Failing pill is clicked", async () => {
    const user = userEvent.setup();
    render(
      <StandardRulesCatalogView
        packs={[pack()]}
        findings={[finding("owasp.injection")]}
        selectedStandard="all"
        onSelectRuleInFindings={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Failing \(1\)/ }));

    expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    expect(screen.queryByText("Broken Authentication")).not.toBeInTheDocument();
  });

  it("shows only compliant rules when the Compliant pill is clicked", async () => {
    const user = userEvent.setup();
    render(
      <StandardRulesCatalogView
        packs={[pack()]}
        findings={[finding("owasp.injection")]}
        selectedStandard="all"
        onSelectRuleInFindings={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Compliant \(1\)/ }));

    expect(screen.getByText("Broken Authentication")).toBeInTheDocument();
    expect(screen.queryByText("SQL Injection")).not.toBeInTheDocument();
  });

  it("calls onSelectRuleInFindings with the rule id when triaging a failing rule", async () => {
    const user = userEvent.setup();
    const onSelectRuleInFindings = vi.fn();
    render(
      <StandardRulesCatalogView
        packs={[pack()]}
        findings={[finding("owasp.injection")]}
        selectedStandard="all"
        onSelectRuleInFindings={onSelectRuleInFindings}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Triage 1 Finding/ }));

    expect(onSelectRuleInFindings).toHaveBeenCalledWith("owasp.injection");
  });

  it("shows an empty state when no rule matches the current filters", async () => {
    const user = userEvent.setup();
    render(
      <StandardRulesCatalogView
        packs={[pack()]}
        findings={[]}
        selectedStandard="all"
        onSelectRuleInFindings={vi.fn()}
      />,
    );

    await user.type(
      screen.getByPlaceholderText("Search standard rules by name, control, or category…"),
      "nothing matches this",
    );

    expect(screen.getByText("No policy rules matched your criteria")).toBeInTheDocument();
  });
});
