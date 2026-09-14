import { render } from "@testing-library/react";
import { ArtifactSkeleton } from "./ArtifactSkeleton";

describe("ArtifactSkeleton", () => {
  it("renders three pulse bars by default, hidden from assistive tech", () => {
    const { container } = render(<ArtifactSkeleton />);

    const root = container.firstElementChild as HTMLElement;
    expect(root).toHaveAttribute("aria-hidden", "true");
    expect(root.children).toHaveLength(3);
  });

  it("renders the requested number of bars", () => {
    const { container } = render(<ArtifactSkeleton lines={5} />);

    expect(container.firstElementChild?.children).toHaveLength(5);
  });

  it("shortens only the last bar, so the skeleton doesn't read as a solid block", () => {
    const { container } = render(<ArtifactSkeleton lines={3} />);

    const bars = Array.from(container.firstElementChild?.children ?? []);
    expect(bars.slice(0, -1).every((bar) => bar.className.includes("w-full"))).toBe(true);
    expect(bars.at(-1)?.className).toContain("w-2/3");
  });
});
