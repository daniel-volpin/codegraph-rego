import { render, screen } from "@testing-library/react";
import CodeHighlight from "./CodeHighlight";

describe("CodeHighlight", () => {
  it("keeps scrollable code snippets keyboard-focusable", () => {
    render(<CodeHighlight code='MessageDigest.getInstance("MD5")' language="java" />);

    expect(screen.getByLabelText(/java code snippet/i)).toHaveAttribute("tabindex", "0");
  });
});
