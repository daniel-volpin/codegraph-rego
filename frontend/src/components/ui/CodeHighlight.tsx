import { useEffect, useRef } from "react";
import Prism from "prismjs";
import "prismjs/components/prism-java";
import "prismjs/components/prism-json";
import "prismjs/themes/prism-tomorrow.css";

interface CodeHighlightProps {
  code: string;
  language?: "java" | "json" | "text";
  className?: string;
}

const CodeHighlight = ({
  code,
  language = "text",
  className,
}: CodeHighlightProps) => {
  const ref = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (ref.current) {
      Prism.highlightElement(ref.current);
    }
  }, [code, language]);

  const lang = language === "text" ? "" : language;

  return (
    <pre className={`code-highlight ${className ?? ""}`}>
      <code ref={ref} className={`language-${lang || "none"}`}>
        {code}
      </code>
    </pre>
  );
};

export default CodeHighlight;
