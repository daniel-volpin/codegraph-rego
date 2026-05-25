import { cn } from "../../lib/utils";
import { PrismLight as SyntaxHighlighter } from "react-syntax-highlighter";
import java from "react-syntax-highlighter/dist/esm/languages/prism/java";
import json from "react-syntax-highlighter/dist/esm/languages/prism/json";
import { oneLight } from "react-syntax-highlighter/dist/esm/styles/prism";

// Only register the grammars we actually render. The default `Prism` entry
// pulls every language Prism supports (~hundreds of kB pre-gzip).
SyntaxHighlighter.registerLanguage("java", java);
SyntaxHighlighter.registerLanguage("json", json);

interface CodeHighlightProps {
  code: string;
  language?: "java" | "json" | "text";
  className?: string;
  wrapLongLines?: boolean;
  maxHeight?: number;
}

const CodeHighlight = ({
  code,
  language = "text",
  className,
  wrapLongLines = false,
  maxHeight,
}: CodeHighlightProps) => {
  const normalizedLanguage = language === "text" ? "plaintext" : language;
  const maxHeightClass =
    maxHeight == null
      ? undefined
      : maxHeight <= 320
        ? "max-h-80"
        : maxHeight <= 460
          ? "max-h-[460px]"
          : "max-h-[640px]";

  return (
    <div
      className={cn("overflow-auto rounded-lg border border-slate-200 bg-slate-50", maxHeightClass, className)}
    >
      <SyntaxHighlighter
        language={normalizedLanguage}
        style={oneLight}
        wrapLongLines={wrapLongLines}
        showLineNumbers
        customStyle={{
          margin: 0,
          background: "transparent",
          padding: "0.625rem 0.75rem",
          fontSize: "12px",
          lineHeight: "1.4",
          minWidth: "100%",
        }}
        codeTagProps={{
          style: {
            fontFamily:
              "'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
          },
        }}
        lineNumberStyle={{
          minWidth: "2.25em",
          paddingRight: "0.75em",
          color: "#94a3b8",
          userSelect: "none",
        }}
      >
        {code || "// snippet unavailable"}
      </SyntaxHighlighter>
    </div>
  );
};

export default CodeHighlight;
