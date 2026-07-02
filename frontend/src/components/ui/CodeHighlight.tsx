import { cn } from "../../lib/utils";
import { PrismLight as SyntaxHighlighter } from "react-syntax-highlighter";
import java from "react-syntax-highlighter/dist/esm/languages/prism/java";
import json from "react-syntax-highlighter/dist/esm/languages/prism/json";
import { oneLight } from "react-syntax-highlighter/dist/esm/styles/prism";

// Only register the grammars we actually render. The default `Prism` entry
// pulls every language Prism supports (~hundreds of kB pre-gzip).
SyntaxHighlighter.registerLanguage("java", java);
SyntaxHighlighter.registerLanguage("json", json);

const accessibleOneLight = {
  ...oneLight,
  comment: { ...oneLight.comment, color: "#475569" },
  prolog: { ...oneLight.prolog, color: "#475569" },
  cdata: { ...oneLight.cdata, color: "#475569" },
  "attr-name": { ...oneLight["attr-name"], color: "#92400e" },
  "class-name": { ...oneLight["class-name"], color: "#92400e" },
  boolean: { ...oneLight.boolean, color: "#92400e" },
  constant: { ...oneLight.constant, color: "#92400e" },
  number: { ...oneLight.number, color: "#92400e" },
  atrule: { ...oneLight.atrule, color: "#92400e" },
  selector: { ...oneLight.selector, color: "#166534" },
  string: { ...oneLight.string, color: "#166534" },
  char: { ...oneLight.char, color: "#166534" },
  builtin: { ...oneLight.builtin, color: "#166534" },
  inserted: { ...oneLight.inserted, color: "#166534" },
  regex: { ...oneLight.regex, color: "#166534" },
  "attr-value": { ...oneLight["attr-value"], color: "#166534" },
  "attr-value > .token.punctuation": {
    ...oneLight["attr-value > .token.punctuation"],
    color: "#166534",
  },
  variable: { ...oneLight.variable, color: "#1d4ed8" },
  operator: { ...oneLight.operator, color: "#1d4ed8" },
  function: { ...oneLight.function, color: "#1d4ed8" },
} satisfies typeof oneLight;

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
        style={accessibleOneLight}
        wrapLongLines={wrapLongLines}
        showLineNumbers
        tabIndex={0}
        aria-label={`${language} code snippet`}
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
          color: "#475569",
          userSelect: "none",
        }}
      >
        {code || "// snippet unavailable"}
      </SyntaxHighlighter>
    </div>
  );
};

export default CodeHighlight;
