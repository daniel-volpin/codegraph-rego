import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

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
  return (
    <div className={className}>
      <SyntaxHighlighter
        language={language === "text" ? "java" : language}
        style={oneDark}
        showLineNumbers
        wrapLongLines={wrapLongLines}
        customStyle={{
          margin: 0,
          borderRadius: 8,
          ...(maxHeight != null ? { maxHeight, overflow: "auto" } : {}),
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
};

export default CodeHighlight;
