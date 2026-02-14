import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

interface CodeHighlightProps {
  code: string;
  language?: "java" | "json" | "text";
  className?: string;
}

const CodeHighlight = ({ code, language = "text", className }: CodeHighlightProps) => {
  return (
    <div className={className}>
      <SyntaxHighlighter
        language={language === "text" ? "java" : language}
        style={oneDark}
        showLineNumbers
        customStyle={{ margin: 0, borderRadius: 8 }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
};

export default CodeHighlight;
