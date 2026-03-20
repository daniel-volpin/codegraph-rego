import { cn } from "../../lib/utils";

interface CodeHighlightProps {
  code: string;
  language?: "java" | "json" | "text";
  className?: string;
  wrapLongLines?: boolean;
  maxHeight?: number;
}

const CodeHighlight = ({
  code,
  className,
  wrapLongLines = false,
  maxHeight,
}: CodeHighlightProps) => {
  const lines = code.split("\n");

  return (
    <div
      className={cn("overflow-hidden rounded-lg border border-slate-800 bg-slate-950 text-slate-100", className)}
      style={maxHeight != null ? { maxHeight } : undefined}
    >
      <pre
        className={cn(
          "m-0 overflow-auto p-4 font-mono text-xs leading-6",
          wrapLongLines ? "whitespace-pre-wrap break-words" : "whitespace-pre"
        )}
      >
        {lines.map((line, index) => (
          <div key={`${index + 1}:${line}`} className="grid grid-cols-[auto,1fr] gap-4">
            <span className="select-none text-right text-slate-500">{index + 1}</span>
            <code>{line || " "}</code>
          </div>
        ))}
      </pre>
    </div>
  );
};

export default CodeHighlight;
