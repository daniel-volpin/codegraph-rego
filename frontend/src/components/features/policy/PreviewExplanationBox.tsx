import Markdown from "react-markdown";

export interface PreviewExplanationBoxProps {
  heading: string;
  explanation: string;
}

/** Shown when a preview result has explanatory text but no diff to render. */
export const PreviewExplanationBox = ({ heading, explanation }: PreviewExplanationBoxProps) => (
  <div className="prose prose-xs max-w-none rounded-lg border border-emerald-200 bg-emerald-50/70 p-3.5 text-emerald-950 break-words dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-100">
    <p className="font-semibold text-emerald-900 dark:text-emerald-300">{heading}</p>
    <Markdown>{explanation}</Markdown>
  </div>
);

export default PreviewExplanationBox;
