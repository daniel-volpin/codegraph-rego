export interface ArtifactSkeletonProps {
  lines?: number;
}

export const ArtifactSkeleton = ({ lines = 3 }: ArtifactSkeletonProps) => (
  <div className="space-y-2 py-1" aria-hidden="true">
    {Array.from({ length: lines }).map((_, index) => (
      <div
        key={index}
        className={`h-3 animate-pulse rounded bg-slate-200/80 dark:bg-zinc-800 ${
          index === lines - 1 ? "w-2/3" : "w-full"
        }`}
      />
    ))}
  </div>
);

export default ArtifactSkeleton;
