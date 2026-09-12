const normalizePath = (value: string) => value.replace(/\\/g, "/");

export const relativeToUploadedWorkspace = (value: string) => {
  const normalized = normalizePath(value);
  const uploadedIndex = normalized.indexOf("/uploaded_code/");
  if (uploadedIndex >= 0) {
    return normalized
      .slice(uploadedIndex + "/uploaded_code/".length)
      .replace(/^(uploaded_code\/)+/, "");
  }
  return normalized.replace(/^(uploaded_code\/)+/, "");
};

export const deriveModuleLabel = (value: string) => {
  if (!value || value === "—") {
    return "workspace-root";
  }
  const normalized = normalizePath(value);
  const srcIndex = normalized.indexOf("/src/main/java");
  if (srcIndex >= 0) {
    const beforeSrc = normalized.slice(0, srcIndex);
    const parts = beforeSrc.split("/").filter(Boolean);
    return parts[parts.length - 1] || "workspace-root";
  }
  const relative = relativeToUploadedWorkspace(value);
  const parts = relative.split("/").filter(Boolean);
  return parts[0] || "workspace-root";
};

export const uniqueSortedModuleLabels = (values: string[]) =>
  Array.from(new Set(values.map((value) => deriveModuleLabel(value)).filter(Boolean))).sort((left, right) =>
    left.localeCompare(right),
  );
