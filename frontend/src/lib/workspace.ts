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
    return "unknown-module";
  }
  const relative = relativeToUploadedWorkspace(value);
  const srcIndex = relative.indexOf("/src/main/java");
  if (srcIndex < 0) {
    return relative || "workspace-root";
  }
  const modulePath = relative.slice(0, srcIndex).replace(/^\/+|\/+$/g, "");
  return modulePath || "workspace-root";
};

export const uniqueSortedModuleLabels = (values: string[]) =>
  Array.from(new Set(values.map((value) => deriveModuleLabel(value)).filter(Boolean))).sort((left, right) =>
    left.localeCompare(right),
  );
