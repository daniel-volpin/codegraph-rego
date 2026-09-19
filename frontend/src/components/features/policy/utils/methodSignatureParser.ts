import { relativeToUploadedWorkspace } from "../../../../lib/workspace";

export interface ParsedMethodInfo {
  raw: string;
  className: string;
  methodName: string;
  shortSignature: string;
  compactSignature: string;
  paramTypes: string[];
  filePath?: string;
  packageName?: string;
}

export const formatCitationDisplay = (citation: string) => {
  const trimmed = citation.trim();
  if (!trimmed) return { display: citation, full: citation };
  const match = trimmed.match(/^(.*?)(:\d+(?:-\d+)?)$/);
  const rawPath = match?.[1] ?? trimmed;
  const suffix = match?.[2] ?? "";
  const normalizedPath = rawPath.replace(/\\/g, "/");
  let displayPath = normalizedPath;
  const srcIndex = normalizedPath.indexOf("/src/");
  if (normalizedPath.includes("/uploaded_code/") || normalizedPath.startsWith("uploaded_code/")) {
    displayPath = relativeToUploadedWorkspace(normalizedPath);
  } else if (srcIndex >= 0) {
    displayPath = normalizedPath.slice(srcIndex + 1);
  } else {
    const parts = normalizedPath.split("/").filter(Boolean);
    if (parts.length > 4) displayPath = parts.slice(-4).join("/");
  }
  return { display: `${displayPath}${suffix}`, full: trimmed };
};

export const parseMethodKey = (raw: string): ParsedMethodInfo => {
  if (!raw || typeof raw !== "string" || !raw.trim() || raw === "—") {
    return {
      raw: raw || "",
      className: "—",
      methodName: "—",
      shortSignature: raw || "—",
      compactSignature: raw || "—",
      paramTypes: [],
    };
  }

  const trimmed = raw.trim();

  // Handle AST Node Keys with #type: / #method: / #file:
  if (trimmed.includes("#method:") || trimmed.includes("#type:")) {
    let typeName = "";
    const typeMatch = trimmed.match(/#type:([^#]+)/);
    if (typeMatch) {
      typeName = typeMatch[1];
    }

    let methodName = "";
    let paramsStr = "";
    const methodMatch = trimmed.match(/#method:([^#/]+)(?:\/(\d+)\/([^#]*))?/);
    if (methodMatch) {
      methodName = methodMatch[1];
      paramsStr = methodMatch[3] || "";
    } else {
      const fallbackMethod = trimmed.match(/#method:([^#]+)/);
      if (fallbackMethod) {
        const parts = fallbackMethod[1].split("/");
        methodName = parts[0] || "method";
        paramsStr = parts[2] || "";
      }
    }

    let filePath: string | undefined;
    const fileMatch = trimmed.match(/#file:([^#]+)/);
    if (fileMatch) {
      filePath = formatCitationDisplay(fileMatch[1]).display;
    } else {
      const colonIndex = trimmed.indexOf(":");
      const hashIndex = trimmed.indexOf("#");
      if (colonIndex >= 0 && hashIndex > colonIndex) {
        filePath = formatCitationDisplay(trimmed.slice(colonIndex + 1, hashIndex)).display;
      }
    }

    const typeSegments = typeName.split(".").filter(Boolean);
    const className = typeSegments.length > 0 ? typeSegments[typeSegments.length - 1] : "Class";
    const packageName = typeSegments.length > 1 ? typeSegments.slice(0, -1).join(".") : undefined;

    const rawParams = paramsStr ? paramsStr.split(",").map((p) => p.trim()).filter(Boolean) : [];
    const paramTypes = rawParams.map((p) => {
      const segs = p.split(".").filter(Boolean);
      return segs.length > 0 ? segs[segs.length - 1] : p;
    });

    const cleanMethodName = methodName || "method";
    const shortSignature = `${className}.${cleanMethodName}(${paramTypes.join(", ")})`;
    const compactSignature = `${className}.${cleanMethodName}(${paramTypes.length > 0 ? "…" : ""})`;

    return {
      raw: trimmed,
      className,
      methodName: cleanMethodName,
      shortSignature,
      compactSignature,
      paramTypes,
      filePath,
      packageName,
    };
  }

  // Handle standard Java method signature: pkg.Class.method(params)
  const openParen = trimmed.indexOf("(");
  const closeParen = trimmed.lastIndexOf(")");
  const methodPrefix = openParen >= 0 ? trimmed.slice(0, openParen) : trimmed;
  const paramBlock = openParen >= 0 && closeParen > openParen ? trimmed.slice(openParen + 1, closeParen) : "";

  const prefixParts = methodPrefix.split(".").filter(Boolean);
  let className = "Class";
  let methodName = methodPrefix;
  let packageName: string | undefined;

  if (prefixParts.length >= 2) {
    methodName = prefixParts[prefixParts.length - 1];
    className = prefixParts[prefixParts.length - 2];
    if (prefixParts.length > 2) {
      packageName = prefixParts.slice(0, -2).join(".");
    }
  } else if (prefixParts.length === 1) {
    methodName = prefixParts[0];
  }

  const rawParams = paramBlock ? paramBlock.split(",").map((p) => p.trim()).filter(Boolean) : [];
  const paramTypes = rawParams.map((p) => {
    const base = p.replace(/<.*>/, "");
    const segs = base.split(".").filter(Boolean);
    return segs.length > 0 ? segs[segs.length - 1] : p;
  });

  const shortSignature = `${className !== "Class" ? className + "." : ""}${methodName}(${paramTypes.join(", ")})`;
  const compactSignature = `${className !== "Class" ? className + "." : ""}${methodName}(${paramTypes.length > 0 ? "…" : ""})`;

  return {
    raw: trimmed,
    className,
    methodName,
    shortSignature,
    compactSignature,
    paramTypes,
    packageName,
  };
};

export const compactTargetMethod = (value: string) => {
  if (!value || value === "—") return value;
  const parsed = parseMethodKey(value);
  return parsed.shortSignature;
};
