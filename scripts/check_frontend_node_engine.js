#!/usr/bin/env node
"use strict";

// `make dev` starts the backend and frontend as a pair; if the frontend's
// yarn engine check fails after the backend has already started (loading
// FAISS/embeddings can take 15-20s), the dev target's shared trap tears the
// still-healthy backend down too. Failing fast here, before either process
// starts, avoids that wasted startup and gives a clearer remediation hint
// than yarn's own engine error.

const path = require("node:path");

const packageJsonPath = path.resolve(__dirname, "..", "frontend", "package.json");
const pkg = require(packageJsonPath);
const range = (pkg.engines && pkg.engines.node) || "";

function toParts(version) {
  return version
    .replace(/^v/, "")
    .split(".")
    .map(Number);
}

function compare(a, b) {
  for (let i = 0; i < 3; i += 1) {
    const diff = (a[i] || 0) - (b[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function satisfiesClause(actual, clause) {
  const match = clause.match(/^(>=|<=|>|<|=)?(.+)$/);
  const operator = match[1] || "=";
  const target = toParts(match[2]);
  const diff = compare(actual, target);
  switch (operator) {
    case ">=":
      return diff >= 0;
    case "<=":
      return diff <= 0;
    case ">":
      return diff > 0;
    case "<":
      return diff < 0;
    default:
      return diff === 0;
  }
}

const actual = toParts(process.version);
const clauses = range.split(/\s+/).filter(Boolean);
const satisfied = clauses.length === 0 || clauses.every((clause) => satisfiesClause(actual, clause));

if (!satisfied) {
  console.error(
    `Frontend requires Node ${range}, but PATH resolves to ${process.version} (${process.execPath}).`,
  );
  console.error(
    'If you use nvm, run "nvm use" (or install a matching version) before "make dev" so the ' +
      "frontend dev server does not fail its engine check after the backend has already started.",
  );
  process.exit(1);
}
