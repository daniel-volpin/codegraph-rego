import type { Violation } from "../schemas";
import { DEMO_ISO_VIOLATIONS } from "./violationsIso";
import { DEMO_OTHER_STANDARDS_VIOLATIONS } from "./violationsStandards";

export const DEMO_VIOLATIONS: Violation[] = [
  ...DEMO_ISO_VIOLATIONS,
  ...DEMO_OTHER_STANDARDS_VIOLATIONS,
];
