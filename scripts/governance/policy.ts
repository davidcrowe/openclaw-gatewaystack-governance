import * as fs from "fs";
import type { Policy } from "./types.js";
import { DEFAULT_POLICY_PATH } from "./constants.js";
import { validatePolicy } from "./validate-policy.js";

export function loadPolicy(policyPath?: string): Policy {
  const resolvedPath = policyPath || DEFAULT_POLICY_PATH;
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(
      `Governance policy not found at ${resolvedPath}. Run: cp policy.example.json policy.json`
    );
  }
  const raw = JSON.parse(fs.readFileSync(resolvedPath, "utf-8"));

  const validation = validatePolicy(raw);
  if (!validation.valid) {
    throw new Error(
      `Invalid policy at ${resolvedPath}: ${validation.errors.join("; ")}`
    );
  }
  if (validation.warnings.length > 0) {
    for (const w of validation.warnings) {
      process.stderr.write(`[governance] policy warning: ${w}\n`);
    }
  }

  return raw;
}
