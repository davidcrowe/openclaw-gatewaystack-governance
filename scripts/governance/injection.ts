import type { Policy } from "./types.js";
import {
  INJECTION_PATTERNS_HIGH,
  INJECTION_PATTERNS_MEDIUM,
  INJECTION_PATTERNS_LOW,
} from "./constants.js";

export function detectInjection(
  args: string,
  policy: Policy
): { clean: boolean; detail: string; matches: string[] } {
  if (!policy.injectionDetection.enabled) {
    return { clean: true, detail: "Injection detection disabled", matches: [] };
  }

  const sensitivity = policy.injectionDetection.sensitivity;
  const matches: string[] = [];

  // Always check high-severity patterns
  for (const pattern of INJECTION_PATTERNS_HIGH) {
    const match = args.match(pattern);
    if (match) {
      matches.push(`HIGH: ${pattern.source} → "${match[0]}"`);
    }
  }

  // Medium and high sensitivity
  if (sensitivity === "medium" || sensitivity === "high") {
    for (const pattern of INJECTION_PATTERNS_MEDIUM) {
      const match = args.match(pattern);
      if (match) {
        matches.push(`MEDIUM: ${pattern.source} → "${match[0]}"`);
      }
    }
  }

  // High sensitivity only
  if (sensitivity === "high") {
    for (const pattern of INJECTION_PATTERNS_LOW) {
      const match = args.match(pattern);
      if (match) {
        matches.push(`LOW: ${pattern.source} → "${match[0]}"`);
      }
    }
  }

  // Custom patterns from policy — guarded with per-pattern timeout
  if (policy.injectionDetection.customPatterns) {
    for (const patternStr of policy.injectionDetection.customPatterns) {
      try {
        const pattern = new RegExp(patternStr, "i");
        const start = Date.now();
        const match = args.match(pattern);
        const elapsed = Date.now() - start;
        if (elapsed > 50) {
          // Pattern took too long — likely ReDoS, skip and log
          matches.push(`CUSTOM: ${patternStr} — skipped (${elapsed}ms, possible ReDoS)`);
          continue;
        }
        if (match) {
          matches.push(`CUSTOM: ${patternStr} → "${match[0]}"`);
        }
      } catch {
        // Skip invalid regex
      }
    }
  }

  if (matches.length > 0) {
    return {
      clean: false,
      detail: `Detected ${matches.length} potential injection pattern(s)`,
      matches,
    };
  }

  return { clean: true, detail: "No injection patterns detected", matches: [] };
}
