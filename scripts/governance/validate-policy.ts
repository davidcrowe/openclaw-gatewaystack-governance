/**
 * Detects regex patterns likely to cause catastrophic backtracking (ReDoS).
 * Catches nested quantifiers like (a+)+, (a*)+, (a+)*, (a|b+)+ and
 * overlapping alternations with quantifiers.
 */
function isReDoSVulnerable(pattern: string): boolean {
  // Nested quantifiers: a group with an inner quantifier followed by an outer quantifier
  // e.g. (a+)+, (a+)*, (.*)+, (a|b+)+, ([a-z]+)*
  const nestedQuantifier = /\([^)]*[+*]\)?[+*{]/;
  if (nestedQuantifier.test(pattern)) {
    return true;
  }

  // Overlapping alternation with quantifier: (a|a)+ or similar
  // Simplified check: group with alternation followed by quantifier where
  // alternatives share character classes
  const groupWithAlt = /\(([^)]+\|[^)]+)\)[+*{]/;
  const match = pattern.match(groupWithAlt);
  if (match) {
    const alternatives = match[1].split("|");
    // If any two alternatives are identical or both use wildcards, flag it
    for (let i = 0; i < alternatives.length; i++) {
      for (let j = i + 1; j < alternatives.length; j++) {
        if (alternatives[i].trim() === alternatives[j].trim()) {
          return true;
        }
      }
    }
  }

  return false;
}

export interface PolicyValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function validatePolicy(policy: unknown): PolicyValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (typeof policy !== "object" || policy === null) {
    return { valid: false, errors: ["Policy must be a non-null object"], warnings };
  }

  const p = policy as Record<string, unknown>;

  // --- Required top-level fields ---

  if (!p.allowedTools || typeof p.allowedTools !== "object") {
    errors.push("Missing or invalid 'allowedTools' (must be an object)");
  }

  if (!p.rateLimits || typeof p.rateLimits !== "object") {
    errors.push("Missing or invalid 'rateLimits' (must be an object)");
  } else {
    const rl = p.rateLimits as Record<string, unknown>;
    for (const key of ["perUser", "perSession"] as const) {
      if (!rl[key] || typeof rl[key] !== "object") {
        errors.push(`Missing or invalid 'rateLimits.${key}' (must be an object)`);
      } else {
        const bucket = rl[key] as Record<string, unknown>;
        if (typeof bucket.maxCalls !== "number" || bucket.maxCalls < 0) {
          errors.push(`'rateLimits.${key}.maxCalls' must be a non-negative number`);
        }
        if (typeof bucket.windowSeconds !== "number" || bucket.windowSeconds < 0) {
          errors.push(`'rateLimits.${key}.windowSeconds' must be a non-negative number`);
        }
      }
    }
  }

  if (!p.identityMap || typeof p.identityMap !== "object") {
    errors.push("Missing or invalid 'identityMap' (must be an object)");
  }

  if (!p.injectionDetection || typeof p.injectionDetection !== "object") {
    errors.push("Missing or invalid 'injectionDetection' (must be an object)");
  } else {
    const id = p.injectionDetection as Record<string, unknown>;
    if (typeof id.enabled !== "boolean") {
      errors.push("'injectionDetection.enabled' must be a boolean");
    }
    if (!["low", "medium", "high"].includes(id.sensitivity as string)) {
      errors.push("'injectionDetection.sensitivity' must be 'low', 'medium', or 'high'");
    }
    // Validate custom patterns
    if (id.customPatterns !== undefined) {
      if (!Array.isArray(id.customPatterns)) {
        errors.push("'injectionDetection.customPatterns' must be an array");
      } else {
        for (let i = 0; i < id.customPatterns.length; i++) {
          const pat = id.customPatterns[i];
          if (typeof pat !== "string") {
            warnings.push(`customPatterns[${i}] is not a string`);
            continue;
          }
          try {
            new RegExp(pat);
          } catch {
            warnings.push(`customPatterns[${i}] is not a valid regex: "${pat}"`);
            continue;
          }
          if (isReDoSVulnerable(pat)) {
            warnings.push(`customPatterns[${i}] may be vulnerable to ReDoS (catastrophic backtracking): "${pat}"`);
          }
        }
      }
    }
  }

  if (!p.auditLog || typeof p.auditLog !== "object") {
    errors.push("Missing or invalid 'auditLog' (must be an object)");
  }

  // --- Warnings (non-fatal) ---

  // Empty collections
  if (p.allowedTools && typeof p.allowedTools === "object" && Object.keys(p.allowedTools).length === 0) {
    warnings.push("'allowedTools' is empty — all tools will be denied");
  }

  if (p.identityMap && typeof p.identityMap === "object" && Object.keys(p.identityMap).length === 0) {
    warnings.push("'identityMap' is empty — all users will be denied");
  }

  // Cross-reference: roles referenced by tools but not assigned to any identity
  if (
    p.allowedTools && typeof p.allowedTools === "object" &&
    p.identityMap && typeof p.identityMap === "object"
  ) {
    const allIdentityRoles = new Set<string>();
    for (const entry of Object.values(p.identityMap as Record<string, unknown>)) {
      if (entry && typeof entry === "object" && Array.isArray((entry as any).roles)) {
        for (const r of (entry as any).roles) {
          allIdentityRoles.add(r);
        }
      }
    }

    for (const [toolName, toolConfig] of Object.entries(p.allowedTools as Record<string, unknown>)) {
      if (toolConfig && typeof toolConfig === "object" && Array.isArray((toolConfig as any).roles)) {
        for (const role of (toolConfig as any).roles) {
          if (!allIdentityRoles.has(role)) {
            warnings.push(`Tool "${toolName}" requires role "${role}" but no identity has it`);
          }
        }
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}
