import { describe, it, expect } from "vitest";
import { validatePolicy } from "./validate-policy.js";

const validPolicy = {
  allowedTools: {
    read: { roles: ["default", "admin"], maxArgsLength: 5000 },
  },
  rateLimits: {
    perUser: { maxCalls: 100, windowSeconds: 3600 },
    perSession: { maxCalls: 30, windowSeconds: 300 },
  },
  identityMap: {
    main: { userId: "agent-main", roles: ["admin"] },
    ops: { userId: "agent-ops", roles: ["default"] },
  },
  injectionDetection: {
    enabled: true,
    sensitivity: "medium" as const,
    customPatterns: [],
  },
  auditLog: {
    path: "audit.jsonl",
    maxFileSizeMB: 100,
  },
};

describe("validatePolicy", () => {
  it("accepts a valid policy", () => {
    const result = validatePolicy(validPolicy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects null", () => {
    const result = validatePolicy(null);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Policy must be a non-null object");
  });

  it("rejects non-object", () => {
    const result = validatePolicy("not an object");
    expect(result.valid).toBe(false);
  });

  describe("missing required fields", () => {
    const requiredFields = [
      "allowedTools",
      "rateLimits",
      "identityMap",
      "injectionDetection",
      "auditLog",
    ];

    it.each(requiredFields)("errors when '%s' is missing", (field) => {
      const policy = { ...validPolicy, [field]: undefined };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes(field))).toBe(true);
    });
  });

  describe("rateLimits validation", () => {
    it("errors on negative maxCalls", () => {
      const policy = {
        ...validPolicy,
        rateLimits: {
          perUser: { maxCalls: -1, windowSeconds: 3600 },
          perSession: { maxCalls: 30, windowSeconds: 300 },
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("maxCalls"))).toBe(true);
    });

    it("errors on negative windowSeconds", () => {
      const policy = {
        ...validPolicy,
        rateLimits: {
          perUser: { maxCalls: 100, windowSeconds: -1 },
          perSession: { maxCalls: 30, windowSeconds: 300 },
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("windowSeconds"))).toBe(true);
    });
  });

  describe("injectionDetection validation", () => {
    it("errors on invalid sensitivity", () => {
      const policy = {
        ...validPolicy,
        injectionDetection: { enabled: true, sensitivity: "extreme" },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("sensitivity"))).toBe(true);
    });

    it("errors on non-boolean enabled", () => {
      const policy = {
        ...validPolicy,
        injectionDetection: { enabled: "yes", sensitivity: "medium" },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("enabled"))).toBe(true);
    });
  });

  describe("warnings", () => {
    it("warns on empty allowedTools", () => {
      const policy = { ...validPolicy, allowedTools: {} };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes("allowedTools") && w.includes("empty"))).toBe(true);
    });

    it("warns on empty identityMap", () => {
      const policy = { ...validPolicy, identityMap: {} };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(true);
      expect(result.warnings.some((w) => w.includes("identityMap") && w.includes("empty"))).toBe(true);
    });

    it("warns when a tool requires a role that no identity has", () => {
      const policy = {
        ...validPolicy,
        allowedTools: { deploy: { roles: ["superadmin"] } },
        identityMap: { main: { userId: "agent-main", roles: ["admin"] } },
      };
      const result = validatePolicy(policy);
      expect(result.warnings.some((w) => w.includes("superadmin") && w.includes("no identity"))).toBe(true);
    });

    it("no warning when all tool roles exist in identity map", () => {
      const result = validatePolicy(validPolicy);
      const roleWarnings = result.warnings.filter((w) => w.includes("no identity"));
      expect(roleWarnings).toHaveLength(0);
    });

    it("warns on invalid custom regex", () => {
      const policy = {
        ...validPolicy,
        injectionDetection: {
          enabled: true,
          sensitivity: "medium" as const,
          customPatterns: ["[invalid("],
        },
      };
      const result = validatePolicy(policy);
      expect(result.warnings.some((w) => w.includes("not a valid regex"))).toBe(true);
    });

    it("warns on ReDoS-vulnerable custom pattern", () => {
      const policy = {
        ...validPolicy,
        injectionDetection: {
          enabled: true,
          sensitivity: "medium" as const,
          customPatterns: ["(a+)+b"],
        },
      };
      const result = validatePolicy(policy);
      expect(result.warnings.some((w) => w.includes("ReDoS"))).toBe(true);
    });

    it("does not warn on safe custom patterns", () => {
      const policy = {
        ...validPolicy,
        injectionDetection: {
          enabled: true,
          sensitivity: "medium" as const,
          customPatterns: ["secret_key\\s*=", "password:\\s+\\S+"],
        },
      };
      const result = validatePolicy(policy);
      const redosWarnings = result.warnings.filter((w) => w.includes("ReDoS"));
      expect(redosWarnings).toHaveLength(0);
    });
  });

  // --- outputDlp validation ---

  describe("outputDlp validation", () => {
    it("accepts a valid outputDlp config", () => {
      const policy = {
        ...validPolicy,
        outputDlp: { enabled: false, mode: "log", redactionMode: "mask", customPatterns: [] },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(true);
    });

    it("accepts policy without outputDlp (optional)", () => {
      const result = validatePolicy(validPolicy);
      expect(result.valid).toBe(true);
    });

    it("errors when outputDlp is not an object", () => {
      const policy = { ...validPolicy, outputDlp: "enabled" };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("outputDlp"))).toBe(true);
    });

    it("errors on non-boolean enabled", () => {
      const policy = {
        ...validPolicy,
        outputDlp: { enabled: "yes", mode: "log", redactionMode: "mask" },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("outputDlp.enabled"))).toBe(true);
    });

    it("errors on invalid mode", () => {
      const policy = {
        ...validPolicy,
        outputDlp: { enabled: false, mode: "warn", redactionMode: "mask" },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("outputDlp.mode"))).toBe(true);
    });

    it("errors on invalid redactionMode", () => {
      const policy = {
        ...validPolicy,
        outputDlp: { enabled: false, mode: "log", redactionMode: "hash" },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("outputDlp.redactionMode"))).toBe(true);
    });

    it("errors when customPatterns is not an array", () => {
      const policy = {
        ...validPolicy,
        outputDlp: { enabled: false, mode: "log", redactionMode: "mask", customPatterns: "SSN" },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("outputDlp.customPatterns"))).toBe(true);
    });

    it("errors when customPatterns contains non-string", () => {
      const policy = {
        ...validPolicy,
        outputDlp: { enabled: false, mode: "log", redactionMode: "mask", customPatterns: [123] },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("outputDlp.customPatterns[0]"))).toBe(true);
    });
  });

  // --- escalation validation ---

  describe("escalation validation", () => {
    it("accepts a valid escalation config", () => {
      const policy = {
        ...validPolicy,
        escalation: {
          enabled: false,
          reviewOnMediumInjection: true,
          reviewOnFirstToolUse: false,
          tokenTTLSeconds: 300,
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(true);
    });

    it("accepts policy without escalation (optional)", () => {
      const result = validatePolicy(validPolicy);
      expect(result.valid).toBe(true);
    });

    it("errors when escalation is not an object", () => {
      const policy = { ...validPolicy, escalation: true };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("escalation"))).toBe(true);
    });

    it("errors on non-boolean enabled", () => {
      const policy = {
        ...validPolicy,
        escalation: {
          enabled: "yes",
          reviewOnMediumInjection: true,
          reviewOnFirstToolUse: false,
          tokenTTLSeconds: 300,
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("escalation.enabled"))).toBe(true);
    });

    it("errors on non-boolean reviewOnMediumInjection", () => {
      const policy = {
        ...validPolicy,
        escalation: {
          enabled: false,
          reviewOnMediumInjection: "yes",
          reviewOnFirstToolUse: false,
          tokenTTLSeconds: 300,
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("reviewOnMediumInjection"))).toBe(true);
    });

    it("errors on non-boolean reviewOnFirstToolUse", () => {
      const policy = {
        ...validPolicy,
        escalation: {
          enabled: false,
          reviewOnMediumInjection: true,
          reviewOnFirstToolUse: 1,
          tokenTTLSeconds: 300,
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("reviewOnFirstToolUse"))).toBe(true);
    });

    it("errors on negative tokenTTLSeconds", () => {
      const policy = {
        ...validPolicy,
        escalation: {
          enabled: false,
          reviewOnMediumInjection: true,
          reviewOnFirstToolUse: false,
          tokenTTLSeconds: -10,
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("tokenTTLSeconds"))).toBe(true);
    });

    it("errors on non-number tokenTTLSeconds", () => {
      const policy = {
        ...validPolicy,
        escalation: {
          enabled: false,
          reviewOnMediumInjection: true,
          reviewOnFirstToolUse: false,
          tokenTTLSeconds: "300",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("tokenTTLSeconds"))).toBe(true);
    });
  });

  // --- behavioralMonitoring validation ---

  describe("behavioralMonitoring validation", () => {
    it("accepts a valid behavioralMonitoring config", () => {
      const policy = {
        ...validPolicy,
        behavioralMonitoring: {
          enabled: false,
          spikeThreshold: 3.0,
          monitoringWindowSeconds: 3600,
          action: "log",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(true);
    });

    it("accepts policy without behavioralMonitoring (optional)", () => {
      const result = validatePolicy(validPolicy);
      expect(result.valid).toBe(true);
    });

    it("errors when behavioralMonitoring is not an object", () => {
      const policy = { ...validPolicy, behavioralMonitoring: "on" };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("behavioralMonitoring"))).toBe(true);
    });

    it("errors on non-boolean enabled", () => {
      const policy = {
        ...validPolicy,
        behavioralMonitoring: {
          enabled: 1,
          spikeThreshold: 3.0,
          monitoringWindowSeconds: 3600,
          action: "log",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("behavioralMonitoring.enabled"))).toBe(true);
    });

    it("errors on zero spikeThreshold", () => {
      const policy = {
        ...validPolicy,
        behavioralMonitoring: {
          enabled: false,
          spikeThreshold: 0,
          monitoringWindowSeconds: 3600,
          action: "log",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("spikeThreshold"))).toBe(true);
    });

    it("errors on negative spikeThreshold", () => {
      const policy = {
        ...validPolicy,
        behavioralMonitoring: {
          enabled: false,
          spikeThreshold: -1,
          monitoringWindowSeconds: 3600,
          action: "log",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("spikeThreshold"))).toBe(true);
    });

    it("errors on negative monitoringWindowSeconds", () => {
      const policy = {
        ...validPolicy,
        behavioralMonitoring: {
          enabled: false,
          spikeThreshold: 3.0,
          monitoringWindowSeconds: -1,
          action: "log",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("monitoringWindowSeconds"))).toBe(true);
    });

    it("errors on invalid action", () => {
      const policy = {
        ...validPolicy,
        behavioralMonitoring: {
          enabled: false,
          spikeThreshold: 3.0,
          monitoringWindowSeconds: 3600,
          action: "warn",
        },
      };
      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("behavioralMonitoring.action"))).toBe(true);
    });

    it("accepts all valid action values", () => {
      for (const action of ["log", "review", "block"]) {
        const policy = {
          ...validPolicy,
          behavioralMonitoring: {
            enabled: false,
            spikeThreshold: 3.0,
            monitoringWindowSeconds: 3600,
            action,
          },
        };
        const result = validatePolicy(policy);
        expect(result.valid).toBe(true);
      }
    });
  });
});
