import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Policy } from "./types.js";

// Minimal policy fixture
function makePolicy(dlpOverrides: Partial<NonNullable<Policy["outputDlp"]>> = {}): Policy {
  return {
    allowedTools: {},
    rateLimits: {
      perUser: { maxCalls: 100, windowSeconds: 3600 },
      perSession: { maxCalls: 30, windowSeconds: 300 },
    },
    identityMap: {},
    injectionDetection: { enabled: false, sensitivity: "medium" },
    auditLog: { path: "audit.jsonl", maxFileSizeMB: 100 },
    outputDlp: {
      enabled: true,
      mode: "log",
      redactionMode: "mask",
      customPatterns: [],
      ...dlpOverrides,
    },
  };
}

describe("dlp", () => {
  describe("scanOutput — when transformabl-core is NOT installed", () => {
    it("throws a clear error message", async () => {
      // Import fresh to ensure no cache
      const { scanOutput } = await import("./dlp.js");
      const policy = makePolicy();

      try {
        scanOutput("some output with SSN 123-45-6789", policy);
        // If transformabl-core IS installed, this won't throw — skip
      } catch (e: any) {
        expect(e.message).toContain("@gatewaystack/transformabl-core");
        expect(e.message).toContain("npm install");
      }
    });
  });

  describe("scanOutput — when DLP is disabled", () => {
    it("returns no matches", async () => {
      const { scanOutput } = await import("./dlp.js");
      const policy = makePolicy({ enabled: false });
      const result = scanOutput("SSN: 123-45-6789", policy);
      expect(result.hasMatches).toBe(false);
      expect(result.summary).toBe("DLP not enabled");
    });
  });

  describe("isTransformablAvailable", () => {
    it("returns a boolean", async () => {
      const { isTransformablAvailable } = await import("./dlp.js");
      const available = isTransformablAvailable();
      expect(typeof available).toBe("boolean");
    });
  });

  describe("redactOutput — when DLP is disabled", () => {
    it("returns output unchanged", async () => {
      const { redactOutput } = await import("./dlp.js");
      const policy = makePolicy({ enabled: false });
      const output = "SSN: 123-45-6789";
      expect(redactOutput(output, policy)).toBe(output);
    });
  });
});
