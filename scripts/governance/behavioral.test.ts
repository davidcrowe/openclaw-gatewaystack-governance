import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import type { Policy } from "./types.js";
import {
  buildBaseline,
  detectAnomalies,
  countCurrentWindowCalls,
  clearBaselineCache,
} from "./behavioral.js";
import { BEHAVIORAL_BASELINE_PATH, SKILL_DIR } from "./constants.js";

const TEST_AUDIT_PATH = path.join(SKILL_DIR, ".test-behavioral-audit.jsonl");

function makePolicy(overrides: Partial<NonNullable<Policy["behavioralMonitoring"]>> = {}): Policy {
  return {
    allowedTools: {},
    rateLimits: {
      perUser: { maxCalls: 100, windowSeconds: 3600 },
      perSession: { maxCalls: 30, windowSeconds: 300 },
    },
    identityMap: {},
    injectionDetection: { enabled: false, sensitivity: "medium" },
    auditLog: { path: TEST_AUDIT_PATH, maxFileSizeMB: 100 },
    behavioralMonitoring: {
      enabled: true,
      spikeThreshold: 3.0,
      monitoringWindowSeconds: 3600,
      action: "log",
      ...overrides,
    },
  };
}

function writeAuditEntries(entries: Array<{ tool: string; timestamp: string }>): void {
  const lines = entries.map((e) =>
    JSON.stringify({
      action: "tool-check",
      tool: e.tool,
      timestamp: e.timestamp,
      requestId: "test",
    })
  );
  fs.writeFileSync(TEST_AUDIT_PATH, lines.join("\n") + "\n");
}

function cleanup() {
  try { fs.unlinkSync(TEST_AUDIT_PATH); } catch {}
  try { fs.unlinkSync(BEHAVIORAL_BASELINE_PATH); } catch {}
  clearBaselineCache();
}

describe("buildBaseline", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("handles missing audit log gracefully", () => {
    const baseline = buildBaseline("/nonexistent/path.jsonl", 3600);
    expect(baseline.totalCalls).toBe(0);
    expect(baseline.toolsSeen).toEqual([]);
  });

  it("builds baseline from audit entries", () => {
    const now = Date.now();
    writeAuditEntries([
      { tool: "read", timestamp: new Date(now - 3000).toISOString() },
      { tool: "write", timestamp: new Date(now - 2000).toISOString() },
      { tool: "read", timestamp: new Date(now - 1000).toISOString() },
    ]);

    const baseline = buildBaseline(TEST_AUDIT_PATH, 3600);
    expect(baseline.totalCalls).toBe(3);
    expect(baseline.toolsSeen).toContain("read");
    expect(baseline.toolsSeen).toContain("write");
    expect(baseline.avgCallsPerWindow).toBeGreaterThan(0);
  });

  it("saves baseline to file", () => {
    writeAuditEntries([
      { tool: "read", timestamp: new Date().toISOString() },
    ]);

    buildBaseline(TEST_AUDIT_PATH, 3600);
    expect(fs.existsSync(BEHAVIORAL_BASELINE_PATH)).toBe(true);
  });
});

describe("detectAnomalies", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("returns empty when monitoring is disabled", () => {
    const policy = makePolicy({ enabled: false });
    const anomalies = detectAnomalies("read", 10, "agent-1", policy);
    expect(anomalies).toEqual([]);
  });

  it("flags unusual-pattern when no baseline exists", () => {
    const policy = makePolicy();
    const anomalies = detectAnomalies("read", 5, "agent-1", policy);
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe("unusual-pattern");
    expect(anomalies[0].severity).toBe("low");
  });

  it("flags new-tool when tool not in baseline", () => {
    // Create a baseline with only "read"
    const now = Date.now();
    writeAuditEntries([
      { tool: "read", timestamp: new Date(now - 1000).toISOString() },
    ]);
    buildBaseline(TEST_AUDIT_PATH, 3600);

    const policy = makePolicy();
    const anomalies = detectAnomalies("exec", 1, "agent-1", policy);
    const newToolAnomaly = anomalies.find((a) => a.type === "new-tool");
    expect(newToolAnomaly).toBeDefined();
    expect(newToolAnomaly!.severity).toBe("medium");
  });

  it("flags frequency-spike when rate exceeds threshold", () => {
    // Create baseline with avg 2 calls/window
    const now = Date.now();
    writeAuditEntries([
      { tool: "read", timestamp: new Date(now - 2000).toISOString() },
      { tool: "read", timestamp: new Date(now - 1000).toISOString() },
    ]);
    buildBaseline(TEST_AUDIT_PATH, 3600);

    const policy = makePolicy({ spikeThreshold: 2.0 });
    // 10 calls > 2 * 2.0 = 4 threshold
    const anomalies = detectAnomalies("read", 10, "agent-1", policy);
    const spike = anomalies.find((a) => a.type === "frequency-spike");
    expect(spike).toBeDefined();
    expect(spike!.severity).toBe("high");
  });

  it("does not flag when within threshold", () => {
    const now = Date.now();
    writeAuditEntries([
      { tool: "read", timestamp: new Date(now - 2000).toISOString() },
      { tool: "read", timestamp: new Date(now - 1000).toISOString() },
    ]);
    buildBaseline(TEST_AUDIT_PATH, 3600);

    const policy = makePolicy({ spikeThreshold: 3.0 });
    // 3 calls < 2 * 3.0 = 6 threshold
    const anomalies = detectAnomalies("read", 3, "agent-1", policy);
    const spike = anomalies.find((a) => a.type === "frequency-spike");
    expect(spike).toBeUndefined();
  });
});

describe("countCurrentWindowCalls", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("counts calls within the window", () => {
    const now = Date.now();
    writeAuditEntries([
      { tool: "read", timestamp: new Date(now - 500).toISOString() },
      { tool: "read", timestamp: new Date(now - 1000).toISOString() },
      { tool: "read", timestamp: new Date(now - 7200_000).toISOString() }, // outside window
    ]);

    const count = countCurrentWindowCalls(TEST_AUDIT_PATH, 3600);
    expect(count).toBe(2);
  });

  it("returns 0 for missing file", () => {
    const count = countCurrentWindowCalls("/nonexistent.jsonl", 3600);
    expect(count).toBe(0);
  });
});
