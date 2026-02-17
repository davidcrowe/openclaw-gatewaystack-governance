import * as fs from "fs";
import type { Policy } from "./types.js";
import { BEHAVIORAL_BASELINE_PATH } from "./constants.js";

// ---------------------------------------------------------------------------
// Lazy import of @gatewaystack/limitabl-core
// ---------------------------------------------------------------------------

interface LimitablCore {
  AgentGuard: new (config: Record<string, unknown>) => {
    check: (toolName: string) => { allowed: boolean; reason?: string };
    record: (toolName: string) => void;
  };
}

let _limitabl: LimitablCore | null = null;

function loadLimitabl(): LimitablCore {
  if (_limitabl) return _limitabl;
  try {
    _limitabl = require("@gatewaystack/limitabl-core");
    return _limitabl!;
  } catch {
    throw new Error(
      "Behavioral monitoring requires @gatewaystack/limitabl-core — " +
      "GatewayStack's rate limiting and agent guard engine (workflow limits, budget tracking, runaway prevention).\n\n" +
      "  npm install @gatewaystack/limitabl-core\n\n" +
      "GatewayStack is an open-source agentic control plane for identity, policy, and audit.\n" +
      "Managed version: https://agenticcontrolplane.com"
    );
  }
}

// ---------------------------------------------------------------------------
// Baseline types
// ---------------------------------------------------------------------------

export interface ToolBaseline {
  avgCallsPerWindow: number;
  toolsSeen: string[];
  totalCalls: number;
  windowSeconds: number;
}

export interface Anomaly {
  type: "new-tool" | "frequency-spike" | "unusual-pattern";
  severity: "low" | "medium" | "high";
  detail: string;
}

// ---------------------------------------------------------------------------
// In-memory baseline cache (60s TTL)
// ---------------------------------------------------------------------------

let _baselineCache: ToolBaseline | null = null;
let _baselineCacheTime = 0;
const BASELINE_CACHE_TTL_MS = 60_000;

function getCachedBaseline(): ToolBaseline | null {
  if (_baselineCache && Date.now() - _baselineCacheTime < BASELINE_CACHE_TTL_MS) {
    return _baselineCache;
  }
  // Try loading from file
  try {
    const data = fs.readFileSync(BEHAVIORAL_BASELINE_PATH, "utf-8");
    _baselineCache = JSON.parse(data);
    _baselineCacheTime = Date.now();
    return _baselineCache;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Build baseline from audit log (offline)
// ---------------------------------------------------------------------------

export function buildBaseline(auditLogPath: string, windowSeconds: number): ToolBaseline {
  let lines: string[];
  try {
    const raw = fs.readFileSync(auditLogPath, "utf-8");
    lines = raw.trim().split("\n").filter(Boolean);
  } catch {
    return {
      avgCallsPerWindow: 0,
      toolsSeen: [],
      totalCalls: 0,
      windowSeconds,
    };
  }

  const toolsSeen = new Set<string>();
  const timestamps: number[] = [];

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (entry.action === "tool-check" && entry.tool) {
        toolsSeen.add(entry.tool);
        timestamps.push(new Date(entry.timestamp).getTime());
      }
    } catch {
      // Skip malformed lines
    }
  }

  if (timestamps.length === 0) {
    return {
      avgCallsPerWindow: 0,
      toolsSeen: [...toolsSeen],
      totalCalls: 0,
      windowSeconds,
    };
  }

  // Calculate average calls per window
  const minTs = Math.min(...timestamps);
  const maxTs = Math.max(...timestamps);
  const spanMs = maxTs - minTs;
  const windowMs = windowSeconds * 1000;
  const numWindows = Math.max(1, Math.ceil(spanMs / windowMs));
  const avgCallsPerWindow = timestamps.length / numWindows;

  const baseline: ToolBaseline = {
    avgCallsPerWindow,
    toolsSeen: [...toolsSeen],
    totalCalls: timestamps.length,
    windowSeconds,
  };

  // Save to file for caching
  fs.writeFileSync(BEHAVIORAL_BASELINE_PATH, JSON.stringify(baseline, null, 2));
  _baselineCache = baseline;
  _baselineCacheTime = Date.now();

  return baseline;
}

// ---------------------------------------------------------------------------
// Anomaly detection
// ---------------------------------------------------------------------------

export function detectAnomalies(
  toolName: string,
  currentWindowCalls: number,
  agentId: string,
  policy: Policy
): Anomaly[] {
  const config = policy.behavioralMonitoring;
  if (!config?.enabled) return [];

  const anomalies: Anomaly[] = [];
  const baseline = getCachedBaseline();

  if (!baseline) {
    // No baseline exists — flag as unusual
    anomalies.push({
      type: "unusual-pattern",
      severity: "low",
      detail: `No behavioral baseline found for agent "${agentId}". Run 'gatewaystack-governance --action build-baseline' to create one.`,
    });
    return anomalies;
  }

  // Check for new tool usage
  if (!baseline.toolsSeen.includes(toolName)) {
    anomalies.push({
      type: "new-tool",
      severity: "medium",
      detail: `Agent "${agentId}" is using tool "${toolName}" for the first time (not in baseline of ${baseline.toolsSeen.length} known tools)`,
    });
  }

  // Check for frequency spike
  if (
    baseline.avgCallsPerWindow > 0 &&
    currentWindowCalls > baseline.avgCallsPerWindow * config.spikeThreshold
  ) {
    anomalies.push({
      type: "frequency-spike",
      severity: "high",
      detail: `Current call rate (${currentWindowCalls} calls/window) exceeds ${config.spikeThreshold}x baseline (${baseline.avgCallsPerWindow.toFixed(1)} calls/window)`,
    });
  }

  return anomalies;
}

// ---------------------------------------------------------------------------
// Count calls in the current monitoring window from audit log
// ---------------------------------------------------------------------------

export function countCurrentWindowCalls(
  auditLogPath: string,
  windowSeconds: number
): number {
  try {
    const raw = fs.readFileSync(auditLogPath, "utf-8");
    const lines = raw.trim().split("\n").filter(Boolean);
    const cutoff = Date.now() - windowSeconds * 1000;
    let count = 0;

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (
          entry.action === "tool-check" &&
          new Date(entry.timestamp).getTime() > cutoff
        ) {
          count++;
        }
      } catch {
        // Skip malformed
      }
    }

    return count;
  } catch {
    return 0;
  }
}

// ---------------------------------------------------------------------------
// Check if limitabl-core is available (for self-test skip logic)
// ---------------------------------------------------------------------------

export function isLimitablAvailable(): boolean {
  try {
    require.resolve("@gatewaystack/limitabl-core");
    return true;
  } catch {
    return false;
  }
}

// Export for testing
export function clearBaselineCache(): void {
  _baselineCache = null;
  _baselineCacheTime = 0;
}
