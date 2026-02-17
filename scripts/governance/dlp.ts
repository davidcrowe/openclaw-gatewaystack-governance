import type { Policy, AuditEntry } from "./types.js";
import { writeAuditLog } from "./audit.js";
import { generateRequestId } from "./utils.js";

// ---------------------------------------------------------------------------
// Lazy import of @gatewaystack/transformabl-core
// ---------------------------------------------------------------------------

interface TransformablCore {
  detectPii: (input: string, options?: Record<string, unknown>) => Array<{
    type: string;
    value: string;
    start: number;
    end: number;
    confidence: number;
  }>;
  redactPii: (input: string, options?: Record<string, unknown>) => string;
}

let _transformabl: TransformablCore | null = null;

function loadTransformabl(): TransformablCore {
  if (_transformabl) return _transformabl;
  try {
    _transformabl = require("@gatewaystack/transformabl-core");
    return _transformabl!;
  } catch {
    throw new Error(
      "Output DLP requires @gatewaystack/transformabl-core — " +
      "GatewayStack's content safety engine (PII detection, redaction, injection classification).\n\n" +
      "  npm install @gatewaystack/transformabl-core\n\n" +
      "GatewayStack is an open-source agentic control plane for identity, policy, and audit.\n" +
      "Managed version: https://agenticcontrolplane.com"
    );
  }
}

// ---------------------------------------------------------------------------
// DLP scanning
// ---------------------------------------------------------------------------

export interface DlpMatch {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

export interface DlpScanResult {
  matches: DlpMatch[];
  hasMatches: boolean;
  summary: string;
}

export function scanOutput(
  output: string,
  policy: Policy
): DlpScanResult {
  const dlpConfig = policy.outputDlp;
  if (!dlpConfig?.enabled) {
    return { matches: [], hasMatches: false, summary: "DLP not enabled" };
  }

  const transformabl = loadTransformabl();
  const options: Record<string, unknown> = {};
  if (dlpConfig.customPatterns && dlpConfig.customPatterns.length > 0) {
    options.customPatterns = dlpConfig.customPatterns;
  }

  const rawMatches = transformabl.detectPii(output, options);
  const matches: DlpMatch[] = rawMatches.map((m) => ({
    type: m.type,
    value: m.value,
    start: m.start,
    end: m.end,
    confidence: m.confidence,
  }));

  return {
    matches,
    hasMatches: matches.length > 0,
    summary: matches.length > 0
      ? `Found ${matches.length} PII match(es): ${[...new Set(matches.map((m) => m.type))].join(", ")}`
      : "No PII detected",
  };
}

// ---------------------------------------------------------------------------
// DLP redaction
// ---------------------------------------------------------------------------

export function redactOutput(
  output: string,
  policy: Policy
): string {
  const dlpConfig = policy.outputDlp;
  if (!dlpConfig?.enabled) return output;

  const transformabl = loadTransformabl();
  const options: Record<string, unknown> = {
    mode: dlpConfig.redactionMode || "mask",
  };
  if (dlpConfig.customPatterns && dlpConfig.customPatterns.length > 0) {
    options.customPatterns = dlpConfig.customPatterns;
  }

  return transformabl.redactPii(output, options);
}

// ---------------------------------------------------------------------------
// DLP audit logging
// ---------------------------------------------------------------------------

export function logDlpScan(
  scanResult: DlpScanResult,
  toolName: string,
  policy: Policy
): void {
  if (!scanResult.hasMatches) return;

  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    requestId: generateRequestId(),
    action: "dlp-scan",
    tool: toolName,
    dlpMatches: scanResult.matches.map(
      (m) => `${m.type}: "${m.value.substring(0, 20)}..." (confidence: ${m.confidence})`
    ),
    reason: scanResult.summary,
  };
  writeAuditLog(entry, policy);
}

// ---------------------------------------------------------------------------
// Check if transformabl-core is available (for self-test skip logic)
// ---------------------------------------------------------------------------

export function isTransformablAvailable(): boolean {
  try {
    require.resolve("@gatewaystack/transformabl-core");
    return true;
  } catch {
    return false;
  }
}
