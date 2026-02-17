import * as fs from "fs";
import * as crypto from "crypto";
import {
  FIRST_USE_STATE_PATH,
  PENDING_REVIEWS_PATH,
} from "./constants.js";

// ---------------------------------------------------------------------------
// Severity classification
// ---------------------------------------------------------------------------

export type InjectionSeverity = "HIGH" | "MEDIUM" | "LOW" | "NONE";

export function classifyInjectionSeverity(matches: string[]): InjectionSeverity {
  if (matches.length === 0) return "NONE";

  for (const m of matches) {
    if (
      m.startsWith("HIGH:") ||
      m.startsWith("EXTRACTION:") ||
      m.startsWith("OBFUSCATED:")
    ) {
      return "HIGH";
    }
  }

  for (const m of matches) {
    if (
      m.startsWith("MEDIUM:") ||
      m.startsWith("MULTILANG:") ||
      m.startsWith("CANARY:")
    ) {
      return "MEDIUM";
    }
  }

  return "LOW";
}

// ---------------------------------------------------------------------------
// First-time tool usage tracking
// ---------------------------------------------------------------------------

interface ToolUsageState {
  agents: Record<string, string[]>; // agentId → list of tool names used
}

function loadToolUsageState(): ToolUsageState {
  try {
    const data = fs.readFileSync(FIRST_USE_STATE_PATH, "utf-8");
    return JSON.parse(data);
  } catch {
    return { agents: {} };
  }
}

function saveToolUsageState(state: ToolUsageState): void {
  fs.writeFileSync(FIRST_USE_STATE_PATH, JSON.stringify(state, null, 2));
}

export function isFirstTimeToolUse(agentId: string, toolName: string): boolean {
  const state = loadToolUsageState();
  const tools = state.agents[agentId] || [];
  return !tools.includes(toolName);
}

export function recordToolUse(agentId: string, toolName: string): void {
  const state = loadToolUsageState();
  if (!state.agents[agentId]) {
    state.agents[agentId] = [];
  }
  if (!state.agents[agentId].includes(toolName)) {
    state.agents[agentId].push(toolName);
  }
  saveToolUsageState(state);
}

// ---------------------------------------------------------------------------
// Approval tokens
// ---------------------------------------------------------------------------

interface PendingReview {
  token: string;
  toolName: string;
  argsHash: string;
  createdAt: number;
  ttlSeconds: number;
  approved: boolean;
}

interface PendingReviewsState {
  reviews: PendingReview[];
}

function loadPendingReviews(): PendingReviewsState {
  try {
    const data = fs.readFileSync(PENDING_REVIEWS_PATH, "utf-8");
    return JSON.parse(data);
  } catch {
    return { reviews: [] };
  }
}

function savePendingReviews(state: PendingReviewsState): void {
  fs.writeFileSync(PENDING_REVIEWS_PATH, JSON.stringify(state, null, 2));
}

function cleanExpiredReviews(state: PendingReviewsState): PendingReviewsState {
  const now = Date.now();
  state.reviews = state.reviews.filter(
    (r) => now - r.createdAt < r.ttlSeconds * 1000
  );
  return state;
}

export function hashArgs(args: string): string {
  return crypto.createHash("sha256").update(args).digest("hex").substring(0, 16);
}

export function generateApprovalToken(
  toolName: string,
  argsHash: string,
  ttlSeconds: number
): string {
  const token = `gw-rev-${crypto.randomBytes(8).toString("hex")}`;
  const state = cleanExpiredReviews(loadPendingReviews());

  state.reviews.push({
    token,
    toolName,
    argsHash,
    createdAt: Date.now(),
    ttlSeconds,
    approved: false,
  });
  savePendingReviews(state);
  return token;
}

export function checkApprovalToken(
  token: string,
  toolName: string,
  argsHash: string
): boolean {
  const state = cleanExpiredReviews(loadPendingReviews());

  const review = state.reviews.find(
    (r) =>
      r.token === token &&
      r.toolName === toolName &&
      r.argsHash === argsHash &&
      r.approved
  );

  if (review) {
    // Consume the token
    state.reviews = state.reviews.filter((r) => r.token !== token);
    savePendingReviews(state);
    return true;
  }

  return false;
}

/**
 * Check if any approved token exists for this tool + args combination.
 * Used by before_tool_call to allow retries after approval.
 */
export function hasApprovedToken(toolName: string, argsHash: string): boolean {
  const state = cleanExpiredReviews(loadPendingReviews());
  return state.reviews.some(
    (r) => r.toolName === toolName && r.argsHash === argsHash && r.approved
  );
}

/**
 * Consume the first matching approved token for this tool + args.
 */
export function consumeApprovedToken(toolName: string, argsHash: string): boolean {
  const state = cleanExpiredReviews(loadPendingReviews());
  const idx = state.reviews.findIndex(
    (r) => r.toolName === toolName && r.argsHash === argsHash && r.approved
  );
  if (idx >= 0) {
    state.reviews.splice(idx, 1);
    savePendingReviews(state);
    return true;
  }
  return false;
}

/**
 * Approve a pending review token (called by CLI `gatewaystack approve <token>`).
 */
export function approveToken(token: string): { success: boolean; detail: string } {
  const state = cleanExpiredReviews(loadPendingReviews());
  const review = state.reviews.find((r) => r.token === token && !r.approved);

  if (!review) {
    return {
      success: false,
      detail: `Token "${token}" not found or expired`,
    };
  }

  review.approved = true;
  savePendingReviews(state);
  return {
    success: true,
    detail: `Approved: tool="${review.toolName}" (token expires in ${review.ttlSeconds}s)`,
  };
}

// ---------------------------------------------------------------------------
// Review block formatting
// ---------------------------------------------------------------------------

export function formatReviewBlock(reason: string, token: string): string {
  return (
    `[REVIEW REQUIRED] ${reason}\n\n` +
    `To approve this tool call, run:\n` +
    `  gatewaystack-governance approve ${token}\n\n` +
    `Then retry the tool call. Token expires in 5 minutes.`
  );
}
