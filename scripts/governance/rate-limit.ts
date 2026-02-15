import * as fs from "fs";
import type { Policy, RateLimitState } from "./types.js";
import { RATE_LIMIT_STATE_PATH } from "./constants.js";

const LOCK_PATH = RATE_LIMIT_STATE_PATH + ".lock";
const LOCK_TIMEOUT_MS = 5000;
const LOCK_RETRY_MS = 50;

function isLockStale(): boolean {
  try {
    const pidStr = fs.readFileSync(LOCK_PATH, "utf-8").trim();
    const pid = parseInt(pidStr, 10);
    if (isNaN(pid)) return true;
    // process.kill(pid, 0) throws if the process doesn't exist
    process.kill(pid, 0);
    return false; // process is alive, lock is valid
  } catch {
    return true; // can't read or process is dead — stale lock
  }
}

function acquireLock(): boolean {
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      // O_EXCL: fail if file exists — atomic advisory lock
      fs.writeFileSync(LOCK_PATH, String(process.pid), { flag: "wx" });
      return true;
    } catch {
      // Lock file exists — check if the holding process is still alive
      if (isLockStale()) {
        try {
          fs.unlinkSync(LOCK_PATH);
          continue; // retry immediately after clearing stale lock
        } catch {
          // another process beat us to cleanup — retry normally
        }
      }
      // Lock held by a live process — spin-wait
      const start = Date.now();
      while (Date.now() - start < LOCK_RETRY_MS) {
        // busy wait
      }
    }
  }
  return false;
}

function releaseLock(): void {
  try {
    fs.unlinkSync(LOCK_PATH);
  } catch {
    // Lock already released or never acquired
  }
}

function loadRateLimitState(): Record<string, RateLimitState> {
  if (fs.existsSync(RATE_LIMIT_STATE_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(RATE_LIMIT_STATE_PATH, "utf-8"));
    } catch {
      return {};
    }
  }
  return {};
}

function saveRateLimitState(state: Record<string, RateLimitState>): void {
  fs.writeFileSync(RATE_LIMIT_STATE_PATH, JSON.stringify(state, null, 2));
}

function _checkRateLimitInner(
  userId: string,
  session: string | undefined,
  policy: Policy
): { allowed: boolean; detail: string } {
  const state = loadRateLimitState();
  const now = Date.now();

  // Per-user check
  const userKey = `user:${userId}`;
  const userState = state[userKey] || { calls: [] };
  const userWindow = policy.rateLimits.perUser.windowSeconds * 1000;
  userState.calls = userState.calls.filter(
    (c) => now - c.timestamp < userWindow
  );

  if (userState.calls.length >= policy.rateLimits.perUser.maxCalls) {
    return {
      allowed: false,
      detail: `User ${userId} exceeded rate limit: ${policy.rateLimits.perUser.maxCalls} calls per ${policy.rateLimits.perUser.windowSeconds}s (current: ${userState.calls.length})`,
    };
  }

  // Per-session check
  if (session) {
    const sessionKey = `session:${session}`;
    const sessionState = state[sessionKey] || { calls: [] };
    const sessionWindow = policy.rateLimits.perSession.windowSeconds * 1000;
    sessionState.calls = sessionState.calls.filter(
      (c) => now - c.timestamp < sessionWindow
    );

    if (sessionState.calls.length >= policy.rateLimits.perSession.maxCalls) {
      return {
        allowed: false,
        detail: `Session ${session} exceeded rate limit: ${policy.rateLimits.perSession.maxCalls} calls per ${policy.rateLimits.perSession.windowSeconds}s`,
      };
    }

    sessionState.calls.push({ timestamp: now });
    state[sessionKey] = sessionState;
  }

  userState.calls.push({ timestamp: now });
  state[userKey] = userState;
  saveRateLimitState(state);

  return {
    allowed: true,
    detail: `Rate limit OK: ${userState.calls.length}/${policy.rateLimits.perUser.maxCalls} calls in window`,
  };
}

export function checkRateLimit(
  userId: string,
  session: string | undefined,
  policy: Policy
): { allowed: boolean; detail: string } {
  if (!acquireLock()) {
    return {
      allowed: false,
      detail: "Rate limit state lock timeout — concurrent access. Try again.",
    };
  }

  try {
    return _checkRateLimitInner(userId, session, policy);
  } finally {
    releaseLock();
  }
}
