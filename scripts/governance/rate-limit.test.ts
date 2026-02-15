import { describe, it, expect, beforeEach, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { Policy } from "./types.js";

// Use a real temp directory to isolate from the project's state file
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gov-rl-test-"));
const stateFile = path.join(tmpDir, ".rate-limit-state.json");
const lockFile = stateFile + ".lock";

// The rate-limit module reads RATE_LIMIT_STATE_PATH from constants at import time,
// so we can't redirect it. Instead, test the inner logic directly by writing state
// and calling checkRateLimit with the real module — but we need to reset the actual
// state file between tests.

import { RATE_LIMIT_STATE_PATH } from "./constants.js";
import { checkRateLimit } from "./rate-limit.js";

function makePolicy(perUser = { maxCalls: 3, windowSeconds: 60 }): Policy {
  return {
    allowedTools: {},
    rateLimits: {
      perUser,
      perSession: { maxCalls: 10, windowSeconds: 300 },
    },
    identityMap: {},
    injectionDetection: { enabled: false, sensitivity: "medium" },
    auditLog: { path: "audit.jsonl", maxFileSizeMB: 100 },
  };
}

describe("checkRateLimit", () => {
  beforeEach(() => {
    // Clean the real state file between tests
    try { fs.unlinkSync(RATE_LIMIT_STATE_PATH); } catch {}
    try { fs.unlinkSync(RATE_LIMIT_STATE_PATH + ".lock"); } catch {}
  });

  afterAll(() => {
    try { fs.unlinkSync(RATE_LIMIT_STATE_PATH); } catch {}
    try { fs.unlinkSync(RATE_LIMIT_STATE_PATH + ".lock"); } catch {}
    try { fs.rmdirSync(tmpDir); } catch {}
  });

  it("allows calls within the limit", () => {
    const policy = makePolicy({ maxCalls: 5, windowSeconds: 60 });
    const result = checkRateLimit("test-user-1", undefined, policy);
    expect(result.allowed).toBe(true);
    expect(result.detail).toContain("1/5");
  });

  it("denies calls exceeding the per-user limit", () => {
    const policy = makePolicy({ maxCalls: 2, windowSeconds: 3600 });

    checkRateLimit("test-user-1", undefined, policy);
    checkRateLimit("test-user-1", undefined, policy);
    const result = checkRateLimit("test-user-1", undefined, policy);

    expect(result.allowed).toBe(false);
    expect(result.detail).toContain("exceeded rate limit");
  });

  it("tracks users independently", () => {
    const policy = makePolicy({ maxCalls: 1, windowSeconds: 3600 });

    const r1 = checkRateLimit("test-user-a", undefined, policy);
    expect(r1.allowed).toBe(true);

    const r2 = checkRateLimit("test-user-b", undefined, policy);
    expect(r2.allowed).toBe(true);
  });
});
