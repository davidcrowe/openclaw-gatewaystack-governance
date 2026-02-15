import { describe, it, expect } from "vitest";
import { verifyIdentity } from "./identity.js";
import type { Policy } from "./types.js";

function makePolicy(identityMap: Policy["identityMap"] = {}): Policy {
  return {
    allowedTools: {},
    rateLimits: { perUser: { maxCalls: 100, windowSeconds: 3600 }, perSession: { maxCalls: 30, windowSeconds: 300 } },
    identityMap,
    injectionDetection: { enabled: false, sensitivity: "medium" },
    auditLog: { path: "audit.jsonl", maxFileSizeMB: 100 },
  };
}

describe("verifyIdentity", () => {
  it("rejects when no user or channel provided", () => {
    const result = verifyIdentity(undefined, undefined, makePolicy());
    expect(result.verified).toBe(false);
    expect(result.userId).toBe("unknown");
    expect(result.roles).toHaveLength(0);
  });

  it("maps a known user to their identity", () => {
    const policy = makePolicy({ main: { userId: "agent-main", roles: ["admin"] } });
    const result = verifyIdentity("main", undefined, policy);
    expect(result.verified).toBe(true);
    expect(result.userId).toBe("agent-main");
    expect(result.roles).toContain("admin");
  });

  it("maps a known channel to its identity", () => {
    const policy = makePolicy({ "slack-general": { userId: "channel-general", roles: ["default"] } });
    const result = verifyIdentity(undefined, "slack-general", policy);
    expect(result.verified).toBe(true);
    expect(result.userId).toBe("channel-general");
  });

  it("prefers channel over user when both provided", () => {
    const policy = makePolicy({
      "my-channel": { userId: "from-channel", roles: ["viewer"] },
      "my-user": { userId: "from-user", roles: ["admin"] },
    });
    const result = verifyIdentity("my-user", "my-channel", policy);
    expect(result.verified).toBe(true);
    expect(result.userId).toBe("from-channel");
  });

  it("denies unmapped user (deny-by-default)", () => {
    const policy = makePolicy({ main: { userId: "agent-main", roles: ["admin"] } });
    const result = verifyIdentity("unknown-rando", undefined, policy);
    expect(result.verified).toBe(false);
    expect(result.userId).toBe("unknown-rando");
    expect(result.detail).toContain("not in the identity map");
  });

  it("denies unmapped channel", () => {
    const policy = makePolicy({});
    const result = verifyIdentity(undefined, "unknown-channel", policy);
    expect(result.verified).toBe(false);
    expect(result.detail).toContain("no identity mapping");
  });
});
