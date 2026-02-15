import { describe, it, expect } from "vitest";
import { checkScope } from "./scope.js";
import type { Policy } from "./types.js";

function makePolicy(allowedTools: Policy["allowedTools"] = {}): Policy {
  return {
    allowedTools,
    rateLimits: { perUser: { maxCalls: 100, windowSeconds: 3600 }, perSession: { maxCalls: 30, windowSeconds: 300 } },
    identityMap: {},
    injectionDetection: { enabled: false, sensitivity: "medium" },
    auditLog: { path: "audit.jsonl", maxFileSizeMB: 100 },
  };
}

describe("checkScope", () => {
  it("denies tools not in the allowlist", () => {
    const result = checkScope("evil-tool", ["default"], makePolicy());
    expect(result.allowed).toBe(false);
    expect(result.detail).toContain("not in the allowlist");
  });

  it("allows tools in the allowlist with no role restrictions", () => {
    const result = checkScope("read", ["default"], makePolicy({ read: {} }));
    expect(result.allowed).toBe(true);
  });

  it("allows tools when user has a matching role", () => {
    const policy = makePolicy({ write: { roles: ["admin"] } });
    const result = checkScope("write", ["admin", "default"], policy);
    expect(result.allowed).toBe(true);
  });

  it("denies tools when user lacks required role", () => {
    const policy = makePolicy({ write: { roles: ["admin"] } });
    const result = checkScope("write", ["default"], policy);
    expect(result.allowed).toBe(false);
    expect(result.detail).toContain("requires roles");
  });

  it("allows tools with empty roles array (no restriction)", () => {
    const policy = makePolicy({ read: { roles: [] } });
    const result = checkScope("read", ["default"], policy);
    expect(result.allowed).toBe(true);
  });

  it("handles user with no roles trying to access unrestricted tool", () => {
    const policy = makePolicy({ read: {} });
    const result = checkScope("read", [], policy);
    expect(result.allowed).toBe(true);
  });

  it("handles user with no roles trying to access restricted tool", () => {
    const policy = makePolicy({ write: { roles: ["admin"] } });
    const result = checkScope("write", [], policy);
    expect(result.allowed).toBe(false);
  });
});
