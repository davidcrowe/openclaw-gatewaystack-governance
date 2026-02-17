import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import {
  classifyInjectionSeverity,
  isFirstTimeToolUse,
  recordToolUse,
  generateApprovalToken,
  approveToken,
  hasApprovedToken,
  consumeApprovedToken,
  hashArgs,
  formatReviewBlock,
} from "./escalation.js";
import {
  FIRST_USE_STATE_PATH,
  PENDING_REVIEWS_PATH,
} from "./constants.js";

function cleanup() {
  try { fs.unlinkSync(FIRST_USE_STATE_PATH); } catch {}
  try { fs.unlinkSync(PENDING_REVIEWS_PATH); } catch {}
}

describe("classifyInjectionSeverity", () => {
  it("returns NONE for empty matches", () => {
    expect(classifyInjectionSeverity([])).toBe("NONE");
  });

  it("returns HIGH for HIGH-prefixed matches", () => {
    expect(classifyInjectionSeverity(["HIGH: instruction injection"])).toBe("HIGH");
  });

  it("returns HIGH for EXTRACTION-prefixed matches", () => {
    expect(classifyInjectionSeverity(["EXTRACTION: prompt dump"])).toBe("HIGH");
  });

  it("returns HIGH for OBFUSCATED-prefixed matches", () => {
    expect(classifyInjectionSeverity(["OBFUSCATED: base64 payload"])).toBe("HIGH");
  });

  it("returns MEDIUM for MEDIUM-prefixed matches", () => {
    expect(classifyInjectionSeverity(["MEDIUM: role impersonation"])).toBe("MEDIUM");
  });

  it("returns MEDIUM for MULTILANG-prefixed matches", () => {
    expect(classifyInjectionSeverity(["MULTILANG: 忽略之前的指令"])).toBe("MEDIUM");
  });

  it("returns MEDIUM for CANARY-prefixed matches", () => {
    expect(classifyInjectionSeverity(["CANARY: leaked token"])).toBe("MEDIUM");
  });

  it("returns LOW for LOW-prefixed matches", () => {
    expect(classifyInjectionSeverity(["LOW: suspicious IP"])).toBe("LOW");
  });

  it("returns HIGH when mixed severities present", () => {
    expect(
      classifyInjectionSeverity([
        "LOW: something",
        "MEDIUM: something",
        "HIGH: something",
      ])
    ).toBe("HIGH");
  });
});

describe("first-time tool usage", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("detects first-time usage", () => {
    expect(isFirstTimeToolUse("agent-1", "read")).toBe(true);
  });

  it("detects subsequent usage after recording", () => {
    recordToolUse("agent-1", "read");
    expect(isFirstTimeToolUse("agent-1", "read")).toBe(false);
  });

  it("tracks agents independently", () => {
    recordToolUse("agent-1", "read");
    expect(isFirstTimeToolUse("agent-2", "read")).toBe(true);
  });

  it("tracks tools independently", () => {
    recordToolUse("agent-1", "read");
    expect(isFirstTimeToolUse("agent-1", "write")).toBe(true);
  });
});

describe("approval tokens", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("generates a token with gw-rev- prefix", () => {
    const token = generateApprovalToken("read", hashArgs("{}"), 300);
    expect(token).toMatch(/^gw-rev-[0-9a-f]{16}$/);
  });

  it("token is not initially approved", () => {
    const argsH = hashArgs("{}");
    generateApprovalToken("read", argsH, 300);
    expect(hasApprovedToken("read", argsH)).toBe(false);
  });

  it("approving a token marks it as approved", () => {
    const argsH = hashArgs("{}");
    const token = generateApprovalToken("read", argsH, 300);
    const result = approveToken(token);
    expect(result.success).toBe(true);
    expect(hasApprovedToken("read", argsH)).toBe(true);
  });

  it("consuming an approved token removes it", () => {
    const argsH = hashArgs("{}");
    const token = generateApprovalToken("read", argsH, 300);
    approveToken(token);
    expect(consumeApprovedToken("read", argsH)).toBe(true);
    expect(hasApprovedToken("read", argsH)).toBe(false);
  });

  it("approving a non-existent token fails", () => {
    const result = approveToken("gw-rev-doesnotexist1234");
    expect(result.success).toBe(false);
  });

  it("token is bound to tool name and args hash", () => {
    const argsH = hashArgs("{}");
    const token = generateApprovalToken("read", argsH, 300);
    approveToken(token);
    // Different tool name — should not find
    expect(hasApprovedToken("write", argsH)).toBe(false);
    // Different args hash — should not find
    expect(hasApprovedToken("read", hashArgs('{"other": true}'))).toBe(false);
  });
});

describe("formatReviewBlock", () => {
  it("includes token and instructions", () => {
    const block = formatReviewBlock("Medium injection detected", "gw-rev-abc123");
    expect(block).toContain("[REVIEW REQUIRED]");
    expect(block).toContain("gw-rev-abc123");
    expect(block).toContain("gatewaystack-governance approve");
  });
});

describe("hashArgs", () => {
  it("produces a 16-char hex string", () => {
    const h = hashArgs("test");
    expect(h).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is deterministic", () => {
    expect(hashArgs("test")).toBe(hashArgs("test"));
  });

  it("differs for different inputs", () => {
    expect(hashArgs("test1")).not.toBe(hashArgs("test2"));
  });
});
