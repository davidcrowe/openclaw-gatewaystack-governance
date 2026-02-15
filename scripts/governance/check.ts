import type { Policy, AuditEntry, GovernanceCheckResult } from "./types.js";
import { loadPolicy } from "./policy.js";
import { generateRequestId } from "./utils.js";
import { verifyIdentity } from "./identity.js";
import { checkScope } from "./scope.js";
import { checkRateLimit } from "./rate-limit.js";
import { detectInjection } from "./injection.js";
import { writeAuditLog } from "./audit.js";

export async function checkGovernance(params: {
  toolName: string;
  args: string;
  userId: string;
  session?: string;
  policyPath?: string;
}): Promise<GovernanceCheckResult> {
  const policy = loadPolicy(params.policyPath);
  const requestId = generateRequestId();

  const checks: Record<string, { passed: boolean; detail: string }> = {};

  // 1. Identity verification
  const identity = verifyIdentity(params.userId, undefined, policy);
  checks["identity"] = {
    passed: identity.verified,
    detail: identity.detail,
  };

  if (!identity.verified) {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      requestId,
      action: "tool-check",
      tool: params.toolName,
      user: params.userId,
      session: params.session,
      allowed: false,
      reason: "Identity verification failed",
      checks,
    };
    writeAuditLog(entry, policy);
    return {
      allowed: false,
      reason: `Identity verification failed: ${identity.detail}`,
      requestId,
    };
  }

  // 2. Scope enforcement
  const scope = checkScope(params.toolName, identity.roles, policy);
  checks["scope"] = { passed: scope.allowed, detail: scope.detail };

  if (!scope.allowed) {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      requestId,
      action: "tool-check",
      tool: params.toolName,
      user: params.userId,
      resolvedIdentity: identity.userId,
      roles: identity.roles,
      session: params.session,
      allowed: false,
      reason: "Scope check failed",
      checks,
    };
    writeAuditLog(entry, policy);
    return {
      allowed: false,
      reason: `Scope check failed: ${scope.detail}`,
      requestId,
    };
  }

  // 3. Rate limiting
  const rateLimit = checkRateLimit(identity.userId, params.session, policy);
  checks["rateLimit"] = {
    passed: rateLimit.allowed,
    detail: rateLimit.detail,
  };

  if (!rateLimit.allowed) {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      requestId,
      action: "tool-check",
      tool: params.toolName,
      user: params.userId,
      resolvedIdentity: identity.userId,
      roles: identity.roles,
      session: params.session,
      allowed: false,
      reason: "Rate limit exceeded",
      checks,
    };
    writeAuditLog(entry, policy);
    return {
      allowed: false,
      reason: `Rate limit exceeded: ${rateLimit.detail}`,
      requestId,
    };
  }

  // 4. Injection detection
  if (params.args) {
    const injection = detectInjection(params.args, policy);
    checks["injection"] = {
      passed: injection.clean,
      detail: injection.clean
        ? injection.detail
        : `${injection.detail}: ${injection.matches.join("; ")}`,
    };

    if (!injection.clean) {
      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        requestId,
        action: "tool-check",
        tool: params.toolName,
        user: params.userId,
        resolvedIdentity: identity.userId,
        roles: identity.roles,
        session: params.session,
        allowed: false,
        reason: "Prompt injection detected",
        checks,
      };
      writeAuditLog(entry, policy);
      return {
        allowed: false,
        reason: `Blocked: potential prompt injection detected in tool arguments. ${injection.matches.length} pattern(s) matched.`,
        requestId,
        patterns: injection.matches,
      };
    }

    // Check args length
    const toolPolicy = policy.allowedTools[params.toolName];
    if (
      toolPolicy?.maxArgsLength &&
      params.args.length > toolPolicy.maxArgsLength
    ) {
      checks["argsLength"] = {
        passed: false,
        detail: `Args length ${params.args.length} exceeds limit ${toolPolicy.maxArgsLength}`,
      };
      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        requestId,
        action: "tool-check",
        tool: params.toolName,
        user: params.userId,
        resolvedIdentity: identity.userId,
        roles: identity.roles,
        session: params.session,
        allowed: false,
        reason: "Arguments too long",
        checks,
      };
      writeAuditLog(entry, policy);
      return {
        allowed: false,
        reason: `Tool arguments exceed maximum length (${params.args.length} > ${toolPolicy.maxArgsLength})`,
        requestId,
      };
    }
  }

  // All checks passed
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    requestId,
    action: "tool-check",
    tool: params.toolName,
    user: params.userId,
    resolvedIdentity: identity.userId,
    roles: identity.roles,
    session: params.session,
    allowed: true,
    reason: "All governance checks passed",
    checks,
  };
  writeAuditLog(entry, policy);

  return {
    allowed: true,
    requestId,
    identity: identity.userId,
    roles: identity.roles,
  };
}
