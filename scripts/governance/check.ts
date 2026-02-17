import type { Policy, AuditEntry, GovernanceCheckResult } from "./types.js";
import { loadPolicy } from "./policy.js";
import { generateRequestId } from "./utils.js";
import { verifyIdentity } from "./identity.js";
import { checkScope } from "./scope.js";
import { checkRateLimit } from "./rate-limit.js";
import { detectInjection } from "./injection.js";
import { writeAuditLog } from "./audit.js";
import {
  classifyInjectionSeverity,
  isFirstTimeToolUse,
  recordToolUse,
  hasApprovedToken,
  consumeApprovedToken,
  generateApprovalToken,
  formatReviewBlock,
  hashArgs,
} from "./escalation.js";
import { detectAnomalies, countCurrentWindowCalls } from "./behavioral.js";

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

  // 0. Check for pre-approved escalation token
  if (policy.escalation?.enabled && params.args) {
    const argsH = hashArgs(params.args);
    if (hasApprovedToken(params.toolName, argsH)) {
      consumeApprovedToken(params.toolName, argsH);
      recordToolUse(params.userId, params.toolName);
      checks["escalation"] = {
        passed: true,
        detail: "Approved via escalation token",
      };

      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        requestId,
        action: "tool-check",
        tool: params.toolName,
        user: params.userId,
        session: params.session,
        allowed: true,
        reason: "Approved via escalation token",
        checks,
      };
      writeAuditLog(entry, policy);

      return {
        allowed: true,
        requestId,
        verdict: "allow",
      };
    }
  }

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
      const severity = classifyInjectionSeverity(injection.matches);

      // Step 4: MEDIUM + escalation enabled → review instead of block
      if (
        severity === "MEDIUM" &&
        policy.escalation?.enabled &&
        policy.escalation.reviewOnMediumInjection
      ) {
        const argsH = hashArgs(params.args);
        const token = generateApprovalToken(
          params.toolName,
          argsH,
          policy.escalation.tokenTTLSeconds
        );
        const reviewReason = `Medium-severity injection detected: ${injection.matches.join("; ")}`;
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
          reason: "Escalation: review required (medium injection)",
          checks,
        };
        writeAuditLog(entry, policy);
        return {
          allowed: false,
          reason: formatReviewBlock(reviewReason, token),
          requestId,
          patterns: injection.matches,
          verdict: "review",
          reviewReason,
        };
      }

      // HIGH or LOW (without escalation) → block
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
        verdict: "block",
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

  // 4.5. First-time tool usage review
  if (
    policy.escalation?.enabled &&
    policy.escalation.reviewOnFirstToolUse &&
    isFirstTimeToolUse(params.userId, params.toolName)
  ) {
    const argsH = hashArgs(params.args || "");
    const token = generateApprovalToken(
      params.toolName,
      argsH,
      policy.escalation.tokenTTLSeconds
    );
    const reviewReason = `First-time use of tool "${params.toolName}" by "${params.userId}"`;
    checks["firstUse"] = {
      passed: false,
      detail: reviewReason,
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
      reason: "Escalation: review required (first tool use)",
      checks,
    };
    writeAuditLog(entry, policy);
    return {
      allowed: false,
      reason: formatReviewBlock(reviewReason, token),
      requestId,
      verdict: "review",
      reviewReason,
    };
  }

  // 5. Behavioral monitoring
  if (policy.behavioralMonitoring?.enabled) {
    const auditPath = policy.auditLog?.path || "audit.jsonl";
    const windowCalls = countCurrentWindowCalls(
      auditPath,
      policy.behavioralMonitoring.monitoringWindowSeconds
    );
    const anomalies = detectAnomalies(
      params.toolName,
      windowCalls,
      params.userId,
      policy
    );

    if (anomalies.length > 0) {
      checks["behavioral"] = {
        passed: false,
        detail: anomalies.map((a) => `[${a.severity}] ${a.type}: ${a.detail}`).join("; "),
      };

      const action = policy.behavioralMonitoring.action;

      if (action === "block") {
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
          reason: "Behavioral anomaly detected",
          checks,
          anomalies,
        };
        writeAuditLog(entry, policy);
        return {
          allowed: false,
          reason: `Blocked: behavioral anomaly detected — ${anomalies.map((a) => a.detail).join("; ")}`,
          requestId,
          verdict: "block",
        };
      }

      if (action === "review" && policy.escalation?.enabled) {
        const argsH = hashArgs(params.args || "");
        const token = generateApprovalToken(
          params.toolName,
          argsH,
          policy.escalation.tokenTTLSeconds
        );
        const reviewReason = `Behavioral anomaly: ${anomalies.map((a) => a.detail).join("; ")}`;
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
          reason: "Escalation: review required (behavioral anomaly)",
          checks,
          anomalies,
        };
        writeAuditLog(entry, policy);
        return {
          allowed: false,
          reason: formatReviewBlock(reviewReason, token),
          requestId,
          verdict: "review",
          reviewReason,
        };
      }

      // action === "log" — continue but log the anomaly
      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        requestId,
        action: "behavioral-anomaly",
        tool: params.toolName,
        user: params.userId,
        resolvedIdentity: identity.userId,
        roles: identity.roles,
        session: params.session,
        allowed: true,
        reason: "Behavioral anomaly logged (action: log)",
        anomalies,
      };
      writeAuditLog(entry, policy);
    } else {
      checks["behavioral"] = {
        passed: true,
        detail: "No anomalies detected",
      };
    }
  }

  // All checks passed — record tool use for escalation tracking
  if (policy.escalation?.enabled) {
    recordToolUse(params.userId, params.toolName);
  }

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
    verdict: "allow",
  };
}
